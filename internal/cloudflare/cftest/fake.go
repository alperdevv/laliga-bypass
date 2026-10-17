package cftest

import (
	"encoding/json"
	"io"
	"net/http"
	"net/http/httptest"
	"sort"
	"strconv"
	"strings"
	"sync"
	"time"

	"github.com/alperdevv/laliga-bypass/internal/cloudflare"
)

type Request struct {
	Method string
	Path   string
	Body   string
}

type Server struct {
	*httptest.Server
	Token string

	mu       sync.Mutex
	zones    map[string]string
	records  map[string]*cloudflare.Record
	requests []Request
	clock    time.Time
	failNext map[string]int
}

func New(token string) *Server {
	s := &Server{
		Token:    token,
		zones:    map[string]string{},
		records:  map[string]*cloudflare.Record{},
		clock:    time.Date(2026, 1, 1, 0, 0, 0, 0, time.UTC),
		failNext: map[string]int{},
	}
	s.Server = httptest.NewServer(http.HandlerFunc(s.handle))
	return s
}

func (s *Server) BaseURL() string { return s.URL + "/client/v4" }

func (s *Server) AddZone(id, name string) {
	s.mu.Lock()
	defer s.mu.Unlock()
	s.zones[id] = name
}

func (s *Server) AddRecord(zoneID string, r cloudflare.Record) {
	s.mu.Lock()
	defer s.mu.Unlock()
	r.ModifiedOn = s.tick()
	s.records[zoneID+"/"+r.ID] = &r
}

func (s *Server) Record(zoneID, id string) cloudflare.Record {
	s.mu.Lock()
	defer s.mu.Unlock()
	return *s.records[zoneID+"/"+id]
}

func (s *Server) ManualEdit(zoneID, id string, edit func(*cloudflare.Record)) {
	s.mu.Lock()
	defer s.mu.Unlock()
	r := s.records[zoneID+"/"+id]
	edit(r)
	r.ModifiedOn = s.tick()
}

func (s *Server) FailNext(method string, n int) {
	s.mu.Lock()
	defer s.mu.Unlock()
	s.failNext[method] = n
}

func (s *Server) Requests() []Request {
	s.mu.Lock()
	defer s.mu.Unlock()
	return append([]Request(nil), s.requests...)
}

func (s *Server) Count(method string) int {
	n := 0
	for _, r := range s.Requests() {
		if r.Method == method {
			n++
		}
	}
	return n
}

func (s *Server) tick() time.Time {
	s.clock = s.clock.Add(time.Second)
	return s.clock
}

func (s *Server) handle(w http.ResponseWriter, r *http.Request) {
	s.mu.Lock()
	defer s.mu.Unlock()
	raw, _ := io.ReadAll(io.LimitReader(r.Body, 1<<20))
	s.requests = append(s.requests, Request{Method: r.Method, Path: r.URL.Path, Body: string(raw)})

	if r.Header.Get("Authorization") != "Bearer "+s.Token {
		writeErr(w, http.StatusForbidden, 10000, "Authentication error")
		return
	}
	if s.failNext[r.Method] > 0 {
		s.failNext[r.Method]--
		writeErr(w, http.StatusInternalServerError, 1000, "simulated failure")
		return
	}
	parts := strings.Split(strings.TrimPrefix(r.URL.Path, "/client/v4/"), "/")
	switch {
	case len(parts) == 1 && parts[0] == "zones" && r.Method == http.MethodGet:
		var zones []cloudflare.Zone
		for id, name := range s.zones {
			if q := r.URL.Query().Get("name"); q == "" || q == name {
				zones = append(zones, cloudflare.Zone{ID: id, Name: name, Status: "active"})
			}
		}
		sort.Slice(zones, func(i, j int) bool { return zones[i].Name < zones[j].Name })
		writePage(w, r, zones)
	case len(parts) == 3 && parts[0] == "zones" && parts[2] == "dns_records" && r.Method == http.MethodGet:
		if _, ok := s.zones[parts[1]]; !ok {
			writeErr(w, http.StatusNotFound, 1001, "Invalid zone identifier")
			return
		}
		var recs []cloudflare.Record
		for key, rec := range s.records {
			if strings.HasPrefix(key, parts[1]+"/") {
				recs = append(recs, *rec)
			}
		}
		sort.Slice(recs, func(i, j int) bool { return recs[i].Name+recs[i].Type < recs[j].Name+recs[j].Type })
		writePage(w, r, recs)
	case len(parts) == 2 && parts[0] == "zones" && r.Method == http.MethodGet:
		name, ok := s.zones[parts[1]]
		if !ok {
			writeErr(w, http.StatusNotFound, 1001, "Invalid zone identifier")
			return
		}
		writeOK(w, cloudflare.Zone{ID: parts[1], Name: name, Status: "active"})
	case len(parts) == 4 && parts[0] == "zones" && parts[2] == "dns_records":
		rec, ok := s.records[parts[1]+"/"+parts[3]]
		if !ok {
			writeErr(w, http.StatusNotFound, 81044, "Record does not exist.")
			return
		}
		switch r.Method {
		case http.MethodGet:
			writeOK(w, rec)
		case http.MethodPatch:
			var in map[string]any
			if err := json.Unmarshal(raw, &in); err != nil {
				writeErr(w, http.StatusBadRequest, 9207, "Request body is invalid.")
				return
			}
			if p, ok := in["proxied"].(bool); ok {
				rec.Proxied = p
				if p {
					rec.TTL = 1
				}
			}
			rec.ModifiedOn = s.tick()
			writeOK(w, rec)
		default:
			writeErr(w, http.StatusMethodNotAllowed, 10405, "Method not allowed")
		}
	default:
		writeErr(w, http.StatusNotFound, 7003, "Could not route to "+r.URL.Path)
	}
}

func writePage[T any](w http.ResponseWriter, r *http.Request, items []T) {
	perPage, _ := strconv.Atoi(r.URL.Query().Get("per_page"))
	if perPage <= 0 {
		perPage = 20
	}
	page, _ := strconv.Atoi(r.URL.Query().Get("page"))
	if page <= 0 {
		page = 1
	}
	total := (len(items) + perPage - 1) / perPage
	start := min((page-1)*perPage, len(items))
	end := min(start+perPage, len(items))
	w.Header().Set("Content-Type", "application/json")
	_ = json.NewEncoder(w).Encode(map[string]any{
		"success":     true,
		"errors":      []any{},
		"result":      items[start:end],
		"result_info": map[string]int{"page": page, "per_page": perPage, "total_pages": total, "total_count": len(items)},
	})
}

func writeOK(w http.ResponseWriter, result any) {
	w.Header().Set("Content-Type", "application/json")
	_ = json.NewEncoder(w).Encode(map[string]any{"success": true, "errors": []any{}, "messages": []any{}, "result": result})
}

func writeErr(w http.ResponseWriter, status, code int, msg string) {
	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(status)
	_ = json.NewEncoder(w).Encode(map[string]any{
		"success": false,
		"errors":  []map[string]any{{"code": code, "message": msg}},
		"result":  nil,
	})
}
