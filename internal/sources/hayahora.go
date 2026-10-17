package sources

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net/http"
	"net/netip"
	"slices"
	"sort"
	"strings"
	"sync"
	"time"

	"github.com/alperdevv/laliga-bypass/internal/detector"
)

type hayahoraFeed struct {
	LastUpdate string          `json:"lastUpdate"`
	Data       []hayahoraEntry `json:"data"`
}

type hayahoraEntry struct {
	IP           string `json:"ip"`
	ISP          string `json:"isp"`
	Description  string `json:"description"`
	StateChanges []struct {
		Timestamp string `json:"timestamp"`
		State     bool   `json:"state"`
	} `json:"stateChanges"`
}

type ipState struct {
	Blocked bool
	Since   time.Time
}

type Feed struct {
	LastUpdate time.Time
	states     map[string]map[string]ipState
}

type Hayahora struct {
	URL             string
	HTTP            *http.Client
	RefreshInterval time.Duration
	RetryAfterError time.Duration
	Now             func() time.Time

	mu        sync.Mutex
	feed      *Feed
	etag      string
	fetchedAt time.Time
	lastErr   error
}

const maxFeedBytes = 64 << 20

func (h *Hayahora) Get(ctx context.Context) (*Feed, error) {
	h.mu.Lock()
	defer h.mu.Unlock()
	now := h.now()
	if h.lastErr == nil && h.feed != nil && now.Sub(h.fetchedAt) < h.RefreshInterval {
		return h.feed, nil
	}
	if h.lastErr != nil && now.Sub(h.fetchedAt) < h.retryAfterError() {
		return h.feed, h.lastErr
	}
	h.fetchedAt = now
	feed, err := h.fetch(ctx)
	h.lastErr = err
	if err != nil {
		return h.feed, err
	}
	if feed != nil {
		h.feed = feed
	}
	return h.feed, nil
}

func (h *Hayahora) retryAfterError() time.Duration {
	if h.RetryAfterError > 0 {
		return h.RetryAfterError
	}
	return time.Minute
}

func (h *Hayahora) fetch(ctx context.Context) (*Feed, error) {
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, h.URL, nil)
	if err != nil {
		return nil, err
	}
	req.Header.Set("User-Agent", "github.com/alperdevv/laliga-bypass/1")
	req.Header.Set("Accept", "application/json")
	if h.etag != "" && h.feed != nil {
		req.Header.Set("If-None-Match", h.etag)
	}
	client := h.HTTP
	if client == nil {
		client = &http.Client{Timeout: 30 * time.Second}
	}
	resp, err := client.Do(req)
	if err != nil {
		return nil, fmt.Errorf("fetching hayahora feed: %w", err)
	}
	defer resp.Body.Close()
	switch resp.StatusCode {
	case http.StatusNotModified:
		return nil, nil
	case http.StatusOK:
	default:
		_, _ = io.Copy(io.Discard, io.LimitReader(resp.Body, 4096))
		return nil, fmt.Errorf("hayahora feed: HTTP %d", resp.StatusCode)
	}
	feed, err := ParseHayahora(io.LimitReader(resp.Body, maxFeedBytes))
	if err != nil {
		return nil, err
	}
	h.etag = resp.Header.Get("ETag")
	return feed, nil
}

func (h *Hayahora) now() time.Time {
	if h.Now != nil {
		return h.Now()
	}
	return time.Now()
}

func ParseHayahora(r io.Reader) (*Feed, error) {
	var raw hayahoraFeed
	if err := json.NewDecoder(r).Decode(&raw); err != nil {
		return nil, fmt.Errorf("unexpected hayahora feed format: %w", err)
	}
	last, err := parseHayahoraTime(raw.LastUpdate)
	if err != nil {
		return nil, fmt.Errorf("hayahora feed has no valid lastUpdate: %w", err)
	}
	if raw.Data == nil {
		return nil, errors.New("hayahora feed has no data field")
	}
	f := &Feed{LastUpdate: last, states: make(map[string]map[string]ipState, len(raw.Data))}
	for _, e := range raw.Data {
		ip, ok := normalizeIP(e.IP)
		if !ok || e.ISP == "" {
			continue
		}
		var latest ipState
		var latestTS time.Time
		for _, sc := range e.StateChanges {
			ts, err := parseHayahoraTime(sc.Timestamp)
			if err != nil {
				continue
			}
			if latestTS.IsZero() || !ts.Before(latestTS) {
				latestTS, latest = ts, ipState{Blocked: sc.State, Since: ts}
			}
		}
		if latestTS.IsZero() {
			continue
		}
		if f.states[ip] == nil {
			f.states[ip] = map[string]ipState{}
		}
		f.states[ip][e.ISP] = latest
	}
	return f, nil
}

type LookupOptions struct {
	ISPs            []string
	IgnoreOlderThan time.Duration
	Now             time.Time
}

func (f *Feed) Lookup(ips []string, opt LookupOptions) *detector.HayahoraEvidence {
	ev := &detector.HayahoraEvidence{Available: true, LastUpdate: f.LastUpdate, BlockedBy: map[string][]string{}}
	allowed := map[string]bool{}
	for _, isp := range opt.ISPs {
		allowed[strings.ToLower(isp)] = true
	}
	for _, raw := range ips {
		ip, ok := normalizeIP(raw)
		if !ok {
			continue
		}
		ev.CheckedIPs = append(ev.CheckedIPs, ip)
		byISP, tracked := f.states[ip]
		if !tracked {
			continue
		}
		ev.TrackedIPs = append(ev.TrackedIPs, ip)
		for isp, st := range byISP {
			if len(allowed) > 0 && !allowed[strings.ToLower(isp)] {
				continue
			}
			if !st.Blocked {
				continue
			}
			if opt.IgnoreOlderThan > 0 && opt.Now.Sub(st.Since) > opt.IgnoreOlderThan {
				continue
			}
			ev.BlockedBy[ip] = append(ev.BlockedBy[ip], isp)
		}
		sort.Strings(ev.BlockedBy[ip])
	}
	sort.Strings(ev.CheckedIPs)
	sort.Strings(ev.TrackedIPs)
	ev.CheckedIPs = slices.Compact(ev.CheckedIPs)
	ev.TrackedIPs = slices.Compact(ev.TrackedIPs)
	return ev
}

func Unavailable(err error) *detector.HayahoraEvidence {
	return &detector.HayahoraEvidence{Available: false, Error: err.Error()}
}

func parseHayahoraTime(s string) (time.Time, error) {
	for _, layout := range []string{"2006-01-02 15:04:05Z07:00", time.RFC3339, "2006-01-02 15:04:05"} {
		if t, err := time.Parse(layout, s); err == nil {
			return t.UTC(), nil
		}
	}
	return time.Time{}, fmt.Errorf("unrecognized timestamp %q", s)
}

func normalizeIP(s string) (string, bool) {
	a, err := netip.ParseAddr(strings.TrimSpace(s))
	if err != nil {
		return "", false
	}
	return a.Unmap().String(), true
}
