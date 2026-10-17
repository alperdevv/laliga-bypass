package sources_test

import (
	"context"
	"encoding/json"
	"fmt"
	"net/http"
	"net/http/httptest"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/alperdevv/laliga-bypass/internal/config"
	"github.com/alperdevv/laliga-bypass/internal/detector"
	"github.com/alperdevv/laliga-bypass/internal/sources"
)

type probeOutcome struct {
	status        string
	statusCode    int
	resolved      string
	failureSource string
}

type fakeGlobalping struct {
	mu      sync.Mutex
	byMagic map[string][]probeOutcome
	created map[string]string
	bodies  []map[string]any
	auth    []string
	rateHit bool
}

func newFakeGlobalping(byMagic map[string][]probeOutcome) (*fakeGlobalping, *httptest.Server) {
	f := &fakeGlobalping{byMagic: byMagic, created: map[string]string{}}
	return f, httptest.NewServer(http.HandlerFunc(f.handle))
}

func (f *fakeGlobalping) handle(w http.ResponseWriter, r *http.Request) {
	f.mu.Lock()
	defer f.mu.Unlock()
	f.auth = append(f.auth, r.Header.Get("Authorization"))
	switch {
	case r.Method == http.MethodPost && r.URL.Path == "/v1/measurements":
		if f.rateHit {
			w.Header().Set("X-RateLimit-Reset", "1200")
			w.WriteHeader(http.StatusTooManyRequests)
			_, _ = w.Write([]byte(`{"error":{"type":"too_many_requests","message":"limit"}}`))
			return
		}
		var body map[string]any
		_ = json.NewDecoder(r.Body).Decode(&body)
		f.bodies = append(f.bodies, body)
		magic := body["locations"].([]any)[0].(map[string]any)["magic"].(string)
		id := fmt.Sprintf("m%d", len(f.created))
		f.created[id] = magic
		w.Header().Set("Location", "/v1/measurements/"+id)
		w.WriteHeader(http.StatusAccepted)
		_, _ = fmt.Fprintf(w, `{"id":%q,"probesCount":%d}`, id, len(f.byMagic[magic]))
	case r.Method == http.MethodGet && strings.HasPrefix(r.URL.Path, "/v1/measurements/"):
		id := strings.TrimPrefix(r.URL.Path, "/v1/measurements/")
		magic, ok := f.created[id]
		if !ok {
			w.WriteHeader(http.StatusNotFound)
			return
		}
		var results []map[string]any
		for _, p := range f.byMagic[magic] {
			res := map[string]any{"status": p.status, "rawOutput": ""}
			if p.status == "finished" {
				res["statusCode"] = p.statusCode
				res["resolvedAddress"] = p.resolved
			}
			if p.failureSource != "" {
				res["failureSource"] = p.failureSource
			}
			results = append(results, map[string]any{"probe": map[string]any{"country": "ES", "asn": 3352}, "result": res})
		}
		_ = json.NewEncoder(w).Encode(map[string]any{"id": id, "status": "finished", "results": results})
	default:
		w.WriteHeader(http.StatusNotFound)
	}
}

func measurement() sources.HTTPMeasurement {
	return sources.HTTPMeasurement{
		Host:           "example.com",
		Path:           "/",
		Protocol:       "HTTPS",
		ExpectedStatus: []int{200},
		Targets: []config.ProbeGroup{
			{Name: "Movistar", Magic: "ES+AS3352", Limit: 2},
			{Name: "Orange", Magic: "ES+AS12479", Limit: 1},
			{Name: "Vodafone", Magic: "ES+AS12430", Limit: 1},
			{Name: "DIGI", Magic: "ES+AS57269", Limit: 1},
		},
		Controls:   []config.ProbeGroup{{Name: "control-de", Magic: "Germany", Limit: 1}},
		ExcludeIPs: []string{"203.0.113.10"},
	}
}

func groupByName(ev *detector.GlobalpingEvidence, name string) detector.ProbeGroupResult {
	for _, g := range ev.Groups {
		if g.Name == name {
			return g
		}
	}
	return detector.ProbeGroupResult{}
}

func TestGlobalpingClassifiesProbeResultsPerGroup(t *testing.T) {
	fake, srv := newFakeGlobalping(map[string][]probeOutcome{
		"ES+AS3352":  {{status: "failed", failureSource: "target"}, {status: "failed"}},
		"ES+AS12479": {{status: "finished", statusCode: 200, resolved: "104.21.0.1"}},
		"ES+AS12430": {{status: "finished", statusCode: 503, resolved: "104.21.0.1"}},
		"ES+AS57269": {{status: "finished", statusCode: 200, resolved: "203.0.113.10"}, {status: "failed", failureSource: "resolver"}},
		"Germany":    {{status: "finished", statusCode: 200, resolved: "104.21.0.1"}},
	})
	defer srv.Close()

	gp := &sources.Globalping{BaseURL: srv.URL, Token: "gp-secret", PollInterval: 10 * time.Millisecond, WaitTimeout: time.Second}
	ev := gp.MeasureHTTP(context.Background(), measurement())
	if !ev.Available {
		t.Fatalf("not available: %s", ev.Error)
	}
	if g := groupByName(ev, "Movistar"); !g.IsUnreachable() || g.Unreachable != 2 {
		t.Fatalf("Movistar %+v", g)
	}
	if g := groupByName(ev, "Orange"); !g.IsReachable() || g.OK != 1 {
		t.Fatalf("Orange %+v", g)
	}
	if g := groupByName(ev, "Vodafone"); !g.IsReachable() || g.Reached != 1 {
		t.Fatalf("Vodafone %+v", g)
	}
	if g := groupByName(ev, "DIGI"); g.Inconclusive != 2 || g.IsReachable() || g.IsUnreachable() {
		t.Fatalf("DIGI %+v", g)
	}
	if g := groupByName(ev, "control-de"); g.Role != detector.RoleControl || !g.IsReachable() {
		t.Fatalf("control %+v", g)
	}

	fake.mu.Lock()
	defer fake.mu.Unlock()
	if len(fake.bodies) != 5 {
		t.Fatalf("expected one measurement per group, got %d", len(fake.bodies))
	}
	body := fake.bodies[0]
	if body["type"] != "http" || body["target"] != "example.com" {
		t.Fatalf("body %+v", body)
	}
	for _, a := range fake.auth {
		if a != "Bearer gp-secret" {
			t.Fatalf("auth header %q", a)
		}
	}
}

func TestGlobalpingRateLimitMakesEvidenceUnavailable(t *testing.T) {
	fake, srv := newFakeGlobalping(nil)
	defer srv.Close()
	fake.rateHit = true
	gp := &sources.Globalping{BaseURL: srv.URL, WaitTimeout: time.Second}
	ev := gp.MeasureHTTP(context.Background(), measurement())
	if ev.Available || !strings.Contains(ev.Error, "rate limit") {
		t.Fatalf("%+v", ev)
	}
}

func TestGlobalpingGroupWithoutProbesIsAnError(t *testing.T) {
	_, srv := newFakeGlobalping(map[string][]probeOutcome{
		"Germany": {{status: "finished", statusCode: 200, resolved: "104.21.0.1"}},
	})
	defer srv.Close()
	gp := &sources.Globalping{BaseURL: srv.URL, PollInterval: 10 * time.Millisecond, WaitTimeout: time.Second}
	ev := gp.MeasureHTTP(context.Background(), measurement())
	if !ev.Available {
		t.Fatalf("partial results should still be available: %s", ev.Error)
	}
	if g := groupByName(ev, "Movistar"); g.Error == "" || g.Probes != 0 {
		t.Fatalf("%+v", g)
	}
}
