package collector_test

import (
	"context"
	"fmt"
	"io"
	"log/slog"
	"net/http"
	"net/http/httptest"
	"strings"
	"sync/atomic"
	"testing"
	"time"

	"github.com/alperdevv/laliga-bypass/internal/collector"
	"github.com/alperdevv/laliga-bypass/internal/config"
	"github.com/alperdevv/laliga-bypass/internal/monitor"
	"github.com/alperdevv/laliga-bypass/internal/sources"
	"github.com/alperdevv/laliga-bypass/internal/state"
)

type env struct {
	site       *httptest.Server
	feedBody   atomic.Value
	gpCreates  atomic.Int32
	collector  *collector.Collector
	domain     config.Domain
	clock      time.Time
	siteStatus atomic.Int32
}

func newEnv(t *testing.T) *env {
	t.Helper()
	e := &env{clock: time.Date(2026, 10, 17, 18, 0, 0, 0, time.UTC)}
	e.siteStatus.Store(200)
	e.site = httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(int(e.siteStatus.Load()))
	}))
	t.Cleanup(e.site.Close)
	e.setFeed(nil)
	feed := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		_, _ = io.WriteString(w, e.feedBody.Load().(string))
	}))
	t.Cleanup(feed.Close)
	gp := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.Method == http.MethodPost {
			n := e.gpCreates.Add(1)
			w.WriteHeader(http.StatusAccepted)
			_, _ = fmt.Fprintf(w, `{"id":"m%d","probesCount":1}`, n)
			return
		}
		_, _ = io.WriteString(w, `{"id":"m","status":"finished","results":[{"probe":{},"result":{"status":"finished","statusCode":200,"resolvedAddress":"127.0.0.1"}}]}`)
	}))
	t.Cleanup(gp.Close)

	hayaCfg := config.HayahoraConfig{Enabled: true, URL: feed.URL, RefreshInterval: time.Minute, MaxFeedAge: time.Hour}
	gpCfg := config.GlobalpingConfig{
		Enabled:     true,
		APIURL:      gp.URL,
		MinInterval: 10 * time.Minute,
		Targets:     []config.ProbeGroup{{Name: "Movistar", Magic: "ES+AS3352", Limit: 1}},
		Controls:    []config.ProbeGroup{{Name: "control", Magic: "Germany", Limit: 1}},
	}
	now := func() time.Time { return e.clock }
	e.collector = &collector.Collector{
		Checker:    &monitor.Checker{},
		Resolver:   monitor.Resolver{},
		Hayahora:   &sources.Hayahora{URL: feed.URL, RefreshInterval: time.Second, Now: now},
		Globalping: &sources.Globalping{BaseURL: gp.URL, PollInterval: 10 * time.Millisecond, WaitTimeout: time.Second, Now: now},
		HayaCfg:    hayaCfg,
		GPCfg:      gpCfg,
		Now:        now,
		Log:        slog.New(slog.NewTextHandler(io.Discard, nil)),
	}
	e.domain = config.Domain{
		Name:      "127.0.0.1",
		ZoneID:    "z",
		Endpoints: []config.Endpoint{{URL: e.site.URL + "/", ExpectedStatus: []int{200}, Timeout: time.Second}},
		Origin:    config.Origin{Address: strings.TrimPrefix(e.site.URL, "http://")},
		Records:   []config.Record{{RecordID: "r", ExpectedType: "A", ExpectedName: "x", ExpectedContent: "203.0.113.10"}},
	}
	return e
}

func (e *env) setFeed(blockedISPs []string) {
	var changes []string
	for _, isp := range blockedISPs {
		changes = append(changes, fmt.Sprintf(`{"ip":"127.0.0.1","isp":%q,"stateChanges":[{"timestamp":"2026-10-17 17:00:00Z","state":true}]}`, isp))
	}
	if len(changes) == 0 {
		changes = append(changes, `{"ip":"127.0.0.1","isp":"DIGI","stateChanges":[{"timestamp":"2026-10-17 17:00:00Z","state":false}]}`)
	}
	e.feedBody.Store(`{"lastUpdate":"2026-10-17 17:59:00Z","data":[` + strings.Join(changes, ",") + `]}`)
}

func (e *env) advance(d time.Duration) { e.clock = e.clock.Add(d) }

func TestHealthyNormalModeSpendsNoGlobalpingQuota(t *testing.T) {
	e := newEnv(t)
	ev := e.collector.Collect(context.Background(), e.domain, collector.Phase{Mode: state.ModeNormal})
	if ev.Origin[0].Outcome != monitor.OutcomeOK || ev.Edge[0].Outcome != monitor.OutcomeOK {
		t.Fatalf("local checks %+v %+v", ev.Origin, ev.Edge)
	}
	if len(ev.EdgeIPs) != 1 || ev.EdgeIPs[0] != "127.0.0.1" {
		t.Fatalf("edge IPs %v", ev.EdgeIPs)
	}
	if ev.Hayahora == nil || len(ev.Hayahora.TrackedIPs) != 1 {
		t.Fatalf("hayahora %+v", ev.Hayahora)
	}
	if e.gpCreates.Load() != 0 {
		t.Fatal("measurement launched without any sign of trouble")
	}
	if ev.Globalping == nil || ev.Globalping.Available {
		t.Fatalf("expected placeholder evidence, got %+v", ev.Globalping)
	}
}

func TestHayahoraHintTriggersRateLimitedMeasurement(t *testing.T) {
	e := newEnv(t)
	e.setFeed([]string{"Movistar", "Orange"})
	ctx := context.Background()
	ev := e.collector.Collect(ctx, e.domain, collector.Phase{Mode: state.ModeNormal})
	if e.gpCreates.Load() != 2 || !ev.Globalping.Available {
		t.Fatalf("expected one measurement per group, creates=%d ev=%+v", e.gpCreates.Load(), ev.Globalping)
	}
	e.advance(5 * time.Minute)
	e.collector.Collect(ctx, e.domain, collector.Phase{Mode: state.ModeNormal})
	if e.gpCreates.Load() != 2 {
		t.Fatal("measured again before min_interval")
	}
	e.advance(6 * time.Minute)
	e.collector.Collect(ctx, e.domain, collector.Phase{Mode: state.ModeNormal})
	if e.gpCreates.Load() != 4 {
		t.Fatal("did not measure again after min_interval")
	}
}

func TestEdgeAnomalyTriggersMeasurement(t *testing.T) {
	e := newEnv(t)
	e.siteStatus.Store(503)
	e.collector.Collect(context.Background(), e.domain, collector.Phase{Mode: state.ModeNormal})
	if e.gpCreates.Load() == 0 {
		t.Fatal("expected measurement on local anomaly")
	}
}

func TestContingencyChecksSavedEdgeIPsAndSkipsGlobalpingWithoutCanary(t *testing.T) {
	e := newEnv(t)
	e.setFeed([]string{"Movistar"})
	ev := e.collector.Collect(context.Background(), e.domain, collector.Phase{Mode: state.ModeContingency, SavedEdgeIPs: []string{"127.0.0.1", "198.51.100.1"}})
	if ev.Globalping != nil || e.gpCreates.Load() != 0 {
		t.Fatal("no canary: nothing to measure through Cloudflare")
	}
	if len(ev.Hayahora.CheckedIPs) != 2 || len(ev.Hayahora.BlockedBy["127.0.0.1"]) != 1 {
		t.Fatalf("hayahora %+v", ev.Hayahora)
	}
}

func TestRecoveryWaitsForVerifyDelayBeforeMeasuring(t *testing.T) {
	e := newEnv(t)
	ctx := context.Background()
	ph := collector.Phase{Mode: state.ModeRecovery, VerifyNotBefore: e.clock.Add(6 * time.Minute)}
	e.collector.Collect(ctx, e.domain, ph)
	if e.gpCreates.Load() != 0 {
		t.Fatal("measured before DNS TTL expiry")
	}
	e.advance(6 * time.Minute)
	ev := e.collector.Collect(ctx, e.domain, ph)
	if e.gpCreates.Load() == 0 || ev.Globalping.MeasuredAt.Before(ph.VerifyNotBefore) {
		t.Fatal("expected verification measurement after verify delay")
	}
}
