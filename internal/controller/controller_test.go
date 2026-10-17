package controller_test

import (
	"context"
	"io"
	"log/slog"
	"path/filepath"
	"slices"
	"testing"
	"time"

	"github.com/alperdevv/laliga-bypass/internal/cloudflare"
	"github.com/alperdevv/laliga-bypass/internal/cloudflare/cftest"
	"github.com/alperdevv/laliga-bypass/internal/collector"
	"github.com/alperdevv/laliga-bypass/internal/config"
	"github.com/alperdevv/laliga-bypass/internal/controller"
	"github.com/alperdevv/laliga-bypass/internal/detector"
	"github.com/alperdevv/laliga-bypass/internal/monitor"
	"github.com/alperdevv/laliga-bypass/internal/notifier"
	"github.com/alperdevv/laliga-bypass/internal/state"
)

const (
	token    = "cf-test-token"
	zoneID   = "zone1"
	recordID = "rec-apex"
	wwwID    = "rec-www"
	originIP = "203.0.113.10"
)

var edgeIPs = []string{"104.21.0.1", "172.67.0.1"}

type scenario string

const (
	sHealthy       scenario = "healthy"
	sBlocked       scenario = "blocked"
	sOneSource     scenario = "one_source"
	sOneProbe      scenario = "one_probe"
	sOriginDown    scenario = "origin_down"
	sBlockedOrigin scenario = "blocked_and_origin_down"
)

type fakeCollector struct {
	clock    *clock
	scenario scenario
	phases   []collector.Phase
}

func (f *fakeCollector) Collect(_ context.Context, d config.Domain, ph collector.Phase) detector.Evidence {
	f.phases = append(f.phases, ph)
	now := f.clock.Now()
	ev := detector.Evidence{
		Now:     now,
		Domain:  d.Name,
		Origin:  []monitor.CheckResult{{URL: d.Endpoints[0].URL, Via: "origin", Outcome: monitor.OutcomeOK, Status: 200}},
		Edge:    []monitor.CheckResult{{URL: d.Endpoints[0].URL, Via: "edge", Outcome: monitor.OutcomeOK, Status: 200}},
		EdgeIPs: edgeIPs,
	}
	blocked := map[string][]string{"104.21.0.1": {"DIGI", "Movistar", "Orange"}}
	h := &detector.HayahoraEvidence{Available: true, LastUpdate: now.Add(-time.Minute), CheckedIPs: edgeIPs, TrackedIPs: edgeIPs, BlockedBy: map[string][]string{}}
	g := &detector.GlobalpingEvidence{Available: true, Target: "example.com", MeasuredAt: now.Add(-time.Minute), Groups: []detector.ProbeGroupResult{
		{Name: "Movistar", Role: detector.RoleTarget, Probes: 1, OK: 1},
		{Name: "Orange", Role: detector.RoleTarget, Probes: 1, OK: 1},
		{Name: "control", Role: detector.RoleControl, Probes: 1, OK: 1},
	}}
	if ph.Mode == state.ModeContingency {
		h.CheckedIPs, h.TrackedIPs = ph.SavedEdgeIPs, ph.SavedEdgeIPs
		ev.Globalping = nil
	}
	switch f.scenario {
	case sBlocked, sBlockedOrigin:
		h.BlockedBy = blocked
		g.Groups[0] = detector.ProbeGroupResult{Name: "Movistar", Role: detector.RoleTarget, Probes: 1, Unreachable: 1}
		g.Groups[1] = detector.ProbeGroupResult{Name: "Orange", Role: detector.RoleTarget, Probes: 1, Unreachable: 1}
	case sOneSource:
		h.BlockedBy = blocked
	case sOneProbe:
		g.Groups[0] = detector.ProbeGroupResult{Name: "Movistar", Role: detector.RoleTarget, Probes: 1, Unreachable: 1}
	}
	if f.scenario == sOriginDown || f.scenario == sBlockedOrigin {
		ev.Origin[0].Outcome, ev.Origin[0].Status = monitor.OutcomeTimeout, 0
		ev.Edge[0].Outcome, ev.Edge[0].Status = monitor.OutcomeServerError, 522
	}
	ev.Hayahora = h
	if ph.Mode != state.ModeContingency {
		ev.Globalping = g
	}
	return ev
}

type clock struct{ t time.Time }

func (c *clock) Now() time.Time          { return c.t }
func (c *clock) Advance(d time.Duration) { c.t = c.t.Add(d) }

type harness struct {
	t         *testing.T
	cf        *cftest.Server
	clock     *clock
	collector *fakeCollector
	events    *notifier.Recorder
	store     state.Store
	cfg       *config.Config
	ctrl      *controller.Controller
}

func testConfig(dryRun bool) *config.Config {
	cfg := config.Default()
	cfg.DryRun = dryRun
	cfg.PollInterval = 30 * time.Second
	cfg.Controller = config.ControllerConfig{
		MinFailures:       3,
		RecoveryWindow:    10 * time.Minute,
		MaxContingency:    60 * time.Minute,
		MinChangeInterval: 15 * time.Minute,
		VerifyDelay:       6 * time.Minute,
		VerifyTimeout:     45 * time.Minute,
		ManualHold:        6 * time.Hour,
	}
	cfg.Domains = []config.Domain{{
		Name:      "example.com",
		ZoneID:    zoneID,
		Endpoints: []config.Endpoint{{URL: "https://example.com/", ExpectedStatus: []int{200}, Timeout: time.Second}},
		Origin:    config.Origin{Address: originIP + ":443"},
		Records: []config.Record{
			{RecordID: recordID, ExpectedType: "A", ExpectedName: "example.com", ExpectedContent: originIP},
			{RecordID: wwwID, ExpectedType: "CNAME", ExpectedName: "www.example.com", ExpectedContent: "example.com"},
		},
	}}
	return cfg
}

func newHarness(t *testing.T, dryRun bool) *harness {
	t.Helper()
	cf := cftest.New(token)
	t.Cleanup(cf.Close)
	cf.AddZone(zoneID, "example.com")
	cf.AddRecord(zoneID, cloudflare.Record{ID: recordID, Name: "example.com", Type: "A", Content: originIP, Proxied: true, Proxiable: true, TTL: 1})
	cf.AddRecord(zoneID, cloudflare.Record{ID: wwwID, Name: "www.example.com", Type: "CNAME", Content: "example.com", Proxied: true, Proxiable: true, TTL: 1})
	cf.AddRecord(zoneID, cloudflare.Record{ID: "rec-mx", Name: "example.com", Type: "MX", Content: "mail.example.com", TTL: 3600})
	cf.AddRecord(zoneID, cloudflare.Record{ID: "rec-mail", Name: "mail.example.com", Type: "A", Content: "203.0.113.20", Proxied: false, TTL: 3600})
	cf.AddRecord(zoneID, cloudflare.Record{ID: "rec-api", Name: "api.example.com", Type: "A", Content: "203.0.113.30", Proxied: true, TTL: 1})

	clk := &clock{t: time.Date(2026, 10, 17, 18, 0, 0, 0, time.UTC)}
	h := &harness{
		t:         t,
		cf:        cf,
		clock:     clk,
		collector: &fakeCollector{clock: clk, scenario: sHealthy},
		events:    &notifier.Recorder{},
		store:     state.Store{Path: filepath.Join(t.TempDir(), "state.json")},
		cfg:       testConfig(dryRun),
	}
	h.restart()
	return h
}

func (h *harness) restart() {
	h.t.Helper()
	dns, err := cloudflare.New(cloudflare.Options{
		BaseURL: h.cf.BaseURL(),
		Token:   token,
		DryRun:  h.cfg.DryRun,
		Allowlist: []cloudflare.RecordRef{
			{ZoneID: zoneID, RecordID: recordID},
			{ZoneID: zoneID, RecordID: wwwID},
		},
	})
	if err != nil {
		h.t.Fatal(err)
	}
	ctrl, err := controller.New(context.Background(), controller.Options{
		Config:    h.cfg,
		Collector: h.collector,
		DNS:       dns,
		Store:     h.store,
		Notifier:  h.events,
		Logger:    slog.New(slog.NewTextHandler(io.Discard, nil)),
		Now:       h.clock.Now,
	})
	if err != nil {
		h.t.Fatal(err)
	}
	h.ctrl = ctrl
}

func (h *harness) cycles(n int) {
	h.t.Helper()
	for range n {
		if err := h.ctrl.RunOnce(context.Background()); err != nil {
			h.t.Fatal(err)
		}
		h.clock.Advance(h.cfg.PollInterval)
	}
}

func (h *harness) runFor(d time.Duration) {
	h.t.Helper()
	h.cycles(int(d / h.cfg.PollInterval))
}

func (h *harness) domain() *state.DomainState {
	st, err := h.store.Load()
	if err != nil {
		h.t.Fatal(err)
	}
	return st.Domains["example.com"]
}

func (h *harness) proxied(id string) bool { return h.cf.Record(zoneID, id).Proxied }

func (h *harness) hasEvent(kind string) bool { return slices.Contains(h.events.Kinds(), kind) }

func (h *harness) assertUntouchedNonAllowlisted() {
	h.t.Helper()
	for _, r := range h.cf.Requests() {
		for _, forbidden := range []string{"rec-mx", "rec-mail", "rec-api"} {
			if filepath.Base(r.Path) == forbidden {
				h.t.Fatalf("request touched non-allowlisted record: %+v", r)
			}
		}
	}
	if !h.cf.Record(zoneID, "rec-api").Proxied || h.cf.Record(zoneID, "rec-mail").Proxied {
		h.t.Fatal("non-allowlisted record changed")
	}
}

func TestHealthyNeverTouchesDNS(t *testing.T) {
	h := newHarness(t, false)
	h.cycles(20)
	if h.cf.Count("PATCH") != 0 {
		t.Fatal("PATCH sent while healthy")
	}
	if h.domain().Mode != state.ModeNormal {
		t.Fatal("mode changed")
	}
}

func TestOriginDownDoesNotActivateContingency(t *testing.T) {
	h := newHarness(t, false)
	h.collector.scenario = sBlockedOrigin
	h.cycles(10)
	if h.cf.Count("PATCH") != 0 || h.domain().Mode != state.ModeNormal {
		t.Fatal("contingency activated with origin down")
	}
	if h.domain().LastVerdict != string(detector.VerdictOriginDown) || !h.hasEvent("assessment_changed") {
		t.Fatalf("verdict %q events %v", h.domain().LastVerdict, h.events.Kinds())
	}
}

func TestSingleProbeBlockDoesNotActivate(t *testing.T) {
	h := newHarness(t, false)
	h.collector.scenario = sOneProbe
	h.cycles(10)
	if h.cf.Count("PATCH") != 0 || h.domain().Mode != state.ModeNormal {
		t.Fatal("activated on a single probe")
	}
}

func TestSingleSourceOnlyAlertsAndStaysNormal(t *testing.T) {
	h := newHarness(t, false)
	h.collector.scenario = sOneSource
	h.cycles(10)
	if h.cf.Count("PATCH") != 0 || h.domain().Mode != state.ModeNormal {
		t.Fatal("activated with insufficient evidence")
	}
	if h.domain().LastVerdict != string(detector.VerdictBlockSuspected) || !h.hasEvent("assessment_changed") {
		t.Fatalf("expected suspected alert, verdict %q", h.domain().LastVerdict)
	}
}

func TestSelectiveBlockActivatesAfterMinFailures(t *testing.T) {
	h := newHarness(t, false)
	h.collector.scenario = sBlocked
	h.cycles(2)
	if h.cf.Count("PATCH") != 0 {
		t.Fatal("activated before min_failures")
	}
	h.cycles(1)
	if h.proxied(recordID) || h.proxied(wwwID) {
		t.Fatal("records still proxied after confirmed block")
	}
	ds := h.domain()
	if ds.Mode != state.ModeContingency || ds.Simulated || len(ds.Pending()) != 2 {
		t.Fatalf("state %+v", ds)
	}
	ch := ds.Changes[recordID]
	if !ch.Original.Proxied || ch.Applied.Proxied || ch.Original.Content != originIP || ch.Applied.ModifiedOn.IsZero() {
		t.Fatalf("change %+v", ch)
	}
	if !slices.Equal(ds.EdgeIPs, edgeIPs) {
		t.Fatalf("edge IPs not saved: %v", ds.EdgeIPs)
	}
	if !h.hasEvent("contingency_activated") {
		t.Fatal("no activation event")
	}
	h.assertUntouchedNonAllowlisted()
}

func TestDryRunNeverModifiesRecordsAcrossFullCycle(t *testing.T) {
	h := newHarness(t, true)
	h.collector.scenario = sBlocked
	h.cycles(5)
	if ds := h.domain(); ds.Mode != state.ModeContingency || !ds.Simulated {
		t.Fatalf("expected simulated contingency, got %+v", ds)
	}
	h.collector.scenario = sHealthy
	h.runFor(16 * time.Minute)
	if ds := h.domain(); ds.Mode != state.ModeRecovery {
		t.Fatalf("expected simulated recovery, got %s", ds.Mode)
	}
	h.runFor(8 * time.Minute)
	if ds := h.domain(); ds.Mode != state.ModeNormal {
		t.Fatalf("expected normal, got %s", ds.Mode)
	}
	if n := h.cf.Count("PATCH"); n != 0 {
		t.Fatalf("DRY_RUN sent %d PATCH requests", n)
	}
	if !h.proxied(recordID) || !h.proxied(wwwID) {
		t.Fatal("record modified in DRY_RUN")
	}
	if h.cf.Count("GET") == 0 {
		t.Fatal("dry run should still validate records with read-only calls")
	}
	h.assertUntouchedNonAllowlisted()
}

func TestRecoveryRestoresAndIsVerifiedExternally(t *testing.T) {
	h := newHarness(t, false)
	h.collector.scenario = sBlocked
	h.cycles(3)
	if h.proxied(recordID) {
		t.Fatal("not activated")
	}

	h.collector.scenario = sHealthy
	h.runFor(9 * time.Minute)
	if h.proxied(recordID) {
		t.Fatal("restored before recovery window")
	}
	h.runFor(7 * time.Minute)
	if !h.proxied(recordID) || !h.proxied(wwwID) {
		t.Fatal("not restored after recovery window")
	}
	ds := h.domain()
	if ds.Mode != state.ModeRecovery {
		t.Fatalf("expected recovery (pending verification), got %s", ds.Mode)
	}
	if h.hasEvent("recovery_verified") {
		t.Fatal("recovery claimed before external verification")
	}
	h.runFor(5 * time.Minute)
	if h.domain().Mode != state.ModeRecovery {
		t.Fatal("verified before verify_delay")
	}
	h.runFor(2 * time.Minute)
	if h.domain().Mode != state.ModeNormal || !h.hasEvent("recovery_verified") {
		t.Fatalf("not verified: mode %s events %v", h.domain().Mode, h.events.Kinds())
	}
	if h.cf.Count("PATCH") != 4 {
		t.Fatalf("expected 4 PATCH (2 off, 2 on), got %d", h.cf.Count("PATCH"))
	}
	h.assertUntouchedNonAllowlisted()
}

func TestBlockReturningResetsRecoveryWindow(t *testing.T) {
	h := newHarness(t, false)
	h.collector.scenario = sBlocked
	h.cycles(3)
	h.collector.scenario = sHealthy
	h.runFor(8 * time.Minute)
	h.collector.scenario = sBlocked
	h.cycles(1)
	h.collector.scenario = sHealthy
	h.runFor(8 * time.Minute)
	if h.proxied(recordID) {
		t.Fatal("recovery window not reset by renewed block")
	}
	h.runFor(3 * time.Minute)
	if !h.proxied(recordID) {
		t.Fatal("not restored after a full clear window")
	}
}

func TestManualChangeDuringContingencyIsNeverOverwritten(t *testing.T) {
	h := newHarness(t, false)
	h.collector.scenario = sBlocked
	h.cycles(3)
	h.cf.ManualEdit(zoneID, recordID, func(r *cloudflare.Record) { r.Content = "198.51.100.99" })
	h.cycles(1)
	ds := h.domain()
	if ds.Changes[recordID].Status != state.ChangeReleased || !h.hasEvent("manual_change_detected") {
		t.Fatalf("manual change not detected: %+v", ds.Changes[recordID])
	}
	h.collector.scenario = sHealthy
	h.runFor(30 * time.Minute)
	rec := h.cf.Record(zoneID, recordID)
	if rec.Proxied || rec.Content != "198.51.100.99" {
		t.Fatalf("manually changed record was overwritten: %+v", rec)
	}
	if !h.proxied(wwwID) {
		t.Fatal("untouched record should still be restored")
	}
}

func TestManualReenableOfProxyReleasesContingency(t *testing.T) {
	h := newHarness(t, false)
	h.collector.scenario = sBlocked
	h.cycles(3)
	h.cf.ManualEdit(zoneID, recordID, func(r *cloudflare.Record) { r.Proxied = true })
	h.cf.ManualEdit(zoneID, wwwID, func(r *cloudflare.Record) { r.Proxied = true })
	patches := h.cf.Count("PATCH")
	h.cycles(1)
	if h.domain().Mode != state.ModeNormal || !h.hasEvent("contingency_released") {
		t.Fatalf("expected release, mode %s", h.domain().Mode)
	}
	h.runFor(2 * time.Hour)
	if h.cf.Count("PATCH") != patches {
		t.Fatal("service modified records after a manual takeover")
	}
	if !h.hasEvent("manual_hold") {
		t.Fatal("expected manual_hold alert")
	}
}

func TestStaleRestoreIsRefusedWhenRecordChangedAfterOurChange(t *testing.T) {
	h := newHarness(t, false)
	h.collector.scenario = sBlocked
	h.cycles(3)
	h.collector.scenario = sHealthy
	h.runFor(10 * time.Minute)
	h.cf.ManualEdit(zoneID, wwwID, func(r *cloudflare.Record) { r.TTL = 300 })
	h.runFor(6 * time.Minute)
	if h.proxied(wwwID) {
		t.Fatal("restored a record that changed after the service modified it")
	}
	if !h.hasEvent("manual_change_detected") {
		t.Fatal("no manual change event")
	}
	if !h.proxied(recordID) {
		t.Fatal("unchanged record should be restored")
	}
}

func TestRestartDuringContingencyResumesAndRestores(t *testing.T) {
	h := newHarness(t, false)
	h.collector.scenario = sBlocked
	h.cycles(3)
	if h.proxied(recordID) {
		t.Fatal("not activated")
	}
	h.restart()
	h.collector.scenario = sHealthy
	h.cycles(1)
	if len(h.collector.phases) == 0 {
		t.Fatal("collector not called")
	}
	last := h.collector.phases[len(h.collector.phases)-1]
	if last.Mode != state.ModeContingency || !slices.Equal(last.SavedEdgeIPs, edgeIPs) {
		t.Fatalf("state not resumed after restart: %+v", last)
	}
	h.restart()
	h.runFor(16 * time.Minute)
	if !h.proxied(recordID) || !h.proxied(wwwID) {
		t.Fatal("not restored after restarts")
	}
	if h.cf.Count("PATCH") != 4 {
		t.Fatalf("expected exactly 4 PATCH, got %d", h.cf.Count("PATCH"))
	}
}

func TestPreconditionMismatchAbortsActivation(t *testing.T) {
	h := newHarness(t, false)
	h.cf.ManualEdit(zoneID, wwwID, func(r *cloudflare.Record) { r.Content = "other.example.net" })
	h.collector.scenario = sBlocked
	h.cycles(5)
	if h.cf.Count("PATCH") != 0 {
		t.Fatal("PATCH sent despite precondition mismatch")
	}
	if h.domain().Mode != state.ModeNormal || !h.hasEvent("activation_aborted") {
		t.Fatal("expected aborted activation")
	}
}

func TestAlreadyDNSOnlyRecordIsNotAdopted(t *testing.T) {
	h := newHarness(t, false)
	h.cf.ManualEdit(zoneID, recordID, func(r *cloudflare.Record) { r.Proxied = false })
	h.collector.scenario = sBlocked
	h.cycles(5)
	if h.cf.Count("PATCH") != 0 || !h.hasEvent("activation_aborted") {
		t.Fatal("service adopted a record it did not change")
	}
}

func TestMaxContingencyAlertsOnce(t *testing.T) {
	h := newHarness(t, false)
	h.collector.scenario = sBlocked
	h.cycles(3)
	h.runFor(70 * time.Minute)
	n := 0
	for _, k := range h.events.Kinds() {
		if k == "max_contingency" {
			n++
		}
	}
	if n != 1 {
		t.Fatalf("expected one max_contingency alert, got %d", n)
	}
	if h.proxied(recordID) {
		t.Fatal("max_contingency must alert, not restore on its own")
	}
}

func TestMinChangeIntervalPreventsFlapping(t *testing.T) {
	h := newHarness(t, false)
	h.cfg.Controller.MinChangeInterval = 30 * time.Minute
	h.collector.scenario = sBlocked
	h.cycles(3)
	h.collector.scenario = sHealthy
	h.runFor(31 * time.Minute)
	if h.domain().Mode != state.ModeRecovery {
		t.Fatalf("expected recovery, got %s", h.domain().Mode)
	}
	patches := h.cf.Count("PATCH")
	h.collector.scenario = sBlocked
	h.cycles(10)
	if h.cf.Count("PATCH") != patches {
		t.Fatal("re-activated before min_change_interval")
	}
	if !h.hasEvent("change_held") {
		t.Fatalf("expected change_held, got %v", h.events.Kinds())
	}
	h.runFor(26 * time.Minute)
	if !h.hasEvent("verification_failed") {
		t.Fatalf("expected verification_failed, got %v", h.events.Kinds())
	}
	if h.proxied(recordID) {
		t.Fatal("should re-activate once min_change_interval has elapsed")
	}
}

func TestPatchFailureLeavesConsistentState(t *testing.T) {
	h := newHarness(t, false)
	h.collector.scenario = sBlocked
	h.cycles(2)
	h.cf.FailNext("PATCH", 1)
	h.cycles(1)
	if h.domain().Mode != state.ModeNormal || !h.hasEvent("activation_failed") {
		t.Fatalf("mode %s", h.domain().Mode)
	}
	if !h.proxied(recordID) {
		t.Fatal("record changed despite failure")
	}
}

func TestSwitchingFromDryRunDiscardsSimulatedState(t *testing.T) {
	h := newHarness(t, true)
	h.collector.scenario = sBlocked
	h.cycles(3)
	if !h.domain().Simulated {
		t.Fatal("expected simulated contingency")
	}
	h.cfg.DryRun = false
	h.restart()
	ds := h.domain()
	if ds.Mode != state.ModeNormal || len(ds.Pending()) != 0 || !h.hasEvent("simulated_state_discarded") {
		t.Fatalf("simulated state survived: %+v", ds)
	}
	h.collector.scenario = sHealthy
	h.cycles(5)
	if h.cf.Count("PATCH") != 0 {
		t.Fatal("restored records that were never changed")
	}
}

func TestDryRunAfterRealChangeNeverMarksItRestored(t *testing.T) {
	h := newHarness(t, false)
	h.collector.scenario = sBlocked
	h.cycles(3)
	h.cfg.DryRun = true
	h.restart()
	if !h.hasEvent("real_changes_pending_in_dry_run") {
		t.Fatal("expected critical alert about pending real changes")
	}
	h.collector.scenario = sHealthy
	h.runFor(30 * time.Minute)
	ds := h.domain()
	if len(ds.Pending()) != 2 || ds.Mode != state.ModeContingency {
		t.Fatalf("real changes lost in dry run: %+v", ds)
	}
	if h.cf.Count("PATCH") != 2 {
		t.Fatal("DRY_RUN modified records")
	}
}

func TestManualRollback(t *testing.T) {
	h := newHarness(t, false)
	h.collector.scenario = sBlocked
	h.cycles(3)
	if err := h.ctrl.Rollback(context.Background(), "example.com"); err != nil {
		t.Fatal(err)
	}
	if !h.proxied(recordID) || !h.proxied(wwwID) {
		t.Fatal("rollback did not restore")
	}
	if h.domain().Mode != state.ModeRecovery {
		t.Fatalf("mode %s", h.domain().Mode)
	}
	if err := h.ctrl.Rollback(context.Background(), "example.com"); err == nil {
		t.Fatal("second rollback should report nothing pending")
	}
}

func TestMatchExpected(t *testing.T) {
	rec := config.Record{RecordID: "r", ExpectedType: "AAAA", ExpectedName: "example.com", ExpectedContent: "2001:db8::1"}
	live := cloudflare.Record{ID: "r", Name: "Example.COM.", Type: "AAAA", Content: "2001:0db8:0:0:0:0:0:1"}
	if p := controller.MatchExpected(rec, live); len(p) != 0 {
		t.Fatalf("unexpected mismatch %v", p)
	}
	live.Content = "2001:db8::2"
	if p := controller.MatchExpected(rec, live); len(p) != 1 {
		t.Fatalf("expected content mismatch, got %v", p)
	}
}
