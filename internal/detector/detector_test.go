package detector_test

import (
	"strings"
	"testing"
	"time"

	"github.com/alperdevv/laliga-bypass/internal/detector"
	"github.com/alperdevv/laliga-bypass/internal/monitor"
)

var (
	now = time.Date(2026, 10, 17, 18, 0, 0, 0, time.UTC)
	cfg = detector.Config{MinISPs: 2, MinConfirmingSources: 2, HayahoraMaxFeedAge: 30 * time.Minute, GlobalpingMaxAge: 20 * time.Minute}
)

func ok(via string) monitor.CheckResult {
	return monitor.CheckResult{URL: "https://example.com/", Via: via, Outcome: monitor.OutcomeOK, Status: 200}
}

func result(via string, o monitor.Outcome, status int) monitor.CheckResult {
	return monitor.CheckResult{URL: "https://example.com/", Via: via, Outcome: o, Status: status}
}

func hayahora(blockedBy map[string][]string) *detector.HayahoraEvidence {
	return &detector.HayahoraEvidence{
		Available:  true,
		LastUpdate: now.Add(-time.Minute),
		CheckedIPs: []string{"104.21.0.1", "172.67.0.1"},
		TrackedIPs: []string{"104.21.0.1", "172.67.0.1"},
		BlockedBy:  blockedBy,
	}
}

func group(name string, role detector.ProbeRole, okN, unreachable int) detector.ProbeGroupResult {
	return detector.ProbeGroupResult{Name: name, Role: role, Probes: okN + unreachable, OK: okN, Unreachable: unreachable}
}

func globalping(groups ...detector.ProbeGroupResult) *detector.GlobalpingEvidence {
	return &detector.GlobalpingEvidence{Available: true, Target: "example.com", MeasuredAt: now.Add(-2 * time.Minute), Groups: groups}
}

func gpBlocked() *detector.GlobalpingEvidence {
	return globalping(
		group("Movistar", detector.RoleTarget, 0, 1),
		group("Orange", detector.RoleTarget, 0, 1),
		group("Vodafone", detector.RoleTarget, 1, 0),
		group("control-de", detector.RoleControl, 1, 0),
	)
}

func gpClear() *detector.GlobalpingEvidence {
	return globalping(
		group("Movistar", detector.RoleTarget, 1, 0),
		group("Orange", detector.RoleTarget, 1, 0),
		group("control-de", detector.RoleControl, 1, 0),
	)
}

func base() detector.Evidence {
	return detector.Evidence{
		Now:     now,
		Domain:  "example.com",
		Origin:  []monitor.CheckResult{ok("origin")},
		Edge:    []monitor.CheckResult{ok("edge")},
		EdgeIPs: []string{"104.21.0.1", "172.67.0.1"},
	}
}

func TestAssess(t *testing.T) {
	blockedTwoISPs := map[string][]string{"104.21.0.1": {"Movistar", "Orange"}}
	blockedOneISP := map[string][]string{"104.21.0.1": {"Movistar"}}

	tests := []struct {
		name   string
		mutate func(*detector.Evidence)
		want   detector.Verdict
	}{
		{
			name:   "everything healthy",
			mutate: func(e *detector.Evidence) { e.Hayahora = hayahora(nil); e.Globalping = gpClear() },
			want:   detector.VerdictHealthy,
		},
		{
			name: "two independent sources confirm a selective block",
			mutate: func(e *detector.Evidence) {
				e.Hayahora = hayahora(blockedTwoISPs)
				e.Globalping = gpBlocked()
			},
			want: detector.VerdictBlockConfirmed,
		},
		{
			name: "origin down wins over block evidence",
			mutate: func(e *detector.Evidence) {
				e.Origin = []monitor.CheckResult{result("origin", monitor.OutcomeTimeout, 0)}
				e.Edge = []monitor.CheckResult{result("edge", monitor.OutcomeServerError, 522)}
				e.Hayahora = hayahora(blockedTwoISPs)
				e.Globalping = gpBlocked()
			},
			want: detector.VerdictOriginDown,
		},
		{
			name: "origin connection refused is an origin outage",
			mutate: func(e *detector.Evidence) {
				e.Origin = []monitor.CheckResult{result("origin", monitor.OutcomeConnError, 0)}
			},
			want: detector.VerdictOriginDown,
		},
		{
			name: "application 5xx at origin is an application error",
			mutate: func(e *detector.Evidence) {
				e.Origin = []monitor.CheckResult{result("origin", monitor.OutcomeServerError, 500)}
				e.Edge = []monitor.CheckResult{result("edge", monitor.OutcomeServerError, 500)}
				e.Hayahora = hayahora(blockedTwoISPs)
				e.Globalping = gpBlocked()
			},
			want: detector.VerdictAppError,
		},
		{
			name: "single HTTP error through Cloudflare from this host is never a block",
			mutate: func(e *detector.Evidence) {
				e.Edge = []monitor.CheckResult{result("edge", monitor.OutcomeServerError, 502)}
				e.Hayahora = hayahora(nil)
			},
			want: detector.VerdictEdgeIssue,
		},
		{
			name: "only one source reports a block: suspected, not confirmed",
			mutate: func(e *detector.Evidence) {
				e.Hayahora = hayahora(blockedTwoISPs)
				e.Globalping = gpClear()
			},
			want: detector.VerdictBlockSuspected,
		},
		{
			name: "a single blocked probe does not count",
			mutate: func(e *detector.Evidence) {
				e.Hayahora = hayahora(nil)
				e.Globalping = globalping(
					group("Movistar", detector.RoleTarget, 0, 1),
					group("Orange", detector.RoleTarget, 1, 0),
					group("control-de", detector.RoleControl, 1, 0),
				)
			},
			want: detector.VerdictHealthy,
		},
		{
			name: "hayahora block on a single ISP is below min_isps",
			mutate: func(e *detector.Evidence) {
				e.Hayahora = hayahora(blockedOneISP)
				e.Globalping = gpBlocked()
			},
			want: detector.VerdictBlockSuspected,
		},
		{
			name: "control probes failing means a general outage",
			mutate: func(e *detector.Evidence) {
				e.Hayahora = hayahora(blockedTwoISPs)
				e.Globalping = globalping(
					group("Movistar", detector.RoleTarget, 0, 1),
					group("Orange", detector.RoleTarget, 0, 1),
					group("control-de", detector.RoleControl, 0, 1),
				)
			},
			want: detector.VerdictEdgeIssue,
		},
		{
			name: "stale hayahora feed does not count",
			mutate: func(e *detector.Evidence) {
				h := hayahora(blockedTwoISPs)
				h.LastUpdate = now.Add(-2 * time.Hour)
				e.Hayahora = h
				e.Globalping = gpBlocked()
			},
			want: detector.VerdictBlockSuspected,
		},
		{
			name: "stale Globalping measurement does not count",
			mutate: func(e *detector.Evidence) {
				e.Hayahora = hayahora(blockedTwoISPs)
				g := gpBlocked()
				g.MeasuredAt = now.Add(-time.Hour)
				e.Globalping = g
			},
			want: detector.VerdictBlockSuspected,
		},
		{
			name: "IPs not tracked by hayahora give no data",
			mutate: func(e *detector.Evidence) {
				h := hayahora(nil)
				h.TrackedIPs = nil
				e.Hayahora = h
				e.Globalping = gpBlocked()
			},
			want: detector.VerdictBlockSuspected,
		},
		{
			name:   "no external sources at all is healthy, never confirmed",
			mutate: func(e *detector.Evidence) {},
			want:   detector.VerdictHealthy,
		},
		{
			name: "unavailable sources cannot confirm",
			mutate: func(e *detector.Evidence) {
				e.Hayahora = &detector.HayahoraEvidence{Available: false, Error: "timeout"}
				e.Globalping = &detector.GlobalpingEvidence{Available: false, Error: "429"}
			},
			want: detector.VerdictHealthy,
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			ev := base()
			tt.mutate(&ev)
			a := detector.Assess(ev, cfg)
			if a.Verdict != tt.want {
				t.Fatalf("verdict %s, want %s; reasons: %s", a.Verdict, tt.want, strings.Join(a.Reasons, " | "))
			}
			if len(a.Reasons) == 0 && a.Verdict != detector.VerdictHealthy {
				t.Fatal("non-healthy verdict without reasons")
			}
		})
	}
}

func TestAssessWithSingleSourceConfigured(t *testing.T) {
	ev := base()
	ev.Hayahora = hayahora(map[string][]string{"104.21.0.1": {"Movistar", "DIGI"}})
	one := cfg
	one.MinConfirmingSources = 1
	if a := detector.Assess(ev, one); a.Verdict != detector.VerdictBlockConfirmed {
		t.Fatalf("verdict %s", a.Verdict)
	}
}

func TestAssessRecovery(t *testing.T) {
	tests := []struct {
		name   string
		mutate func(*detector.Evidence)
		clear  bool
	}{
		{"hayahora reports saved IPs unblocked", func(e *detector.Evidence) { e.Hayahora = hayahora(nil) }, true},
		{"any ISP still blocking prevents recovery", func(e *detector.Evidence) {
			e.Hayahora = hayahora(map[string][]string{"104.21.0.1": {"Movistar"}})
		}, false},
		{"no data is never a recovery", func(e *detector.Evidence) {
			h := hayahora(nil)
			h.TrackedIPs = nil
			e.Hayahora = h
		}, false},
		{"unavailable feed is never a recovery", func(e *detector.Evidence) {
			e.Hayahora = &detector.HayahoraEvidence{Available: false, Error: "down"}
		}, false},
		{"canary clear but hayahora still blocked", func(e *detector.Evidence) {
			e.Hayahora = hayahora(map[string][]string{"104.21.0.1": {"Movistar", "Orange"}})
			e.Globalping = gpClear()
		}, false},
		{"canary clear and hayahora clear", func(e *detector.Evidence) {
			e.Hayahora = hayahora(nil)
			e.Globalping = gpClear()
		}, true},
		{"canary clear without hayahora data", func(e *detector.Evidence) {
			e.Globalping = gpClear()
		}, true},
		{"one canary probe still failing", func(e *detector.Evidence) {
			e.Globalping = globalping(
				group("Movistar", detector.RoleTarget, 0, 1),
				group("Orange", detector.RoleTarget, 1, 0),
				group("control-de", detector.RoleControl, 1, 0),
			)
		}, false},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			ev := base()
			tt.mutate(&ev)
			r := detector.AssessRecovery(ev, cfg)
			if r.Clear != tt.clear {
				t.Fatalf("clear=%v want %v: %s", r.Clear, tt.clear, strings.Join(r.Reasons, " | "))
			}
		})
	}
}

func TestAssessVerification(t *testing.T) {
	restoredAt := now.Add(-10 * time.Minute)
	notBefore := restoredAt.Add(6 * time.Minute)

	t.Run("measurement before TTL expiry is ignored", func(t *testing.T) {
		ev := base()
		g := gpClear()
		g.MeasuredAt = restoredAt.Add(time.Minute)
		ev.Globalping = g
		v := detector.AssessVerification(ev, notBefore, cfg)
		if v.Verified || v.Failed {
			t.Fatalf("%+v", v)
		}
	})
	t.Run("fresh clear measurement verifies", func(t *testing.T) {
		ev := base()
		ev.Globalping = gpClear()
		if v := detector.AssessVerification(ev, notBefore, cfg); !v.Verified {
			t.Fatalf("%+v", v)
		}
	})
	t.Run("block persists", func(t *testing.T) {
		ev := base()
		ev.Globalping = gpBlocked()
		if v := detector.AssessVerification(ev, notBefore, cfg); !v.Failed {
			t.Fatalf("%+v", v)
		}
	})
	t.Run("probes resolving to origin are inconclusive", func(t *testing.T) {
		ev := base()
		ev.Globalping = globalping(
			detector.ProbeGroupResult{Name: "Movistar", Role: detector.RoleTarget, Probes: 1, Inconclusive: 1},
			group("control-de", detector.RoleControl, 1, 0),
		)
		if v := detector.AssessVerification(ev, notBefore, cfg); v.Verified || v.Failed {
			t.Fatalf("%+v", v)
		}
	})
	t.Run("unavailable Globalping keeps it pending", func(t *testing.T) {
		ev := base()
		ev.Globalping = &detector.GlobalpingEvidence{Available: false, Error: "429"}
		if v := detector.AssessVerification(ev, notBefore, cfg); v.Verified || v.Failed {
			t.Fatalf("%+v", v)
		}
	})
	t.Run("without Globalping, fresh hayahora clear is a weak verification", func(t *testing.T) {
		ev := base()
		ev.Hayahora = hayahora(nil)
		v := detector.AssessVerification(ev, notBefore, cfg)
		if !v.Verified || !strings.Contains(v.Reasons[0], "weak") {
			t.Fatalf("%+v", v)
		}
	})
}
