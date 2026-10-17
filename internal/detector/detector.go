package detector

import (
	"fmt"
	"slices"
	"sort"
	"strings"
	"time"

	"github.com/alperdevv/laliga-bypass/internal/monitor"
)

type Config struct {
	MinISPs              int
	MinConfirmingSources int
	HayahoraMaxFeedAge   time.Duration
	GlobalpingMaxAge     time.Duration
}

type Verdict string

const (
	VerdictHealthy        Verdict = "healthy"
	VerdictOriginDown     Verdict = "origin_down"
	VerdictAppError       Verdict = "app_error"
	VerdictEdgeIssue      Verdict = "edge_issue"
	VerdictBlockSuspected Verdict = "block_suspected"
	VerdictBlockConfirmed Verdict = "block_confirmed"
)

type Signal string

const (
	SignalBlock       Signal = "block"
	SignalClear       Signal = "clear"
	SignalGlobalIssue Signal = "global_issue"
	SignalNoData      Signal = "no_data"
	SignalUnavailable Signal = "unavailable"
)

type SourceSignal struct {
	Source      string   `json:"source"`
	Signal      Signal   `json:"signal"`
	Detail      string   `json:"detail"`
	BlockedISPs []string `json:"blocked_isps,omitempty"`
}

type Assessment struct {
	Verdict Verdict        `json:"verdict"`
	Reasons []string       `json:"reasons"`
	Sources []SourceSignal `json:"sources"`
}

func Assess(ev Evidence, cfg Config) Assessment {
	signals := externalSignals(ev, cfg)
	a := Assessment{Sources: signals, Reasons: signalReasons(signals)}
	blocking := countSignal(signals, SignalBlock)
	prepend := func(v Verdict, reason string) Assessment {
		a.Verdict = v
		a.Reasons = append([]string{reason}, a.Reasons...)
		return a
	}

	if len(ev.Origin) == 0 {
		if blocking > 0 {
			return prepend(VerdictBlockSuspected, "no origin check available: an origin outage cannot be ruled out, nothing is confirmed")
		}
		return prepend(VerdictHealthy, "no origin check available")
	}
	if bad := failing(ev.Origin, func(r monitor.CheckResult) bool { return !r.Outcome.Reachable() }); len(bad) > 0 {
		out := prepend(VerdictOriginDown, "origin unreachable on direct connection: "+describe(bad))
		if blocking > 0 {
			out.Reasons = append(out.Reasons, "external sources report a block, but DNS-only cannot help while the origin is down")
		}
		return out
	}
	if bad := failing(ev.Origin, func(r monitor.CheckResult) bool { return r.Outcome == monitor.OutcomeServerError }); len(bad) > 0 {
		return prepend(VerdictAppError, "origin answers with application errors: "+describe(bad))
	}
	if bad := failing(ev.Edge, func(r monitor.CheckResult) bool { return r.Outcome != monitor.OutcomeOK }); len(bad) > 0 {
		return prepend(VerdictEdgeIssue, "the Cloudflare path also fails from this host: "+describe(bad))
	}
	if countSignal(signals, SignalGlobalIssue) > 0 {
		return prepend(VerdictEdgeIssue, "control probes fail too: this is not a selective block")
	}

	switch {
	case blocking >= cfg.MinConfirmingSources:
		return prepend(VerdictBlockConfirmed, fmt.Sprintf("%d independent external sources report a selective block (minimum %d)", blocking, cfg.MinConfirmingSources))
	case blocking > 0:
		return prepend(VerdictBlockSuspected, fmt.Sprintf("only %d external source(s) report a block (minimum %d): staying in normal mode", blocking, cfg.MinConfirmingSources))
	default:
		a.Verdict = VerdictHealthy
		return a
	}
}

type RecoveryAssessment struct {
	Clear   bool           `json:"clear"`
	Reasons []string       `json:"reasons"`
	Sources []SourceSignal `json:"sources"`
}

func AssessRecovery(ev Evidence, cfg Config) RecoveryAssessment {
	strict := cfg
	strict.MinISPs = 1
	signals := externalSignals(ev, strict)
	r := RecoveryAssessment{Sources: signals, Reasons: signalReasons(signals)}
	clear := countSignal(signals, SignalClear)
	blocked := countSignal(signals, SignalBlock) + countSignal(signals, SignalGlobalIssue)
	switch {
	case blocked > 0:
		r.Reasons = append([]string{"at least one external source reports the block is still active"}, r.Reasons...)
	case clear == 0:
		r.Reasons = append([]string{"no external source can confirm the block has ended"}, r.Reasons...)
	default:
		r.Clear = true
		r.Reasons = append([]string{fmt.Sprintf("%d external source(s) report the block has ended and none contradicts it", clear)}, r.Reasons...)
	}
	return r
}

type VerificationResult struct {
	Verified bool     `json:"verified"`
	Failed   bool     `json:"failed"`
	Reasons  []string `json:"reasons"`
}

func AssessVerification(ev Evidence, notBefore time.Time, cfg Config) VerificationResult {
	g := ev.Globalping
	if g == nil {
		h := hayahoraSignal(ev.Hayahora, ev.Now, Config{MinISPs: 1, HayahoraMaxFeedAge: cfg.HayahoraMaxFeedAge})
		switch {
		case h.Signal == SignalClear && ev.Hayahora.LastUpdate.After(notBefore):
			return VerificationResult{Verified: true, Reasons: []string{"verified by hayahora only (current IPs not blocked); Globalping disabled, weak verification"}}
		case h.Signal == SignalBlock:
			return VerificationResult{Failed: true, Reasons: []string{"hayahora reports current IPs still blocked: " + h.Detail}}
		default:
			return VerificationResult{Reasons: []string{"pending: Globalping disabled and hayahora is inconclusive (" + h.Detail + ")"}}
		}
	}
	if !g.Available {
		return VerificationResult{Reasons: []string{"pending: Globalping unavailable: " + g.Error}}
	}
	if g.MeasuredAt.Before(notBefore) {
		return VerificationResult{Reasons: []string{"pending: no measurement taken after the restore and DNS TTL yet"}}
	}
	if ev.Now.Sub(g.MeasuredAt) > cfg.GlobalpingMaxAge {
		return VerificationResult{Reasons: []string{"pending: latest measurement is stale"}}
	}
	var reachable, unreachable []string
	controlsOK := false
	for _, grp := range g.Groups {
		switch {
		case grp.Role == RoleControl && grp.IsReachable():
			controlsOK = true
		case grp.Role == RoleTarget && grp.IsReachable():
			reachable = append(reachable, grp.Name)
		case grp.Role == RoleTarget && grp.IsUnreachable():
			unreachable = append(unreachable, grp.Name)
		}
	}
	switch {
	case !controlsOK:
		return VerificationResult{Reasons: []string{"pending: no control group answered correctly"}}
	case len(unreachable) >= cfg.MinISPs:
		return VerificationResult{Failed: true, Reasons: []string{"external probes still cannot connect from: " + strings.Join(unreachable, ", ")}}
	case len(unreachable) > 0:
		return VerificationResult{Reasons: []string{"pending: isolated failures from " + strings.Join(unreachable, ", ")}}
	case len(reachable) == 0:
		return VerificationResult{Reasons: []string{"pending: no target probe produced a conclusive result"}}
	default:
		return VerificationResult{Verified: true, Reasons: []string{"verified by Globalping from: " + strings.Join(reachable, ", ")}}
	}
}

func externalSignals(ev Evidence, cfg Config) []SourceSignal {
	var out []SourceSignal
	if ev.Hayahora != nil {
		out = append(out, hayahoraSignal(ev.Hayahora, ev.Now, cfg))
	}
	if ev.Globalping != nil {
		out = append(out, globalpingSignal(ev.Globalping, ev.Now, cfg))
	}
	return out
}

func hayahoraSignal(h *HayahoraEvidence, now time.Time, cfg Config) SourceSignal {
	s := SourceSignal{Source: "hayahora"}
	switch {
	case h == nil:
		s.Signal, s.Detail = SignalUnavailable, "disabled"
		return s
	case !h.Available:
		s.Signal, s.Detail = SignalUnavailable, "feed unavailable: "+h.Error
		return s
	case now.Sub(h.LastUpdate) > cfg.HayahoraMaxFeedAge:
		s.Signal, s.Detail = SignalUnavailable, "stale feed (lastUpdate "+h.LastUpdate.UTC().Format(time.RFC3339)+")"
		return s
	case len(h.CheckedIPs) == 0:
		s.Signal, s.Detail = SignalNoData, "no Cloudflare IPs to check"
		return s
	case len(h.TrackedIPs) == 0:
		s.Signal, s.Detail = SignalNoData, "none of the IPs ("+strings.Join(h.CheckedIPs, ", ")+") is tracked by hayahora"
		return s
	}
	isps := map[string]bool{}
	var ips []string
	for ip, list := range h.BlockedBy {
		if len(list) == 0 {
			continue
		}
		ips = append(ips, ip)
		for _, isp := range list {
			isps[isp] = true
		}
	}
	sort.Strings(ips)
	s.BlockedISPs = sortedKeys(isps)
	switch {
	case len(isps) >= cfg.MinISPs:
		s.Signal = SignalBlock
		s.Detail = fmt.Sprintf("IPs %s blocked on %s", strings.Join(ips, ", "), strings.Join(s.BlockedISPs, ", "))
	case len(isps) > 0:
		s.Signal = SignalClear
		s.Detail = fmt.Sprintf("blocked only on %s (minimum %d ISPs)", strings.Join(s.BlockedISPs, ", "), cfg.MinISPs)
	default:
		s.Signal = SignalClear
		s.Detail = "tracked IPs not blocked: " + strings.Join(h.TrackedIPs, ", ")
	}
	return s
}

func globalpingSignal(g *GlobalpingEvidence, now time.Time, cfg Config) SourceSignal {
	s := SourceSignal{Source: "globalping"}
	switch {
	case !g.Available:
		s.Signal, s.Detail = SignalUnavailable, "no measurement: "+g.Error
		return s
	case now.Sub(g.MeasuredAt) > cfg.GlobalpingMaxAge:
		s.Signal, s.Detail = SignalUnavailable, "stale measurement from "+g.MeasuredAt.UTC().Format(time.RFC3339)
		return s
	}
	var ctrlOK, ctrlDown, tgtDown, tgtOK []string
	for _, grp := range g.Groups {
		switch {
		case grp.Role == RoleControl && grp.IsReachable():
			ctrlOK = append(ctrlOK, grp.Name)
		case grp.Role == RoleControl && grp.IsUnreachable():
			ctrlDown = append(ctrlDown, grp.Name)
		case grp.Role == RoleTarget && grp.IsUnreachable():
			tgtDown = append(tgtDown, grp.Name)
		case grp.Role == RoleTarget && grp.IsReachable():
			tgtOK = append(tgtOK, grp.Name)
		}
	}
	switch {
	case len(ctrlDown) > 0:
		s.Signal, s.Detail = SignalGlobalIssue, "control groups cannot connect: "+strings.Join(ctrlDown, ", ")
	case len(ctrlOK) == 0:
		s.Signal, s.Detail = SignalNoData, "no control group produced a conclusive result"
	case len(tgtDown) >= cfg.MinISPs:
		s.Signal = SignalBlock
		s.BlockedISPs = slices.Clone(tgtDown)
		s.Detail = fmt.Sprintf("cannot connect from %s; controls OK (%s)", strings.Join(tgtDown, ", "), strings.Join(ctrlOK, ", "))
	case len(tgtDown) > 0:
		s.Signal = SignalClear
		s.BlockedISPs = slices.Clone(tgtDown)
		s.Detail = fmt.Sprintf("failure only from %s (minimum %d ISPs)", strings.Join(tgtDown, ", "), cfg.MinISPs)
	case len(tgtOK) == 0:
		s.Signal, s.Detail = SignalNoData, "no target probe produced a conclusive result"
	default:
		s.Signal, s.Detail = SignalClear, "reachable from "+strings.Join(tgtOK, ", ")
	}
	return s
}

func signalReasons(signals []SourceSignal) []string {
	out := make([]string, 0, len(signals))
	for _, s := range signals {
		out = append(out, fmt.Sprintf("%s: %s (%s)", s.Source, s.Signal, s.Detail))
	}
	return out
}

func countSignal(signals []SourceSignal, want Signal) int {
	n := 0
	for _, s := range signals {
		if s.Signal == want {
			n++
		}
	}
	return n
}

func failing(results []monitor.CheckResult, bad func(monitor.CheckResult) bool) []monitor.CheckResult {
	var out []monitor.CheckResult
	for _, r := range results {
		if bad(r) {
			out = append(out, r)
		}
	}
	return out
}

func describe(results []monitor.CheckResult) string {
	parts := make([]string, 0, len(results))
	for _, r := range results {
		p := fmt.Sprintf("%s -> %s", r.URL, r.Outcome)
		if r.Status != 0 {
			p += fmt.Sprintf(" (HTTP %d)", r.Status)
		}
		parts = append(parts, p)
	}
	return strings.Join(parts, "; ")
}

func sortedKeys(m map[string]bool) []string {
	out := make([]string, 0, len(m))
	for k := range m {
		out = append(out, k)
	}
	sort.Strings(out)
	return out
}
