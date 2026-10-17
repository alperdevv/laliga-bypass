package controller

import (
	"context"
	"errors"
	"fmt"
	"log/slog"
	"net/netip"
	"slices"
	"sort"
	"strings"
	"sync"
	"time"

	"github.com/alperdevv/laliga-bypass/internal/cloudflare"
	"github.com/alperdevv/laliga-bypass/internal/collector"
	"github.com/alperdevv/laliga-bypass/internal/config"
	"github.com/alperdevv/laliga-bypass/internal/detector"
	"github.com/alperdevv/laliga-bypass/internal/notifier"
	"github.com/alperdevv/laliga-bypass/internal/state"
)

type Collector interface {
	Collect(ctx context.Context, d config.Domain, ph collector.Phase) detector.Evidence
}

type DNS interface {
	GetRecord(ctx context.Context, zoneID, recordID string) (cloudflare.Record, error)
	SetProxied(ctx context.Context, zoneID, recordID, recordType string, proxied bool) (cloudflare.Record, error)
}

type Options struct {
	Config    *config.Config
	Collector Collector
	DNS       DNS
	Store     state.Store
	Notifier  notifier.Notifier
	Logger    *slog.Logger
	Now       func() time.Time
}

type Controller struct {
	cfg       *config.Config
	det       detector.Config
	collector Collector
	dns       DNS
	store     state.Store
	notify    notifier.Notifier
	log       *slog.Logger
	now       func() time.Time
	st        *state.State
	savedFP   string

	mu        sync.RWMutex
	snapshot  *state.State
	lastCycle time.Time
	lastErr   error
}

func New(ctx context.Context, o Options) (*Controller, error) {
	if o.Config == nil || o.Collector == nil || o.Notifier == nil {
		return nil, errors.New("controller: config, collector and notifier are required")
	}
	if o.DNS == nil && !o.Config.DryRun {
		return nil, errors.New("controller: a Cloudflare client is required when DRY_RUN=false")
	}
	if o.Logger == nil {
		o.Logger = slog.Default()
	}
	if o.Now == nil {
		o.Now = time.Now
	}
	st, err := o.Store.Load()
	if err != nil {
		return nil, err
	}
	c := &Controller{
		cfg:       o.Config,
		collector: o.Collector,
		dns:       o.DNS,
		store:     o.Store,
		notify:    o.Notifier,
		log:       o.Logger,
		now:       o.Now,
		st:        st,
		det: detector.Config{
			MinISPs:              o.Config.Detector.MinISPs,
			MinConfirmingSources: o.Config.Detector.MinConfirmingSources,
			HayahoraMaxFeedAge:   o.Config.Sources.Hayahora.MaxFeedAge,
			GlobalpingMaxAge:     o.Config.Sources.Globalping.MaxResultAge,
		},
	}
	c.reconcileOnStart(ctx)
	if err := c.persist(); err != nil {
		return nil, err
	}
	c.publish()
	return c, nil
}

func (c *Controller) reconcileOnStart(ctx context.Context) {
	now := c.now()
	configured := map[string]bool{}
	for _, d := range c.cfg.Domains {
		configured[d.Name] = true
	}
	names := make([]string, 0, len(c.st.Domains))
	for name := range c.st.Domains {
		names = append(names, name)
	}
	sort.Strings(names)
	for _, name := range names {
		ds := c.st.Domain(name, now)
		var real, simulated []*state.RecordChange
		for _, ch := range ds.Pending() {
			if ch.Simulated {
				simulated = append(simulated, ch)
			} else {
				real = append(real, ch)
			}
		}
		if !c.cfg.DryRun && len(simulated) > 0 {
			for _, ch := range simulated {
				delete(ds.Changes, ch.RecordID)
			}
			if len(ds.Pending()) == 0 {
				ds.SetMode(state.ModeNormal, now)
				ds.Simulated = false
				ds.ClearSince = nil
				ds.Alerted = map[string]bool{}
			}
			c.emit(ctx, notifier.LevelInfo, name, "simulated_state_discarded", "DRY_RUN is now false: simulated contingency state discarded, no record was ever modified", nil)
		}
		if !c.cfg.DryRun && ds.Simulated && ds.Mode == state.ModeRecovery {
			ds.SetMode(state.ModeNormal, now)
			ds.Simulated = false
		}
		if len(real) == 0 {
			continue
		}
		ids := make([]string, 0, len(real))
		for _, ch := range real {
			ids = append(ids, ch.ZoneID+"/"+ch.RecordID)
		}
		if !configured[name] {
			c.emit(ctx, notifier.LevelCritical, name, "orphaned_changes", "state contains DNS changes made by this service for a domain that is no longer configured; restore them manually", []string{strings.Join(ids, ", ")})
			continue
		}
		if c.cfg.DryRun {
			c.emit(ctx, notifier.LevelCritical, name, "real_changes_pending_in_dry_run", "real DNS changes made by this service are pending restore, but DRY_RUN=true prevents restoring them", []string{strings.Join(ids, ", ")})
		} else {
			c.log.Info("resuming after restart with pending changes", "domain", name, "mode", ds.Mode, "records", ids)
		}
	}
}

func (c *Controller) Run(ctx context.Context) error {
	ticker := time.NewTicker(c.cfg.PollInterval)
	defer ticker.Stop()
	for {
		c.cycle(ctx)
		select {
		case <-ctx.Done():
			return nil
		case <-ticker.C:
		}
	}
}

func (c *Controller) cycle(ctx context.Context) {
	timeout := c.cfg.Sources.Globalping.WaitTimeout + 2*time.Minute
	cctx, cancel := context.WithTimeout(ctx, timeout)
	defer cancel()
	err := c.RunOnce(cctx)
	if err != nil {
		c.log.Error("cycle failed", "error", err.Error())
	}
}

func (c *Controller) RunOnce(ctx context.Context) error {
	for _, d := range c.cfg.Domains {
		if ctx.Err() != nil {
			break
		}
		c.step(ctx, d)
	}
	err := c.persist()
	c.mu.Lock()
	c.lastErr = err
	if err == nil {
		c.lastCycle = c.now()
	}
	c.mu.Unlock()
	c.publish()
	return err
}

func (c *Controller) step(ctx context.Context, d config.Domain) {
	now := c.now()
	ds := c.st.Domain(d.Name, now)
	ev := c.collector.Collect(ctx, d, collector.Phase{
		Mode:            ds.Mode,
		SavedEdgeIPs:    ds.EdgeIPs,
		VerifyNotBefore: ds.RestoredAt.Add(c.cfg.Controller.VerifyDelay),
	})
	ds.LastCheck = now
	if ds.Mode == state.ModeContingency {
		c.stepContingency(ctx, d, ds, ev)
	} else {
		c.stepNormal(ctx, d, ds, ev)
	}
}

func (c *Controller) stepNormal(ctx context.Context, d config.Domain, ds *state.DomainState, ev detector.Evidence) {
	now := c.now()
	a := detector.Assess(ev, c.det)
	c.recordVerdict(ctx, d.Name, ds, string(a.Verdict), a.Reasons)

	if a.Verdict == detector.VerdictBlockConfirmed {
		ds.ConsecutiveConfirmed++
	} else {
		ds.ConsecutiveConfirmed = 0
		for _, k := range []string{"change_held", "activation_aborted", "activation_failed", "manual_hold"} {
			delete(ds.Alerted, k)
		}
	}

	if ds.Mode == state.ModeRecovery {
		v := detector.AssessVerification(ev, ds.RestoredAt.Add(c.cfg.Controller.VerifyDelay), c.det)
		switch {
		case v.Verified:
			c.finishRecovery(ctx, d.Name, ds, v.Reasons)
		case v.Failed:
			c.emitOnce(ctx, ds, "verification_failed", notifier.LevelCritical, d.Name, "proxy restored but external probes still fail through Cloudflare", v.Reasons)
		case now.Sub(ds.RestoredAt) > c.cfg.Controller.VerifyTimeout:
			c.emitOnce(ctx, ds, "verification_timeout", notifier.LevelWarning, d.Name, "recovery not verified by external probes within verify_timeout; the site is NOT confirmed as recovered", v.Reasons)
		default:
			c.log.Debug("recovery verification pending", "domain", d.Name, "reasons", v.Reasons)
		}
	}

	if ds.ConsecutiveConfirmed < c.cfg.Controller.MinFailures {
		if ds.ConsecutiveConfirmed > 0 {
			c.log.Info("block confirmed, waiting for consecutive confirmations", "domain", d.Name, "count", ds.ConsecutiveConfirmed, "required", c.cfg.Controller.MinFailures)
		}
		return
	}
	if now.Before(ds.ManualHoldUntil) {
		c.emitOnce(ctx, ds, "manual_hold", notifier.LevelWarning, d.Name,
			fmt.Sprintf("block confirmed but automation is paused until %s after a manual takeover", ds.ManualHoldUntil.UTC().Format(time.RFC3339)), a.Reasons)
		return
	}
	if !ds.LastChange.IsZero() && now.Sub(ds.LastChange) < c.cfg.Controller.MinChangeInterval {
		c.emitOnce(ctx, ds, "change_held", notifier.LevelWarning, d.Name,
			fmt.Sprintf("block confirmed but last DNS change was %s ago (min_change_interval %s): holding", now.Sub(ds.LastChange).Round(time.Second), c.cfg.Controller.MinChangeInterval), a.Reasons)
		return
	}
	c.activate(ctx, d, ds, ev, a)
}

func (c *Controller) activate(ctx context.Context, d config.Domain, ds *state.DomainState, ev detector.Evidence, a detector.Assessment) {
	now := c.now()
	ds.ConsecutiveConfirmed = 0
	dry := c.cfg.DryRun

	type planned struct {
		rec  config.Record
		live *cloudflare.Record
	}
	var plan []planned
	for _, rec := range d.Records {
		if ch := ds.Changes[rec.RecordID]; ch != nil && ch.Status == state.ChangeApplied {
			c.emitOnce(ctx, ds, "activation_aborted", notifier.LevelCritical, d.Name, "a previous change on this record is still pending restore", []string{rec.RecordID})
			return
		}
		if c.dns == nil {
			plan = append(plan, planned{rec: rec})
			continue
		}
		live, err := c.dns.GetRecord(ctx, d.ZoneID, rec.RecordID)
		if err != nil {
			c.emitOnce(ctx, ds, "activation_aborted", notifier.LevelCritical, d.Name, "could not read record before changing it; nothing was modified", []string{err.Error()})
			return
		}
		if problems := MatchExpected(rec, live); len(problems) > 0 {
			c.emitOnce(ctx, ds, "activation_aborted", notifier.LevelCritical, d.Name, "record does not match the expected configuration; nothing was modified", problems)
			return
		}
		if !live.Proxied {
			c.emitOnce(ctx, ds, "activation_aborted", notifier.LevelCritical, d.Name, "record is already DNS-only (manual change?); nothing was modified and it will not be managed", []string{rec.RecordID})
			return
		}
		plan = append(plan, planned{rec: rec, live: &live})
	}

	applied := 0
	for _, p := range plan {
		original := snapshotFromConfig(p.rec)
		if p.live != nil {
			original = snapshot(*p.live)
		}
		ch := &state.RecordChange{
			ZoneID:    d.ZoneID,
			RecordID:  p.rec.RecordID,
			Original:  original,
			Status:    state.ChangeApplied,
			ChangedAt: now,
			UpdatedAt: now,
		}
		if dry {
			ch.Simulated = true
			ch.Applied = original
			ch.Applied.Proxied = false
			c.log.Warn("DRY_RUN: would set proxied=false", "domain", d.Name, "record_id", p.rec.RecordID, "name", p.rec.ExpectedName)
		} else {
			updated, err := c.dns.SetProxied(ctx, d.ZoneID, p.rec.RecordID, p.rec.ExpectedType, false)
			if err != nil {
				c.emitOnce(ctx, ds, "activation_failed", notifier.LevelCritical, d.Name,
					fmt.Sprintf("failed to set proxied=false on %s after %d successful change(s)", p.rec.RecordID, applied), []string{err.Error()})
				break
			}
			ch.Applied = snapshot(updated)
		}
		ds.Changes[p.rec.RecordID] = ch
		applied++
		if err := c.persist(); err != nil {
			c.emit(ctx, notifier.LevelCritical, d.Name, "state_write_failed", "DNS changed but state could not be saved", []string{err.Error()})
		}
	}
	if applied == 0 {
		return
	}

	ds.SetMode(state.ModeContingency, now)
	ds.Simulated = dry
	ds.ActivatedAt = now
	ds.LastChange = now
	ds.EdgeIPs = slices.Clone(ev.EdgeIPs)
	ds.ClearSince = nil
	ds.Alerted = map[string]bool{}
	msg := "contingency activated: records switched to DNS-only (origin IP is now publicly exposed)"
	if dry {
		msg = "DRY_RUN: contingency would be activated (no record was modified)"
	}
	c.emit(ctx, notifier.LevelCritical, d.Name, "contingency_activated", msg, a.Reasons)
	if err := c.persist(); err != nil {
		c.log.Error("state write failed", "error", err.Error())
	}
}

func (c *Controller) stepContingency(ctx context.Context, d config.Domain, ds *state.DomainState, ev detector.Evidence) {
	now := c.now()
	c.reconcileApplied(ctx, d, ds)
	if len(ds.Pending()) == 0 {
		c.release(ctx, d.Name, ds, "every changed record was modified manually: the service no longer manages them")
		return
	}

	a := detector.Assess(ev, c.det)
	verdict := "contingency_active"
	if a.Verdict == detector.VerdictOriginDown || a.Verdict == detector.VerdictAppError {
		verdict = string(a.Verdict)
	}
	c.recordVerdict(ctx, d.Name, ds, verdict, a.Reasons)

	if now.Sub(ds.ActivatedAt) > c.cfg.Controller.MaxContingency {
		c.emitOnce(ctx, ds, "max_contingency", notifier.LevelCritical, d.Name,
			fmt.Sprintf("contingency active for %s, longer than max_contingency (%s)", now.Sub(ds.ActivatedAt).Round(time.Second), c.cfg.Controller.MaxContingency), nil)
	}

	r := detector.AssessRecovery(ev, c.det)
	if !r.Clear {
		if ds.ClearSince != nil {
			c.log.Info("block signals returned, recovery window reset", "domain", d.Name, "reasons", r.Reasons)
		}
		ds.ClearSince = nil
		return
	}
	if ds.ClearSince == nil {
		t := now
		ds.ClearSince = &t
		c.log.Info("block appears to have ended, recovery window started", "domain", d.Name, "window", c.cfg.Controller.RecoveryWindow.String(), "reasons", r.Reasons)
	}
	if now.Sub(*ds.ClearSince) < c.cfg.Controller.RecoveryWindow {
		return
	}
	if now.Sub(ds.LastChange) < c.cfg.Controller.MinChangeInterval {
		return
	}
	c.restore(ctx, d.Name, ds, r.Reasons)
}

func (c *Controller) reconcileApplied(ctx context.Context, d config.Domain, ds *state.DomainState) {
	if c.dns == nil {
		return
	}
	for _, ch := range sortedPending(ds) {
		if ch.Simulated {
			continue
		}
		live, err := c.dns.GetRecord(ctx, ch.ZoneID, ch.RecordID)
		if err != nil {
			c.emitOnce(ctx, ds, "record_check_failed:"+ch.RecordID, notifier.LevelWarning, d.Name, "could not read changed record", []string{err.Error()})
			continue
		}
		delete(ds.Alerted, "record_check_failed:"+ch.RecordID)
		if diff := diffApplied(ch.Applied, live); len(diff) > 0 {
			c.markReleased(ctx, d.Name, ch, diff)
		}
	}
}

func (c *Controller) restore(ctx context.Context, domain string, ds *state.DomainState, reasons []string) bool {
	now := c.now()
	restored, failed := 0, 0
	for _, ch := range sortedPending(ds) {
		if ch.Simulated {
			ch.Status, ch.UpdatedAt = state.ChangeRestored, now
			restored++
			c.log.Warn("DRY_RUN: would restore proxied=true", "domain", domain, "record_id", ch.RecordID)
			continue
		}
		if c.cfg.DryRun || c.dns == nil {
			failed++
			c.emitOnce(ctx, ds, "restore_blocked_dry_run", notifier.LevelCritical, domain, "a real change is pending restore but DRY_RUN=true prevents modifying records", []string{ch.RecordID})
			continue
		}
		if !c.allowed(ch.ZoneID, ch.RecordID) {
			failed++
			c.emitOnce(ctx, ds, "restore_not_allowed:"+ch.RecordID, notifier.LevelCritical, domain, "record changed by this service is no longer in the allowlist; restore it manually", []string{ch.ZoneID + "/" + ch.RecordID})
			continue
		}
		live, err := c.dns.GetRecord(ctx, ch.ZoneID, ch.RecordID)
		if err != nil {
			failed++
			c.emitOnce(ctx, ds, "restore_read_failed:"+ch.RecordID, notifier.LevelWarning, domain, "could not read record before restoring it; will retry", []string{err.Error()})
			continue
		}
		if diff := diffApplied(ch.Applied, live); len(diff) > 0 {
			c.markReleased(ctx, domain, ch, diff)
			continue
		}
		updated, err := c.dns.SetProxied(ctx, ch.ZoneID, ch.RecordID, live.Type, ch.Original.Proxied)
		if err != nil {
			failed++
			c.emitOnce(ctx, ds, "restore_failed:"+ch.RecordID, notifier.LevelCritical, domain, "failed to restore proxied=true; will retry", []string{err.Error()})
			continue
		}
		ch.Status, ch.UpdatedAt, ch.Note = state.ChangeRestored, now, ""
		ch.Applied = snapshot(updated)
		restored++
		if err := c.persist(); err != nil {
			c.log.Error("state write failed", "error", err.Error())
		}
	}
	if failed > 0 {
		return false
	}
	if restored == 0 {
		c.release(ctx, domain, ds, "every changed record was modified manually: nothing restored")
		return true
	}
	ds.SetMode(state.ModeRecovery, now)
	ds.RestoredAt = now
	ds.LastChange = now
	ds.ClearSince = nil
	ds.Alerted = map[string]bool{}
	msg := "proxy restored (proxied=true); recovery is pending verification from external probes"
	if ds.Simulated {
		msg = "DRY_RUN: proxy would be restored; recovery is pending verification from external probes"
	}
	c.emit(ctx, notifier.LevelWarning, domain, "proxy_restored", msg, reasons)
	return true
}

func (c *Controller) finishRecovery(ctx context.Context, domain string, ds *state.DomainState, reasons []string) {
	now := c.now()
	ds.SetMode(state.ModeNormal, now)
	for id, ch := range ds.Changes {
		if ch.Status != state.ChangeApplied {
			delete(ds.Changes, id)
		}
	}
	simulated := ds.Simulated
	ds.Simulated = false
	ds.EdgeIPs = nil
	ds.Alerted = map[string]bool{}
	msg := "recovery verified by external probes"
	if simulated {
		msg = "DRY_RUN: simulated recovery verified by external probes"
	}
	c.emit(ctx, notifier.LevelInfo, domain, "recovery_verified", msg, reasons)
}

func (c *Controller) release(ctx context.Context, domain string, ds *state.DomainState, msg string) {
	now := c.now()
	ds.SetMode(state.ModeNormal, now)
	ds.LastChange = now
	ds.ClearSince = nil
	ds.Simulated = false
	ds.EdgeIPs = nil
	ds.Alerted = map[string]bool{}
	ds.ManualHoldUntil = now.Add(c.cfg.Controller.ManualHold)
	c.emit(ctx, notifier.LevelWarning, domain, "contingency_released", msg+fmt.Sprintf("; automation paused for %s", c.cfg.Controller.ManualHold), nil)
}

func (c *Controller) markReleased(ctx context.Context, domain string, ch *state.RecordChange, diff []string) {
	ch.Status = state.ChangeReleased
	ch.UpdatedAt = c.now()
	ch.Note = "manual change detected: " + strings.Join(diff, "; ")
	c.emit(ctx, notifier.LevelWarning, domain, "manual_change_detected", "record was modified outside this service; it will not be restored automatically", append([]string{ch.ZoneID + "/" + ch.RecordID}, diff...))
}

func (c *Controller) Rollback(ctx context.Context, domain string) error {
	var target *config.Domain
	for i := range c.cfg.Domains {
		if c.cfg.Domains[i].Name == domain {
			target = &c.cfg.Domains[i]
		}
	}
	ds, ok := c.st.Domains[domain]
	if !ok || len(ds.Pending()) == 0 {
		return fmt.Errorf("no pending changes for %s", domain)
	}
	if target != nil {
		c.reconcileApplied(ctx, *target, ds)
	}
	if len(ds.Pending()) > 0 && !c.restore(ctx, domain, ds, []string{"manual rollback"}) {
		_ = c.persist()
		return fmt.Errorf("rollback for %s incomplete; check the logs", domain)
	}
	if ds.Mode == state.ModeContingency {
		c.release(ctx, domain, ds, "every changed record was modified manually: nothing restored")
	}
	return c.persist()
}

func (c *Controller) recordVerdict(ctx context.Context, domain string, ds *state.DomainState, verdict string, reasons []string) {
	prev := ds.LastVerdict
	ds.LastReasons = reasons
	if prev == verdict {
		c.log.Debug("assessment", "domain", domain, "verdict", verdict, "mode", ds.Mode, "reasons", reasons)
		return
	}
	ds.LastVerdict = verdict
	level := notifier.LevelWarning
	switch verdict {
	case string(detector.VerdictHealthy), "contingency_active":
		level = notifier.LevelInfo
	case string(detector.VerdictOriginDown):
		level = notifier.LevelCritical
	}
	msg := fmt.Sprintf("assessment changed: %s -> %s", orDash(prev), verdict)
	if verdict == string(detector.VerdictBlockSuspected) {
		msg += " (not enough evidence to confirm a block: staying in normal mode)"
	}
	c.emit(ctx, level, domain, "assessment_changed", msg, reasons)
}

func (c *Controller) emit(ctx context.Context, level notifier.Level, domain, kind, msg string, reasons []string) {
	e := notifier.Event{
		Time:    c.now(),
		Level:   level,
		Domain:  domain,
		Kind:    kind,
		Message: msg,
		Reasons: reasons,
		Fields:  map[string]any{"dry_run": c.cfg.DryRun},
	}
	if err := c.notify.Notify(ctx, e); err != nil {
		c.log.Warn("notification failed", "kind", kind, "error", err.Error())
	}
}

func (c *Controller) emitOnce(ctx context.Context, ds *state.DomainState, key string, level notifier.Level, domain, msg string, reasons []string) {
	if ds.Alerted[key] {
		return
	}
	ds.Alerted[key] = true
	c.emit(ctx, level, domain, strings.SplitN(key, ":", 2)[0], msg, reasons)
}

func (c *Controller) allowed(zoneID, recordID string) bool {
	_, ok := c.cfg.Allowlist()[zoneID+"/"+recordID]
	return ok
}

func (c *Controller) persist() error {
	fp := c.st.Fingerprint()
	if fp == c.savedFP {
		return nil
	}
	if err := c.store.Save(c.st, c.now()); err != nil {
		return err
	}
	c.savedFP = fp
	return nil
}

func (c *Controller) publish() {
	snap := c.st.Clone()
	c.mu.Lock()
	c.snapshot = snap
	c.mu.Unlock()
}

type Status struct {
	DryRun    bool         `json:"dry_run"`
	LastCycle time.Time    `json:"last_cycle"`
	LastError string       `json:"last_error,omitempty"`
	State     *state.State `json:"state"`
}

func (c *Controller) Status() Status {
	c.mu.RLock()
	defer c.mu.RUnlock()
	s := Status{DryRun: c.cfg.DryRun, LastCycle: c.lastCycle, State: c.snapshot}
	if c.lastErr != nil {
		s.LastError = c.lastErr.Error()
	}
	return s
}

func (c *Controller) Healthy(maxAge time.Duration) bool {
	c.mu.RLock()
	defer c.mu.RUnlock()
	return !c.lastCycle.IsZero() && c.now().Sub(c.lastCycle) <= maxAge
}

func (c *Controller) State() *state.State { return c.st }

func MatchExpected(rec config.Record, live cloudflare.Record) []string {
	var p []string
	if live.ID != rec.RecordID {
		p = append(p, fmt.Sprintf("id %q != expected %q", live.ID, rec.RecordID))
	}
	if normalizeName(live.Name) != rec.ExpectedName {
		p = append(p, fmt.Sprintf("name %q != expected %q", live.Name, rec.ExpectedName))
	}
	if !strings.EqualFold(live.Type, rec.ExpectedType) {
		p = append(p, fmt.Sprintf("type %q != expected %q", live.Type, rec.ExpectedType))
	}
	if !sameContent(rec.ExpectedType, live.Content, rec.ExpectedContent) {
		p = append(p, fmt.Sprintf("content %q != expected %q", live.Content, rec.ExpectedContent))
	}
	return p
}

func diffApplied(applied state.Snapshot, live cloudflare.Record) []string {
	var d []string
	if normalizeName(live.Name) != normalizeName(applied.Name) {
		d = append(d, fmt.Sprintf("name %q -> %q", applied.Name, live.Name))
	}
	if !strings.EqualFold(live.Type, applied.Type) {
		d = append(d, fmt.Sprintf("type %q -> %q", applied.Type, live.Type))
	}
	if !sameContent(applied.Type, live.Content, applied.Content) {
		d = append(d, fmt.Sprintf("content %q -> %q", applied.Content, live.Content))
	}
	if live.Proxied != applied.Proxied {
		d = append(d, fmt.Sprintf("proxied %v -> %v", applied.Proxied, live.Proxied))
	}
	if !live.ModifiedOn.Equal(applied.ModifiedOn) {
		d = append(d, fmt.Sprintf("modified_on %s -> %s", applied.ModifiedOn.Format(time.RFC3339), live.ModifiedOn.Format(time.RFC3339)))
	}
	return d
}

func sameContent(recordType, a, b string) bool {
	switch strings.ToUpper(recordType) {
	case "A", "AAAA":
		x, err1 := netip.ParseAddr(strings.TrimSpace(a))
		y, err2 := netip.ParseAddr(strings.TrimSpace(b))
		return err1 == nil && err2 == nil && x == y
	default:
		return normalizeName(a) == normalizeName(b)
	}
}

func normalizeName(s string) string {
	return strings.TrimSuffix(strings.ToLower(strings.TrimSpace(s)), ".")
}

func snapshot(r cloudflare.Record) state.Snapshot {
	return state.Snapshot{
		Name:       normalizeName(r.Name),
		Type:       strings.ToUpper(r.Type),
		Content:    r.Content,
		Proxied:    r.Proxied,
		TTL:        r.TTL,
		ModifiedOn: r.ModifiedOn,
	}
}

func snapshotFromConfig(r config.Record) state.Snapshot {
	return state.Snapshot{Name: r.ExpectedName, Type: r.ExpectedType, Content: r.ExpectedContent, Proxied: true}
}

func sortedPending(ds *state.DomainState) []*state.RecordChange {
	p := ds.Pending()
	sort.Slice(p, func(i, j int) bool { return p[i].RecordID < p[j].RecordID })
	return p
}

func orDash(s string) string {
	if s == "" {
		return "-"
	}
	return s
}
