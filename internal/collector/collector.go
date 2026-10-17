package collector

import (
	"context"
	"log/slog"
	"net/url"
	"slices"
	"strconv"
	"strings"
	"sync"
	"time"

	"github.com/alperdevv/laliga-bypass/internal/config"
	"github.com/alperdevv/laliga-bypass/internal/detector"
	"github.com/alperdevv/laliga-bypass/internal/monitor"
	"github.com/alperdevv/laliga-bypass/internal/sources"
	"github.com/alperdevv/laliga-bypass/internal/state"
)

type Phase struct {
	Mode            state.Mode
	SavedEdgeIPs    []string
	VerifyNotBefore time.Time
}

type Collector struct {
	Checker    *monitor.Checker
	Resolver   monitor.Resolver
	Hayahora   *sources.Hayahora
	Globalping *sources.Globalping
	HayaCfg    config.HayahoraConfig
	GPCfg      config.GlobalpingConfig
	Now        func() time.Time
	Log        *slog.Logger

	mu sync.Mutex
	gp map[string]*gpCache
}

type gpCache struct {
	lastRun time.Time
	result  *detector.GlobalpingEvidence
}

func (c *Collector) Collect(ctx context.Context, d config.Domain, ph Phase) detector.Evidence {
	ev := detector.Evidence{Now: c.now(), Domain: d.Name}
	origins := OriginIPs(d)

	ev.Origin = make([]monitor.CheckResult, len(d.Endpoints))
	ev.Edge = make([]monitor.CheckResult, len(d.Endpoints))
	var wg sync.WaitGroup
	for i, ep := range d.Endpoints {
		wg.Add(2)
		go func() { defer wg.Done(); ev.Origin[i] = c.Checker.CheckOrigin(ctx, ep, d.Origin) }()
		go func() { defer wg.Done(); ev.Edge[i] = c.Checker.CheckEdge(ctx, ep) }()
	}

	hosts := endpointHosts(d)
	var current []string
	for _, h := range hosts {
		ips, err := c.Resolver.LookupIPs(ctx, h)
		if err != nil {
			c.Log.Warn("domain resolution failed", "domain", d.Name, "host", h, "error", err.Error())
			continue
		}
		current = append(current, ips...)
	}
	ev.EdgeIPs = without(dedupe(current), origins)
	wg.Wait()

	hayaIPs := ev.EdgeIPs
	gpHost := ""
	if len(hosts) > 0 {
		gpHost = hosts[0]
	}
	if ph.Mode == state.ModeContingency {
		hayaIPs = slices.Clone(ph.SavedEdgeIPs)
		gpHost = d.CanaryHost
		if d.CanaryHost != "" {
			if ips, err := c.Resolver.LookupIPs(ctx, d.CanaryHost); err == nil {
				hayaIPs = append(hayaIPs, ips...)
			} else {
				c.Log.Warn("canary resolution failed", "domain", d.Name, "error", err.Error())
			}
		}
		hayaIPs = without(dedupe(hayaIPs), origins)
	}

	if c.Hayahora != nil {
		ev.Hayahora = c.hayahora(ctx, hayaIPs)
	}
	if c.Globalping != nil {
		ev.Globalping = c.globalping(ctx, d, ph, gpHost, ev, origins)
	}
	return ev
}

func (c *Collector) hayahora(ctx context.Context, ips []string) *detector.HayahoraEvidence {
	feed, err := c.Hayahora.Get(ctx)
	if feed == nil {
		if err == nil {
			return &detector.HayahoraEvidence{Available: false, Error: "empty feed"}
		}
		return sources.Unavailable(err)
	}
	ev := feed.Lookup(ips, sources.LookupOptions{
		ISPs:            c.HayaCfg.ISPs,
		IgnoreOlderThan: c.HayaCfg.IgnoreBlocksOlderThan,
		Now:             c.now(),
	})
	if err != nil {
		ev.Error = "last refresh failed, using previous copy: " + err.Error()
	}
	return ev
}

func (c *Collector) globalping(ctx context.Context, d config.Domain, ph Phase, host string, ev detector.Evidence, origins []string) *detector.GlobalpingEvidence {
	if host == "" {
		return nil
	}
	now := c.now()
	c.mu.Lock()
	if c.gp == nil {
		c.gp = map[string]*gpCache{}
	}
	cache := c.gp[host]
	if cache == nil {
		cache = &gpCache{}
		c.gp[host] = cache
	}
	lastRun := cache.lastRun
	c.mu.Unlock()

	if c.measurementDue(ph, now, lastRun, ev) {
		c.Log.Info("starting Globalping measurement", "domain", d.Name, "host", host, "mode", ph.Mode)
		res := c.Globalping.MeasureHTTP(ctx, c.measurement(d, host, origins))
		if !res.Available {
			c.Log.Warn("Globalping measurement failed", "domain", d.Name, "error", res.Error)
		}
		c.mu.Lock()
		cache.lastRun = now
		cache.result = res
		c.mu.Unlock()
	}

	c.mu.Lock()
	defer c.mu.Unlock()
	if cache.result == nil {
		return &detector.GlobalpingEvidence{Available: false, Target: host, Error: "no measurement yet (measurements only run when there are signs of trouble)"}
	}
	return cache.result
}

func (c *Collector) measurementDue(ph Phase, now, lastRun time.Time, ev detector.Evidence) bool {
	if now.Sub(lastRun) < c.GPCfg.MinInterval {
		return false
	}
	switch ph.Mode {
	case state.ModeContingency:
		return true
	case state.ModeRecovery:
		return !now.Before(ph.VerifyNotBefore)
	default:
		return edgeAnomaly(ev) || hayahoraHints(ev.Hayahora) ||
			(c.GPCfg.BaselineInterval > 0 && now.Sub(lastRun) >= c.GPCfg.BaselineInterval)
	}
}

func (c *Collector) measurement(d config.Domain, host string, origins []string) sources.HTTPMeasurement {
	ep := d.Endpoints[0]
	m := sources.HTTPMeasurement{
		Host:           host,
		ExpectedStatus: ep.ExpectedStatus,
		Targets:        c.GPCfg.Targets,
		Controls:       c.GPCfg.Controls,
		ExcludeIPs:     origins,
	}
	if u, err := url.Parse(ep.URL); err == nil {
		m.Path = u.EscapedPath()
		m.Query = u.RawQuery
		m.Protocol = strings.ToUpper(u.Scheme)
		if p := u.Port(); p != "" {
			m.Port, _ = strconv.Atoi(p)
		}
	}
	if host == d.CanaryHost {
		m.Path, m.Query = "/", ""
	}
	return m
}

func edgeAnomaly(ev detector.Evidence) bool {
	for _, r := range ev.Edge {
		if r.Outcome != monitor.OutcomeOK {
			return true
		}
	}
	return false
}

func hayahoraHints(h *detector.HayahoraEvidence) bool {
	if h == nil || !h.Available {
		return false
	}
	for _, isps := range h.BlockedBy {
		if len(isps) > 0 {
			return true
		}
	}
	return false
}

func endpointHosts(d config.Domain) []string {
	var hosts []string
	for _, ep := range d.Endpoints {
		if u, err := url.Parse(ep.URL); err == nil {
			h := strings.ToLower(u.Hostname())
			if !slices.Contains(hosts, h) {
				hosts = append(hosts, h)
			}
		}
	}
	return hosts
}

func OriginIPs(d config.Domain) []string {
	var out []string
	for _, r := range d.Records {
		if r.ExpectedType == "A" || r.ExpectedType == "AAAA" {
			out = append(out, r.ExpectedContent)
		}
	}
	return out
}

func dedupe(in []string) []string {
	out := slices.Clone(in)
	slices.Sort(out)
	return slices.Compact(out)
}

func without(in, exclude []string) []string {
	var out []string
	for _, ip := range in {
		if !slices.Contains(exclude, ip) {
			out = append(out, ip)
		}
	}
	return out
}

func (c *Collector) now() time.Time {
	if c.Now != nil {
		return c.Now()
	}
	return time.Now()
}
