package preflight

import (
	"context"
	"fmt"
	"net/url"
	"strings"
	"sync"

	"github.com/alperdevv/laliga-bypass/internal/config"
	"github.com/alperdevv/laliga-bypass/internal/monitor"
)

type Level string

const (
	LevelWarning Level = "warning"
	LevelError   Level = "error"
)

type Finding struct {
	Level   Level  `json:"level"`
	URL     string `json:"url"`
	Message string `json:"message"`
}

func Check(ctx context.Context, checker *monitor.Checker, d config.Domain) []Finding {
	results := make([][]Finding, len(d.Endpoints))
	var wg sync.WaitGroup
	for i, ep := range d.Endpoints {
		wg.Add(1)
		go func() {
			defer wg.Done()
			edge := checker.CheckEdge(ctx, ep)
			origin := checker.CheckOrigin(ctx, ep, config.Origin{Address: d.Origin.Address})
			results[i] = evaluate(ep, edge, origin)
		}()
	}
	wg.Wait()
	var out []Finding
	for _, r := range results {
		out = append(out, r...)
	}
	return out
}

func evaluate(ep config.Endpoint, edge, origin monitor.CheckResult) []Finding {
	var out []Finding
	add := func(level Level, format string, a ...any) {
		out = append(out, Finding{Level: level, URL: ep.URL, Message: fmt.Sprintf(format, a...)})
	}
	if isAccessRedirect(edge) {
		add(LevelError, "protected by Cloudflare Access: in DNS-only it would be reachable without login; remove this host from the config")
	}
	switch {
	case origin.Outcome == monitor.OutcomeTLSError:
		add(LevelError, "origin certificate is not trusted by browsers (%s): visitors would get TLS errors in DNS-only", origin.Error)
	case !origin.Outcome.Reachable():
		add(LevelError, "origin not reachable from this host (%s): fix origin.address", origin.Outcome)
	case origin.Outcome == monitor.OutcomeServerError:
		add(LevelWarning, "origin answers HTTP %d", origin.Status)
	case isRedirect(edge.Status) && (origin.Status == 404 || origin.Status == 421) && !isAccessRedirect(edge):
		add(LevelError, "Cloudflare answers with a redirect to %s but the origin returns HTTP %d: the redirect lives in Cloudflare and would break in DNS-only", edge.Location, origin.Status)
	case edge.Outcome == monitor.OutcomeOK && origin.Outcome == monitor.OutcomeUnexpectedStatus:
		add(LevelWarning, "through Cloudflare HTTP %d but origin HTTP %d: some behaviour lives in Cloudflare and may change in DNS-only", edge.Status, origin.Status)
	}
	if !edge.Outcome.Reachable() {
		add(LevelWarning, "not reachable through Cloudflare from this host (%s)", edge.Outcome)
	}
	return out
}

func isRedirect(status int) bool { return status >= 300 && status < 400 }

func isAccessRedirect(r monitor.CheckResult) bool {
	if !isRedirect(r.Status) || r.Location == "" {
		return false
	}
	u, err := url.Parse(r.Location)
	if err != nil {
		return false
	}
	host := strings.ToLower(u.Hostname())
	return strings.HasSuffix(host, ".cloudflareaccess.com") || strings.HasPrefix(u.Path, "/cdn-cgi/access/")
}

func HasErrors(f []Finding) bool {
	for _, x := range f {
		if x.Level == LevelError {
			return true
		}
	}
	return false
}
