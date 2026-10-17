package discover

import (
	"fmt"
	"net/netip"
	"sort"
	"strings"

	"github.com/alperdevv/laliga-bypass/internal/cloudflare"
	"github.com/alperdevv/laliga-bypass/internal/config"
)

type Skip struct {
	Name    string
	Type    string
	Content string
	Reason  string
}

type Result struct {
	Domain   *config.Domain
	Skipped  []Skip
	Warnings []string
}

var externalPlatforms = map[string]string{
	"pages.dev":         "Cloudflare Pages",
	"workers.dev":       "Cloudflare Workers",
	"cfargotunnel.com":  "Cloudflare Tunnel",
	"up.railway.app":    "Railway",
	"railway.app":       "Railway",
	"vercel-dns.com":    "Vercel",
	"vercel.app":        "Vercel",
	"netlify.app":       "Netlify",
	"github.io":         "GitHub Pages",
	"herokudns.com":     "Heroku",
	"azurewebsites.net": "Azure",
	"cloudfront.net":    "CloudFront",
	"fly.dev":           "Fly.io",
	"onrender.com":      "Render",
}

const PlaceholderOrigin = "ORIGIN_IP:443"

func Build(zone cloudflare.Zone, records []cloudflare.Record) Result {
	zoneName := normalize(zone.Name)
	res := Result{}
	var kept []cloudflare.Record
	for _, r := range records {
		typ := strings.ToUpper(r.Type)
		if typ != "A" && typ != "AAAA" && typ != "CNAME" {
			continue
		}
		name := normalize(r.Name)
		skip := func(reason string) {
			res.Skipped = append(res.Skipped, Skip{Name: name, Type: typ, Content: r.Content, Reason: reason})
		}
		switch {
		case !r.Proxied:
			skip("already DNS-only: not affected by Cloudflare IP blocks")
		case strings.HasPrefix(name, "*"):
			skip("wildcard record")
		case hasServiceLabel(name):
			skip("service record (label starting with _)")
		case typ == "CNAME" && !config.HostInDomain(normalize(r.Content), zoneName):
			if platform := platformOf(normalize(r.Content)); platform != "" {
				skip("CNAME to " + platform + ": DNS-only would not move traffic off Cloudflare or would break the custom domain")
			} else {
				skip("CNAME to an external host: review manually")
			}
		default:
			kept = append(kept, r)
		}
	}
	if len(kept) == 0 {
		return res
	}
	sort.Slice(kept, func(i, j int) bool {
		a, b := normalize(kept[i].Name), normalize(kept[j].Name)
		if (a == zoneName) != (b == zoneName) {
			return a == zoneName
		}
		return a < b
	})

	d := &config.Domain{Name: zoneName, ZoneID: zone.ID}
	origins := map[string]int{}
	for _, r := range kept {
		typ := strings.ToUpper(r.Type)
		name := normalize(r.Name)
		content := strings.TrimSpace(r.Content)
		if typ == "CNAME" {
			content = normalize(content)
		} else if a, err := netip.ParseAddr(content); err == nil {
			content = a.String()
			origins[content]++
		}
		d.Records = append(d.Records, config.Record{RecordID: r.ID, ExpectedType: typ, ExpectedName: name, ExpectedContent: content})
		d.Endpoints = append(d.Endpoints, config.Endpoint{URL: "https://" + name + "/", ExpectedStatus: []int{200, 301, 302}})
	}

	d.Origin.Address = PlaceholderOrigin
	if ip := mostCommon(origins); ip != "" {
		host := ip
		if strings.Contains(ip, ":") {
			host = "[" + ip + "]"
		}
		d.Origin.Address = host + ":443"
		if len(origins) > 1 {
			res.Warnings = append(res.Warnings, fmt.Sprintf("%s: records point to %d different origins; origin.address uses %s, split the others into a separate domain entry or remove them", zoneName, len(origins), ip))
		}
	} else {
		res.Warnings = append(res.Warnings, fmt.Sprintf("%s: no proxied A/AAAA record found; set origin.address by hand", zoneName))
	}
	res.Domain = d
	return res
}

func Render(domains []config.Domain) string {
	var b strings.Builder
	b.WriteString(header)
	b.WriteString("\ndomains:\n")
	for i, d := range domains {
		if i > 0 {
			b.WriteString("\n")
		}
		fmt.Fprintf(&b, "  - name: %q\n    zone_id: %q\n    canary_host: \"\"\n    endpoints:\n", d.Name, d.ZoneID)
		for _, e := range d.Endpoints {
			fmt.Fprintf(&b, "      - url: %q\n        expected_status: %s\n        timeout: 10s\n", e.URL, intList(e.ExpectedStatus))
		}
		fmt.Fprintf(&b, "    origin:\n      address: %q\n      insecure_skip_verify: false\n    records:\n", d.Origin.Address)
		for _, r := range d.Records {
			fmt.Fprintf(&b, "      - record_id: %q\n        expected_type: %q\n        expected_name: %q\n        expected_content: %q\n", r.RecordID, r.ExpectedType, r.ExpectedName, r.ExpectedContent)
		}
	}
	return b.String()
}

func intList(v []int) string {
	parts := make([]string, len(v))
	for i, n := range v {
		parts[i] = fmt.Sprint(n)
	}
	return "[" + strings.Join(parts, ", ") + "]"
}

func mostCommon(m map[string]int) string {
	keys := make([]string, 0, len(m))
	for k := range m {
		keys = append(keys, k)
	}
	sort.Slice(keys, func(i, j int) bool {
		a, b := keys[i], keys[j]
		if m[a] != m[b] {
			return m[a] > m[b]
		}
		if v4a, v4b := !strings.Contains(a, ":"), !strings.Contains(b, ":"); v4a != v4b {
			return v4a
		}
		return a < b
	})
	if len(keys) == 0 {
		return ""
	}
	return keys[0]
}

func platformOf(host string) string {
	for suffix, name := range externalPlatforms {
		if host == suffix || strings.HasSuffix(host, "."+suffix) {
			return name
		}
	}
	return ""
}

func hasServiceLabel(name string) bool {
	for _, label := range strings.Split(name, ".") {
		if strings.HasPrefix(label, "_") {
			return true
		}
	}
	return false
}

func normalize(s string) string {
	return strings.TrimSuffix(strings.ToLower(strings.TrimSpace(s)), ".")
}

const header = `poll_interval: 30s
dry_run: true
listen: 127.0.0.1:8080
state_file: /data/state.json
resolver: 1.1.1.1:53

detector:
  min_isps: 2
  min_confirming_sources: 2

sources:
  hayahora:
    enabled: true
    url: https://hayahora.futbol/estado/data.json
    refresh_interval: 5m
    max_feed_age: 30m
    ignore_blocks_older_than: 12h
    isps: []
    timeout: 30s
  globalping:
    enabled: true
    api_url: https://api.globalping.io
    min_interval: 10m
    baseline_interval: 20m
    max_result_age: 20m
    wait_timeout: 60s
    targets:
      - { name: Movistar, magic: "ES+AS3352", limit: 1 }
      - { name: Orange, magic: "ES+AS12479", limit: 1 }
      - { name: Vodafone, magic: "ES+AS12430", limit: 1 }
      - { name: DIGI, magic: "ES+AS57269", limit: 1 }
      - { name: MasMovil, magic: "ES+AS15704", limit: 1 }
    controls:
      - { name: control-es-ionos, magic: "ES+AS8560", limit: 1 }
      - { name: control-de, magic: "Germany", limit: 1 }

controller:
  min_failures: 3
  recovery_window: 10m
  max_contingency: 60m
  min_change_interval: 15m
  verify_delay: 6m
  verify_timeout: 45m
  manual_hold: 6h

notifier:
  webhook_format: generic
  timeout: 10s
`
