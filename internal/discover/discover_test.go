package discover_test

import (
	"os"
	"reflect"
	"strings"
	"testing"

	"github.com/alperdevv/laliga-bypass/internal/cloudflare"
	"github.com/alperdevv/laliga-bypass/internal/config"
	"github.com/alperdevv/laliga-bypass/internal/discover"
)

func records() []cloudflare.Record {
	return []cloudflare.Record{
		{ID: "www", Name: "www.example.com", Type: "CNAME", Content: "example.com", Proxied: true},
		{ID: "apex", Name: "example.com", Type: "A", Content: "203.0.113.10", Proxied: true},
		{ID: "dev", Name: "dev.example.com", Type: "A", Content: "203.0.113.10", Proxied: false},
		{ID: "mx", Name: "example.com", Type: "MX", Content: "mail.example.com"},
		{ID: "pages", Name: "blog.example.com", Type: "CNAME", Content: "blog.pages.dev", Proxied: true},
		{ID: "tunnel", Name: "admin.example.com", Type: "CNAME", Content: "abc.cfargotunnel.com", Proxied: true},
		{ID: "ext", Name: "shop.example.com", Type: "CNAME", Content: "shops.example.net", Proxied: true},
		{ID: "wild", Name: "*.example.com", Type: "A", Content: "203.0.113.10", Proxied: true},
		{ID: "srv", Name: "_acme.example.com", Type: "CNAME", Content: "example.com", Proxied: true},
		{ID: "api6", Name: "api.example.com", Type: "AAAA", Content: "2001:0db8::1", Proxied: true},
	}
}

func TestBuildKeepsOnlyRecordsThatDNSOnlyCanHelp(t *testing.T) {
	res := discover.Build(cloudflare.Zone{ID: "zone1", Name: "Example.com"}, records())
	d := res.Domain
	if d == nil {
		t.Fatal("no domain built")
	}
	var ids []string
	for _, r := range d.Records {
		ids = append(ids, r.RecordID)
	}
	if strings.Join(ids, ",") != "apex,api6,www" {
		t.Fatalf("kept records %v", ids)
	}
	if d.Origin.Address != "203.0.113.10:443" || d.Name != "example.com" || d.Endpoints[0].URL != "https://example.com/" {
		t.Fatalf("domain %+v", d)
	}
	if d.Records[1].ExpectedContent != "2001:db8::1" {
		t.Fatalf("AAAA content not normalized: %q", d.Records[1].ExpectedContent)
	}
	reasons := map[string]string{}
	for _, s := range res.Skipped {
		reasons[s.Name] = s.Reason
	}
	for name, want := range map[string]string{
		"dev.example.com":   "already DNS-only",
		"blog.example.com":  "Cloudflare Pages",
		"admin.example.com": "Cloudflare Tunnel",
		"shop.example.com":  "external host",
		"*.example.com":     "wildcard",
		"_acme.example.com": "service record",
	} {
		if !strings.Contains(reasons[name], want) {
			t.Errorf("%s: reason %q, want %q", name, reasons[name], want)
		}
	}
	if len(res.Warnings) != 1 || !strings.Contains(res.Warnings[0], "2 different origins") {
		t.Fatalf("expected warning about IPv4 and IPv6 origins, got %v", res.Warnings)
	}
}

func TestBuildWithoutCandidates(t *testing.T) {
	res := discover.Build(cloudflare.Zone{ID: "z", Name: "example.org"}, []cloudflare.Record{
		{ID: "a", Name: "example.org", Type: "A", Content: "198.51.100.1", Proxied: false},
	})
	if res.Domain != nil || len(res.Skipped) != 1 {
		t.Fatalf("%+v", res)
	}
}

func TestBuildWithOnlyInternalCNAMEUsesPlaceholderOrigin(t *testing.T) {
	res := discover.Build(cloudflare.Zone{ID: "z", Name: "example.org"}, []cloudflare.Record{
		{ID: "www", Name: "www.example.org", Type: "CNAME", Content: "example.org", Proxied: true},
	})
	if res.Domain == nil || res.Domain.Origin.Address != discover.PlaceholderOrigin || len(res.Warnings) != 1 {
		t.Fatalf("%+v", res)
	}
}

func TestRenderedConfigIsValidAndMatchesExampleDefaults(t *testing.T) {
	res := discover.Build(cloudflare.Zone{ID: "zone1", Name: "example.com"}, records())
	out := discover.Render([]config.Domain{*res.Domain})
	cfg, err := config.Parse([]byte(out), func(string) string { return "" })
	if err != nil {
		t.Fatalf("rendered config invalid: %v\n%s", err, out)
	}
	if len(cfg.Domains) != 1 || len(cfg.Domains[0].Records) != 3 || !cfg.DryRun {
		t.Fatalf("%+v", cfg)
	}
	raw, err := os.ReadFile("../../config.example.yaml")
	if err != nil {
		t.Fatal(err)
	}
	example, err := config.Parse(raw, func(string) string { return "" })
	if err != nil {
		t.Fatal(err)
	}
	if !reflect.DeepEqual(example.Sources, cfg.Sources) || example.Controller != cfg.Controller ||
		example.Detector != cfg.Detector || example.PollInterval != cfg.PollInterval || example.Notifier != cfg.Notifier {
		t.Fatal("discover header drifted from config.example.yaml")
	}
}
