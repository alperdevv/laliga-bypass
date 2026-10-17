package config_test

import (
	"os"
	"strings"
	"testing"
	"time"

	"github.com/alperdevv/laliga-bypass/internal/config"
)

const valid = `
poll_interval: 30s
domains:
  - name: Example.com.
    zone_id: "ZONE_ID"
    endpoints:
      - url: https://example.com/
    origin:
      address: "203.0.113.10:443"
    records:
      - record_id: "RECORD_ID"
        expected_type: "a"
        expected_name: "example.com"
        expected_content: "203.0.113.10"
sources:
  globalping:
    targets:
      - {name: Movistar, magic: "ES+AS3352"}
    controls:
      - {name: control-de, magic: "Germany"}
`

func env(m map[string]string) func(string) string {
	return func(k string) string { return m[k] }
}

func TestParseAppliesSafeDefaults(t *testing.T) {
	cfg, err := config.Parse([]byte(valid), env(nil))
	if err != nil {
		t.Fatal(err)
	}
	if !cfg.DryRun {
		t.Fatal("dry_run must default to true")
	}
	if cfg.Listen != "127.0.0.1:8080" {
		t.Fatalf("listen %q", cfg.Listen)
	}
	d := cfg.Domains[0]
	if d.Name != "example.com" || d.Records[0].ExpectedType != "A" || d.Endpoints[0].ExpectedStatus[0] != 200 {
		t.Fatalf("normalization failed: %+v", d)
	}
	if cfg.Controller.MinChangeInterval != 15*time.Minute || cfg.Detector.MinConfirmingSources != 2 {
		t.Fatalf("defaults %+v %+v", cfg.Controller, cfg.Detector)
	}
}

func TestEnvironmentOverridesAndSecrets(t *testing.T) {
	cfg, err := config.Parse([]byte(valid), env(map[string]string{"DRY_RUN": "false", "CF_API_TOKEN": " secret-token "}))
	if err != nil {
		t.Fatal(err)
	}
	if cfg.DryRun || cfg.Secrets.CloudflareToken != "secret-token" {
		t.Fatalf("dry=%v", cfg.DryRun)
	}
	if strings.Contains(cfg.Secrets.String(), "secret") || strings.Contains(cfg.Secrets.GoString(), "secret-token") {
		t.Fatal("secrets leak through String")
	}
	if _, err := config.Parse([]byte(valid), env(map[string]string{"DRY_RUN": "maybe"})); err == nil {
		t.Fatal("invalid DRY_RUN accepted")
	}
}

func TestGlobalAPIKeyIsRefused(t *testing.T) {
	_, err := config.Parse([]byte(valid), env(map[string]string{"CF_API_KEY": "global"}))
	if err == nil || !strings.Contains(err.Error(), "global") {
		t.Fatalf("expected refusal, got %v", err)
	}
}

func TestValidationRejectsUnsafeConfigs(t *testing.T) {
	tests := map[string]func(string) string{
		"MX record": func(s string) string {
			return strings.Replace(s, `expected_type: "a"`, `expected_type: "MX"`, 1)
		},
		"record outside domain": func(s string) string {
			return strings.Replace(s, `expected_name: "example.com"`, `expected_name: "evil.org"`, 1)
		},
		"public listen": func(s string) string { return "listen: 0.0.0.0:8080\n" + s },
		"missing origin": func(s string) string {
			return strings.Replace(s, `address: "203.0.113.10:443"`, `address: ""`, 1)
		},
		"content not IPv4": func(s string) string {
			return strings.Replace(s, `expected_content: "203.0.113.10"`, `expected_content: "2001:db8::1"`, 1)
		},
		"unknown field": func(s string) string { return "dryrun: false\n" + s },
		"no controls": func(s string) string {
			return strings.Replace(s, `      - {name: control-de, magic: "Germany"}`, ``, 1)
		},
		"tiny change interval": func(s string) string { return "controller:\n  min_change_interval: 10s\n" + s },
	}
	for name, mutate := range tests {
		t.Run(name, func(t *testing.T) {
			if _, err := config.Parse([]byte(mutate(valid)), env(nil)); err == nil {
				t.Fatal("expected validation error")
			}
		})
	}
}

func TestAutomaticModeProblems(t *testing.T) {
	cfg, err := config.Parse([]byte(valid), env(nil))
	if err != nil {
		t.Fatal(err)
	}
	if len(cfg.AutomaticModeProblems()) == 0 {
		t.Fatal("missing token must block automatic mode")
	}
	cfg.Secrets.CloudflareToken = "x"
	if p := cfg.AutomaticModeProblems(); len(p) != 0 {
		t.Fatalf("unexpected problems %v", p)
	}
	cfg.Sources.Globalping.Enabled = false
	if len(cfg.AutomaticModeProblems()) == 0 {
		t.Fatal("one source with min_confirming_sources=2 must block automatic mode")
	}
}

func TestExampleConfigIsValid(t *testing.T) {
	raw, err := os.ReadFile("../../config.example.yaml")
	if err != nil {
		t.Skip("example config not present:", err)
	}
	if _, err := config.Parse(raw, env(nil)); err != nil {
		t.Fatal(err)
	}
}
