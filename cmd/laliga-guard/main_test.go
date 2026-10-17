package main

import (
	"bytes"
	"io"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"strings"
	"sync/atomic"
	"testing"
)

const inlineConfig = `
domains:
  - name: example.com
    zone_id: "ZONE"
    endpoints:
      - url: https://example.com/
    origin:
      address: "203.0.113.10:443"
    records:
      - {record_id: "REC", expected_type: A, expected_name: example.com, expected_content: "203.0.113.10"}
sources:
  globalping:
    targets: [{name: Movistar, magic: "ES+AS3352"}]
    controls: [{name: control-de, magic: "Germany"}]
`

func TestConfigFromEnvironmentTakesPrecedence(t *testing.T) {
	t.Setenv("CONFIG_YAML", inlineConfig)
	cfg, err := loadConfig(filepath.Join(t.TempDir(), "missing.yaml"))
	if err != nil {
		t.Fatal(err)
	}
	if cfg.Domains[0].ZoneID != "ZONE" || !cfg.DryRun {
		t.Fatalf("%+v", cfg.Domains)
	}
}

func TestInvalidConfigFromEnvironmentIsReported(t *testing.T) {
	t.Setenv("CONFIG_YAML", "domains: [")
	if _, err := loadConfig("unused"); err == nil || !strings.Contains(err.Error(), "CONFIG_YAML") {
		t.Fatalf("expected CONFIG_YAML error, got %v", err)
	}
}

func TestConfigFileIsUsedWithoutEnvironment(t *testing.T) {
	t.Setenv("CONFIG_YAML", "")
	path := filepath.Join(t.TempDir(), "config.yaml")
	if err := os.WriteFile(path, []byte(inlineConfig), 0o600); err != nil {
		t.Fatal(err)
	}
	if _, err := loadConfig(path); err != nil {
		t.Fatal(err)
	}
}

func TestNotifyTestDeliversToWebhook(t *testing.T) {
	var got atomic.Int32
	hook := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		body, _ := io.ReadAll(r.Body)
		if strings.Contains(string(body), "test alert") {
			got.Add(1)
		}
	}))
	defer hook.Close()
	t.Setenv("CONFIG_YAML", inlineConfig)
	t.Setenv("WEBHOOK_URL", hook.URL)
	var out bytes.Buffer
	if code := run([]string{"notify-test"}, &out, io.Discard); code != 0 {
		t.Fatalf("exit %d: %s", code, out.String())
	}
	if got.Load() != 1 {
		t.Fatal("webhook not called")
	}
}

func TestNotifyTestFailsWithoutWebhook(t *testing.T) {
	t.Setenv("CONFIG_YAML", inlineConfig)
	t.Setenv("WEBHOOK_URL", "")
	var out bytes.Buffer
	if code := run([]string{"notify-test"}, &out, io.Discard); code == 0 {
		t.Fatal("expected failure without WEBHOOK_URL")
	}
}
