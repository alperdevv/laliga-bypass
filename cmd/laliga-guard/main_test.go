package main

import (
	"os"
	"path/filepath"
	"strings"
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
