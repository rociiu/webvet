package config_test

import (
	"os"
	"path/filepath"
	"testing"

	"github.com/rociiu/webvet/config"
)

func TestLoad(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, ".webvet.yml")
	if err := os.WriteFile(path, []byte("severity: high\ndisable:\n  - WEBVET-HTTP-001\n"), 0o600); err != nil {
		t.Fatal(err)
	}
	cfg, err := config.Load(path, true)
	if err != nil {
		t.Fatal(err)
	}
	if cfg.Severity != "high" || len(cfg.Disable) != 1 {
		t.Fatalf("unexpected config: %+v", cfg)
	}
}

func TestLoadValidation(t *testing.T) {
	for _, tc := range []struct{ name, body string }{
		{"unknown field", "mystery: true\n"}, {"severity", "severity: severe\n"}, {"rule", "disable: [WEBVET-NOPE-001]\n"},
	} {
		t.Run(tc.name, func(t *testing.T) {
			path := filepath.Join(t.TempDir(), "config.yml")
			if err := os.WriteFile(path, []byte(tc.body), 0o600); err != nil {
				t.Fatal(err)
			}
			if _, err := config.Load(path, true); err == nil {
				t.Fatal("expected validation error")
			}
		})
	}
	if _, err := config.Load(filepath.Join(t.TempDir(), "missing.yml"), false); err != nil {
		t.Fatal(err)
	}
	empty := filepath.Join(t.TempDir(), "empty.yml")
	if err := os.WriteFile(empty, nil, 0o600); err != nil {
		t.Fatal(err)
	}
	if _, err := config.Load(empty, true); err != nil {
		t.Fatal(err)
	}
}
