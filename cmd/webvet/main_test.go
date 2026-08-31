package main

import (
	"os"
	"path/filepath"
	"testing"
)

func TestExitCodes(t *testing.T) {
	if got := run([]string{"-severity", "not-a-severity", "."}); got != 2 {
		t.Fatalf("configuration exit=%d", got)
	}
	if got := run([]string{"-disable", "WEBVET-NOPE-001", "."}); got != 2 {
		t.Fatalf("unknown rule exit=%d", got)
	}
	if got := run([]string{"-severity", "critical", "."}); got != 0 {
		t.Fatalf("clean exit=%d", got)
	}
	if got := run([]string{"-severity", "high", "../../testdata/projects/vulnerable"}); got != 1 {
		t.Fatalf("finding exit=%d", got)
	}
}

func TestConfigPrecedence(t *testing.T) {
	path := filepath.Join(t.TempDir(), "webvet.yml")
	if err := os.WriteFile(path, []byte("severity: critical\n"), 0o600); err != nil {
		t.Fatal(err)
	}
	project := "../../testdata/projects/vulnerable"
	if got := run([]string{"-config", path, project}); got != 0 {
		t.Fatalf("config threshold exit=%d", got)
	}
	if got := run([]string{"-config", path, "-severity", "high", project}); got != 1 {
		t.Fatalf("CLI precedence exit=%d", got)
	}
}
