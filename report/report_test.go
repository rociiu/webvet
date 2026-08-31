package report_test

import (
	"bytes"
	"encoding/json"
	"errors"
	"testing"

	"github.com/rociiu/webvet/report"
)

type failingWriter struct{}

func (failingWriter) Write([]byte) (int, error) { return 0, errors.New("write failed") }

func TestWriters(t *testing.T) {
	f := report.Finding{RuleID: "WEBVET-TEST-001", Severity: report.High, Confidence: report.ConfidenceHigh, Filename: "handler.go", Line: 3, Column: 2, Message: "problem", Explanation: "why", Remediation: "fix", CWE: "CWE-1"}
	var text bytes.Buffer
	if err := report.WriteText(&text, []report.Finding{f}); err != nil {
		t.Fatal(err)
	}
	if !bytes.Contains(text.Bytes(), []byte("1 finding")) {
		t.Fatalf("unexpected text: %s", text.String())
	}
	var raw bytes.Buffer
	if err := report.WriteJSON(&raw, []report.Finding{f}); err != nil {
		t.Fatal(err)
	}
	var decoded struct {
		Count int `json:"count"`
	}
	if err := json.Unmarshal(raw.Bytes(), &decoded); err != nil || decoded.Count != 1 {
		t.Fatalf("invalid JSON: %v %s", err, raw.String())
	}
	var sarif bytes.Buffer
	if err := report.WriteSARIF(&sarif, []report.Finding{f}, []report.RuleInfo{{ID: f.RuleID, Name: "test", Description: "test", CWE: f.CWE}}, "test"); err != nil {
		t.Fatal(err)
	}
	var doc map[string]any
	if err := json.Unmarshal(sarif.Bytes(), &doc); err != nil || doc["version"] != "2.1.0" {
		t.Fatalf("invalid SARIF: %v", err)
	}
	if err := report.WriteText(failingWriter{}, []report.Finding{f}); err == nil {
		t.Fatal("expected write error")
	}
	if err := report.WriteJSON(failingWriter{}, []report.Finding{f}); err == nil {
		t.Fatal("expected JSON write error")
	}
	if err := report.WriteSARIF(failingWriter{}, []report.Finding{f}, nil, "test"); err == nil {
		t.Fatal("expected SARIF write error")
	}
}

func TestEnumSafety(t *testing.T) {
	if report.Severity(99).String() != "UNKNOWN" || report.Confidence(99).String() != "UNKNOWN" {
		t.Fatal("invalid enum should be safe")
	}
	if _, err := report.ParseSeverity("HIGH"); err != nil {
		t.Fatal(err)
	}
}
