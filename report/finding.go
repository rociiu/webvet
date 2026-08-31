package report

import (
	"fmt"
	"strings"
)

type Severity int

const (
	Info Severity = iota
	Low
	Medium
	High
	Critical
)

func (s Severity) String() string {
	names := []string{"INFO", "LOW", "MEDIUM", "HIGH", "CRITICAL"}
	if int(s) < 0 || int(s) >= len(names) {
		return "UNKNOWN"
	}
	return names[s]
}
func ParseSeverity(v string) (Severity, error) {
	for i, n := range []string{"info", "low", "medium", "high", "critical"} {
		if strings.EqualFold(v, n) {
			return Severity(i), nil
		}
	}
	return 0, fmt.Errorf("unknown severity %q", v)
}
func (s Severity) MarshalJSON() ([]byte, error) { return []byte(fmt.Sprintf("%q", s.String())), nil }

type Confidence int

const (
	ConfidenceLow Confidence = iota
	ConfidenceMedium
	ConfidenceHigh
)

func (c Confidence) String() string {
	names := []string{"LOW", "MEDIUM", "HIGH"}
	if int(c) < 0 || int(c) >= len(names) {
		return "UNKNOWN"
	}
	return names[c]
}
func (c Confidence) MarshalJSON() ([]byte, error) { return []byte(fmt.Sprintf("%q", c.String())), nil }

type Finding struct {
	RuleID      string     `json:"rule_id"`
	Severity    Severity   `json:"severity"`
	Confidence  Confidence `json:"confidence"`
	Filename    string     `json:"filename"`
	Line        int        `json:"line"`
	Column      int        `json:"column"`
	Message     string     `json:"message"`
	Explanation string     `json:"explanation"`
	Remediation string     `json:"remediation"`
	CWE         string     `json:"cwe,omitempty"`
	Route       string     `json:"route,omitempty"`
	Framework   string     `json:"framework,omitempty"`
}
