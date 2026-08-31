package report

import (
	"fmt"
	"io"
	"strings"
)

func WriteText(w io.Writer, findings []Finding) error {
	counts := map[Severity]int{}
	for _, f := range findings {
		counts[f.Severity]++
		if _, err := fmt.Fprintf(w, "%s:%d:%d\n  %s [%s/%s]\n  %s\n\n  %s\n\n  Suggested fix:\n      %s\n\n", f.Filename, f.Line, f.Column, f.RuleID, f.Severity, f.Confidence, f.Message, f.Explanation, strings.ReplaceAll(f.Remediation, "\n", "\n      ")); err != nil {
			return err
		}
	}
	if _, err := fmt.Fprintf(w, "webvet: %d finding%s\n", len(findings), plural(len(findings))); err != nil {
		return err
	}
	var parts []string
	for _, s := range []Severity{Critical, High, Medium, Low, Info} {
		if counts[s] > 0 {
			parts = append(parts, fmt.Sprintf("%d %s", counts[s], strings.ToLower(s.String())))
		}
	}
	if len(parts) > 0 {
		_, err := fmt.Fprintln(w, strings.Join(parts, ", "))
		return err
	}
	return nil
}
func plural(n int) string {
	if n == 1 {
		return ""
	}
	return "s"
}
