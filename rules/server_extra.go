package rules

import (
	"go/ast"

	"github.com/rociiu/webvet/report"
)

func writeTimeoutRule() Rule {
	m := Metadata{ID: "WEBVET-HTTP-003", Name: "HTTP server missing WriteTimeout", Description: "http.Server missing WriteTimeout", Severity: report.Medium, CWE: "CWE-400", Confidence: report.ConfidenceMedium, Frameworks: []string{"net/http"}}
	return serverFieldRule(m, "WriteTimeout", nil, "Without a write deadline, a slow client can retain server resources while a response is written.", "Set WriteTimeout to a deployment-appropriate duration; review streaming endpoints separately.")
}

func idleTimeoutRule() Rule {
	m := Metadata{ID: "WEBVET-HTTP-004", Name: "HTTP server missing IdleTimeout", Description: "http.Server missing IdleTimeout or ReadTimeout fallback", Severity: report.Medium, CWE: "CWE-400", Confidence: report.ConfidenceHigh, Frameworks: []string{"net/http"}}
	return serverFieldRule(m, "IdleTimeout", func(fields map[string]ast.Expr) bool { v, ok := fields["ReadTimeout"]; return ok && !obviouslyZero(v) }, "Without IdleTimeout or ReadTimeout, idle keep-alive connections have no server-defined deadline.", "Set IdleTimeout, or configure a non-zero ReadTimeout fallback.")
}

func serverFieldRule(meta Metadata, field string, fallback func(map[string]ast.Expr) bool, explanation, remediation string) Rule {
	return rule{meta, func(c *Context) []report.Finding {
		var out []report.Finding
		configuredLater := configuredServerLiterals(c, field)
		ast.Inspect(c.File, func(n ast.Node) bool {
			lit, ok := n.(*ast.CompositeLit)
			if !ok || compositeTypePath(c.Types, lit) != "net/http.Server" || configuredLater[lit] {
				return true
			}
			fields := fieldMap(lit)
			if v, ok := fields[field]; ok && !obviouslyZero(v) {
				return true
			}
			if fallback != nil && fallback(fields) {
				return true
			}
			out = append(out, finding(c, lit, meta, "http.Server does not configure a non-zero "+field+".", explanation, remediation))
			return true
		})
		return out
	}}
}
