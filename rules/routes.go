package rules

import (
	"strings"

	"github.com/rociiu/webvet/report"
	"github.com/rociiu/webvet/route"
)

var sensitiveRouteMeta = Metadata{ID: "WEBVET-ROUTE-002", Name: "Unprotected sensitive route", Description: "sensitive endpoint has no detected route middleware", Severity: report.Medium, CWE: "CWE-306", Confidence: report.ConfidenceLow, Frameworks: []string{"gin", "chi"}}

func CheckSensitiveRoutes(routes []route.Route) []report.Finding {
	var out []report.Finding
	for _, r := range routes {
		if len(r.Middleware) > 0 || !sensitivePath(r.Path) {
			continue
		}
		out = append(out, report.Finding{RuleID: sensitiveRouteMeta.ID, Severity: sensitiveRouteMeta.Severity, Confidence: sensitiveRouteMeta.Confidence, Filename: r.Position.Filename, Line: r.Position.Line, Column: r.Position.Column, Message: "No route-level middleware was detected for sensitive endpoint " + r.Path + ".", Explanation: "This endpoint name commonly denotes operational or administrative data. Static analysis cannot determine network-level protection, so review whether it is externally accessible.", Remediation: "Attach appropriate authentication/authorization middleware or restrict the endpoint at the network boundary.", CWE: sensitiveRouteMeta.CWE, Route: r.Method + " " + r.Path, Framework: r.Framework})
	}
	return out
}
func sensitivePath(p string) bool {
	p = strings.ToLower(strings.TrimSuffix(p, "/"))
	return p == "/debug" || strings.HasPrefix(p, "/debug/") || p == "/admin/debug" || p == "/metrics"
}
