package rules

import (
	"go/ast"

	"github.com/rociiu/webvet/report"
)

func corsRule() Rule {
	m := Metadata{ID: "WEBVET-CORS-001", Name: "Credentialed wildcard CORS", Description: "wildcard CORS combined with credentials", Severity: report.High, CWE: "CWE-942", Confidence: report.ConfidenceHigh, Frameworks: []string{"gin", "chi", "net/http"}}
	return rule{m, func(c *Context) []report.Finding {
		var out []report.Finding
		ast.Inspect(c.File, func(n ast.Node) bool {
			lit, ok := n.(*ast.CompositeLit)
			if !ok {
				return true
			}
			path := compositeTypePath(c.Types, lit)
			if path != "github.com/rs/cors.Options" && path != "github.com/gin-contrib/cors.Config" {
				return true
			}
			f := fieldMap(lit)
			cred, _ := boolLiteral(f["AllowCredentials"])
			if !cred {
				return true
			}
			wild := false
			if b, ok := boolLiteral(f["AllowAllOrigins"]); ok && b {
				wild = true
			}
			if origins, ok := f["AllowedOrigins"]; ok {
				wild = containsStar(origins)
			}
			if origins, ok := f["AllowOrigins"]; ok {
				wild = containsStar(origins)
			}
			if wild {
				out = append(out, finding(c, lit, m, "CORS allows credentials with a wildcard origin.", "Credentialed cross-origin access must be restricted to explicitly trusted origins.", "Replace the wildcard with an explicit allowlist and validate origins."))
			}
			return true
		})
		return out
	}}
}
func containsStar(e ast.Expr) bool {
	lit, ok := e.(*ast.CompositeLit)
	if !ok {
		return false
	}
	for _, x := range lit.Elts {
		if s, ok := stringLiteral(x); ok && s == "*" {
			return true
		}
	}
	return false
}
