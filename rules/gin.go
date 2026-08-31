package rules

import (
	"go/ast"
	"strings"

	"github.com/rociiu/webvet/report"
)

func ginProxyRule() Rule {
	m := Metadata{ID: "WEBVET-GIN-001", Name: "Unsafe Gin trusted proxies", Description: "Gin trusts all forwarding proxies", Severity: report.High, CWE: "CWE-345", Confidence: report.ConfidenceHigh, Frameworks: []string{"gin"}}
	return rule{m, func(c *Context) []report.Finding {
		var out []report.Finding
		ast.Inspect(c.File, func(n ast.Node) bool {
			call, ok := n.(*ast.CallExpr)
			if !ok {
				return true
			}
			sel, ok := call.Fun.(*ast.SelectorExpr)
			if !ok || sel.Sel.Name != "SetTrustedProxies" || len(call.Args) != 1 {
				return true
			}
			obj := c.Types.Uses[sel.Sel]
			if obj == nil || obj.Pkg() == nil || obj.Pkg().Path() != "github.com/gin-gonic/gin" {
				return true
			}
			if !unsafeProxyList(call.Args[0]) {
				return true
			}
			out = append(out, finding(c, call, m, "Gin is configured to trust all proxies.", "Trusting unrestricted forwarding proxies lets untrusted clients influence the derived client IP and scheme.", "Pass only the CIDRs or addresses of proxies controlled by your deployment."))
			return true
		})
		return out
	}}
}
func unsafeProxyList(e ast.Expr) bool {
	lit, ok := e.(*ast.CompositeLit)
	if !ok {
		return false
	}
	for _, x := range lit.Elts {
		if s, ok := stringLiteral(x); ok {
			s = strings.TrimSpace(s)
			if s == "*" || s == "0.0.0.0/0" || s == "::/0" {
				return true
			}
		}
	}
	return false
}
