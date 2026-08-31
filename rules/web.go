package rules

import (
	"go/ast"
	"go/token"
	"strings"

	"github.com/rociiu/webvet/report"
)

func securityHeadersRule() Rule {
	m := Metadata{ID: "WEBVET-HEADER-001", Name: "HTML response lacks browser security headers", Description: "explicit HTML response has no detected CSP or frame policy", Severity: report.Low, CWE: "CWE-693", Confidence: report.ConfidenceLow, Frameworks: []string{"net/http", "gin", "chi"}}
	return rule{m, func(c *Context) []report.Finding {
		var out []report.Finding
		for _, decl := range c.File.Decls {
			fn, ok := decl.(*ast.FuncDecl)
			if !ok || fn.Body == nil {
				continue
			}
			html, protected := false, false
			var at ast.Node = fn
			ast.Inspect(fn.Body, func(n ast.Node) bool {
				call, ok := n.(*ast.CallExpr)
				if !ok {
					return true
				}
				key, value, ok := headerSet(c, call)
				if !ok {
					return true
				}
				k := strings.ToLower(key)
				if k == "content-type" && strings.Contains(strings.ToLower(value), "text/html") {
					html = true
					at = call
				}
				if k == "content-security-policy" || k == "x-frame-options" {
					protected = true
				}
				return true
			})
			if html && !protected {
				out = append(out, finding(c, at, m, "HTML response has no detected Content-Security-Policy or X-Frame-Options header.", "No handler-level browser framing policy was found. Middleware or a reverse proxy may provide one, so this is a review finding.", "Set a restrictive Content-Security-Policy (prefer frame-ancestors) or an appropriate X-Frame-Options header."))
			}
		}
		return out
	}}
}

func headerSet(c *Context, call *ast.CallExpr) (string, string, bool) {
	sel, ok := call.Fun.(*ast.SelectorExpr)
	if !ok || len(call.Args) != 2 {
		return "", "", false
	}
	obj := c.Types.Uses[sel.Sel]
	if obj == nil || obj.Pkg() == nil || !((obj.Pkg().Path() == "net/http" && sel.Sel.Name == "Set") || (obj.Pkg().Path() == "github.com/gin-gonic/gin" && sel.Sel.Name == "Header")) {
		return "", "", false
	}
	k, kok := stringLiteral(call.Args[0])
	v, vok := stringLiteral(call.Args[1])
	return k, v, kok && vok
}

func bodyLimitRule() Rule {
	m := Metadata{ID: "WEBVET-BODY-001", Name: "Unbounded request body read", Description: "request body read without MaxBytesReader", Severity: report.Medium, CWE: "CWE-400", Confidence: report.ConfidenceHigh, Frameworks: []string{"net/http", "chi"}}
	return rule{m, func(c *Context) []report.Finding {
		var out []report.Finding
		for _, decl := range c.File.Decls {
			fn, ok := decl.(*ast.FuncDecl)
			if !ok || fn.Body == nil {
				continue
			}
			bounded := false
			var reads []*ast.CallExpr
			ast.Inspect(fn.Body, func(n ast.Node) bool {
				call, ok := n.(*ast.CallExpr)
				if !ok {
					return true
				}
				p := callPath(c.Types, call)
				if p == "net/http.MaxBytesReader" {
					bounded = true
				}
				if p == "io.ReadAll" && len(call.Args) == 1 && requestBody(c, call.Args[0]) {
					reads = append(reads, call)
				}
				return true
			})
			if !bounded {
				for _, call := range reads {
					out = append(out, finding(c, call, m, "Request body is read without an explicit size limit.", "Reading an attacker-controlled body to completion can exhaust memory or other resources.", "Wrap the body with http.MaxBytesReader before reading it."))
				}
			}
		}
		return out
	}}
}
func requestBody(c *Context, e ast.Expr) bool {
	sel, ok := e.(*ast.SelectorExpr)
	if !ok || sel.Sel.Name != "Body" {
		return false
	}
	t := c.Types.TypeOf(sel.X)
	return t != nil && strings.Contains(t.String(), "net/http.Request")
}

func redirectRule() Rule {
	m := Metadata{ID: "WEBVET-REDIRECT-001", Name: "Untrusted redirect target", Description: "HTTP input flows to a redirect target", Severity: report.High, CWE: "CWE-601", Confidence: report.ConfidenceHigh, Frameworks: []string{"net/http", "gin", "chi"}}
	return rule{m, func(c *Context) []report.Finding {
		var out []report.Finding
		for _, decl := range c.File.Decls {
			fn, ok := decl.(*ast.FuncDecl)
			if !ok || fn.Body == nil {
				continue
			}
			tainted := taintedVariables(c, fn.Body)
			ast.Inspect(fn.Body, func(n ast.Node) bool {
				call, ok := n.(*ast.CallExpr)
				if !ok {
					return true
				}
				index := -1
				p := callPath(c.Types, call)
				if p == "net/http.Redirect" && len(call.Args) >= 3 {
					index = 2
				} else if isGinRedirect(c, call) && len(call.Args) >= 2 {
					index = 1
				}
				if index >= 0 && exprTainted(c, call.Args[index], tainted) {
					out = append(out, finding(c, call, m, "User-controlled HTTP input is used as a redirect target.", "An attacker may construct a trusted-looking URL that redirects users to an external site.", "Allowlist local paths or trusted origins before redirecting."))
				}
				return true
			})
		}
		return out
	}}
}
func isGinRedirect(c *Context, call *ast.CallExpr) bool {
	sel, ok := call.Fun.(*ast.SelectorExpr)
	if !ok || sel.Sel.Name != "Redirect" {
		return false
	}
	obj := c.Types.Uses[sel.Sel]
	return obj != nil && obj.Pkg() != nil && obj.Pkg().Path() == "github.com/gin-gonic/gin"
}

func stringContainsSQLMutation(lit *ast.BasicLit) bool {
	if lit.Kind != token.STRING {
		return false
	}
	s, ok := stringLiteral(lit)
	if !ok {
		return false
	}
	s = strings.ToUpper(strings.TrimSpace(s))
	return strings.HasPrefix(s, "DELETE FROM") || strings.HasPrefix(s, "UPDATE ") || strings.HasPrefix(s, "INSERT INTO")
}
