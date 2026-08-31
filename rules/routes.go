package rules

import (
	"go/ast"
	"strings"

	"github.com/rociiu/webvet/report"
	"github.com/rociiu/webvet/route"
	"golang.org/x/tools/go/packages"
)

var stateChangingGETMeta = Metadata{ID: "WEBVET-ROUTE-001", Name: "State-changing GET route", Description: "GET handler performs an obvious mutation", Severity: report.Medium, CWE: "CWE-749", Confidence: report.ConfidenceMedium, Frameworks: []string{"gin", "chi"}}
var sensitiveRouteMeta = Metadata{ID: "WEBVET-ROUTE-002", Name: "Unprotected sensitive route", Description: "sensitive endpoint has no detected route middleware", Severity: report.Medium, CWE: "CWE-306", Confidence: report.ConfidenceLow, Frameworks: []string{"gin", "chi"}}
var csrfRouteMeta = Metadata{ID: "WEBVET-ROUTE-003", Name: "Cookie-authenticated route missing CSRF middleware", Description: "state-changing cookie-authenticated route has no recognized CSRF middleware", Severity: report.High, CWE: "CWE-352", Confidence: report.ConfidenceMedium, Frameworks: []string{"gin", "chi"}}

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

func CheckStateChangingGET(pkg *packages.Package, routes []route.Route) []report.Finding {
	var out []report.Finding
	for _, r := range routes {
		if r.Method != "GET" {
			continue
		}
		fn := functionByName(pkg, r.Handler)
		if fn == nil || fn.Body == nil {
			continue
		}
		var evidence string
		ast.Inspect(fn.Body, func(n ast.Node) bool {
			if evidence != "" {
				return false
			}
			switch x := n.(type) {
			case *ast.CallExpr:
				name := ""
				switch f := x.Fun.(type) {
				case *ast.Ident:
					name = f.Name
				case *ast.SelectorExpr:
					name = f.Sel.Name
				}
				lower := strings.ToLower(name)
				if strings.HasPrefix(lower, "delete") || strings.HasPrefix(lower, "remove") || lower == "update" || lower == "insert" || lower == "save" || lower == "create" {
					evidence = name + "(...)"
					return false
				}
				for _, arg := range x.Args {
					if lit, ok := arg.(*ast.BasicLit); ok && stringContainsSQLMutation(lit) {
						evidence = "mutation SQL"
						return false
					}
				}
			}
			return true
		})
		if evidence != "" {
			out = append(out, routeFinding(r, stateChangingGETMeta, "GET handler performs an obvious state mutation via "+evidence+".", "GET requests may be prefetched, cached, crawled, or triggered cross-site and should be safe and idempotent.", "Use POST, PUT, PATCH, or DELETE and apply appropriate CSRF protection."))
		}
	}
	return out
}

func CheckCSRF(pkg *packages.Package, routes []route.Route) []report.Finding {
	var out []report.Finding
	for _, r := range routes {
		if r.Method != "POST" && r.Method != "PUT" && r.Method != "PATCH" && r.Method != "DELETE" {
			continue
		}
		csrf, cookieAuth := false, false
		for _, mw := range r.Middleware {
			name := strings.ToLower(mw.Name)
			if strings.Contains(name, "csrf") {
				csrf = true
			}
			if fn := functionByName(pkg, mw.Name); fn != nil && functionUsesRequestCookie(pkg, fn) {
				cookieAuth = true
			}
		}
		if cookieAuth && !csrf {
			out = append(out, routeFinding(r, csrfRouteMeta, "Cookie-authenticated state-changing route has no recognized CSRF middleware.", "The attached middleware reads an HTTP cookie, but no route-level CSRF protection was detected.", "Attach a well-reviewed CSRF middleware and validate tokens for unsafe HTTP methods."))
		}
	}
	return out
}

func functionByName(pkg *packages.Package, name string) *ast.FuncDecl {
	if i := strings.LastIndex(name, "."); i >= 0 {
		name = name[i+1:]
	}
	for _, file := range pkg.Syntax {
		for _, decl := range file.Decls {
			if fn, ok := decl.(*ast.FuncDecl); ok && fn.Name.Name == name {
				return fn
			}
		}
	}
	return nil
}
func functionUsesRequestCookie(pkg *packages.Package, fn *ast.FuncDecl) bool {
	found := false
	ast.Inspect(fn.Body, func(n ast.Node) bool {
		call, ok := n.(*ast.CallExpr)
		if !ok {
			return true
		}
		sel, ok := call.Fun.(*ast.SelectorExpr)
		if !ok || sel.Sel.Name != "Cookie" {
			return true
		}
		obj := pkg.TypesInfo.Uses[sel.Sel]
		if obj != nil && obj.Pkg() != nil && obj.Pkg().Path() == "net/http" {
			found = true
			return false
		}
		return true
	})
	return found
}
func routeFinding(r route.Route, m Metadata, message, explanation, fix string) report.Finding {
	return report.Finding{RuleID: m.ID, Severity: m.Severity, Confidence: m.Confidence, Filename: r.Position.Filename, Line: r.Position.Line, Column: r.Position.Column, Message: message, Explanation: explanation, Remediation: fix, CWE: m.CWE, Route: r.Method + " " + r.Path, Framework: r.Framework}
}
func sensitivePath(p string) bool {
	p = strings.ToLower(strings.TrimSuffix(p, "/"))
	return p == "/debug" || strings.HasPrefix(p, "/debug/") || p == "/admin/debug" || p == "/metrics"
}
