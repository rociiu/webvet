package rules

import (
	"go/ast"
	"go/types"

	"github.com/rociiu/webvet/report"
)

func templRawRule() Rule {
	m := Metadata{ID: "WEBVET-TEMPL-001", Name: "Untrusted content passed to templ.Raw", Description: "request input bypasses templ HTML escaping", Severity: report.High, CWE: "CWE-79", Confidence: report.ConfidenceHigh, Frameworks: []string{"templ"}}
	return templBypassRule(m, map[string]bool{"Raw": true}, "User-controlled HTTP input is passed to templ.Raw.", "templ.Raw bypasses templ's HTML escaping and writes the supplied markup directly.", "Render the original string normally, or sanitize trusted HTML with a well-reviewed HTML sanitizer before calling templ.Raw.")
}

func templContextRule() Rule {
	m := Metadata{ID: "WEBVET-TEMPL-002", Name: "Untrusted content marked safe for templ", Description: "request input bypasses templ URL, CSS, or JavaScript sanitization", Severity: report.High, CWE: "CWE-79", Confidence: report.ConfidenceHigh, Frameworks: []string{"templ"}}
	return templBypassRule(m, map[string]bool{"SafeURL": true, "SafeCSS": true, "SafeCSSProperty": true, "JSUnsafeFuncCall": true}, "User-controlled HTTP input is marked safe for templ output.", "This templ API explicitly bypasses contextual URL, CSS, or JavaScript sanitization.", "Keep request data in templ's normally sanitized types, or validate it with a strict context-specific allowlist before using this API.")
}

func templBypassRule(meta Metadata, sinks map[string]bool, message, explanation, remediation string) Rule {
	return rule{meta, func(c *Context) []report.Finding {
		var out []report.Finding
		for _, decl := range c.File.Decls {
			fn, ok := decl.(*ast.FuncDecl)
			if !ok || fn.Body == nil {
				continue
			}
			tainted := taintedVariables(c, fn.Body)
			ast.Inspect(fn.Body, func(n ast.Node) bool {
				call, ok := n.(*ast.CallExpr)
				if !ok || len(call.Args) == 0 {
					return true
				}
				pkg, name := calledName(c.Types, call)
				if pkg != "github.com/a-h/templ" || !sinks[name] {
					return true
				}
				if exprTainted(c, call.Args[0], tainted) {
					out = append(out, finding(c, call, meta, message, explanation, remediation))
				}
				return true
			})
		}
		return out
	}}
}

func calledName(info *types.Info, call *ast.CallExpr) (string, string) {
	var obj types.Object
	switch fun := call.Fun.(type) {
	case *ast.Ident:
		obj = info.ObjectOf(fun)
	case *ast.SelectorExpr:
		obj = info.Uses[fun.Sel]
	}
	if obj == nil || obj.Pkg() == nil {
		return "", ""
	}
	return obj.Pkg().Path(), obj.Name()
}
