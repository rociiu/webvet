package rules

import (
	"go/ast"
	"go/types"
	"strings"

	"github.com/rociiu/webvet/report"
)

func httpTimeoutRule() Rule {
	m := Metadata{ID: "WEBVET-HTTP-001", Name: "HTTP server missing ReadHeaderTimeout", Description: "http.Server missing ReadHeaderTimeout", Severity: report.Medium, CWE: "CWE-400", Confidence: report.ConfidenceHigh, Frameworks: []string{"net/http"}}
	return rule{m, func(c *Context) []report.Finding {
		var out []report.Finding
		safeLiterals := configuredServerLiterals(c, "ReadHeaderTimeout")
		ast.Inspect(c.File, func(n ast.Node) bool {
			lit, ok := n.(*ast.CompositeLit)
			if !ok || compositeTypePath(c.Types, lit) != "net/http.Server" || safeLiterals[lit] {
				return true
			}
			fields := fieldMap(lit)
			value, exists := fields["ReadHeaderTimeout"]
			if exists && !obviouslyZero(value) {
				return true
			}
			msg := "http.Server does not configure ReadHeaderTimeout."
			if exists {
				msg = "http.Server configures ReadHeaderTimeout to zero."
			}
			out = append(out, finding(c, lit, m, msg, "A server without a header-read deadline can hold resources while sending request headers slowly.", "Set ReadHeaderTimeout to an appropriate non-zero duration."))
			return true
		})
		return out
	}}
}

func configuredServerLiterals(c *Context, field string) map[*ast.CompositeLit]bool {
	safeObjects := map[types.Object]bool{}
	ast.Inspect(c.File, func(n ast.Node) bool {
		a, ok := n.(*ast.AssignStmt)
		if !ok {
			return true
		}
		for i, lhs := range a.Lhs {
			sel, ok := lhs.(*ast.SelectorExpr)
			if !ok || sel.Sel.Name != field || i >= len(a.Rhs) || obviouslyZero(a.Rhs[i]) {
				continue
			}
			if id, ok := sel.X.(*ast.Ident); ok {
				safeObjects[c.Types.ObjectOf(id)] = true
			}
		}
		return true
	})
	literals := map[*ast.CompositeLit]bool{}
	ast.Inspect(c.File, func(n ast.Node) bool {
		switch x := n.(type) {
		case *ast.AssignStmt:
			for i, rhs := range x.Rhs {
				if i < len(x.Lhs) {
					markSafeServerLiteral(c, x.Lhs[i], rhs, safeObjects, literals)
				}
			}
		case *ast.ValueSpec:
			for i, rhs := range x.Values {
				if i < len(x.Names) {
					markSafeServerLiteral(c, x.Names[i], rhs, safeObjects, literals)
				}
			}
		}
		return true
	})
	return literals
}

func markSafeServerLiteral(c *Context, lhs, rhs ast.Expr, safe map[types.Object]bool, literals map[*ast.CompositeLit]bool) {
	id, ok := lhs.(*ast.Ident)
	if !ok || !safe[c.Types.ObjectOf(id)] {
		return
	}
	if unary, ok := rhs.(*ast.UnaryExpr); ok {
		rhs = unary.X
	}
	if lit, ok := rhs.(*ast.CompositeLit); ok && compositeTypePath(c.Types, lit) == "net/http.Server" {
		literals[lit] = true
	}
}
func obviouslyZero(e ast.Expr) bool {
	if l, ok := e.(*ast.BasicLit); ok {
		return l.Value == "0"
	}
	return false
}

func pprofRule() Rule {
	m := Metadata{ID: "WEBVET-HTTP-002", Name: "Exposed pprof endpoint", Description: "pprof handlers exposed on the default HTTP server", Severity: report.High, CWE: "CWE-489", Confidence: report.ConfidenceHigh, Frameworks: []string{"net/http"}}
	return rule{m, func(c *Context) []report.Finding {
		var imp ast.Node
		imported := false
		for _, i := range c.File.Imports {
			if strings.Trim(i.Path.Value, "\"") == "net/http/pprof" {
				imported = true
				imp = i
				break
			}
		}
		if !imported {
			return nil
		}
		exposed := false
		ast.Inspect(c.File, func(n ast.Node) bool {
			call, ok := n.(*ast.CallExpr)
			if !ok {
				return true
			}
			if callPath(c.Types, call) == "net/http.ListenAndServe" && len(call.Args) >= 2 {
				if id, ok := call.Args[1].(*ast.Ident); ok && id.Name == "nil" {
					exposed = true
				}
			}
			return true
		})
		if !exposed {
			return nil
		}
		return []report.Finding{finding(c, imp, m, "pprof is registered on an exposed default HTTP server.", "Importing net/http/pprof registers diagnostic handlers on DefaultServeMux, which is served here without a custom handler.", "Serve pprof on a private listener or protected, dedicated mux; do not expose DefaultServeMux publicly.")}
	}}
}
