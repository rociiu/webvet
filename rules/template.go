package rules

import (
	"go/ast"
	"go/types"

	"github.com/rociiu/webvet/report"
)

func templateRule() Rule {
	m := Metadata{ID: "WEBVET-TEMPLATE-001", Name: "Unsafe template content", Description: "untrusted HTTP input converted to a trusted html/template type", Severity: report.High, CWE: "CWE-79", Confidence: report.ConfidenceHigh, Frameworks: []string{"net/http", "gin", "chi"}}
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
				if !ok || len(call.Args) != 1 || !templateSink(c, call) {
					return true
				}
				if exprTainted(c, call.Args[0], tainted) {
					out = append(out, finding(c, call, m, "User-controlled HTTP input is converted to "+sinkName(c, call)+".", "Trusted html/template content types bypass contextual escaping, so request data can become executable markup or script.", "Pass the original string to html/template, or sanitize it with a trusted context-appropriate sanitizer before conversion."))
				}
				return true
			})
		}
		return out
	}}
}

func taintedVariables(c *Context, body *ast.BlockStmt) map[*types.Var]bool {
	tainted := map[*types.Var]bool{}
	// Iterate to a fixed point so straightforward assignment chains work regardless of statement shape.
	for changed := true; changed; {
		changed = false
		ast.Inspect(body, func(n ast.Node) bool {
			switch x := n.(type) {
			case *ast.AssignStmt:
				for i, rhs := range x.Rhs {
					if i < len(x.Lhs) && exprTainted(c, rhs, tainted) {
						if id, ok := x.Lhs[i].(*ast.Ident); ok {
							if v, ok := c.Types.ObjectOf(id).(*types.Var); ok && !tainted[v] {
								tainted[v] = true
								changed = true
							}
						}
					}
				}
			case *ast.ValueSpec:
				for i, rhs := range x.Values {
					if i < len(x.Names) && exprTainted(c, rhs, tainted) {
						if v, ok := c.Types.ObjectOf(x.Names[i]).(*types.Var); ok && !tainted[v] {
							tainted[v] = true
							changed = true
						}
					}
				}
			}
			return true
		})
	}
	return tainted
}

func exprTainted(c *Context, e ast.Expr, vars map[*types.Var]bool) bool {
	switch x := e.(type) {
	case *ast.Ident:
		v, ok := c.Types.ObjectOf(x).(*types.Var)
		return ok && vars[v]
	case *ast.CallExpr:
		if isSourceCall(c.Types, x) {
			return true
		}
		for _, a := range x.Args {
			if exprTainted(c, a, vars) {
				return true
			}
		}
	case *ast.SelectorExpr:
		return exprTainted(c, x.X, vars)
	case *ast.ParenExpr:
		return exprTainted(c, x.X, vars)
	case *ast.IndexExpr:
		return exprTainted(c, x.X, vars) || exprTainted(c, x.Index, vars)
	}
	return false
}
func isSourceCall(info *types.Info, call *ast.CallExpr) bool {
	sel, ok := call.Fun.(*ast.SelectorExpr)
	if !ok {
		return false
	}
	obj, ok := info.Uses[sel.Sel].(*types.Func)
	if !ok || obj.Pkg() == nil {
		return false
	}
	p, n := obj.Pkg().Path(), obj.Name()
	if p == "net/http" && (n == "FormValue" || n == "PostFormValue" || n == "Get") {
		return true
	}
	if p == "net/url" && n == "Get" {
		return true
	}
	if p == "github.com/go-chi/chi/v5" && n == "URLParam" {
		return true
	}
	if p == "github.com/gorilla/mux" && n == "Vars" {
		return true
	}
	return p == "github.com/gin-gonic/gin" && (n == "Query" || n == "Param" || n == "PostForm")
}
func templateSink(c *Context, call *ast.CallExpr) bool { return sinkName(c, call) != "" }
func sinkName(c *Context, call *ast.CallExpr) string {
	n, ok := c.Types.TypeOf(call).(*types.Named)
	if !ok || n.Obj().Pkg() == nil || n.Obj().Pkg().Path() != "html/template" {
		return ""
	}
	switch n.Obj().Name() {
	case "HTML", "JS", "URL", "CSS", "HTMLAttr":
		return "template." + n.Obj().Name()
	}
	return ""
}
