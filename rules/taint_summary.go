package rules

import (
	"go/ast"
	"go/types"

	"golang.org/x/tools/go/packages"
)

// BuildTaintSummaries identifies application helpers whose return values are
// derived from HTTP request sources. The fixed point supports chains of small
// wrapper functions without constructing a whole-program SSA graph.
func BuildTaintSummaries(pkgs []*packages.Package) map[string]bool {
	summaries := map[string]bool{}
	for changed := true; changed; {
		changed = false
		for _, pkg := range pkgs {
			if pkg == nil || pkg.TypesInfo == nil {
				continue
			}
			for _, file := range pkg.Syntax {
				ctx := &Context{Package: pkg, File: file, Fset: pkg.Fset, Types: pkg.TypesInfo, TaintSummaries: summaries}
				for _, decl := range file.Decls {
					fn, ok := decl.(*ast.FuncDecl)
					if !ok || fn.Body == nil {
						continue
					}
					obj, ok := pkg.TypesInfo.Defs[fn.Name].(*types.Func)
					if !ok || summaries[functionKey(obj)] {
						continue
					}
					if functionReturnsTaint(ctx, fn) {
						summaries[functionKey(obj)] = true
						changed = true
					}
				}
			}
		}
	}
	return summaries
}

func functionReturnsTaint(c *Context, fn *ast.FuncDecl) bool {
	tainted := taintedVariables(c, fn.Body)
	found := false
	ast.Inspect(fn.Body, func(n ast.Node) bool {
		if found {
			return false
		}
		if _, ok := n.(*ast.FuncLit); ok {
			return false
		}
		ret, ok := n.(*ast.ReturnStmt)
		if !ok {
			return true
		}
		for _, result := range ret.Results {
			if exprTainted(c, result, tainted) {
				found = true
				return false
			}
		}
		return true
	})
	return found
}

func calledFunc(info *types.Info, call *ast.CallExpr) *types.Func {
	switch fun := call.Fun.(type) {
	case *ast.Ident:
		obj, _ := info.ObjectOf(fun).(*types.Func)
		return obj
	case *ast.SelectorExpr:
		obj, _ := info.Uses[fun.Sel].(*types.Func)
		return obj
	}
	return nil
}
func functionKey(fn *types.Func) string {
	if fn == nil || fn.Pkg() == nil {
		return ""
	}
	key := fn.Pkg().Path() + "."
	if sig, ok := fn.Type().(*types.Signature); ok && sig.Recv() != nil {
		key += types.TypeString(sig.Recv().Type(), func(p *types.Package) string { return p.Path() }) + "."
	}
	return key + fn.Name()
}
