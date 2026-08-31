package route

import (
	"go/ast"
	"go/token"
	"strconv"

	"golang.org/x/tools/go/packages"
)

var routeMethods = map[string]string{
	"Get": "GET", "Post": "POST", "Put": "PUT", "Patch": "PATCH", "Delete": "DELETE", "Head": "HEAD", "Options": "OPTIONS",
	"GET": "GET", "POST": "POST", "PUT": "PUT", "PATCH": "PATCH", "DELETE": "DELETE", "HEAD": "HEAD", "OPTIONS": "OPTIONS",
}

func Collect(pkg *packages.Package) []Route {
	var out []Route
	for _, f := range pkg.Syntax {
		ast.Inspect(f, func(n ast.Node) bool {
			call, ok := n.(*ast.CallExpr)
			if !ok {
				return true
			}
			sel, ok := call.Fun.(*ast.SelectorExpr)
			if !ok {
				return true
			}
			if (sel.Sel.Name == "Handle" || sel.Sel.Name == "HandleFunc") && len(call.Args) >= 2 && selectorPackage(pkg, sel) == "net/http" {
				path, ok := stringValue(call.Args[0])
				if ok {
					out = append(out, Route{Method: "ANY", Path: path, Handler: exprName(call.Args[1]), Framework: "net/http", Position: pkg.Fset.Position(call.Pos())})
				}
				return true
			}
			method, ok := routeMethods[sel.Sel.Name]
			if !ok || len(call.Args) < 2 {
				return true
			}
			path, ok := stringValue(call.Args[0])
			if !ok {
				return true
			}
			framework := inferFramework(pkg, sel)
			if framework == "" {
				return true
			}
			handlerIndex := len(call.Args) - 1
			mws := middlewareFromReceiver(sel.X)
			if framework == "gin" && handlerIndex > 1 {
				for _, a := range call.Args[1:handlerIndex] {
					mws = append(mws, Middleware{Name: exprName(a)})
				}
			}
			out = append(out, Route{Method: method, Path: path, Handler: exprName(call.Args[handlerIndex]), Middleware: cleanMiddleware(mws), Framework: framework, Position: pkg.Fset.Position(call.Pos())})
			return true
		})
	}
	return out
}

func inferFramework(pkg *packages.Package, sel *ast.SelectorExpr) string {
	switch selectorPackage(pkg, sel) {
	case "github.com/gin-gonic/gin":
		return "gin"
	case "github.com/go-chi/chi/v5":
		return "chi"
	}
	return ""
}

func selectorPackage(pkg *packages.Package, sel *ast.SelectorExpr) string {
	obj := pkg.TypesInfo.Uses[sel.Sel]
	if obj == nil || obj.Pkg() == nil {
		return ""
	}
	return obj.Pkg().Path()
}

func middlewareFromReceiver(e ast.Expr) []Middleware {
	call, ok := e.(*ast.CallExpr)
	if !ok {
		return nil
	}
	sel, ok := call.Fun.(*ast.SelectorExpr)
	if !ok || sel.Sel.Name != "With" {
		return nil
	}
	var out []Middleware
	for _, a := range call.Args {
		out = append(out, Middleware{Name: exprName(a)})
	}
	return out
}

func cleanMiddleware(in []Middleware) []Middleware {
	var out []Middleware
	for _, m := range in {
		if m.Name != "" {
			out = append(out, m)
		}
	}
	return out
}

func stringValue(e ast.Expr) (string, bool) {
	b, ok := e.(*ast.BasicLit)
	if !ok || b.Kind != token.STRING {
		return "", false
	}
	s, err := strconv.Unquote(b.Value)
	return s, err == nil
}
func exprName(e ast.Expr) string {
	switch x := e.(type) {
	case *ast.Ident:
		return x.Name
	case *ast.CallExpr:
		return exprName(x.Fun)
	case *ast.SelectorExpr:
		p := exprName(x.X)
		if p != "" {
			return p + "." + x.Sel.Name
		}
		return x.Sel.Name
	}
	return ""
}
