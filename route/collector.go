package route

import (
	"go/ast"
	"go/token"
	"go/types"
	"path"
	"strconv"
	"strings"

	"golang.org/x/tools/go/packages"
)

var routeMethods = map[string]string{
	"Get": "GET", "Post": "POST", "Put": "PUT", "Patch": "PATCH", "Delete": "DELETE", "Head": "HEAD", "Options": "OPTIONS",
	"GET": "GET", "POST": "POST", "PUT": "PUT", "PATCH": "PATCH", "DELETE": "DELETE", "HEAD": "HEAD", "OPTIONS": "OPTIONS",
}

type routerState struct {
	framework  string
	prefix     string
	middleware []Middleware
}

func (s *routerState) clone() *routerState {
	return &routerState{framework: s.framework, prefix: s.prefix, middleware: append([]Middleware(nil), s.middleware...)}
}

type collector struct {
	pkg    *packages.Package
	routes []Route
}

// Collect builds a small route graph by walking router setup statements in
// source order. Group-local middleware is isolated from the parent router.
func Collect(pkg *packages.Package) []Route {
	c := &collector{pkg: pkg}
	for _, file := range pkg.Syntax {
		for _, decl := range file.Decls {
			if fn, ok := decl.(*ast.FuncDecl); ok && fn.Body != nil {
				c.block(fn.Body, map[types.Object]*routerState{})
			}
		}
	}
	return c.routes
}

func (c *collector) block(block *ast.BlockStmt, env map[types.Object]*routerState) {
	for _, stmt := range block.List {
		c.statement(stmt, env)
	}
}

func (c *collector) statement(stmt ast.Stmt, env map[types.Object]*routerState) {
	switch s := stmt.(type) {
	case *ast.AssignStmt:
		for i, rhs := range s.Rhs {
			if i >= len(s.Lhs) {
				continue
			}
			if state := c.state(rhs, env); state != nil {
				if id, ok := s.Lhs[i].(*ast.Ident); ok {
					env[c.pkg.TypesInfo.ObjectOf(id)] = state
				}
			}
		}
	case *ast.DeclStmt:
		decl, ok := s.Decl.(*ast.GenDecl)
		if !ok {
			return
		}
		for _, spec := range decl.Specs {
			vs, ok := spec.(*ast.ValueSpec)
			if !ok {
				continue
			}
			for i, rhs := range vs.Values {
				if i < len(vs.Names) {
					if state := c.state(rhs, env); state != nil {
						env[c.pkg.TypesInfo.ObjectOf(vs.Names[i])] = state
					}
				}
			}
		}
	case *ast.ExprStmt:
		if call, ok := s.X.(*ast.CallExpr); ok {
			c.call(call, env)
		}
	case *ast.BlockStmt:
		c.block(s, cloneEnv(env))
	case *ast.IfStmt:
		branch := cloneEnv(env)
		if s.Init != nil {
			c.statement(s.Init, branch)
		}
		c.block(s.Body, branch)
		if s.Else != nil {
			c.statement(s.Else, cloneEnv(env))
		}
	case *ast.ForStmt:
		loop := cloneEnv(env)
		if s.Init != nil {
			c.statement(s.Init, loop)
		}
		c.block(s.Body, loop)
	case *ast.RangeStmt:
		c.block(s.Body, cloneEnv(env))
	case *ast.SwitchStmt:
		for _, item := range s.Body.List {
			if clause, ok := item.(*ast.CaseClause); ok {
				for _, child := range clause.Body {
					c.statement(child, cloneEnv(env))
				}
			}
		}
	case *ast.TypeSwitchStmt:
		for _, item := range s.Body.List {
			if clause, ok := item.(*ast.CaseClause); ok {
				for _, child := range clause.Body {
					c.statement(child, cloneEnv(env))
				}
			}
		}
	case *ast.GoStmt:
		c.call(s.Call, env)
	case *ast.DeferStmt:
		c.call(s.Call, env)
	case *ast.LabeledStmt:
		c.statement(s.Stmt, env)
	}
}

func (c *collector) call(call *ast.CallExpr, env map[types.Object]*routerState) {
	sel, ok := call.Fun.(*ast.SelectorExpr)
	if !ok {
		return
	}
	if (sel.Sel.Name == "Handle" || sel.Sel.Name == "HandleFunc") && len(call.Args) >= 2 && selectorPackage(c.pkg, sel) == "net/http" {
		if routePath, ok := stringValue(call.Args[0]); ok {
			c.add("ANY", routePath, "net/http", call.Args[1], nil, call)
		}
		return
	}
	state := c.state(sel.X, env)
	if state == nil {
		return
	}
	if sel.Sel.Name == "Use" {
		for _, arg := range call.Args {
			if name := exprName(arg); name != "" {
				state.middleware = append(state.middleware, Middleware{Name: name})
			}
		}
		return
	}
	if state.framework == "chi" && (sel.Sel.Name == "Route" || sel.Sel.Name == "Group") {
		c.chiGroup(state, sel.Sel.Name, call, env)
		return
	}
	method, ok := routeMethods[sel.Sel.Name]
	if !ok || len(call.Args) < 2 {
		return
	}
	routePath, ok := stringValue(call.Args[0])
	if !ok {
		return
	}
	handlerIndex := len(call.Args) - 1
	middleware := append([]Middleware(nil), state.middleware...)
	if state.framework == "gin" && handlerIndex > 1 {
		for _, arg := range call.Args[1:handlerIndex] {
			if name := exprName(arg); name != "" {
				middleware = append(middleware, Middleware{Name: name})
			}
		}
	}
	c.add(method, joinRoute(state.prefix, routePath), state.framework, call.Args[handlerIndex], middleware, call)
}

func (c *collector) chiGroup(parent *routerState, name string, call *ast.CallExpr, env map[types.Object]*routerState) {
	if len(call.Args) == 0 {
		return
	}
	child := parent.clone()
	callbackIndex := 0
	if name == "Route" {
		if len(call.Args) < 2 {
			return
		}
		prefix, ok := stringValue(call.Args[0])
		if !ok {
			return
		}
		child.prefix = joinRoute(child.prefix, prefix)
		callbackIndex = 1
	}
	fn, ok := call.Args[callbackIndex].(*ast.FuncLit)
	if !ok || fn.Body == nil {
		return
	}
	inner := cloneEnv(env)
	if fn.Type.Params != nil && len(fn.Type.Params.List) > 0 && len(fn.Type.Params.List[0].Names) > 0 {
		inner[c.pkg.TypesInfo.ObjectOf(fn.Type.Params.List[0].Names[0])] = child
	}
	c.block(fn.Body, inner)
}

func (c *collector) state(expr ast.Expr, env map[types.Object]*routerState) *routerState {
	switch x := expr.(type) {
	case *ast.Ident:
		return env[c.pkg.TypesInfo.ObjectOf(x)]
	case *ast.ParenExpr:
		return c.state(x.X, env)
	case *ast.CallExpr:
		p := callPath(c.pkg, x)
		if p == "github.com/go-chi/chi/v5.NewRouter" {
			return &routerState{framework: "chi"}
		}
		if p == "github.com/gin-gonic/gin.New" || p == "github.com/gin-gonic/gin.Default" {
			return &routerState{framework: "gin"}
		}
		sel, ok := x.Fun.(*ast.SelectorExpr)
		if !ok {
			return nil
		}
		base := c.state(sel.X, env)
		if base == nil {
			return nil
		}
		child := base.clone()
		switch sel.Sel.Name {
		case "With":
			for _, arg := range x.Args {
				if name := exprName(arg); name != "" {
					child.middleware = append(child.middleware, Middleware{Name: name})
				}
			}
			return child
		case "Group":
			if base.framework != "gin" || len(x.Args) == 0 {
				return nil
			}
			prefix, ok := stringValue(x.Args[0])
			if !ok {
				return nil
			}
			child.prefix = joinRoute(child.prefix, prefix)
			for _, arg := range x.Args[1:] {
				if name := exprName(arg); name != "" {
					child.middleware = append(child.middleware, Middleware{Name: name})
				}
			}
			return child
		}
	}
	return nil
}

func (c *collector) add(method, routePath, framework string, handler ast.Expr, middleware []Middleware, node ast.Node) {
	c.routes = append(c.routes, Route{Method: method, Path: routePath, Handler: exprName(handler), Middleware: cleanMiddleware(middleware), Framework: framework, Position: c.pkg.Fset.Position(node.Pos())})
}

func cloneEnv(in map[types.Object]*routerState) map[types.Object]*routerState {
	out := make(map[types.Object]*routerState, len(in))
	for k, v := range in {
		out[k] = v
	}
	return out
}
func joinRoute(prefix, suffix string) string {
	if prefix == "" {
		if suffix == "" {
			return "/"
		}
		return suffix
	}
	if suffix == "" || suffix == "/" {
		return prefix
	}
	return strings.TrimSuffix(prefix, "/") + "/" + strings.TrimPrefix(suffix, "/")
}
func selectorPackage(pkg *packages.Package, sel *ast.SelectorExpr) string {
	obj := pkg.TypesInfo.Uses[sel.Sel]
	if obj == nil || obj.Pkg() == nil {
		return ""
	}
	return obj.Pkg().Path()
}
func callPath(pkg *packages.Package, call *ast.CallExpr) string {
	switch f := call.Fun.(type) {
	case *ast.Ident:
		if obj := pkg.TypesInfo.ObjectOf(f); obj != nil && obj.Pkg() != nil {
			return obj.Pkg().Path() + "." + obj.Name()
		}
	case *ast.SelectorExpr:
		if obj := pkg.TypesInfo.Uses[f.Sel]; obj != nil && obj.Pkg() != nil {
			return obj.Pkg().Path() + "." + obj.Name()
		}
	}
	return ""
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
	case *ast.IndexExpr:
		return exprName(x.X)
	case *ast.ParenExpr:
		return exprName(x.X)
	}
	return path.Base(types.ExprString(e))
}
