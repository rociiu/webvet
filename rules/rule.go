package rules

import (
	"go/ast"
	"go/token"
	"go/types"
	"strconv"
	"strings"

	"github.com/rociiu/webvet/report"
	"golang.org/x/tools/go/packages"
)

type Metadata struct {
	ID          string            `json:"id"`
	Name        string            `json:"name"`
	Description string            `json:"description"`
	Severity    report.Severity   `json:"severity"`
	CWE         string            `json:"cwe,omitempty"`
	Confidence  report.Confidence `json:"confidence"`
	Frameworks  []string          `json:"frameworks"`
}
type Context struct {
	Package        *packages.Package
	File           *ast.File
	Fset           *token.FileSet
	Types          *types.Info
	TaintSummaries map[string]bool
}
type Rule interface {
	Meta() Metadata
	Run(*Context) []report.Finding
}
type rule struct {
	meta Metadata
	run  func(*Context) []report.Finding
}

func (r rule) Meta() Metadata                  { return r.meta }
func (r rule) Run(c *Context) []report.Finding { return r.run(c) }

func finding(c *Context, n ast.Node, m Metadata, message, explanation, fix string) report.Finding {
	p := c.Fset.Position(n.Pos())
	return report.Finding{RuleID: m.ID, Severity: m.Severity, Confidence: m.Confidence, Filename: p.Filename, Line: p.Line, Column: p.Column, Message: message, Explanation: explanation, Remediation: fix, CWE: m.CWE}
}
func objectPath(info *types.Info, e ast.Expr) string {
	s, ok := e.(*ast.SelectorExpr)
	if !ok {
		return ""
	}
	obj := info.Uses[s.Sel]
	if obj == nil || obj.Pkg() == nil {
		return ""
	}
	return obj.Pkg().Path() + "." + obj.Name()
}
func callPath(info *types.Info, c *ast.CallExpr) string { return objectPath(info, c.Fun) }
func stringLiteral(e ast.Expr) (string, bool) {
	l, ok := e.(*ast.BasicLit)
	if !ok || l.Kind != token.STRING {
		return "", false
	}
	v, err := strconv.Unquote(l.Value)
	return v, err == nil
}
func boolLiteral(e ast.Expr) (bool, bool) {
	i, ok := e.(*ast.Ident)
	if !ok {
		return false, false
	}
	if i.Name == "true" {
		return true, true
	}
	if i.Name == "false" {
		return false, true
	}
	return false, false
}
func fieldMap(lit *ast.CompositeLit) map[string]ast.Expr {
	m := map[string]ast.Expr{}
	for _, e := range lit.Elts {
		if kv, ok := e.(*ast.KeyValueExpr); ok {
			if id, ok := kv.Key.(*ast.Ident); ok {
				m[id.Name] = kv.Value
			}
		}
	}
	return m
}
func compositeTypePath(info *types.Info, lit *ast.CompositeLit) string {
	t := info.TypeOf(lit)
	if p, ok := t.(*types.Pointer); ok {
		t = p.Elem()
	}
	n, ok := t.(*types.Named)
	if !ok || n.Obj().Pkg() == nil {
		return ""
	}
	return n.Obj().Pkg().Path() + "." + n.Obj().Name()
}
func sensitiveCookie(name string) bool {
	n := strings.ToLower(strings.ReplaceAll(name, "-", "_"))
	switch n {
	case "session", "session_id", "auth", "token", "access_token", "jwt", "refresh_token":
		return true
	}
	return strings.HasPrefix(n, "session_") || strings.HasPrefix(n, "auth_")
}
