package analyzer

import (
	"fmt"
	"go/ast"
	"go/token"
	"sort"
	"strings"

	"github.com/rociiu/webvet/report"
	"github.com/rociiu/webvet/route"
	"github.com/rociiu/webvet/rules"
	"golang.org/x/tools/go/packages"
)

type Result struct {
	Findings []report.Finding
	Routes   []route.Route
}

type Options struct {
	Dir        string
	Disabled   map[string]bool
	Enabled    map[string]bool
	RoutesOnly bool
}

func Run(patterns []string, opts Options) (Result, error) {
	if len(patterns) == 0 {
		patterns = []string{"."}
	}
	cfg := &packages.Config{
		Mode: packages.NeedName | packages.NeedFiles | packages.NeedCompiledGoFiles |
			packages.NeedSyntax | packages.NeedTypes | packages.NeedTypesInfo |
			packages.NeedImports | packages.NeedDeps | packages.NeedModule,
		Dir:  opts.Dir,
		Fset: token.NewFileSet(),
	}
	pkgs, err := packages.Load(cfg, patterns...)
	if err != nil {
		return Result{}, fmt.Errorf("load packages: %w", err)
	}
	if n := packages.PrintErrors(pkgs); n > 0 {
		return Result{}, fmt.Errorf("package loading failed with %d error(s)", n)
	}
	var out Result
	for _, pkg := range pkgs {
		if pkg.TypesInfo == nil {
			continue
		}
		result := analyzePackage(pkg, opts)
		out.Routes = append(out.Routes, result.Routes...)
		out.Findings = append(out.Findings, result.Findings...)
	}
	sort.Slice(out.Findings, func(i, j int) bool {
		a, b := out.Findings[i], out.Findings[j]
		if a.Filename != b.Filename {
			return a.Filename < b.Filename
		}
		if a.Line != b.Line {
			return a.Line < b.Line
		}
		if a.Column != b.Column {
			return a.Column < b.Column
		}
		return a.RuleID < b.RuleID
	})
	sort.Slice(out.Routes, func(i, j int) bool {
		a, b := out.Routes[i], out.Routes[j]
		if a.Path != b.Path {
			return a.Path < b.Path
		}
		if a.Method != b.Method {
			return a.Method < b.Method
		}
		return a.Position.Filename < b.Position.Filename
	})
	return out, nil
}

func analyzePackage(pkg *packages.Package, opts Options) Result {
	routes := route.Collect(pkg)
	out := Result{Routes: routes}
	if opts.RoutesOnly {
		return out
	}
	for _, file := range pkg.Syntax {
		ctx := &rules.Context{Package: pkg, File: file, Fset: pkg.Fset, Types: pkg.TypesInfo}
		for _, rule := range rules.Default() {
			id := rule.Meta().ID
			if opts.Disabled[id] && !opts.Enabled[id] {
				continue
			}
			for _, finding := range rule.Run(ctx) {
				if !suppressed(file, pkg.Fset, finding) {
					out.Findings = append(out.Findings, finding)
				}
			}
		}
	}
	if !opts.Disabled["WEBVET-ROUTE-002"] || opts.Enabled["WEBVET-ROUTE-002"] {
		for _, finding := range rules.CheckSensitiveRoutes(routes) {
			if !suppressedInPackage(pkg, finding) {
				out.Findings = append(out.Findings, finding)
			}
		}
	}
	if !opts.Disabled["WEBVET-ROUTE-001"] || opts.Enabled["WEBVET-ROUTE-001"] {
		for _, finding := range rules.CheckStateChangingGET(pkg, routes) {
			if !suppressedInPackage(pkg, finding) {
				out.Findings = append(out.Findings, finding)
			}
		}
	}
	if !opts.Disabled["WEBVET-ROUTE-003"] || opts.Enabled["WEBVET-ROUTE-003"] {
		for _, finding := range rules.CheckCSRF(pkg, routes) {
			if !suppressedInPackage(pkg, finding) {
				out.Findings = append(out.Findings, finding)
			}
		}
	}
	return out
}

func suppressedInPackage(pkg *packages.Package, finding report.Finding) bool {
	for _, file := range pkg.Syntax {
		if pkg.Fset.Position(file.Pos()).Filename == finding.Filename {
			return suppressed(file, pkg.Fset, finding)
		}
	}
	return false
}

func suppressed(file *ast.File, fset *token.FileSet, finding report.Finding) bool {
	for _, group := range file.Comments {
		for _, c := range group.List {
			text := strings.TrimSpace(strings.TrimPrefix(c.Text, "//"))
			prefix := "webvet:ignore " + finding.RuleID + " -- "
			if !strings.HasPrefix(text, prefix) || strings.TrimSpace(strings.TrimPrefix(text, prefix)) == "" {
				continue
			}
			line := fset.Position(c.Pos()).Line
			if finding.Line >= line && finding.Line <= line+2 {
				return true
			}
		}
	}
	return false
}
