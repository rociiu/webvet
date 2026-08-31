package analyzer

import (
	"go/ast"
	"go/token"

	"golang.org/x/tools/go/analysis"
	"golang.org/x/tools/go/packages"
)

// New returns a standard go/analysis adapter. The CLI uses Run so route
// collection and all rules share one package load; integrations can use this
// analyzer directly.
func New() *analysis.Analyzer {
	return &analysis.Analyzer{
		Name: "webvet",
		Doc:  "checks Go web-application security semantics",
		Run: func(pass *analysis.Pass) (any, error) {
			pkg := &packages.Package{Fset: pass.Fset, Syntax: pass.Files, Types: pass.Pkg, TypesInfo: pass.TypesInfo}
			result := analyzePackage(pkg, Options{})
			for _, f := range result.Findings {
				if pos := findingPos(pass.Fset, pass.Files, f.Filename, f.Line, f.Column); pos.IsValid() {
					pass.Report(analysis.Diagnostic{Pos: pos, Category: f.RuleID, Message: f.Message})
				}
			}
			return nil, nil
		},
	}
}

func findingPos(fset *token.FileSet, files []*ast.File, filename string, line, column int) token.Pos {
	for _, file := range files {
		f := fset.File(file.Pos())
		if f == nil || fset.Position(file.Pos()).Filename != filename || line < 1 || line > f.LineCount() {
			continue
		}
		pos := f.LineStart(line)
		if column > 1 {
			pos += token.Pos(column - 1)
		}
		return pos
	}
	return token.NoPos
}
