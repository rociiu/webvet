package analyzer

import (
	"github.com/rociiu/webvet/rules"
	"golang.org/x/tools/go/analysis"
)

// New returns a standard go/analysis adapter. The CLI uses Run so route
// collection and all rules share one package load; integrations can use this
// analyzer directly.
func New() *analysis.Analyzer {
	return &analysis.Analyzer{
		Name: "webvet",
		Doc:  "checks Go web-application security semantics",
		Run: func(pass *analysis.Pass) (any, error) {
			for _, file := range pass.Files {
				ctx := &rules.Context{File: file, Fset: pass.Fset, Types: pass.TypesInfo}
				for _, r := range rules.Default() {
					for _, f := range r.Run(ctx) {
						pos := pass.Fset.File(file.Pos()).LineStart(f.Line)
						pass.Report(analysis.Diagnostic{Pos: pos, Category: f.RuleID, Message: f.Message})
					}
				}
			}
			return nil, nil
		},
	}
}
