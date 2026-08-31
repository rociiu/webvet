package analyzer_test

import (
	"path/filepath"
	"runtime"
	"testing"

	"github.com/webvet/webvet/analyzer"
	"golang.org/x/tools/go/analysis/analysistest"
)

func TestRules(t *testing.T) {
	t.Parallel()
	analysistest.Run(t, analysistest.TestData(), analyzer.New(), "vulnerable")
}

func TestSuppression(t *testing.T) {
	t.Parallel()
	_, here, _, _ := runtime.Caller(0)
	root := filepath.Dir(filepath.Dir(here))
	result, err := analyzer.Run([]string{"./testdata/projects/suppressed"}, analyzer.Options{Dir: root})
	if err != nil {
		t.Fatal(err)
	}
	for _, f := range result.Findings {
		if f.RuleID == "WEBVET-HTTP-001" {
			t.Fatalf("suppressed finding was reported: %+v", f)
		}
	}
}
