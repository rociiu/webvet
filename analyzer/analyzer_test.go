package analyzer_test

import (
	"path/filepath"
	"runtime"
	"testing"

	"github.com/rociiu/webvet/analyzer"
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

func TestSuppressionValidation(t *testing.T) {
	t.Parallel()
	_, here, _, _ := runtime.Caller(0)
	root := filepath.Dir(filepath.Dir(here))
	result, err := analyzer.Run([]string{"./testdata/projects/suppressions"}, analyzer.Options{Dir: root})
	if err != nil {
		t.Fatal(err)
	}
	count := 0
	for _, f := range result.Findings {
		if f.RuleID == "WEBVET-HTTP-001" {
			count++
		}
	}
	if count != 3 {
		t.Fatalf("got %d unsuppressed timeout findings, want 3", count)
	}
}

func TestRouteGraph(t *testing.T) {
	t.Parallel()
	_, here, _, _ := runtime.Caller(0)
	root := filepath.Dir(filepath.Dir(here))
	result, err := analyzer.Run([]string{"./testdata/projects/vulnerable", "./testdata/projects/vulnerable"}, analyzer.Options{Dir: root, RoutesOnly: true})
	if err != nil {
		t.Fatal(err)
	}
	found := 0
	for _, r := range result.Routes {
		if r.Path == "/admin/users" {
			found++
			if len(r.Middleware) != 1 || r.Middleware[0].Name != "auth" {
				t.Fatalf("middleware propagation failed: %+v", r)
			}
		}
	}
	if found != 1 {
		t.Fatalf("nested Chi route count=%d, want 1", found)
	}
}

func TestMultiFilePackage(t *testing.T) {
	t.Parallel()
	_, here, _, _ := runtime.Caller(0)
	root := filepath.Dir(filepath.Dir(here))
	result, err := analyzer.Run([]string{"./testdata/projects/multifile"}, analyzer.Options{Dir: root, RoutesOnly: true})
	if err != nil {
		t.Fatal(err)
	}
	if len(result.Routes) != 1 || result.Routes[0].Handler != "handler" {
		t.Fatalf("multi-file route collection failed: %+v", result.Routes)
	}
}
