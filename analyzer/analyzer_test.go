package analyzer_test

import (
	"path/filepath"
	"runtime"
	"testing"

	"github.com/rociiu/webvet/analyzer"
	"github.com/rociiu/webvet/route"
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
			if !r.Security.Auth.Detected {
				t.Fatalf("auth property not detected: %+v", r.Security)
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

func TestCrossPackageTaintSummary(t *testing.T) {
	t.Parallel()
	_, here, _, _ := runtime.Caller(0)
	root := filepath.Dir(filepath.Dir(here))
	result, err := analyzer.Run([]string{"./testdata/projects/crosspkg/app"}, analyzer.Options{Dir: root})
	if err != nil {
		t.Fatal(err)
	}
	seen := map[string]int{}
	for _, f := range result.Findings {
		seen[f.RuleID]++
	}
	if seen["WEBVET-TEMPLATE-001"] != 1 || seen["WEBVET-REDIRECT-001"] != 1 {
		t.Fatalf("cross-package findings: %v", seen)
	}
}

func TestRouteSecurityProperties(t *testing.T) {
	t.Parallel()
	_, here, _, _ := runtime.Caller(0)
	root := filepath.Dir(filepath.Dir(here))
	result, err := analyzer.Run([]string{"./testdata/projects/securityroutes"}, analyzer.Options{Dir: root})
	if err != nil {
		t.Fatal(err)
	}
	properties := map[string]route.Security{}
	for _, r := range result.Routes {
		properties[r.Path] = r.Security
	}
	unsafe := properties["/unsafe"]
	if !unsafe.Auth.Detected || !unsafe.CookieAuth.Detected || unsafe.CSRF.Detected {
		t.Fatalf("unsafe properties: %+v", unsafe)
	}
	safe := properties["/safe"]
	if !safe.Auth.Detected || !safe.CookieAuth.Detected || !safe.CSRF.Detected {
		t.Fatalf("safe properties: %+v", safe)
	}
	count := 0
	for _, f := range result.Findings {
		if f.RuleID == "WEBVET-ROUTE-003" {
			count++
		}
	}
	if count != 1 {
		t.Fatalf("CSRF findings=%d, want 1", count)
	}
}

func TestRouteAuthorizationProperties(t *testing.T) {
	t.Parallel()
	_, here, _, _ := runtime.Caller(0)
	root := filepath.Dir(filepath.Dir(here))
	result, err := analyzer.Run([]string{"./testdata/projects/securityroutes"}, analyzer.Options{Dir: root})
	if err != nil {
		t.Fatal(err)
	}

	wantProtected := map[string]bool{
		"chi /admin/safe":        false,
		"chi /admin/body-policy": false,
	}
	for _, r := range result.Routes {
		key := r.Framework + " " + r.Path
		if _, ok := wantProtected[key]; ok && r.Security.Authorization.Detected {
			wantProtected[key] = true
		}
	}
	for key, detected := range wantProtected {
		if !detected {
			t.Errorf("authorization not detected for %s", key)
		}
	}

	findings := 0
	for _, f := range result.Findings {
		if f.RuleID == "WEBVET-ROUTE-004" {
			findings++
			if f.Route != "GET /admin/missing" {
				t.Errorf("unexpected authorization finding: %+v", f)
			}
		}
	}
	if findings != 1 {
		t.Fatalf("authorization findings=%d, want 1", findings)
	}
}
