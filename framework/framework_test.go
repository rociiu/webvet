package framework_test

import (
	"testing"

	"github.com/rociiu/webvet/framework"
	"golang.org/x/tools/go/packages"
)

func TestDetect(t *testing.T) {
	pkg := &packages.Package{Imports: map[string]*packages.Package{"net/http": {}, "github.com/labstack/echo/v4": {}, "github.com/gofiber/fiber/v2": {}, "github.com/gofiber/fiber/v3": {}}}
	got := framework.Detect(pkg)
	if len(got) != 3 || got[0] != "net/http" || got[1] != "echo" || got[2] != "fiber" {
		t.Fatalf("unexpected frameworks: %v", got)
	}
}
