package framework

import "golang.org/x/tools/go/packages"

type Framework interface {
	Name() string
	Detect(*packages.Package) bool
}

type importFramework struct{ name, path string }

func (f importFramework) Name() string                    { return f.name }
func (f importFramework) Detect(p *packages.Package) bool { _, ok := p.Imports[f.path]; return ok }

func Detect(p *packages.Package) []string {
	known := []Framework{
		importFramework{"net/http", "net/http"},
		importFramework{"gin", "github.com/gin-gonic/gin"},
		importFramework{"chi", "github.com/go-chi/chi/v5"},
		importFramework{"echo", "github.com/labstack/echo/v4"},
		importFramework{"fiber", "github.com/gofiber/fiber/v2"},
		importFramework{"fiber", "github.com/gofiber/fiber/v3"},
		importFramework{"templ", "github.com/a-h/templ"},
	}
	var names []string
	seen := map[string]bool{}
	for _, f := range known {
		if f.Detect(p) && !seen[f.Name()] {
			names = append(names, f.Name())
			seen[f.Name()] = true
		}
	}
	return names
}
