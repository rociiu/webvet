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
	}
	var names []string
	for _, f := range known {
		if f.Detect(p) {
			names = append(names, f.Name())
		}
	}
	return names
}
