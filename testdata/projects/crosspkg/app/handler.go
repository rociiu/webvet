package app

import (
	"html/template"
	"net/http"

	"github.com/rociiu/webvet/testdata/projects/crosspkg/source"
)

func UnsafeTemplate(r *http.Request) template.HTML {
	value := source.ChainedValue(r)
	return template.HTML(value)
}
func UnsafeRedirect(w http.ResponseWriter, r *http.Request) {
	http.Redirect(w, r, source.RequestValue(r), http.StatusFound)
}
func SafeRedirect(w http.ResponseWriter, r *http.Request) {
	http.Redirect(w, r, source.ConstantValue(), http.StatusFound)
}
