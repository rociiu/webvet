// Command chi-example is a minimal, safely configured Chi application used to
// keep the supported framework dependency exercised outside Go's ignored
// testdata directories.
package main

import (
	"net/http"
	"time"

	"github.com/go-chi/chi/v5"
)

func home(w http.ResponseWriter, _ *http.Request) { _, _ = w.Write([]byte("ok")) }

func main() {
	r := chi.NewRouter()
	r.Get("/", home)
	srv := &http.Server{Addr: ":8080", Handler: r, ReadHeaderTimeout: 5 * time.Second}
	_ = srv.ListenAndServe()
}
