package main

import (
	"html/template"
	"net/http"

	"github.com/go-chi/chi/v5"
)

func auth(next http.Handler) http.Handler     { return next }
func home(http.ResponseWriter, *http.Request) {}
func profile(w http.ResponseWriter, r *http.Request) {
	bio := r.FormValue("bio")
	_ = template.HTML(bio)
	http.SetCookie(w, &http.Cookie{Name: "session", Value: "token"})
}
func metrics(http.ResponseWriter, *http.Request) {}

func main() {
	r := chi.NewRouter()
	r.Get("/", home)
	r.With(auth).Get("/profile", profile)
	r.Get("/metrics", metrics)
	r.Route("/admin", func(r chi.Router) {
		r.Use(auth)
		r.Get("/users", home)
	})
	http.HandleFunc("/health", home)
	srv := &http.Server{Addr: ":8080", Handler: r}
	_ = srv.ListenAndServe()
}
