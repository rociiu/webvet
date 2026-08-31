package securityroutes

import (
	"net/http"

	"github.com/go-chi/chi/v5"
)

func cookieAuth(next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) { _, _ = r.Cookie("session"); next.ServeHTTP(w, r) })
}
func csrfMiddleware(next http.Handler) http.Handler { return next }
func update(http.ResponseWriter, *http.Request)     {}

func Routes() chi.Router {
	r := chi.NewRouter()
	r.With(cookieAuth).Post("/unsafe", update)
	r.With(cookieAuth, csrfMiddleware).Post("/safe", update)
	return r
}
