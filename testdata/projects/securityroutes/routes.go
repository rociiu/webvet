package securityroutes

import (
	"net/http"

	"github.com/go-chi/chi/v5"
)

func cookieAuth(next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) { _, _ = r.Cookie("session"); next.ServeHTTP(w, r) })
}
func csrfMiddleware(next http.Handler) http.Handler { return next }
func requireRole(next http.Handler) http.Handler    { return next }
func hasPermission(string) bool                     { return true }
func policyGate(next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if hasPermission("admin") {
			next.ServeHTTP(w, r)
		}
	})
}
func update(http.ResponseWriter, *http.Request) {}

func Routes() chi.Router {
	r := chi.NewRouter()
	r.With(cookieAuth).Post("/unsafe", update)
	r.With(cookieAuth, csrfMiddleware).Post("/safe", update)
	r.With(cookieAuth).Get("/admin/missing", update)
	r.With(cookieAuth, requireRole).Get("/admin/safe", update)
	r.With(cookieAuth, policyGate).Get("/admin/body-policy", update)
	r.With(cookieAuth).Get("/account", update)
	return r
}
