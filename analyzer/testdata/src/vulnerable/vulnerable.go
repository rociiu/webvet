package vulnerable

import (
	"html/template"
	"net/http"
	_ "net/http/pprof" // want `pprof is registered on an exposed default HTTP server`
	"time"

	"github.com/gin-gonic/gin"
	"github.com/rs/cors"
)

var goodServer = &http.Server{ReadHeaderTimeout: 5 * time.Second}

func badServer() {
	_ = &http.Server{} // want `http.Server does not configure ReadHeaderTimeout`
}

func cookies(w http.ResponseWriter) {
	http.SetCookie(w, &http.Cookie{ // want `Authentication cookie "session" does not enable HttpOnly` `Authentication cookie "session" does not enable Secure`
		Name: "session",
	})
	http.SetCookie(w, &http.Cookie{Name: "theme"})
	http.SetCookie(w, &http.Cookie{Name: "session", HttpOnly: true, Secure: true})
	http.SetCookie(w, &http.Cookie{ // want `Cookie "preference" uses SameSite=None without Secure`
		Name: "preference", SameSite: http.SameSiteNoneMode,
	})
}

func unsafeTemplate(_ http.ResponseWriter, r *http.Request) template.HTML {
	bio := r.FormValue("bio")
	return template.HTML(bio) // want `User-controlled HTTP input is converted to template.HTML`
}

func safeTemplate(_ http.ResponseWriter, _ *http.Request) template.HTML {
	return template.HTML("<b>constant</b>")
}

func exposePprof() { _ = http.ListenAndServe(":6060", nil) }

func unsafeGin(engine *gin.Engine) {
	_ = engine.SetTrustedProxies([]string{"0.0.0.0/0"}) // want `Gin is configured to trust all proxies`
}

var badCORS = cors.Options{ // want `CORS allows credentials with a wildcard origin`
	AllowedOrigins: []string{"*"}, AllowCredentials: true,
}
