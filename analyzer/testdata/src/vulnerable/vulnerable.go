package vulnerable

import (
	"html/template"
	"io"
	"net/http"
	_ "net/http/pprof" // want `pprof is registered on an exposed default HTTP server`
	"time"

	"github.com/a-h/templ"
	"github.com/gin-gonic/gin"
	fiber2 "github.com/gofiber/fiber/v2"
	fiber3 "github.com/gofiber/fiber/v3"
	"github.com/labstack/echo/v4"
	"github.com/rs/cors"
)

var goodServer = &http.Server{ReadHeaderTimeout: 5 * time.Second, WriteTimeout: 10 * time.Second, IdleTimeout: 30 * time.Second}

func badServer() {
	_ = &http.Server{} // want `http.Server does not configure ReadHeaderTimeout` `http.Server does not configure a non-zero WriteTimeout` `http.Server does not configure a non-zero IdleTimeout`
}

func configuredAfterConstruction() {
	srv := &http.Server{}
	srv.ReadHeaderTimeout = 5 * time.Second
	srv.WriteTimeout = 10 * time.Second
	srv.IdleTimeout = 30 * time.Second
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

func htmlResponse(w http.ResponseWriter) {
	w.Header().Set("Content-Type", "text/html") // want `HTML response has no detected Content-Security-Policy or X-Frame-Options header`
}

func protectedHTML(w http.ResponseWriter) {
	w.Header().Set("Content-Type", "text/html")
	w.Header().Set("Content-Security-Policy", "default-src 'self'")
}

func readBody(_ http.ResponseWriter, r *http.Request) {
	_, _ = io.ReadAll(r.Body) // want `Request body is read without an explicit size limit`
}

func boundedBody(w http.ResponseWriter, r *http.Request) {
	r.Body = http.MaxBytesReader(w, r.Body, 1024)
	_, _ = io.ReadAll(r.Body)
}

func openRedirect(w http.ResponseWriter, r *http.Request) {
	next := r.FormValue("next")
	http.Redirect(w, r, next, http.StatusFound) // want `User-controlled HTTP input is used as a redirect target`
}
func safeRedirect(w http.ResponseWriter, r *http.Request) {
	http.Redirect(w, r, "/home", http.StatusFound)
}

type store struct{}

func (*store) Delete(any) {}

var db store

func deleteUser(*gin.Context)   { db.Delete("user") }
func updateUser(*gin.Context)   {}
func cookieAuth(c *gin.Context) { _, _ = c.Request.Cookie("session") }
func csrf(*gin.Context)         {}
func requireRole(*gin.Context)  {}

func ginRoutes() {
	r := gin.New()
	r.Use(cookieAuth)
	r.POST("/profile", updateUser)    // want `Cookie-authenticated state-changing route has no recognized CSRF middleware`
	r.GET("/delete-user", deleteUser) // want `GET handler performs an obvious state mutation`
	admin := r.Group("/admin", csrf)
	admin.POST("/profile", updateUser) // want `Authenticated admin route has no recognized authorization middleware`
	admin.POST("/settings", requireRole, updateUser)
}

func echoUpdate(*echo.Context) error { return nil }
func echoDelete(*echo.Context) error { db.Delete("user"); return nil }
func echoCookieAuth(next echo.HandlerFunc) echo.HandlerFunc {
	return func(c *echo.Context) error { _, _ = c.Request().Cookie("session"); return next(c) }
}
func echoCSRF(next echo.HandlerFunc) echo.HandlerFunc              { return next }
func echoRequirePermission(next echo.HandlerFunc) echo.HandlerFunc { return next }
func echoUnsafeTemplate(c *echo.Context) template.HTML {
	bio := c.FormValue("bio")
	return template.HTML(bio) // want `User-controlled HTTP input is converted to template.HTML`
}
func echoRedirect(c *echo.Context) error {
	next := c.QueryParam("next")
	return c.Redirect(http.StatusFound, next) // want `User-controlled HTTP input is used as a redirect target`
}

func echoRoutes() {
	e := echo.New()
	e.POST("/profile", echoUpdate, echoCookieAuth) // want `Cookie-authenticated state-changing route has no recognized CSRF middleware`
	e.GET("/delete", echoDelete)                   // want `GET handler performs an obvious state mutation`
	e.GET("/debug", echoUpdate)                    // want `No route-level middleware was detected for sensitive endpoint /debug`
	admin := e.Group("/admin", echoCookieAuth, echoCSRF)
	admin.POST("/profile", echoUpdate) // want `Authenticated admin route has no recognized authorization middleware`
	admin.POST("/settings", echoUpdate, echoRequirePermission)
}

func fiber2Update(*fiber2.Ctx) error       { return nil }
func fiber2Delete(*fiber2.Ctx) error       { db.Delete("user"); return nil }
func fiber2CookieAuth(c *fiber2.Ctx) error { _ = c.Cookies("session"); return nil }
func fiber2CSRF(*fiber2.Ctx) error         { return nil }
func fiber2RequireScope(*fiber2.Ctx) error { return nil }
func fiber2UnsafeTemplate(c *fiber2.Ctx) template.HTML {
	value := c.FormValue("bio")
	return template.HTML(value) // want `User-controlled HTTP input is converted to template.HTML`
}
func fiber2Redirect(c *fiber2.Ctx) error { next := c.Query("next"); return c.Redirect(next) } // want `User-controlled HTTP input is used as a redirect target`

func fiber2Routes() {
	app := fiber2.New()
	app.Use("/api", fiber2CookieAuth)
	app.Post("/api/profile", fiber2Update) // want `Cookie-authenticated state-changing route has no recognized CSRF middleware`
	app.Post("/public", fiber2Update)
	app.Add("PUT", "/api/thing", fiber2CSRF, fiber2Update)
	app.Get("/delete", fiber2Delete) // want `GET handler performs an obvious state mutation`
	app.Get("/debug", fiber2Update)  // want `No route-level middleware was detected for sensitive endpoint /debug`
	admin := app.Group("/admin", fiber2CookieAuth, fiber2CSRF)
	admin.Post("/profile", fiber2Update) // want `Authenticated admin route has no recognized authorization middleware`
	admin.Post("/settings", fiber2RequireScope, fiber2Update)
	v1 := admin.Group("/v1", fiber2CSRF)
	v1.Get("/status", fiber2Update) // want `Authenticated admin route has no recognized authorization middleware`
	v1.Get("/audit", fiber2RequireScope, fiber2Update)
}

func fiber3Update(fiber3.Ctx) error       { return nil }
func fiber3CookieAuth(c fiber3.Ctx) error { _ = c.Cookies("session"); return nil }
func fiber3RequireRole(fiber3.Ctx) error  { return nil }
func fiber3UnsafeTemplate(c fiber3.Ctx) template.HTML {
	value := c.Params("value")
	return template.HTML(value) // want `User-controlled HTTP input is converted to template.HTML`
}
func fiber3Redirect(c fiber3.Ctx) error {
	next := c.Query("next")
	return c.Redirect().Status(http.StatusFound).To(next) // want `User-controlled HTTP input is used as a redirect target`
}

func fiber3Routes() {
	app := fiber3.New()
	app.Use(fiber3CookieAuth)
	app.Post("/profile", fiber3Update)      // want `Cookie-authenticated state-changing route has no recognized CSRF middleware`
	app.Get("/admin/profile", fiber3Update) // want `Authenticated admin route has no recognized authorization middleware`
	app.Get("/admin/settings", fiber3RequireRole, fiber3Update)
}

func unsafeTemplRaw(r *http.Request) templ.Component {
	value := r.FormValue("html")
	return templ.Raw(value) // want `User-controlled HTTP input is passed to templ.Raw`
}
func unsafeTemplURL(r *http.Request) templ.SafeURL {
	value := r.FormValue("url")
	return templ.SafeURL(value) // want `User-controlled HTTP input is marked safe for templ output`
}
func unsafeTemplCSS(r *http.Request) templ.SafeCSS  { return templ.SafeCSS(r.FormValue("css")) }         // want `User-controlled HTTP input is marked safe for templ output`
func unsafeTemplJS(r *http.Request) templ.Component { return templ.JSUnsafeFuncCall(r.FormValue("js")) } // want `User-controlled HTTP input is marked safe for templ output`
func safeTemplRaw() templ.Component                 { return templ.Raw("<strong>trusted constant</strong>") }
