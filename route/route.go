package route

import "go/token"

type Middleware struct {
	Name string `json:"name"`
}

type Route struct {
	Method     string         `json:"method"`
	Path       string         `json:"path"`
	Handler    string         `json:"handler,omitempty"`
	Middleware []Middleware   `json:"middleware,omitempty"`
	Framework  string         `json:"framework"`
	Position   token.Position `json:"position"`
	Security   Security       `json:"security"`
}

type Security struct {
	Auth          Property `json:"auth"`
	Authorization Property `json:"authorization"`
	CookieAuth    Property `json:"cookie_auth"`
	CSRF          Property `json:"csrf"`
}

type Property struct {
	Detected bool     `json:"detected"`
	Evidence []string `json:"evidence,omitempty"`
}
