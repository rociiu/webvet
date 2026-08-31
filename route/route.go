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
}
