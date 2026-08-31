package echo

import "net/http"

type Context struct{ request *http.Request }
type HandlerFunc func(*Context) error
type MiddlewareFunc func(HandlerFunc) HandlerFunc
type Echo struct{}
type Group struct{}

func New() *Echo                                           { return &Echo{} }
func (*Echo) Use(...MiddlewareFunc)                        {}
func (*Echo) GET(string, HandlerFunc, ...MiddlewareFunc)   {}
func (*Echo) POST(string, HandlerFunc, ...MiddlewareFunc)  {}
func (*Echo) Group(string, ...MiddlewareFunc) *Group       { return &Group{} }
func (*Group) Use(...MiddlewareFunc)                       {}
func (*Group) GET(string, HandlerFunc, ...MiddlewareFunc)  {}
func (*Group) POST(string, HandlerFunc, ...MiddlewareFunc) {}
func (*Context) QueryParam(string) string                  { return "" }
func (*Context) Param(string) string                       { return "" }
func (*Context) FormValue(string) string                   { return "" }
func (c *Context) Request() *http.Request                  { return c.request }
func (*Context) Redirect(int, string) error                { return nil }
