package gin

import "net/http"

type Context struct{ Request *http.Request }
type HandlerFunc func(*Context)
type Engine struct{}
type RouterGroup struct{}

func (*Engine) SetTrustedProxies([]string) error          { return nil }
func New() *Engine                                        { return &Engine{} }
func (*Engine) Use(...HandlerFunc)                        {}
func (*Engine) GET(string, ...HandlerFunc)                {}
func (*Engine) POST(string, ...HandlerFunc)               {}
func (*Engine) Group(string, ...HandlerFunc) *RouterGroup { return &RouterGroup{} }
func (*RouterGroup) Use(...HandlerFunc)                   {}
func (*RouterGroup) GET(string, ...HandlerFunc)           {}
func (*RouterGroup) POST(string, ...HandlerFunc)          {}
func (*Context) Redirect(int, string)                     {}
func (*Context) Header(string, string)                    {}
