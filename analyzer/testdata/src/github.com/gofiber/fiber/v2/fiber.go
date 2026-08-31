package fiber

type Ctx struct{}
type Handler func(*Ctx) error
type App struct{}
type Group struct{}

func New() *App                                 { return &App{} }
func (*App) Use(...any)                         {}
func (*App) Get(string, ...Handler)             {}
func (*App) Post(string, ...Handler)            {}
func (*App) Add(string, string, ...Handler)     {}
func (*App) Group(string, ...Handler) *Group    { return &Group{} }
func (*Group) Use(...any)                       {}
func (*Group) Get(string, ...Handler)           {}
func (*Group) Post(string, ...Handler)          {}
func (*Group) Group(string, ...Handler) *Group  { return &Group{} }
func (*Ctx) Query(string, ...string) string     { return "" }
func (*Ctx) Params(string, ...string) string    { return "" }
func (*Ctx) FormValue(string, ...string) string { return "" }
func (*Ctx) Get(string, ...string) string       { return "" }
func (*Ctx) Cookies(string, ...string) string   { return "" }
func (*Ctx) Redirect(string, ...int) error      { return nil }
func (*Ctx) Set(string, string)                 {}
