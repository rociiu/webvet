package fiber

type Ctx struct{}
type Handler func(Ctx) error
type App struct{}
type Group struct{}
type Redirect struct{}

func New() *App                                { return &App{} }
func (*App) Use(...any)                        {}
func (*App) Get(string, ...any)                {}
func (*App) Post(string, ...any)               {}
func (*App) Add(string, string, ...any)        {}
func (*App) Group(string, ...any) *Group       { return &Group{} }
func (*Group) Use(...any)                      {}
func (*Group) Get(string, ...any)              {}
func (*Group) Post(string, ...any)             {}
func (*Group) Group(string, ...any) *Group     { return &Group{} }
func (Ctx) Query(string, ...string) string     { return "" }
func (Ctx) Params(string, ...string) string    { return "" }
func (Ctx) FormValue(string, ...string) string { return "" }
func (Ctx) Get(string, ...string) string       { return "" }
func (Ctx) Cookies(string, ...string) string   { return "" }
func (Ctx) Redirect() *Redirect                { return &Redirect{} }
func (Ctx) Set(string, string)                 {}
func (*Redirect) Status(int) *Redirect         { return &Redirect{} }
func (*Redirect) To(string) error              { return nil }
func (*Redirect) Back(string) error            { return nil }
