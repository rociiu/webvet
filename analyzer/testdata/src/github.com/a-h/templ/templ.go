package templ

type Component interface{}
type SafeURL string
type SafeCSS string
type SafeCSSProperty string

func Raw(string) Component              { return nil }
func JSUnsafeFuncCall(string) Component { return nil }
