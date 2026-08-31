package gin

type Engine struct{}

func (*Engine) SetTrustedProxies([]string) error { return nil }
