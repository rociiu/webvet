package source

import "net/http"

func RequestValue(r *http.Request) string { return r.FormValue("value") }
func ChainedValue(r *http.Request) string { return RequestValue(r) }
func ConstantValue() string               { return "/home" }
