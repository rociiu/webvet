package rules

func Default() []Rule {
	return []Rule{httpTimeoutRule(), pprofRule(), cookieHTTPOnlyRule(), cookieSecureRule(), cookieSameSiteRule(), corsRule(), ginProxyRule(), templateRule()}
}
func MetadataList() []Metadata {
	rs := Default()
	out := make([]Metadata, 0, len(rs)+1)
	for _, r := range rs {
		out = append(out, r.Meta())
	}
	out = append(out, sensitiveRouteMeta)
	return out
}
