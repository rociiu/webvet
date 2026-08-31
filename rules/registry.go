package rules

import "fmt"

func Default() []Rule {
	return []Rule{httpTimeoutRule(), pprofRule(), writeTimeoutRule(), idleTimeoutRule(), cookieHTTPOnlyRule(), cookieSecureRule(), cookieSameSiteRule(), corsRule(), ginProxyRule(), templateRule(), templRawRule(), templContextRule(), securityHeadersRule(), bodyLimitRule(), redirectRule()}
}
func Validate() error {
	seen := map[string]bool{}
	for _, m := range MetadataList() {
		if m.ID == "" {
			return fmt.Errorf("rule has empty ID")
		}
		if seen[m.ID] {
			return fmt.Errorf("duplicate rule ID %s", m.ID)
		}
		seen[m.ID] = true
	}
	return nil
}
func KnownIDs() map[string]bool {
	out := map[string]bool{}
	for _, m := range MetadataList() {
		out[m.ID] = true
	}
	return out
}
func MetadataList() []Metadata {
	rs := Default()
	out := make([]Metadata, 0, len(rs)+3)
	for _, r := range rs {
		out = append(out, r.Meta())
	}
	out = append(out, stateChangingGETMeta, sensitiveRouteMeta, csrfRouteMeta)
	return out
}
