package rules

import (
	"fmt"
	"go/ast"

	"github.com/webvet/webvet/report"
)

var cookieHTTPOnlyMeta = Metadata{ID: "WEBVET-COOKIE-001", Name: "Sensitive cookie missing HttpOnly", Description: "sensitive cookie missing HttpOnly", Severity: report.High, CWE: "CWE-1004", Confidence: report.ConfidenceHigh, Frameworks: []string{"net/http", "gin", "chi"}}
var cookieSecureMeta = Metadata{ID: "WEBVET-COOKIE-002", Name: "Sensitive cookie missing Secure", Description: "sensitive cookie missing Secure", Severity: report.High, CWE: "CWE-614", Confidence: report.ConfidenceHigh, Frameworks: []string{"net/http", "gin", "chi"}}
var cookieSameSiteMeta = Metadata{ID: "WEBVET-COOKIE-003", Name: "SameSite=None cookie missing Secure", Description: "SameSite=None cookie missing Secure", Severity: report.High, CWE: "CWE-1275", Confidence: report.ConfidenceHigh, Frameworks: []string{"net/http", "gin", "chi"}}

func cookieHTTPOnlyRule() Rule { return cookieRule(cookieHTTPOnlyMeta, "httponly") }
func cookieSecureRule() Rule   { return cookieRule(cookieSecureMeta, "secure") }
func cookieSameSiteRule() Rule { return cookieRule(cookieSameSiteMeta, "samesite") }
func cookieRule(meta Metadata, kind string) Rule {
	return rule{meta, func(c *Context) []report.Finding {
		var out []report.Finding
		ast.Inspect(c.File, func(n ast.Node) bool {
			call, ok := n.(*ast.CallExpr)
			if !ok || callPath(c.Types, call) != "net/http.SetCookie" || len(call.Args) < 2 {
				return true
			}
			arg := call.Args[1]
			if u, ok := arg.(*ast.UnaryExpr); ok {
				arg = u.X
			}
			lit, ok := arg.(*ast.CompositeLit)
			if !ok || compositeTypePath(c.Types, lit) != "net/http.Cookie" {
				return true
			}
			fields := fieldMap(lit)
			name, known := stringLiteral(fields["Name"])
			if !known {
				return true
			}
			secure, _ := boolLiteral(fields["Secure"])
			switch kind {
			case "httponly":
				if !sensitiveCookie(name) {
					return true
				}
				enabled, _ := boolLiteral(fields["HttpOnly"])
				if enabled {
					return true
				}
				out = append(out, finding(c, lit, meta, fmt.Sprintf("Authentication cookie %q does not enable HttpOnly.", name), "Without HttpOnly, script running in the page can read this sensitive cookie.", "Set HttpOnly: true."))
			case "secure":
				if !sensitiveCookie(name) || secure {
					return true
				}
				out = append(out, finding(c, lit, meta, fmt.Sprintf("Authentication cookie %q does not enable Secure.", name), "A sensitive cookie without Secure may be sent over an unencrypted HTTP connection.", "Set Secure: true in production."))
			case "samesite":
				v, ok := fields["SameSite"]
				if !ok || objectPath(c.Types, v) != "net/http.SameSiteNoneMode" || secure {
					return true
				}
				out = append(out, finding(c, lit, meta, fmt.Sprintf("Cookie %q uses SameSite=None without Secure.", name), "Browsers require SameSite=None cookies to be Secure; otherwise the cookie may be rejected and its cross-site policy is unsafe.", "Set Secure: true or choose a stricter SameSite mode."))
			}
			return true
		})
		return out
	}}
}
