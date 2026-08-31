# WEBVET-TEMPL-001

## Untrusted content passed to templ.Raw

Severity: High  
Confidence: High  
CWE: CWE-79

`templ.Raw` bypasses templ's normal HTML escaping. Pass ordinary strings to templ interpolation, or sanitize trusted HTML before explicitly rendering it raw.

Reference: [templ raw HTML documentation](https://templ.guide/syntax-and-usage/rendering-raw-html/)
