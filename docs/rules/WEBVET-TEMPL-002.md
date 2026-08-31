# WEBVET-TEMPL-002

## Untrusted content marked safe for templ output

Severity: High  
Confidence: High  
CWE: CWE-79

`templ.SafeURL`, `templ.SafeCSS`, `templ.SafeCSSProperty`, and `templ.JSUnsafeFuncCall` bypass contextual sanitization. Use them only after strict context-specific validation.

References: [templ injection guidance](https://templ.guide/security/injection-attacks/), [templ JavaScript guidance](https://templ.guide/syntax-and-usage/script-templates/)
