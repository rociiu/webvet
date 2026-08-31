# WEBVET-REDIRECT-001

## Untrusted redirect target

Severity: High  
Confidence: High  
CWE: CWE-601

Request-derived data flows directly to `http.Redirect` or Gin's redirect API. Allowlist local paths or trusted origins before redirecting.
