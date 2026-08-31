# WEBVET-HTTP-002

## Exposed pprof endpoint

Severity: High  
Confidence: High  
CWE: CWE-489

A blank `net/http/pprof` import registers diagnostics on `DefaultServeMux`. Serving that mux publicly can disclose sensitive runtime data. Use a private listener or a protected dedicated mux.
