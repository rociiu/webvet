# WEBVET-HTTP-004

## HTTP server missing idle deadline

Severity: Medium  
Confidence: High  
CWE: CWE-400

Configure `IdleTimeout` or a non-zero `ReadTimeout` fallback so idle keep-alive connections have a server-defined deadline.
