# WEBVET-CORS-001

## Credentialed wildcard CORS

Severity: High  
Confidence: High  
CWE: CWE-942

Credentials should not be combined with an unrestricted origin policy. Use an explicit allowlist for `rs/cors` or `gin-contrib/cors` and validate origins deliberately.
