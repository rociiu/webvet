# WEBVET-HEADER-001

## HTML response lacks a detected browser security policy

Severity: Low  
Confidence: Low  
CWE: CWE-693

An explicit `text/html` response has no handler-level CSP or frame policy. Middleware or an ingress may provide one, so this finding requests review rather than asserting exposure.
