# WEBVET-COOKIE-001

## Authentication cookie missing HttpOnly

Severity: High  
Confidence: High  
CWE: CWE-1004

Session and authentication cookies should normally be inaccessible to browser script. Set `HttpOnly: true`. Cookies without strongly sensitive names are intentionally ignored.
