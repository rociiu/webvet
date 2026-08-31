# WEBVET-ROUTE-003

## Cookie-authenticated route missing CSRF middleware

Severity: High  
Confidence: Medium  
CWE: CWE-352

A POST, PUT, PATCH, or DELETE route inherits middleware that reads an HTTP cookie, but no middleware with a recognized CSRF identity is attached. Apply and validate CSRF tokens.
