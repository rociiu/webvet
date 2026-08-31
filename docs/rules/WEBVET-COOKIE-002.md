# WEBVET-COOKIE-002

## Authentication cookie missing Secure

Severity: High  
Confidence: High  
CWE: CWE-614

A sensitive cookie without `Secure` can travel over plain HTTP. Set `Secure: true` in production and serve the application over HTTPS.
