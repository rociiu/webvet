# WEBVET-COOKIE-003

## SameSite=None cookie missing Secure

Severity: High  
Confidence: High  
CWE: CWE-1275

Browsers require a `SameSite=None` cookie to also be Secure. Set `Secure: true`, or choose a stricter SameSite mode when cross-site use is unnecessary.
