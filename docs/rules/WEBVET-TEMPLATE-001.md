# WEBVET-TEMPLATE-001

## Untrusted data converted to trusted template content

Severity: High  
Confidence: High  
CWE: CWE-79

Trusted `html/template` content types bypass contextual escaping. Pass request-derived strings unchanged, or sanitize with a trusted context-specific sanitizer first.
