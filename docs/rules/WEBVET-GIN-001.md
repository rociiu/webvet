# WEBVET-GIN-001

## Unsafe Gin trusted proxies

Severity: High  
Confidence: High  
CWE: CWE-345

Trusting `*`, `0.0.0.0/0`, or `::/0` lets arbitrary peers influence forwarding headers used to determine client identity. Configure only deployment-controlled proxy addresses or CIDRs.
