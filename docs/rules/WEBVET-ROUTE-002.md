# WEBVET-ROUTE-002

## Sensitive route without detected middleware

Severity: Medium  
Confidence: Low  
CWE: CWE-306

No route-level middleware was found on an obvious debug, pprof, metrics, or admin-debug endpoint. This is a review finding because network-level protection may exist. Attach access control or restrict exposure at the network boundary.
