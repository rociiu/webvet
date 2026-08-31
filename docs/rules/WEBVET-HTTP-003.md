# WEBVET-HTTP-003

## HTTP server missing WriteTimeout

Severity: Medium  
Confidence: Medium  
CWE: CWE-400

A server without a write deadline can retain resources while a slow client receives a response. Configure `WriteTimeout`; streaming endpoints may require a deliberate exception.
