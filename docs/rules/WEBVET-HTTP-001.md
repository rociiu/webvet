# WEBVET-HTTP-001

## HTTP server missing ReadHeaderTimeout

Severity: Medium  
Confidence: High  
CWE: CWE-400

An `http.Server` without a header-read deadline can be held open by slowly delivered headers. Configure a non-zero `ReadHeaderTimeout`. A direct post-construction assignment is recognized.

```go
srv := &http.Server{ReadHeaderTimeout: 5 * time.Second}
```
