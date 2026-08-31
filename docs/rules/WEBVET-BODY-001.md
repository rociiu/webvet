# WEBVET-BODY-001

## Unbounded request body read

Severity: Medium  
Confidence: High  
CWE: CWE-400

`io.ReadAll` consumes an HTTP request body without a detected `http.MaxBytesReader`. Apply a deployment-appropriate limit before reading attacker-controlled data.
