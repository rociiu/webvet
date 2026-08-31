# WEBVET-ROUTE-001

## State-changing GET route

Severity: Medium  
Confidence: Medium  
CWE: CWE-749

A GET handler contains strong mutation evidence such as a delete/update call or mutation SQL. Use an unsafe HTTP method and apply CSRF protection where authentication uses cookies.
