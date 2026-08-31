# WEBVET-ROUTE-004

## Authenticated admin route missing authorization

Severity: High  
Confidence: Medium  
CWE: CWE-862

An authenticated route at `/admin` or below it has no middleware that webvet
recognizes as enforcing a role, permission, scope, or authorization policy.
Authentication only establishes identity; attach explicit authorization
middleware before allowing administrative actions.

webvet recognizes focused authorization middleware names such as
`requireRole`, `requirePermission`, and `authorize`, and also inspects simple
middleware bodies for calls with those semantics. Indirect or externally
enforced policies may require a local suppression with a reason.
