# webvet

Static security analysis for Go web applications.

`webvet` understands routes, middleware, HTTP configuration, cookies,
templates, and web-framework semantics that generic Go linters often cannot
see. Version 0.1 favors a small number of explainable, high-confidence checks.

## Install

```sh
go install github.com/rociiu/webvet/cmd/webvet@latest
```

The module path is isolated to `go.mod` and internal imports, so a future owner
rename is a mechanical change.

## Quick start

```sh
webvet ./...
webvet -severity high -format json ./...
webvet -format sarif ./... > webvet.sarif
webvet routes ./...
webvet rules
```

Findings make the certainty explicit and include an explanation and suggested
fix. Exit status is 0 for a clean scan, 1 for findings at the selected severity,
and 2 for scanner or configuration errors.

Local suppressions require a rule and reason:

```go
//webvet:ignore WEBVET-HTTP-001 -- timeout enforced by the private ingress
srv := &http.Server{Addr: ":8080"}
```

Project defaults can be stored in `.webvet.yml`; CLI flags take precedence:

```yaml
severity: medium
disable:
  - WEBVET-HEADER-001
enable: []
```

## Supported frameworks

- `net/http`: server, cookie, pprof, and template checks
- Chi v5: static method/path/handler extraction and `With` middleware chains
- Gin: static route extraction, inline middleware, trusted-proxy checks, and request sources
- Echo v4: static routes, groups, inherited/inline middleware, request sources, and redirects
- Fiber v2/v3: routes, nested groups, prefix middleware, request sources, and version-specific redirects
- templ: request-taint checks for explicit HTML, URL, CSS, and JavaScript sanitization bypasses

Dynamic paths, router aliases passed through arbitrary functions, and
network-level controls are intentionally not guessed. Shallow cross-package
taint summaries recognize request-source wrapper functions. Fiber v2 and
v3 are both recognized; version-specific request and redirect APIs are handled
separately.

## Rules

| Rule | Severity | Purpose |
|---|---:|---|
| WEBVET-HTTP-001 | Medium | `http.Server` missing `ReadHeaderTimeout` |
| WEBVET-HTTP-002 | High | pprof exposed through the default server |
| WEBVET-HTTP-003 | Medium | `http.Server` missing `WriteTimeout` |
| WEBVET-HTTP-004 | Medium | missing idle connection deadline |
| WEBVET-COOKIE-001 | High | sensitive cookie missing `HttpOnly` |
| WEBVET-COOKIE-002 | High | sensitive cookie missing `Secure` |
| WEBVET-COOKIE-003 | High | `SameSite=None` without `Secure` |
| WEBVET-CORS-001 | High | credentialed wildcard CORS |
| WEBVET-GIN-001 | High | unrestricted Gin trusted proxies |
| WEBVET-TEMPLATE-001 | High | request input converted to trusted template content |
| WEBVET-TEMPL-001 | High | request input passed to `templ.Raw` |
| WEBVET-TEMPL-002 | High | request input marked safe for templ URL/CSS/JavaScript output |
| WEBVET-HEADER-001 | Low | explicit HTML response lacks a detected browser policy |
| WEBVET-BODY-001 | Medium | request body read without a size limit |
| WEBVET-REDIRECT-001 | High | request input used as a redirect target |
| WEBVET-ROUTE-001 | Medium | GET handler performs an obvious mutation |
| WEBVET-ROUTE-002 | Medium | sensitive route has no detected route middleware |
| WEBVET-ROUTE-003 | High | cookie-authenticated unsafe method lacks detected CSRF middleware |

## Architecture

The CLI loads each package once with `go/packages`. Typed AST information and
request-source return summaries are shared by a small rule registry and the route collector. A `go/analysis`
adapter supports `analysistest` and future linter integrations. Findings and
routes are deterministic intermediate models; text and JSON are presentation
layers.

## Why not gosec?

gosec is an excellent general-purpose Go security scanner. webvet focuses
specifically on web application semantics such as routes, middleware chains,
framework configuration, browser security policies, and template rendering.
The projects are complementary.

## Roadmap

Next priorities are authorization-property modeling and SSA-backed summaries
for more complex cross-package data flow.

## Contributing

Run `go test ./...` and `go vet ./...`. New checks should include positive,
negative, and edge cases and should prefer silence over an uncertain claim.

Licensed under the MIT License.
