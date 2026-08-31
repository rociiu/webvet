# Project readiness checklist

This checklist tracks the work required to make webvet a useful, dependable
public package. Complete correctness work before treating webvet findings as a
required CI security gate.

## P0 — Publish a usable package

- [ ] Create the public `github.com/rociiu/webvet` repository.
- [ ] Add the GitHub repository as the Git remote and push `main`.
- [ ] Confirm `go install github.com/rociiu/webvet/cmd/webvet@latest` works from a clean environment.
- [ ] Create and push a semantic version tag, starting with `v0.1.0` when the release criteria below pass.
- [ ] Add a GitHub Actions release workflow that runs GoReleaser for version tags.
- [ ] Verify Linux, macOS, and Windows archives and checksums from a test release.

## P1 — Close correctness gaps

### Route access control

- [ ] Make `WEBVET-ROUTE-002` use detected authentication or authorization properties instead of treating any middleware as protection.
- [ ] Report unauthenticated `/admin` routes; do not require authentication to be detected before identifying missing access control.
- [ ] Keep authentication and authorization findings distinct and avoid duplicate findings for the same underlying problem.
- [ ] Add negative tests showing that logging, tracing, recovery, and compression middleware do not count as access control.
- [ ] Add tests for public routes, authenticated user routes, authenticated admin routes, and explicitly authorized admin routes.

### Route and middleware propagation

- [ ] Deep-copy mutable router state when entering conditional branches and loops.
- [ ] Ensure middleware added in one conditional branch does not leak into sibling branches or later routes.
- [ ] Define conservative behavior for middleware registered conditionally when the condition cannot be evaluated statically.
- [ ] Add direct route-collector tests for branches, loops, aliases, nested groups, and middleware registration order.
- [ ] Add regression fixtures for Chi, Gin, Echo, Fiber v2, and Fiber v3.

### Data-flow accuracy

- [ ] Make taint tracking respect statement order.
- [ ] Clear taint after a variable is overwritten with a known-safe value.
- [ ] Model branch joins without marking sinks that execute before the taint source.
- [ ] Distinguish propagating helpers, sanitizers, and validation functions.
- [ ] Add tests for reassignment, early sinks, branches, loops, tuple assignments, methods, and named returns.
- [ ] Replace or augment shallow summaries with SSA-backed summaries for complex cross-package flows.
- [ ] Reassess rule confidence levels after measuring false positives and false negatives.

## P1 — Harden the public Go API

- [ ] Stop writing package-load errors directly to process stderr from `analyzer.Run`; return structured or wrapped errors instead.
- [ ] Preserve caller-provided `Options.TaintSummaries` instead of overwriting them.
- [ ] Add documentation comments to all exported types, fields, functions, and constants.
- [ ] Decide which packages are stable public API and move implementation-only packages under `internal/` where appropriate.
- [ ] Add a context-aware entry point so callers can cancel long scans.
- [ ] Allow advanced callers to provide build tags, environment, overlays, tests, and other `go/packages` settings.
- [ ] Document API compatibility expectations for the `v0.x` series.
- [ ] Add external-package tests demonstrating supported embedding patterns.

## P2 — Improve CLI and CI usability

- [ ] Add JSON output to `webvet routes`, including property evidence.
- [ ] Add a documented quiet or output-file workflow for SARIF generation in CI.
- [ ] Upload SARIF through GitHub Code Scanning instead of only writing a local file.
- [ ] Test CLI help, `rules`, `routes`, `version`, invalid formats, writer failures, and broken packages.
- [ ] Document flag ordering, configuration discovery, precedence, and exit codes in one reference section.
- [ ] Decide whether `enable` is an override for disabled rules or an allowlist, then document and test that behavior.
- [ ] Add an option to scan test packages when desired.
- [ ] Ensure paths in text, JSON, and SARIF output are stable and repository-relative in CI.

## P2 — Compatibility and quality

- [ ] Establish the minimum supported Go version; use Go 1.24 if no Go 1.25 feature is required.
- [ ] Test the minimum and latest supported Go versions in CI.
- [ ] Run `go test ./...`, `go test -race ./...`, and `go vet ./...` in CI.
- [ ] Add a compatible Staticcheck job.
- [ ] Add `govulncheck ./...` to CI.
- [ ] Add coverage reporting with thresholds focused on analyzer and route behavior.
- [ ] Add benchmarks for package loading, route collection, taint summaries, and full scans.
- [ ] Test a representative small, medium, and large Go web application.
- [ ] Record expected runtime and memory use for representative scans.

## P2 — Documentation and project trust

- [ ] Add `SECURITY.md` with supported versions and a private vulnerability-reporting process.
- [ ] Add `CONTRIBUTING.md` with rule design, testing, documentation, and commit expectations.
- [ ] Add a changelog or automated release notes.
- [ ] Document known false positives, false negatives, and unsupported code patterns.
- [ ] Add complete examples for each supported framework.
- [ ] Document how to suppress a finding and require a meaningful reason.
- [ ] Document how webvet complements, rather than replaces, tools such as `govulncheck` and gosec.
- [ ] Add package documentation and small embedding examples for `analyzer`, `report`, and `route`.

## Release criteria for v0.1.0

- [ ] All P0 items are complete.
- [ ] Route access-control and conditional middleware correctness items are complete.
- [ ] No known high-confidence rule has a reproducible common false positive.
- [ ] All supported-framework fixtures pass on every supported Go version.
- [ ] Tests, race detection, vet, Staticcheck, and `govulncheck` pass.
- [ ] The project self-scan completes cleanly.
- [ ] Text, JSON, SARIF, route inventory, configuration, and suppressions have end-to-end tests.
- [ ] A clean machine can install the tagged CLI and scan the example application.
- [ ] Release archives and checksums have been manually verified once.

## Later enhancements

- [ ] Support custom `net/http.ServeMux` instances and Go method-pattern routes.
- [ ] Add upload and multipart body-size analysis.
- [ ] Add JWT transport checks, including query-parameter tokens.
- [ ] Expand CSP and browser-header analysis.
- [ ] Add configurable middleware semantics for application-specific authentication and authorization.
- [ ] Evaluate golangci-lint and editor/LSP integrations after the analyzer API stabilizes.
