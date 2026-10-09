# Implementation plan

A checked task means implemented and verified in this environment. No whole phase is declared complete merely because its scaffold exists.

## Phase 0 — foundation (partial)
- [x] Initialize Python monorepo foundation and locked dependencies
- [x] Initial source, scan, analyzer, candidate and review persistence models
- [x] Architecture, ADR, threat model and local-only identity boundary
- [x] Baseline lint/type/test/security CI definition
- [x] Alembic upgrade/downgrade tested on SQLite
- [ ] Full domain model including organizations, users, verification and evaluation entities
- [ ] Execute PostgreSQL development environment (Docker unavailable locally)

## Phase 1 — deterministic analysis (partial; blocked at sandbox executors)
- [x] Bounded local ZIP ingestion and immutable content manifests
- [x] File count, size, traversal, symlink, duplicate and source-type validation
- [x] Safe, honestly labeled lexical review scanner
- [x] Slither and Semgrep output normalization (synthetic parser tests)
- [x] Persist candidates, raw analyzer results and evidence provenance
- [x] Versioned API with pagination, severity filter, idempotency and cancellation
- [x] Human review with optimistic version checks and audit records
- [x] Content-pinned Markdown report and reproducible offline API demo
- [x] Source-only Docker runner, fixed command policy and timeout/output-budget unit tests
- [ ] Real Slither and Semgrep execution in a validated sandbox
- [ ] Compiler diagnostics and Foundry build metadata
- [ ] Public Git URL ingestion, commit SHA pinning and SSRF protection
- [ ] Semantic cross-tool deduplication
- [ ] Artifact retention and raw-output artifact store

## Phases 2–8 — pending
- [ ] Typed LangGraph, durable checkpointer, leases, budgets and restart/failure tests
- [ ] OpenAI/Anthropic/mock structured provider interfaces and usage telemetry
- [ ] Threat models, hypotheses, transparent prioritization and evidence linking
- [ ] Sandboxed Foundry plans, controlled test generation, executable evidence and isolation tests
- [ ] Licensed benchmark suite, metrics, ablations and deterministic regression baseline
- [ ] Functional strict TypeScript Next.js dashboard and typed API client
- [ ] Multi-user authentication, full tenant isolation, observability and recovery hardening
- [ ] PDF reports, real UI screenshots, demo video and case study

## Blocker and resumption condition
Docker isolation probing timed out. Host execution of analyzers or Foundry is prohibited. Semgrep is not installed. External executors deliberately return `unavailable`; there is no fallback to host execution. Establish a sandbox with pinned images, least privilege, network denial and tested resource boundaries before marking Phase 1 complete or moving to the subsequent graph and verification milestones.
