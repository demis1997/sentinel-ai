# Actual validation — 2026-10-09

Environment: macOS ARM64, Python 3.14.3. Checks ran locally; GitHub Actions and Python 3.12 CI jobs have not run.

- Pytest: **46 passed**, one upstream Starlette/httpx TestClient deprecation warning.
- Ruff lint: passed across source, tests, migrations, scripts and sandbox wrapper.
- Ruff formatting: 19 files passed.
- Strict Mypy: passed across 9 application modules.
- Bandit: passed. Targeted subprocess annotations document reviewed fixed Docker/tool invocations; this is not a full security audit.
- uv lock consistency: passed, 64 resolved packages.
- pip-audit 2.10.1: no known vulnerabilities reported across 62 packages; no skipped packages. This reflects the advisory service at execution time, not proof of dependency safety.
- Alembic: initial SQLite migration ran; automated upgrade/downgrade test passed.
- HTTP smoke: real Uvicorn loopback server returned health 200, OpenAPI 200 (9 paths), and same-origin ZIP upload 201 with a correlation ID. Server was shut down after the check.
- Offline demo: real ASGI API uploaded the local ExternalCall fixture, persisted a scan, produced one informational lexical candidate, recorded a human `needs_more_evidence` decision and exported Markdown. Scan status was `partial`; reproduction was **not performed**.
- Fatal-interruption test: a simulated abrupt worker exit after one committed analyzer node recovered through a new database session factory, preserved its run ID and did not duplicate its finding.
- Sandbox tests: command policy, rootless/cgroup/seccomp capability denial, fixed image/tool allowlist, timeout/output budgets, synthetic tool envelopes and forced cleanup paths. These are **unit tests**, not execution isolation tests.

Artifacts: [pytest JUnit](evidence/pytest.xml), [dependency audit](evidence/dependency-audit.json), [actual offline scan](examples/scan.json), [actual report](examples/report.md).

## Checks unavailable

Docker daemon isolation probing timed out after eight seconds. No actual container, Slither, Semgrep, Solidity compiler or Foundry execution was performed against repository code. PostgreSQL Compose was not started. No paid models, live evaluations, GitHub push/CI, deployment, frontend, screenshots, or exploit verification ran. The bundled image wrapper is implemented but its image has not been built or runtime-validated.

The initial deterministic milestone therefore remains partial. Full LangGraph checkpointing, production authorization, benchmark metrics, Foundry reproduction, and dashboard acceptance are pending. Consult the implementation plan rather than interpreting passing foundation tests as final acceptance.
