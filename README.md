# Sentinel AI

Evidence-first Solidity security research. This repository is an implemented **foundation milestone**, not the finished platform described in the implementation brief.

## What runs today

A real ZIP source archive goes through bounded ingestion, a deterministic content manifest, a safe lexical scanner, persisted analyzer outcomes, review candidates, human triage, and a Markdown report through FastAPI. No paid APIs or repository code execution is involved.

The bundled lexical scanner identifies source patterns requiring review. It does **not** perform Slither analysis, compiler-aware security analysis, or vulnerability verification. Candidates have informational severity and `plausible_unverified` evidence strength. A reviewer's acceptance does not change that strength.

Slither and Semgrep JSON parsers are implemented and tested using explicitly synthetic parser inputs. A source-only Docker runner and command policy are implemented; execution remains disabled by default until an operator validates a suitable rootless Linux engine and an audited image. Runtime isolation has not been tested. A missing analyzer makes a scan `partial`; an analyzer error makes it `failed`. Foundry, AI, LangGraph, Git URL ingestion, multi-user authentication, PDF exports, and the Next.js dashboard are not yet implemented. There are no claimed benchmark numbers, screenshots, or exploit reproductions.

## Quick start (Python 3.12+)

Install [uv](https://docs.astral.sh/uv/getting-started/installation/), then from this directory:

```sh
uv sync --locked
uv run alembic upgrade head
uv run python scripts/demo.py
uv run uvicorn sentinel.api:app --host 127.0.0.1 --port 8000 --no-proxy-headers
```

Open the generated [OpenAPI interface](http://127.0.0.1:8000/docs). The server is intentionally a loopback-only single-user demo. Do not expose it through a proxy, port forwarding, or public listener. `SENTINEL_MODE` values other than `local` refuse startup. This is not production authentication.

The demo uses the real application via its ASGI API, uploads the original MIT-licensed `ExternalCall.sol` fixture, creates a scan, runs the worker, requests more evidence with an explicit justification, and writes actual API responses and a report into `demo-output/`. The source contains unsafe state ordering, but the lexical result alone does not demonstrate exploitability. The report records that reproduction did not run.

For an uploaded archive, POST its bytes to `/api/v1/repositories?name=my-contracts` with `Content-Type: application/zip`. POST `{ "repository_id": "…" }` to `/api/v1/scans` with a fresh `Idempotency-Key` header. Run `uv run python -m sentinel.cli SCAN_ID` in a separate terminal. The queued scan survives API restart; an interrupted worker can be rerun to skip committed analyzer results. Run only one worker at a time. Failed scans require a new scan; automatic retries are not implemented.

SQLite is the zero-service offline default. For PostgreSQL development:

```sh
docker compose up -d postgres
export SENTINEL_DATABASE_URL=postgresql+psycopg://sentinel:local-demo-only@127.0.0.1:5432/sentinel
uv run alembic upgrade head
uv run python scripts/demo.py
```

The Compose credentials are intentionally local demo credentials, not production secrets. The database binds to loopback. PostgreSQL compatibility is configured; local PostgreSQL execution was unavailable in the initial environment. CI includes a PostgreSQL migration/demo job, which is not claimed to have run locally.

## Architecture

```mermaid
flowchart LR
  U[Local caller] --> A[FastAPI: loopback demo identity]
  A --> I[Bounded ZIP ingestion]
  I --> S[Content-pinned source snapshot]
  A --> D[(SQLAlchemy / SQLite or PostgreSQL)]
  W[Single worker] --> S
  W --> L[Lexical source review]
  W --> X[Unavailable external analyzers]
  L --> D
  X --> D
  D --> R[Human review / Markdown report]
```

See [architecture](docs/architecture/ARCHITECTURE.md), [decisions](docs/decisions/0001-foundation.md), [threat model](docs/security/THREAT_MODEL.md), and the [implementation checklist](docs/IMPLEMENTATION_PLAN.md).

## Quality gates

```sh
uv run ruff check src tests migrations scripts sandbox
uv run ruff format --check src tests migrations scripts sandbox
uv run mypy src
uv run bandit -q -r src sandbox
uv run pytest -q
uv run pip-audit --cache-dir .sentinel/audit-cache
```

Actual results are in [validation](docs/VALIDATION.md). Tests cover ingestion attacks, source integrity, parsers, API persistence, cancellation, tenant predicates, human review conflicts, worker replay, migration rollback, and denial of unsupported reproduction classifications. Sandbox command, timeout and output-budget tests use synthetic responses or trusted test snippets; they are not real container isolation tests or a full security audit.

## Known limits and next milestone

The next milestone is validating real, digest-pinned sandbox analyzer execution. See [sandbox operation](docs/security/SANDBOX.md). On the implementation machine `docker info` did not answer within an eight-second timeout. Installed host Slither and Foundry were deliberately not executed against repository content. Phase 1 remains incomplete, so later phases are queued rather than represented as working features.

No Git fetching means no SSRF endpoint exists yet. Uploaded archives record an immutable **content SHA-256**, not an invented Git commit. Only UTF-8 Solidity, JSON, TOML, lockfiles and Markdown are accepted; Hardhat JavaScript configuration and vendored unsupported file types are rejected rather than executed.

Snapshots are private directories and file hashes are rechecked before analysis. Filesystem permissions are not an integrity boundary against a compromised application user. Raw analyzer outputs and sources remain local; there is no artifact download endpoint. Automatic retention, distributed leases, full finding lifecycle, cross-tool semantic deduplication and full tenant database constraints remain pending.

## Contributing

Read [CONTRIBUTING.md](CONTRIBUTING.md). Report security issues using [SECURITY.md](SECURITY.md). MIT licensed; bundled fixtures were authored for this project and require no third-party dataset licensing assumptions.
