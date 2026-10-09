# ADR 0001: explicit, non-executing foundation milestone

Status: accepted for v0.1; production suitability not asserted.

Context: Empty workspace, installed host analyzers, unavailable Docker isolation. Repository builds can execute malicious configuration, so host tool availability does not authorize host execution.

Decision: Use FastAPI, Pydantic typed schemas, SQLAlchemy 2.x and Alembic. Support PostgreSQL URLs and a SQLite offline demo. Keep a modular monolith. Use content-pinned UTF-8 ZIP ingestion, a transparently lexical analyzer, strict external-output parsers, and a source-only Docker runner with explicit `unavailable` outcomes until operator isolation validation. Defer Git URLs until SSRF-safe retrieval is implemented. Defer the LangGraph graph and UI until the deterministic analyzer milestone is stable.

Consequences: Offline ingestion, persistence, human triage and reporting can be verified now. Real static security analysis and executable reproduction cannot be claimed. A working engine plus a tested isolated execution adapter is a prerequisite for the next milestone. A parser test is never a tool execution test.

References: [FastAPI dependencies](https://fastapi.tiangolo.com/tutorial/dependencies/), [SQLAlchemy sessions](https://docs.sqlalchemy.org/en/20/orm/session_basics.html), [Docker security](https://docs.docker.com/engine/security/).
