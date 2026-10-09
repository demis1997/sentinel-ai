# ADR 0002: local-only demo identity and explicit execution

Status: accepted for the initial milestone.

Context: A real authentication integration and distributed coordination would substantially expand the foundation. A demo must not accidentally claim multi-user security.

Decision: Only local mode starts. API access requires a loopback client, a local Host, and absent or matching same-origin Origin. No forwarded headers or client-supplied tenant identity are trusted. Queries contain tenant predicates. The CLI runs one durable queued scan explicitly. SQLite enables a service-free demo; PostgreSQL is the intended server backend. Alembic owns schema initialization.

Consequences: The API must stay on loopback and must not be proxied. Real auth, database tenant constraints, distributed leases and worker scaling are pending. HTTP request idempotency and optimistic review checks are implemented, but these do not substitute for distributed job coordination.
