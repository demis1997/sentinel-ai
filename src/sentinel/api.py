"""Loopback-only offline demo API. Never configure this identity for production."""

import os
import re
from collections.abc import Iterator
from contextlib import asynccontextmanager
from datetime import UTC
from pathlib import Path
from typing import Annotated, Any
from uuid import uuid4

from fastapi import Depends, FastAPI, Header, HTTPException, Query, Request
from fastapi.responses import JSONResponse, PlainTextResponse
from pydantic import Field
from sqlalchemy import select
from sqlalchemy.exc import IntegrityError
from sqlalchemy.orm import Session
from sqlalchemy.orm.exc import StaleDataError

from sentinel.db import AnalyzerRun, AuditEvent, Finding, Repository, Scan, sessions
from sentinel.domain import StrictModel
from sentinel.ingestion import MAX_ARCHIVE, IngestionError, ingest_zip


class ScanRequest(StrictModel):
    repository_id: str


class ReviewRequest(StrictModel):
    decision: str = Field(pattern="^(accepted|rejected|needs_more_evidence)$")
    justification: str = Field(min_length=8, max_length=2000)
    expected_version: int = Field(ge=1)


def create_app(database_url: str | None = None, storage: Path | None = None) -> FastAPI:
    factory = sessions(
        database_url or os.environ.get("SENTINEL_DATABASE_URL") or "sqlite:///sentinel.db"
    )
    storage = storage or Path(os.getenv("SENTINEL_STORAGE", ".sentinel/snapshots"))

    @asynccontextmanager
    async def lifespan(app: FastAPI) -> Any:
        if os.getenv("SENTINEL_MODE", "local") != "local":
            raise RuntimeError("Production authentication is not implemented; startup refused")
        yield

    app = FastAPI(title="Sentinel AI", version="0.1.0", lifespan=lifespan)
    app.state.factory = factory

    def identity(request: Request) -> str:
        # Never trust forwarded headers or a caller-supplied tenant header.
        if request.client is None or request.client.host not in {"127.0.0.1", "::1", "testclient"}:
            raise HTTPException(403, "Local demo accepts loopback clients only")
        try:
            host = request.url.hostname
        except ValueError:
            raise HTTPException(403, "Invalid local host") from None
        if host not in {"127.0.0.1", "localhost", "::1"}:
            raise HTTPException(403, "Invalid local host")
        origin = request.headers.get("origin")
        expected_origin = f"{request.url.scheme}://{request.headers.get('host')}"
        if origin is not None and origin != expected_origin:
            raise HTTPException(403, "Cross-origin requests are not allowed in local mode")
        return "local-demo"

    def database() -> Iterator[Session]:
        with factory() as session:
            yield session

    Tenant = Annotated[str, Depends(identity)]
    Database = Annotated[Session, Depends(database)]

    @app.middleware("http")
    async def correlation(request: Request, call_next: Any) -> Any:
        request.state.correlation_id = str(uuid4())
        response = await call_next(request)
        response.headers["X-Correlation-ID"] = request.state.correlation_id
        response.headers["X-Content-Type-Options"] = "nosniff"
        return response

    @app.exception_handler(IngestionError)
    async def ingestion_error(request: Request, exc: IngestionError) -> JSONResponse:
        return JSONResponse(
            status_code=422,
            content={"detail": str(exc), "correlation_id": request.state.correlation_id},
        )

    @app.get("/api/v1/health")
    def health() -> dict[str, str]:
        return {"status": "ok", "mode": "local-demo", "verification": "disabled"}

    @app.post(
        "/api/v1/repositories",
        status_code=201,
        openapi_extra={
            "requestBody": {
                "required": True,
                "content": {"application/zip": {"schema": {"type": "string", "format": "binary"}}},
            }
        },
    )
    async def upload(
        request: Request,
        tenant: Tenant,
        db: Database,
        name: str = Query(min_length=1, max_length=100),
    ) -> dict[str, Any]:
        if request.headers.get("content-type") != "application/zip":
            raise HTTPException(415, "Send application/zip")
        data = bytearray()
        async for chunk in request.stream():
            data.extend(chunk)
            if len(data) > MAX_ARCHIVE:
                raise HTTPException(413, "Archive exceeds limit")
        manifest, snapshot = ingest_zip(bytes(data), storage)
        repository = Repository(
            tenant=tenant,
            name=name,
            revision=manifest.revision,
            snapshot=str(snapshot.resolve()),
            manifest=manifest.model_dump(),
        )
        db.add(repository)
        db.flush()
        db.add(
            AuditEvent(
                tenant=tenant,
                entity_id=repository.id,
                action="source_ingested",
                actor=tenant,
                detail={"revision": manifest.revision},
            )
        )
        db.commit()
        return {"id": repository.id, "name": name, "manifest": manifest.model_dump()}

    @app.get("/api/v1/repositories")
    def repositories(
        tenant: Tenant,
        db: Database,
        limit: int = Query(50, ge=1, le=100),
        offset: int = Query(0, ge=0),
    ) -> list[dict[str, Any]]:
        return [
            {"id": r.id, "name": r.name, "revision": r.revision}
            for r in db.scalars(
                select(Repository)
                .where(Repository.tenant == tenant)
                .order_by(Repository.id)
                .limit(limit)
                .offset(offset)
            )
        ]

    @app.post("/api/v1/scans", status_code=201)
    def start(
        body: ScanRequest,
        tenant: Tenant,
        db: Database,
        idempotency_key: Annotated[str, Header(min_length=8, max_length=100)],
    ) -> dict[str, str]:
        repository = db.scalar(
            select(Repository).where(
                Repository.id == body.repository_id, Repository.tenant == tenant
            )
        )
        if repository is None:
            raise HTTPException(404, "Repository not found")
        existing = db.scalar(
            select(Scan).where(Scan.tenant == tenant, Scan.idempotency_key == idempotency_key)
        )
        if existing:
            if existing.repository_id != body.repository_id:
                raise HTTPException(409, "Idempotency key belongs to a different request")
            return {"id": existing.id, "status": existing.status}
        scan = Scan(
            tenant=tenant,
            repository_id=repository.id,
            revision=repository.revision,
            idempotency_key=idempotency_key,
        )
        db.add(scan)
        try:
            db.flush()
            db.add(
                AuditEvent(
                    tenant=tenant,
                    entity_id=scan.id,
                    actor=tenant,
                    action="scan_queued",
                    detail={"revision": scan.revision},
                )
            )
            db.commit()
        except IntegrityError:
            db.rollback()
            raise HTTPException(409, "Concurrent idempotency request; retry") from None
        return {"id": scan.id, "status": scan.status}

    def get_scan(scan_id: str, tenant: str, db: Session) -> Scan:
        scan = db.scalar(select(Scan).where(Scan.id == scan_id, Scan.tenant == tenant))
        if scan is None:
            raise HTTPException(404, "Scan not found")
        return scan

    @app.get("/api/v1/scans")
    def scans(
        tenant: Tenant,
        db: Database,
        limit: int = Query(50, ge=1, le=100),
        offset: int = Query(0, ge=0),
    ) -> list[dict[str, Any]]:
        return [
            {"id": s.id, "status": s.status, "revision": s.revision}
            for s in db.scalars(
                select(Scan)
                .where(Scan.tenant == tenant)
                .order_by(Scan.id)
                .limit(limit)
                .offset(offset)
            )
        ]

    @app.get("/api/v1/scans/{scan_id}")
    def scan_detail(scan_id: str, tenant: Tenant, db: Database) -> dict[str, Any]:
        scan = get_scan(scan_id, tenant, db)
        runs = list(
            db.scalars(
                select(AnalyzerRun).where(
                    AnalyzerRun.scan_id == scan_id, AnalyzerRun.tenant == tenant
                )
            )
        )
        return {
            "id": scan.id,
            "status": scan.status,
            "revision": scan.revision,
            "error": scan.error,
            "analyzers": [{"id": r.id, **r.result} for r in runs],
        }

    @app.post("/api/v1/scans/{scan_id}/cancel")
    def cancel(scan_id: str, tenant: Tenant, db: Database) -> dict[str, str]:
        scan = get_scan(scan_id, tenant, db)
        if scan.status in {"queued", "running"}:
            scan.status = "cancelled"
            db.add(
                AuditEvent(
                    tenant=tenant,
                    entity_id=scan.id,
                    action="scan_cancelled",
                    actor=tenant,
                    detail={},
                )
            )
            db.commit()
        return {"id": scan.id, "status": scan.status}

    @app.get("/api/v1/scans/{scan_id}/findings")
    def findings(
        scan_id: str,
        tenant: Tenant,
        db: Database,
        limit: int = Query(50, ge=1, le=100),
        offset: int = Query(0, ge=0),
        severity: str | None = None,
    ) -> list[dict[str, Any]]:
        get_scan(scan_id, tenant, db)
        statement = select(Finding).where(Finding.scan_id == scan_id, Finding.tenant == tenant)
        if severity:
            statement = statement.where(Finding.candidate["severity"].as_string() == severity)
        return [
            {
                "id": f.id,
                "review": f.review,
                "version": f.version,
                **f.candidate,
                "evidence_sources": f.evidence,
            }
            for f in db.scalars(statement.order_by(Finding.id).limit(limit).offset(offset))
        ]

    @app.get("/api/v1/findings/{finding_id}")
    def finding_detail(finding_id: str, tenant: Tenant, db: Database) -> dict[str, Any]:
        finding = db.scalar(
            select(Finding).where(Finding.id == finding_id, Finding.tenant == tenant)
        )
        if finding is None:
            raise HTTPException(404, "Finding not found")
        return {
            "id": finding.id,
            "scan_id": finding.scan_id,
            "review": finding.review,
            "version": finding.version,
            **finding.candidate,
            "evidence_sources": finding.evidence,
        }

    @app.post("/api/v1/findings/{finding_id}/review")
    def review(
        finding_id: str, body: ReviewRequest, tenant: Tenant, db: Database
    ) -> dict[str, Any]:
        finding = db.scalar(
            select(Finding).where(Finding.id == finding_id, Finding.tenant == tenant)
        )
        if finding is None:
            raise HTTPException(404, "Finding not found")
        if finding.version != body.expected_version:
            raise HTTPException(409, "Stale finding version")
        finding.review = body.decision
        db.add(
            AuditEvent(
                tenant=tenant,
                entity_id=finding.id,
                action="human_review",
                actor=tenant,
                detail=body.model_dump(),
            )
        )
        try:
            db.commit()
        except StaleDataError:
            db.rollback()
            raise HTTPException(409, "Concurrent review conflict") from None
        return {"id": finding.id, "review": finding.review, "version": finding.version}

    @app.get("/api/v1/reports/{scan_id}", response_class=PlainTextResponse)
    def report(scan_id: str, tenant: Tenant, db: Database) -> str:
        scan = get_scan(scan_id, tenant, db)
        rows = list(
            db.scalars(select(Finding).where(Finding.scan_id == scan_id, Finding.tenant == tenant))
        )

        # Code fences containing attacker-controlled text are avoided in reports.
        def escape(value: Any) -> str:
            text = str(value).replace("\n", " ").replace("\r", " ")
            text = text.replace("&", "&amp;").replace("<", "&lt;").replace(">", "&gt;")
            return re.sub(r"([\\`*_{}\[\]()#+.!|~-])", r"\\\1", text)

        lines = [
            "# Sentinel AI security research report",
            "",
            f"Source content SHA-256: {scan.revision}",
            f"Scan status: {scan.status}",
            "",
            "Scope: uploaded source archive. No deployment or runtime configuration assessed.",
            "Methodology: source review and configured static analyzers; "
            "no executable verification.",
            "Assumptions: source-only scope; deployment state, balances "
            "and trust roles are unknown.",
            "No executable reproduction was performed. Review acceptance is not verification.",
            "",
        ]
        runs = db.scalars(
            select(AnalyzerRun).where(AnalyzerRun.scan_id == scan_id, AnalyzerRun.tenant == tenant)
        )
        lines.append("## Tools and execution status")
        for run in runs:
            lines.append(
                f"- {escape(run.tool)} {escape(run.result['version'])}: "
                f"{escape(run.result['status'])}; "
                f"{escape(run.result.get('error') or 'no execution error')}"
            )
        lines.append("")
        for finding in rows:
            candidate = finding.candidate
            lines.extend(
                [
                    f"## {escape(candidate['summary'])}",
                    f"Location: {escape(candidate['path'])}:{candidate['start']}",
                    f"Evidence strength: {candidate['strength']}; review: {finding.review}",
                    f"Evidence: {escape(candidate['evidence'])}",
                    f"Severity: {escape(candidate['severity'])}; "
                    "rationale: lexical candidates are informational; "
                    "other ratings are tool-reported.",
                    "Remediation: assess the referenced trust boundary and security invariant.",
                    "",
                ]
            )
            decisions = db.scalars(
                select(AuditEvent)
                .where(
                    AuditEvent.entity_id == finding.id,
                    AuditEvent.tenant == tenant,
                    AuditEvent.action == "human_review",
                )
                .order_by(AuditEvent.created_at)
            )
            for decision in decisions:
                timestamp = decision.created_at
                if timestamp.tzinfo is None:
                    timestamp = timestamp.replace(tzinfo=UTC)
                lines.append(
                    f"Reviewer: {escape(decision.actor)} at {timestamp.isoformat()}; "
                    f"{escape(decision.detail['justification'])}"
                )
        return "\n".join(lines) + "\n"

    return app


app = create_app()
