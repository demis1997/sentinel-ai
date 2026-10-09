"""Explicit offline worker: committed analyzer results survive interruption."""

import os
from pathlib import Path
from time import monotonic

from sqlalchemy import select
from sqlalchemy.orm import Session, sessionmaker

from sentinel.analysis import Analyzer, LexicalAnalyzer
from sentinel.db import AnalyzerRun, AuditEvent, Finding, Repository, Scan
from sentinel.domain import AnalyzerResult, Manifest
from sentinel.ingestion import verify_snapshot
from sentinel.sandbox import DockerAnalyzer


def execute_scan(
    factory: sessionmaker[Session], scan_id: str, analyzers: list[Analyzer] | None = None
) -> None:
    analyzers = (
        analyzers
        if analyzers is not None
        else [
            LexicalAnalyzer(),
            DockerAnalyzer(
                "slither",
                os.environ.get("SENTINEL_ANALYZER_IMAGE"),
                os.environ.get("SENTINEL_SANDBOX_VALIDATED") == "1",
            ),
            DockerAnalyzer(
                "semgrep",
                os.environ.get("SENTINEL_ANALYZER_IMAGE"),
                os.environ.get("SENTINEL_SANDBOX_VALIDATED") == "1",
            ),
        ]
    )
    with factory.begin() as session:
        scan = session.get(Scan, scan_id)
        if scan is None or scan.status in {"cancelled", "completed", "partial", "failed"}:
            return
        # One worker only in phase 1. Cross-process leases are required before scaling.
        scan.status = "running"
        repository = session.get(Repository, scan.repository_id)
        if repository is None:
            raise ValueError("Missing repository")
        manifest = Manifest.model_validate(repository.manifest)
        snapshot = Path(repository.snapshot)
        tenant = scan.tenant
    try:
        verify_snapshot(manifest, snapshot)
        for analyzer in analyzers:
            with factory() as session:
                scan = session.get(Scan, scan_id)
                if scan is None:
                    raise ValueError("Missing scan")
                if scan.status == "cancelled":
                    return
                completed = {
                    run.tool
                    for run in session.scalars(
                        select(AnalyzerRun).where(
                            AnalyzerRun.scan_id == scan_id, AnalyzerRun.tenant == tenant
                        )
                    )
                }
            tool = analyzer.tool
            if tool in completed:
                continue
            started = monotonic()
            result = AnalyzerResult.model_validate(
                analyzer.run(manifest, snapshot).model_dump(mode="json")
            )
            result.duration_ms = int((monotonic() - started) * 1000)
            with factory.begin() as session:
                scan = session.get(Scan, scan_id)
                if scan is None:
                    raise ValueError("Missing scan")
                if scan.status == "cancelled":
                    return
                session.add(
                    AnalyzerRun(
                        tenant=tenant,
                        scan_id=scan_id,
                        tool=result.tool,
                        result=result.model_dump(mode="json"),
                    )
                )
                for candidate in result.findings:
                    fingerprint = candidate.fingerprint(manifest.revision)
                    existing = session.scalar(
                        select(Finding).where(
                            Finding.scan_id == scan_id,
                            Finding.fingerprint == fingerprint,
                            Finding.tenant == tenant,
                        )
                    )
                    evidence = {
                        "tool": result.tool,
                        "version": result.version,
                        "candidate": candidate.model_dump(mode="json"),
                    }
                    if existing:
                        existing.evidence = [*existing.evidence, evidence]
                    else:
                        session.add(
                            Finding(
                                tenant=tenant,
                                scan_id=scan_id,
                                fingerprint=fingerprint,
                                candidate=candidate.model_dump(mode="json"),
                                evidence=[evidence],
                            )
                        )
        with factory.begin() as session:
            scan = session.get(Scan, scan_id)
            if scan is None:
                raise ValueError("Missing scan")
            if scan.status == "cancelled":
                return
            statuses = [
                run.result["status"]
                for run in session.scalars(
                    select(AnalyzerRun).where(AnalyzerRun.scan_id == scan_id)
                )
            ]
            scan.status = (
                "failed"
                if "failed" in statuses
                else ("partial" if "unavailable" in statuses else "completed")
            )
            session.add(
                AuditEvent(
                    tenant=tenant,
                    entity_id=scan_id,
                    action="scan_finished",
                    detail={"status": scan.status},
                )
            )
    except Exception:
        with factory.begin() as session:
            scan = session.get(Scan, scan_id)
            if scan is None:
                raise ValueError("Missing scan") from None
            if scan.status != "cancelled":
                scan.status = "failed"
                scan.error = "Analysis failed; inspect local worker diagnostics"
        raise
