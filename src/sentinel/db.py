"""Tenant-scoped persistence. The initial demo identity is single-user only."""

from datetime import UTC, datetime
from typing import Any
from uuid import uuid4

from sqlalchemy import JSON, DateTime, ForeignKey, String, UniqueConstraint, create_engine
from sqlalchemy.orm import DeclarativeBase, Mapped, Session, mapped_column, sessionmaker


def identifier() -> str:
    return str(uuid4())


class Base(DeclarativeBase):
    pass


class Repository(Base):
    __tablename__ = "repositories"
    id: Mapped[str] = mapped_column(String, primary_key=True, default=identifier)
    tenant: Mapped[str]
    name: Mapped[str]
    revision: Mapped[str]
    snapshot: Mapped[str]
    manifest: Mapped[dict[str, Any]] = mapped_column(JSON)


class Scan(Base):
    __tablename__ = "scans"
    __table_args__ = (UniqueConstraint("tenant", "idempotency_key"),)
    id: Mapped[str] = mapped_column(String, primary_key=True, default=identifier)
    tenant: Mapped[str]
    repository_id: Mapped[str] = mapped_column(ForeignKey("repositories.id"))
    revision: Mapped[str]
    idempotency_key: Mapped[str]
    status: Mapped[str] = mapped_column(default="queued")
    error: Mapped[str | None]


class AnalyzerRun(Base):
    __tablename__ = "analyzer_runs"
    __table_args__ = (UniqueConstraint("scan_id", "tool"),)
    id: Mapped[str] = mapped_column(String, primary_key=True, default=identifier)
    tenant: Mapped[str]
    scan_id: Mapped[str] = mapped_column(ForeignKey("scans.id"))
    tool: Mapped[str]
    result: Mapped[dict[str, Any]] = mapped_column(JSON)


class Finding(Base):
    __tablename__ = "findings"
    __table_args__ = (UniqueConstraint("scan_id", "fingerprint"),)
    id: Mapped[str] = mapped_column(String, primary_key=True, default=identifier)
    tenant: Mapped[str]
    scan_id: Mapped[str] = mapped_column(ForeignKey("scans.id"))
    fingerprint: Mapped[str]
    candidate: Mapped[dict[str, Any]] = mapped_column(JSON)
    evidence: Mapped[list[dict[str, Any]]] = mapped_column(JSON)
    review: Mapped[str] = mapped_column(default="pending")
    version: Mapped[int] = mapped_column(default=1)
    __mapper_args__ = {"version_id_col": version}


class AuditEvent(Base):
    __tablename__ = "audit_events"
    id: Mapped[str] = mapped_column(String, primary_key=True, default=identifier)
    tenant: Mapped[str]
    entity_id: Mapped[str]
    action: Mapped[str]
    actor: Mapped[str] = mapped_column(default="worker")
    created_at: Mapped[datetime] = mapped_column(
        DateTime(timezone=True), default=lambda: datetime.now(UTC)
    )
    detail: Mapped[dict[str, Any]] = mapped_column(JSON)


def sessions(url: str) -> sessionmaker[Session]:
    kwargs: dict[str, Any] = {}
    if url.startswith("sqlite"):
        kwargs["connect_args"] = {"check_same_thread": False}
    engine = create_engine(url, **kwargs)
    return sessionmaker(engine, expire_on_commit=False)
