"""Initial persisted source, scan, evidence and audit schema."""

import sqlalchemy as sa
from alembic import op

revision = "0001"
down_revision = None
branch_labels = None
depends_on = None


def upgrade() -> None:
    op.create_table(
        "repositories",
        sa.Column("id", sa.String(), primary_key=True),
        sa.Column("tenant", sa.String(), nullable=False),
        sa.Column("name", sa.String(), nullable=False),
        sa.Column("revision", sa.String(), nullable=False),
        sa.Column("snapshot", sa.String(), nullable=False),
        sa.Column("manifest", sa.JSON(), nullable=False),
    )
    op.create_table(
        "scans",
        sa.Column("id", sa.String(), primary_key=True),
        sa.Column("tenant", sa.String(), nullable=False),
        sa.Column("repository_id", sa.String(), sa.ForeignKey("repositories.id"), nullable=False),
        sa.Column("revision", sa.String(), nullable=False),
        sa.Column("idempotency_key", sa.String(), nullable=False),
        sa.Column("status", sa.String(), nullable=False),
        sa.Column("error", sa.String(), nullable=True),
        sa.UniqueConstraint("tenant", "idempotency_key"),
    )
    op.create_table(
        "analyzer_runs",
        sa.Column("id", sa.String(), primary_key=True),
        sa.Column("tenant", sa.String(), nullable=False),
        sa.Column("scan_id", sa.String(), sa.ForeignKey("scans.id"), nullable=False),
        sa.Column("tool", sa.String(), nullable=False),
        sa.Column("result", sa.JSON(), nullable=False),
        sa.UniqueConstraint("scan_id", "tool"),
    )
    op.create_table(
        "findings",
        sa.Column("id", sa.String(), primary_key=True),
        sa.Column("tenant", sa.String(), nullable=False),
        sa.Column("scan_id", sa.String(), sa.ForeignKey("scans.id"), nullable=False),
        sa.Column("fingerprint", sa.String(), nullable=False),
        sa.Column("candidate", sa.JSON(), nullable=False),
        sa.Column("evidence", sa.JSON(), nullable=False),
        sa.Column("review", sa.String(), nullable=False),
        sa.Column("version", sa.Integer(), nullable=False),
        sa.UniqueConstraint("scan_id", "fingerprint"),
    )
    op.create_table(
        "audit_events",
        sa.Column("id", sa.String(), primary_key=True),
        sa.Column("tenant", sa.String(), nullable=False),
        sa.Column("entity_id", sa.String(), nullable=False),
        sa.Column("action", sa.String(), nullable=False),
        sa.Column("actor", sa.String(), nullable=False),
        sa.Column("created_at", sa.DateTime(timezone=True), nullable=False),
        sa.Column("detail", sa.JSON(), nullable=False),
    )


def downgrade() -> None:
    for table in ("audit_events", "findings", "analyzer_runs", "scans", "repositories"):
        op.drop_table(table)
