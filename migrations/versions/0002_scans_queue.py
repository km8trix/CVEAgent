"""scans queue table

Revision ID: 0002_scans_queue
Revises: 0001_initial
Create Date: 2026-07-02

"""

from collections.abc import Sequence

import sqlalchemy as sa
from alembic import op
from sqlalchemy.dialects import postgresql

revision: str = "0002_scans_queue"
down_revision: str | None = "0001_initial"
branch_labels: Sequence[str] | None = None
depends_on: str | Sequence[str] | None = None


def upgrade() -> None:
    op.create_table(
        "scans",
        sa.Column("id", sa.String(), primary_key=True),
        sa.Column("status", sa.String(16), nullable=False, server_default="pending"),
        sa.Column("engine", sa.String(8), nullable=False, server_default="scan"),
        sa.Column("filename", sa.Text(), nullable=False),
        sa.Column("content", sa.Text(), nullable=False),
        sa.Column("result", postgresql.JSONB(), nullable=True),
        sa.Column("error", sa.Text(), nullable=True),
        sa.Column(
            "created_at",
            sa.DateTime(timezone=True),
            nullable=False,
            server_default=sa.text("now()"),
        ),
        sa.Column("claimed_at", sa.DateTime(timezone=True), nullable=True),
        sa.Column("finished_at", sa.DateTime(timezone=True), nullable=True),
        # A done scan must carry its report; the GET read path depends on this.
        sa.CheckConstraint(
            "status <> 'done' OR result IS NOT NULL", name="ck_scans_done_has_result"
        ),
    )
    # Partial index: FIFO claim only ever scans pending rows, so keep it cheap as
    # done/error rows pile up.
    op.create_index(
        "ix_scans_pending",
        "scans",
        ["created_at"],
        postgresql_where=sa.text("status = 'pending'"),
    )


def downgrade() -> None:
    op.drop_index("ix_scans_pending", table_name="scans")
    op.drop_table("scans")
