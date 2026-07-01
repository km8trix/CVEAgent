"""initial: advisories + advisory_embeddings

Revision ID: 0001_initial
Revises:
Create Date: 2026-07-01

"""

from collections.abc import Sequence

import sqlalchemy as sa
from alembic import op
from pgvector.sqlalchemy import Vector
from sqlalchemy.dialects import postgresql

from palisade.config import get_settings

revision: str = "0001_initial"
down_revision: str | None = None
branch_labels: Sequence[str] | None = None
depends_on: str | Sequence[str] | None = None

EMBEDDING_DIM = get_settings().embedding_dim


def upgrade() -> None:
    op.execute("CREATE EXTENSION IF NOT EXISTS vector")

    op.create_table(
        "advisories",
        sa.Column("id", sa.String(), primary_key=True),
        sa.Column("source", sa.String(8), nullable=False),
        sa.Column("source_id", sa.String(), nullable=False),
        sa.Column("aliases", postgresql.ARRAY(sa.String()), nullable=False, server_default="{}"),
        sa.Column("summary", sa.Text(), nullable=False, server_default=""),
        sa.Column("details", sa.Text(), nullable=False, server_default=""),
        sa.Column("severity", postgresql.JSONB(), nullable=False, server_default="{}"),
        sa.Column("cwe_ids", postgresql.ARRAY(sa.String()), nullable=False, server_default="{}"),
        sa.Column("affected", postgresql.JSONB(), nullable=False, server_default="[]"),
        sa.Column("references", postgresql.ARRAY(sa.String()), nullable=False, server_default="{}"),
        sa.Column("published", sa.DateTime(timezone=True), nullable=False),
        sa.Column("modified", sa.DateTime(timezone=True), nullable=False),
        sa.Column("content_hash", sa.String(64), nullable=False),
    )
    op.create_index("ix_advisories_source", "advisories", ["source"])
    op.create_index("ix_advisories_source_id", "advisories", ["source_id"])
    op.create_index("ix_advisories_modified", "advisories", ["modified"])
    op.create_index("ix_advisories_content_hash", "advisories", ["content_hash"])
    op.create_index(
        "ix_advisories_source_source_id", "advisories", ["source", "source_id"], unique=True
    )

    op.create_table(
        "advisory_embeddings",
        sa.Column(
            "advisory_id",
            sa.String(),
            sa.ForeignKey("advisories.id", ondelete="CASCADE"),
            primary_key=True,
        ),
        sa.Column("chunk_index", sa.Integer(), primary_key=True, server_default="0"),
        sa.Column("content", sa.Text(), nullable=False),
        sa.Column("embedding", Vector(EMBEDDING_DIM), nullable=False),
    )
    op.create_index(
        "ix_advisory_embeddings_hnsw",
        "advisory_embeddings",
        ["embedding"],
        postgresql_using="hnsw",
        postgresql_with={"m": 16, "ef_construction": 64},
        postgresql_ops={"embedding": "vector_cosine_ops"},
    )


def downgrade() -> None:
    op.drop_table("advisory_embeddings")
    op.drop_table("advisories")
