"""ORM tables for the advisory corpus, its embeddings, and the M3 scan queue.

See IMPLEMENTATION_PLAN.md section 4.
"""

from datetime import datetime
from typing import Any

from pgvector.sqlalchemy import Vector
from sqlalchemy import CheckConstraint, DateTime, ForeignKey, Index, String, Text, func, text
from sqlalchemy.dialects.postgresql import ARRAY, JSONB
from sqlalchemy.orm import Mapped, mapped_column

from palisade.config import get_settings
from palisade.db.base import Base

EMBEDDING_DIM = get_settings().embedding_dim


class Advisory(Base):
    __tablename__ = "advisories"

    id: Mapped[str] = mapped_column(String, primary_key=True)
    source: Mapped[str] = mapped_column(String(8), index=True)
    source_id: Mapped[str] = mapped_column(String, index=True)
    aliases: Mapped[list[str]] = mapped_column(ARRAY(String), default=list)
    summary: Mapped[str] = mapped_column(Text, default="")
    details: Mapped[str] = mapped_column(Text, default="")
    severity: Mapped[dict[str, Any]] = mapped_column(JSONB, default=dict)
    cwe_ids: Mapped[list[str]] = mapped_column(ARRAY(String), default=list)
    affected: Mapped[list[Any]] = mapped_column(JSONB, default=list)
    references: Mapped[list[str]] = mapped_column(ARRAY(String), default=list)
    published: Mapped[datetime] = mapped_column(DateTime(timezone=True))
    modified: Mapped[datetime] = mapped_column(DateTime(timezone=True), index=True)
    content_hash: Mapped[str] = mapped_column(String(64), index=True)

    __table_args__ = (Index("ix_advisories_source_source_id", "source", "source_id", unique=True),)


class AdvisoryEmbedding(Base):
    __tablename__ = "advisory_embeddings"

    advisory_id: Mapped[str] = mapped_column(
        ForeignKey("advisories.id", ondelete="CASCADE"), primary_key=True
    )
    chunk_index: Mapped[int] = mapped_column(primary_key=True, default=0)
    content: Mapped[str] = mapped_column(Text)
    embedding: Mapped[list[float]] = mapped_column(Vector(EMBEDDING_DIM))


class Scan(Base):
    """M3 async scan queue: one row per submitted scan. The worker claims pending
    rows with SELECT ... FOR UPDATE SKIP LOCKED, runs the pipeline, and writes the
    ScanReport into ``result``.

    # ponytail: ``result`` is a JSONB blob of the whole ScanReport, not a normalized
    # findings schema — normalize only if we ever need to query findings in SQL.
    """

    __tablename__ = "scans"

    id: Mapped[str] = mapped_column(String, primary_key=True)
    status: Mapped[str] = mapped_column(String(16), nullable=False, server_default="pending")
    engine: Mapped[str] = mapped_column(String(8), nullable=False, server_default="scan")
    filename: Mapped[str] = mapped_column(Text, nullable=False)
    content: Mapped[str] = mapped_column(Text, nullable=False)
    result: Mapped[dict[str, Any] | None] = mapped_column(JSONB, nullable=True)
    error: Mapped[str | None] = mapped_column(Text, nullable=True)
    created_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), server_default=func.now())
    claimed_at: Mapped[datetime | None] = mapped_column(DateTime(timezone=True), nullable=True)
    finished_at: Mapped[datetime | None] = mapped_column(DateTime(timezone=True), nullable=True)

    __table_args__ = (
        # Partial index keeps the FIFO claim scan cheap as done/error rows accumulate.
        Index("ix_scans_pending", "created_at", postgresql_where=text("status = 'pending'")),
        # A done scan must carry its report — the read path relies on this invariant.
        CheckConstraint("status <> 'done' OR result IS NOT NULL", name="ck_scans_done_has_result"),
    )
