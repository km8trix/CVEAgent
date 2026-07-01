"""ORM tables for the advisory corpus and its embeddings.

Scans/findings tables are deferred to M2, built with the scan pipeline that
populates them (their shape follows the still-evolving Finding model).
See IMPLEMENTATION_PLAN.md section 4.
"""

from datetime import datetime
from typing import Any

from pgvector.sqlalchemy import Vector
from sqlalchemy import DateTime, ForeignKey, Index, String, Text
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
