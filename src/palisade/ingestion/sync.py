"""Sync OSV advisories into Postgres with idempotent, content-hash-based upsert.

A record is inserted if new, updated if its content_hash changed, skipped otherwise.
See IMPLEMENTATION_PLAN.md sections 4 and 5.
"""

import logging
import time
from collections.abc import Iterable
from dataclasses import dataclass
from typing import Any

import httpx
from sqlalchemy.orm import Session

from palisade.db.tables import Advisory
from palisade.ingestion.normalize import normalize_osv
from palisade.ingestion.sources.osv_export import download_export, iter_records
from palisade.models.advisory import AdvisoryRecord

logger = logging.getLogger(__name__)


@dataclass
class SyncStats:
    inserted: int = 0
    updated: int = 0
    skipped: int = 0
    errors: int = 0


def _to_row(rec: AdvisoryRecord) -> dict[str, Any]:
    return {
        "id": rec.id,
        "source": rec.source,
        "source_id": rec.source_id,
        "aliases": rec.aliases,
        "summary": rec.summary,
        "details": rec.details,
        "severity": rec.severity.model_dump(),
        "cwe_ids": rec.cwe_ids,
        "affected": [a.model_dump() for a in rec.affected],
        "references": rec.references,
        "published": rec.published,
        "modified": rec.modified,
        "content_hash": rec.content_hash,
    }


def _decide(existing_hash: str | None, new_hash: str) -> str:
    """Pure upsert decision: inserted / skipped / updated."""
    if existing_hash is None:
        return "inserted"
    if existing_hash == new_hash:
        return "skipped"
    return "updated"


def upsert_advisory(session: Session, rec: AdvisoryRecord) -> str:
    # ponytail: per-record SELECT via session.get; batch/COPY if full-corpus sync gets slow.
    existing = session.get(Advisory, rec.id)
    decision = _decide(existing.content_hash if existing else None, rec.content_hash)
    row = _to_row(rec)
    if decision == "inserted":
        session.add(Advisory(**row))
    elif decision == "updated" and existing is not None:
        for key, value in row.items():
            setattr(existing, key, value)
    return decision


def sync_records(
    session: Session, raws: Iterable[dict[str, Any]], *, commit_every: int = 500
) -> SyncStats:
    stats = SyncStats()
    pending = 0
    for raw in raws:
        try:
            rec = normalize_osv(raw)
        except ValueError as exc:
            stats.errors += 1
            logger.warning("normalize failed for %s: %s", raw.get("id", "<unknown>"), exc)
            continue
        decision = upsert_advisory(session, rec)
        setattr(stats, decision, getattr(stats, decision) + 1)
        if decision != "skipped":  # skips write nothing; don't advance the commit batch
            pending += 1
        if pending >= commit_every:
            session.commit()
            pending = 0
    session.commit()
    return stats


async def sync_ecosystem(
    ecosystem: str, session: Session, *, client: httpx.AsyncClient | None = None
) -> SyncStats:
    zip_bytes = await download_export(ecosystem, client=client)
    start = time.monotonic()
    stats = sync_records(session, iter_records(zip_bytes))
    logger.info("sync %s: %s in %.1fs", ecosystem, stats, time.monotonic() - start)
    return stats


def _run(ecosystem: str) -> None:  # pragma: no cover
    import asyncio

    from palisade.db.base import SessionLocal

    async def go() -> SyncStats:
        with SessionLocal() as session:
            return await sync_ecosystem(ecosystem, session)

    print(asyncio.run(go()))


if __name__ == "__main__":  # pragma: no cover
    import sys

    logging.basicConfig(level=logging.INFO)
    _run(sys.argv[1] if len(sys.argv) > 1 else "PyPI")
