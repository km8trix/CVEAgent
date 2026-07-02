"""Postgres-only scan queue: enqueue, claim, and terminal writes.

The whole queue is one table (``scans``) polled with ``SELECT ... FOR UPDATE
SKIP LOCKED``. All helpers are synchronous and take an explicit Session so the
caller controls its lifecycle (request-scoped in the API, per-cycle in the worker).

# ponytail: pg-backed queue; add Redis/RQ only when one worker measurably can't keep up.
"""

from datetime import UTC, datetime
from typing import Any, NamedTuple, cast
from uuid import uuid4

from sqlalchemy import CursorResult, text, update
from sqlalchemy.orm import Session

from palisade.db.tables import Scan


class ClaimedJob(NamedTuple):
    id: str
    engine: str
    filename: str
    content: str


# Claim exactly one pending row and flip it to 'running' in a single round trip.
# SKIP LOCKED lets multiple workers coexist without blocking on each other's rows.
_CLAIM = text(
    """
    UPDATE scans
       SET status = 'running', claimed_at = now()
     WHERE id = (
         SELECT id FROM scans
          WHERE status = 'pending'
          ORDER BY created_at
            FOR UPDATE SKIP LOCKED
          LIMIT 1
     )
    RETURNING id, engine, filename, content
    """
)

# Startup crash recovery: return rows stuck in 'running' (worker died mid-job)
# to 'pending' so another worker can pick them up.
_RECLAIM = text(
    """
    UPDATE scans
       SET status = 'pending', claimed_at = NULL
     WHERE status = 'running'
       AND claimed_at < now() - make_interval(secs => :stale)
    """
)


def enqueue(session: Session, filename: str, content: str, engine: str) -> str:
    """Insert a pending scan and return its id (also the eventual ScanReport.scan_id)."""
    scan_id = str(uuid4())
    session.add(Scan(id=scan_id, filename=filename, content=content, engine=engine))
    session.commit()  # commit so the worker can see the row immediately
    return scan_id


def claim_one(session: Session) -> ClaimedJob | None:
    """Atomically claim the oldest pending scan, or None if the queue is empty."""
    row = session.execute(_CLAIM).first()
    session.commit()
    if row is None:
        return None
    return ClaimedJob(id=row[0], engine=row[1], filename=row[2], content=row[3])


# The `status == "running"` guard makes finish/fail no-ops if the row was reclaimed
# and re-claimed by another worker meanwhile — a stale worker can't clobber a fresh
# result. Harmless for a single worker; correct if we ever run N.
def finish(session: Session, scan_id: str, result: dict[str, Any]) -> None:
    session.execute(
        update(Scan)
        .where(Scan.id == scan_id, Scan.status == "running")
        .values(status="done", result=result, finished_at=datetime.now(UTC))
    )
    session.commit()


def fail(session: Session, scan_id: str, error: str) -> None:
    session.execute(
        update(Scan)
        .where(Scan.id == scan_id, Scan.status == "running")
        .values(status="error", error=error, finished_at=datetime.now(UTC))
    )
    session.commit()


def reclaim_stale(session: Session, stale_seconds: int) -> int:
    """Reset 'running' rows older than stale_seconds back to 'pending'. Returns the count."""
    result = cast("CursorResult[Any]", session.execute(_RECLAIM, {"stale": stale_seconds}))
    session.commit()
    return result.rowcount


def get_scan(session: Session, scan_id: str) -> Scan | None:
    return session.get(Scan, scan_id)
