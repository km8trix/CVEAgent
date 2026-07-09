"""``python -m palisade.worker`` — single-process pg-queue consumer.

Claims one pending scan at a time (SELECT ... FOR UPDATE SKIP LOCKED), runs the
existing async scan pipeline, and writes the ScanReport (or the error) back to the row.

The DB engine stays synchronous; async runners are bridged with ``asyncio.run`` per
job, exactly as the CLI does. A poisoned job is recorded as an error and never kills
the loop.

# ponytail: single worker, FIFO; SKIP LOCKED already makes N workers safe if ever needed.
# ponytail: no automatic retries — a failed scan is stored as status='error';
#           resubmit is a new POST /scan.
# ponytail: crash recovery = reclaim stale 'running' rows at startup; no per-job lease renewal.
# ponytail: worker is a separate process, not a FastAPI background task, so app startup
#           and the DB-free test suite stay untouched.
"""

import asyncio
import logging
import time
from typing import Any

from sqlalchemy.orm import Session

from palisade import queue
from palisade.agents.graph import run_graph_content
from palisade.config import get_settings
from palisade.db.base import SessionLocal
from palisade.observability.tracing import get_tracer
from palisade.scanner import scan_content

logger = logging.getLogger(__name__)


def _run_job(job: queue.ClaimedJob) -> dict[str, Any]:
    runner = run_graph_content if job.engine == "graph" else scan_content
    report = asyncio.run(runner(job.filename, job.content))
    report.scan_id = job.id  # the row id is the canonical job id clients poll on
    return report.model_dump(mode="json")


def process_once(session: Session) -> bool:
    """Claim and run one job. Returns True if a job was handled, False if empty."""
    job = queue.claim_one(session)
    if job is None:
        return False
    try:
        queue.finish(session, job.id, _run_job(job))
    except Exception as exc:  # noqa: BLE001 — one bad job must not kill the worker
        # Full traceback goes to the server log; the client only sees the exception
        # class, never str(exc), which could carry paths/URLs/credentials.
        logger.exception("scan %s failed", job.id)
        queue.fail(session, job.id, f"scan failed: {type(exc).__name__}")
    return True


def main() -> None:
    logging.basicConfig(level=logging.INFO)
    settings = get_settings()
    with SessionLocal() as session:
        reclaimed = queue.reclaim_stale(session, settings.worker_stale_seconds)
    if reclaimed:
        logger.info("reclaimed %d stale running scan(s)", reclaimed)
    logger.info("worker started; polling every %ss", settings.worker_poll_interval)
    try:
        while True:
            with SessionLocal() as session:
                worked = process_once(session)
            if not worked:
                time.sleep(settings.worker_poll_interval)
    finally:
        # Close the process-wide cached tracer on exit (flush buffered traces, stop its export
        # threads). Only if a scan actually built it — currsize stays 0 if get_tracer() was
        # never called, so shutting down before the first scan doesn't construct a client just
        # to destroy it. None here means Langfuse is off.
        if get_tracer.cache_info().currsize:
            tracer = get_tracer()
            if tracer is not None:
                tracer.close()


if __name__ == "__main__":
    main()
