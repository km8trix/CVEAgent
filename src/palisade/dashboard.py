"""Read-side helpers for the Streamlit dashboard (M3).

Pure/DB-only — no Streamlit import here, so the aggregation logic stays importable and
unit-testable; `dashboard/app.py` is the thin UI glue on top. Each done scan's ``result``
is the full ScanReport blob (see db.tables.Scan), so counts and latency come straight from it.
"""

from __future__ import annotations

from math import ceil
from typing import Any

from sqlalchemy import select
from sqlalchemy.orm import Session

from palisade.db.tables import Scan
from palisade.models.finding import ScanReport


def recent_scans(session: Session, limit: int = 50) -> list[Scan]:
    return list(session.scalars(select(Scan).order_by(Scan.created_at.desc()).limit(limit)))


def _report(scan: Scan) -> ScanReport | None:
    return ScanReport.model_validate(scan.result) if scan.result is not None else None


def p95(values: list[int]) -> int | None:
    """95th-percentile latency by nearest-rank. None if there's nothing to rank."""
    if not values:
        return None
    ordered = sorted(values)
    k = min(len(ordered) - 1, ceil(0.95 * len(ordered)) - 1)
    return ordered[max(0, k)]


def scan_row(scan: Scan) -> dict[str, Any]:
    """One display row for the recent-scans table."""
    report = _report(scan)
    return {
        "id": scan.id[:8],
        "target": scan.filename,
        "engine": scan.engine,
        "status": scan.status,
        "findings": len(report.findings) if report else 0,
        "kev": sum(1 for f in report.findings if f.kev_listed) if report else 0,
        "latency_ms": report.latency_ms if report else None,
        "created_at": scan.created_at,
    }


def overview(scans: list[Scan]) -> dict[str, Any]:
    """Aggregate metric cards over a batch of scans."""
    reports = [(_report(s), s.status) for s in scans]
    latencies = [r.latency_ms for r, _ in reports if r and r.latency_ms is not None]
    return {
        "scans": len(scans),
        "done": sum(1 for _, st in reports if st == "done"),
        "errored": sum(1 for _, st in reports if st == "error"),
        "findings": sum(len(r.findings) for r, _ in reports if r),
        "kev": sum(1 for r, _ in reports if r for f in r.findings if f.kev_listed),
        "p95_latency_ms": p95(latencies),
    }
