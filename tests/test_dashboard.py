from datetime import UTC, datetime
from typing import Any

from palisade.dashboard import overview, p95, scan_row
from palisade.db.tables import Scan
from palisade.models.dependency import Dependency
from palisade.models.finding import Finding, ScanReport


def _finding(*, kev: bool = False) -> Finding:
    return Finding(
        dependency=Dependency(
            ecosystem="PyPI", name="flask", version="1", direct=True, source_file="r"
        ),
        advisory_id="osv:GHSA-x",
        installed_version="1",
        is_affected=True,
        kev_listed=kev,
        rank_score=1.0,
    )


def _report(findings: list[Finding], latency: int = 100) -> dict[str, Any]:
    report = ScanReport(
        scan_id="s",
        target="requirements.txt",
        created_at=datetime.now(UTC),
        ecosystem="PyPI",
        findings=findings,
        latency_ms=latency,
    )
    return report.model_dump(mode="json")  # JSONB-shaped, as the worker stores it


def _scan(status: str, result: dict[str, Any] | None) -> Scan:
    return Scan(
        id="abcdef123456",
        status=status,
        engine="scan",
        filename="requirements.txt",
        content="",
        result=result,
        created_at=datetime.now(UTC),
    )


def test_p95_nearest_rank() -> None:
    assert p95([]) is None
    assert p95([5]) == 5
    assert p95(list(range(1, 21))) == 19
    assert p95([100, 300]) == 300


def test_scan_row_counts_findings_and_kev() -> None:
    row = scan_row(_scan("done", _report([_finding(kev=True), _finding()])))
    assert row["findings"] == 2
    assert row["kev"] == 1
    assert row["latency_ms"] == 100
    assert row["status"] == "done"
    assert row["id"] == "abcdef12"  # truncated for display


def test_scan_row_pending_has_no_report() -> None:
    row = scan_row(_scan("pending", None))
    assert row["findings"] == 0
    assert row["kev"] == 0
    assert row["latency_ms"] is None


def test_overview_aggregates() -> None:
    scans = [
        _scan("done", _report([_finding(kev=True)], latency=100)),
        _scan("done", _report([_finding(), _finding()], latency=300)),
        _scan("error", None),
        _scan("pending", None),
    ]
    o = overview(scans)
    assert o["scans"] == 4
    assert o["done"] == 2
    assert o["errored"] == 1
    assert o["findings"] == 3
    assert o["kev"] == 1
    assert o["p95_latency_ms"] == 300
