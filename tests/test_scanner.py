import asyncio
from datetime import datetime
from typing import Any

from palisade.models.advisory import (
    AdvisoryRecord,
    AffectedPackage,
    Event,
    Range,
    Severity,
)
from palisade.models.dependency import Dependency
from palisade.scanner import build_report, scan_content


def _advisory() -> AdvisoryRecord:
    return AdvisoryRecord(
        id="osv:1",
        source="osv",
        source_id="GHSA-x",
        aliases=["CVE-2024-22195"],
        summary="",
        details="",
        severity=Severity(bucket="high"),
        affected=[
            AffectedPackage(
                ecosystem="PyPI",
                name="jinja2",
                ranges=[
                    Range(type="ECOSYSTEM", events=[Event(introduced="0"), Event(fixed="3.1.3")])
                ],
            )
        ],
        references=["https://example.test/adv"],
        published=datetime(2024, 1, 1),
        modified=datetime(2024, 1, 1),
        content_hash="h",
    )


def test_build_report_matches_ranks_and_cites() -> None:
    deps = [
        Dependency(
            ecosystem="PyPI", name="jinja2", version="3.1.2", direct=True, source_file="req"
        ),
        Dependency(ecosystem="PyPI", name="flask", version="3.0.0", direct=True, source_file="req"),
    ]
    report = build_report("req", "PyPI", deps, [_advisory()], {"CVE-2024-22195": (0.5, 0.9)}, {})
    assert report.stats["total_dependencies"] == 2
    assert len(report.findings) == 1  # only the vulnerable jinja2
    f = report.findings[0]
    assert f.dependency.name == "jinja2"
    assert f.epss_score == 0.5
    assert f.citations  # cited
    assert f.rank_score > 0


class _FakeOsv:
    """Duck-typed OsvSource: returns records whose affected package matches the query name."""

    def __init__(self, records: list[dict[str, Any]]) -> None:
        self._by_id = {r["id"]: r for r in records}

    async def query_batch(self, queries: list[dict[str, Any]]) -> list[list[dict[str, Any]]]:
        out = []
        for q in queries:
            name = q["package"]["name"]
            out.append(
                [
                    {"id": rid}
                    for rid, r in self._by_id.items()
                    if any(a.get("package", {}).get("name") == name for a in r.get("affected", []))
                ]
            )
        return out

    async def get_vuln(self, vuln_id: str) -> dict[str, Any]:
        return self._by_id[vuln_id]

    async def aclose(self) -> None:
        return None


def test_scan_content_end_to_end() -> None:
    osv_record: dict[str, Any] = {
        "id": "GHSA-x",
        "aliases": ["CVE-2024-22195"],
        "modified": "2024-01-01T00:00:00Z",
        "affected": [
            {
                "package": {"ecosystem": "PyPI", "name": "jinja2"},
                "ranges": [
                    {"type": "ECOSYSTEM", "events": [{"introduced": "0"}, {"fixed": "3.1.3"}]}
                ],
            }
        ],
        "severity": [{"type": "CVSS_V3", "score": "CVSS:3.1/AV:N/AC:L/PR:N/UI:R/S:C/C:L/I:L/A:N"}],
    }
    report = asyncio.run(
        scan_content(
            "requirements.txt",
            "jinja2==3.1.2\nflask==3.0.0\n",
            osv=_FakeOsv([osv_record]),
            epss={"CVE-2024-22195": (0.5, 0.9)},
            kev={},
        )
    )
    assert report.ecosystem == "PyPI"
    assert report.stats["total_dependencies"] == 2
    assert [f.dependency.name for f in report.findings] == ["jinja2"]
    assert report.findings[0].epss_score == 0.5
    assert report.latency_ms is not None and report.latency_ms >= 0  # telemetry stamped


def test_scan_empty_npm_lockfile_infers_ecosystem() -> None:
    report = asyncio.run(
        scan_content(
            "package-lock.json",
            '{"lockfileVersion": 3, "packages": {}}',
            osv=_FakeOsv([]),
            epss={},
            kev={},
        )
    )
    assert report.ecosystem == "npm"  # inferred from kind, not from deps[0]
    assert report.stats["total_dependencies"] == 0


def test_scan_endpoint_rejects_oversized_content() -> None:
    from fastapi.testclient import TestClient

    from palisade.main import app

    client = TestClient(app)
    resp = client.post("/scan", json={"filename": "requirements.txt", "content": "x" * 500_001})
    assert resp.status_code == 422
