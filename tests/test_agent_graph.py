"""Agent graph (M2) tests: end-to-end parity with the M1 scanner, the Verifier's independent
re-checks, the deterministic Remediation builder, and the bounded Verify->Impact reject loop."""

import asyncio
from datetime import datetime
from typing import Any

import pytest

from palisade.agents.graph import run_graph_content
from palisade.agents.nodes import build_remediation, verify_finding
from palisade.enrichment.enrich import enrich_findings
from palisade.models.advisory import (
    AdvisoryRecord,
    AffectedPackage,
    Event,
    Range,
    Severity,
)
from palisade.models.dependency import Dependency
from palisade.models.finding import Finding, Remediation

_JINJA2_OSV: dict[str, Any] = {
    "id": "GHSA-x",
    "aliases": ["CVE-2024-22195"],
    "modified": "2024-01-01T00:00:00Z",
    "references": [{"url": "https://example.test/adv"}],
    "affected": [
        {
            "package": {"ecosystem": "PyPI", "name": "jinja2"},
            "ranges": [{"type": "ECOSYSTEM", "events": [{"introduced": "0"}, {"fixed": "3.1.3"}]}],
        }
    ],
    "severity": [{"type": "CVSS_V3", "score": "CVSS:3.1/AV:N/AC:L/PR:N/UI:R/S:C/C:L/I:L/A:N"}],
}


class _FakeOsv:
    """Duck-typed OsvSource returning records whose affected package matches the query name."""

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


def _finding(**over: Any) -> Finding:
    adv = _advisory()
    f = Finding(
        dependency=Dependency(
            ecosystem="PyPI", name="jinja2", version="3.1.2", direct=True, source_file="req"
        ),
        advisory_id=adv.id,
        aliases=["CVE-2024-22195", "GHSA-x"],
        matched_range=adv.affected[0].ranges[0],
        installed_version="3.1.2",
        fixed_versions=["3.1.3"],
        is_affected=True,
        reachability="direct",
        severity_bucket="high",
        citations=list(adv.references),
    )
    enrich_findings([f], {}, {})  # set a consistent rank_score
    for k, v in over.items():
        setattr(f, k, v)
    return f


# --- end-to-end graph ---


def test_graph_end_to_end_matches_and_verifies() -> None:
    report = asyncio.run(
        run_graph_content(
            "requirements.txt",
            "jinja2==3.1.2\nflask==3.0.0\n",
            osv=_FakeOsv([_JINJA2_OSV]),
            epss={"CVE-2024-22195": (0.5, 0.9)},
            kev={},
        )
    )
    assert report.ecosystem == "PyPI"
    assert [f.dependency.name for f in report.findings] == ["jinja2"]
    assert report.stats["candidates"] == 1
    assert report.stats["dropped_by_verifier"] == 0
    assert report.latency_ms is not None and report.latency_ms >= 0  # telemetry stamped

    f = report.findings[0]
    assert f.verdict is not None and f.verdict.passed
    assert f.verdict.version_in_range
    assert f.verdict.all_claims_cited
    assert f.verdict.severity_consistent
    assert f.remediation is not None and f.remediation.type == "upgrade"
    assert f.remediation.upgrade_to == "3.1.3"
    assert f.remediation.citations == ["https://example.test/adv"]  # cited to the advisory
    assert f.epss_score == 0.5


# --- Verifier ---


def test_verify_passes_clean_finding() -> None:
    f = _finding()
    f.remediation = build_remediation(f)
    verdict = verify_finding(f, _advisory())
    assert verdict.passed


def test_verify_rejects_fabricated_citation() -> None:
    f = _finding()
    f.remediation = Remediation(
        type="upgrade", summary="x", citations=["https://evil.test/made-up"]
    )
    verdict = verify_finding(f, _advisory())
    assert not verdict.passed
    assert not verdict.all_claims_cited
    assert verdict.rejected_reason is not None


def test_verify_rejects_when_no_evidence() -> None:
    verdict = verify_finding(_finding(), None)
    assert not verdict.passed
    assert not verdict.version_in_range


def test_verify_rejects_out_of_range_installed_version() -> None:
    # Installed a patched version, but the finding still claims affected -> Verifier catches it.
    f = _finding(
        installed_version="3.1.5",
        dependency=Dependency(
            ecosystem="PyPI", name="jinja2", version="3.1.5", direct=True, source_file="req"
        ),
    )
    verdict = verify_finding(f, _advisory())
    assert not verdict.passed
    assert not verdict.version_in_range


def test_verify_rejects_tampered_rank() -> None:
    f = _finding(rank_score=999.0)  # not what compute_rank would produce
    f.remediation = build_remediation(f)
    verdict = verify_finding(f, _advisory())
    assert not verdict.passed
    assert not verdict.severity_consistent


# --- Remediation builder ---


def test_build_remediation_upgrade_target_from_range() -> None:
    rem = build_remediation(_finding())
    assert rem.type == "upgrade"
    assert rem.upgrade_to == "3.1.3"
    assert rem.citations == ["https://example.test/adv"]


def test_build_remediation_mitigate_when_no_fix() -> None:
    f = _finding(matched_range=None, fixed_versions=[])
    rem = build_remediation(f)
    assert rem.type == "mitigate"
    assert rem.upgrade_to is None


def test_build_remediation_fallback_picks_minimal_fix_by_version_order() -> None:
    # matched_range names no fix above installed -> fall back to fixed_versions, version-ordered.
    # Must pick 9.0.1, never lexical 10.0.1.
    f = _finding(
        matched_range=None,
        installed_version="8.0.0",
        dependency=Dependency(
            ecosystem="PyPI", name="x", version="8.0.0", direct=True, source_file="req"
        ),
        fixed_versions=["10.0.1", "9.0.1"],
    )
    rem = build_remediation(f)
    assert rem.type == "upgrade"
    assert rem.upgrade_to == "9.0.1"


def test_build_remediation_no_fix_above_installed_becomes_mitigate() -> None:
    # A fix only *below* the installed version must not be advised as an "upgrade" (a downgrade
    # into a still-vulnerable version) -> mitigate instead.
    f = _finding(
        matched_range=None,
        installed_version="3.5.0",
        dependency=Dependency(
            ecosystem="PyPI", name="x", version="3.5.0", direct=True, source_file="req"
        ),
        fixed_versions=["2.0.0"],
    )
    rem = build_remediation(f)
    assert rem.type == "mitigate"
    assert rem.upgrade_to is None


def test_verify_passes_multi_affected_package_advisory() -> None:
    # Advisory lists the package twice; only the SECOND range contains the installed version.
    # The Verifier must check every same-named entry (mirrors the matcher), not just the first.
    adv = AdvisoryRecord(
        id="osv:multi",
        source="osv",
        source_id="GHSA-multi",
        summary="",
        details="",
        severity=Severity(bucket="high"),
        affected=[
            AffectedPackage(
                ecosystem="PyPI",
                name="werkzeug",
                ranges=[
                    Range(
                        type="ECOSYSTEM", events=[Event(introduced="1.0.0"), Event(fixed="1.9.9")]
                    )
                ],
            ),
            AffectedPackage(
                ecosystem="PyPI",
                name="werkzeug",
                ranges=[
                    Range(
                        type="ECOSYSTEM", events=[Event(introduced="2.0.0"), Event(fixed="2.0.3")]
                    )
                ],
            ),
        ],
        references=["https://example.test/adv"],
        published=datetime(2024, 1, 1),
        modified=datetime(2024, 1, 1),
        content_hash="h",
    )
    f = Finding(
        dependency=Dependency(
            ecosystem="PyPI", name="werkzeug", version="2.0.0", direct=True, source_file="req"
        ),
        advisory_id="osv:multi",
        matched_range=adv.affected[1].ranges[0],
        installed_version="2.0.0",
        fixed_versions=["2.0.3"],
        is_affected=True,
        citations=["https://example.test/adv"],
    )
    enrich_findings([f], {}, {})
    f.remediation = build_remediation(f)
    verdict = verify_finding(f, adv)
    assert verdict.passed
    assert verdict.version_in_range


# --- reject loop ---


def test_reject_loop_drops_unverifiable_finding(monkeypatch: pytest.MonkeyPatch) -> None:
    # Force Remediate to fabricate a citation; the Verifier must drop the finding after a
    # bounded retry (Impact re-runs once, still fails), leaving 0 findings and dropped=1.
    def _bad_remediation(finding: Finding) -> Remediation:
        return Remediation(type="upgrade", summary="x", citations=["https://evil.test/fabricated"])

    monkeypatch.setattr("palisade.agents.graph.build_remediation", _bad_remediation)
    report = asyncio.run(
        run_graph_content(
            "requirements.txt",
            "jinja2==3.1.2\n",
            osv=_FakeOsv([_JINJA2_OSV]),
            epss={},
            kev={},
            max_retries=1,
        )
    )
    assert report.stats["candidates"] == 1
    assert report.findings == []
    assert report.stats["dropped_by_verifier"] == 1
