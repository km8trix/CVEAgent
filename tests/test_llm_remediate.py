"""LLM Remediate node (M2): the LLM drafts cited remediation prose, the Verifier guards it.

No live API — a fake Drafter stands in. Covers: a well-behaved draft passes; a fabricated
citation is dropped by the Verifier; an LLM error degrades cleanly to deterministic remediation;
plus model routing and the no-key fallback.
"""

import asyncio
from datetime import datetime
from typing import Any

from pydantic import SecretStr

from palisade.agents.graph import run_graph_content
from palisade.agents.llm import RemediationDraft, llm_remediation, make_drafter, route
from palisade.config import Settings
from palisade.models.advisory import (
    AdvisoryRecord,
    AffectedPackage,
    Event,
    Range,
    Severity,
)
from palisade.models.dependency import Dependency
from palisade.models.finding import Finding

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


class _FakeDrafter:
    def __init__(self, citations: list[str]) -> None:
        self._citations = citations
        self.seen_upgrade: str | None = None
        self.cost_usd = 0.0

    async def draft(
        self, finding: Finding, adv: AdvisoryRecord, upgrade_to: str | None
    ) -> RemediationDraft:
        self.seen_upgrade = upgrade_to
        return RemediationDraft(
            summary=f"Upgrade to {upgrade_to} promptly.",  # names the version -> grounded
            steps=[f"Bump jinja2 to {upgrade_to}"],
            draft_pr_text="PR body",
            citations=self._citations,
        )


class _RaisingDrafter:
    cost_usd = 0.0

    async def draft(
        self, finding: Finding, adv: AdvisoryRecord, upgrade_to: str | None
    ) -> RemediationDraft:
        raise RuntimeError("api unavailable")


class _UngroundedDrafter:
    """Returns prose that never names the fix version (the hallucination the guard catches)."""

    cost_usd = 0.0

    async def draft(
        self, finding: Finding, adv: AdvisoryRecord, upgrade_to: str | None
    ) -> RemediationDraft:
        return RemediationDraft(
            summary="No action needed.", steps=[], draft_pr_text="", citations=[]
        )


def _advisory() -> AdvisoryRecord:
    return AdvisoryRecord(
        id="osv:1",
        source="osv",
        source_id="GHSA-x",
        aliases=["CVE-2024-22195"],
        summary="XSS in jinja2",
        details="details",
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


def _finding() -> Finding:
    adv = _advisory()
    return Finding(
        dependency=Dependency(
            ecosystem="PyPI", name="jinja2", version="3.1.2", direct=True, source_file="req"
        ),
        advisory_id=adv.id,
        aliases=["CVE-2024-22195", "GHSA-x"],
        matched_range=adv.affected[0].ranges[0],
        installed_version="3.1.2",
        fixed_versions=["3.1.3"],
        is_affected=True,
        citations=list(adv.references),
    )


# --- llm_remediation unit ---


def test_llm_remediation_keeps_deterministic_version_target() -> None:
    drafter = _FakeDrafter(["https://example.test/adv"])
    rem = asyncio.run(llm_remediation(_finding(), _advisory(), drafter))
    assert rem.type == "upgrade"
    assert rem.upgrade_to == "3.1.3"  # deterministic — LLM never chooses the version
    assert drafter.seen_upgrade == "3.1.3"  # and it was handed that target
    assert rem.summary == "Upgrade to 3.1.3 promptly."  # LLM prose
    assert rem.draft_pr_text == "PR body"
    assert rem.citations == ["https://example.test/adv"]


def test_llm_remediation_discards_ungrounded_draft() -> None:
    # A draft that never names the fix version is not trusted -> deterministic remediation.
    rem = asyncio.run(llm_remediation(_finding(), _advisory(), _UngroundedDrafter()))
    assert rem.summary.startswith("Upgrade jinja2")  # deterministic, not "No action needed."
    assert rem.upgrade_to == "3.1.3"


# --- graph end-to-end with a drafter ---


def test_graph_uses_llm_draft_when_cited_correctly() -> None:
    report = asyncio.run(
        run_graph_content(
            "requirements.txt",
            "jinja2==3.1.2\n",
            osv=_FakeOsv([_JINJA2_OSV]),
            epss={},
            kev={},
            drafter=_FakeDrafter(["https://example.test/adv"]),
        )
    )
    assert [f.dependency.name for f in report.findings] == ["jinja2"]
    assert report.stats["dropped_by_verifier"] == 0
    f = report.findings[0]
    assert f.verdict is not None and f.verdict.passed
    assert f.remediation is not None
    assert f.remediation.summary == "Upgrade to 3.1.3 promptly."  # the LLM draft was used
    assert f.remediation.upgrade_to == "3.1.3"


def test_verifier_drops_llm_fabricated_citation() -> None:
    report = asyncio.run(
        run_graph_content(
            "requirements.txt",
            "jinja2==3.1.2\n",
            osv=_FakeOsv([_JINJA2_OSV]),
            epss={},
            kev={},
            drafter=_FakeDrafter(["https://evil.test/fabricated"]),  # not in advisory refs
        )
    )
    assert report.findings == []
    assert report.stats["dropped_by_verifier"] == 1


def test_graph_falls_back_when_llm_errors() -> None:
    report = asyncio.run(
        run_graph_content(
            "requirements.txt",
            "jinja2==3.1.2\n",
            osv=_FakeOsv([_JINJA2_OSV]),
            epss={},
            kev={},
            drafter=_RaisingDrafter(),
        )
    )
    assert [f.dependency.name for f in report.findings] == ["jinja2"]  # not dropped
    assert report.stats["dropped_by_verifier"] == 0
    rem = report.findings[0].remediation
    assert rem is not None and rem.summary.startswith("Upgrade jinja2")  # deterministic fallback


# --- routing / no-key fallback ---


def test_route_sends_remediate_to_strong_model() -> None:
    settings = Settings(anthropic_api_key=None)
    assert route(settings, "remediate") == settings.strong_model
    assert route(settings, "impact") == settings.strong_model
    assert route(settings, "triage") == settings.cheap_model


def test_make_drafter_none_without_key_and_built_with_key() -> None:
    assert make_drafter(Settings(anthropic_api_key=None)) is None
    assert make_drafter(Settings(anthropic_api_key=SecretStr("sk-test"))) is not None
