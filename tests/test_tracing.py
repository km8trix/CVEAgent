"""Task 85: LLM cost -> ScanReport.cost_usd, and the optional Langfuse tracer seam.

No live API or keys: a fake Anthropic client, a fake drafter, and fake tracers stand in. Covers
the pricing math, per-scan cost accumulation, make_tracer's no-op-without-keys behavior, and that
run_graph stamps cost_usd and exports a trace without letting a broken tracer break the scan.
The concrete Langfuse SDK call is not exercised here (needs live keys) — see tracing.py.
"""

import asyncio
import sys
import types
from datetime import datetime
from typing import Any

from pydantic import SecretStr

from palisade.agents.graph import run_graph_content
from palisade.agents.llm import AnthropicDrafter, RemediationDraft, _cost_usd
from palisade.config import Settings
from palisade.models.advisory import (
    AdvisoryRecord,
    AffectedPackage,
    Event,
    Range,
    Severity,
)
from palisade.models.dependency import Dependency
from palisade.models.finding import Finding, ScanReport
from palisade.observability import tracing
from palisade.observability.tracing import make_tracer

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
        return [
            [
                {"id": rid}
                for rid, r in self._by_id.items()
                if any(
                    a.get("package", {}).get("name") == q["package"]["name"]
                    for a in r.get("affected", [])
                )
            ]
            for q in queries
        ]

    async def get_vuln(self, vuln_id: str) -> dict[str, Any]:
        return self._by_id[vuln_id]

    async def aclose(self) -> None:
        return None


def _advisory() -> AdvisoryRecord:
    return AdvisoryRecord(
        id="osv:1",
        source="osv",
        source_id="GHSA-x",
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
    return Finding(
        dependency=Dependency(
            ecosystem="PyPI", name="jinja2", version="3.1.2", direct=True, source_file="req"
        ),
        advisory_id="osv:1",
        installed_version="3.1.2",
        fixed_versions=["3.1.3"],
        is_affected=True,
        citations=["https://example.test/adv"],
    )


class _CostingDrafter:
    """Drafts correctly-cited prose and reports a fixed per-scan cost."""

    def __init__(self, cost: float) -> None:
        self.cost_usd = cost

    async def draft(
        self, finding: Finding, adv: AdvisoryRecord, upgrade_to: str | None
    ) -> RemediationDraft:
        return RemediationDraft(
            summary=f"Upgrade to {upgrade_to} promptly.",
            steps=[f"Bump to {upgrade_to}"],
            citations=["https://example.test/adv"],
        )


class _RecordingTracer:
    def __init__(self) -> None:
        self.calls: list[ScanReport] = []

    def record_scan(
        self, report: ScanReport, trace: list[dict[str, Any]], *, prompt_version: str
    ) -> None:
        self.calls.append(report)


class _BoomTracer:
    def record_scan(
        self, report: ScanReport, trace: list[dict[str, Any]], *, prompt_version: str
    ) -> None:
        raise RuntimeError("langfuse down")


# --- pricing math ---


def test_cost_usd_prices_known_models() -> None:
    # opus 4.8 ($5/$25 per 1M): 1000 in + 500 out = 0.005 + 0.0125
    assert abs(_cost_usd("claude-opus-4-8", 1000, 500) - 0.0175) < 1e-9
    # haiku 4.5 ($1/$5 per 1M): 1M in + 1M out = 1.0 + 5.0
    assert _cost_usd("claude-haiku-4-5", 1_000_000, 1_000_000) == 6.0


def test_cost_usd_unknown_model_is_zero() -> None:
    assert _cost_usd("some-future-model", 10_000, 10_000) == 0.0


# --- drafter accumulates cost from message.usage ---


class _FakeUsage:
    def __init__(self, input_tokens: int, output_tokens: int) -> None:
        self.input_tokens = input_tokens
        self.output_tokens = output_tokens


class _FakeParsed:
    def __init__(self) -> None:
        self.parsed_output = RemediationDraft(summary="Upgrade to 3.1.3")
        self.usage = _FakeUsage(1000, 500)


class _FakeMessages:
    async def parse(self, **kwargs: Any) -> _FakeParsed:
        return _FakeParsed()


class _FakeAnthropic:
    def __init__(self) -> None:
        self.messages = _FakeMessages()


def test_anthropic_drafter_accumulates_cost() -> None:
    drafter = AnthropicDrafter(_FakeAnthropic(), "claude-opus-4-8")  # type: ignore[arg-type]
    assert drafter.cost_usd == 0.0
    adv = _advisory()
    asyncio.run(drafter.draft(_finding(), adv, "3.1.3"))
    asyncio.run(drafter.draft(_finding(), adv, "3.1.3"))
    assert abs(drafter.cost_usd - 0.0175 * 2) < 1e-9  # accumulates across calls


class _RefusalParsed:
    def __init__(self) -> None:
        self.parsed_output = None  # refusal / unparseable
        self.usage = _FakeUsage(1000, 500)  # ...but tokens were still billed


class _RefusalMessages:
    async def parse(self, **kwargs: Any) -> _RefusalParsed:
        return _RefusalParsed()


class _RefusalAnthropic:
    def __init__(self) -> None:
        self.messages = _RefusalMessages()


def test_anthropic_drafter_bills_on_refusal() -> None:
    # A refusal raises (caller falls back to deterministic) but the tokens are still billed.
    drafter = AnthropicDrafter(_RefusalAnthropic(), "claude-opus-4-8")  # type: ignore[arg-type]
    try:
        asyncio.run(drafter.draft(_finding(), _advisory(), "3.1.3"))
    except ValueError:
        pass
    else:
        raise AssertionError("expected ValueError on unparseable draft")
    assert abs(drafter.cost_usd - 0.0175) < 1e-9  # cost accounted before the None check/raise


# --- make_tracer: no-op without keys ---


def test_make_tracer_none_without_keys() -> None:
    assert make_tracer(Settings(langfuse_public_key=None, langfuse_secret_key=None)) is None
    # public set but secret missing -> still None (both required)
    assert make_tracer(Settings(langfuse_public_key="pk", langfuse_secret_key=None)) is None


def _with_langfuse_module(module: Any) -> Any:
    """Swap sys.modules['langfuse'] for a test, restoring the original afterward."""
    saved = sys.modules.get("langfuse")

    def restore() -> None:
        if saved is None:
            sys.modules.pop("langfuse", None)
        else:
            sys.modules["langfuse"] = saved

    sys.modules["langfuse"] = module
    return restore


def test_make_tracer_none_when_langfuse_unimportable() -> None:
    # Keys configured but the optional package isn't installed -> disabled, not crashed.
    restore = _with_langfuse_module(None)  # None forces ImportError on `import langfuse`
    try:
        settings = Settings(langfuse_public_key="pk", langfuse_secret_key=SecretStr("sk"))
        assert make_tracer(settings) is None
    finally:
        restore()


def test_make_tracer_none_when_client_construction_fails() -> None:
    # A Langfuse constructor hiccup (realistic across the >=2,<4 pin) must degrade to None,
    # not raise into run_graph — this guards the "tracing never breaks a scan" invariant.
    fake = types.ModuleType("langfuse")

    class _BoomLangfuse:
        def __init__(self, **kwargs: Any) -> None:
            raise RuntimeError("langfuse init boom")

    fake.Langfuse = _BoomLangfuse  # type: ignore[attr-defined]
    restore = _with_langfuse_module(fake)
    try:
        settings = Settings(langfuse_public_key="pk", langfuse_secret_key=SecretStr("sk"))
        assert make_tracer(settings) is None
    finally:
        restore()


# --- get_tracer: cache one client for the worker's lifetime, close it on exit ---


def test_get_tracer_caches_one_client_and_closes(monkeypatch: Any) -> None:
    # The worker calls get_tracer() once per scan in an infinite loop; it must build the Langfuse
    # client ONCE (not leak a new one — with its own export threads — per scan), and close() must
    # shut that single client down cleanly on worker exit.
    constructed: list[Any] = []
    fake = types.ModuleType("langfuse")

    class _FakeLangfuse:
        def __init__(self, **kwargs: Any) -> None:
            self.did_shutdown = False
            constructed.append(self)

        def shutdown(self) -> None:
            self.did_shutdown = True

    fake.Langfuse = _FakeLangfuse  # type: ignore[attr-defined]
    restore_mod = _with_langfuse_module(fake)
    keyed = Settings(langfuse_public_key="pk", langfuse_secret_key=SecretStr("sk"))
    monkeypatch.setattr(tracing, "get_settings", lambda: keyed)
    tracing.get_tracer.cache_clear()
    try:
        first = tracing.get_tracer()
        second = tracing.get_tracer()  # a second "scan" reuses the cached tracer
        assert first is not None and first is second
        assert len(constructed) == 1  # one Langfuse client across scans, not one per call
        first.close()
        assert constructed[0].did_shutdown  # worker exit flushes + stops export threads
    finally:
        tracing.get_tracer.cache_clear()
        restore_mod()


# --- run_graph wiring: cost stamped, trace exported, broken tracer tolerated ---


def _run(**kwargs: Any) -> ScanReport:
    return asyncio.run(
        run_graph_content(
            "requirements.txt",
            "jinja2==3.1.2\n",
            osv=_FakeOsv([_JINJA2_OSV]),
            epss={},
            kev={},
            **kwargs,
        )
    )


def test_run_graph_stamps_cost_from_drafter() -> None:
    report = _run(drafter=_CostingDrafter(0.42), tracer=None)
    assert report.cost_usd == 0.42


def test_run_graph_deterministic_path_has_no_cost() -> None:
    report = _run(drafter=None, tracer=None)
    assert report.cost_usd is None  # no LLM -> untracked, not $0


def test_run_graph_exports_trace() -> None:
    tracer = _RecordingTracer()
    report = _run(drafter=None, tracer=tracer)
    assert len(tracer.calls) == 1 and tracer.calls[0] is report


def test_broken_tracer_never_breaks_scan() -> None:
    report = _run(drafter=None, tracer=_BoomTracer())
    assert [f.dependency.name for f in report.findings] == ["jinja2"]
