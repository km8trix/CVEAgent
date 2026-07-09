"""The M2 agent graph: the deterministic scanner wired as a LangGraph state machine.

    Ingest -> Triage -> Impact -> Remediate -> Verify --pass--> Report
                          ^                       |
                          +---------reject--------+   (bounded by retry_counts < max_retries)

PR #11 wires the *existing* deterministic pipeline as nodes and gives the Verifier real,
independent re-checks (see nodes.py). The Verify->Impact reject loop is a structural no-op while
Impact/Remediate are deterministic — a re-run yields the same result, so a failing finding just
exhausts its retries and is dropped — but it is the rail PR #12's LLM Impact node re-drafts on.
The M1 `scanner.scan()` path stays the default; this graph is opt-in until the LLM nodes land
and evals confirm parity. See IMPLEMENTATION_PLAN.md sections 4.4 and 6.
"""

import asyncio
import logging
import time
from dataclasses import dataclass
from datetime import UTC, datetime
from typing import Any, cast
from uuid import uuid4

from langgraph.graph import END, START, StateGraph

from palisade.agents.llm import PROMPT_VERSION, Drafter, llm_remediation, make_drafter
from palisade.agents.nodes import build_remediation, verify_finding
from palisade.clients.osv import OsvClient
from palisade.config import get_settings
from palisade.enrichment.enrich import enrich_findings
from palisade.matching.matcher import match
from palisade.models.dependency import DependencyGraph, Lockfile
from palisade.models.finding import Finding, ScanReport
from palisade.models.state import ScanState
from palisade.observability.tracing import Tracer, get_tracer
from palisade.parsers.registry import load_lockfile, lockfile_from_content, parse_lockfile

# Reuse the M1 scanner internals so the graph is a thin orchestration, not a second pipeline.
from palisade.scanner import (
    _KIND_TO_ECOSYSTEM,
    OsvSource,
    _cached_feeds,
    _Epss,
    _fetch_advisories,
    _Kev,
)

logger = logging.getLogger(__name__)

# Sentinel: run_graph(drafter=_AUTO) builds a drafter from settings; drafter=None forces the
# deterministic path. ponytail: typed Any to avoid a three-member union on the public signature.
_AUTO: Any = object()


@dataclass
class GraphDeps:
    """Per-run injectables. Nodes close over this so the graph needs no global state."""

    osv: OsvSource
    epss: _Epss
    kev: _Kev
    max_retries: int = 1
    drafter: Drafter | None = None  # None -> deterministic remediation (no LLM)


def build_graph(deps: GraphDeps) -> Any:  # ponytail: CompiledStateGraph generics churn; Any here.
    """Compile the agent graph. Nodes are closures over `deps` (keeps them injection-free)."""

    async def ingest(state: ScanState) -> dict[str, Any]:
        lockfile = state["lockfile"]
        parsed = parse_lockfile(lockfile)
        ecosystem = parsed[0].ecosystem if parsed else _KIND_TO_ECOSYSTEM.get(lockfile.kind, "PyPI")
        graph = DependencyGraph(target=lockfile.path, ecosystem=ecosystem, dependencies=parsed)
        return {
            "graph": graph,
            "ecosystem": ecosystem,
            "retry_counts": {},
            "verified": [],
            "rejected": [],
            "trace": [{"node": "ingest", "dependencies": len(parsed)}],
        }

    async def triage(state: ScanState) -> dict[str, Any]:
        graph = state["graph"]
        advisories = await _fetch_advisories(graph.dependencies, deps.osv)
        candidates = match(graph.dependencies, advisories)
        return {
            "candidates": candidates,
            "impacted": list(candidates),  # first pass: Impact sees every candidate
            "advisories": {a.id: a for a in advisories},
            "trace": state["trace"]
            + [{"node": "triage", "advisories": len(advisories), "candidates": len(candidates)}],
        }

    async def impact(state: ScanState) -> dict[str, Any]:
        # Deterministic v0: EPSS/KEV enrichment (reachability is already set by the matcher).
        # RAG/LLM impact is a later PR. enrich_findings folds reachability into rank_score, and
        # the Verifier re-derives that rank — so the two must agree.
        findings = state.get("impacted", [])
        enrich_findings(findings, deps.epss, deps.kev)
        return {
            "impacted": findings,
            "trace": state["trace"] + [{"node": "impact", "impacted": len(findings)}],
        }

    async def remediate(state: ScanState) -> dict[str, Any]:
        findings = state.get("impacted", [])
        advisories = state.get("advisories", {})

        async def _remediate_one(f: Finding) -> None:
            adv = advisories.get(f.advisory_id)
            if deps.drafter is None or adv is None:
                f.remediation = build_remediation(f)
                return
            try:
                f.remediation = await llm_remediation(f, adv, deps.drafter)
            except Exception as exc:  # never let an LLM hiccup break the scan — degrade cleanly
                logger.warning(
                    "LLM remediation failed for %s; using deterministic: %s", f.advisory_id, exc
                )
                f.remediation = build_remediation(f)

        await asyncio.gather(*(_remediate_one(f) for f in findings))
        return {
            "impacted": findings,
            "trace": state["trace"] + [{"node": "remediate", "remediated": len(findings)}],
        }

    async def verify(state: ScanState) -> dict[str, Any]:
        advisories = state.get("advisories", {})
        retry = dict(state.get("retry_counts", {}))
        verified = list(state.get("verified", []))  # accumulate across retry passes
        rejected = list(state.get("rejected", []))
        to_retry: list[Finding] = []
        for f in state.get("impacted", []):
            key = f"{f.dependency.key}|{f.advisory_id}"
            verdict = verify_finding(f, advisories.get(f.advisory_id))
            verdict.loop_count = retry.get(key, 0)
            f.verdict = verdict
            if verdict.passed:
                verified.append(f)
            elif retry.get(key, 0) < deps.max_retries:
                retry[key] = retry.get(key, 0) + 1
                to_retry.append(f)  # bounce back to Impact for a re-draft
            else:
                rejected.append(f)  # exhausted retries: drop, never ship unverified
        return {
            "verified": verified,
            "rejected": rejected,
            "retry_counts": retry,
            "impacted": to_retry,
            "trace": state["trace"]
            + [{"node": "verify", "retry": len(to_retry), "rejected": len(rejected)}],
        }

    def route_after_verify(state: ScanState) -> str:
        return "impact" if state.get("impacted") else "report"

    async def report(state: ScanState) -> dict[str, Any]:
        graph = state["graph"]
        verified = sorted(state.get("verified", []), key=lambda f: f.rank_score, reverse=True)
        rejected = state.get("rejected", [])
        stats: dict[str, Any] = {
            "total_dependencies": len(graph.dependencies),
            "candidates": len(state.get("candidates", [])),
            "findings": len(verified),
            "dropped_by_verifier": len(rejected),
            "kev_findings": sum(1 for f in verified if f.kev_listed),
            "affected_packages": len({f.dependency.name for f in verified}),
        }
        rep = ScanReport(
            scan_id=state["scan_id"],
            target=state["target"],
            created_at=datetime.now(UTC),
            ecosystem=state.get("ecosystem", graph.ecosystem),
            findings=verified,
            stats=stats,
        )
        return {
            "report": rep,
            "trace": state["trace"] + [{"node": "report", "findings": len(verified)}],
        }

    g = StateGraph(ScanState)
    g.add_node("ingest", ingest)
    g.add_node("triage", triage)
    g.add_node("impact", impact)
    g.add_node("remediate", remediate)
    g.add_node("verify", verify)
    g.add_node("report", report)
    g.add_edge(START, "ingest")
    g.add_edge("ingest", "triage")
    g.add_edge("triage", "impact")
    g.add_edge("impact", "remediate")
    g.add_edge("remediate", "verify")
    g.add_conditional_edges("verify", route_after_verify, {"impact": "impact", "report": "report"})
    g.add_edge("report", END)
    return g.compile()


async def run_graph(
    lockfile: Lockfile,
    *,
    osv: OsvSource | None = None,
    epss: _Epss | None = None,
    kev: _Kev | None = None,
    max_retries: int = 1,
    drafter: Any = _AUTO,
    tracer: Any = _AUTO,
) -> ScanReport:
    """Run the agent graph over a lockfile. Dependency injection mirrors `scanner.scan()`.

    `drafter` defaults to a drafter built from settings (LLM remediation when an API key is
    configured, deterministic otherwise). Pass `drafter=None` to force the deterministic path,
    or a Drafter to inject one (tests). `tracer` defaults to a Langfuse tracer built from
    settings (no-op without keys); pass `tracer=None` to disable, or inject one (tests).
    """
    start = time.monotonic()
    resolved: Drafter | None = make_drafter(get_settings()) if drafter is _AUTO else drafter
    resolved_tracer: Tracer | None = get_tracer() if tracer is _AUTO else tracer
    owns = osv is None
    osv = osv or OsvClient()
    try:
        if epss is None or kev is None:
            cached_epss, cached_kev = await _cached_feeds()
            epss = epss if epss is not None else cached_epss
            kev = kev if kev is not None else cached_kev
        graph = build_graph(
            GraphDeps(osv=osv, epss=epss, kev=kev, max_retries=max_retries, drafter=resolved)
        )
        initial: ScanState = {
            "scan_id": str(uuid4()),
            "target": lockfile.path,
            "lockfile": lockfile,
        }
        final = await graph.ainvoke(initial)
        report = cast(ScanReport, final["report"])
        report.latency_ms = int((time.monotonic() - start) * 1000)
        # Only the LLM path costs money; the deterministic path leaves cost_usd None (not $0).
        report.cost_usd = resolved.cost_usd if resolved is not None else None
        if resolved_tracer is not None:
            try:
                resolved_tracer.record_scan(
                    report, final.get("trace", []), prompt_version=PROMPT_VERSION
                )
            except Exception as exc:  # tracing must never break a scan
                logger.warning("scan tracing failed: %s", exc)
        return report
    finally:
        if owns:
            await osv.aclose()


async def run_graph_content(filename: str, content: str, **kwargs: Any) -> ScanReport:
    return await run_graph(lockfile_from_content(filename, content), **kwargs)


async def run_graph_path(path: str, **kwargs: Any) -> ScanReport:
    return await run_graph(load_lockfile(path), **kwargs)
