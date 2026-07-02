"""LangGraph agent state. See IMPLEMENTATION_PLAN.md section 4.4.

The plan's ScanState is the contract; the extra runtime channels below (lockfile, ecosystem,
advisories, report) are what the graph threads between nodes. `total=False` keeps every field
optional so each node writes only the channels it owns.
"""

from typing import Any, TypedDict

from palisade.models.advisory import AdvisoryRecord
from palisade.models.dependency import DependencyGraph, Lockfile
from palisade.models.finding import Finding, ScanReport


class ScanState(TypedDict, total=False):
    scan_id: str
    target: str
    lockfile: Lockfile  # graph input; ingest parses it
    ecosystem: str
    graph: DependencyGraph
    advisories: dict[str, AdvisoryRecord]  # id -> record; the Verifier's evidence
    candidates: list[Finding]  # from Triage (deterministic OSV match)
    impacted: list[Finding]  # from Impact; also the Verify->Impact retry set
    verified: list[Finding]  # passed the Verifier (accumulates across retries)
    rejected: list[Finding]  # dropped, with reason
    retry_counts: dict[str, int]  # per-finding, bounds the Verify->Impact loop
    trace: list[dict[str, Any]]  # step log (Langfuse export in M3)
    report: ScanReport  # from Report
