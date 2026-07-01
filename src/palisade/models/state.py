"""LangGraph agent state. See IMPLEMENTATION_PLAN.md section 4.4."""

from typing import Any, TypedDict

from palisade.models.dependency import DependencyGraph
from palisade.models.finding import Finding


class ScanState(TypedDict, total=False):
    scan_id: str
    target: str
    graph: DependencyGraph
    candidates: list[Finding]
    impacted: list[Finding]
    verified: list[Finding]
    rejected: list[Finding]
    retry_counts: dict[str, int]
    trace: list[dict[str, Any]]
    errors: list[str]
