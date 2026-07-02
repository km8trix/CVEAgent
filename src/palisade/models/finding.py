"""Finding and report models. See IMPLEMENTATION_PLAN.md section 4.3."""

from datetime import date, datetime
from typing import Any, Literal

from pydantic import BaseModel, Field

from palisade.models.advisory import Range
from palisade.models.dependency import Dependency


class Remediation(BaseModel):
    type: Literal["upgrade", "patch", "config", "mitigate"]
    summary: str
    upgrade_to: str | None = None
    steps: list[str] = Field(default_factory=list)
    draft_pr_text: str | None = None
    citations: list[str] = Field(default_factory=list)


class VerifierVerdict(BaseModel):
    passed: bool
    version_in_range: bool
    all_claims_cited: bool
    severity_consistent: bool
    rejected_reason: str | None = None
    loop_count: int = 0


class Finding(BaseModel):
    dependency: Dependency
    advisory_id: str
    aliases: list[str] = Field(default_factory=list)
    matched_range: Range | None = None
    installed_version: str
    fixed_versions: list[str] = Field(default_factory=list)
    is_affected: bool
    reachability: Literal["direct", "transitive", "unknown"] = "unknown"
    epss_score: float | None = None
    epss_percentile: float | None = None
    kev_listed: bool = False
    kev_date_added: date | None = None
    severity_bucket: str | None = None
    remediation: Remediation | None = None
    citations: list[str] = Field(default_factory=list)
    verdict: VerifierVerdict | None = None
    rank_score: float = 0.0


class ScanReport(BaseModel):
    scan_id: str
    target: str
    created_at: datetime
    ecosystem: str
    findings: list[Finding] = Field(default_factory=list)
    stats: dict[str, Any] = Field(default_factory=dict)
    cost_usd: float | None = None
    latency_ms: int | None = None
