"""Attach EPSS + CISA KEV exploit signal to findings and compute a deterministic rank.

Severity is grounded in real exploit signal (KEV > EPSS > CVSS bucket), not CVSS alone.
See IMPLEMENTATION_PLAN.md §1/§4.
"""

from datetime import date

from palisade.models.finding import Finding

_SEVERITY_WEIGHT = {"critical": 4.0, "high": 3.0, "medium": 2.0, "low": 1.0}


def _cves(finding: Finding) -> list[str]:
    # Uppercase so lookups hit the EPSS/KEV dicts, which are keyed by canonical CVE IDs.
    return [a.upper() for a in finding.aliases if a.upper().startswith("CVE-")]


def compute_rank(finding: Finding) -> float:
    # Tiers: KEV (1000) dominates any non-KEV finding; within a tier, EPSS (0-100) then the
    # severity bucket (0-4) then a direct-dep tiebreak (0.5). kev_date_added is deliberately
    # NOT part of the rank — within KEV, higher exploit probability sorts first.
    score = 0.0
    if finding.kev_listed:
        score += 1000.0
    if finding.epss_score is not None:
        score += finding.epss_score * 100.0
    score += _SEVERITY_WEIGHT.get(finding.severity_bucket or "", 0.0)
    if finding.reachability == "direct":
        score += 0.5
    return score


def enrich_findings(
    findings: list[Finding],
    epss: dict[str, tuple[float, float]],
    kev: dict[str, date],
) -> None:
    """Mutate findings in place: set EPSS/KEV fields and rank_score."""
    for finding in findings:
        cves = _cves(finding)
        scored = [epss[c] for c in cves if c in epss]
        if scored:
            finding.epss_score, finding.epss_percentile = max(scored, key=lambda t: t[0])
        kev_dates = [kev[c] for c in cves if c in kev]
        if kev_dates:
            finding.kev_listed = True
            finding.kev_date_added = min(kev_dates)
        finding.rank_score = compute_rank(finding)
