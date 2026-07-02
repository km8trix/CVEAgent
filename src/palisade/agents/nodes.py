"""Pure node logic: the Remediation builder and the Verifier's independent re-checks.

These are the deterministic heart of the agent graph and are unit-tested directly. The graph
wiring in `graph.py` only threads state between them. The Verifier never trusts an upstream
node: it re-derives affectedness from the raw advisory (`is_version_affected`), confirms every
citation traces to the advisory's own references (no fabricated sources), and re-computes the
rank. See IMPLEMENTATION_PLAN.md sections 4.3 and 6.
"""

from math import isclose

from palisade.enrichment.enrich import compute_rank
from palisade.matching.matcher import name_key
from palisade.matching.version import is_version_affected, smallest_above, smallest_fixed_above
from palisade.models.advisory import AdvisoryRecord, AffectedPackage
from palisade.models.dependency import Dependency
from palisade.models.finding import Finding, Remediation, VerifierVerdict


def _pkgs_for(dep: Dependency, adv: AdvisoryRecord) -> list[AffectedPackage]:
    # Key packages exactly as the matcher does (shared name_key) — the Verifier must not drift.
    # An advisory may list the same package more than once (distinct ranges); return them all.
    want = name_key(dep.ecosystem, dep.name)
    return [p for p in adv.affected if name_key(p.ecosystem, p.name) == want]


def build_remediation(finding: Finding) -> Remediation:
    """Deterministic upgrade path from the advisory's fix boundary, cited to the advisory.

    Prefers the fix that closes the range the installed version fell in; falls back to the
    finding's enumerated fixed versions. Every claim is tagged with the advisory's references.
    """
    eco, installed = finding.dependency.ecosystem, finding.installed_version
    upgrade_to: str | None = None
    if finding.matched_range is not None:
        upgrade_to = smallest_fixed_above(eco, installed, finding.matched_range)
    if upgrade_to is None and finding.fixed_versions:
        # Fall back to the enumerated fixes — but only one strictly above the installed version,
        # version-ordered. A lexical fixed_versions[0] could recommend a non-minimal fix or even
        # a downgrade below the installed (still-vulnerable) version. None here -> mitigate below.
        upgrade_to = smallest_above(eco, installed, finding.fixed_versions)

    name = finding.dependency.name
    citations = list(finding.citations)
    if upgrade_to is not None:
        return Remediation(
            type="upgrade",
            summary=f"Upgrade {name} to {upgrade_to} or later.",
            upgrade_to=upgrade_to,
            steps=[
                f"Bump {name} from {finding.installed_version} to {upgrade_to} and re-lock.",
            ],
            citations=citations,
        )
    return Remediation(
        type="mitigate",
        summary=f"No fixed version is published for {name}; apply the advisory's mitigation.",
        citations=citations,
    )


def _version_in_range(finding: Finding, adv: AdvisoryRecord | None) -> bool:
    # Re-derive affectedness from the raw advisory — independent of the matcher's earlier verdict.
    # Affected if ANY same-named affected package's range contains the version (mirrors the
    # matcher); checking only the first would falsely reject multi-entry advisories.
    if adv is None:
        return False  # no evidence -> never ship unverified
    eco, version = finding.dependency.ecosystem, finding.installed_version
    return any(is_version_affected(eco, version, pkg) for pkg in _pkgs_for(finding.dependency, adv))


def _all_claims_cited(finding: Finding, adv: AdvisoryRecord | None) -> bool:
    # Every citation must trace to the advisory's own references. Catches a fabricated source
    # (the exact failure mode once an LLM drafts remediation text). Empty citations are fine:
    # nothing was invented. A missing-references advisory is not punished.
    if adv is None:
        return False
    evidence = set(adv.references)
    cited = set(finding.citations)
    if finding.remediation is not None:
        cited |= set(finding.remediation.citations)
    return cited <= evidence


def _severity_consistent(finding: Finding) -> bool:
    # Integrity check: rank_score must match a re-computation from the finding's OWN signal
    # fields — catches a rank set out of step with its inputs (e.g. a reordered report). It does
    # NOT re-derive EPSS/KEV from the feeds; validating the signal fields themselves against
    # source data is PR #12 hardening, once an LLM can fabricate them.
    return isclose(finding.rank_score, compute_rank(finding), rel_tol=0.0, abs_tol=1e-9)


def verify_finding(finding: Finding, adv: AdvisoryRecord | None) -> VerifierVerdict:
    """Independent deterministic re-check. Pass only if all three checks hold."""
    version_in_range = _version_in_range(finding, adv)
    all_cited = _all_claims_cited(finding, adv)
    severity_consistent = _severity_consistent(finding)
    passed = version_in_range and all_cited and severity_consistent
    reason: str | None = None
    if not passed:
        problems = []
        if not version_in_range:
            problems.append("installed version not independently verified in an affected range")
        if not all_cited:
            problems.append("a claim cites a source absent from the advisory references")
        if not severity_consistent:
            problems.append("rank score inconsistent with recomputed EPSS/KEV/severity signals")
        reason = "; ".join(problems)
    return VerifierVerdict(
        passed=passed,
        version_in_range=version_in_range,
        all_claims_cited=all_cited,
        severity_consistent=severity_consistent,
        rejected_reason=reason,
    )
