"""Verifier-effectiveness eval — the M2 headline (IMPLEMENTATION_PLAN.md §6/§7).

Does the Verifier catch an LLM's hallucinated remediations without rejecting genuine findings?
Measured deterministically: a fabricated-citation remediation stands in for a hallucinating LLM
(the exact failure mode the Verifier guards), so this runs offline in CI with no API key.

For each genuine finding we check both directions:
  * a correctly-grounded remediation (cited to the advisory) must PASS  -> false rejection if not
  * the same finding with a fabricated citation must be REJECTED         -> a miss if not
"""

from dataclasses import dataclass
from typing import Any

from evals.datasets import Case
from palisade.agents.nodes import build_remediation, verify_finding
from palisade.enrichment.enrich import enrich_findings
from palisade.matching.matcher import match
from palisade.matching.reachability import reachability

# A URL that is deliberately not in any advisory's references — the fabricated source.
_FABRICATED_CITATION = "https://hallucinated.invalid/not-a-real-source"


@dataclass
class VerifierResult:
    id: str
    genuine_findings: int  # in-range candidates (all genuinely apply; match() excludes traps)
    hallucinations_caught: int  # fabricated-citation remediations the Verifier rejected
    false_rejections: int  # correctly-cited genuine findings the Verifier wrongly rejected


def evaluate_verifier(case: Case) -> VerifierResult:
    adv_by_id = {a.id: a for a in case.advisories}
    findings = match(case.deps, case.advisories)  # only in-range findings — the genuine set
    for f in findings:
        f.reachability = reachability(f.dependency)
    enrich_findings(findings, {}, {})  # set a consistent rank_score (as the graph's Impact does)

    caught = 0
    false_rejections = 0
    for f in findings:
        adv = adv_by_id.get(f.advisory_id)

        f.remediation = build_remediation(f)  # correctly grounded -> must pass
        if not verify_finding(f, adv).passed:
            false_rejections += 1

        hallucinated = build_remediation(f)  # same finding, fabricated citation -> must be caught
        hallucinated.citations = [_FABRICATED_CITATION]
        f.remediation = hallucinated
        if not verify_finding(f, adv).passed:
            caught += 1

    return VerifierResult(
        id=case.id,
        genuine_findings=len(findings),
        hallucinations_caught=caught,
        false_rejections=false_rejections,
    )


def aggregate_verifier(results: list[VerifierResult]) -> dict[str, Any]:
    genuine = sum(r.genuine_findings for r in results)
    caught = sum(r.hallucinations_caught for r in results)
    false_rejections = sum(r.false_rejections for r in results)
    return {
        "verifier_findings_tested": genuine,
        # Fraction of hallucinated remediations the Verifier dropped (1.0 = none shipped).
        "hallucination_catch_rate": round(caught / genuine, 4) if genuine else 1.0,
        "verifier_false_rejections": false_rejections,
    }
