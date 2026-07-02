"""Detection metrics vs the golden labels and vs the naive baseline (IMPLEMENTATION_PLAN.md §6)."""

from dataclasses import dataclass
from typing import Any

from evals.baseline import naive_flag
from evals.datasets import Case
from palisade.matching.matcher import match


@dataclass
class CaseResult:
    id: str
    tp: int
    fp: int
    fn: int
    baseline_fp: int
    kev_total: int
    kev_found: int
    version_correct: int
    version_total: int


def evaluate_case(case: Case) -> CaseResult:
    palisade = {f.advisory_id for f in match(case.deps, case.advisories)}
    baseline = naive_flag(case.deps, case.advisories)
    gt_pos = {i for i, lab in case.labels.items() if lab["applies"]}
    kev_pos = {i for i in gt_pos if case.labels[i].get("is_kev")}
    # Per-advisory-record accuracy (GHSA and its PYSEC alias for one CVE count separately,
    # which matches what the system surfaces: two distinct findings).
    version_correct = sum(
        1 for i, lab in case.labels.items() if (i in palisade) == bool(lab["applies"])
    )
    return CaseResult(
        id=case.id,
        tp=len(palisade & gt_pos),
        fp=len(palisade - gt_pos),
        fn=len(gt_pos - palisade),
        baseline_fp=len(baseline - gt_pos),
        kev_total=len(kev_pos),
        kev_found=len(palisade & kev_pos),
        version_correct=version_correct,
        version_total=len(case.labels),
    )


def aggregate(results: list[CaseResult]) -> dict[str, Any]:
    tp = sum(r.tp for r in results)
    fp = sum(r.fp for r in results)
    fn = sum(r.fn for r in results)
    base_fp = sum(r.baseline_fp for r in results)
    kev_total = sum(r.kev_total for r in results)
    kev_found = sum(r.kev_found for r in results)
    vc = sum(r.version_correct for r in results)
    vt = sum(r.version_total for r in results)
    return {
        "cases": len(results),
        "precision": round(tp / (tp + fp), 4) if tp + fp else 1.0,
        "recall": round(tp / (tp + fn), 4) if tp + fn else 1.0,
        "kev_recall": round(kev_found / kev_total, 4) if kev_total else 1.0,
        "version_match_accuracy": round(vc / vt, 4) if vt else 1.0,
        # Reported headline (not gated): 0.0 when the baseline had nothing to over-flag.
        "fp_reduction_vs_baseline": round(1 - fp / base_fp, 4) if base_fp else 0.0,
        "palisade_false_positives": fp,
        "baseline_false_positives": base_fp,
    }
