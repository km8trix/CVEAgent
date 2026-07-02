"""Run the golden eval, write metrics.json, optionally enforce thresholds (--gate)."""

import json
import sys
from pathlib import Path

from evals.datasets import load_all
from evals.metrics import aggregate, evaluate_case
from evals.verifier_eval import aggregate_verifier, evaluate_verifier

_THRESHOLDS = {
    "kev_recall": 1.0,
    "recall": 0.9,
    "precision": 0.9,
    "version_match_accuracy": 0.9,
    "hallucination_catch_rate": 1.0,  # the Verifier must drop every hallucinated remediation
}


def main() -> int:
    cases = load_all()
    metrics = aggregate([evaluate_case(c) for c in cases])
    metrics.update(aggregate_verifier([evaluate_verifier(c) for c in cases]))
    (Path(__file__).parent / "metrics.json").write_text(json.dumps(metrics, indent=2) + "\n")
    print(json.dumps(metrics, indent=2))
    if "--gate" in sys.argv:
        failed = [f"{k}={metrics[k]} < {t}" for k, t in _THRESHOLDS.items() if metrics[k] < t]
        if metrics["verifier_false_rejections"] > 0:
            failed.append(f"verifier_false_rejections={metrics['verifier_false_rejections']} > 0")
        if failed:
            print("EVAL GATE FAILED:", "; ".join(failed))
            return 1
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
