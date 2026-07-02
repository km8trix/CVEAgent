"""Run the golden eval, write metrics.json, optionally enforce thresholds (--gate)."""

import json
import sys
from pathlib import Path

from evals.datasets import load_all
from evals.metrics import aggregate, evaluate_case

_THRESHOLDS = {"kev_recall": 1.0, "recall": 0.9, "precision": 0.9, "version_match_accuracy": 0.9}


def main() -> int:
    results = [evaluate_case(c) for c in load_all()]
    metrics = aggregate(results)
    (Path(__file__).parent / "metrics.json").write_text(json.dumps(metrics, indent=2) + "\n")
    print(json.dumps(metrics, indent=2))
    if "--gate" in sys.argv:
        failed = [f"{k}={metrics[k]} < {t}" for k, t in _THRESHOLDS.items() if metrics[k] < t]
        if failed:
            print("EVAL GATE FAILED:", "; ".join(failed))
            return 1
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
