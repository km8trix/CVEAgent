# Eval harness

Measures Palisade's version-aware matching against a pinned golden set, and against a naive
"any advisory mentioning the package" baseline (`baseline.py`).

```bash
uv run python -m evals.run_eval          # writes evals/metrics.json + prints
uv run python -m evals.run_eval --gate   # exits non-zero if below thresholds
```

**Golden set** (`golden/cases/<id>/`): a lockfile + `advisories.json` (pinned real OSV records)
+ `labels.json` (ground truth). Advisories are pinned so the eval is deterministic and offline.

**Ground-truth provenance (honest caveat):** labels are derived from OSV.dev's own per-version
matching + the real CISA KEV feed. So precision/recall measure *agreement with OSV's authoritative
matching* (expected to be high, since Palisade re-verifies OSV). The meaningful headline is
**`fp_reduction_vs_baseline`**: how many alerts the naive package-name baseline raises that
Palisade's version check correctly suppresses. Independent, hand-labeled adversarial cases would
strengthen precision/recall — a good next step as the set grows past this skeleton.

## Metric notes

- **Gated** (via `--gate`): `kev_recall` (>=1.0), `recall`, `precision`, `version_match_accuracy` (>=0.9). **Reported** (not gated): `fp_reduction_vs_baseline` — the headline; it is a ratio that is legitimately 0.0 when the baseline over-flags nothing.
- `version_match_accuracy` is **per advisory record**, not per unique CVE: an advisory and its cross-source alias (GHSA + PYSEC for the same CVE) count as two, matching the two findings the system actually emits.
- `kev_recall` only diverges from `recall` when Palisade misses a KEV-flagged advisory while catching others; add `is_kev=true` cases to exercise it beyond the current set.
