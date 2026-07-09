# Palisade — 2-minute demo

A copy-pasteable walkthrough. The headline step (the eval) runs **offline with no API keys**; the
live-scan steps hit public OSV/deps.dev/EPSS/KEV feeds over the network. An `ANTHROPIC_API_KEY` is
optional and only upgrades remediation prose from deterministic to LLM-drafted.

```bash
make install    # once: uv creates .venv and installs deps
```

## 0:00 — The headline: 18 false positives → 0 (offline)

The whole thesis in one command. It scores Palisade against a naive "flag every advisory that
mentions the package" baseline over the pinned golden set — no network, fully deterministic:

```bash
uv run python -m evals.run_eval
```

```json
{
  "cases": 6,
  "precision": 1.0,
  "recall": 1.0,
  "kev_recall": 1.0,
  "version_match_accuracy": 1.0,
  "fp_reduction_vs_baseline": 1.0,
  "palisade_false_positives": 0,
  "baseline_false_positives": 18,
  "verifier_findings_tested": 30,
  "hallucination_catch_rate": 1.0,
  "verifier_false_rejections": 0
}
```

The naive baseline raises **18** false positives; Palisade's version-aware matching suppresses all
of them (**100% FP reduction**) while catching every real one. The Verifier catches fabricated
citations on 30 findings with **zero** false rejections.

## 0:30 — Scan a real lockfile (live)

Point the CLI at a vulnerable lockfile. `werkzeug==2.0.0` is years out of date:

```bash
uv run palisade scan evals/golden/cases/pypi-werkzeug-vulnerable/requirements.txt
```

You get a ranked, **cited** JSON report — each finding carries the installed version, the matched
affected range, an EPSS/KEV-informed rank, and a remediation with an upgrade target and citations
that trace back to the advisory. Now scan the patched variant:

```bash
uv run palisade scan evals/golden/cases/pypi-werkzeug-patched/requirements.txt
```

`werkzeug==3.0.6` returns **no findings** — the same advisories exist, but the installed version
isn't in range, so Palisade stays quiet where a name-matching scanner would still cry wolf.

## 1:15 — The agent graph + Verifier

Run the same scan through the M2 LangGraph pipeline
(`Ingest → Triage → Impact → Remediate → Verify → Report`). Every finding must clear the Verifier's
three independent re-checks before it appears:

```bash
uv run palisade scan evals/golden/cases/pypi-werkzeug-vulnerable/requirements.txt --engine graph
```

## 1:30 — The API path (needs Docker)

Scans are async: `POST /scan` enqueues into a Postgres-backed queue and a worker runs them.

```bash
make up-db && make migrate          # Postgres + pgvector, schema
make run &                          # API on :8000
make worker &                       # queue consumer

curl -s -X POST localhost:8000/scan \
  -H 'content-type: application/json' \
  -d '{"filename":"requirements.txt","content":"werkzeug==2.0.0\n"}'
# -> 202 {"id":"<id>","status":"queued"}

curl -s localhost:8000/scans/<id>   # -> ScanReport once the worker finishes
```

## In production

- **GitHub PR webhook** — `POST /github/webhook` (HMAC-SHA256 verified) scans changed lockfiles on
  opened/synchronized PRs and upserts a single ranked, cited comment. Set `GITHUB_WEBHOOK_SECRET`
  and `GITHUB_TOKEN`.
- **Dashboard** — `make dashboard` serves a read-only Streamlit view over the scans table
  (overview cards, recent scans, findings drill-down) at http://localhost:8501.
- **CI eval-gate** — PRs touching matching/enrichment/agents/scanner re-run the golden eval and are
  blocked if any metric regresses or the Verifier starts falsely rejecting findings.

See [`WRITEUP.md`](WRITEUP.md) for the design story and the Verifier bug the eval caught.
