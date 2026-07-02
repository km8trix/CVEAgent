# Palisade — Implementation Plan

Derived from [`docs/palisade-project-spec.md`](docs/palisade-project-spec.md). That spec is the
source of truth; this plan is *how* to build it. Target: ~3 months, solo, portfolio-grade.

**This is a plan, not code.** Nothing here should be built until the plan is agreed. The
"[First 10 PRs](#12-first-10-prs-execution-backlog)" section is the concrete starting point.

---

## 1. Engineering principles (lazy defaults that keep this shippable solo)

These bias every decision below toward the least code that is still correct.

- **Lean on OSV for version matching.** OSV.dev already does ecosystem-aware
  version-range matching server-side and its schema is the de-facto standard. We normalize
  *everything* (NVD, GHSA) into the OSV schema and use `osv.dev/v1/querybatch` at scan time.
  We only re-implement the range check locally for the Verifier's independent second opinion.
- **Bulk downloads over per-item API calls.** EPSS (daily CSV), CISA KEV (single JSON), and
  the OSV corpus (per-ecosystem zip export) are fetched in bulk once/day and looked up locally.
  Live per-item APIs (OSV `query`, deps.dev) are hit only at scan time.
- **Postgres does more than one job.** Advisory store, vector store (pgvector), *and* the scan
  queue (a `scans` table + `SELECT … FOR UPDATE SKIP LOCKED`) all live in Postgres. Add Redis/RQ
  only when a single worker measurably can't keep up. `# ponytail: pg-backed queue, add Redis/RQ if throughput demands`
- **Pydantic v2 models are the data models AND the API schemas.** One definition, reused for
  domain logic, DB (de)serialization, and FastAPI request/response bodies.
- **Deterministic before probabilistic.** Version-range membership, KEV membership, and EPSS
  lookup are pure functions with unit tests. The LLM never decides "is it in range" — it only
  explains, summarizes, and drafts. This is the whole thesis and the headline metric's foundation.
- **Defer the demo surface.** GitHub App PR-scanner and dashboard are Month 3. Months 1–2 ship a
  CLI + a synchronous `/scan` endpoint, which is enough to measure everything that matters.
- **Two ecosystems only (npm, PyPI).** Parsers are pluggable so a third is additive, but we do
  not build the plugin registry any fancier than a filename→parser dict until there's a third.

---

## 2. Milestones mapped to the 3-month schedule

The spec's Month 1/2/3 become three milestones with hard exit criteria. Each milestone is a
demoable state, not just a pile of code.

### Milestone M1 — Data plane + grounded baseline (Month 1)
**Goal:** given a lockfile, list the CVEs that genuinely apply, with citations — no LLM yet.
**Exit:** `palisade scan <lockfile>` and `POST /scan` return a ranked, cited candidate list for
an npm and a PyPI repo, where every finding's installed version is machine-verified in range.

Tasks:
- [ ] Repo scaffold: `uv` project, `src/palisade` layout, `pydantic-settings` config, FastAPI app with `/health`.
- [ ] `docker-compose` with `pgvector/pgvector:pg16`; Alembic baseline migration; `Makefile` targets.
- [ ] Domain models (advisory, dependency, finding, state) as Pydantic v2 + ORM tables.
- [ ] `BaseClient` (httpx async + tenacity + per-host token bucket + content-hash cache).
- [ ] OSV client + `normalize.py` → `AdvisoryRecord`; NVD + GHSA clients mapping into the same schema.
- [ ] Ingestion: OSV bulk-export delta sync (npm + PyPI) → normalize → upsert (idempotent via `content_hash`).
- [ ] Lockfile parsers: npm (`package-lock.json`, `pnpm-lock.yaml`), PyPI (`requirements.txt`, `poetry.lock`).
- [ ] deps.dev client → transitive `DependencyGraph` (direct/indirect edges).
- [ ] Deterministic matcher: `dependency × advisory → candidate Finding` via version-range membership.
- [ ] EPSS (daily CSV) + CISA KEV (JSON) loaders + local lookup; attach to findings; severity bucket.
- [ ] Embeddings (HF) → pgvector; retriever + BGE reranker; baseline RAG retrieval over advisory corpus.
- [ ] CLI `scan` + synchronous `POST /scan` returning ranked cited candidates.

### Milestone M2 — Agent graph + evals + the Verifier (Month 2)
**Goal:** the LangGraph pipeline runs end to end and the Verifier measurably cuts false positives.
**Exit:** measurable precision/recall on the golden set, a working Verifier→Impact reject loop, and
a headline "FP reduction vs naive baseline" number.

Tasks:
- [ ] LangGraph `ScanState` + graph wiring: Ingest → Triage → Impact → Remediate → Verify → Report.
- [ ] Triage node: zero-shot candidate ranking (upgrade to a small fine-tuned classifier if time).
- [ ] Impact node: RAG over advisories + version-range reasoning + reachability heuristic.
- [ ] Remediate node: upgrade-path/patch/mitigation + draft PR text, each sentence citation-tagged.
- [ ] **Verifier node** (the heart): independent deterministic re-check —
      (1) installed version in affected range, (2) every remediation sentence has a live citation,
      (3) severity ranking consistent with EPSS+KEV. Fail → drop or loop back to Impact (bounded retries).
- [ ] HF NER (package/version/CWE/CPE extraction) + triage classifier wired into Triage/Impact.
- [ ] Model routing: cheap model for easy hops, strong model for Impact/Remediate.
- [ ] Golden dataset (20–40 cases incl. FP traps) + `metrics.py` + naive baseline + `run_eval.py`.
- [ ] Measure and record: detection P/R, KEV-recall, version-match accuracy, FP reduction vs baseline.

### Milestone M3 — Productionize + demo (Month 3)
**Goal:** it runs on a live PR and comments a cited, ranked report; changes are gated by evals.
**Exit:** GitHub App comments on a real PR; CI eval-regression gate blocks quality drops.

Tasks:
- [x] Async scan queue (pg-backed worker) so scans don't block the API.
- [ ] Langfuse tracing; cost + p95 latency captured per scan; prompt versioning.
- [x] CI eval-regression gate (`.github/workflows/eval-gate.yml`) on PRs touching prompts/retrieval/matching.
- [ ] GitHub App / webhook PR-scan mode → posts a comment with the ranked cited report.
- [ ] Dashboard (Streamlit first — lazy; Next.js only if time) showing findings + metrics.
- [ ] Ragas faithfulness/context-precision in the eval suite; enforce faithfulness ≥ 0.9 in the gate.
- [ ] Write-up ("How I stopped my security agent from crying wolf") + 2-min demo + architecture diagram.

**Stretch (only if M1–M3 land clean):** call-graph reachability, more ecosystems (Go/Cargo/Maven),
SBOM (Syft/Grype), Sigstore/SLSA provenance, auto-opened remediation PRs, Pinecone swap-in.

---

## 3. Proposed module / package / file layout

```
palisade/
├── IMPLEMENTATION_PLAN.md
├── README.md
├── pyproject.toml               # uv-managed
├── docker-compose.yml           # db (pgvector) + api + worker [+ redis if needed]
├── .env.example
├── Makefile                     # up / migrate / seed / eval / test / lint
├── alembic.ini
├── migrations/                  # Alembic versions
├── src/palisade/
│   ├── config.py                # pydantic-settings (env: API keys, DB URL, model names)
│   ├── main.py                  # FastAPI app factory
│   ├── cli.py                   # `palisade scan <path>` (Typer)
│   ├── api/
│   │   ├── routes/{scans,advisories,health}.py
│   │   └── deps.py              # db session, auth dependencies
│   ├── models/                  # Pydantic v2 domain models (see §4)
│   │   ├── advisory.py          # AdvisoryRecord, AffectedPackage, Range, Severity
│   │   ├── dependency.py        # Dependency, DependencyGraph, Lockfile
│   │   ├── finding.py           # Finding, Remediation, VerifierVerdict, ScanReport
│   │   └── state.py             # ScanState (LangGraph)
│   ├── db/
│   │   ├── base.py              # SQLAlchemy 2.0 engine/session
│   │   ├── tables.py            # advisories, advisory_embeddings, scans, findings
│   │   └── vector.py            # pgvector helpers (upsert, cosine search)
│   ├── clients/                 # external API clients (§5)
│   │   ├── base.py              # BaseClient: httpx + tenacity + token bucket + cache
│   │   ├── osv.py  nvd.py  ghsa.py  depsdev.py  epss.py  kev.py  scorecard.py
│   ├── ingestion/
│   │   ├── sources/{osv,nvd,ghsa}.py   # fetch raw
│   │   ├── normalize.py         # raw → AdvisoryRecord (OSV schema)
│   │   ├── embed.py             # HF embeddings → pgvector upsert
│   │   ├── sync.py              # delta-sync orchestration + content-hash cache
│   │   └── worker.py            # scheduled ingestion job
│   ├── parsers/                 # lockfile parsers (pluggable)
│   │   ├── base.py              # LockfileParser protocol
│   │   ├── npm.py  pypi.py
│   │   └── registry.py          # filename → parser dict
│   ├── matching/
│   │   ├── version.py           # deterministic range membership (packaging / node-semver)
│   │   ├── matcher.py           # deps × advisories → candidate Findings
│   │   └── reachability.py      # heuristic: direct/transitive + import-present
│   ├── enrichment/{epss,kev,scorecard}.py
│   ├── retrieval/
│   │   ├── embedder.py  retriever.py  reranker.py
│   ├── classifiers/{ner,triage}.py     # HF token-classification + text-classification
│   ├── agents/
│   │   ├── graph.py             # LangGraph wiring
│   │   ├── nodes/{ingest,triage,impact,remediate,verifier,report}.py
│   │   ├── prompts/             # versioned prompt templates
│   │   └── llm.py               # model routing
│   ├── worker/scan_worker.py    # pg-queue consumer (Month 3)
│   └── observability/tracing.py # Langfuse
├── evals/
│   ├── golden/cases/<case-id>/{lockfile, meta.yaml, labels.yaml}
│   ├── datasets.py  metrics.py  baseline.py  ragas_eval.py  run_eval.py
│   └── baseline_metrics.json    # committed reference metrics for the CI gate
├── github_app/{webhook,comment}.py     # Month 3
├── dashboard/                           # Month 3 (Streamlit)
├── tests/
└── .github/workflows/{ci.yml, eval-gate.yml}
```

---

## 4. Key interfaces & data models

All models are Pydantic v2. The advisory model deliberately mirrors the **OSV schema** so NVD and
GHSA records normalize into one shape and OSV.dev data lands with zero translation.

### 4.1 Advisory record (normalized, OSV-shaped)

```python
class Event(BaseModel):          # one boundary in a range
    introduced: str | None = None
    fixed: str | None = None
    last_affected: str | None = None

class Range(BaseModel):
    type: Literal["SEMVER", "ECOSYSTEM", "GIT"]
    events: list[Event]

class AffectedPackage(BaseModel):
    ecosystem: Literal["npm", "PyPI"]        # widen later
    name: str
    ranges: list[Range] = []
    versions: list[str] = []                 # explicit affected versions, if enumerated
    database_specific: dict = {}

class Severity(BaseModel):
    cvss_vector: str | None = None
    cvss_score: float | None = None
    bucket: Literal["low", "medium", "high", "critical"] | None = None

class AdvisoryRecord(BaseModel):
    id: str                                  # internal id
    source: Literal["osv", "nvd", "ghsa"]
    source_id: str                           # e.g. "GHSA-xxxx", "CVE-2023-1234"
    aliases: list[str] = []                  # cross-source ids (CVE ↔ GHSA)
    summary: str
    details: str
    severity: Severity
    cwe_ids: list[str] = []
    affected: list[AffectedPackage]
    references: list[str] = []
    published: datetime
    modified: datetime
    content_hash: str                        # dedupe / skip-unchanged on ingest
```

### 4.2 Dependency / lockfile model

```python
class Dependency(BaseModel):
    ecosystem: Literal["npm", "PyPI"]
    name: str
    version: str                             # resolved / installed
    direct: bool                             # top-level vs transitive
    depth: int = 0
    path: list[str] = []                     # dep chain from a root, e.g. ["app","lodash"]
    source_file: str                         # which lockfile it came from

class DependencyGraph(BaseModel):
    target: str                              # repo URL or lockfile path
    ecosystem: Literal["npm", "PyPI"]
    dependencies: list[Dependency]
    edges: list[tuple[str, str]] = []        # (parent_key, child_key)

class Lockfile(BaseModel):
    path: str
    kind: Literal["package-lock", "pnpm-lock", "requirements", "poetry-lock"]
    raw: str
```

### 4.3 Finding / report schema

```python
class Remediation(BaseModel):
    type: Literal["upgrade", "patch", "config", "mitigate"]
    summary: str
    upgrade_to: str | None = None
    steps: list[str] = []
    draft_pr_text: str | None = None
    citations: list[str] = []                # every claim must trace to a source

class VerifierVerdict(BaseModel):
    passed: bool
    version_in_range: bool                   # deterministic re-check
    all_claims_cited: bool
    severity_consistent: bool                # ranking agrees with EPSS + KEV
    rejected_reason: str | None = None
    loop_count: int = 0

class Finding(BaseModel):
    dependency: Dependency
    advisory_id: str
    matched_range: Range | None
    installed_version: str
    fixed_versions: list[str] = []
    is_affected: bool                        # deterministic, not LLM
    reachability: Literal["direct", "transitive", "unknown"]
    epss_score: float | None = None
    epss_percentile: float | None = None
    kev_listed: bool = False
    kev_date_added: date | None = None
    severity_bucket: str | None = None
    remediation: Remediation | None = None
    citations: list[str] = []
    verdict: VerifierVerdict | None = None
    rank_score: float                        # ordering key for the report

class ScanReport(BaseModel):
    scan_id: str
    target: str
    created_at: datetime
    ecosystem: str
    findings: list[Finding]                  # ranked, verifier-passed only
    stats: dict                              # total_deps, candidates, confirmed,
                                             # dropped_by_verifier, fp_reduction_vs_baseline
    cost_usd: float | None = None
    latency_ms: int | None = None
```

### 4.4 Agent state (LangGraph)

`ScanState` is the single object threaded through every node. Nodes append/replace fields; the
Verifier can route back to Impact by leaving findings in `pending` with an incremented retry count.

```python
class ScanState(TypedDict, total=False):
    scan_id: str
    target: str
    graph: DependencyGraph
    candidates: list[Finding]                # from Triage
    impacted: list[Finding]                  # from Impact (with remediation)
    verified: list[Finding]                  # passed the Verifier
    rejected: list[Finding]                  # dropped, with reason
    retry_counts: dict[str, int]             # per-finding, bounds the Verifier→Impact loop
    trace: list[dict]                        # step log for observability
    errors: list[str]
```

### 4.5 Lockfile parser interface

```python
class LockfileParser(Protocol):
    kind: str
    filenames: tuple[str, ...]               # e.g. ("package-lock.json",)
    def parse(self, lockfile: Lockfile) -> list[Dependency]: ...
```

`parsers/registry.py` is just `{filename: parser}` — dispatch by basename. No plugin framework
until a third ecosystem actually needs one.

---

## 5. External API integration notes (auth + rate limits)

Every client extends `clients/base.BaseClient`: an `httpx.AsyncClient` with a **per-host token
bucket**, `tenacity` retry (exponential backoff + jitter on 429/5xx, honoring `Retry-After`),
conditional requests (ETag / `Last-Modified`) and a content-hash cache to skip unchanged records.
Secrets come from `config.py` (`pydantic-settings`): `NVD_API_KEY`, `GITHUB_TOKEN`, etc.

| Source | Endpoint / mode | Auth | Rate limit & handling |
|---|---|---|---|
| **NVD 2.0** | `services.nvd.nist.gov/rest/json/cves/2.0`; delta via `lastModStartDate`/`lastModEndDate` (≤120-day window), paginate `startIndex`/`resultsPerPage` (max 2000) | `apiKey` header (free key) | 5 req/30s no key → **50 req/30s with key**. Token bucket ~0.6s spacing; sleep+backoff on 403/503. Request the key. |
| **OSV.dev** | **Primary matcher.** `POST /v1/query` `{package:{ecosystem,name}, version}`; `POST /v1/querybatch` (≤1000). Full corpus via `gs://osv-vulnerabilities/<ecosystem>/all.zip` bulk export | none | No hard published limit; be polite (batch + local bucket). Bulk export for ingestion; live `querybatch` at scan time. Native OSV schema = our normalized shape. |
| **GitHub Advisory** | GraphQL `api.github.com/graphql`, `securityAdvisories`/`securityVulnerabilities`; cursor paginate (`after`, `pageInfo`); delta via `updatedSince` | Bearer PAT / App token | 5000 points/hr. Watch GraphQL point cost; back off on secondary-rate-limit signal. Maps cleanly to OSV (GHSA id, ecosystem, `vulnerableVersionRange`, `firstPatchedVersion`). |
| **deps.dev** | `api.deps.dev/v3/systems/{npm\|pypi}/packages/{name}/versions/{version}:dependencies` → resolved transitive graph (nodes/edges, direct vs indirect) | none | Generous; local token bucket only. Used at scan time to build `DependencyGraph` without installing anything. |
| **EPSS (FIRST)** | Bulk daily CSV `epss.cyentia.com/epss_scores-YYYY-MM-DD.csv.gz` (preferred) or `api.first.org/data/v1/epss?cve=` | none | Download once/day into a `cve → (score, percentile)` table; lookups are local. Avoid per-CVE calls. |
| **CISA KEV** | Single JSON `cisa.gov/sites/default/files/feeds/known_exploited_vulnerabilities.json` | none | Download once/day; store `{cve, dateAdded}` set; local membership check. |
| **OpenSSF Scorecard** | `api.securityscorecards.dev/projects/github.com/{org}/{repo}` (cached) or `scorecard` binary | none (API) | Enrichment only; cache per repo; failures are non-fatal. |

**Bulk-first rule:** EPSS, KEV, and OSV corpus are synced by a daily job; only OSV `querybatch`
and deps.dev are called live during a scan. This keeps scans fast and within limits.

**Deterministic version matching** uses `packaging.specifiers`/`packaging.version` for PyPI and a
Node-semver-compatible check for npm ranges — never a hand-rolled parser, never an LLM. This
function is the Verifier's independent second opinion and gets the heaviest unit tests (boundary
versions, pre-releases, `>=`/`<`/caret/tilde, `0.0.0` edge cases).

---

## 6. Agent graph design

LangGraph state machine over `ScanState`:

```
Ingest → Triage → Impact → Remediate → Verify ──pass──▶ Report
                    ▲                     │
                    └──────reject─────────┘   (bounded by retry_counts[finding] < N)
```

- **Ingest** — parse lockfile → deps.dev transitive resolution → `DependencyGraph`.
- **Triage** — deterministic OSV/NVD match → candidate findings; zero-shot (later fine-tuned) classifier ranks.
- **Impact** — RAG over advisory corpus (retrieve → rerank) + version-range reasoning + reachability heuristic; decides real vs noise.
- **Remediate** — upgrade path / patch / mitigation + draft PR text; each sentence citation-tagged.
- **Verify** — deterministic re-check (§4.3 `VerifierVerdict`). Pass → Report. Fail → drop, or one hop back to Impact if `retry_counts < N`.
- **Report** — assemble ranked `ScanReport`; compute stats incl. FP reduction vs baseline.

Model routing (`agents/llm.py`): cheap model for Triage/Report, strong model for Impact/Remediate.
Prompts are versioned files under `agents/prompts/` so the CI eval gate can pin and diff them.

---

## 7. Evaluation harness design

### Golden dataset structure
`evals/golden/cases/<case-id>/`:
- `lockfile` — pinned, committed (the exact input).
- `meta.yaml` — `{ecosystem, source_repo, commit, notes}`.
- `labels.yaml` — list of `{id: CVE/GHSA, package, applies: true|false, is_kev: bool, is_trap: bool, reason}`.

20–40 cases. Seed with repos carrying documented CVEs; **deliberately include FP traps**: a CVE
against an adjacent (non-installed) version, and a CVE against an unreachable transitive dep.
Label quality over quantity.

### Metrics (`evals/metrics.py` → `metrics.json`)
- Detection **precision / recall** (findings vs `applies: true` labels).
- **KEV-recall** — recall restricted to `is_kev: true` (must be high; these are act-now CVEs).
- **Overall precision**.
- **FP-rate vs naive baseline** — the headline number.
- **Version-match accuracy** — was the installed-in-range verdict correct.
- **Ragas** faithfulness + context precision on remediation text.
- **Cost/scan** and **p95 latency**.

### Baseline (`evals/baseline.py`)
Naive matcher: flag every advisory that *mentions the package name*, ignoring version and
reachability. Palisade's FP reduction is measured against this — the resume headline.

### CI eval gate (`.github/workflows/eval-gate.yml`)
- Triggers on PRs touching `agents/prompts/**`, `retrieval/**`, `matching/**`, `enrichment/**`.
- Runs `run_eval.py` against a **pinned advisory fixture snapshot** (not live APIs — determinism).
- Compares to committed `evals/baseline_metrics.json`; **fails** if faithfulness < 0.9 or
  KEV-recall regresses beyond threshold. Posts a metrics table as a PR comment.

---

## 8. Local dev setup

`docker-compose.yml`:
- `db` — `pgvector/pgvector:pg16`; init SQL enables the `vector` extension; named volume for data.
- `api` — FastAPI/uvicorn (dev reload).
- `worker` — scan worker (Month 3; no-op earlier).
- `redis` — commented out; uncomment only if the pg-backed queue proves insufficient.

Tooling: `uv` for deps/venv, `alembic` migrations, `Makefile` targets:
`make up` (compose up), `make migrate`, `make seed` (pull a small OSV npm+PyPI subset locally),
`make eval` (`run_eval.py`), `make test`, `make lint` (ruff + mypy).
`.env.example` documents every key (`DATABASE_URL`, `NVD_API_KEY`, `GITHUB_TOKEN`, model names,
`LANGFUSE_*`). Real `.env` is git-ignored.

---

## 9. Testing strategy

- **Deterministic core gets real tests:** version matching (boundary/pre-release/caret/tilde),
  lockfile parsers (sample fixtures per format), normalize (NVD/GHSA → OSV shape), matcher.
- **Clients tested against recorded fixtures** (VCR-style / saved JSON) — no live network in CI.
- **Agent nodes**: unit-test the deterministic parts (Verifier checks) directly; smoke-test the
  full graph on one npm + one PyPI fixture case.
- **Evals are the integration test** for quality; unit tests are for correctness of the plumbing.

---

## 10. Risks & mitigations

| Risk | Mitigation |
|---|---|
| NVD rate limits stall ingestion | Bulk-first (OSV export primary); NVD only for CVSS/CPE enrichment; get the API key. |
| npm semver edge cases break matching | Use a Node-semver-compatible lib, not hand-rolled; heavy boundary tests; Verifier double-checks. |
| Golden set too small to be credible | 20–40 honest cases with traps beats 200 sloppy ones; report N alongside every metric. |
| Verifier loops forever | Hard `retry_counts < N` bound; on exhaustion, drop with reason (never ship unverified). |
| Scope creep (SBOM, provenance, more ecosystems) | Explicitly stretch; M1–M3 ship npm+PyPI only. |
| LLM cost | Model routing + reranking to shrink context; measure cost/scan from day one. |

---

## 11. Definition of done (portfolio)

- Runs on a live PR and comments a cited, ranked report.
- A measured FP-reduction number vs the naive baseline across N labeled repos.
- KEV-recall and version-match accuracy reported.
- CI eval-regression gate live and blocking.
- Architecture diagram + write-up + 2-minute demo.

---

## 12. First 10 PRs (execution backlog)

Ordered so each PR is independently reviewable and builds on the last. This is where the next
session starts.

1. **Scaffold.** `uv` project, `src/palisade` layout, `config.py` (pydantic-settings), FastAPI app
   with `/health`, `docker-compose` (Postgres+pgvector), `.env.example`, `Makefile`, CI lint/test.
2. **Domain models + DB.** Pydantic models (§4) + ORM tables (advisories, advisory_embeddings,
   scans, findings) + first Alembic migration.
3. **BaseClient + OSV client + normalize.** Shared httpx/tenacity/token-bucket/cache client; OSV
   client; `normalize.py` → `AdvisoryRecord`. Tests against recorded fixtures.
4. **OSV ingestion.** Bulk-export delta sync for npm + PyPI → normalize → idempotent upsert
   (`content_hash`). No embeddings yet.
5. **Lockfile parsers.** npm (`package-lock.json`) + PyPI (`requirements.txt`/`poetry.lock`) with a
   filename→parser registry. Fixture tests.
6. **Deterministic matching.** `matching/version.py` (packaging + node-semver) + `matcher.py`
   (deps × advisories → candidate findings). Heaviest unit tests in the repo — the grounding core.
7. **Transitive resolution.** deps.dev client → `DependencyGraph` (direct/indirect) + reachability
   heuristic v0.
8. **Enrichment.** EPSS daily-CSV + CISA KEV JSON loaders + local lookup; attach to findings;
   severity bucketing.
9. **Retrieval + `/scan` v0.** HF embedder → pgvector; retriever + BGE reranker; embed the corpus;
   synchronous `POST /scan` + `palisade scan` CLI returning ranked cited candidates. **→ M1 exit.**
10. **Eval harness skeleton.** Golden layout + 5 seed cases (incl. 2 FP traps), `metrics.py`, naive
    `baseline.py`, `run_eval.py` → `metrics.json`; non-blocking eval job in CI. Sets the measurement
    spine before the agents land in M2.

PRs 1–10 complete Milestone M1 and lay the rails for the LangGraph agents (Triage/Impact/Remediate/
**Verify**/Report) and the CI eval-regression gate in M2–M3.
