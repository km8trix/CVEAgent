# Palisade

**A self-verifying, multi-agent software-supply-chain vulnerability intelligence agent.**

> Portfolio project spec for a mid-level SWE (2–6 YOE) pivoting into an AI engineering role. Target build time: ~3 months, solo. This document is the source-of-truth brief; an implementation plan is derived from it.

---

## 1. What it is and the problem it solves

**One-liner:** Point Palisade at a repository (or a raw lockfile) and it returns a ranked, de-noised, fully-cited list of the vulnerabilities that *actually* matter for that codebase — plus concrete, verified remediation steps.

**The problem.** Security and platform teams drown in CVE noise. Naive SCA tooling (and naive "ask an LLM about my dependencies" wrappers) over-alert catastrophically: they flag CVEs against the wrong version, against transitive packages that are never reached, or with a scary CVSS score even when there is zero real-world exploitation. Analysts spend hours triaging alerts that don't apply. Worse, an LLM asked "is my app affected by CVE-XXXX?" will confidently hallucinate a version range or a fix.

**Palisade's thesis — verifiable grounding.** Nothing ships without proof:
- No dependency is called "vulnerable" unless the installed version falls inside a machine-checked affected-version range from an authoritative source (OSV / NVD / GHSA).
- Severity is grounded in real exploit signal — EPSS (exploit probability) and the CISA KEV catalog (known-exploited) — not CVSS alone.
- Every claim in the final report carries a citation to the source advisory, and a dedicated Verifier agent rejects any unsupported or version-mismatched claim before the report is returned.

This "guardrail + eval harness" layer is exactly what separates an AI engineer from someone who wrapped an API, and it is the story the whole project is designed to tell.

---

## 2. HuggingFace tasks used

- Token Classification (NER): extract package names, version ranges, CWE IDs, CPE strings from unstructured advisory prose
- Text Classification: triage exploitability / severity bucket / advisory type; reachability likelihood
- Zero-Shot Classification: route advisories & questions; tag remediation type (upgrade / patch / config / mitigate)
- Feature Extraction: embeddings for the advisory corpus (RAG retrieval)
- Text Ranking: rerank retrieved advisory passages (cross-encoder / BGE reranker)
- Question Answering: "Is my usage of package X affected by this advisory?"
- Summarization: condense long advisories into a one-paragraph analyst brief
- Text Generation: remediation guidance and auto-drafted PR descriptions
- Table Question Answering (stretch): parse CPE / affected-version tables inside NVD records

---

## 3. Real-world data APIs (all free / public)

- NVD API 2.0 (NIST): canonical CVE records, CVSS, CPE (rate-limited; request an API key)
- OSV.dev API (Google / OpenSSF): open-source vulns with precise ecosystem-aware affected-version ranges — PRIMARY source for version matching
- GitHub Advisory Database: GraphQL securityAdvisories; also powers Dependabot
- deps.dev API (Google): dependency graphs, version metadata, transitive resolution
- EPSS (FIRST.org): daily exploit-prediction scores per CVE
- CISA KEV catalog: known-exploited vulnerabilities (strongest "act now" signal)
- OpenSSF Scorecard: repo-health signals for the upstream package
- Package registries: npm, PyPI, crates.io, Maven Central, Go proxy — for lockfile resolution
- (Stretch) Syft/Grype for SBOM; Sigstore / SLSA provenance

Input formats: a GitHub repo URL, or a raw lockfile (package-lock.json / pnpm-lock.yaml, poetry.lock / requirements.txt, go.sum, Cargo.lock, pom.xml).

Output: a ranked, cited vulnerability report — per finding: package, installed vs. fixed version, why it's reachable/relevant, EPSS + KEV status, remediation, source links. Optional auto-drafted remediation PR.

---

## 4. Architecture — Agent graph (LangGraph state machine)

Ingest (parse lockfile -> resolve full dep tree via deps.dev) -> Triage (deterministic CVE match OSV/NVD -> classifier ranks candidates) -> Impact (RAG over advisories; reachability + version-range reasoning) -> Remediate (upgrade path / patch / mitigation + draft PR text) -> VERIFIER (independent re-check; on reject loop back to Impact) -> Report.

The Verifier is the heart of the project. It independently re-checks each finding: (1) does the installed version actually fall in the affected range (deterministic semver/range check, not an LLM guess); (2) is every sentence in the remediation grounded in a cited source; (3) is the severity ranking consistent with EPSS + KEV, not just the model's vibe. Failing findings are dropped or sent back one hop. This drives the headline false-positive-reduction metric.

Data plane: advisory corpus + embeddings in Postgres + pgvector (transactional, cheap; Pinecone as managed alternative). Ingestion pipeline does scheduled delta sync (NVD lastModStartDate, OSV export, GHSA) -> normalize -> embed -> upsert, with content-hash caching. Scan queue: async worker (RQ/Celery or simple queue) so repo scans don't block the API.

---

## 5. Recommended tech stack

- Orchestration: LangGraph (stateful cyclic graph; Verifier->Impact loop needs real control flow)
- Ingestion/parsing: LlamaIndex
- Vector store: pgvector on Postgres (Pinecone as managed alt)
- Embeddings + rerank: HF open-weight embeddings + BGE reranker
- Triage classifier: zero-shot first, then a small fine-tuned classifier
- LLM: hosted LLM for generation; model routing (cheap model for easy hops)
- Evals: Ragas (faithfulness, context precision/recall) + custom detection eval
- Observability: Langfuse (OSS) or LangSmith
- Serving: FastAPI backend + async worker
- Delivery: GitHub App / webhook that scans PRs, + Streamlit/Next.js dashboard
- Infra: Docker + docker-compose; GitHub Actions with an eval-regression gate

---

## 6. Evaluation harness

Golden dataset: ~20–40 real repositories (or pinned lockfiles) with hand-labeled ground truth of which advisories genuinely apply. Seed with repos that have known documented CVEs, and deliberately include false-positive traps (CVEs against an adjacent version or an unreachable transitive dep).

Metrics tracked in CI: vulnerability detection recall/precision (especially recall on CISA-KEV CVEs and overall precision); false-positive rate vs. a naive "any CVE mentioning this package" baseline (headline number); version-match accuracy; faithfulness/context precision (Ragas); cost & p95 latency per scan.

CI gate: a GitHub Actions job runs the eval set on every PR touching prompts/retrieval; merges blocked if faithfulness or KEV-recall regress below threshold.

---

## 7. How it maps to real AI-engineering JDs

- "Build/productionize RAG pipelines" -> advisory retrieval + reranking over pgvector
- "Design agentic / multi-agent workflows" -> LangGraph triage->remediate->verify graph
- "LLM evaluation, guardrails, hallucination mitigation" -> Verifier + version-range grounding + Ragas
- "LLMOps / observability / CI for LLM apps" -> tracing, cost routing, prompt versioning, eval-regression gate
- "NER / text classification / information extraction" -> advisory NER + triage classifier
- "Ship LLM features as a service" -> FastAPI + GitHub App PR scanner
- "Security / supply-chain awareness" -> the domain itself

---

## 8. Resume-ready impact (measure these — don't invent them)

- "Cut false-positive vulnerability alerts by ~X% vs. naive CVE matching by grounding findings in machine-checked version ranges + EPSS/KEV signal, measured across N labeled repos."
- "Achieved Y% recall on CISA-KEV (known-exploited) CVEs at Z% overall precision."
- "Reduced analyst triage effort from ~A findings to ~B actionable, cited findings per scan."
- "Shipped an eval-regression gate in CI that blocks prompt/retrieval changes dropping faithfulness below 0.9."
- "Cut cost/scan ~40% via retrieval reranking + model routing without measurable quality loss."

Portfolio artifacts: the repo, an architecture diagram, a short write-up ("How I stopped my security agent from crying wolf"), and a 2-minute demo of the GitHub App commenting on a real PR.

---

## 9. 3-month build plan

Month 1 — Data + baseline: NVD/OSV/GHSA delta sync into Postgres+pgvector; lockfile parsers for npm + PyPI; deterministic dependency->CVE matching; deps.dev transitive resolution; baseline RAG retrieval. Exit: lists applicable CVEs for a repo with citations.

Month 2 — Agents + evals: LangGraph graph (Ingest->Triage->Impact->Remediate->Verify->Report); Verifier with version-range grounding + EPSS/KEV enrichment; NER + triage classifier; golden dataset + eval harness; measure false-positive reduction. Exit: measurable precision/recall + working verifier loop.

Month 3 — Productionize: Langfuse tracing, cost routing, prompt versioning; GitHub Actions eval-regression gate; GitHub App / webhook PR-scanning mode; dashboard UI; Docker; write-up + demo. Exit: runs on a live PR and comments a cited, ranked report.

---

## 10. Scope guardrails

- Start with 2 ecosystems (npm, PyPI); design parsers pluggably.
- Reachability starts as a heuristic (direct vs. transitive, is the import present); full call-graph reachability is a stretch goal.
- SBOM/Sigstore/SLSA provenance = stretch, not core.
- Keep the golden set small but honest (20–40 repos); label quality beats quantity.
