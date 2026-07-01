# Palisade

**A self-verifying, multi-agent software-supply-chain vulnerability intelligence agent.**

Point Palisade at a repository (or a raw lockfile) and it returns a ranked, de-noised,
fully-cited list of the vulnerabilities that *actually* matter for that codebase — plus
concrete, verified remediation steps.

Its thesis is **verifiable grounding**: no dependency is called "vulnerable" unless the
installed version falls inside a machine-checked affected-version range from an authoritative
source (OSV / NVD / GHSA), severity is grounded in real exploit signal (EPSS + CISA KEV),
and a dedicated Verifier agent rejects any unsupported or version-mismatched claim before the
report is returned.

## Status

🚧 Early development — planning phase.

- **Project spec:** [`docs/palisade-project-spec.md`](docs/palisade-project-spec.md)
- **Implementation plan:** [`IMPLEMENTATION_PLAN.md`](IMPLEMENTATION_PLAN.md)

## What's here now

Just the spec and the derived implementation plan. Nothing is built yet — see the plan for
the phased milestone breakdown and the "first 10 PRs" backlog.

## Stack (planned)

FastAPI backend · LangGraph agent graph · Postgres + pgvector · async ingestion workers ·
Ragas + custom eval harness with a CI eval-regression gate.

## License

TBD.
