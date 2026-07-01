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

> The GitHub repo is named **CVEAgent**; **Palisade** is the product/package name used
> throughout the code and docs.

## Status

🚧 Early development. PR #1 (scaffold) is the first slice of Milestone M1.

- **Project spec:** [`docs/palisade-project-spec.md`](docs/palisade-project-spec.md)
- **Implementation plan:** [`IMPLEMENTATION_PLAN.md`](IMPLEMENTATION_PLAN.md)

## Local development

Requires [uv](https://docs.astral.sh/uv/) and Docker.

```bash
make install     # create .venv and install deps (uv provisions Python 3.12)
make up-db       # start Postgres + pgvector
make run         # run the API with reload -> http://localhost:8000/health
make test        # pytest
make lint        # ruff + mypy
```

`make up` runs the full stack (Postgres + API) in Docker. Copy `.env.example` to `.env`
for local config; the real `.env` is gitignored.

## Stack (planned)

FastAPI backend · LangGraph agent graph · Postgres + pgvector · async ingestion workers ·
Ragas + custom eval harness with a CI eval-regression gate.

## License

TBD.
