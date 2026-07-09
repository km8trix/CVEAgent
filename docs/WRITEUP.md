# How I stopped my security agent from crying wolf

Most dependency scanners have the same failure mode: they cry wolf. Point one at a repo and it
returns a wall of "vulnerable" packages, most of which don't apply — the CVE is against a version
you don't run, or a code path you never import, or it's a decade-old advisory with no real exploit
signal. The security team learns to ignore the tool, and then misses the one alert that mattered.

Palisade is my attempt to build the opposite: a scanner whose findings you can trust *because it
can prove each one*. This is the story of how it works and, more usefully, the bug it caught in
its own truth-checker.

## The baseline is the villain

To measure "crying wolf" you need something to compare against. Palisade's baseline is deliberately
the dumbest thing that ships in a lot of real tooling: **flag every advisory that mentions the
package name, ignoring the installed version entirely.**

On six small golden cases (npm + PyPI, each in a vulnerable and a patched variant), that naive
baseline raises **18 false positives** — advisories for versions the lockfile doesn't contain, or
packages that were already patched. Eighteen alerts a human has to triage to zero. That's the wolf.

Palisade brings it to **0 false positives** on the same set: a **100% reduction**, with precision,
recall, KEV-recall, and version-match accuracy all at 1.00. You can reproduce every number offline,
no API keys and no network, because the golden advisories are pinned into the repo:

```bash
uv run python -m evals.run_eval
```

(The honest caveat — [`evals/README.md`](../evals/README.md) — is that precision/recall here measure
*agreement with OSV's own authoritative version matching*, since Palisade re-verifies OSV. The
independent headline is the FP-reduction number and the Verifier metrics below. A larger,
hand-labeled adversarial set is the obvious next step.)

## The thesis: deterministic before probabilistic

The reason naive scanners over-alert is that they answer the wrong question. "Does this advisory
mention lodash?" is easy and useless. "Is *this installed version* of lodash inside *this
advisory's affected range*?" is the question that matters, and it has a deterministic, testable
answer.

So Palisade's whole design is: **the LLM never decides whether something is vulnerable.** That
verdict comes from pure functions — version-range membership (`packaging` for PyPI, a
node-semver-compatible check for npm), EPSS/KEV lookups, and a rank score — each with the heaviest
unit tests in the repo. The advisory corpus (OSV, plus NVD and GHSA normalized into the OSV schema)
and the exploit-signal feeds (EPSS, CISA KEV) are bulk-synced daily and looked up locally.

The LLM does exactly one job: in the **Remediate** node it drafts the human-readable "here's what
to do and why" prose, with citations. And even there it's on a short leash:

- The **fix type and target version are computed deterministically** — the model never picks the
  version to upgrade to.
- A **grounding guard** discards any draft that doesn't actually name the computed fix.
- Untrusted advisory text is delimited before it reaches the prompt.

That leaves one residual risk: the model can still *write a sentence that cites a source that
doesn't exist.* Which is where the Verifier comes in.

## The Verifier: an agent that doesn't trust the other agents

The graph is a LangGraph state machine — `Ingest → Triage → Impact → Remediate → Verify → Report`
— but the interesting node is **Verify**. It refuses to trust anything upstream and independently
re-derives each finding from the raw advisory, running three checks:

1. **Version in range.** Re-check the installed version against the advisory's affected ranges from
   scratch, ignoring the matcher's earlier verdict. If it can't independently confirm the version
   is affected, the finding dies.
2. **All claims cited.** Every citation on the finding *and its remediation* must be a subset of the
   advisory's own references. This is the tripwire for a hallucinated source — the precise failure
   mode of an LLM drafting security prose.
3. **Severity consistent.** The finding's rank score must re-compute from its own EPSS/KEV/severity
   signals. A rank that's out of step with its inputs (a reordered or tampered report) fails.

A finding ships only if all three hold. Otherwise it loops back to Impact for a bounded re-draft,
and if it still can't pass, it's dropped with a reason. The rule is absolute: **never ship an
unverified finding.**

I tested this against a drafter that deliberately fabricates citations — a stand-in for a
hallucinating LLM, run with no API key so the eval stays deterministic. Across **30 findings**, the
Verifier's hallucinated-citation **catch rate was 1.00**, with **0 false rejections** of legitimate
findings. That last number matters as much as the first: a truth-checker that rejects real findings
is just a different way of crying wolf.

## The bug in the truth-checker

Here's the part I didn't expect. When I built the Verifier-effectiveness eval, it immediately
caught a bug — not in the LLM, but in the Verifier itself.

The "version in range" check originally looked at only the *first* affected-package entry with a
matching name. But an advisory can list the same package more than once, with different ranges.
`GHSA-hrfv-mqp8-q5rw` lists **werkzeug twice**. A genuinely vulnerable werkzeug whose version fell
in the *second* range was being independently "verified" as *not* affected — and dropped. My
truth-checker was quietly crying wolf in reverse, throwing away real findings.

The fix was one word — check whether **any** same-named entry contains the version, not just the
first — mirroring exactly what the deterministic matcher already did. The lesson wasn't the fix; it
was that the eval harness earned its keep on day one by finding a correctness bug in the component
whose entire job is correctness.

## Where it runs

The same verified report drives every surface: a `palisade scan` CLI, an async `POST /scan` API
backed by a Postgres queue and worker, a **GitHub PR webhook** that comments a ranked, cited report
on opened and synchronized PRs (HMAC-verified, upserting a single comment), and a read-only
Streamlit dashboard over the scans table. Building the PR-webhook against live OSV data caught
another real-world wrinkle — an internal `osv:` id prefix that produced broken advisory links — the
kind of thing you only find by running on real data, which is why every PR in this project is
verified against live feeds before it merges.

Changes that touch matching, enrichment, the agent nodes, or the scanner are gated in CI by an
**eval-regression gate**: the golden eval runs against pinned fixtures and blocks the PR if any
metric regresses or the Verifier starts falsely rejecting findings.

## What's still open

The honest to-do list:

- **Langfuse tracing + per-scan LLM cost** — the tracer and token-cost plumbing (deterministic
  scans are already $0; LLM token usage isn't yet surfaced into `cost_usd`).
- **Ragas faithfulness / context-precision** in the eval, enforced at ≥ 0.9 in the gate.
- **A bigger, hand-labeled adversarial golden set** — the current six cases prove the mechanism;
  scale and independent labels would strengthen the precision/recall story.

But the core thesis is already load-bearing and measured: a security agent that never *decides*
vulnerability probabilistically, checks its own work independently, and drops anything it can't
prove — is an agent that stops crying wolf.
