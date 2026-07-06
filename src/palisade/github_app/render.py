"""Render a ScanReport as a GitHub PR comment (Markdown). Pure — no I/O.

MARKER is a hidden HTML comment on the first line so the webhook can find and update its
own previous comment on a new push instead of stacking a fresh one on every commit.
"""

from palisade.models.finding import Finding, ScanReport

MARKER = "<!-- palisade-scan -->"
_MAX_ROWS = 25  # ponytail: top-25 rows; add detail links/pagination if reports get large
_OSV_URL = "https://osv.dev/vulnerability/{}"
_HEADER = "| Package | Advisory | Severity | EPSS | KEV | Fix |\n|---|---|---|---|---|---|"


def _fix(f: Finding) -> str:
    if f.remediation and f.remediation.upgrade_to:
        return f"`{f.remediation.upgrade_to}`"
    return f"`{f.fixed_versions[0]}`" if f.fixed_versions else "—"


def _epss(f: Finding) -> str:
    return f"{f.epss_percentile:.0%}" if f.epss_percentile is not None else "—"


def _osv_id(advisory_id: str) -> str:
    # Findings carry the internal id ("osv:GHSA-...", "osv:PYSEC-..."); OSV's canonical URL and
    # a clean display both want the bare source id, so drop the "<source>:" prefix.
    return advisory_id.split(":", 1)[-1]


def _row(f: Finding) -> str:
    aid = _osv_id(f.advisory_id)
    adv = f"[{aid}]({_OSV_URL.format(aid)})"
    kev = "🔴 **yes**" if f.kev_listed else "no"
    sev = f.severity_bucket or "—"
    return (
        f"| `{f.dependency.name}` {f.installed_version} | {adv} | {sev} "
        f"| {_epss(f)} | {kev} | {_fix(f)} |"
    )


def render_section(report: ScanReport) -> str:
    if not report.findings:
        return f"### ✅ `{report.target}` — no known-vulnerable dependencies"
    n = len(report.findings)
    kev = sum(1 for f in report.findings if f.kev_listed)
    head = (
        f"### `{report.target}` ({report.ecosystem}) — "
        f"**{n}** finding{'s' if n != 1 else ''}" + (f", **{kev}** in CISA KEV" if kev else "")
    )
    rows = [_row(f) for f in report.findings[:_MAX_ROWS]]
    body = "\n".join([head, "", _HEADER, *rows])
    if n > _MAX_ROWS:
        body += f"\n\n_…and {n - _MAX_ROWS} more, ranked lower._"
    return body


def render_comment(reports: list[ScanReport]) -> str:
    """One comment for the whole PR: a summary line plus a section per scanned lockfile."""
    total = sum(len(r.findings) for r in reports)
    n_files = len(reports)
    title = f"{MARKER}\n## 🛡️ Palisade — dependency scan"
    summary = (
        "No known-vulnerable dependencies found. ✅"
        if total == 0
        else f"Found **{total}** finding{'s' if total != 1 else ''} across "
        f"{n_files} lockfile{'s' if n_files != 1 else ''}."
    )
    sections = "\n\n".join(render_section(r) for r in reports)
    footer = (
        "<sub>Installed versions are machine-checked in range — findings are "
        "deterministically verified, not just name-matched. via "
        "[palisade](https://github.com/km8trix/CVEAgent)</sub>"
    )
    return "\n\n".join([title, summary, sections, footer])
