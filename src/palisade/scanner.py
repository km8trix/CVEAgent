"""End-to-end scan (M1 exit): lockfile -> deps -> OSV candidates -> deterministic match ->
EPSS/KEV enrich -> ranked, cited ScanReport.

OSV is the candidate source (server-side version matching); the local deterministic matcher
independently re-verifies each hit. RAG retrieval/embeddings (the M2 Impact agent) are deferred.
See IMPLEMENTATION_PLAN.md §4/§9.
"""

import asyncio
import logging
import time
from datetime import UTC, date, datetime
from typing import Any, Protocol
from uuid import uuid4

from palisade.clients.osv import OsvClient
from palisade.enrichment.enrich import enrich_findings
from palisade.enrichment.epss import download_epss, load_epss
from palisade.enrichment.kev import download_kev, load_kev
from palisade.ingestion.normalize import normalize_osv
from palisade.matching.matcher import match
from palisade.models.advisory import AdvisoryRecord, Ecosystem
from palisade.models.dependency import Dependency, Lockfile
from palisade.models.finding import ScanReport
from palisade.parsers.registry import load_lockfile, lockfile_from_content, parse_lockfile

logger = logging.getLogger(__name__)

_Epss = dict[str, tuple[float, float]]
_Kev = dict[str, date]

_KIND_TO_ECOSYSTEM: dict[str, Ecosystem] = {
    "requirements": "PyPI",
    "poetry-lock": "PyPI",
    "package-lock": "npm",
    "pnpm-lock": "npm",
}


class OsvSource(Protocol):
    async def query_batch(self, queries: list[dict[str, Any]]) -> list[list[dict[str, Any]]]: ...
    async def get_vuln(self, vuln_id: str) -> dict[str, Any]: ...
    async def aclose(self) -> None: ...


# ponytail: process-global feed cache, no TTL; refresh via restart or the M3 worker.
_epss_cache: _Epss | None = None
_kev_cache: _Kev | None = None
_feed_lock = asyncio.Lock()


async def _cached_feeds() -> tuple[_Epss, _Kev]:
    global _epss_cache, _kev_cache
    if _epss_cache is not None and _kev_cache is not None:
        return _epss_cache, _kev_cache  # fast path: no lock once warm
    async with _feed_lock:
        if _epss_cache is None:
            _epss_cache = load_epss(await download_epss())
        if _kev_cache is None:
            _kev_cache = load_kev(await download_kev())
        return _epss_cache, _kev_cache


async def _fetch_one(osv: OsvSource, vuln_id: str) -> AdvisoryRecord | None:
    try:
        return normalize_osv(await osv.get_vuln(vuln_id))
    except ValueError as exc:
        if "withdrawn" in str(exc):
            logger.debug("skipping withdrawn advisory %s", vuln_id)
        else:
            logger.warning("skipping malformed advisory %s: %s", vuln_id, exc)
        return None


async def _fetch_advisories(deps: list[Dependency], osv: OsvSource) -> list[AdvisoryRecord]:
    ids: set[str] = set()
    for i in range(0, len(deps), 1000):  # querybatch caps at 1000 queries
        chunk = deps[i : i + 1000]
        queries = [
            {"version": d.version, "package": {"name": d.name, "ecosystem": d.ecosystem}}
            for d in chunk
        ]
        for hits in await osv.query_batch(queries):
            ids.update(v["id"] for v in hits)
    # Independent fetches; the client's token bucket paces them at the rate limit.
    fetched = await asyncio.gather(*(_fetch_one(osv, vid) for vid in sorted(ids)))
    return [adv for adv in fetched if adv is not None]


def build_report(
    target: str,
    ecosystem: str,
    deps: list[Dependency],
    advisories: list[AdvisoryRecord],
    epss: _Epss,
    kev: _Kev,
) -> ScanReport:
    findings = match(deps, advisories)
    enrich_findings(findings, epss, kev)
    findings.sort(key=lambda f: f.rank_score, reverse=True)
    stats: dict[str, Any] = {
        "total_dependencies": len(deps),
        "findings": len(findings),
        "kev_findings": sum(1 for f in findings if f.kev_listed),
        "affected_packages": len({f.dependency.name for f in findings}),
    }
    return ScanReport(
        scan_id=str(uuid4()),
        target=target,
        created_at=datetime.now(UTC),
        ecosystem=ecosystem,
        findings=findings,
        stats=stats,
    )


async def scan(
    lockfile: Lockfile,
    *,
    osv: OsvSource | None = None,
    epss: _Epss | None = None,
    kev: _Kev | None = None,
) -> ScanReport:
    start = time.monotonic()
    deps = parse_lockfile(lockfile)
    ecosystem = deps[0].ecosystem if deps else _KIND_TO_ECOSYSTEM.get(lockfile.kind, "PyPI")
    owns = osv is None
    osv = osv or OsvClient()
    try:
        advisories = await _fetch_advisories(deps, osv)
    finally:
        if owns:
            await osv.aclose()
    if epss is None or kev is None:
        cached_epss, cached_kev = await _cached_feeds()
        epss = epss if epss is not None else cached_epss
        kev = kev if kev is not None else cached_kev
    report = build_report(lockfile.path, ecosystem, deps, advisories, epss, kev)
    report.latency_ms = int((time.monotonic() - start) * 1000)
    return report


async def scan_content(filename: str, content: str, **kwargs: Any) -> ScanReport:
    return await scan(lockfile_from_content(filename, content), **kwargs)


async def scan_path(path: str, **kwargs: Any) -> ScanReport:
    return await scan(load_lockfile(path), **kwargs)
