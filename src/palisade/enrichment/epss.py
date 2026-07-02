"""EPSS (exploit-prediction) scores — FIRST.org daily bulk CSV, looked up locally.

See IMPLEMENTATION_PLAN.md §5: bulk-first, one download/day, local lookups per CVE.
"""

import csv
import gzip
import io

import httpx

EPSS_URL = "https://epss.cyentia.com/epss_scores-current.csv.gz"


async def download_epss(*, client: httpx.AsyncClient | None = None) -> bytes:
    owns = client is None
    client = client or httpx.AsyncClient(timeout=120.0, follow_redirects=True)
    try:
        resp = await client.get(EPSS_URL)
        try:
            resp.raise_for_status()
        except httpx.HTTPStatusError as exc:
            raise RuntimeError(f"EPSS feed returned {exc.response.status_code}") from exc
        return resp.content
    finally:
        if owns:
            await client.aclose()


def load_epss(csv_gz: bytes) -> dict[str, tuple[float, float]]:
    """Parse the gzipped EPSS CSV into cve -> (score, percentile). Malformed rows are skipped."""
    text = gzip.decompress(csv_gz).decode()
    scores: dict[str, tuple[float, float]] = {}
    header_seen = False
    for row in csv.reader(io.StringIO(text)):
        if not row or row[0].startswith("#"):  # leading model-version comment line(s)
            continue
        if not header_seen:  # first non-comment row is the header
            header_seen = True
            if row != ["cve", "epss", "percentile"]:
                raise ValueError(f"unexpected EPSS CSV header: {row}")
            continue
        if len(row) < 3:
            continue
        try:
            scores[row[0]] = (float(row[1]), float(row[2]))
        except ValueError:
            continue  # skip a malformed data row rather than aborting the whole feed
    return scores
