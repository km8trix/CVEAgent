"""CISA Known Exploited Vulnerabilities — single JSON feed, looked up locally.

The strongest "act now" signal. See IMPLEMENTATION_PLAN.md §5.
"""

import json
from datetime import date

import httpx

KEV_URL = "https://www.cisa.gov/sites/default/files/feeds/known_exploited_vulnerabilities.json"


async def download_kev(*, client: httpx.AsyncClient | None = None) -> bytes:
    owns = client is None
    client = client or httpx.AsyncClient(timeout=120.0, follow_redirects=True)
    try:
        resp = await client.get(KEV_URL)
        try:
            resp.raise_for_status()
        except httpx.HTTPStatusError as exc:
            raise RuntimeError(f"KEV feed returned {exc.response.status_code}") from exc
        return resp.content
    finally:
        if owns:
            await client.aclose()


def load_kev(data: bytes) -> dict[str, date]:
    """Parse the KEV feed into cve -> date_added. Malformed entries are skipped."""
    obj = json.loads(data)
    kev: dict[str, date] = {}
    for entry in obj.get("vulnerabilities", []):
        cve = entry.get("cveID")
        added = entry.get("dateAdded")
        if not cve or not added:
            continue
        try:
            kev[cve] = date.fromisoformat(added[:10])  # tolerate a time suffix
        except ValueError:
            continue
    return kev
