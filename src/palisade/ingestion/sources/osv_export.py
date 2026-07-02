"""OSV bulk export: per-ecosystem all.zip from the public GCS bucket.

The export is the full corpus per ecosystem (no incremental API); idempotency is
achieved downstream via content-hash skip-unchanged. See IMPLEMENTATION_PLAN.md section 5.
"""

import io
import json
import zipfile
from collections.abc import Iterator
from typing import Any

import httpx

OSV_EXPORT_URL = "https://osv-vulnerabilities.storage.googleapis.com/{ecosystem}/all.zip"


async def download_export(ecosystem: str, *, client: httpx.AsyncClient | None = None) -> bytes:
    """Download the all.zip for an ecosystem (e.g. 'PyPI', 'npm')."""
    url = OSV_EXPORT_URL.format(ecosystem=ecosystem)
    owns = client is None
    client = client or httpx.AsyncClient(timeout=120.0, follow_redirects=True)
    try:
        resp = await client.get(url)
        resp.raise_for_status()
        return resp.content
    finally:
        if owns:
            await client.aclose()


def iter_records(zip_bytes: bytes) -> Iterator[dict[str, Any]]:
    """Yield each raw OSV record (one JSON file) from an export zip."""
    with zipfile.ZipFile(io.BytesIO(zip_bytes)) as zf:
        for name in zf.namelist():
            if not name.endswith(".json"):
                continue
            with zf.open(name) as f:
                yield json.loads(f.read())
