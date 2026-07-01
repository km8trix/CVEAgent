"""OSV.dev API client — the primary version-matching source. https://osv.dev/docs/"""

from typing import Any

import httpx

from palisade.clients.base import BaseClient

OSV_BASE_URL = "https://api.osv.dev"


class OsvClient(BaseClient):
    def __init__(self, *, transport: httpx.AsyncBaseTransport | None = None) -> None:
        super().__init__(OSV_BASE_URL, rate=10.0, capacity=10.0, transport=transport)

    async def query(self, name: str, version: str, ecosystem: str) -> list[dict[str, Any]]:
        """Full advisory records affecting {ecosystem, name} at `version`."""
        payload = {"version": version, "package": {"name": name, "ecosystem": ecosystem}}
        data = await self.post_json("/v1/query", json=payload)
        return list(data.get("vulns", []))

    async def query_batch(self, queries: list[dict[str, Any]]) -> list[list[dict[str, Any]]]:
        """Batch query (<=1000). Returns per-query lists of vuln stubs, aligned to `queries`."""
        data = await self.post_json("/v1/querybatch", json={"queries": queries})
        results = data.get("results", [])
        if len(results) != len(queries):
            raise ValueError(
                f"OSV querybatch returned {len(results)} results for {len(queries)} queries"
            )
        return [r.get("vulns", []) for r in results]

    async def get_vuln(self, vuln_id: str) -> dict[str, Any]:
        """Fetch one full OSV record by id."""
        return dict(await self.get_json(f"/v1/vulns/{vuln_id}"))
