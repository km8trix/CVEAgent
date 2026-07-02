"""deps.dev API client — resolved transitive dependency graphs. https://docs.deps.dev/api/v3/"""

from typing import Any
from urllib.parse import quote

import httpx

from palisade.clients.base import BaseClient

DEPSDEV_BASE_URL = "https://api.deps.dev"
_SYSTEM = {"npm": "npm", "PyPI": "pypi"}


class DepsDevClient(BaseClient):
    def __init__(self, *, transport: httpx.AsyncBaseTransport | None = None) -> None:
        super().__init__(DEPSDEV_BASE_URL, rate=10.0, capacity=10.0, transport=transport)

    async def get_dependencies(self, ecosystem: str, name: str, version: str) -> dict[str, Any]:
        """The resolved transitive dependency graph (nodes + edges) for a package@version.

        Raises ValueError for an unsupported ecosystem or a package/version deps.dev doesn't know.
        """
        system = _SYSTEM.get(ecosystem)
        if system is None:
            raise ValueError(f"unsupported ecosystem for deps.dev: {ecosystem!r}")
        pkg = quote(name, safe="")  # scoped npm names: @scope/pkg -> %40scope%2Fpkg
        ver = quote(version, safe="")
        path = f"/v3/systems/{system}/packages/{pkg}/versions/{ver}:dependencies"
        try:
            return dict(await self.get_json(path))
        except httpx.HTTPStatusError as exc:
            if exc.response.status_code == 404:
                raise ValueError(f"not found in deps.dev: {ecosystem}:{name}@{version}") from exc
            raise
