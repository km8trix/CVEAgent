import asyncio
import json
from pathlib import Path
from typing import Any, cast

import httpx
from tenacity import wait_none

from palisade.clients.osv import OsvClient

FIXTURE = Path(__file__).parent / "fixtures" / "osv_pypi_example.json"


def _record() -> dict[str, Any]:
    return cast(dict[str, Any], json.loads(FIXTURE.read_text()))


def test_osv_query_returns_vulns() -> None:
    record = _record()

    def handler(request: httpx.Request) -> httpx.Response:
        assert request.url.path == "/v1/query"
        assert json.loads(request.content)["package"]["ecosystem"] == "PyPI"
        return httpx.Response(200, json={"vulns": [record]})

    async def run() -> list[dict[str, Any]]:
        client = OsvClient(transport=httpx.MockTransport(handler))
        try:
            return await client.query("jinja2", "3.1.2", "PyPI")
        finally:
            await client.aclose()

    vulns = asyncio.run(run())
    assert len(vulns) == 1
    assert vulns[0]["id"] == "GHSA-h5c8-rqwp-cp95"


def test_osv_retries_on_503() -> None:
    calls = {"n": 0}

    def handler(request: httpx.Request) -> httpx.Response:
        calls["n"] += 1
        if calls["n"] < 3:
            return httpx.Response(503)
        return httpx.Response(200, json={"vulns": []})

    async def run() -> list[dict[str, Any]]:
        client = OsvClient(transport=httpx.MockTransport(handler))
        client._wait = wait_none()  # no backoff sleeps in the test
        try:
            return await client.query("x", "1.0.0", "PyPI")
        finally:
            await client.aclose()

    vulns = asyncio.run(run())
    assert calls["n"] == 3
    assert vulns == []
