import asyncio
from typing import Any

import httpx
import pytest

from palisade.clients.depsdev import DepsDevClient
from palisade.matching.reachability import reachability, refine_directness
from palisade.models.dependency import Dependency
from palisade.resolve import build_dependency_graph

_RAW: dict[str, Any] = {
    "nodes": [
        {"versionKey": {"system": "PYPI", "name": "flask", "version": "3.0.0"}, "relation": "SELF"},
        {
            "versionKey": {"system": "PYPI", "name": "werkzeug", "version": "3.0.1"},
            "relation": "DIRECT",
        },
        {
            "versionKey": {"system": "PYPI", "name": "markupsafe", "version": "2.1.3"},
            "relation": "INDIRECT",
        },
    ],
    "edges": [
        {"fromNode": 0, "toNode": 1},
        {"fromNode": 1, "toNode": 2},
    ],
}


def test_build_graph_relations_depth_edges() -> None:
    graph = build_dependency_graph("PyPI", "PyPI:flask@3.0.0", _RAW)
    by_name = {d.name: d for d in graph.dependencies}
    assert "flask" not in by_name  # SELF (root) excluded
    assert by_name["werkzeug"].direct is True
    assert by_name["werkzeug"].depth == 1
    assert by_name["markupsafe"].direct is False
    assert by_name["markupsafe"].depth == 2
    assert ("PYPI:werkzeug@3.0.1", "PYPI:markupsafe@2.1.3") in graph.edges  # keys include system


def test_build_graph_handles_cycle() -> None:
    raw: dict[str, Any] = {
        "nodes": [
            {"versionKey": {"system": "NPM", "name": "a", "version": "1.0.0"}, "relation": "SELF"},
            {
                "versionKey": {"system": "NPM", "name": "b", "version": "1.0.0"},
                "relation": "DIRECT",
            },
            {
                "versionKey": {"system": "NPM", "name": "c", "version": "1.0.0"},
                "relation": "INDIRECT",
            },
        ],
        "edges": [
            {"fromNode": 0, "toNode": 1},
            {"fromNode": 1, "toNode": 2},
            {"fromNode": 2, "toNode": 1},
        ],
    }
    graph = build_dependency_graph("npm", "t", raw)  # must terminate despite the b<->c cycle
    by_name = {d.name: d for d in graph.dependencies}
    assert by_name["b"].depth == 1
    assert by_name["c"].depth == 2


def test_build_graph_rejects_out_of_range_edge() -> None:
    raw: dict[str, Any] = {
        "nodes": [
            {"versionKey": {"system": "NPM", "name": "a", "version": "1.0.0"}, "relation": "SELF"}
        ],
        "edges": [{"fromNode": 0, "toNode": 5}],
    }
    with pytest.raises(ValueError, match="out-of-range"):
        build_dependency_graph("npm", "t", raw)


def test_build_graph_requires_self_node() -> None:
    raw: dict[str, Any] = {
        "nodes": [
            {"versionKey": {"system": "NPM", "name": "a", "version": "1.0.0"}, "relation": "DIRECT"}
        ],
        "edges": [],
    }
    with pytest.raises(ValueError, match="SELF"):
        build_dependency_graph("npm", "t", raw)


def test_reachability_classifier() -> None:
    graph = build_dependency_graph("PyPI", "t", _RAW)
    by_name = {d.name: d for d in graph.dependencies}
    assert reachability(by_name["werkzeug"]) == "direct"
    assert reachability(by_name["markupsafe"]) == "transitive"


def test_refine_directness_corrects_lockfile() -> None:
    graph = build_dependency_graph("PyPI", "t", _RAW)
    lockfile = [
        Dependency(
            ecosystem="PyPI", name="markupsafe", version="2.1.3", direct=True, source_file="req"
        ),
        Dependency(
            ecosystem="PyPI", name="unknown-pkg", version="1.0", direct=True, source_file="req"
        ),
    ]
    refined = {d.name: d for d in refine_directness(lockfile, graph)}
    assert refined["markupsafe"].direct is False  # corrected from the graph
    assert refined["unknown-pkg"].direct is True  # not in graph -> unchanged


def test_depsdev_client_builds_url() -> None:
    def handler(request: httpx.Request) -> httpx.Response:
        assert request.url.path == "/v3/systems/pypi/packages/flask/versions/3.0.0:dependencies"
        return httpx.Response(200, json=_RAW)

    async def run() -> dict[str, Any]:
        client = DepsDevClient(transport=httpx.MockTransport(handler))
        try:
            return await client.get_dependencies("PyPI", "flask", "3.0.0")
        finally:
            await client.aclose()

    assert len(asyncio.run(run())["nodes"]) == 3


def test_depsdev_rejects_unknown_ecosystem() -> None:
    async def run() -> None:
        client = DepsDevClient(
            transport=httpx.MockTransport(lambda r: httpx.Response(200, json={}))
        )
        try:
            await client.get_dependencies("Go", "x", "1.0")
        finally:
            await client.aclose()

    with pytest.raises(ValueError, match="unsupported ecosystem"):
        asyncio.run(run())
