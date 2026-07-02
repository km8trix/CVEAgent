"""Build a DependencyGraph from a deps.dev :dependencies response (nodes/edges) and resolve
one live. Used when the input is a root package rather than a fully-resolved lockfile, and to
refine direct-vs-transitive for ecosystems whose lockfiles do not encode it (PyPI).

Prefer the context-manager form when passing your own client:
    async with DepsDevClient() as c:
        graph = await resolve("PyPI", "flask", "3.0.0", client=c)
See IMPLEMENTATION_PLAN.md §4.2.
"""

from collections import deque
from typing import Any

from palisade.clients.depsdev import DepsDevClient
from palisade.models.advisory import Ecosystem
from palisade.models.dependency import Dependency, DependencyGraph


def build_dependency_graph(
    ecosystem: Ecosystem, target: str, raw: dict[str, Any]
) -> DependencyGraph:
    nodes = raw.get("nodes", [])
    raw_edges = raw.get("edges", [])

    # A malformed response (edge -> non-existent node) becomes a clear error, not an IndexError.
    for edge in raw_edges:
        for idx in (edge["fromNode"], edge["toNode"]):
            if not isinstance(idx, int) or idx < 0 or idx >= len(nodes):
                raise ValueError(f"deps.dev edge references out-of-range node index {idx}")

    adjacency: dict[int, list[int]] = {}
    for edge in raw_edges:
        adjacency.setdefault(edge["fromNode"], []).append(edge["toNode"])

    root = next((i for i, n in enumerate(nodes) if n.get("relation") == "SELF"), None)
    if root is None:
        if nodes:
            raise ValueError("deps.dev response has no SELF node")
        return DependencyGraph(target=target, ecosystem=ecosystem, dependencies=[], edges=[])

    depth = {root: 0}
    queue = deque([root])
    while queue:  # visited-guard makes this terminate even on cyclic graphs
        cur = queue.popleft()
        for nxt in adjacency.get(cur, []):
            if nxt not in depth:
                depth[nxt] = depth[cur] + 1
                queue.append(nxt)

    def _key(index: int) -> str:
        vk = nodes[index]["versionKey"]
        return f"{vk['system']}:{vk['name']}@{vk['version']}"

    dependencies: list[Dependency] = []
    for i, node in enumerate(nodes):
        if node.get("relation") == "SELF":
            continue
        vk = node["versionKey"]
        dependencies.append(
            Dependency(
                ecosystem=ecosystem,
                name=vk["name"],
                version=vk["version"],
                direct=node.get("relation") == "DIRECT",
                depth=depth.get(i, 0),
                source_file=target,
            )
        )
    edges = [(_key(e["fromNode"]), _key(e["toNode"])) for e in raw_edges]
    return DependencyGraph(
        target=target, ecosystem=ecosystem, dependencies=dependencies, edges=edges
    )


async def resolve(
    ecosystem: Ecosystem, name: str, version: str, *, client: DepsDevClient | None = None
) -> DependencyGraph:
    owns = client is None
    client = client or DepsDevClient()
    try:
        raw = await client.get_dependencies(ecosystem, name, version)
    finally:
        if owns:
            await client.aclose()
    return build_dependency_graph(ecosystem, f"{ecosystem}:{name}@{version}", raw)
