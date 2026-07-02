"""Reachability heuristic v0 (IMPLEMENTATION_PLAN.md §10).

v0 = direct vs transitive. "Is the import actually present in the source" is a stretch goal
that needs the repo's code, not just a lockfile.
"""

from typing import Literal

from palisade.models.dependency import Dependency, DependencyGraph


def reachability(dep: Dependency) -> Literal["direct", "transitive", "unknown"]:
    return "direct" if dep.direct else "transitive"


def refine_directness(deps: list[Dependency], graph: DependencyGraph) -> list[Dependency]:
    """Correct a flat lockfile's direct flags from a deps.dev graph, keyed by (ecosystem, name).

    requirements.txt / poetry.lock mark everything direct=True; the graph knows better. Matching
    ignores version (a lock may pin a different resolved version) — a documented limitation.
    """
    relation = {(d.ecosystem, d.name): d.direct for d in graph.dependencies}
    return [
        d.model_copy(update={"direct": relation[(d.ecosystem, d.name)]})
        if (d.ecosystem, d.name) in relation
        else d
        for d in deps
    ]
