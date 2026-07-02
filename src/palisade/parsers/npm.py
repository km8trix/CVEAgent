"""npm package-lock.json parser (lockfileVersion 2/3 preferred, v1 fallback)."""

import json
from typing import Any

from palisade.models.dependency import Dependency, Lockfile


def _parse_v3(packages: dict[str, Any], source_file: str) -> list[Dependency]:
    root = packages.get("", {})
    # Root deps are keyed by the install segment (the alias for aliased installs), not the
    # canonical package name, so direct-ness must be checked against the path segment.
    direct_names = (
        set(root.get("dependencies", {}))
        | set(root.get("devDependencies", {}))
        | set(root.get("optionalDependencies", {}))
        | set(root.get("peerDependencies", {}))
    )
    out: list[Dependency] = []
    for path, info in packages.items():
        if not path.startswith("node_modules/"):
            continue  # root "" entry and monorepo workspace packages (packages/*) are not installs
        if info.get("extraneous") or info.get("link"):
            continue  # undeclared leftovers / workspace symlinks
        version = info.get("version")
        if not version:
            continue
        path_name = path.split("node_modules/")[-1]
        out.append(
            Dependency(
                ecosystem="npm",
                name=info.get("name") or path_name,  # canonical name (handles aliased installs)
                version=version,
                direct=path_name in direct_names,
                depth=path.count("node_modules/"),
                source_file=source_file,
            )
        )
    return out


def _parse_v1(dependencies: dict[str, Any], source_file: str, depth: int = 0) -> list[Dependency]:
    # NOTE: npm v1/v5/v6 hoists conflict-free transitives to the top level, so direct=depth==0
    # over-classifies hoisted transitives as direct. The deps.dev graph (PR #7) refines this.
    out: list[Dependency] = []
    for name, info in dependencies.items():
        version = info.get("version")
        if version:
            out.append(
                Dependency(
                    ecosystem="npm",
                    name=name,
                    version=version,
                    direct=depth == 0,
                    depth=depth,
                    source_file=source_file,
                )
            )
        nested = info.get("dependencies")
        if nested:
            out.extend(_parse_v1(nested, source_file, depth + 1))
    return out


def parse_package_lock(lockfile: Lockfile) -> list[Dependency]:
    data = json.loads(lockfile.raw)
    packages = data.get("packages")
    if packages is not None:
        return _parse_v3(packages, lockfile.path)
    return _parse_v1(data.get("dependencies") or {}, lockfile.path)
