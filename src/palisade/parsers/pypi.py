"""PyPI lockfile parsers: requirements.txt (pinned ==) and poetry.lock (TOML).

requirements.txt and poetry.lock are flat resolved sets that do not reliably encode
direct-vs-transitive, so every entry is marked direct=True; the real graph is refined
by deps.dev transitive resolution in a later PR.
"""

import re
import tomllib

from palisade.models.dependency import Dependency, Lockfile

# name, optional [extras], ==, version — extras are stripped (PEP 508).
_PINNED = re.compile(r"^([A-Za-z0-9._-]+)(?:\[[^\]]*\])?\s*==\s*([^\s;#]+)")


def normalize_name(name: str) -> str:
    """PEP 503 normalization."""
    return re.sub(r"[-_.]+", "-", name).lower()


def parse_requirements(lockfile: Lockfile) -> list[Dependency]:
    out: list[Dependency] = []
    for raw_line in lockfile.raw.splitlines():
        line = raw_line.strip()
        if not line or line.startswith(("#", "-")):
            continue
        match = _PINNED.match(line)
        if not match:
            continue
        out.append(
            Dependency(
                ecosystem="PyPI",
                name=normalize_name(match.group(1)),
                version=match.group(2),
                direct=True,
                source_file=lockfile.path,
            )
        )
    return out


def parse_poetry_lock(lockfile: Lockfile) -> list[Dependency]:
    data = tomllib.loads(lockfile.raw)
    out: list[Dependency] = []
    for pkg in data.get("package", []):
        name = pkg.get("name")
        version = pkg.get("version")
        if not name or not version:
            continue
        out.append(
            Dependency(
                ecosystem="PyPI",
                name=normalize_name(name),
                version=version,
                direct=True,
                source_file=lockfile.path,
            )
        )
    return out
