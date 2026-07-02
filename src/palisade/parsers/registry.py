"""Filename -> parser dispatch. Kept as a plain dict until a third ecosystem needs more."""

from pathlib import Path

from palisade.models.dependency import Dependency, Lockfile
from palisade.parsers.base import LockfileParser
from palisade.parsers.npm import parse_package_lock
from palisade.parsers.pypi import parse_poetry_lock, parse_requirements

_KIND_BY_FILENAME: dict[str, str] = {
    "package-lock.json": "package-lock",
    "requirements.txt": "requirements",
    "poetry.lock": "poetry-lock",
}

_PARSERS: dict[str, LockfileParser] = {
    "package-lock": parse_package_lock,
    "requirements": parse_requirements,
    "poetry-lock": parse_poetry_lock,
}


def load_lockfile(path: str) -> Lockfile:
    """Build a Lockfile from a filesystem path, inferring kind from the basename."""
    name = Path(path).name
    kind = _KIND_BY_FILENAME.get(name)
    if kind is None:
        raise ValueError(f"unsupported lockfile: {name}")
    raw = Path(path).read_text(encoding="utf-8")
    return Lockfile(path=path, kind=kind, raw=raw)  # type: ignore[arg-type]


def parse_lockfile(lockfile: Lockfile) -> list[Dependency]:
    parser = _PARSERS.get(lockfile.kind)
    if parser is None:
        raise ValueError(f"no parser for lockfile kind: {lockfile.kind}")
    return parser(lockfile)
