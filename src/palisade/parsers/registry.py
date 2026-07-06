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

# Public: basenames we can scan (used to filter a PR's changed files).
LOCKFILE_FILENAMES = frozenset(_KIND_BY_FILENAME)

_PARSERS: dict[str, LockfileParser] = {
    "package-lock": parse_package_lock,
    "requirements": parse_requirements,
    "poetry-lock": parse_poetry_lock,
}


def lockfile_from_content(filename: str, content: str) -> Lockfile:
    """Build a Lockfile from in-memory content, inferring kind from the basename."""
    kind = _KIND_BY_FILENAME.get(Path(filename).name)
    if kind is None:
        raise ValueError(f"unsupported lockfile: {Path(filename).name}")
    return Lockfile(path=filename, kind=kind, raw=content)  # type: ignore[arg-type]


def load_lockfile(path: str) -> Lockfile:
    """Read a lockfile from disk. Validates the kind before reading."""
    if Path(path).name not in _KIND_BY_FILENAME:
        raise ValueError(f"unsupported lockfile: {Path(path).name}")
    return lockfile_from_content(path, Path(path).read_text(encoding="utf-8"))


def parse_lockfile(lockfile: Lockfile) -> list[Dependency]:
    parser = _PARSERS.get(lockfile.kind)
    if parser is None:
        raise ValueError(f"no parser for lockfile kind: {lockfile.kind}")
    return parser(lockfile)
