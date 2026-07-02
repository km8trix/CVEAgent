"""Lockfile parser contract. Parsers are callables Lockfile -> list[Dependency]."""

from typing import Protocol

from palisade.models.dependency import Dependency, Lockfile


class LockfileParser(Protocol):
    def __call__(self, lockfile: Lockfile) -> list[Dependency]: ...
