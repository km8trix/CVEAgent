"""Deterministic version-range membership — the grounding core (IMPLEMENTATION_PLAN.md §4/§5).

PyPI uses PEP 440 (packaging); npm uses semver. An OSV range is an ordered list of
introduced/fixed/last_affected events; a version is affected iff it falls in an
[introduced, fixed) interval (or <= last_affected). Only version-comparable range types
are considered — GIT ranges carry commit hashes, not versions — and any range with an
unparseable boundary is skipped. Unparseable installed versions never match. All of this
is conservative on purpose: the project's thesis is false-positive reduction.
"""

import logging
from collections.abc import Iterable
from functools import cmp_to_key

from packaging.version import InvalidVersion
from packaging.version import Version as PypiVersion
from semver import Version as SemverVersion

from palisade.models.advisory import AffectedPackage, Event, Range

logger = logging.getLogger(__name__)

# GIT ranges use commit shas, not versions; only these types are version-comparable.
_VERSION_RANGE_TYPES = {"ECOSYSTEM", "SEMVER"}


def _compare(ecosystem: str, a: str, b: str) -> int | None:
    """sign(a - b), or None if either version is unparseable for the ecosystem."""
    try:
        if ecosystem == "PyPI":
            pa, pb = PypiVersion(a), PypiVersion(b)
            return (pa > pb) - (pa < pb)
        sa, sb = SemverVersion.parse(a), SemverVersion.parse(b)
        return (sa > sb) - (sa < sb)
    except (InvalidVersion, ValueError):
        return None


def _parseable(ecosystem: str, version: str) -> bool:
    try:
        PypiVersion(version) if ecosystem == "PyPI" else SemverVersion.parse(version)
        return True
    except (InvalidVersion, ValueError):
        return False


def _ge(ecosystem: str, a: str, b: str) -> bool:
    cmp = _compare(ecosystem, a, b)
    return cmp is not None and cmp >= 0


def _gt(ecosystem: str, a: str, b: str) -> bool:
    cmp = _compare(ecosystem, a, b)
    return cmp is not None and cmp > 0


def _range_comparable(ecosystem: str, events: list[Event]) -> bool:
    """Every non-sentinel boundary must parse; otherwise the range is unreliable and skipped
    (prevents a stale affected=True when a `fixed` boundary can't be compared)."""
    for event in events:
        for boundary in (event.introduced, event.fixed, event.last_affected):
            if boundary is not None and boundary != "0" and not _parseable(ecosystem, boundary):
                return False
    return True


def _events_match(ecosystem: str, version: str, events: list[Event]) -> bool:
    if not _range_comparable(ecosystem, events):
        logger.warning("skipping advisory range with an unparseable version boundary")
        return False
    affected = False
    for event in events:  # OSV emits events in ascending order within a range
        if event.introduced is not None:
            if event.introduced == "0" or _ge(ecosystem, version, event.introduced):
                affected = True
        elif event.fixed is not None:
            if _ge(ecosystem, version, event.fixed):
                affected = False
        elif event.last_affected is not None:
            if _gt(ecosystem, version, event.last_affected):
                affected = False
    return affected


def is_version_affected(ecosystem: str, version: str, affected: AffectedPackage) -> bool:
    if version in affected.versions:
        return True
    if not _parseable(ecosystem, version):
        return False
    return any(
        _events_match(ecosystem, version, rng.events)
        for rng in affected.ranges
        if rng.type in _VERSION_RANGE_TYPES
    )


def matching_range(ecosystem: str, version: str, affected: AffectedPackage) -> Range | None:
    """The first version-comparable range whose interval contains `version` (for citation)."""
    if not _parseable(ecosystem, version):
        return None
    for rng in affected.ranges:
        if rng.type in _VERSION_RANGE_TYPES and _events_match(ecosystem, version, rng.events):
            return rng
    return None


def smallest_above(ecosystem: str, version: str, candidates: Iterable[str]) -> str | None:
    """Lowest candidate strictly greater than `version` by ecosystem version order, or None.

    Grounds an upgrade target in the same parsed-version logic as matching — never a lexical
    sort (which would rank 10.0.1 below 9.0.1, or a prerelease below its release).
    """
    above = [c for c in candidates if _gt(ecosystem, c, version)]
    if not above:
        return None

    def _cmp(a: str, b: str) -> int:
        return _compare(ecosystem, a, b) or 0  # both parseable here (passed _gt above)

    return min(above, key=cmp_to_key(_cmp))


def smallest_fixed_above(ecosystem: str, version: str, rng: Range) -> str | None:
    """Lowest `fixed` boundary in `rng` greater than `version` — the minimal safe upgrade target."""
    return smallest_above(ecosystem, version, [e.fixed for e in rng.events if e.fixed])
