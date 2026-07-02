"""Naive SCA baseline: the "any CVE mentioning this package" matcher Palisade is measured against.

Flags every advisory whose affected package name matches a dependency, ignoring version — the
noise source the version-aware matcher is designed to cut. See IMPLEMENTATION_PLAN.md §6.
"""

from palisade.models.advisory import AdvisoryRecord
from palisade.models.dependency import Dependency
from palisade.parsers.pypi import normalize_name


def _name_key(ecosystem: str, name: str) -> tuple[str, str]:
    return (ecosystem, normalize_name(name) if ecosystem == "PyPI" else name)


def naive_flag(deps: list[Dependency], advisories: list[AdvisoryRecord]) -> set[str]:
    dep_keys = {_name_key(d.ecosystem, d.name) for d in deps}
    flagged: set[str] = set()
    for adv in advisories:
        if any(_name_key(p.ecosystem, p.name) in dep_keys for p in adv.affected):
            flagged.add(adv.id)
    return flagged
