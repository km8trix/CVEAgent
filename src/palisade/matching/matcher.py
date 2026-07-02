"""Deterministic dependency x advisory matching -> candidate Findings (IMPLEMENTATION_PLAN.md §4).

The LLM never decides affectedness; this is a pure semver/PEP-440 check.
"""

from collections import defaultdict
from collections.abc import Iterable

from palisade.matching.version import is_version_affected, matching_range
from palisade.models.advisory import AdvisoryRecord, AffectedPackage
from palisade.models.dependency import Dependency
from palisade.models.finding import Finding
from palisade.parsers.pypi import normalize_name


def _name_key(ecosystem: str, name: str) -> tuple[str, str]:
    return (ecosystem, normalize_name(name) if ecosystem == "PyPI" else name)


def _make_finding(dep: Dependency, adv: AdvisoryRecord, pkg: AffectedPackage) -> Finding:
    fixed = sorted({e.fixed for r in pkg.ranges for e in r.events if e.fixed})
    return Finding(
        dependency=dep,
        advisory_id=adv.id,
        matched_range=matching_range(dep.ecosystem, dep.version, pkg),
        installed_version=dep.version,
        fixed_versions=fixed,
        is_affected=True,
        reachability="direct" if dep.direct else "transitive",
        severity_bucket=adv.severity.bucket,
        citations=list(adv.references),
    )


def match(
    dependencies: Iterable[Dependency], advisories: Iterable[AdvisoryRecord]
) -> list[Finding]:
    """Every (dep, advisory) whose installed version is machine-verified in an affected range."""
    index: dict[tuple[str, str], list[tuple[AdvisoryRecord, AffectedPackage]]] = defaultdict(list)
    for adv in advisories:
        for pkg in adv.affected:
            index[_name_key(pkg.ecosystem, pkg.name)].append((adv, pkg))

    findings: list[Finding] = []
    seen: set[tuple[str, str]] = set()
    for dep in dependencies:
        for adv, pkg in index.get(_name_key(dep.ecosystem, dep.name), []):
            if not is_version_affected(dep.ecosystem, dep.version, pkg):
                continue
            key = (dep.key, adv.id)
            if key in seen:
                continue
            seen.add(key)
            findings.append(_make_finding(dep, adv, pkg))
    return findings
