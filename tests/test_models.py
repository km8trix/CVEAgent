from datetime import datetime

from palisade.models.advisory import (
    AdvisoryRecord,
    AffectedPackage,
    Event,
    Range,
    Severity,
)
from palisade.models.dependency import Dependency, DependencyGraph
from palisade.models.finding import Finding, Remediation, VerifierVerdict


def _advisory() -> AdvisoryRecord:
    return AdvisoryRecord(
        id="osv-1",
        source="osv",
        source_id="GHSA-xxxx",
        summary="test",
        details="test details",
        severity=Severity(cvss_score=7.5, bucket="high"),
        affected=[
            AffectedPackage(
                ecosystem="PyPI",
                name="requests",
                ranges=[
                    Range(type="ECOSYSTEM", events=[Event(introduced="0"), Event(fixed="2.32.0")])
                ],
            )
        ],
        published=datetime(2024, 1, 1),
        modified=datetime(2024, 1, 2),
        content_hash="abc",
    )


def test_advisory_roundtrip() -> None:
    adv = _advisory()
    restored = AdvisoryRecord.model_validate(adv.model_dump())
    assert restored == adv
    assert restored.affected[0].ranges[0].events[1].fixed == "2.32.0"


def test_dependency_key() -> None:
    dep = Dependency(
        ecosystem="npm",
        name="lodash",
        version="4.17.20",
        direct=True,
        source_file="package-lock.json",
    )
    assert dep.key == "npm:lodash@4.17.20"


def test_dependency_graph_defaults() -> None:
    graph = DependencyGraph(target="repo", ecosystem="npm", dependencies=[])
    assert graph.edges == []


def test_finding_defaults() -> None:
    dep = Dependency(
        ecosystem="PyPI",
        name="requests",
        version="2.31.0",
        direct=True,
        source_file="requirements.txt",
    )
    finding = Finding(
        dependency=dep,
        advisory_id="osv-1",
        installed_version="2.31.0",
        is_affected=True,
        remediation=Remediation(type="upgrade", summary="bump to 2.32.0", upgrade_to="2.32.0"),
        verdict=VerifierVerdict(
            passed=True, version_in_range=True, all_claims_cited=True, severity_consistent=True
        ),
    )
    assert finding.reachability == "unknown"
    assert finding.kev_listed is False
    assert finding.rank_score == 0.0
