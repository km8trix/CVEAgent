from datetime import datetime

from palisade.matching.matcher import match
from palisade.matching.version import is_version_affected, matching_range
from palisade.models.advisory import (
    AdvisoryRecord,
    AffectedPackage,
    Ecosystem,
    Event,
    Range,
    Severity,
)
from palisade.models.dependency import Dependency


def _range(*pairs: tuple[str, str]) -> Range:
    events: list[Event] = []
    for kind, ver in pairs:
        if kind == "introduced":
            events.append(Event(introduced=ver))
        elif kind == "fixed":
            events.append(Event(fixed=ver))
        else:
            events.append(Event(last_affected=ver))
    return Range(type="ECOSYSTEM", events=events)


def _affected(
    ecosystem: Ecosystem,
    name: str,
    *,
    ranges: list[Range] | None = None,
    versions: list[str] | None = None,
) -> AffectedPackage:
    return AffectedPackage(
        ecosystem=ecosystem, name=name, ranges=ranges or [], versions=versions or []
    )


# ---------- PyPI (PEP 440) ----------
def test_pypi_in_range_and_fixed_boundary() -> None:
    ap = _affected("PyPI", "jinja2", ranges=[_range(("introduced", "0"), ("fixed", "3.1.3"))])
    assert is_version_affected("PyPI", "3.1.2", ap) is True
    assert is_version_affected("PyPI", "3.1.3", ap) is False  # fixed is exclusive
    assert is_version_affected("PyPI", "3.1.4", ap) is False
    assert is_version_affected("PyPI", "0.1", ap) is True


def test_pypi_multiple_intervals() -> None:
    ap = _affected(
        "PyPI",
        "x",
        ranges=[
            _range(("introduced", "1.0"), ("fixed", "1.5"), ("introduced", "2.0"), ("fixed", "2.5"))
        ],
    )
    assert is_version_affected("PyPI", "1.2", ap) is True
    assert is_version_affected("PyPI", "1.7", ap) is False  # between intervals
    assert is_version_affected("PyPI", "2.3", ap) is True
    assert is_version_affected("PyPI", "3.0", ap) is False


def test_pypi_last_affected() -> None:
    ap = _affected("PyPI", "x", ranges=[_range(("introduced", "1.0"), ("last_affected", "1.9"))])
    assert is_version_affected("PyPI", "1.9", ap) is True
    assert is_version_affected("PyPI", "2.0", ap) is False


def test_pypi_explicit_versions() -> None:
    ap = _affected("PyPI", "x", versions=["1.2.3", "1.2.5"])
    assert is_version_affected("PyPI", "1.2.3", ap) is True
    assert is_version_affected("PyPI", "1.2.4", ap) is False


def test_pypi_prerelease_ordering() -> None:
    ap = _affected("PyPI", "x", ranges=[_range(("introduced", "0"), ("fixed", "2.0.0"))])
    assert is_version_affected("PyPI", "2.0.0rc1", ap) is True  # rc precedes the final
    assert is_version_affected("PyPI", "2.0.0", ap) is False


def test_pypi_unparseable_version_is_not_affected() -> None:
    ap = _affected("PyPI", "x", ranges=[_range(("introduced", "0"), ("fixed", "2.0"))])
    assert is_version_affected("PyPI", "not-a-version", ap) is False


# ---------- npm (semver) ----------
def test_npm_semver_range_and_prerelease() -> None:
    ap = _affected("npm", "lodash", ranges=[_range(("introduced", "0"), ("fixed", "4.17.21"))])
    assert is_version_affected("npm", "4.17.20", ap) is True
    assert is_version_affected("npm", "4.17.21", ap) is False
    pre = _affected("npm", "x", ranges=[_range(("introduced", "0"), ("fixed", "1.0.0"))])
    assert is_version_affected("npm", "1.0.0-beta.1", pre) is True  # prerelease < release
    assert is_version_affected("npm", "1.0.0", pre) is False


def test_matching_range_returns_the_hit() -> None:
    rng = _range(("introduced", "0"), ("fixed", "3.1.3"))
    ap = _affected("PyPI", "jinja2", ranges=[rng])
    assert matching_range("PyPI", "3.1.2", ap) == rng
    assert matching_range("PyPI", "3.1.3", ap) is None


# ---------- matcher ----------
def _adv(adv_id: str, affected: list[AffectedPackage]) -> AdvisoryRecord:
    return AdvisoryRecord(
        id=adv_id,
        source="osv",
        source_id=adv_id,
        summary="",
        details="",
        severity=Severity(bucket="high"),
        affected=affected,
        references=["https://example.test/adv"],
        published=datetime(2024, 1, 1),
        modified=datetime(2024, 1, 1),
        content_hash="h",
    )


def _dep(ecosystem: Ecosystem, name: str, version: str, *, direct: bool = True) -> Dependency:
    return Dependency(
        ecosystem=ecosystem, name=name, version=version, direct=direct, source_file="lock"
    )


def test_matcher_produces_grounded_finding() -> None:
    adv = _adv(
        "osv:1",
        [_affected("PyPI", "jinja2", ranges=[_range(("introduced", "0"), ("fixed", "3.1.3"))])],
    )
    deps = [_dep("PyPI", "jinja2", "3.1.2"), _dep("PyPI", "flask", "3.0.0")]
    findings = match(deps, [adv])
    assert len(findings) == 1
    f = findings[0]
    assert f.advisory_id == "osv:1"
    assert f.installed_version == "3.1.2"
    assert f.is_affected is True
    assert f.reachability == "direct"
    assert f.fixed_versions == ["3.1.3"]
    assert f.severity_bucket == "high"


def test_matcher_skips_out_of_range() -> None:
    adv = _adv(
        "osv:1",
        [_affected("PyPI", "jinja2", ranges=[_range(("introduced", "0"), ("fixed", "3.1.3"))])],
    )
    assert match([_dep("PyPI", "jinja2", "3.1.5")], [adv]) == []


def test_matcher_normalizes_pypi_names() -> None:
    adv = _adv(
        "osv:1",
        [
            _affected(
                "PyPI", "Flask_Login", ranges=[_range(("introduced", "0"), ("fixed", "0.6.3"))]
            )
        ],
    )
    findings = match([_dep("PyPI", "flask-login", "0.6.2")], [adv])
    assert len(findings) == 1


def test_matcher_marks_transitive() -> None:
    adv = _adv(
        "osv:1",
        [_affected("npm", "lodash", ranges=[_range(("introduced", "0"), ("fixed", "4.17.21"))])],
    )
    findings = match([_dep("npm", "lodash", "4.17.20", direct=False)], [adv])
    assert findings[0].reachability == "transitive"


def test_git_range_is_ignored() -> None:
    # A co-present GIT range (commit shas) must not flag a patched version.
    ap = AffectedPackage(
        ecosystem="PyPI",
        name="x",
        ranges=[
            _range(("introduced", "0"), ("fixed", "3.1.3")),
            Range(type="GIT", events=[Event(introduced="0"), Event(fixed="abc123deadbeef")]),
        ],
    )
    assert is_version_affected("PyPI", "3.1.4", ap) is False  # patched -> not flagged
    assert is_version_affected("PyPI", "3.1.2", ap) is True  # still caught by the ECOSYSTEM range


def test_unparseable_fixed_boundary_skips_range() -> None:
    ap = _affected("PyPI", "x", ranges=[_range(("introduced", "0"), ("fixed", "not-a-version"))])
    assert is_version_affected("PyPI", "1.0", ap) is False  # unreliable range -> conservative
