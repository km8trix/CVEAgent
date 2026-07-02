import json
from pathlib import Path

from palisade.models.dependency import Dependency, Lockfile
from palisade.parsers.registry import load_lockfile, parse_lockfile

FIX = Path(__file__).parent / "fixtures"


def _parse(name: str) -> dict[str, Dependency]:
    deps = parse_lockfile(load_lockfile(str(FIX / name)))
    return {d.name: d for d in deps}


def test_package_lock_v3() -> None:
    deps = _parse("package-lock.json")
    assert deps["lodash"].version == "4.17.21"
    assert deps["lodash"].direct is True
    assert deps["jest"].direct is True  # devDependency counts as direct
    assert deps["chalk"].direct is False  # transitive
    assert deps["chalk"].depth == 2


def test_requirements_pinned_only_normalized() -> None:
    deps = _parse("requirements.txt")
    assert set(deps) == {"requests", "flask", "urllib3"}  # Flask normalized; unpinned/-r skipped
    assert deps["requests"].version == "2.31.0"
    assert all(d.ecosystem == "PyPI" for d in deps.values())


def test_poetry_lock() -> None:
    deps = _parse("poetry.lock")
    assert deps["requests"].version == "2.31.0"
    assert deps["pytest"].version == "8.0.0"


def test_package_lock_v1_fallback() -> None:
    raw = json.dumps(
        {
            "name": "old",
            "lockfileVersion": 1,
            "dependencies": {
                "a": {"version": "1.0.0", "dependencies": {"b": {"version": "2.0.0"}}}
            },
        }
    )
    deps = {
        d.name: d
        for d in parse_lockfile(Lockfile(path="package-lock.json", kind="package-lock", raw=raw))
    }
    assert deps["a"].direct is True and deps["a"].depth == 0
    assert deps["b"].direct is False and deps["b"].depth == 1


def test_unsupported_lockfile() -> None:
    import pytest

    with pytest.raises(ValueError, match="unsupported"):
        load_lockfile("Gemfile.lock")


def test_package_lock_v3_alias_and_extraneous() -> None:
    raw = json.dumps(
        {
            "lockfileVersion": 3,
            "packages": {
                "": {"dependencies": {"lodash-4": "npm:lodash@^4.0.0"}},
                "node_modules/lodash-4": {"name": "lodash", "version": "4.17.21"},
                "node_modules/leftover": {"version": "9.9.9", "extraneous": True},
            },
        }
    )
    deps = {
        d.name: d
        for d in parse_lockfile(Lockfile(path="package-lock.json", kind="package-lock", raw=raw))
    }
    assert deps["lodash"].version == "4.17.21"  # canonical name, not the alias
    assert deps["lodash"].direct is True  # declared under the alias in root deps
    assert "leftover" not in deps  # extraneous packages are dropped
