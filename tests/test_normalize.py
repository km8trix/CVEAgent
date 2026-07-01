import json
from pathlib import Path
from typing import Any, cast

from palisade.ingestion.normalize import content_hash, normalize_osv

FIXTURE = Path(__file__).parent / "fixtures" / "osv_pypi_example.json"


def _raw() -> dict[str, Any]:
    return cast(dict[str, Any], json.loads(FIXTURE.read_text()))


def test_normalize_osv_basic() -> None:
    adv = normalize_osv(_raw())
    assert adv.source == "osv"
    assert adv.source_id == "GHSA-h5c8-rqwp-cp95"
    assert adv.id == "osv:GHSA-h5c8-rqwp-cp95"
    assert "CVE-2024-22195" in adv.aliases
    assert adv.cwe_ids == ["CWE-79"]
    assert adv.severity.cvss_vector is not None
    assert adv.severity.bucket == "medium"
    assert len(adv.affected) == 1
    ap = adv.affected[0]
    assert ap.ecosystem == "PyPI"
    assert ap.name == "jinja2"
    assert ap.ranges[0].events[1].fixed == "3.1.3"
    assert any("nvd.nist.gov" in r for r in adv.references)


def test_normalize_drops_unsupported_ecosystems() -> None:
    raw = _raw()
    raw["affected"].append({"package": {"ecosystem": "Go", "name": "x"}, "ranges": []})
    adv = normalize_osv(raw)
    assert [a.ecosystem for a in adv.affected] == ["PyPI"]


def test_content_hash_stable() -> None:
    raw = _raw()
    assert content_hash(raw) == content_hash(dict(raw))


def test_normalize_rejects_withdrawn() -> None:
    import pytest

    raw = _raw()
    raw["withdrawn"] = "2024-05-01T00:00:00Z"
    with pytest.raises(ValueError, match="withdrawn"):
        normalize_osv(raw)


def test_normalize_requires_modified() -> None:
    import pytest

    raw = _raw()
    del raw["modified"]
    with pytest.raises(ValueError, match="modified"):
        normalize_osv(raw)
