import gzip
import json
from datetime import date

from palisade.enrichment.enrich import enrich_findings
from palisade.enrichment.epss import load_epss
from palisade.enrichment.kev import load_kev
from palisade.models.dependency import Dependency
from palisade.models.finding import Finding


def _finding(aliases: list[str], *, bucket: str = "high", direct: bool = True) -> Finding:
    dep = Dependency(ecosystem="PyPI", name="x", version="1.0", direct=direct, source_file="r")
    return Finding(
        dependency=dep,
        advisory_id="osv:1",
        aliases=aliases,
        installed_version="1.0",
        is_affected=True,
        severity_bucket=bucket,
        reachability="direct" if direct else "transitive",
    )


def test_load_epss() -> None:
    csv_text = (
        "#model_version:v2024\n"
        "cve,epss,percentile\n"
        "CVE-2021-44228,0.97,0.99\n"
        "CVE-2020-0001,0.01,0.10\n"
        "CVE-BAD,notafloat,0.5\n"  # malformed -> skipped
    )
    scores = load_epss(gzip.compress(csv_text.encode()))
    assert scores["CVE-2021-44228"] == (0.97, 0.99)
    assert "CVE-BAD" not in scores
    assert len(scores) == 2  # comment + header skipped, bad row dropped


def test_load_kev() -> None:
    data = json.dumps(
        {"vulnerabilities": [{"cveID": "CVE-2021-44228", "dateAdded": "2021-12-10"}]}
    ).encode()
    assert load_kev(data)["CVE-2021-44228"] == date(2021, 12, 10)


def test_enrich_sets_signals_and_rank() -> None:
    f = _finding(["CVE-2021-44228"])
    enrich_findings([f], {"CVE-2021-44228": (0.97, 0.99)}, {"CVE-2021-44228": date(2021, 12, 10)})
    assert f.epss_score == 0.97
    assert f.epss_percentile == 0.99
    assert f.kev_listed is True
    assert f.kev_date_added == date(2021, 12, 10)
    assert f.rank_score > 1000  # KEV dominates


def test_rank_kev_beats_higher_epss() -> None:
    epss = {"CVE-1": (0.9, 0.9), "CVE-2": (0.1, 0.1)}
    kev = {"CVE-2": date(2022, 1, 1)}
    f1 = _finding(["CVE-1"])  # high EPSS, not KEV
    f2 = _finding(["CVE-2"])  # low EPSS, KEV-listed
    enrich_findings([f1, f2], epss, kev)
    assert f2.rank_score > f1.rank_score


def test_enrich_ignores_non_cve_alias() -> None:
    f = _finding(["GHSA-xxxx-yyyy-zzzz"])  # no CVE alias
    enrich_findings([f], {"CVE-1": (0.5, 0.5)}, {})
    assert f.epss_score is None
    assert f.kev_listed is False


def test_enrich_normalizes_lowercase_cve() -> None:
    f = _finding(["cve-2021-44228"])  # lowercase alias
    enrich_findings([f], {"CVE-2021-44228": (0.9, 0.9)}, {})
    assert f.epss_score == 0.9
