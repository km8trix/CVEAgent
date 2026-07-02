from datetime import datetime

from evals.baseline import naive_flag
from evals.datasets import Case
from evals.metrics import aggregate, evaluate_case

from palisade.models.advisory import AdvisoryRecord, AffectedPackage, Event, Range, Severity
from palisade.models.dependency import Dependency


def _adv(adv_id: str, fixed: str) -> AdvisoryRecord:
    return AdvisoryRecord(
        id=adv_id,
        source="osv",
        source_id=adv_id,
        summary="",
        details="",
        severity=Severity(),
        affected=[
            AffectedPackage(
                ecosystem="PyPI",
                name="jinja2",
                ranges=[
                    Range(type="ECOSYSTEM", events=[Event(introduced="0"), Event(fixed=fixed)])
                ],
            )
        ],
        references=[],
        published=datetime(2024, 1, 1),
        modified=datetime(2024, 1, 1),
        content_hash="h",
    )


def _case(installed: str) -> Case:
    dep = Dependency(
        ecosystem="PyPI", name="jinja2", version=installed, direct=True, source_file="r"
    )
    advs = [_adv("osv:applies", "3.1.3"), _adv("osv:trap", "1.0.0")]  # trap fixed long ago
    labels = {
        "osv:applies": {
            "id": "osv:applies",
            "applies": installed == "3.1.2",
            "is_kev": True,
            "is_trap": False,
        },
        "osv:trap": {"id": "osv:trap", "applies": False, "is_kev": False, "is_trap": True},
    }
    return Case(id="t", deps=[dep], advisories=advs, labels=labels)


def test_baseline_flags_regardless_of_version() -> None:
    case = _case("3.1.2")
    assert naive_flag(case.deps, case.advisories) == {"osv:applies", "osv:trap"}


def test_metrics_vulnerable_case_is_perfect() -> None:
    m = aggregate([evaluate_case(_case("3.1.2"))])
    assert m["precision"] == 1.0 and m["recall"] == 1.0 and m["kev_recall"] == 1.0
    assert m["fp_reduction_vs_baseline"] == 1.0  # palisade avoids the trap the baseline flags


def test_metrics_patched_case_avoids_false_positives() -> None:
    m = aggregate([evaluate_case(_case("3.1.6"))])  # patched: nothing applies
    assert m["palisade_false_positives"] == 0
    assert m["baseline_false_positives"] == 2  # naive flags both
    assert m["fp_reduction_vs_baseline"] == 1.0
