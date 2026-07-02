"""Load pinned golden-eval cases (IMPLEMENTATION_PLAN.md §6/§7).

Each case dir has a lockfile, advisories.json (pinned OSV records), and labels.json
(ground truth: which advisories genuinely apply, is_kev, is_trap). Advisories are pinned so
the eval is deterministic and runs offline in CI.
"""

import json
from dataclasses import dataclass
from pathlib import Path
from typing import Any

from palisade.models.advisory import AdvisoryRecord
from palisade.models.dependency import Dependency
from palisade.parsers.registry import load_lockfile, parse_lockfile

GOLDEN = Path(__file__).parent / "golden" / "cases"
_LOCKFILE_NAMES = {"requirements.txt", "package-lock.json", "poetry.lock"}


@dataclass
class Case:
    id: str
    deps: list[Dependency]
    advisories: list[AdvisoryRecord]
    labels: dict[str, dict[str, Any]]  # advisory_id -> {applies, is_kev, is_trap}


def load_case(case_dir: Path) -> Case:
    lockfile_path = next(p for p in case_dir.iterdir() if p.name in _LOCKFILE_NAMES)
    deps = parse_lockfile(load_lockfile(str(lockfile_path)))
    advisories = [
        AdvisoryRecord.model_validate(a)
        for a in json.loads((case_dir / "advisories.json").read_text())
    ]
    labels_raw = json.loads((case_dir / "labels.json").read_text())["advisories"]
    labels: dict[str, dict[str, Any]] = {entry["id"]: entry for entry in labels_raw}
    return Case(id=case_dir.name, deps=deps, advisories=advisories, labels=labels)


def load_all() -> list[Case]:
    return [load_case(d) for d in sorted(GOLDEN.iterdir()) if d.is_dir()]
