import io
import json
import zipfile
from typing import Any

from palisade.ingestion.sources.osv_export import iter_records
from palisade.ingestion.sync import _decide


def _zip(files: dict[str, Any]) -> bytes:
    buf = io.BytesIO()
    with zipfile.ZipFile(buf, "w") as zf:
        for name, obj in files.items():
            zf.writestr(name, json.dumps(obj))
    return buf.getvalue()


def test_iter_records_yields_json_only() -> None:
    data = _zip(
        {
            "GHSA-1.json": {"id": "GHSA-1"},
            "sub/GHSA-2.json": {"id": "GHSA-2"},
            "index.txt": {"id": "ignore-me"},
        }
    )
    ids = sorted(str(r["id"]) for r in iter_records(data))
    assert ids == ["GHSA-1", "GHSA-2"]


def test_decide_upsert() -> None:
    assert _decide(None, "h") == "inserted"
    assert _decide("h", "h") == "skipped"
    assert _decide("h", "h2") == "updated"


def test_sync_records_counts_errors_and_inserts() -> None:
    from pathlib import Path
    from unittest.mock import MagicMock

    from palisade.ingestion.sync import sync_records

    session = MagicMock()
    session.get.return_value = None  # nothing exists -> everything valid inserts
    valid = json.loads((Path(__file__).parent / "fixtures" / "osv_pypi_example.json").read_text())
    withdrawn = {**valid, "id": "GHSA-withdrawn", "withdrawn": "2024-01-01T00:00:00Z"}

    stats = sync_records(session, iter([valid, withdrawn]))
    assert stats.inserted == 1
    assert stats.errors == 1
    assert stats.skipped == 0
