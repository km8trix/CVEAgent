"""Scan-queue API + worker unit tests. No live Postgres: the DB session dependency
is overridden and the queue helpers are monkeypatched, so these exercise wiring and
state transitions only (the SKIP LOCKED SQL is validated by hand against real PG)."""

from datetime import UTC, datetime
from types import SimpleNamespace
from typing import Any, cast

import pytest
from fastapi.testclient import TestClient
from sqlalchemy.orm import Session

from palisade import queue, worker
from palisade.db.base import get_session
from palisade.main import app
from palisade.models.finding import ScanReport


def _report(scan_id: str) -> ScanReport:
    return ScanReport(
        scan_id=scan_id, target="requirements.txt", created_at=datetime.now(UTC), ecosystem="PyPI"
    )


def test_post_scan_enqueues(monkeypatch: pytest.MonkeyPatch) -> None:
    seen: dict[str, Any] = {}

    def fake_enqueue(session: Any, filename: str, content: str, engine: str) -> str:
        seen["args"] = (filename, content, engine)
        return "job-123"

    monkeypatch.setattr("palisade.queue.enqueue", fake_enqueue)
    monkeypatch.setitem(app.dependency_overrides, get_session, lambda: None)

    resp = TestClient(app).post(
        "/scan",
        json={"filename": "requirements.txt", "content": "flask==3.0.0", "engine": "graph"},
    )
    assert resp.status_code == 202
    assert resp.json() == {"id": "job-123", "status": "pending", "error": None}
    assert seen["args"] == ("requirements.txt", "flask==3.0.0", "graph")


def test_get_scan_done_returns_full_report(monkeypatch: pytest.MonkeyPatch) -> None:
    done = _report("job-1").model_dump(mode="json")
    row = SimpleNamespace(id="job-1", status="done", result=done)
    monkeypatch.setattr("palisade.queue.get_scan", lambda s, sid: row)
    monkeypatch.setitem(app.dependency_overrides, get_session, lambda: None)

    resp = TestClient(app).get("/scans/job-1")
    assert resp.status_code == 200
    body = resp.json()
    assert body["scan_id"] == "job-1"
    assert body["ecosystem"] == "PyPI"
    ScanReport.model_validate(body)  # the done shape is a real ScanReport


def test_get_scan_done_without_result_does_not_500(monkeypatch: pytest.MonkeyPatch) -> None:
    # The ck_scans_done_has_result constraint makes this state unreachable in the DB,
    # but the read path must degrade to a status envelope, never crash on model_validate(None).
    row = SimpleNamespace(id="job-x", status="done", result=None, error=None)
    monkeypatch.setattr("palisade.queue.get_scan", lambda s, sid: row)
    monkeypatch.setitem(app.dependency_overrides, get_session, lambda: None)

    resp = TestClient(app).get("/scans/job-x")
    assert resp.status_code == 200
    assert resp.json() == {"id": "job-x", "status": "done", "error": None}


def test_get_scan_running_returns_status(monkeypatch: pytest.MonkeyPatch) -> None:
    row = SimpleNamespace(id="job-2", status="running", result=None, error=None)
    monkeypatch.setattr("palisade.queue.get_scan", lambda s, sid: row)
    monkeypatch.setitem(app.dependency_overrides, get_session, lambda: None)

    resp = TestClient(app).get("/scans/job-2")
    assert resp.status_code == 200
    assert resp.json() == {"id": "job-2", "status": "running", "error": None}


def test_get_scan_error_surfaces_message(monkeypatch: pytest.MonkeyPatch) -> None:
    row = SimpleNamespace(id="job-3", status="error", result=None, error="unsupported lockfile")
    monkeypatch.setattr("palisade.queue.get_scan", lambda s, sid: row)
    monkeypatch.setitem(app.dependency_overrides, get_session, lambda: None)

    resp = TestClient(app).get("/scans/job-3")
    assert resp.status_code == 200
    assert resp.json() == {"id": "job-3", "status": "error", "error": "unsupported lockfile"}


def test_get_scan_missing_is_404(monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.setattr("palisade.queue.get_scan", lambda s, sid: None)
    monkeypatch.setitem(app.dependency_overrides, get_session, lambda: None)

    resp = TestClient(app).get("/scans/nope")
    assert resp.status_code == 404


def test_worker_empty_queue_returns_false(monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.setattr("palisade.queue.claim_one", lambda s: None)
    assert worker.process_once(cast(Session, None)) is False


def test_worker_stores_result_and_overrides_scan_id(monkeypatch: pytest.MonkeyPatch) -> None:
    job = queue.ClaimedJob(id="j1", engine="scan", filename="requirements.txt", content="flask")
    stored: dict[str, Any] = {}

    async def fake_scan(filename: str, content: str, **kw: Any) -> ScanReport:
        return _report("internal-uuid")  # runner picks its own id; worker must override it

    monkeypatch.setattr("palisade.queue.claim_one", lambda s: job)
    monkeypatch.setattr(
        "palisade.queue.finish",
        lambda s, sid, result: stored.update(id=sid, result=result),
    )
    monkeypatch.setattr("palisade.worker.scan_content", fake_scan)

    assert worker.process_once(cast(Session, None)) is True
    assert stored["id"] == "j1"
    assert stored["result"]["scan_id"] == "j1"  # overridden to the row id


def test_worker_records_error_and_survives(monkeypatch: pytest.MonkeyPatch) -> None:
    job = queue.ClaimedJob(id="j2", engine="scan", filename="x", content="y")
    failed: dict[str, Any] = {}

    async def boom(filename: str, content: str, **kw: Any) -> ScanReport:
        raise RuntimeError("kaboom")

    monkeypatch.setattr("palisade.queue.claim_one", lambda s: job)
    monkeypatch.setattr("palisade.queue.fail", lambda s, sid, err: failed.update(id=sid, err=err))
    monkeypatch.setattr("palisade.worker.scan_content", boom)

    assert worker.process_once(cast(Session, None)) is True  # loop survives the bad job
    assert failed["id"] == "j2"
    assert "RuntimeError" in failed["err"]  # class name is surfaced...
    assert "kaboom" not in failed["err"]  # ...but the raw message (paths/tokens) is not


def test_post_scan_rejects_oversized_bytes(monkeypatch: pytest.MonkeyPatch) -> None:
    # 200k multi-byte chars = 200k chars but 600k UTF-8 bytes: must fail the byte cap.
    monkeypatch.setitem(app.dependency_overrides, get_session, lambda: None)
    resp = TestClient(app).post(
        "/scan", json={"filename": "requirements.txt", "content": "€" * 200_000}
    )
    assert resp.status_code == 422
