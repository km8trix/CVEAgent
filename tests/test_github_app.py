import asyncio
import hashlib
import hmac
import json
from datetime import UTC, datetime
from typing import Any

import httpx
import pytest
from pydantic import SecretStr

from palisade.config import Settings
from palisade.github_app.render import MARKER, render_comment
from palisade.github_app.webhook import (
    GitHubClient,
    changed_lockfiles,
    handle_pull_request,
    verify_signature,
)
from palisade.models.dependency import Dependency
from palisade.models.finding import Finding, ScanReport


def _finding(name: str = "flask", *, kev: bool = False) -> Finding:
    return Finding(
        dependency=Dependency(
            ecosystem="PyPI", name=name, version="0.12.0", direct=True, source_file="req"
        ),
        advisory_id="osv:GHSA-abcd",  # internal id; render strips the "osv:" prefix for the URL
        installed_version="0.12.0",
        fixed_versions=["0.12.3"],
        is_affected=True,
        kev_listed=kev,
        epss_percentile=0.97,
        severity_bucket="high",
        rank_score=9.0,
    )


def _report(target: str = "requirements.txt", findings: list[Finding] | None = None) -> ScanReport:
    return ScanReport(
        scan_id="s1",
        target=target,
        created_at=datetime.now(UTC),
        ecosystem="PyPI",
        findings=[_finding()] if findings is None else findings,
    )


# --- signature (security boundary) ---


def test_verify_signature_roundtrip() -> None:
    secret, body = b"shh", b'{"hello":"world"}'
    good = "sha256=" + hmac.new(secret, body, hashlib.sha256).hexdigest()
    assert verify_signature(secret, body, good) is True
    assert verify_signature(secret, body + b"x", good) is False  # tampered body
    assert verify_signature(b"other", body, good) is False  # wrong secret
    assert verify_signature(secret, body, None) is False  # missing header
    assert verify_signature(secret, body, "garbage") is False


# --- lockfile filtering ---


def test_changed_lockfiles_filters_and_ignores_deletions() -> None:
    files = [
        {"filename": "requirements.txt", "status": "modified"},
        {"filename": "sub/dir/package-lock.json", "status": "added"},
        {"filename": "poetry.lock", "status": "removed"},  # deletion -> excluded
        {"filename": "README.md", "status": "modified"},  # not a lockfile
    ]
    assert changed_lockfiles(files) == ["requirements.txt", "sub/dir/package-lock.json"]


# --- markdown rendering ---


def test_render_comment_has_marker_findings_and_citation() -> None:
    md = render_comment([_report(findings=[_finding(kev=True)])])
    assert md.startswith(MARKER)
    assert "flask" in md
    assert "osv.dev/vulnerability/GHSA-abcd" in md  # bare source id
    assert "vulnerability/osv:" not in md  # internal prefix must be stripped from the link
    assert "yes" in md  # KEV column
    assert "`0.12.3`" in md  # fix version


def test_render_comment_empty_is_green() -> None:
    md = render_comment([_report(findings=[])])
    assert MARKER in md
    assert "✅" in md
    assert "no known-vulnerable" in md.lower()


# --- orchestration ---


class FakeGitHub:
    def __init__(self, files: list[dict[str, Any]], contents: dict[str, str], *, existing: bool):
        self._files = files
        self._contents = contents
        self._existing = existing
        self.posted: list[str] = []
        self.patched: list[str] = []
        self.closed = False

    async def pr_files(self, repo: str, pr: int) -> list[dict[str, Any]]:
        return self._files

    async def file_content(self, repo: str, path: str, ref: str) -> str:
        return self._contents[path]

    async def upsert_comment(self, repo: str, pr: int, body: str) -> None:
        (self.patched if self._existing else self.posted).append(body)

    async def aclose(self) -> None:
        self.closed = True


_PAYLOAD = {
    "action": "opened",
    "repository": {"full_name": "octo/repo"},
    "pull_request": {"number": 7, "head": {"sha": "deadbeef"}},
}


def test_handle_pull_request_posts_new_comment() -> None:
    gh = FakeGitHub(
        files=[{"filename": "requirements.txt", "status": "modified"}],
        contents={"requirements.txt": "flask==0.12.0\n"},
        existing=False,
    )

    async def fake_scan(path: str, content: str) -> ScanReport:
        assert (path, content) == ("requirements.txt", "flask==0.12.0\n")
        return _report(target=path)

    asyncio.run(handle_pull_request(_PAYLOAD, gh=gh, scan_fn=fake_scan, settings=Settings()))
    assert len(gh.posted) == 1 and not gh.patched
    assert "flask" in gh.posted[0]
    assert not gh.closed  # injected client is not owned -> not closed


def test_handle_pull_request_updates_existing_comment() -> None:
    gh = FakeGitHub(
        files=[{"filename": "requirements.txt", "status": "modified"}],
        contents={"requirements.txt": "x"},
        existing=True,
    )

    async def fake_scan(path: str, content: str) -> ScanReport:
        return _report(target=path)

    asyncio.run(handle_pull_request(_PAYLOAD, gh=gh, scan_fn=fake_scan, settings=Settings()))
    assert len(gh.patched) == 1 and not gh.posted


def test_handle_pull_request_no_lockfiles_posts_nothing() -> None:
    gh = FakeGitHub(
        files=[{"filename": "README.md", "status": "modified"}],
        contents={},
        existing=False,
    )

    async def fake_scan(path: str, content: str) -> ScanReport:  # pragma: no cover - not reached
        raise AssertionError("scan should not run when no lockfiles changed")

    asyncio.run(handle_pull_request(_PAYLOAD, gh=gh, scan_fn=fake_scan, settings=Settings()))
    assert not gh.posted and not gh.patched


# --- GitHubClient pagination (single-page fetch used to miss lockfiles / the bot comment) ---


def test_pr_files_paginates_and_finds_late_lockfile() -> None:
    def handler(request: httpx.Request) -> httpx.Response:
        assert request.url.path == "/repos/o/r/pulls/1/files"
        page = int(request.url.params.get("page", "1"))
        if page == 1:  # a full page of non-lockfiles forces a second page fetch
            return httpx.Response(
                200, json=[{"filename": f"src/f{i}.py", "status": "modified"} for i in range(100)]
            )
        if page == 2:
            return httpx.Response(200, json=[{"filename": "requirements.txt", "status": "added"}])
        return httpx.Response(200, json=[])

    async def run() -> list[dict[str, Any]]:
        gh = GitHubClient("tok", transport=httpx.MockTransport(handler))
        try:
            return await gh.pr_files("o/r", 1)
        finally:
            await gh.aclose()

    files = asyncio.run(run())
    assert len(files) == 101
    assert changed_lockfiles(files) == ["requirements.txt"]


def test_upsert_patches_marker_comment_found_on_a_later_page() -> None:
    seen: dict[str, Any] = {}

    def handler(request: httpx.Request) -> httpx.Response:
        path, method = request.url.path, request.method
        if method == "GET" and path == "/repos/o/r/issues/1/comments":
            page = int(request.url.params.get("page", "1"))
            if page == 1:
                return httpx.Response(200, json=[{"id": i, "body": "chatter"} for i in range(100)])
            if page == 2:
                return httpx.Response(200, json=[{"id": 999, "body": f"{MARKER}\nold report"}])
            return httpx.Response(200, json=[])
        if method == "PATCH" and path == "/repos/o/r/issues/comments/999":
            seen["patched"] = json.loads(request.content)["body"]
            return httpx.Response(200, json={})
        if method == "POST":
            seen["posted"] = True
            return httpx.Response(201, json={})
        raise AssertionError(f"unexpected {method} {path}")

    async def run() -> None:
        gh = GitHubClient("tok", transport=httpx.MockTransport(handler))
        try:
            await gh.upsert_comment("o/r", 1, "fresh report")
        finally:
            await gh.aclose()

    asyncio.run(run())
    assert seen.get("patched") == "fresh report"
    assert "posted" not in seen  # updated the existing comment, did not duplicate


# --- route (trust boundary: signature enforcement) ---


def test_webhook_route_503_without_secret() -> None:
    from fastapi.testclient import TestClient

    from palisade.main import app

    # No GITHUB_WEBHOOK_SECRET in the test env -> the endpoint refuses to process anything.
    resp = TestClient(app).post(
        "/github/webhook", content=b"{}", headers={"X-GitHub-Event": "ping"}
    )
    assert resp.status_code == 503


def test_webhook_route_rejects_bad_signature_and_schedules_valid(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    from fastapi.testclient import TestClient

    import palisade.github_app.webhook as wh
    from palisade.main import app

    secret = "topsecret"
    scheduled: list[dict[str, Any]] = []

    async def fake_handle(payload: dict[str, Any], **kwargs: Any) -> None:
        scheduled.append(payload)

    monkeypatch.setattr(
        wh, "get_settings", lambda: Settings(github_webhook_secret=SecretStr(secret))
    )
    monkeypatch.setattr(wh, "handle_pull_request", fake_handle)

    client = TestClient(app)
    body = (
        b'{"action":"opened","repository":{"full_name":"o/r"},'
        b'"pull_request":{"number":1,"head":{"sha":"s"}}}'
    )
    sig = "sha256=" + hmac.new(secret.encode(), body, hashlib.sha256).hexdigest()
    pr = {"X-GitHub-Event": "pull_request"}

    bad = client.post(
        "/github/webhook", content=body, headers={**pr, "X-Hub-Signature-256": "sha256=nope"}
    )
    assert bad.status_code == 401
    assert not scheduled  # rejected before scheduling

    ok = client.post("/github/webhook", content=body, headers={**pr, "X-Hub-Signature-256": sig})
    assert ok.status_code == 202 and ok.json() == {"msg": "scan scheduled"}
    assert len(scheduled) == 1 and scheduled[0]["repository"]["full_name"] == "o/r"
