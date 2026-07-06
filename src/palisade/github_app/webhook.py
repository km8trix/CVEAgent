"""GitHub webhook: on a pull_request event, scan the changed lockfiles and post a ranked,
cited report as a PR comment (M3 headline demo).

Security: every request must carry a valid HMAC-SHA256 signature (X-Hub-Signature-256)
computed with GITHUB_WEBHOOK_SECRET. No secret configured -> the endpoint refuses (503) and
never processes an unsigned event. The scan runs in a BackgroundTask so GitHub gets a fast
2xx; advisories are fetched live from OSV (no local DB needed).
"""

from __future__ import annotations

import hashlib
import hmac
import json
import logging
from collections.abc import Awaitable, Callable
from pathlib import Path
from typing import Any, Protocol

import httpx
from fastapi import APIRouter, BackgroundTasks, HTTPException, Request, status

from palisade.config import Settings, get_settings
from palisade.github_app.render import MARKER, render_comment
from palisade.models.finding import ScanReport
from palisade.parsers.registry import LOCKFILE_FILENAMES
from palisade.scanner import scan_content

logger = logging.getLogger(__name__)
router = APIRouter(prefix="/github", tags=["github"])

_PR_ACTIONS = {"opened", "synchronize", "reopened"}
_MAX_LOCKFILE_BYTES = 2_000_000  # skip absurd files rather than feed them to the parser
_API = "https://api.github.com"
_PER_PAGE = 100
_MAX_PAGES = 50  # ponytail: pagination runaway guard (~5k items); lift if a real PR exceeds it
_MAX_LOCKFILES = 20  # ponytail: fan-out cap per PR; raise if a monorepo legitimately needs more

ScanFn = Callable[[str, str], Awaitable[ScanReport]]


def verify_signature(secret: bytes, body: bytes, header: str | None) -> bool:
    """Constant-time HMAC-SHA256 check of GitHub's X-Hub-Signature-256 header."""
    if not header:
        return False
    digest = hmac.new(secret, body, hashlib.sha256).hexdigest()
    return hmac.compare_digest(f"sha256={digest}", header)


def changed_lockfiles(files: list[dict[str, Any]]) -> list[str]:
    """Paths of supported lockfiles in a PR-files listing, excluding deletions."""
    return [
        f["filename"]
        for f in files
        if f.get("status") != "removed" and Path(f["filename"]).name in LOCKFILE_FILENAMES
    ]


class GitHubApi(Protocol):
    async def pr_files(self, repo: str, pr: int) -> list[dict[str, Any]]: ...
    async def file_content(self, repo: str, path: str, ref: str) -> str: ...
    async def upsert_comment(self, repo: str, pr: int, body: str) -> None: ...
    async def aclose(self) -> None: ...


class GitHubClient:
    """Minimal GitHub REST client for the three calls the PR-commenter needs.

    ponytail: PAT bearer auth; swap for App installation tokens (JWT -> installation
    token) when this runs as a real multi-tenant GitHub App.
    """

    def __init__(
        self, token: str | None, *, transport: httpx.AsyncBaseTransport | None = None
    ) -> None:
        headers = {
            "Accept": "application/vnd.github+json",
            "X-GitHub-Api-Version": "2022-11-28",
        }
        if token:
            headers["Authorization"] = f"Bearer {token}"
        self._c = httpx.AsyncClient(
            base_url=_API, headers=headers, timeout=30.0, transport=transport
        )

    async def _get_all(self, path: str) -> list[dict[str, Any]]:
        """Follow GitHub's page-number pagination until a short page (it returns full pages
        until the last). Single-page fetches silently missed lockfiles / the bot's own comment
        on large PRs. Bounded by _MAX_PAGES as a runaway guard."""
        out: list[dict[str, Any]] = []
        for page in range(1, _MAX_PAGES + 1):
            r = await self._c.get(path, params={"per_page": _PER_PAGE, "page": page})
            r.raise_for_status()
            batch: list[dict[str, Any]] = r.json()
            out.extend(batch)
            if len(batch) < _PER_PAGE:
                break
        else:
            logger.warning("pagination hit the %d-page cap for %s", _MAX_PAGES, path)
        return out

    async def pr_files(self, repo: str, pr: int) -> list[dict[str, Any]]:
        return await self._get_all(f"/repos/{repo}/pulls/{pr}/files")

    async def file_content(self, repo: str, path: str, ref: str) -> str:
        r = await self._c.get(
            f"/repos/{repo}/contents/{path}",
            params={"ref": ref},
            headers={"Accept": "application/vnd.github.raw"},
        )
        r.raise_for_status()
        return r.text

    async def upsert_comment(self, repo: str, pr: int, body: str) -> None:
        comments = await self._get_all(f"/repos/{repo}/issues/{pr}/comments")
        mine = next((c for c in comments if MARKER in (c.get("body") or "")), None)
        if mine is not None:
            resp = await self._c.patch(
                f"/repos/{repo}/issues/comments/{mine['id']}", json={"body": body}
            )
        else:
            resp = await self._c.post(f"/repos/{repo}/issues/{pr}/comments", json={"body": body})
        resp.raise_for_status()

    async def aclose(self) -> None:
        await self._c.aclose()


async def handle_pull_request(
    payload: dict[str, Any],
    *,
    gh: GitHubApi | None = None,
    scan_fn: ScanFn = scan_content,
    settings: Settings | None = None,
) -> None:
    """Scan the PR's changed lockfiles and upsert a single report comment.

    Broad except by design: this runs fire-and-forget in a BackgroundTask, so a failure is
    logged (not silently swallowed) rather than propagated to a caller that no longer exists.
    """
    settings = settings or get_settings()
    owns = gh is None
    try:
        # Unpack inside the try: a malformed-but-signed payload must be logged, not crash the task.
        repo = payload["repository"]["full_name"]
        pr = int(payload["pull_request"]["number"])
        head = payload["pull_request"]["head"]["sha"]
        if gh is None:
            token = settings.github_token.get_secret_value() if settings.github_token else None
            gh = GitHubClient(token)
        paths = changed_lockfiles(await gh.pr_files(repo, pr))
        if not paths:
            logger.info("PR %s#%s: no supported lockfiles changed", repo, pr)
            return
        if len(paths) > _MAX_LOCKFILES:
            logger.warning(
                "PR %s#%s: %d lockfiles changed; scanning the first %d",
                repo,
                pr,
                len(paths),
                _MAX_LOCKFILES,
            )
            paths = paths[:_MAX_LOCKFILES]
        reports: list[ScanReport] = []
        for path in paths:
            content = await gh.file_content(repo, path, head)
            if len(content.encode("utf-8")) > _MAX_LOCKFILE_BYTES:
                logger.warning("PR %s#%s: skipping oversized lockfile %s", repo, pr, path)
                continue
            reports.append(await scan_fn(path, content))
        if reports:
            await gh.upsert_comment(repo, pr, render_comment(reports))
            logger.info("PR %s#%s: posted scan comment (%d lockfile(s))", repo, pr, len(reports))
    except Exception:
        logger.exception(
            "PR scan/comment failed for %s#%s",
            payload.get("repository", {}).get("full_name", "?"),
            payload.get("pull_request", {}).get("number", "?"),
        )
    finally:
        if owns and gh is not None:
            await gh.aclose()


@router.post("/webhook", status_code=status.HTTP_202_ACCEPTED)
async def webhook(request: Request, background_tasks: BackgroundTasks) -> dict[str, str]:
    settings = get_settings()
    if settings.github_webhook_secret is None:
        raise HTTPException(
            status.HTTP_503_SERVICE_UNAVAILABLE, "github webhook secret not configured"
        )
    body = await request.body()
    if not verify_signature(
        settings.github_webhook_secret.get_secret_value().encode("utf-8"),
        body,
        request.headers.get("X-Hub-Signature-256"),
    ):
        raise HTTPException(status.HTTP_401_UNAUTHORIZED, "invalid signature")
    event = request.headers.get("X-GitHub-Event", "")
    if event == "ping":
        return {"msg": "pong"}
    if event != "pull_request":
        return {"msg": f"ignored event: {event}"}
    payload = json.loads(body)
    if payload.get("action") not in _PR_ACTIONS:
        return {"msg": f"ignored action: {payload.get('action')}"}
    # ponytail: inline BackgroundTask scan; route via the pg scan-queue if PR volume
    # needs durability/retries across restarts.
    background_tasks.add_task(handle_pull_request, payload)
    return {"msg": "scan scheduled"}
