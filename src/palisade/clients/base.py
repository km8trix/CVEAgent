"""Shared HTTP client: async httpx + tenacity retry + per-host token-bucket rate limiting.

Record-level content-hash dedup lives in ingestion.normalize, not here; add HTTP
response caching when a caller actually needs it.
"""

from __future__ import annotations

import asyncio
import time
from collections.abc import Callable
from types import TracebackType
from typing import Any

import httpx
from tenacity import (
    AsyncRetrying,
    retry_if_exception_type,
    stop_after_attempt,
    wait_exponential_jitter,
)
from tenacity.wait import wait_base


class TokenBucket:
    """Monotonic-clock token bucket. `time_fn` is injectable for deterministic tests."""

    def __init__(
        self, rate: float, capacity: float, *, time_fn: Callable[[], float] = time.monotonic
    ) -> None:
        self.rate = rate
        self.capacity = capacity
        self._tokens = capacity
        self._time = time_fn
        self._updated = time_fn()
        self._lock = asyncio.Lock()

    def _available(self, now: float) -> float:
        elapsed = now - self._updated
        return min(self.capacity, self._tokens + elapsed * self.rate)

    async def acquire(self) -> float:
        """Take one token, sleeping if none are available. Returns total wait incurred.

        The lock is released around asyncio.sleep so a waiting coroutine never blocks
        others from checking the bucket.
        """
        waited = 0.0
        while True:
            async with self._lock:
                now = self._time()
                self._tokens = self._available(now)
                self._updated = now
                if self._tokens >= 1:
                    self._tokens -= 1
                    return waited
                wait = (1 - self._tokens) / self.rate
            await asyncio.sleep(wait)
            waited += wait


class BaseClient:
    """Async HTTP client with rate limiting + retry. Subclass per external source."""

    def __init__(
        self,
        base_url: str,
        *,
        rate: float = 10.0,
        capacity: float = 10.0,
        timeout: float = 30.0,
        headers: dict[str, str] | None = None,
        max_attempts: int = 4,
        wait: wait_base | None = None,
        transport: httpx.AsyncBaseTransport | None = None,
    ) -> None:
        self._bucket = TokenBucket(rate, capacity)
        self._max_attempts = max_attempts
        self._wait: wait_base = (
            wait if wait is not None else wait_exponential_jitter(initial=1.0, max=30.0)
        )
        self._client = httpx.AsyncClient(
            base_url=base_url, timeout=timeout, headers=headers or {}, transport=transport
        )

    async def request(self, method: str, url: str, **kwargs: Any) -> httpx.Response:
        async for attempt in AsyncRetrying(
            stop=stop_after_attempt(self._max_attempts),
            wait=self._wait,
            retry=retry_if_exception_type((httpx.HTTPStatusError, httpx.TransportError)),
            reraise=True,
        ):
            with attempt:
                await self._bucket.acquire()  # a retry is another request; rate-limit it too
                resp = await self._client.request(method, url, **kwargs)
                if resp.status_code == 429 or resp.status_code >= 500:
                    resp.raise_for_status()
                return resp
        raise RuntimeError("unreachable")  # pragma: no cover

    async def get_json(self, url: str, **kwargs: Any) -> Any:
        resp = await self.request("GET", url, **kwargs)
        resp.raise_for_status()
        return resp.json()

    async def post_json(self, url: str, **kwargs: Any) -> Any:
        resp = await self.request("POST", url, **kwargs)
        resp.raise_for_status()
        return resp.json()

    async def aclose(self) -> None:
        await self._client.aclose()

    async def __aenter__(self) -> BaseClient:
        return self

    async def __aexit__(
        self,
        exc_type: type[BaseException] | None,
        exc_val: BaseException | None,
        exc_tb: TracebackType | None,
    ) -> None:
        await self.aclose()
