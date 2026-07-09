"""Optional Langfuse tracing (M3). No-op unless Langfuse keys are configured — mirrors the
`make_drafter` pattern so CI and key-less runs need neither keys nor the `langfuse` install.
See IMPLEMENTATION_PLAN.md section M3.

`make_tracer` returns None (tracing skipped) when Langfuse isn't configured. When it is, one
Langfuse trace is exported per scan: the graph's step log plus cost/latency/finding-count
metadata. ponytail: the concrete Langfuse SDK call is wrapped so a Langfuse hiccup — or an SDK
API shift across the broad `langfuse>=2,<4` pin — can never break a scan; live-verify against a
real Langfuse project once keys exist (deferred: no keys in the build env).
"""

import logging
from functools import lru_cache
from typing import Any, Protocol

from palisade.config import Settings, get_settings
from palisade.models.finding import ScanReport

logger = logging.getLogger(__name__)


class Tracer(Protocol):
    def record_scan(
        self, report: ScanReport, trace: list[dict[str, Any]], *, prompt_version: str
    ) -> None: ...

    def close(self) -> None: ...


class LangfuseTracer:
    """Exports one Langfuse trace per scan. Any export failure is logged, never raised."""

    def __init__(self, client: Any) -> None:
        self._client = client

    def record_scan(
        self, report: ScanReport, trace: list[dict[str, Any]], *, prompt_version: str
    ) -> None:
        try:
            self._client.trace(
                name="palisade.scan",
                metadata={
                    "scan_id": report.scan_id,
                    "target": report.target,
                    "ecosystem": report.ecosystem,
                    "findings": len(report.findings),
                    "cost_usd": report.cost_usd,
                    "latency_ms": report.latency_ms,
                    "prompt_version": prompt_version,
                    "steps": trace,
                },
            )
            self._client.flush()
        except Exception as exc:  # observability must never break a scan
            logger.warning("langfuse trace export failed: %s", exc)

    def close(self) -> None:
        """Flush buffered traces and stop the SDK's background export threads. Call once on
        worker/CLI exit — the cached client lives for the whole process, so nothing else does."""
        try:
            self._client.shutdown()  # flushes, then joins export threads (langfuse 2.x and 3.x)
        except Exception as exc:  # teardown must never raise into worker shutdown
            logger.warning("langfuse shutdown failed: %s", exc)


def make_tracer(settings: Settings) -> Tracer | None:
    """Build a Tracer, or None when Langfuse isn't configured (tracing then no-ops)."""
    public = settings.langfuse_public_key
    secret = settings.langfuse_secret_key
    if not public or secret is None:
        return None
    try:
        from langfuse import Langfuse  # lazy: optional 'observability' extra
    except ImportError:
        logger.warning(
            "LANGFUSE keys set but 'langfuse' is not installed; "
            "run `uv sync --extra observability`. Tracing disabled."
        )
        return None
    try:
        client = Langfuse(
            public_key=public,
            secret_key=secret.get_secret_value(),
            host=settings.langfuse_host,
        )
    except Exception as exc:  # never let a Langfuse construction hiccup break a scan
        logger.warning("failed to construct Langfuse client; tracing disabled: %s", exc)
        return None
    return LangfuseTracer(client)


@lru_cache(maxsize=1)
def get_tracer() -> Tracer | None:
    """Process-wide tracer, built once (mirrors `get_settings`). The queue worker calls this
    per scan, so caching means ONE Langfuse client for the worker's lifetime — not a new client
    (with its own background OTel export threads) leaked on every scan. Call the returned
    tracer's `close()` on worker exit; see `palisade.worker.main`."""
    return make_tracer(get_settings())
