import asyncio

from palisade.clients.base import TokenBucket


def test_refill_and_cap() -> None:
    clock = {"t": 0.0}
    b = TokenBucket(rate=2.0, capacity=5.0, time_fn=lambda: clock["t"])
    b._tokens = 0.0
    assert b._available(1.0) == 2.0  # 1s * 2 tokens/s
    assert b._available(10.0) == 5.0  # capped at capacity


def test_acquire_deducts_and_waits_when_exhausted() -> None:
    async def run() -> tuple[float, float]:
        b = TokenBucket(rate=50.0, capacity=1.0)
        first = await b.acquire()
        second = await b.acquire()  # bucket exhausted -> must wait, not hang
        return first, second

    first, second = asyncio.run(run())
    assert first == 0.0
    assert 0.0 < second < 1.0


def test_acquire_concurrent_completes() -> None:
    async def run() -> list[float]:
        b = TokenBucket(rate=100.0, capacity=1.0)
        return list(await asyncio.gather(b.acquire(), b.acquire()))

    waits = asyncio.run(run())
    assert len(waits) == 2
    assert min(waits) == 0.0  # one immediate; neither deadlocks
