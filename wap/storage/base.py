"""The storage interface every piece of server state goes through.

A WAP server keeps several kinds of short-lived state: rate-limit meters,
replay caches, spent proof-of-work seeds, dialogue sessions, loop-guard
history and idempotency records. By default all of it lives in process memory
(:class:`~wap.storage.memory.MemoryStore`), which is right for a single worker.
Deployments with several workers or machines pass a shared backend such as
:class:`~wap.storage.redis.RedisStore` so that limits, replay protection and
sessions hold across all of them::

    from wap.storage import RedisStore
    wap = WAPServer(..., store=RedisStore.from_url("redis://localhost:6379/0"))

Values are JSON documents. Implementations must make :meth:`StateStore.add`
and :meth:`StateStore.rate_limit` atomic across every process sharing the store.
"""

from __future__ import annotations

from contextlib import AbstractAsyncContextManager
from typing import Any, Protocol, runtime_checkable

from .meters import RateLimitDecision


class LockTimeout(Exception):
    """A named lock could not be acquired within the allowed wait."""


@runtime_checkable
class StateStore(Protocol):
    """Async key/value store with TTLs, atomic set-if-absent, locks and rate limiting."""

    async def get(self, key: str) -> Any | None:
        """Return the JSON value stored at ``key`` (``None`` if missing or expired)."""
        ...

    async def set(self, key: str, value: Any, ttl: float | None = None) -> None:
        """Store a JSON-serialisable ``value``, expiring after ``ttl`` seconds if given."""
        ...

    async def add(self, key: str, value: Any, ttl: float | None = None) -> bool:
        """Atomically store ``value`` only if ``key`` is absent. Returns ``True`` if stored."""
        ...

    async def delete(self, key: str) -> None: ...

    async def incr(self, key: str, ttl: float) -> int:
        """Atomically increment an integer counter, creating it with ``ttl`` if absent."""
        ...

    def lock(self, key: str, *, timeout: float, wait: float) -> AbstractAsyncContextManager[None]:
        """Mutual exclusion on ``key`` across all processes sharing the store.

        ``timeout`` bounds how long the lock may be held (so a crashed holder
        cannot block forever); ``wait`` bounds how long to wait for it before
        raising :class:`LockTimeout`.
        """
        ...

    async def rate_limit(
        self, keys: list[tuple[str, str]], *, limit: int, window: float, burst: int, cost: float, now: float
    ) -> RateLimitDecision:
        """Atomically check and (if admitted) charge every ``(scope, key)`` meter."""
        ...

    async def aclose(self) -> None: ...


__all__ = ["LockTimeout", "StateStore"]
