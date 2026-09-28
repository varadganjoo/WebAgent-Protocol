"""In-process :class:`StateStore`: the zero-configuration default for single-worker servers."""

from __future__ import annotations

import asyncio
import json
import time
from collections import OrderedDict
from collections.abc import AsyncIterator, Callable
from contextlib import asynccontextmanager
from typing import Any

from .base import LockTimeout
from .meters import MeterTable, RateLimitDecision


class MemoryStore:
    """Dictionary-backed store with TTLs, LRU bounding and asyncio locks.

    Values are stored as JSON text, exactly as a networked backend would, so code
    that works against this store behaves the same against Redis. State is lost on
    restart and is not shared between processes; use a shared backend for that.
    """

    def __init__(
        self,
        *,
        max_entries: int = 200_000,
        max_rate_keys: int = 100_000,
        rate_idle_ttl: float = 600.0,
        clock: Callable[[], float] = time.time,
    ) -> None:
        self.max_entries = max_entries
        self._clock = clock
        self._data: OrderedDict[str, tuple[str, float | None]] = OrderedDict()
        self._locks: dict[str, asyncio.Lock] = {}
        self.meters = MeterTable(idle_ttl=rate_idle_ttl, max_keys=max_rate_keys)
        self._meter_lock = asyncio.Lock()

    def _live(self, key: str) -> str | None:
        entry = self._data.get(key)
        if entry is None:
            return None
        raw, expires = entry
        if expires is not None and expires <= self._clock():
            del self._data[key]
            return None
        return raw

    def _put(self, key: str, value: Any, ttl: float | None) -> None:
        expires = self._clock() + ttl if ttl is not None else None
        self._data[key] = (json.dumps(value, separators=(",", ":")), expires)
        self._data.move_to_end(key)
        if len(self._data) > self.max_entries:
            now = self._clock()
            for stale in [k for k, (_, exp) in self._data.items() if exp is not None and exp <= now]:
                del self._data[stale]
            while len(self._data) > self.max_entries:
                self._data.popitem(last=False)

    async def get(self, key: str) -> Any | None:
        raw = self._live(key)
        return None if raw is None else json.loads(raw)

    async def set(self, key: str, value: Any, ttl: float | None = None) -> None:
        self._put(key, value, ttl)

    async def add(self, key: str, value: Any, ttl: float | None = None) -> bool:
        if self._live(key) is not None:
            return False
        self._put(key, value, ttl)
        return True

    async def delete(self, key: str) -> None:
        self._data.pop(key, None)

    async def incr(self, key: str, ttl: float) -> int:
        raw = self._live(key)
        if raw is None:
            self._put(key, 1, ttl)
            return 1
        value = int(json.loads(raw)) + 1
        expires = self._data[key][1]
        self._data[key] = (json.dumps(value), expires)
        return value

    @asynccontextmanager
    async def lock(self, key: str, *, timeout: float, wait: float) -> AsyncIterator[None]:
        lock = self._locks.setdefault(key, asyncio.Lock())
        try:
            await asyncio.wait_for(lock.acquire(), timeout=wait)
        except TimeoutError as exc:
            raise LockTimeout(key) from exc
        try:
            yield
        finally:
            lock.release()
            if not lock.locked() and not getattr(lock, "_waiters", None):
                self._locks.pop(key, None)

    async def rate_limit(
        self, keys: list[tuple[str, str]], *, limit: int, window: float, burst: int, cost: float, now: float
    ) -> RateLimitDecision:
        async with self._meter_lock:
            return self.meters.check(keys, limit=limit, window=window, burst=burst, cost=cost, now=now)

    async def aclose(self) -> None:
        self._data.clear()
        self.meters.clear()

    def __len__(self) -> int:
        return len(self._data)


__all__ = ["MemoryStore"]
