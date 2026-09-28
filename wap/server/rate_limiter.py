"""Per-IP and per-agent-key rate limiting on top of a pluggable :class:`~wap.storage.StateStore`.

Each principal gets a sliding-window counter (sustained rate) and a token bucket
(bursts); see :mod:`wap.storage.meters`. A request is admitted only if every
applicable meter admits it, and meters are only charged on admission, so a
rejected request never consumes budget in another scope.

With the default :class:`~wap.storage.MemoryStore` the limits apply per process.
Pass a shared store (e.g. :class:`~wap.storage.RedisStore`) to enforce them
across every worker and machine.
"""

from __future__ import annotations

import time
from collections.abc import Callable, Iterable

from ..spec.models import RateLimitPolicy
from ..storage.base import StateStore
from ..storage.memory import MemoryStore
from ..storage.meters import RateLimitDecision, SlidingWindowCounter, TokenBucket


class RateLimiter:
    """Admits or rejects requests for (scope, principal) pairs under a :class:`RateLimitPolicy`."""

    def __init__(
        self,
        policy: RateLimitPolicy | None = None,
        store: StateStore | None = None,
        *,
        window_seconds: float = 60.0,
        idle_ttl: float = 600.0,
        max_keys: int = 100_000,
        clock: Callable[[], float] = time.time,
    ) -> None:
        self.policy = policy or RateLimitPolicy()
        self.window_seconds = window_seconds
        self.store: StateStore = store or MemoryStore(max_rate_keys=max_keys, rate_idle_ttl=idle_ttl)
        self._clock = clock

    def keys_for(
        self, ip: str | None, agent_key: str | None, policy: RateLimitPolicy | None = None
    ) -> list[tuple[str, str]]:
        policy = policy or self.policy
        keys: list[tuple[str, str]] = []
        if "ip" in policy.scopes and ip:
            keys.append(("ip", f"ip:{ip}"))
        if "agent_key" in policy.scopes and agent_key:
            keys.append(("agent_key", f"key:{agent_key}"))
        return keys

    async def check(
        self,
        *,
        ip: str | None = None,
        agent_key: str | None = None,
        cost: float = 1.0,
        policy: RateLimitPolicy | None = None,
    ) -> RateLimitDecision:
        """Admit or reject one request for the given principals (optionally under a tier's policy)."""
        return await self.check_keys(self.keys_for(ip, agent_key, policy), cost=cost, policy=policy)

    async def check_keys(
        self, keys: Iterable[tuple[str, str]], cost: float = 1.0, policy: RateLimitPolicy | None = None
    ) -> RateLimitDecision:
        policy = policy or self.policy
        keys = list(keys)
        if not keys:
            limit = policy.requests_per_minute
            return RateLimitDecision(allowed=True, limit=limit, remaining=limit, retry_after=0.0)
        return await self.store.rate_limit(
            keys,
            limit=policy.requests_per_minute,
            window=self.window_seconds,
            burst=policy.burst,
            cost=cost,
            now=self._clock(),
        )

    def reset(self) -> None:
        if isinstance(self.store, MemoryStore):
            self.store.meters.clear()

    def tracked_keys(self) -> int:
        """Number of principals tracked in process (in-memory store only)."""
        return len(self.store.meters) if isinstance(self.store, MemoryStore) else 0


__all__ = ["RateLimitDecision", "RateLimiter", "SlidingWindowCounter", "TokenBucket"]
