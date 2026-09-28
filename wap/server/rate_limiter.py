"""Async in-memory rate limiting: sliding-window counters combined with token buckets.

Each principal (a client IP address or an agent public key) gets two meters:

* a **sliding-window counter** bounding the sustained rate
  (``requests_per_minute`` over a rolling 60 s window), and
* a **token bucket** bounding bursts (``burst`` tokens, refilled at the
  sustained rate).

A request is admitted only if *every* applicable meter admits it. Meters are
only charged when the request is admitted, so a rejected request never
consumes budget in another scope.
"""

from __future__ import annotations

import asyncio
import math
import time
from collections.abc import Callable, Iterable
from dataclasses import dataclass

from ..spec.models import RateLimitPolicy


@dataclass(frozen=True)
class RateLimitDecision:
    allowed: bool
    limit: int
    remaining: int
    retry_after: float
    scope: str | None = None

    def headers(self) -> dict[str, str]:
        """Standard ``RateLimit-*`` style headers for this decision."""
        headers = {
            "X-RateLimit-Limit": str(self.limit),
            "X-RateLimit-Remaining": str(max(0, self.remaining)),
        }
        if not self.allowed:
            headers["Retry-After"] = str(max(1, math.ceil(self.retry_after)))
        return headers


class TokenBucket:
    """Classic token bucket: ``capacity`` tokens, refilled at ``rate`` tokens/second."""

    __slots__ = ("capacity", "rate", "tokens", "updated")

    def __init__(self, capacity: float, rate: float, now: float) -> None:
        self.capacity = float(capacity)
        self.rate = float(rate)
        self.tokens = float(capacity)
        self.updated = now

    def _refill(self, now: float) -> None:
        elapsed = max(0.0, now - self.updated)
        self.tokens = min(self.capacity, self.tokens + elapsed * self.rate)
        self.updated = now

    def peek(self, now: float, cost: float = 1.0) -> float:
        """Seconds until ``cost`` tokens are available (0 if available now)."""
        self._refill(now)
        if self.tokens >= cost:
            return 0.0
        return (cost - self.tokens) / self.rate

    def consume(self, now: float, cost: float = 1.0) -> None:
        self._refill(now)
        self.tokens -= cost

    @property
    def remaining(self) -> int:
        return int(self.tokens)


class SlidingWindowCounter:
    """Sliding-window counter (Cloudflare-style weighted two-bucket approximation).

    The estimated count over the last ``window`` seconds is
    ``previous * (1 - elapsed_fraction) + current``. Memory is O(1) per key and
    the error versus a true sliding log is bounded by one window's skew.
    """

    __slots__ = ("limit", "window", "window_start", "current", "previous")

    def __init__(self, limit: int, window: float, now: float) -> None:
        self.limit = limit
        self.window = window
        self.window_start = now - (now % window)
        self.current = 0
        self.previous = 0

    def _roll(self, now: float) -> None:
        start = now - (now % self.window)
        if start == self.window_start:
            return
        if start - self.window_start >= 2 * self.window:
            self.previous = 0
        else:
            self.previous = self.current
        self.current = 0
        self.window_start = start

    def estimate(self, now: float) -> float:
        self._roll(now)
        elapsed = (now - self.window_start) / self.window
        return self.previous * (1.0 - elapsed) + self.current

    def peek(self, now: float) -> float:
        """Seconds until one more request fits (0 if it fits now)."""
        estimate = self.estimate(now)
        if estimate + 1 <= self.limit:
            return 0.0
        if self.current + 1 > self.limit:
            return self.window_start + self.window - now
        if self.previous == 0:
            return self.window_start + self.window - now
        # Solve previous * (1 - (t - start)/window) + current + 1 <= limit for t.
        needed_fraction = 1.0 - (self.limit - self.current - 1) / self.previous
        target = self.window_start + needed_fraction * self.window
        return max(0.0, target - now)

    def consume(self, now: float) -> None:
        self._roll(now)
        self.current += 1

    def remaining(self, now: float) -> int:
        return max(0, int(self.limit - self.estimate(now)))


class _Meter:
    __slots__ = ("window", "bucket", "last_seen")

    def __init__(self, policy: RateLimitPolicy, now: float, window_seconds: float) -> None:
        self.window = SlidingWindowCounter(policy.requests_per_minute, window_seconds, now)
        self.bucket = TokenBucket(policy.burst, policy.requests_per_minute / window_seconds, now)
        self.last_seen = now

    def wait_time(self, now: float, cost: float) -> float:
        return max(self.window.peek(now), self.bucket.peek(now, cost))

    def consume(self, now: float, cost: float) -> None:
        self.window.consume(now)
        self.bucket.consume(now, cost)
        self.last_seen = now

    def remaining(self, now: float) -> int:
        return min(self.window.remaining(now), self.bucket.remaining)


class RateLimiter:
    """Per-IP and per-agent-key limiter shared by all WAP endpoints of a server."""

    def __init__(
        self,
        policy: RateLimitPolicy | None = None,
        *,
        window_seconds: float = 60.0,
        idle_ttl: float = 600.0,
        max_keys: int = 100_000,
        clock: Callable[[], float] = time.monotonic,
    ) -> None:
        self.policy = policy or RateLimitPolicy()
        self.window_seconds = window_seconds
        self.idle_ttl = idle_ttl
        self.max_keys = max_keys
        self._clock = clock
        self._meters: dict[str, _Meter] = {}
        self._lock = asyncio.Lock()
        self._last_gc = clock()

    def _meter(self, key: str, now: float) -> _Meter:
        meter = self._meters.get(key)
        if meter is None:
            meter = _Meter(self.policy, now, self.window_seconds)
            self._meters[key] = meter
        return meter

    def _gc(self, now: float) -> None:
        if now - self._last_gc < self.window_seconds and len(self._meters) < self.max_keys:
            return
        cutoff = now - self.idle_ttl
        for key in [k for k, m in self._meters.items() if m.last_seen < cutoff]:
            del self._meters[key]
        if len(self._meters) >= self.max_keys:
            # Evict least-recently-seen principals to bound memory under key-spraying.
            ordered = sorted(self._meters.items(), key=lambda item: item[1].last_seen)
            for key, _ in ordered[: len(self._meters) - self.max_keys + 1]:
                del self._meters[key]
        self._last_gc = now

    def _keys(self, ip: str | None, agent_key: str | None) -> list[tuple[str, str]]:
        keys: list[tuple[str, str]] = []
        if "ip" in self.policy.scopes and ip:
            keys.append(("ip", f"ip:{ip}"))
        if "agent_key" in self.policy.scopes and agent_key:
            keys.append(("agent_key", f"key:{agent_key}"))
        return keys

    async def check(
        self, *, ip: str | None = None, agent_key: str | None = None, cost: float = 1.0
    ) -> RateLimitDecision:
        """Admit or reject one request for the given principals."""
        return await self.check_keys(self._keys(ip, agent_key), cost=cost)

    async def check_keys(self, keys: Iterable[tuple[str, str]], cost: float = 1.0) -> RateLimitDecision:
        keys = list(keys)
        limit = self.policy.requests_per_minute
        if not keys:
            return RateLimitDecision(allowed=True, limit=limit, remaining=limit, retry_after=0.0)
        async with self._lock:
            now = self._clock()
            self._gc(now)
            meters = [(scope, self._meter(key, now)) for scope, key in keys]
            worst_scope, worst_wait = None, 0.0
            for scope, meter in meters:
                wait = meter.wait_time(now, cost)
                if wait > worst_wait:
                    worst_scope, worst_wait = scope, wait
            if worst_wait > 0:
                remaining = min(m.remaining(now) for _, m in meters)
                return RateLimitDecision(
                    allowed=False, limit=limit, remaining=remaining, retry_after=worst_wait, scope=worst_scope
                )
            for _, meter in meters:
                meter.consume(now, cost)
            remaining = min(m.remaining(now) for _, m in meters)
            return RateLimitDecision(allowed=True, limit=limit, remaining=remaining, retry_after=0.0)

    def reset(self) -> None:
        self._meters.clear()

    def tracked_keys(self) -> int:
        return len(self._meters)


__all__ = ["RateLimitDecision", "RateLimiter", "SlidingWindowCounter", "TokenBucket"]
