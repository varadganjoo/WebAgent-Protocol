"""Redis-backed :class:`StateStore` for multi-worker and multi-machine deployments.

Install with ``pip install "webagent-protocol[redis]"`` and pass it to the server::

    from wap.storage import RedisStore
    wap = WAPServer(..., store=RedisStore.from_url("redis://redis:6379/0", prefix="bakery:"))

All workers pointing at the same Redis database (and prefix) share rate limits,
replay protection, spent proof-of-work seeds, sessions, loop guards and
idempotency records. Rate limiting runs as a single Lua script, so the
check-and-charge of every meter involved in a request is atomic.

Keys are namespaced with ``prefix``. Multi-key rate-limit calls must hash to one
slot on Redis Cluster; use a single-shard deployment or a ``prefix`` containing a
hash tag such as ``"{wap}:"`` if you run a cluster.
"""

from __future__ import annotations

import json
import secrets
from collections.abc import AsyncIterator
from contextlib import asynccontextmanager
from typing import Any

try:
    from redis.asyncio import Redis
except ImportError as exc:  # pragma: no cover - exercised only without the extra
    raise ImportError('RedisStore requires the redis extra: pip install "webagent-protocol[redis]"') from exc

from .base import LockTimeout
from .meters import RateLimitDecision

# KEYS: meter keys. ARGV: limit, window, burst, cost, now, idle_ttl_ms.
# Returns {allowed(0/1), retry_after(string), worst_index, remaining}.
_RATE_LIMIT_LUA = """
local limit = tonumber(ARGV[1])
local window = tonumber(ARGV[2])
local burst = tonumber(ARGV[3])
local cost = tonumber(ARGV[4])
local now = tonumber(ARGV[5])
local idle_ms = tonumber(ARGV[6])
local rate = limit / window
local state = {}
local worst, worst_i = 0, 0
for i, key in ipairs(KEYS) do
  local v = redis.call('HMGET', key, 'ws', 'cur', 'prev', 'tokens', 'upd')
  local ws, cur, prev, tokens, upd
  if v[1] then
    ws, cur, prev = tonumber(v[1]), tonumber(v[2]), tonumber(v[3])
    tokens, upd = tonumber(v[4]), tonumber(v[5])
  else
    ws, cur, prev, tokens, upd = now - (now % window), 0, 0, burst, now
  end
  local start = now - (now % window)
  if start ~= ws then
    if start - ws >= 2 * window then prev = 0 else prev = cur end
    cur = 0
    ws = start
  end
  local elapsed = now - upd
  if elapsed < 0 then elapsed = 0 end
  tokens = math.min(burst, tokens + elapsed * rate)
  upd = now
  local estimate = prev * (1 - (now - ws) / window) + cur
  local wait_w = 0
  if estimate + 1 > limit then
    if cur + 1 > limit or prev == 0 then
      wait_w = ws + window - now
    else
      local needed = 1 - (limit - cur - 1) / prev
      wait_w = math.max(0, ws + needed * window - now)
    end
  end
  local wait_b = 0
  if tokens < cost then wait_b = (cost - tokens) / rate end
  local wait = math.max(wait_w, wait_b)
  if wait > worst then worst, worst_i = wait, i end
  state[i] = {ws, cur, prev, tokens, upd}
end
local allowed = 1
if worst > 0 then allowed = 0 end
local remaining = nil
for i, key in ipairs(KEYS) do
  local s = state[i]
  if allowed == 1 then
    s[2] = s[2] + 1
    s[4] = s[4] - cost
  end
  redis.call('HSET', key, 'ws', tostring(s[1]), 'cur', tostring(s[2]), 'prev', tostring(s[3]),
             'tokens', tostring(s[4]), 'upd', tostring(s[5]))
  redis.call('PEXPIRE', key, idle_ms)
  local est = s[3] * (1 - (now - s[1]) / window) + s[2]
  local r = math.min(math.floor(limit - est), math.floor(s[4]))
  if r < 0 then r = 0 end
  if remaining == nil or r < remaining then remaining = r end
end
return {allowed, tostring(worst), worst_i, remaining}
"""

_RELEASE_LUA = """
if redis.call('GET', KEYS[1]) == ARGV[1] then return redis.call('DEL', KEYS[1]) end
return 0
"""


class RedisStore:
    """Shared state in Redis. Safe to use from many workers and machines at once."""

    def __init__(
        self,
        client: Redis,
        *,
        prefix: str = "wap:",
        rate_idle_ttl: float = 600.0,
        lock_poll_interval: float = 0.05,
    ) -> None:
        self.redis = client
        self.prefix = prefix
        self.rate_idle_ttl = rate_idle_ttl
        self.lock_poll_interval = lock_poll_interval
        self._rate_script = client.register_script(_RATE_LIMIT_LUA)
        self._release_script = client.register_script(_RELEASE_LUA)

    @classmethod
    def from_url(cls, url: str, **kwargs: Any) -> RedisStore:
        """Connect with a ``redis://`` / ``rediss://`` URL (``rediss`` for TLS)."""
        store_kwargs = {k: kwargs.pop(k) for k in ("prefix", "rate_idle_ttl", "lock_poll_interval") if k in kwargs}
        return cls(Redis.from_url(url, **kwargs), **store_kwargs)

    def _k(self, key: str) -> str:
        return self.prefix + key

    async def get(self, key: str) -> Any | None:
        raw = await self.redis.get(self._k(key))
        return None if raw is None else json.loads(raw)

    async def set(self, key: str, value: Any, ttl: float | None = None) -> None:
        px = max(1, int(ttl * 1000)) if ttl is not None else None
        await self.redis.set(self._k(key), json.dumps(value, separators=(",", ":")), px=px)

    async def add(self, key: str, value: Any, ttl: float | None = None) -> bool:
        px = max(1, int(ttl * 1000)) if ttl is not None else None
        stored = await self.redis.set(self._k(key), json.dumps(value, separators=(",", ":")), px=px, nx=True)
        return bool(stored)

    async def delete(self, key: str) -> None:
        await self.redis.delete(self._k(key))

    async def incr(self, key: str, ttl: float) -> int:
        name = self._k(key)
        pipe = self.redis.pipeline(transaction=True)
        pipe.incr(name)
        pipe.pexpire(name, max(1, int(ttl * 1000)), nx=True)
        value, _ = await pipe.execute()
        return int(value)

    @asynccontextmanager
    async def lock(self, key: str, *, timeout: float, wait: float) -> AsyncIterator[None]:
        import anyio

        name = self._k("lock:" + key)
        token = secrets.token_hex(16)
        px = max(1, int(timeout * 1000))
        acquired = False
        with anyio.move_on_after(wait):
            while not acquired:
                acquired = bool(await self.redis.set(name, token, px=px, nx=True))
                if not acquired:
                    await anyio.sleep(self.lock_poll_interval)
        if not acquired:
            raise LockTimeout(key)
        try:
            yield
        finally:
            # Only release if we still own it (the lock may have expired and been re-taken).
            await self._release_script(keys=[name], args=[token])

    async def rate_limit(
        self, keys: list[tuple[str, str]], *, limit: int, window: float, burst: int, cost: float, now: float
    ) -> RateLimitDecision:
        if not keys:
            return RateLimitDecision(allowed=True, limit=limit, remaining=limit, retry_after=0.0)
        redis_keys = [self._k(f"rl:{limit}:{window}:{burst}:{key}") for _, key in keys]
        allowed, retry_after, worst_index, remaining = await self._rate_script(
            keys=redis_keys,
            args=[limit, window, burst, cost, repr(float(now)), int(self.rate_idle_ttl * 1000)],
        )
        scope = keys[int(worst_index) - 1][0] if int(worst_index) > 0 else None
        return RateLimitDecision(
            allowed=bool(int(allowed)),
            limit=limit,
            remaining=int(remaining),
            retry_after=float(retry_after),
            scope=None if int(allowed) else scope,
        )

    async def aclose(self) -> None:
        await self.redis.aclose()


__all__ = ["RedisStore"]
