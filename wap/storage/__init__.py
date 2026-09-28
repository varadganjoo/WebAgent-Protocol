"""Pluggable state storage for WAP servers (in-memory by default, Redis for multi-worker deployments)."""

from __future__ import annotations

from typing import Any

from .base import LockTimeout, StateStore
from .memory import MemoryStore
from .meters import MeterTable, RateLimitDecision, SlidingWindowCounter, TokenBucket


def __getattr__(name: str) -> Any:
    # RedisStore needs the optional ``redis`` package; import it lazily.
    if name == "RedisStore":
        from .redis import RedisStore

        return RedisStore
    raise AttributeError(name)


__all__ = [
    "LockTimeout",
    "MemoryStore",
    "MeterTable",
    "RateLimitDecision",
    "RedisStore",
    "SlidingWindowCounter",
    "StateStore",
    "TokenBucket",
]
