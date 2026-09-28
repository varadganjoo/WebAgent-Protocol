"""Admission control: who gets in, under which limits, and how much proof-of-work they pay.

Every protection is the operator's choice. A :class:`WAPServer` takes defaults
(``rate_limit=``, ``require_pow=``, ``pow_difficulty=``) and an optional
``admission=`` hook that can override them per request, e.g. to give partner
agents higher limits, exempt authenticated customers from proof-of-work, or
block known-bad keys::

    async def admission(request: AdmissionRequest) -> AdmissionDecision:
        if request.agent_key in PARTNER_KEYS:
            return AdmissionDecision(tier="partner", rate_limit=RateLimitPolicy(requests_per_minute=6000, burst=500),
                                     require_pow=False)
        if request.principal is not None:          # bearer-authenticated customer
            return AdmissionDecision(tier="customer", require_pow=False)
        return AdmissionDecision()                  # server defaults

    wap = WAPServer(..., admission=admission)

The hook runs after the request's signature has been verified (so
``agent_key`` is proven) and after bearer authentication, but before any
proof-of-work is checked or capability runs.

:class:`AdaptivePow` raises proof-of-work difficulty automatically while the
server is under load, and lowers it again when load subsides.
"""

from __future__ import annotations

import inspect
import math
import time
from collections.abc import Awaitable, Callable, Mapping
from dataclasses import dataclass, field
from typing import Any, Literal

from ..spec.conversation import ConversationPolicy
from ..spec.models import RateLimitPolicy
from ..storage.base import StateStore


@dataclass(frozen=True)
class AdmissionRequest:
    """What the admission hook knows about a request (all identity fields are verified)."""

    client_ip: str | None
    agent_key: str | None
    principal: Any
    capability_id: str | None
    transport: Literal["wap", "mcp"]
    headers: Mapping[str, str] = field(default_factory=dict)


@dataclass(frozen=True)
class AdmissionDecision:
    """Per-request overrides. ``None`` means "use the server default"."""

    tier: str = "default"
    rate_limit: RateLimitPolicy | Literal[False] | None = None
    """Per-agent-key limits for this request; ``False`` disables them."""
    require_pow: bool | None = None
    pow_difficulty: int | None = None
    """Minimum difficulty a solution must have been issued at for this request."""
    deny: str | None = None
    """If set, the request is refused with ``forbidden`` and this message."""
    conversation_policy: ConversationPolicy | Literal[False] | None = None
    """Loop-protection limits for this request; ``False`` disables them (e.g. for a trusted
    aggregator that legitimately repeats the same call for many end users)."""


AdmissionHook = Callable[[AdmissionRequest], AdmissionDecision | Awaitable[AdmissionDecision]]


async def evaluate(hook: AdmissionHook | None, request: AdmissionRequest) -> AdmissionDecision:
    if hook is None:
        return AdmissionDecision()
    decision = hook(request)
    if inspect.isawaitable(decision):
        decision = await decision
    if not isinstance(decision, AdmissionDecision):
        raise TypeError("admission hook must return an AdmissionDecision")
    return decision


class AdaptivePow:
    """Scale proof-of-work difficulty with load.

    Load is the number of challenges issued in the current ``window_seconds``
    bucket (shared across workers through the store). Above
    ``threshold`` challenges per window, difficulty rises by one step for every
    doubling of load, up to ``max_extra`` steps; each step multiplies client work
    by 16.
    """

    def __init__(self, *, threshold: int = 300, window_seconds: float = 10.0, max_extra: int = 2) -> None:
        if threshold < 1 or window_seconds <= 0 or max_extra < 0:
            raise ValueError("invalid AdaptivePow parameters")
        self.threshold = threshold
        self.window_seconds = window_seconds
        self.max_extra = max_extra

    def _bucket(self, now: float) -> str:
        return f"pow-load:{int(now // self.window_seconds)}"

    async def difficulty(self, store: StateStore, base: int, *, record: bool, now: float | None = None) -> int:
        now = time.time() if now is None else now
        key = self._bucket(now)
        if record:
            load = await store.incr(key, self.window_seconds * 2)
        else:
            load = int(await store.get(key) or 0)
        if load <= self.threshold:
            return base
        extra = min(self.max_extra, 1 + int(math.log2(load / self.threshold)))
        return min(16, base + extra)


__all__ = ["AdaptivePow", "AdmissionDecision", "AdmissionHook", "AdmissionRequest", "evaluate"]
