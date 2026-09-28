"""Conversation guards: stop two agents from talking in circles.

When an LLM-driven user agent negotiates with an LLM-driven business agent,
neither side is guaranteed to converge. Typical failure modes are:

* **stuck repetition**: the same question gets the same answer again and again
  ("do you have croissants?" → "yes, 24" → "do you have croissants?" …);
* **ping-pong cycles**: the agents alternate between two or three states
  (offer A → counter B → offer A → counter B …);
* **stalls**: the same request over and over while only a counter or timestamp
  in the answer changes;
* **runaway sessions**: an unbounded number of turns, each costing tokens.

:class:`ConversationGuard` detects all three from *fingerprints* of each
exchange (request plus reply). Fingerprints ignore message ids, timestamps,
signatures, proof-of-work and trivial formatting (case, whitespace,
punctuation), so cosmetic rephrasing does not hide a loop. A repeated request
that gets a *different* answer (for example, polling stock that is changing) is
progress, not a loop.

The same guard runs on both sides:

* the business agent refuses a request that would continue a detected loop,
  *before* running any tool (``loop_detected`` / ``conversation_limit`` errors);
* the user agent (``WAPSession``, the MCP bridge) stops itself and tells the
  model to report back to the user instead of retrying.
"""

from __future__ import annotations

import hashlib
import re
import time
from collections import deque
from dataclasses import dataclass, field
from typing import Any

from .crypto import canonical_json

_PUNCT = re.compile(r"[^\w]+", re.UNICODE)


def normalize_text(text: str) -> str:
    """Case-, whitespace- and punctuation-insensitive form of ``text``."""
    return " ".join(_PUNCT.sub(" ", text.lower()).split())


def fingerprint(*parts: Any) -> str:
    """Stable short hash of JSON-compatible parts (strings are normalised)."""
    normalised = [normalize_text(p) if isinstance(p, str) else p for p in parts]
    return hashlib.sha256(canonical_json(normalised)).hexdigest()[:16]


def request_fingerprint(capability_id: str | None, structured_data: dict[str, Any] | None, content: str) -> str:
    return fingerprint("req", capability_id or "", structured_data or {}, content or "")


def reply_fingerprint(content: str, structured_data: dict[str, Any] | None) -> str:
    return fingerprint("rep", content or "", structured_data or {})


class ConversationLimitError(Exception):
    """Raised when a conversation must stop. ``reason`` is ``"loop_detected"`` or ``"conversation_limit"``."""

    def __init__(self, reason: str, message: str, details: dict[str, Any] | None = None) -> None:
        super().__init__(message)
        self.reason = reason
        self.message = message
        self.details = details or {}


@dataclass(frozen=True)
class ConversationPolicy:
    """Loop-protection limits. Published by business agents in ``conversation_policy``."""

    max_turns: int = 100
    """Hard cap on turns in one session."""
    max_repeats: int = 3
    """How many times the same exchange (or cycle of exchanges) may occur in a row."""
    max_cycle_length: int = 3
    """Longest cycle (in turns) that is detected, e.g. 2 catches A-B-A-B ping-pong."""
    window_seconds: float = 300.0
    """Only exchanges this recent count towards repetition; older ones are forgotten."""
    max_identical_requests: int = 5
    """The same request may be sent at most this many times in a row, even if answers differ
    (catches stalls where only counters or timestamps change). Raise it for deliberate polling."""
    max_repeats_across_sessions: int = 10
    """Looser threshold for loops that hop across fresh session ids under one agent key
    (one key may legitimately serve several end users)."""

    def as_dict(self) -> dict[str, Any]:
        return {
            "max_turns": self.max_turns,
            "max_repeats": self.max_repeats,
            "max_cycle_length": self.max_cycle_length,
            "window_seconds": self.window_seconds,
            "max_identical_requests": self.max_identical_requests,
            "max_repeats_across_sessions": self.max_repeats_across_sessions,
        }


@dataclass
class _Exchange:
    request: str
    reply: str
    at: float


@dataclass
class ConversationGuard:
    """Tracks one conversation and decides whether the next request may proceed."""

    policy: ConversationPolicy = field(default_factory=ConversationPolicy)
    turns: int = 0
    _history: deque[_Exchange] = field(default_factory=deque)

    def _recent(self, now: float) -> list[_Exchange]:
        cutoff = now - self.policy.window_seconds
        while self._history and self._history[0].at < cutoff:
            self._history.popleft()
        return list(self._history)

    def check(self, request_fp: str, now: float | None = None) -> None:
        """Raise :class:`ConversationLimitError` if sending ``request_fp`` would continue a loop.

        The request is refused if the conversation is out of turns, or if the
        last ``max_repeats`` repetitions of some cycle of length ≤ ``max_cycle_length``
        would be extended by this request with no new information (every
        exchange in the cycle got the same reply each time).
        """
        now = time.time() if now is None else now
        if self.turns >= self.policy.max_turns:
            raise ConversationLimitError(
                "conversation_limit",
                f"this conversation reached its limit of {self.policy.max_turns} turns",
                {"max_turns": self.policy.max_turns},
            )
        recent = self._recent(now)
        identical = 0
        for exchange in reversed(recent):
            if exchange.request != request_fp:
                break
            identical += 1
        if identical >= self.policy.max_identical_requests:
            raise ConversationLimitError(
                "loop_detected",
                f"loop detected: the same request was sent {identical} times in a row without converging; "
                "change the request or stop and report back to the user",
                {"identical_requests": identical},
            )
        repeats = self.policy.max_repeats
        for period in range(1, self.policy.max_cycle_length + 1):
            needed = period * repeats
            if len(recent) < needed:
                break
            tail = recent[-needed:]
            block = tail[:period]
            if (
                all(
                    tail[i].request == block[i % period].request and tail[i].reply == block[i % period].reply
                    for i in range(needed)
                )
                and request_fp == block[0].request
            ):
                kind = "the same request" if period == 1 else f"a cycle of {period} requests"
                raise ConversationLimitError(
                    "loop_detected",
                    f"loop detected: {kind} got the same answer {repeats} times in a row; "
                    "change the request or stop and report back to the user",
                    {"cycle_length": period, "repeats": repeats},
                )

    def record(self, request_fp: str, reply_fp: str, now: float | None = None) -> None:
        now = time.time() if now is None else now
        self.turns += 1
        self._history.append(_Exchange(request_fp, reply_fp, now))
        max_len = max(self.policy.max_cycle_length * self.policy.max_repeats, self.policy.max_identical_requests)
        while len(self._history) > max_len:
            self._history.popleft()


__all__ = [
    "ConversationGuard",
    "ConversationLimitError",
    "ConversationPolicy",
    "fingerprint",
    "normalize_text",
    "reply_fingerprint",
    "request_fingerprint",
]
