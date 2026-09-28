"""Dialogue sessions persisted in a :class:`~wap.storage.StateStore`.

A session is a JSON document holding the conversation history, the
application's own ``state`` dict (what actions read and write through
``ctx.state``), the owning agent key and the loop-guard history. It is loaded
at the start of a turn under a per-session lock and saved at the end, so
concurrent requests for the same session are serialised across every worker
sharing the store.

Values written to ``ctx.state`` must therefore be JSON-serialisable.
"""

from __future__ import annotations

import json
import time
from dataclasses import dataclass, field
from typing import Any

from ..spec.conversation import ConversationGuard, ConversationPolicy
from ..spec.models import AgentMessage, ErrorCode
from ..storage.base import StateStore


@dataclass
class SessionState:
    session_id: str
    owner_key: str | None
    created_at: float = field(default_factory=time.time)
    last_seen: float = field(default_factory=time.time)
    history: list[AgentMessage] = field(default_factory=list)
    state: dict[str, Any] = field(default_factory=dict)
    guard: ConversationGuard | None = None

    def to_dict(self) -> dict[str, Any]:
        return {
            "session_id": self.session_id,
            "owner_key": self.owner_key,
            "created_at": self.created_at,
            "last_seen": self.last_seen,
            "history": [m.model_dump(mode="json") for m in self.history],
            "state": self.state,
            "guard": self.guard.to_dict() if self.guard is not None else None,
        }

    @classmethod
    def from_dict(cls, data: dict[str, Any], policy: ConversationPolicy | None) -> SessionState:
        return cls(
            session_id=data["session_id"],
            owner_key=data.get("owner_key"),
            created_at=float(data.get("created_at", time.time())),
            last_seen=float(data.get("last_seen", time.time())),
            history=[AgentMessage.model_validate(m) for m in data.get("history", [])],
            state=dict(data.get("state") or {}),
            guard=ConversationGuard.from_dict(policy, data.get("guard")) if policy is not None else None,
        )


class SessionManager:
    """Loads, saves and locks sessions in a shared store."""

    def __init__(
        self,
        store: StateStore,
        *,
        ttl_seconds: float = 3600.0,
        max_history: int = 100,
        conversation_policy: ConversationPolicy | None = None,
        lock_timeout: float = 120.0,
        lock_wait: float = 10.0,
    ) -> None:
        self.store = store
        self.ttl_seconds = ttl_seconds
        self.max_history = max_history
        self.conversation_policy = conversation_policy
        self.lock_timeout = lock_timeout
        self.lock_wait = lock_wait

    @staticmethod
    def _key(session_id: str) -> str:
        return f"session:{session_id}"

    def lock(self, session_id: str) -> Any:
        return self.store.lock(self._key(session_id), timeout=self.lock_timeout, wait=self.lock_wait)

    async def get(self, session_id: str) -> SessionState | None:
        data = await self.store.get(self._key(session_id))
        return None if data is None else SessionState.from_dict(data, self.conversation_policy)

    async def load(self, session_id: str, owner_key: str | None) -> SessionState:
        """Return the session, creating it if absent. Raises if another key owns it."""
        from .app import WAPProtocolError

        session = await self.get(session_id)
        if session is None:
            guard = ConversationGuard(self.conversation_policy) if self.conversation_policy is not None else None
            return SessionState(session_id=session_id, owner_key=owner_key, guard=guard)
        if session.owner_key != owner_key:
            raise WAPProtocolError(ErrorCode.FORBIDDEN, "session belongs to a different agent key")
        return session

    async def save(self, session: SessionState) -> None:
        session.last_seen = time.time()
        if len(session.history) > self.max_history:
            del session.history[: len(session.history) - self.max_history]
        document = session.to_dict()
        try:
            json.dumps(document)
        except (TypeError, ValueError) as exc:
            raise TypeError(
                f"session {session.session_id!r} state is not JSON-serialisable ({exc}); "
                "store only JSON values in ctx.state"
            ) from exc
        await self.store.set(self._key(session.session_id), document, ttl=self.ttl_seconds)


__all__ = ["SessionManager", "SessionState"]
