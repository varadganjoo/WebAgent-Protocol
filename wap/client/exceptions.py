"""Exceptions raised by the WAP consumer SDK."""

from __future__ import annotations

from typing import Any


class WAPError(Exception):
    """Base class for every error raised by :mod:`wap.client`."""


class ManifestNotFound(WAPError):
    """No valid ``/.well-known/wap.json`` (or legacy ``agent.json``) could be retrieved for a domain."""

    def __init__(self, domain: str, message: str, *, url: str | None = None, status_code: int | None = None) -> None:
        super().__init__(f"{domain}: {message}")
        self.domain = domain
        self.url = url
        self.status_code = status_code


class VerificationFailed(WAPError):
    """A manifest or message failed cryptographic or binding verification."""

    def __init__(self, domain: str, message: str) -> None:
        super().__init__(f"{domain}: {message}")
        self.domain = domain


class InsecureTransport(WAPError):
    """Plain HTTP was requested for a non-loopback domain without ``allow_insecure``."""


class CapabilityNotFound(WAPError):
    """The requested capability is not declared in the remote manifest."""

    def __init__(self, domain: str, capability_id: str, available: list[str]) -> None:
        super().__init__(
            f"{domain} does not offer capability {capability_id!r}; available: {', '.join(available) or 'none'}"
        )
        self.domain = domain
        self.capability_id = capability_id
        self.available = available


class SchemaValidationError(WAPError):
    """``payload`` does not satisfy the capability's declared ``input_schema``."""

    def __init__(self, capability_id: str, errors: list[str]) -> None:
        super().__init__(f"payload for {capability_id!r} is invalid: {'; '.join(errors)}")
        self.capability_id = capability_id
        self.errors = errors


class ProtocolError(WAPError):
    """The remote agent answered with a WAP error object or violated the protocol."""

    def __init__(
        self,
        code: str,
        message: str,
        *,
        status_code: int | None = None,
        details: dict[str, Any] | None = None,
        retry_after: float | None = None,
    ) -> None:
        super().__init__(f"[{code}] {message}")
        self.code = code
        self.message = message
        self.status_code = status_code
        self.details = details or {}
        self.retry_after = retry_after


class RateLimited(ProtocolError):
    """HTTP 429: back off for ``retry_after`` seconds."""


class ProofOfWorkFailed(ProtocolError):
    """The server kept rejecting proof-of-work solutions."""


class AuthRequired(ProtocolError):
    """The capability requires a bearer token that was missing or rejected."""


class EffectsNotPermitted(ProtocolError):
    """The business wanted to run a capability with stronger effects than the request permitted.

    ``details`` names the ``capability_id``, its ``effects`` and the ``payload`` it would have
    used, so the user can be asked and the capability then called directly.
    """


class ConfirmationDeclined(WAPError):
    """The client's ``confirm`` hook declined an action with side effects; nothing was sent."""

    def __init__(self, domain: str, capability_id: str) -> None:
        super().__init__(f"{domain}: the user declined {capability_id!r}; nothing was sent")
        self.domain = domain
        self.capability_id = capability_id


class ConversationStopped(ProtocolError):
    """The conversation was halted to prevent an agent-to-agent loop.

    Raised either locally (``status_code is None``: the client refused to send) or
    because the business agent refused. Do not retry the same request; change it
    or hand control back to the user.
    """


class LoopDetected(ConversationStopped):
    """The same exchange (or a short cycle of exchanges) keeps repeating with no new information."""


class ConversationLimitReached(ConversationStopped):
    """The session used up its turn budget."""


__all__ = [
    "AuthRequired",
    "CapabilityNotFound",
    "ConfirmationDeclined",
    "ConversationLimitReached",
    "ConversationStopped",
    "EffectsNotPermitted",
    "InsecureTransport",
    "LoopDetected",
    "ManifestNotFound",
    "ProofOfWorkFailed",
    "ProtocolError",
    "RateLimited",
    "SchemaValidationError",
    "VerificationFailed",
    "WAPError",
]
