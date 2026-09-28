"""Pydantic v2 data contracts for WebAgent Protocol (WAP/1.0).

Every object that crosses the wire is defined here. The models are shared by
the provider SDK (``wap.server``), the consumer SDK (``wap.client``) and the
MCP bridge so that both sides of a conversation validate against exactly the
same contract.
"""

from __future__ import annotations

import re
import time
import uuid
from enum import Enum
from typing import Any, Literal
from urllib.parse import urlsplit

from pydantic import BaseModel, ConfigDict, Field, field_validator, model_validator

WAP_VERSION = "1.0"
WELL_KNOWN_PATH = "/.well-known/agent.json"
INTERACT_PATH = "/wap/v1/interact"
CHALLENGE_PATH = "/wap/v1/challenge"

HEADER_VERSION = "X-WAP-Version"
HEADER_SIGNATURE = "X-WAP-Signature"
HEADER_KEY_ID = "X-WAP-Key-Id"
HEADER_AGENT_KEY = "X-WAP-Agent-Key"

POW_ALGORITHM = "sha256-leading-zero-hex"

_HEX_RE = re.compile(r"^[0-9a-f]*$")
_LABEL_RE = re.compile(r"^(?!-)[a-z0-9-]{1,63}(?<!-)$")
_CAPABILITY_ID_RE = re.compile(r"^[a-z][a-z0-9_.-]{0,63}$")


def _now() -> float:
    return time.time()


def _new_id() -> str:
    return uuid.uuid4().hex


def normalize_authority(value: str) -> str:
    """Validate and normalise a WAP ``domain`` (an RFC 3986 authority without userinfo).

    Accepts a fully-qualified domain name, ``localhost``, or an IPv4 literal,
    optionally followed by ``:port``. The host part is lower-cased and a
    trailing root dot is removed. Raises ``ValueError`` on anything else.
    """
    if not isinstance(value, str) or not value:
        raise ValueError("domain must be a non-empty string")
    raw = value.strip().lower()
    if "://" in raw or "/" in raw or "@" in raw or "?" in raw or "#" in raw:
        raise ValueError(f"domain must be a bare host[:port], got {value!r}")
    host, sep, port = raw.rpartition(":") if raw.count(":") == 1 else (raw, "", "")
    if sep:
        if not port.isdigit() or not 0 < int(port) < 65536:
            raise ValueError(f"invalid port in domain {value!r}")
    host = host.rstrip(".")
    if len(host) > 253 or not host:
        raise ValueError(f"invalid host in domain {value!r}")
    labels = host.split(".")
    if not all(_LABEL_RE.match(label) for label in labels):
        raise ValueError(f"domain {value!r} is not a valid hostname")
    if all(label.isdigit() for label in labels):
        if len(labels) != 4 or any(int(label) > 255 for label in labels):
            raise ValueError(f"domain {value!r} is not a valid IPv4 literal")
    elif len(labels) < 2 and host != "localhost":
        raise ValueError(f"domain {value!r} must be fully qualified (or 'localhost')")
    return f"{host}:{port}" if sep else host


def authority_host(authority: str) -> str:
    """Return the host component of a ``host[:port]`` authority."""
    return authority.rsplit(":", 1)[0] if authority.count(":") == 1 else authority


def is_local_authority(authority: str) -> bool:
    """True for loopback authorities where plain HTTP is acceptable."""
    host = authority_host(authority)
    return host == "localhost" or host.endswith(".localhost") or host.startswith("127.")


class Role(str, Enum):
    USER_AGENT = "user_agent"
    BUSINESS_AGENT = "business_agent"


class ErrorCode(str, Enum):
    """Machine-readable error codes (see docs/spec_rfc.md, Section 9)."""

    INVALID_REQUEST = "invalid_request"
    UNSUPPORTED_VERSION = "unsupported_version"
    INVALID_SIGNATURE = "invalid_signature"
    AUTH_REQUIRED = "auth_required"
    FORBIDDEN = "forbidden"
    UNKNOWN_CAPABILITY = "unknown_capability"
    REPLAY_DETECTED = "replay_detected"
    VALIDATION_ERROR = "validation_error"
    POW_REQUIRED = "pow_required"
    POW_INVALID = "pow_invalid"
    RATE_LIMITED = "rate_limited"
    ACTION_FAILED = "action_failed"
    INTERNAL_ERROR = "internal_error"


ERROR_STATUS: dict[ErrorCode, int] = {
    ErrorCode.INVALID_REQUEST: 400,
    ErrorCode.UNSUPPORTED_VERSION: 400,
    ErrorCode.INVALID_SIGNATURE: 401,
    ErrorCode.AUTH_REQUIRED: 401,
    ErrorCode.FORBIDDEN: 403,
    ErrorCode.POW_INVALID: 403,
    ErrorCode.UNKNOWN_CAPABILITY: 404,
    ErrorCode.REPLAY_DETECTED: 409,
    ErrorCode.VALIDATION_ERROR: 422,
    ErrorCode.POW_REQUIRED: 428,
    ErrorCode.RATE_LIMITED: 429,
    ErrorCode.ACTION_FAILED: 502,
    ErrorCode.INTERNAL_ERROR: 500,
}


class WAPModel(BaseModel):
    model_config = ConfigDict(extra="forbid", populate_by_name=True)


class Capability(WAPModel):
    """A machine-executable action offered by a business agent."""

    id: str = Field(description="Stable identifier, unique within a manifest.")
    name: str = Field(min_length=1, max_length=128, description="Human readable name.")
    description: str = Field(default="", max_length=4096)
    input_schema: dict[str, Any] = Field(
        default_factory=lambda: {"type": "object", "properties": {}},
        description="JSON Schema (draft 2020-12) for the capability's structured_data input.",
    )
    output_schema: dict[str, Any] | None = Field(
        default=None, description="JSON Schema describing structured_data in the reply."
    )
    requires_auth: bool = False
    streaming: bool = Field(default=False, description="Whether the action streams tokens natively.")

    @field_validator("id")
    @classmethod
    def _check_id(cls, value: str) -> str:
        if not _CAPABILITY_ID_RE.match(value):
            raise ValueError(
                "capability id must match ^[a-z][a-z0-9_.-]{0,63}$ "
                f"(lower-case, starting with a letter), got {value!r}"
            )
        return value

    @field_validator("input_schema")
    @classmethod
    def _check_input_schema(cls, value: dict[str, Any]) -> dict[str, Any]:
        if value.get("type", "object") != "object":
            raise ValueError("input_schema must describe a JSON object")
        return value


class RateLimitPolicy(WAPModel):
    """Advisory rate limit published in the manifest and enforced by the server."""

    requests_per_minute: int = Field(default=60, ge=1)
    burst: int = Field(default=10, ge=1)
    scopes: list[Literal["ip", "agent_key"]] = Field(default_factory=lambda: ["ip", "agent_key"])


class AgentManifest(WAPModel):
    """The document served at ``/.well-known/agent.json`` (RFC 8615)."""

    wap_version: Literal["1.0"] = WAP_VERSION
    domain: str = Field(description="Authority (host[:port]) the manifest is bound to.")
    name: str = Field(min_length=1, max_length=256)
    description: str = Field(default="", max_length=8192)
    public_key: str = Field(description="Hex-encoded raw 32-byte Ed25519 public key.")
    interaction_url: str
    challenge_url: str | None = None
    capabilities: list[Capability] = Field(default_factory=list)
    pow_required: bool = False
    pow_difficulty: int | None = Field(default=None, ge=1, le=16)
    rate_limit_policy: dict[str, Any] = Field(default_factory=lambda: RateLimitPolicy().model_dump())
    issued_at: float = Field(default_factory=_now)
    expires_at: float | None = None
    signature: str = Field(default="", description="Hex Ed25519 signature over the canonical manifest.")

    @field_validator("domain")
    @classmethod
    def _check_domain(cls, value: str) -> str:
        return normalize_authority(value)

    @field_validator("public_key")
    @classmethod
    def _check_public_key(cls, value: str) -> str:
        value = value.lower()
        if len(value) != 64 or not _HEX_RE.match(value):
            raise ValueError("public_key must be 64 hex characters (raw Ed25519 key)")
        return value

    @field_validator("signature")
    @classmethod
    def _check_signature(cls, value: str) -> str:
        value = value.lower()
        if value and (len(value) != 128 or not _HEX_RE.match(value)):
            raise ValueError("signature must be 128 hex characters (raw Ed25519 signature)")
        return value

    @field_validator("interaction_url", "challenge_url")
    @classmethod
    def _check_url(cls, value: str | None) -> str | None:
        if value is None:
            return value
        parts = urlsplit(value)
        if parts.scheme not in ("https", "http") or not parts.netloc:
            raise ValueError(f"URL must be absolute http(s), got {value!r}")
        return value

    @model_validator(mode="after")
    def _check_consistency(self) -> AgentManifest:
        ids = [c.id for c in self.capabilities]
        duplicates = {i for i in ids if ids.count(i) > 1}
        if duplicates:
            raise ValueError(f"duplicate capability ids: {sorted(duplicates)}")
        if self.pow_required and self.pow_difficulty is None:
            raise ValueError("pow_difficulty is required when pow_required is true")
        if self.pow_required and self.challenge_url is None:
            raise ValueError("challenge_url is required when pow_required is true")
        return self

    def get_capability(self, capability_id: str) -> Capability | None:
        for capability in self.capabilities:
            if capability.id == capability_id:
                return capability
        return None

    def is_expired(self, now: float | None = None) -> bool:
        return self.expires_at is not None and (now or time.time()) >= self.expires_at


class AgentMessage(WAPModel):
    """A single signed turn in a WAP dialogue."""

    wap_version: Literal["1.0"] = WAP_VERSION
    message_id: str = Field(default_factory=_new_id, min_length=8, max_length=128)
    session_id: str = Field(min_length=1, max_length=128)
    role: Role
    content: str = Field(default="", max_length=65536)
    capability_id: str | None = None
    structured_data: dict[str, Any] | None = None
    in_reply_to: str | None = None
    timestamp: float = Field(default_factory=_now)
    pow_seed: str | None = None
    pow_nonce: str | None = Field(default=None, max_length=128)
    public_key: str | None = Field(
        default=None, description="Signer's hex Ed25519 key. Required for user_agent messages."
    )
    signature: str = ""

    @field_validator("public_key")
    @classmethod
    def _check_public_key(cls, value: str | None) -> str | None:
        if value is None:
            return value
        value = value.lower()
        if len(value) != 64 or not _HEX_RE.match(value):
            raise ValueError("public_key must be 64 hex characters")
        return value

    @field_validator("signature")
    @classmethod
    def _check_signature(cls, value: str) -> str:
        value = value.lower()
        if value and (len(value) != 128 or not _HEX_RE.match(value)):
            raise ValueError("signature must be 128 hex characters")
        return value

    @model_validator(mode="after")
    def _check_pow_pair(self) -> AgentMessage:
        if (self.pow_seed is None) != (self.pow_nonce is None):
            raise ValueError("pow_seed and pow_nonce must be supplied together")
        return self


class Challenge(WAPModel):
    """A Hashcash-style proof-of-work challenge issued by ``/wap/v1/challenge``."""

    algorithm: Literal["sha256-leading-zero-hex"] = POW_ALGORITHM
    seed: str = Field(min_length=16, max_length=256)
    difficulty: int = Field(ge=1, le=16)
    issued_at: float = Field(default_factory=_now)
    expires_at: float

    @field_validator("seed")
    @classmethod
    def _check_seed(cls, value: str) -> str:
        if not _HEX_RE.match(value):
            raise ValueError("seed must be lower-case hex")
        return value


class ErrorDetail(WAPModel):
    code: ErrorCode
    message: str
    retry_after: float | None = None
    details: dict[str, Any] | None = None


class ErrorResponse(WAPModel):
    error: ErrorDetail

    @classmethod
    def build(
        cls,
        code: ErrorCode,
        message: str,
        *,
        retry_after: float | None = None,
        details: dict[str, Any] | None = None,
    ) -> ErrorResponse:
        return cls(error=ErrorDetail(code=code, message=message, retry_after=retry_after, details=details))


class StreamEventType(str, Enum):
    META = "meta"
    TOKEN = "token"
    DATA = "data"
    MESSAGE = "message"
    ERROR = "error"


__all__ = [
    "WAP_VERSION",
    "WELL_KNOWN_PATH",
    "INTERACT_PATH",
    "CHALLENGE_PATH",
    "HEADER_VERSION",
    "HEADER_SIGNATURE",
    "HEADER_KEY_ID",
    "HEADER_AGENT_KEY",
    "POW_ALGORITHM",
    "ERROR_STATUS",
    "AgentManifest",
    "AgentMessage",
    "Capability",
    "Challenge",
    "ErrorCode",
    "ErrorDetail",
    "ErrorResponse",
    "RateLimitPolicy",
    "Role",
    "StreamEventType",
    "authority_host",
    "is_local_authority",
    "normalize_authority",
]
