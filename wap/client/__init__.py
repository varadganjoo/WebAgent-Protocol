"""Consumer SDK: discover and negotiate with WAP business agents."""

from .exceptions import (
    AuthRequired,
    CapabilityNotFound,
    InsecureTransport,
    ManifestNotFound,
    ProofOfWorkFailed,
    ProtocolError,
    RateLimited,
    SchemaValidationError,
    VerificationFailed,
    WAPError,
)
from .resolver import ManifestResolver, ResolvedManifest, Target, parse_target
from .session import InteractionResult, StreamEvent, WAPClient, WAPSession, validate_payload

__all__ = [
    "AuthRequired",
    "CapabilityNotFound",
    "InsecureTransport",
    "InteractionResult",
    "ManifestNotFound",
    "ManifestResolver",
    "ProofOfWorkFailed",
    "ProtocolError",
    "RateLimited",
    "ResolvedManifest",
    "SchemaValidationError",
    "StreamEvent",
    "Target",
    "VerificationFailed",
    "WAPClient",
    "WAPError",
    "WAPSession",
    "parse_target",
    "validate_payload",
]
