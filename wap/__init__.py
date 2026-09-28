"""WebAgent Protocol (WAP): discovery and negotiation between AI agents on the open web.

The core package ships the specification models and the async consumer SDK::

    from wap import WAPClient

    async with WAPClient() as client:
        result = await client.ask("bakery.example", "Do you have sourdough croissants?")

The provider SDK lives in :mod:`wap.server` (``pip install "webagent-protocol[server]"``) and
the Model Context Protocol bridge in :mod:`wap.mcp` (``pip install "webagent-protocol[mcp]"``).
"""

__version__ = "0.2.0"

from .client import (
    InteractionResult,
    ManifestResolver,
    StreamEvent,
    WAPClient,
    WAPSession,
)
from .client.exceptions import (
    CapabilityNotFound,
    ConversationLimitReached,
    ConversationStopped,
    LoopDetected,
    ManifestNotFound,
    ProtocolError,
    RateLimited,
    VerificationFailed,
    WAPError,
)
from .spec import (
    WAP_VERSION,
    AgentManifest,
    AgentMessage,
    Capability,
    Challenge,
    Signer,
    generate_keypair,
)
from .spec.conversation import ConversationPolicy

__all__ = [
    "__version__",
    "WAP_VERSION",
    "AgentManifest",
    "AgentMessage",
    "Capability",
    "CapabilityNotFound",
    "Challenge",
    "ConversationLimitReached",
    "ConversationPolicy",
    "ConversationStopped",
    "InteractionResult",
    "LoopDetected",
    "ManifestNotFound",
    "ManifestResolver",
    "ProtocolError",
    "RateLimited",
    "Signer",
    "StreamEvent",
    "VerificationFailed",
    "WAPClient",
    "WAPError",
    "WAPSession",
    "generate_keypair",
]
