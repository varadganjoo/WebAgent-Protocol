"""Model Context Protocol bridge: lets Claude Desktop, Cursor, Codex & co. talk to any WAP agent.

Run it over stdio::

    wap-mcp

and register it with an MCP host, e.g. in ``claude_desktop_config.json``::

    {"mcpServers": {"webagent": {"command": "wap-mcp"}}}

Environment variables:

``WAP_AGENT_KEY``               hex Ed25519 private key used to sign requests (ephemeral if unset)
``WAP_BLOCK_PRIVATE_NETWORKS``  ``1`` to refuse domains resolving to private/loopback IPs (SSRF guard)
``WAP_ALLOW_INSECURE``          ``1`` to permit plain-HTTP manifests on non-loopback hosts
``WAP_PINNED_KEYS``             JSON object ``{"domain": "<hex public key>"}`` for key pinning
``WAP_AUTH_TOKENS``             JSON object ``{"domain": "<bearer token>"}`` for authenticated capabilities
``WAP_TIMEOUT``                 request timeout in seconds (default 30)
"""

from __future__ import annotations

import json
import os
from typing import Any

from ..client import WAPClient, WAPError
from ..client.exceptions import ProtocolError, SchemaValidationError
from ..spec.crypto import fingerprint
from ..spec.models import AgentManifest

try:  # mcp >= 2.0
    from mcp.server.mcpserver import MCPServer as _MCPServer
except ImportError:  # mcp 1.x
    from mcp.server.fastmcp import FastMCP as _MCPServer

SERVER_NAME = "webagent-protocol"
INSTRUCTIONS = (
    "Tools for the WebAgent Protocol (WAP). Businesses publish a signed manifest at "
    "https://<domain>/.well-known/agent.json describing machine-executable capabilities. "
    "Call wap_discover first to learn a domain's capabilities and their JSON input schemas, "
    "then wap_interact to execute one with parameters matching that schema, or wap_ask for a "
    "free-text request. All replies are Ed25519-signed by the business and verified before "
    "being returned; proof-of-work challenges are solved automatically."
)


def _env_flag(name: str) -> bool:
    return os.environ.get(name, "").strip().lower() in ("1", "true", "yes", "on")


def _env_json(name: str) -> dict[str, str]:
    raw = os.environ.get(name)
    if not raw:
        return {}
    value = json.loads(raw)
    if not isinstance(value, dict):
        raise ValueError(f"{name} must be a JSON object")
    return {str(k): str(v) for k, v in value.items()}


def client_from_env() -> WAPClient:
    return WAPClient(
        agent_key=os.environ.get("WAP_AGENT_KEY") or None,
        timeout=float(os.environ.get("WAP_TIMEOUT", "30")),
        allow_insecure=_env_flag("WAP_ALLOW_INSECURE"),
        block_private_networks=_env_flag("WAP_BLOCK_PRIVATE_NETWORKS"),
        pinned_keys=_env_json("WAP_PINNED_KEYS"),
        auth_tokens=_env_json("WAP_AUTH_TOKENS"),
    )


def _error(exc: Exception) -> dict[str, Any]:
    error: dict[str, Any] = {"type": type(exc).__name__, "message": str(exc)}
    if isinstance(exc, ProtocolError):
        error.update(code=exc.code, status_code=exc.status_code, details=exc.details, retry_after=exc.retry_after)
    if isinstance(exc, SchemaValidationError):
        error["validation_errors"] = exc.errors
    return {"ok": False, "error": error}


def summarize_manifest(manifest: AgentManifest) -> dict[str, Any]:
    return {
        "domain": manifest.domain,
        "name": manifest.name,
        "description": manifest.description,
        "wap_version": manifest.wap_version,
        "public_key_fingerprint": fingerprint(manifest.public_key),
        "pow_required": manifest.pow_required,
        "pow_difficulty": manifest.pow_difficulty,
        "rate_limit_policy": manifest.rate_limit_policy,
        "capabilities": [
            {
                "id": c.id,
                "name": c.name,
                "description": c.description,
                "input_schema": c.input_schema,
                "output_schema": c.output_schema,
                "requires_auth": c.requires_auth,
            }
            for c in manifest.capabilities
        ],
    }


class WAPBridge:
    """Transport-independent implementation of the MCP tools."""

    def __init__(self, client: WAPClient | None = None) -> None:
        self._client = client

    @property
    def client(self) -> WAPClient:
        if self._client is None:
            self._client = client_from_env()
        return self._client

    async def aclose(self) -> None:
        if self._client is not None:
            await self._client.aclose()

    async def discover(self, domain: str) -> dict[str, Any]:
        try:
            manifest = await self.client.discover(domain)
        except (WAPError, ValueError) as exc:
            return _error(exc)
        return {"ok": True, "verified": True, "manifest": summarize_manifest(manifest)}

    async def interact(
        self, domain: str, capability: str, parameters: dict[str, Any] | None = None, session_id: str | None = None
    ) -> dict[str, Any]:
        try:
            result = await self.client.invoke(domain, capability, parameters or {}, session_id=session_id)
        except (WAPError, ValueError) as exc:
            return _error(exc)
        return {"ok": True, **result.to_dict()}

    async def ask(self, domain: str, query: str, session_id: str | None = None) -> dict[str, Any]:
        try:
            result = await self.client.ask(domain, query, session_id=session_id)
        except (WAPError, ValueError) as exc:
            return _error(exc)
        return {"ok": True, **result.to_dict()}


def build_server(bridge: WAPBridge | None = None) -> Any:
    """Create the MCP server exposing ``wap_discover``, ``wap_interact`` and ``wap_ask``."""
    bridge = bridge or WAPBridge()
    server = _MCPServer(name=SERVER_NAME, instructions=INSTRUCTIONS)

    @server.tool(
        name="wap_discover",
        description=(
            "Fetch and cryptographically verify the WebAgent Protocol manifest of a website "
            "(e.g. 'bakery.example' or 'localhost:8000'). Returns the business agent's name, "
            "capabilities and the JSON Schema each capability accepts."
        ),
    )
    async def wap_discover(domain: str) -> dict[str, Any]:
        return await bridge.discover(domain)

    @server.tool(
        name="wap_interact",
        description=(
            "Execute a capability on a WAP-enabled website. 'capability' is a capability id from "
            "wap_discover and 'parameters' must match its input_schema. Pass the returned "
            "session_id back to continue a multi-turn negotiation."
        ),
    )
    async def wap_interact(
        domain: str, capability: str, parameters: dict[str, Any] | None = None, session_id: str | None = None
    ) -> dict[str, Any]:
        return await bridge.interact(domain, capability, parameters, session_id)

    @server.tool(
        name="wap_ask",
        description=(
            "Send a free-text request to a website's business agent and return its signed reply "
            "(text plus any structured data)."
        ),
    )
    async def wap_ask(domain: str, query: str, session_id: str | None = None) -> dict[str, Any]:
        return await bridge.ask(domain, query, session_id)

    return server


def main() -> None:
    """Console entry point: ``wap-mcp`` (stdio transport)."""
    build_server().run("stdio")


if __name__ == "__main__":
    main()


__all__ = ["WAPBridge", "build_server", "client_from_env", "main", "summarize_manifest"]
