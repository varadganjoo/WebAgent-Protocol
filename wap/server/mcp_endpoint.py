"""Serve a WAPServer's capabilities as a standard MCP server (streamable HTTP) at ``/mcp``.

This is what makes WAP an *extension* of the Model Context Protocol rather than
a competitor: the same ``@wap.action`` functions are exposed twice,

* as WAP capabilities (signed envelopes, proof-of-work, SSE) at ``/wap/v1/interact``, and
* as ordinary MCP tools at ``/mcp``, usable by any MCP client with no WAP code.

The MCP endpoint keeps WAP's guarantees where MCP has room for them:

* every successful ``tools/call`` result carries the business's Ed25519-signed
  reply in ``_meta["io.webagent/signed_reply"]``, verifiable against the key in
  ``/.well-known/agent.json``;
* calls are rate-limited per client IP with the server's policy;
* proof-of-work can be required (``mcp_require_pow``): the client passes
  ``_meta["io.webagent/pow"] = {"seed", "nonce"}`` and a failed call returns a
  fresh challenge in ``_meta["io.webagent/challenge"]``;
* multi-turn state continues via ``_meta["io.webagent/session_id"]``.

Installed with the ``server`` extra (``pip install "webagent-protocol[server]"``).
"""

from __future__ import annotations

import json
import uuid
from collections.abc import AsyncIterator
from contextlib import asynccontextmanager
from typing import TYPE_CHECKING, Any
from urllib.parse import urlsplit

import mcp_types as types
from mcp.server.lowlevel import Server
from mcp.server.streamable_http_manager import StreamableHTTPSessionManager
from mcp.server.transport_security import TransportSecuritySettings
from mcp.shared.exceptions import MCPError

from .. import __version__
from ..spec.models import WAP_VERSION, WELL_KNOWN_PATH, AgentMessage, ErrorCode, Role, authority_host
from ..spec.pow import PowError
from .app import ActionContext, WAPProtocolError

if TYPE_CHECKING:
    from fastapi import FastAPI

    from .app import WAPServer

EXTENSION_ID = "io.webagent/wap"
META_PREFIX = "io.webagent/"
META_SIGNED_REPLY = META_PREFIX + "signed_reply"
META_SESSION_ID = META_PREFIX + "session_id"
META_POW = META_PREFIX + "pow"
META_CHALLENGE = META_PREFIX + "challenge"
META_ERROR = META_PREFIX + "error"
META_MANIFEST = META_PREFIX + "manifest_url"
MCP_SESSION_OWNER = "mcp"
INVALID_PARAMS = -32602


def _error_result(code: str, message: str, extra_meta: dict[str, Any] | None = None) -> types.CallToolResult:
    return types.CallToolResult(
        content=[types.TextContent(type="text", text=f"[{code}] {message}")],
        is_error=True,
        meta={META_ERROR: {"code": code, "message": message}, **(extra_meta or {})},
    )


class MCPEndpoint:
    """Bridges one :class:`WAPServer` onto an MCP ``Server`` served over streamable HTTP."""

    def __init__(self, server: WAPServer, path: str = "/mcp") -> None:
        self.wap = server
        self.path = path
        self.mcp = Server(
            server.name,
            version=__version__,
            description=server.description or None,
            instructions=(
                f"Tools published by {server.name} ({server.domain}) via the WebAgent Protocol. "
                f"Results are signed; verify _meta['{META_SIGNED_REPLY}'] against the public key at "
                f"{server.base_url}{WELL_KNOWN_PATH}."
            ),
            on_list_tools=self._list_tools,
            on_call_tool=self._call_tool,
        )
        # Declared as an MCP extension (SEP-2133) so clients can detect WAP support at initialization.
        self.mcp.extensions[EXTENSION_ID] = self.extension_settings()
        self._manager: StreamableHTTPSessionManager | None = None

    def extension_settings(self) -> dict[str, Any]:
        return {
            "wap_version": WAP_VERSION,
            "manifest_url": self.wap.base_url + WELL_KNOWN_PATH,
            "public_key": self.wap.public_key,
            "pow_required": self.require_pow,
            "signed_results": True,
            "conversation_policy": self.wap.conversation_policy.as_dict(),
        }

    # ------------------------------------------------------------------ MCP handlers

    def tools(self) -> list[types.Tool]:
        tools = []
        for action in self.wap.actions.values():
            cap = action.capability
            output = cap.output_schema if cap.output_schema and cap.output_schema.get("type") == "object" else None
            tools.append(
                types.Tool(
                    name=cap.id,
                    title=cap.name,
                    description=cap.description or cap.name,
                    input_schema=cap.input_schema,
                    output_schema=output,
                    meta={META_PREFIX + "requires_auth": cap.requires_auth},
                )
            )
        return tools

    async def _list_tools(self, ctx: Any, params: Any) -> types.ListToolsResult:
        return types.ListToolsResult(tools=self.tools())

    @property
    def require_pow(self) -> bool:
        configured = self.wap.mcp_require_pow
        return self.wap.require_pow if configured is None else configured

    async def _call_tool(self, ctx: Any, params: types.CallToolRequestParams) -> types.CallToolResult:
        server = self.wap
        if params.name not in server.actions:
            raise MCPError(INVALID_PARAMS, f"unknown tool {params.name!r}", {"available": sorted(server.actions)})
        request = getattr(ctx, "request", None)
        ip = request.client.host if request is not None and getattr(request, "client", None) else None
        headers = request.headers if request is not None else {}
        meta: dict[str, Any] = dict(params.meta or {})

        decision = await server.rate_limiter.check(ip=ip)
        if not decision.allowed:
            return _error_result(
                ErrorCode.RATE_LIMITED.value,
                f"rate limit exceeded; retry in {decision.retry_after:.1f}s",
                {META_PREFIX + "retry_after": round(decision.retry_after, 3)},
            )

        if self.require_pow:
            solution = meta.get(META_POW)
            fresh = {META_CHALLENGE: server.pow.issue().model_dump(mode="json")}
            if not isinstance(solution, dict) or "seed" not in solution or "nonce" not in solution:
                return _error_result(
                    ErrorCode.POW_REQUIRED.value,
                    f"this tool requires proof-of-work: solve _meta['{META_CHALLENGE}'] and resend with "
                    f"_meta['{META_POW}'] = {{'seed': ..., 'nonce': ...}}",
                    fresh,
                )
            try:
                server.pow.verify(str(solution["seed"]), str(solution["nonce"]))
            except PowError as exc:
                return _error_result(ErrorCode.POW_INVALID.value, f"proof-of-work rejected: {exc}", fresh)

        try:
            principal = await server.authenticate(headers.get("authorization"))
        except WAPProtocolError as exc:
            return _error_result(exc.code.value, exc.message)

        session_id = str(meta.get(META_SESSION_ID) or "mcp-" + uuid.uuid4().hex)
        try:
            session = server.sessions.get_or_create(session_id, MCP_SESSION_OWNER)
        except WAPProtocolError as exc:
            return _error_result(exc.code.value, exc.message)
        message = AgentMessage(
            session_id=session_id,
            role=Role.USER_AGENT,
            capability_id=params.name,
            structured_data=dict(params.arguments or {}),
        )
        try:
            # Per-session only: an IP may be shared by many unrelated MCP users.
            server.check_conversation(session, message, None)
        except WAPProtocolError as exc:
            return _error_result(exc.code.value, exc.message, {META_PREFIX + "details": exc.details})
        action_ctx = ActionContext(
            server=server, message=message, session=session, client_ip=ip, agent_key=None, principal=principal
        )
        text: list[str] = []
        data: dict[str, Any] = {}
        try:
            async for chunk in server.run_capability(params.name, message.structured_data or {}, action_ctx):
                if isinstance(chunk, str):
                    text.append(chunk)
                else:
                    data.update(chunk)
        except WAPProtocolError as exc:
            extra = {META_PREFIX + "details": exc.details} if exc.details else None
            return _error_result(exc.code.value, exc.message, extra)
        except Exception as exc:  # noqa: BLE001 - surfaced to the model as a tool error
            return _error_result(ErrorCode.ACTION_FAILED.value, f"the business agent failed: {exc}")

        reply = server.reply(message, "".join(text), data or None)
        server.record_exchange(session, message, reply, None)
        content = [types.TextContent(type="text", text=reply.content or json.dumps(data))]
        if data and reply.content:
            content.append(types.TextContent(type="text", text=json.dumps(data, ensure_ascii=False)))
        return types.CallToolResult(
            content=content,
            structured_content=data or None,
            meta={
                META_SIGNED_REPLY: reply.model_dump(mode="json"),
                META_SESSION_ID: session_id,
                META_MANIFEST: server.base_url + WELL_KNOWN_PATH,
            },
        )

    # ------------------------------------------------------------------ ASGI

    def security_settings(self) -> TransportSecuritySettings:
        hosts = {self.wap.domain, authority_host(self.wap.domain)}
        base = urlsplit(self.wap.base_url)
        hosts.update({base.netloc, base.hostname or ""})
        allowed = sorted(h for h in hosts if h)
        allowed += [f"{authority_host(h)}:*" for h in allowed if ":" not in h]
        return TransportSecuritySettings(
            enable_dns_rebinding_protection=True,
            allowed_hosts=sorted(set(allowed)),
            allowed_origins=sorted({f"{base.scheme}://{base.netloc}", f"https://{self.wap.domain}"}),
        )

    @asynccontextmanager
    async def running(self) -> AsyncIterator[None]:
        """Run the MCP session manager; entered from the host application's lifespan."""
        self.mcp.extensions[EXTENSION_ID] = self.extension_settings()  # pick up config changed after mount
        manager = StreamableHTTPSessionManager(
            app=self.mcp, json_response=True, stateless=True, security_settings=self.security_settings()
        )
        async with manager.run():
            self._manager = manager
            try:
                yield
            finally:
                self._manager = None

    async def __call__(self, scope: dict[str, Any], receive: Any, send: Any) -> None:
        if self._manager is None:
            body = b'{"error":"MCP endpoint is not running; start the app with its ASGI lifespan enabled"}'
            await send(
                {
                    "type": "http.response.start",
                    "status": 503,
                    "headers": [(b"content-type", b"application/json"), (b"content-length", str(len(body)).encode())],
                }
            )
            await send({"type": "http.response.body", "body": body})
            return
        await self._manager.handle_request(scope, receive, send)


def mount_mcp(app: FastAPI, server: WAPServer, path: str = "/mcp") -> MCPEndpoint:
    """Add the MCP endpoint to ``app`` and hook its session manager into the app lifespan."""
    endpoint = MCPEndpoint(server, path)
    app.router.add_route(path, endpoint, methods=["GET", "POST", "DELETE"], include_in_schema=False)
    original = app.router.lifespan_context

    @asynccontextmanager
    async def lifespan(asgi_app: Any) -> AsyncIterator[Any]:
        async with endpoint.running():
            async with original(asgi_app) as state:
                yield state

    app.router.lifespan_context = lifespan
    return endpoint


__all__ = [
    "EXTENSION_ID",
    "META_CHALLENGE",
    "META_POW",
    "META_SESSION_ID",
    "META_SIGNED_REPLY",
    "MCPEndpoint",
    "mount_mcp",
]
