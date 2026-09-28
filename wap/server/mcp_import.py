"""Publish an existing MCP server's tools on the open web through WAP.

If you already have an MCP server, one call makes its tools discoverable at
``/.well-known/agent.json``, with signed replies, proof-of-work and rate limits::

    from mcp.server.mcpserver import MCPServer
    from wap.server import WAPServer

    tools = MCPServer("inventory")

    @tools.tool()
    def check_stock(sku: str) -> dict: ...

    wap = WAPServer(name="Acme", domain="acme.example", private_key=KEY)
    wap.include_mcp(tools)          # imported when the app starts
    app = wap.create_app()

``source`` is anything the MCP SDK's ``Client`` accepts: an in-process server
object, a streamable-HTTP URL, or ``StdioServerParameters`` for a subprocess.
Requires the ``mcp`` extra.
"""

from __future__ import annotations

import re
from contextlib import AsyncExitStack
from typing import TYPE_CHECKING, Any

from mcp.client.client import Client

from ..spec.models import Capability, ErrorCode
from .app import ActionContext, ActionResult, WAPProtocolError

if TYPE_CHECKING:
    from .app import WAPServer

_INVALID = re.compile(r"[^a-z0-9_.-]+")


def capability_id_for(tool_name: str, prefix: str = "") -> str:
    """Map an MCP tool name onto WAP's capability-id grammar (``^[a-z][a-z0-9_.-]{0,63}$``)."""
    ident = _INVALID.sub("_", (prefix + tool_name).lower()).strip("_") or "tool"
    if not ident[0].isalpha():
        ident = "t_" + ident
    return ident[:64]


def _text_of(content: list[Any]) -> str:
    return "\n".join(block.text for block in content if getattr(block, "type", None) == "text")


class MCPToolSource:
    """A live connection to an MCP server whose tools are re-published as WAP capabilities."""

    def __init__(self, source: Any, *, prefix: str = "", include: set[str] | None = None) -> None:
        self.source = source
        self.prefix = prefix
        self.include = include
        self.client: Client | None = None
        self._stack: AsyncExitStack | None = None
        self.capability_ids: list[str] = []

    async def connect(self) -> Client:
        if self.client is None:
            stack = AsyncExitStack()
            self.client = await stack.enter_async_context(Client(self.source))
            self._stack = stack
        return self.client

    async def aclose(self) -> None:
        if self._stack is not None:
            await self._stack.aclose()
        self._stack = None
        self.client = None

    async def register(self, wap: WAPServer) -> list[str]:
        """List the source's tools and add each one to ``wap`` as a capability."""
        client = await self.connect()
        registered = []
        for tool in (await client.list_tools()).tools:
            if self.include is not None and tool.name not in self.include:
                continue
            capability_id = capability_id_for(tool.name, self.prefix)
            if capability_id in wap.actions:
                continue
            schema = dict(tool.input_schema or {"type": "object", "properties": {}})
            schema.setdefault("type", "object")
            output = tool.output_schema if tool.output_schema and tool.output_schema.get("type") == "object" else None
            capability = Capability(
                id=capability_id,
                name=(tool.title or tool.name)[:128],
                description=(tool.description or "")[:4096],
                input_schema=schema,
                output_schema=output,
            )
            wap.add_capability(capability, self._handler(tool.name))
            registered.append(capability_id)
        self.capability_ids = registered
        return registered

    def _handler(self, tool_name: str) -> Any:
        async def call(payload: dict[str, Any], ctx: ActionContext) -> ActionResult:
            if self.client is None:
                raise WAPProtocolError(ErrorCode.ACTION_FAILED, "the upstream MCP server is not connected")
            result = await self.client.call_tool(tool_name, payload)
            text = _text_of(list(result.content or []))
            if result.is_error:
                raise WAPProtocolError(ErrorCode.ACTION_FAILED, text or f"MCP tool {tool_name!r} failed")
            data = result.structured_content
            return ActionResult(content=text, data=dict(data) if isinstance(data, dict) else None)

        return call


__all__ = ["MCPToolSource", "capability_id_for"]
