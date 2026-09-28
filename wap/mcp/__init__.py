"""MCP bridge exposing WAP to Model Context Protocol hosts (``pip install "webagent-protocol[mcp]"``)."""

from .bridge import WAPBridge, build_server, main

__all__ = ["WAPBridge", "build_server", "main"]
