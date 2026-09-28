"""MCP bridge exposing WAP to Model Context Protocol hosts (``pip install "wap[mcp]"``)."""

from .bridge import WAPBridge, build_server, main

__all__ = ["WAPBridge", "build_server", "main"]
