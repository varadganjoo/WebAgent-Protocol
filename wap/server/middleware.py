"""Attach WAP to existing applications.

* :func:`inject_routes` is what :meth:`WAPServer.mount` uses for FastAPI apps:
  it adds the discovery, challenge and interaction routes and stamps every
  WAP response with ``X-WAP-Version``.
* :class:`WAPDiscoveryMiddleware` is a dependency-light pure ASGI middleware
  for *any* ASGI framework (Starlette, Django, Quart, Litestar...). It serves
  ``/.well-known/agent.json`` in front of the wrapped application, so a site
  can publish its manifest without routing changes.
"""

from __future__ import annotations

from typing import TYPE_CHECKING, Any

from ..spec.crypto import canonical_json
from ..spec.models import HEADER_SIGNATURE, HEADER_VERSION, WAP_VERSION, WELL_KNOWN_PATH, ErrorResponse
from .app import WAPProtocolError

if TYPE_CHECKING:
    from fastapi import FastAPI

    from .app import WAPServer

Scope = dict[str, Any]
ASGIApp = Any


class WAPDiscoveryMiddleware:
    """Serve the signed manifest at ``/.well-known/agent.json`` in front of any ASGI app."""

    def __init__(self, app: ASGIApp, server: WAPServer) -> None:
        self.app = app
        self.server = server

    async def __call__(self, scope: Scope, receive: Any, send: Any) -> None:
        if scope["type"] == "http" and scope.get("path") == WELL_KNOWN_PATH:
            method = scope.get("method", "GET")
            if method in ("GET", "HEAD"):
                await self._serve_manifest(scope, send, head=method == "HEAD")
                return
            if method == "OPTIONS":
                await self._send(
                    send,
                    204,
                    b"",
                    {
                        "Allow": "GET, HEAD, OPTIONS",
                        "Access-Control-Allow-Origin": "*",
                        "Access-Control-Allow-Methods": "GET, HEAD, OPTIONS",
                    },
                )
                return
            await self._send(send, 405, b"", {"Allow": "GET, HEAD, OPTIONS"})
            return
        await self.app(scope, receive, send)

    async def _serve_manifest(self, scope: Scope, send: Any, head: bool) -> None:
        client = scope.get("client")
        ip = client[0] if client else None
        try:
            await self.server.limit_ip(ip)
        except WAPProtocolError as exc:
            body = canonical_json(
                ErrorResponse.build(exc.code, exc.message, retry_after=exc.retry_after).model_dump(
                    mode="json", exclude_none=True
                )
            )
            headers = {
                "Content-Type": "application/json",
                **exc.headers,
                HEADER_SIGNATURE: self.server.signer.sign(body),
            }
            await self._send(send, 429, body, headers)
            return
        manifest = self.server.manifest()
        body = canonical_json(manifest.model_dump(mode="json"))
        headers = {
            "Content-Type": "application/json",
            "Cache-Control": "public, max-age=300",
            "Access-Control-Allow-Origin": "*",
            "ETag": f'"{manifest.signature[:32]}"',
            HEADER_SIGNATURE: self.server.signer.sign(body),
        }
        await self._send(send, 200, b"" if head else body, headers, content_length=len(body))

    @staticmethod
    async def _send(
        send: Any, status: int, body: bytes, headers: dict[str, str], content_length: int | None = None
    ) -> None:
        raw_headers = [(k.lower().encode("latin-1"), v.encode("latin-1")) for k, v in headers.items()]
        raw_headers.append((HEADER_VERSION.lower().encode(), WAP_VERSION.encode()))
        raw_headers.append((b"content-length", str(len(body) if content_length is None else content_length).encode()))
        await send({"type": "http.response.start", "status": status, "headers": raw_headers})
        await send({"type": "http.response.body", "body": body})


def inject_routes(app: FastAPI, server: WAPServer) -> None:
    """Register WAP endpoints on ``app`` and expose the server as ``app.state.wap_server``."""
    from .router import build_router

    existing = getattr(app.state, "wap_server", None)
    if existing is not None and existing is not server:
        raise RuntimeError("a different WAPServer is already mounted on this application")
    if existing is server:
        return
    app.include_router(build_router(server))
    app.state.wap_server = server


__all__ = ["WAPDiscoveryMiddleware", "inject_routes"]
