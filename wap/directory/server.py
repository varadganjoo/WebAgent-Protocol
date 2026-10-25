"""Optional FastAPI reference directory. Single-process memory index; no transaction proxy."""

from __future__ import annotations

import secrets

from fastapi import FastAPI, HTTPException, Request
from pydantic import ValidationError

from ..server.rate_limiter import RateLimiter
from ..spec.models import RateLimitPolicy, normalize_authority
from .models import DIRECTORY_PATH, DirectoryQuery
from .providers import DirectoryError, MemoryDirectory


def create_directory_app(directory: MemoryDirectory, *, registration_token: str) -> FastAPI:
    """Use TLS, an operator-managed secret and egress filtering for public hosting. No query logging."""
    if len(registration_token) < 16:
        raise ValueError("registration_token must be at least 16 characters")
    app = FastAPI(title="WAP Capability Directory", docs_url=None, redoc_url=None)
    searches = RateLimiter(RateLimitPolicy(requests_per_minute=60, burst=10, scopes=["ip"]))
    registrations = RateLimiter(RateLimitPolicy(requests_per_minute=10, burst=3, scopes=["ip"]))

    async def body(request: Request, *, registration: bool = False) -> bytes:
        limiter = registrations if registration else searches
        decision = await limiter.check(ip=request.client.host if request.client else "unknown")
        if not decision.allowed:
            raise HTTPException(429, {"code": "rate_limited"}, headers=decision.headers())
        if registration:
            provided = request.headers.get("authorization", "").encode()
            if not secrets.compare_digest(provided, ("Bearer " + registration_token).encode()):
                raise HTTPException(401, {"code": "auth_required"})
        data = bytearray()
        async for chunk in request.stream():
            data.extend(chunk)
            if len(data) > 16384:
                raise HTTPException(413, {"code": "request_too_large"})
        return bytes(data)

    @app.post(DIRECTORY_PATH + "/search")
    async def search(request: Request):
        raw = await body(request)
        try:
            query = DirectoryQuery.model_validate_json(raw)
        except ValidationError:
            raise HTTPException(422, {"code": "invalid_query"}) from None
        return (await directory.search(query)).model_dump(mode="json")

    @app.post(DIRECTORY_PATH + "/registrations")
    async def register(request: Request):
        import json

        raw = await body(request, registration=True)
        try:
            data = json.loads(raw)
            if not isinstance(data, dict) or set(data) != {"domain"}:
                raise ValueError("only a domain may be registered")
            domain = normalize_authority(data["domain"])
        except (ValueError, TypeError, RecursionError):
            raise HTTPException(422, {"code": "invalid_registration"}) from None
        try:
            return (await directory.register(domain)).model_dump(mode="json")
        except DirectoryError as exc:
            raise HTTPException(502, {"code": exc.code}) from None

    return app
