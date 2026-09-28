"""HTTP endpoints for WAP/1.0: ``/.well-known/agent.json``, ``/wap/v1/challenge`` and ``/wap/v1/interact``.

The interaction endpoint enforces the request pipeline defined in
``docs/spec_rfc.md`` Section 7, in this order:

1. per-IP rate limit (cheapest check first),
2. protocol version negotiation,
3. envelope validation,
4. Ed25519 signature verification against the sender's declared key,
5. freshness window and replay detection,
6. per-agent-key rate limit,
7. proof-of-work verification (only now is a challenge consumed),
8. bearer authorisation,
9. session binding, then dispatch to the capability or intent handler.

Nothing expensive (tools, databases, LLMs) runs before step 9.
"""

from __future__ import annotations

import json
import re
import time
from collections.abc import AsyncIterator
from typing import TYPE_CHECKING, Any

from fastapi import APIRouter, Request
from fastapi.responses import Response
from pydantic import ValidationError
from sse_starlette.sse import EventSourceResponse

from ..spec.crypto import canonical_json, verify_model
from ..spec.models import (
    CHALLENGE_PATH,
    ERROR_STATUS,
    HEADER_SIGNATURE,
    HEADER_VERSION,
    INTERACT_PATH,
    WAP_VERSION,
    WELL_KNOWN_PATH,
    AgentMessage,
    ErrorCode,
    ErrorResponse,
    Role,
    StreamEventType,
)
from ..spec.pow import PowError
from .app import ActionContext, Chunk, WAPProtocolError

if TYPE_CHECKING:
    from .app import WAPServer
    from .rate_limiter import RateLimitDecision

MAX_BODY_BYTES = 256 * 1024
_TOKEN_SPLIT_RE = re.compile(r"(\s+)")


def client_ip(request: Request, trust_forwarded_for: bool) -> str | None:
    if trust_forwarded_for:
        forwarded = request.headers.get("x-forwarded-for")
        if forwarded:
            return forwarded.split(",")[0].strip()
    return request.client.host if request.client else None


def signed_json_response(
    server: WAPServer, payload: Any, status_code: int = 200, headers: dict[str, str] | None = None
) -> Response:
    """Serialise ``payload`` canonically and sign the exact body bytes (``X-WAP-Signature``)."""
    body = canonical_json(payload)
    all_headers = {
        HEADER_VERSION: WAP_VERSION,
        HEADER_SIGNATURE: server.signer.sign(body),
        **(headers or {}),
    }
    return Response(content=body, status_code=status_code, media_type="application/json", headers=all_headers)


def error_response(server: WAPServer, error: WAPProtocolError, extra_headers: dict[str, str] | None = None) -> Response:
    payload = ErrorResponse.build(
        error.code, error.message, retry_after=error.retry_after, details=error.details
    ).model_dump(mode="json", exclude_none=True)
    headers = {**error.headers, **(extra_headers or {})}
    if error.retry_after is not None and "Retry-After" not in headers:
        headers["Retry-After"] = str(max(1, int(error.retry_after + 0.999)))
    return signed_json_response(server, payload, ERROR_STATUS[error.code], headers)


def manifest_response(server: WAPServer) -> Response:
    manifest = server.manifest()
    max_age = 300
    if manifest.expires_at is not None:
        max_age = max(0, min(max_age, int(manifest.expires_at - time.time())))
    return signed_json_response(
        server,
        manifest.model_dump(mode="json"),
        headers={
            "Cache-Control": f"public, max-age={max_age}",
            "Access-Control-Allow-Origin": "*",
            "ETag": f'"{manifest.signature[:32]}"',
        },
    )


def _split_tokens(text: str, words_per_token: int = 1) -> list[str]:
    parts = [p for p in _TOKEN_SPLIT_RE.split(text) if p]
    tokens: list[str] = []
    buffer = ""
    count = 0
    for part in parts:
        buffer += part
        if not part.isspace():
            count += 1
            if count >= words_per_token:
                tokens.append(buffer)
                buffer, count = "", 0
    if buffer:
        tokens.append(buffer)
    return tokens


def _rate_limited(decision: RateLimitDecision) -> WAPProtocolError:
    return WAPProtocolError(
        ErrorCode.RATE_LIMITED,
        f"rate limit exceeded for {decision.scope or 'client'}",
        retry_after=round(decision.retry_after, 3),
        details={"scope": decision.scope, "limit_per_minute": decision.limit},
        headers=decision.headers(),
    )


async def _admit(server: WAPServer, request: Request) -> tuple[ActionContext, dict[str, str]]:
    """Run pipeline steps 1-8 and return a ready-to-dispatch context plus response headers."""
    ip = client_ip(request, server.trust_forwarded_for)
    decision = await server.rate_limiter.check(ip=ip)
    if not decision.allowed:
        raise _rate_limited(decision)

    version = request.headers.get(HEADER_VERSION)
    if version is not None and version.split(".")[0] != WAP_VERSION.split(".")[0]:
        raise WAPProtocolError(
            ErrorCode.UNSUPPORTED_VERSION,
            f"unsupported WAP version {version!r}; this agent speaks {WAP_VERSION}",
            details={"supported": [WAP_VERSION]},
        )

    body = await request.body()
    if len(body) > MAX_BODY_BYTES:
        raise WAPProtocolError(ErrorCode.INVALID_REQUEST, f"request body exceeds {MAX_BODY_BYTES} bytes")
    try:
        message = AgentMessage.model_validate_json(body)
    except ValidationError as exc:
        raise WAPProtocolError(
            ErrorCode.INVALID_REQUEST,
            "request body is not a valid AgentMessage",
            details={"errors": exc.errors(include_url=False, include_context=False, include_input=False)},
        ) from exc

    if message.role is not Role.USER_AGENT:
        raise WAPProtocolError(ErrorCode.INVALID_REQUEST, "requests must carry role 'user_agent'")
    if message.public_key is None:
        raise WAPProtocolError(ErrorCode.INVALID_SIGNATURE, "user_agent messages must declare public_key")
    if not verify_model(message, message.public_key):
        raise WAPProtocolError(ErrorCode.INVALID_SIGNATURE, "message signature does not verify against public_key")

    now = time.time()
    skew = abs(now - message.timestamp)
    if skew > server.max_clock_skew_seconds:
        raise WAPProtocolError(
            ErrorCode.REPLAY_DETECTED,
            f"message timestamp is outside the accepted window (±{int(server.max_clock_skew_seconds)}s)",
            details={"server_time": now},
        )
    if not server.replay_cache.check_and_add(f"{message.public_key}:{message.message_id}", now):
        raise WAPProtocolError(ErrorCode.REPLAY_DETECTED, "message_id has already been processed")

    decision = await server.rate_limiter.check_keys(
        [("agent_key", f"key:{message.public_key}")] if "agent_key" in server.rate_limit_policy.scopes else []
    )
    if not decision.allowed:
        raise _rate_limited(decision)

    if server.require_pow:
        if message.pow_seed is None or message.pow_nonce is None:
            raise WAPProtocolError(
                ErrorCode.POW_REQUIRED,
                "this agent requires proof-of-work; solve the attached challenge and resend",
                details={"challenge": server.pow.issue().model_dump(mode="json")},
            )
        try:
            server.pow.verify(message.pow_seed, message.pow_nonce)
        except PowError as exc:
            raise WAPProtocolError(
                ErrorCode.POW_INVALID,
                f"proof-of-work rejected: {exc}",
                details={"reason": exc.reason, "challenge": server.pow.issue().model_dump(mode="json")},
            ) from exc

    principal = await server.authenticate(request.headers.get("authorization"))
    session = server.sessions.get_or_create(message.session_id, message.public_key)
    server.check_conversation(session, message, f"key:{message.public_key}")
    ctx = ActionContext(
        server=server,
        message=message,
        session=session,
        client_ip=ip,
        agent_key=message.public_key,
        principal=principal,
    )
    return ctx, decision.headers()


def build_router(server: WAPServer) -> APIRouter:
    router = APIRouter(tags=["WebAgent Protocol"])

    @router.get(WELL_KNOWN_PATH, include_in_schema=True, summary="WAP discovery manifest (RFC 8615)")
    async def well_known_agent(request: Request) -> Response:
        decision = await server.rate_limiter.check(ip=client_ip(request, server.trust_forwarded_for))
        if not decision.allowed:
            return error_response(server, _rate_limited(decision))
        return manifest_response(server)

    @router.get(CHALLENGE_PATH, summary="Issue a proof-of-work challenge")
    async def challenge(request: Request) -> Response:
        decision = await server.rate_limiter.check(ip=client_ip(request, server.trust_forwarded_for))
        if not decision.allowed:
            return error_response(server, _rate_limited(decision))
        if not server.require_pow:
            return error_response(
                server, WAPProtocolError(ErrorCode.INVALID_REQUEST, "proof-of-work is not enabled on this agent")
            )
        issued = server.pow.issue()
        return signed_json_response(
            server, issued.model_dump(mode="json"), headers={"Cache-Control": "no-store", **decision.headers()}
        )

    @router.post(INTERACT_PATH, summary="Send a signed AgentMessage; JSON or SSE reply")
    async def interact(request: Request) -> Response:
        try:
            ctx, headers = await _admit(server, request)
        except WAPProtocolError as exc:
            return error_response(server, exc)

        wants_stream = "text/event-stream" in request.headers.get("accept", "")
        chunks = server.dispatch(ctx).__aiter__()

        # Pull the first chunk before committing to a status code, so that
        # validation / unknown-capability / auth errors surface as HTTP errors.
        first: Chunk | None = None
        exhausted = False
        try:
            first = await chunks.__anext__()
        except StopAsyncIteration:
            exhausted = True
        except WAPProtocolError as exc:
            return error_response(server, exc, headers)

        if not wants_stream:
            text: list[str] = []
            data: dict[str, Any] = {}

            def collect(chunk: Chunk) -> None:
                if isinstance(chunk, str):
                    text.append(chunk)
                else:
                    data.update(chunk)

            try:
                if not exhausted:
                    collect(first)  # type: ignore[arg-type]
                    async for chunk in chunks:
                        collect(chunk)
            except WAPProtocolError as exc:
                return error_response(server, exc, headers)
            reply = server.reply(ctx.message, "".join(text), data or None)
            server.record_exchange(ctx.session, ctx.message, reply, f"key:{ctx.agent_key}")
            return signed_json_response(server, reply.model_dump(mode="json"), headers=headers)

        async def event_stream() -> AsyncIterator[dict[str, str]]:
            text: list[str] = []
            data: dict[str, Any] = {}

            def encode(event: StreamEventType, payload: Any) -> dict[str, str]:
                return {"event": event.value, "data": json.dumps(payload, separators=(",", ":"), ensure_ascii=False)}

            yield encode(
                StreamEventType.META,
                {
                    "session_id": ctx.session_id,
                    "in_reply_to": ctx.message.message_id,
                    "capability_id": ctx.message.capability_id,
                    "wap_version": WAP_VERSION,
                },
            )

            async def emit(chunk: Chunk) -> AsyncIterator[dict[str, str]]:
                if isinstance(chunk, str):
                    text.append(chunk)
                    for token in _split_tokens(chunk):
                        yield encode(StreamEventType.TOKEN, {"text": token})
                else:
                    data.update(chunk)
                    yield encode(StreamEventType.DATA, chunk)

            try:
                if not exhausted:
                    async for event in emit(first):  # type: ignore[arg-type]
                        yield event
                    async for chunk in chunks:
                        async for event in emit(chunk):
                            yield event
            except WAPProtocolError as exc:
                yield encode(
                    StreamEventType.ERROR,
                    ErrorResponse.build(exc.code, exc.message, details=exc.details).model_dump(
                        mode="json", exclude_none=True
                    ),
                )
                return
            reply = server.reply(ctx.message, "".join(text), data or None)
            server.record_exchange(ctx.session, ctx.message, reply, f"key:{ctx.agent_key}")
            yield encode(StreamEventType.MESSAGE, reply.model_dump(mode="json"))

        return EventSourceResponse(
            event_stream(),
            headers={HEADER_VERSION: WAP_VERSION, "Cache-Control": "no-store", **headers},
            ping=15,
        )

    return router


__all__ = ["build_router", "client_ip", "error_response", "manifest_response", "signed_json_response"]
