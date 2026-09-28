"""HTTP endpoints for WAP/1.0: ``/.well-known/agent.json``, ``/wap/v1/challenge`` and ``/wap/v1/interact``.

The interaction endpoint enforces the request pipeline defined in
``docs/spec_rfc.md`` Section 7.2, in this order:

1. per-IP rate limit (cheapest check first; configurable or disabled),
2. protocol version negotiation,
3. envelope validation,
4. Ed25519 signature verification against the sender's declared key,
5. freshness window and replay detection (shared through the state store),
6. bearer authentication,
7. admission hook, per-agent-key rate limit and proof-of-work (only now is a
   challenge consumed),
8. turn: session lock and ownership, idempotent-retry resolution, loop guards,
9. dispatch to the capability or intent handler.

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
from .admission import AdmissionRequest
from .app import Chunk, Turn, WAPProtocolError

if TYPE_CHECKING:
    from .app import WAPServer

HEADER_IDEMPOTENT_REPLAY = "X-WAP-Idempotent-Replay"

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


async def _admit(server: WAPServer, request: Request) -> tuple[Turn, dict[str, str]]:
    """Run pipeline steps 1-8 and return an opened turn plus response headers."""
    ip = client_ip(request, server.trust_forwarded_for)
    headers = await server.limit_ip(ip)

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

    await server.check_replay(message)
    principal = await server.authenticate(request.headers.get("authorization"))
    decision, key_headers = await server.admit(
        AdmissionRequest(
            client_ip=ip,
            agent_key=message.public_key,
            principal=principal,
            capability_id=message.capability_id,
            transport="wap",
            headers=dict(request.headers),
        ),
        pow_seed=message.pow_seed,
        pow_nonce=message.pow_nonce,
    )
    turn = server.open_turn(
        message,
        owner_key=message.public_key,
        principal_key=f"key:{message.public_key}",
        client_ip=ip,
        agent_key=message.public_key,
        principal=principal,
        tier=decision.tier,
        conversation_policy=decision.conversation_policy,
    )
    await turn.open()
    return turn, {**headers, **key_headers}


def _encode(event: StreamEventType, payload: Any) -> dict[str, str]:
    return {"event": event.value, "data": json.dumps(payload, separators=(",", ":"), ensure_ascii=False)}


def build_router(server: WAPServer) -> APIRouter:
    router = APIRouter(tags=["WebAgent Protocol"])

    @router.get(WELL_KNOWN_PATH, include_in_schema=True, summary="WAP discovery manifest (RFC 8615)")
    async def well_known_agent(request: Request) -> Response:
        try:
            headers = await server.limit_ip(client_ip(request, server.trust_forwarded_for))
        except WAPProtocolError as exc:
            return error_response(server, exc)
        response = manifest_response(server)
        response.headers.update(headers)
        return response

    @router.get(CHALLENGE_PATH, summary="Issue a proof-of-work challenge")
    async def challenge(request: Request) -> Response:
        try:
            headers = await server.limit_ip(client_ip(request, server.trust_forwarded_for))
        except WAPProtocolError as exc:
            return error_response(server, exc)
        if not server.require_pow and server.admission is None:
            return error_response(
                server, WAPProtocolError(ErrorCode.INVALID_REQUEST, "proof-of-work is not enabled on this agent")
            )
        issued = await server.issue_challenge()
        return signed_json_response(
            server, issued.model_dump(mode="json"), headers={"Cache-Control": "no-store", **headers}
        )

    @router.post(INTERACT_PATH, summary="Send a signed AgentMessage; JSON or SSE reply")
    async def interact(request: Request) -> Response:
        try:
            turn, headers = await _admit(server, request)
        except WAPProtocolError as exc:
            if exc.code is not ErrorCode.RATE_LIMITED:
                server.emit("request.rejected", code=exc.code.value)
            return error_response(server, exc)

        wants_stream = "text/event-stream" in request.headers.get("accept", "")

        if turn.replay is not None:
            await turn.close()
            replay = turn.replay
            headers = {**headers, HEADER_IDEMPOTENT_REPLAY: "true"}
            if not wants_stream:
                return signed_json_response(server, replay.model_dump(mode="json"), headers=headers)

            async def replay_stream() -> AsyncIterator[dict[str, str]]:
                yield _encode(
                    StreamEventType.META,
                    {
                        "session_id": replay.session_id,
                        "in_reply_to": replay.in_reply_to,
                        "capability_id": replay.capability_id,
                        "wap_version": WAP_VERSION,
                        "idempotent_replay": True,
                    },
                )
                if replay.structured_data:
                    yield _encode(StreamEventType.DATA, replay.structured_data)
                for token in _split_tokens(replay.content):
                    yield _encode(StreamEventType.TOKEN, {"text": token})
                yield _encode(StreamEventType.MESSAGE, replay.model_dump(mode="json"))

            return EventSourceResponse(
                replay_stream(), headers={HEADER_VERSION: WAP_VERSION, "Cache-Control": "no-store", **headers}
            )

        ctx = turn.ctx
        assert ctx is not None
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
            await turn.fail(exc)
            await turn.close()
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
                reply = await turn.complete("".join(text), data or None)
            except WAPProtocolError as exc:
                await turn.fail(exc)
                return error_response(server, exc, headers)
            finally:
                await turn.close()
            return signed_json_response(server, reply.model_dump(mode="json"), headers=headers)

        async def event_stream() -> AsyncIterator[dict[str, str]]:
            text: list[str] = []
            data: dict[str, Any] = {}

            async def emit(chunk: Chunk) -> AsyncIterator[dict[str, str]]:
                if isinstance(chunk, str):
                    text.append(chunk)
                    for token in _split_tokens(chunk):
                        yield _encode(StreamEventType.TOKEN, {"text": token})
                else:
                    data.update(chunk)
                    yield _encode(StreamEventType.DATA, chunk)

            try:
                yield _encode(
                    StreamEventType.META,
                    {
                        "session_id": ctx.session_id,
                        "in_reply_to": ctx.message.message_id,
                        "capability_id": ctx.message.capability_id,
                        "wap_version": WAP_VERSION,
                    },
                )
                try:
                    if not exhausted:
                        async for event in emit(first):  # type: ignore[arg-type]
                            yield event
                        async for chunk in chunks:
                            async for event in emit(chunk):
                                yield event
                    reply = await turn.complete("".join(text), data or None)
                except WAPProtocolError as exc:
                    await turn.fail(exc)
                    yield _encode(
                        StreamEventType.ERROR,
                        ErrorResponse.build(exc.code, exc.message, details=exc.details).model_dump(
                            mode="json", exclude_none=True
                        ),
                    )
                    return
                yield _encode(StreamEventType.MESSAGE, reply.model_dump(mode="json"))
            finally:
                # Also runs if the client disconnects mid-stream (generator closed/cancelled).
                await turn.close()

        return EventSourceResponse(
            event_stream(),
            headers={HEADER_VERSION: WAP_VERSION, "Cache-Control": "no-store", **headers},
            ping=15,
        )

    return router


__all__ = [
    "HEADER_IDEMPOTENT_REPLAY",
    "build_router",
    "client_ip",
    "error_response",
    "manifest_response",
    "signed_json_response",
]
