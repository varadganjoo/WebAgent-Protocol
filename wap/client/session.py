"""Async WAP consumer: signed requests, proof-of-work, SSE streaming and multi-turn sessions."""

from __future__ import annotations

import asyncio
import inspect
import json
import time
import uuid
from collections import OrderedDict
from collections.abc import AsyncIterator, Awaitable, Callable
from dataclasses import dataclass, field
from typing import Any, Literal

import httpx
from httpx_sse import EventSource
from jsonschema import Draft202012Validator
from jsonschema.exceptions import SchemaError
from pydantic import ValidationError

from .. import __version__
from ..spec.conversation import (
    ConversationGuard,
    ConversationLimitError,
    ConversationPolicy,
    reply_fingerprint,
    request_fingerprint,
)
from ..spec.crypto import Signer, verify_bytes, verify_model
from ..spec.models import (
    HEADER_SIGNATURE,
    HEADER_VERSION,
    WAP_VERSION,
    AgentManifest,
    AgentMessage,
    Capability,
    Challenge,
    Role,
    StreamEventType,
    normalize_authority,
)
from ..spec.pow import solve_async
from .exceptions import (
    AuthRequired,
    CapabilityNotFound,
    ConfirmationDeclined,
    ConversationLimitReached,
    ConversationStopped,
    EffectsNotPermitted,
    LoopDetected,
    ProofOfWorkFailed,
    ProtocolError,
    RateLimited,
    SchemaValidationError,
    VerificationFailed,
)
from .resolver import ManifestResolver, parse_target


@dataclass
class StreamEvent:
    """One incremental event from a business agent's reply."""

    type: StreamEventType
    text: str | None = None
    data: dict[str, Any] | None = None
    message: AgentMessage | None = None
    request: AgentMessage | None = field(default=None, repr=False)
    """For ``MESSAGE`` events: the signed request this reply answers."""


@dataclass(frozen=True)
class ConfirmationRequest:
    """Passed to a client's ``confirm`` hook before an action with side effects."""

    domain: str
    business_name: str
    capability: Capability
    payload: dict[str, Any]

    @property
    def effects(self) -> str:
        return self.capability.effects

    def summary(self) -> str:
        args = ", ".join(f"{k}={v!r}" for k, v in self.payload.items())
        return f"{self.business_name} ({self.domain}): {self.capability.name}({args}) [{self.effects}]"


ConfirmHook = Callable[[ConfirmationRequest], bool | Awaitable[bool]]
_TRANSIENT_STATUS = frozenset({502, 503, 504})


@dataclass
class InteractionResult:
    """The fully collected, signature-verified outcome of one request/response turn."""

    domain: str
    session_id: str
    text: str
    structured_data: dict[str, Any] | None
    message: AgentMessage
    request: AgentMessage
    verified: bool
    pow_solved: bool
    elapsed_seconds: float
    events: list[StreamEvent] = field(default_factory=list, repr=False)

    def to_dict(self) -> dict[str, Any]:
        return {
            "domain": self.domain,
            "session_id": self.session_id,
            "capability_id": self.message.capability_id,
            "text": self.text,
            "structured_data": self.structured_data,
            "verified": self.verified,
            "pow_solved": self.pow_solved,
            "message_id": self.message.message_id,
            "signature": self.message.signature,
            "elapsed_seconds": round(self.elapsed_seconds, 4),
        }


def _has_h2() -> bool:
    try:
        import h2  # noqa: F401
    except ImportError:
        return False
    return True


def validate_payload(manifest: AgentManifest, capability_id: str, payload: dict[str, Any]) -> None:
    """Validate ``payload`` against the capability's JSON Schema before sending it."""
    capability = manifest.get_capability(capability_id)
    if capability is None:
        raise CapabilityNotFound(manifest.domain, capability_id, [c.id for c in manifest.capabilities])
    try:
        validator = Draft202012Validator(capability.input_schema)
    except SchemaError as exc:
        raise VerificationFailed(
            manifest.domain, f"capability {capability_id!r} declares an invalid schema: {exc}"
        ) from exc
    errors = sorted(validator.iter_errors(payload), key=lambda e: list(e.absolute_path))
    if errors:
        rendered = [f"{'/'.join(map(str, e.absolute_path)) or '<root>'}: {e.message}" for e in errors]
        raise SchemaValidationError(capability_id, rendered)


class WAPClient:
    """High-level async client for talking to WAP business agents.

    ``WAPClient`` owns one ``httpx.AsyncClient`` (HTTP/2 when ``h2`` is
    installed), a manifest cache and an Ed25519 *agent key* that signs every
    outgoing message. Use it as an async context manager.
    """

    def __init__(
        self,
        *,
        agent_key: Signer | str | None = None,
        timeout: float = 30.0,
        http2: bool = True,
        transport: httpx.AsyncBaseTransport | None = None,
        cache_ttl: float = 300.0,
        pinned_keys: dict[str, str] | None = None,
        auth_tokens: dict[str, str] | None = None,
        allow_insecure: bool = False,
        verify_dns: bool = False,
        block_private_networks: bool = False,
        allow_loopback: bool = False,
        trust_on_first_use: bool = False,
        dns_key_policy: str = "off",
        txt_resolver: Any = None,
        validate_payloads: bool = True,
        max_pow_attempts: int = 3,
        user_agent: str | None = None,
        conversation_policy: ConversationPolicy | Literal[False] | None = None,
        confirm: ConfirmHook | None = None,
        confirm_effects: frozenset[str] | set[str] = frozenset({"write", "financial"}),
        max_retries: int = 2,
        retry_backoff: float = 0.25,
    ) -> None:
        self.signer = agent_key if isinstance(agent_key, Signer) else Signer(agent_key)
        self.http = httpx.AsyncClient(
            http2=http2 and transport is None and _has_h2(),
            timeout=httpx.Timeout(timeout, connect=min(timeout, 10.0)),
            transport=transport,
            follow_redirects=False,
            headers={
                "User-Agent": user_agent or f"wap-python/{__version__}",
                HEADER_VERSION: WAP_VERSION,
            },
        )
        self.resolver = ManifestResolver(
            self.http,
            cache_ttl=cache_ttl,
            pinned_keys=pinned_keys,
            allow_insecure=allow_insecure,
            verify_dns=verify_dns,
            block_private_networks=block_private_networks,
            allow_loopback=allow_loopback,
            trust_on_first_use=trust_on_first_use,
            dns_key_policy=dns_key_policy,  # type: ignore[arg-type]
            txt_resolver=txt_resolver,
        )
        self.auth_tokens = {normalize_authority(k): v for k, v in (auth_tokens or {}).items()}
        self.allow_insecure = allow_insecure
        self.validate_payloads = validate_payloads
        self.max_pow_attempts = max(1, max_pow_attempts)
        # Loop protection for the user's side: refuse to send a request that would
        # continue a loop, before any network call or proof-of-work.
        self.conversation_policy: ConversationPolicy | None = (
            None if conversation_policy is False else (conversation_policy or ConversationPolicy(max_turns=50))
        )
        self.confirm = confirm
        self.confirm_effects = frozenset(confirm_effects)
        self.max_retries = max(0, max_retries)
        self.retry_backoff = retry_backoff
        self._session_guards: OrderedDict[tuple[str, str], ConversationGuard] = OrderedDict()
        self._domain_guards: dict[str, ConversationGuard] = {}

    async def __aenter__(self) -> WAPClient:
        return self

    async def __aexit__(self, *exc_info: object) -> None:
        await self.aclose()

    async def aclose(self) -> None:
        await self.http.aclose()

    @property
    def agent_public_key(self) -> str:
        return self.signer.public_key

    # ------------------------------------------------------------------ discovery

    async def discover(self, domain: str, *, force_refresh: bool = False) -> AgentManifest:
        """Resolve and verify ``domain``'s manifest (cached)."""
        return await self.resolver.resolve(domain, force_refresh=force_refresh)

    async def fetch_challenge(self, manifest: AgentManifest) -> Challenge:
        if manifest.challenge_url is None:
            raise ProtocolError("pow_required", f"{manifest.domain} requires proof-of-work but has no challenge_url")
        response = await self.http.get(manifest.challenge_url, headers={"Cache-Control": "no-store"})
        body = await self._check_response(manifest, response)
        try:
            return Challenge.model_validate(body)
        except ValidationError as exc:
            raise ProtocolError("invalid_request", f"malformed challenge from {manifest.domain}: {exc}") from exc

    # ------------------------------------------------------------------ loop protection

    def conversation_guards(self, domain: str, session_id: str) -> list[ConversationGuard]:
        """The per-session guard and the per-domain (cross-session) guard for a conversation."""
        if self.conversation_policy is None:
            return []
        key = (domain, session_id)
        guard = self._session_guards.get(key)
        if guard is None:
            guard = self._session_guards[key] = ConversationGuard(self.conversation_policy)
            while len(self._session_guards) > 1_000:
                self._session_guards.popitem(last=False)
        self._session_guards.move_to_end(key)
        domain_guard = self._domain_guards.get(domain)
        if domain_guard is None:
            domain_guard = self._domain_guards[domain] = ConversationGuard(self.conversation_policy.across_sessions())
        return [guard, domain_guard]

    @staticmethod
    def _stopped(exc: ConversationLimitError) -> ConversationStopped:
        cls = LoopDetected if exc.reason == "loop_detected" else ConversationLimitReached
        return cls(exc.reason, f"stopped locally: {exc.message}", details=exc.details)

    # ------------------------------------------------------------------ interaction

    def session(self, domain: str, session_id: str | None = None) -> WAPSession:
        """Open a multi-turn dialogue with ``domain``."""
        return WAPSession(self, domain, session_id)

    async def query(
        self,
        domain: str,
        intent: str = "",
        capability_id: str | None = None,
        payload: dict[str, Any] | None = None,
        *,
        session_id: str | None = None,
        auth_token: str | None = None,
        stream: bool = True,
        idempotency_key: str | None = None,
        max_effects: str | None = None,
    ) -> AsyncIterator[StreamEvent]:
        """Send one turn to ``domain`` and yield reply events as they arrive.

        The final event is always ``StreamEventType.MESSAGE`` carrying the
        business agent's signed :class:`AgentMessage`, already verified against
        the manifest's public key.

        Capabilities that are not read-only get an automatic ``idempotency_key``
        (unless one is given), so the transient-failure retries below can never
        perform the action twice. If a ``confirm`` hook is configured it is called
        before any capability whose ``effects`` are in ``confirm_effects``.
        """
        manifest = await self.discover(domain)
        capability = None
        if capability_id is not None:
            capability = manifest.get_capability(capability_id)
            if capability is None:
                raise CapabilityNotFound(manifest.domain, capability_id, [c.id for c in manifest.capabilities])
            if self.validate_payloads:
                validate_payload(manifest, capability_id, payload or {})
        if not intent and capability_id is None:
            raise ValueError("either an intent or a capability_id is required")

        session_id = session_id or uuid.uuid4().hex
        request_fp = request_fingerprint(capability_id, payload, intent)
        guards = self.conversation_guards(manifest.domain, session_id)
        for guard in guards:
            try:
                guard.check(request_fp)
            except ConversationLimitError as exc:
                raise self._stopped(exc) from None

        effects = capability.effects if capability is not None else None
        if capability is not None and self.confirm is not None and effects in self.confirm_effects:
            approval = self.confirm(
                ConfirmationRequest(
                    domain=manifest.domain,
                    business_name=manifest.name,
                    capability=capability,
                    payload=dict(payload or {}),
                )
            )
            if inspect.isawaitable(approval):
                approval = await approval
            if not approval:
                raise ConfirmationDeclined(manifest.domain, capability.id)
        if idempotency_key is None and capability is not None and effects != "read":
            idempotency_key = "auto-" + uuid.uuid4().hex
        # Free-text intents may trigger actions, so they are only retried with an idempotency key.
        retryable = effects == "read" or idempotency_key is not None or max_effects == "read"

        token = auth_token or self.auth_tokens.get(manifest.domain)
        challenge: Challenge | None = None
        pow_attempts = 0
        transient_attempts = 0
        while True:
            if challenge is None and manifest.pow_required:
                challenge = await self.fetch_challenge(manifest)
            pow_seed = pow_nonce = None
            if challenge is not None:
                pow_seed, pow_nonce = challenge.seed, await solve_async(challenge.seed, challenge.difficulty)
            request = self.signer.sign_model(
                AgentMessage(
                    session_id=session_id,
                    role=Role.USER_AGENT,
                    content=intent,
                    capability_id=capability_id,
                    structured_data=payload,
                    idempotency_key=idempotency_key,
                    max_effects=max_effects,
                    pow_seed=pow_seed,
                    pow_nonce=pow_nonce,
                    public_key=self.signer.public_key,
                )
            )
            yielded = False
            try:
                async for event in self._send(manifest, request, token=token, stream=stream):
                    if event.type is StreamEventType.MESSAGE and event.message is not None:
                        reply_fp = reply_fingerprint(event.message.content, event.message.structured_data)
                        for guard in guards:
                            guard.record(request_fp, reply_fp)
                    yielded = True
                    yield event
                return
            except (httpx.TransportError, ProtocolError) as exc:
                # Gateway errors without a WAP error body (proxies, load balancers) are transient;
                # a WAP "action_failed" (502) means the business's code failed and is not retried.
                transient = isinstance(exc, httpx.TransportError) or (
                    (exc.status_code in _TRANSIENT_STATUS and exc.code == "http_error")
                    or exc.code in ("session_busy",)
                    or (exc.code == "idempotency_conflict" and exc.retry_after is not None)
                )
                if transient and retryable and not yielded and transient_attempts < self.max_retries:
                    transient_attempts += 1
                    delay = getattr(exc, "retry_after", None) or self.retry_backoff * 2 ** (transient_attempts - 1)
                    await asyncio.sleep(min(delay, 30.0))
                    challenge = None  # the previous seed may already be spent
                    continue
                if isinstance(exc, httpx.TransportError):
                    raise ProtocolError("network_error", f"could not reach {manifest.domain}: {exc!s}") from exc
                retry_challenge = exc.details.get("challenge") if exc.code in ("pow_required", "pow_invalid") else None
                pow_attempts += 1
                if retry_challenge is None or pow_attempts >= self.max_pow_attempts:
                    # An error is an answer too: resending a request that keeps failing is a loop.
                    error_fp = reply_fingerprint(f"error:{exc.code}:{exc.message}", exc.details)
                    for guard in guards:
                        guard.record(request_fp, error_fp)
                    if exc.code in ("pow_required", "pow_invalid"):
                        raise ProofOfWorkFailed(
                            exc.code, exc.message, status_code=exc.status_code, details=exc.details
                        ) from exc
                    raise
                challenge = Challenge.model_validate(retry_challenge)

    async def ask(
        self,
        domain: str,
        intent: str = "",
        capability_id: str | None = None,
        payload: dict[str, Any] | None = None,
        *,
        session_id: str | None = None,
        auth_token: str | None = None,
        stream: bool = True,
        idempotency_key: str | None = None,
        max_effects: str | None = None,
    ) -> InteractionResult:
        """Like :meth:`query` but collects the stream into an :class:`InteractionResult`."""
        started = time.perf_counter()
        events: list[StreamEvent] = []
        async for event in self.query(
            domain,
            intent,
            capability_id,
            payload,
            session_id=session_id,
            auth_token=auth_token,
            stream=stream,
            idempotency_key=idempotency_key,
            max_effects=max_effects,
        ):
            events.append(event)
        last = events[-1]
        if last.message is None or last.request is None:
            raise ProtocolError("invalid_response", "reply stream ended without a verified final message")
        final, request = last.message, last.request
        return InteractionResult(
            domain=parse_target(domain, allow_insecure=True).authority,
            session_id=final.session_id,
            text=final.content,
            structured_data=final.structured_data,
            message=final,
            request=request,
            verified=True,
            pow_solved=request.pow_nonce is not None,
            elapsed_seconds=time.perf_counter() - started,
            events=events,
        )

    async def invoke(
        self,
        domain: str,
        capability_id: str,
        payload: dict[str, Any] | None = None,
        *,
        intent: str = "",
        session_id: str | None = None,
        auth_token: str | None = None,
        idempotency_key: str | None = None,
    ) -> InteractionResult:
        """Execute a specific capability with structured input (non-streaming)."""
        return await self.ask(
            domain,
            intent,
            capability_id,
            payload or {},
            session_id=session_id,
            auth_token=auth_token,
            stream=False,
            idempotency_key=idempotency_key,
        )

    # ------------------------------------------------------------------ transport

    def _raise_error(self, manifest: AgentManifest, status: int, body: Any, headers: httpx.Headers) -> None:
        error = body.get("error") if isinstance(body, dict) else None
        if not isinstance(error, dict):
            raise ProtocolError("http_error", f"HTTP {status} from {manifest.domain}", status_code=status)
        code = str(error.get("code", "http_error"))
        message = str(error.get("message", ""))
        details = error.get("details") or {}
        retry_after = error.get("retry_after")
        if retry_after is None and headers.get("retry-after"):
            try:
                retry_after = float(headers["retry-after"])
            except ValueError:
                retry_after = None
        kwargs: dict[str, Any] = {"status_code": status, "details": details, "retry_after": retry_after}
        if code == "rate_limited":
            raise RateLimited(code, message, **kwargs)
        if code == "auth_required":
            raise AuthRequired(code, message, **kwargs)
        if code == "effects_not_permitted":
            raise EffectsNotPermitted(code, message, **kwargs)
        if code == "loop_detected":
            raise LoopDetected(code, message, **kwargs)
        if code == "conversation_limit":
            raise ConversationLimitReached(code, message, **kwargs)
        raise ProtocolError(code, message, **kwargs)

    def _verify_body(self, manifest: AgentManifest, body: bytes, headers: httpx.Headers) -> Any:
        signature = headers.get(HEADER_SIGNATURE)
        if signature is not None and not verify_bytes(manifest.public_key, body, signature):
            raise VerificationFailed(manifest.domain, "X-WAP-Signature does not match the response body")
        try:
            return json.loads(body) if body else None
        except ValueError as exc:
            raise ProtocolError("invalid_response", f"{manifest.domain} returned non-JSON content") from exc

    async def _check_response(self, manifest: AgentManifest, response: httpx.Response) -> Any:
        body = self._verify_body(manifest, response.content, response.headers)
        if response.status_code >= 400:
            self._raise_error(manifest, response.status_code, body, response.headers)
        return body

    def _verify_reply(self, manifest: AgentManifest, request: AgentMessage, raw: Any) -> AgentMessage:
        try:
            reply = AgentMessage.model_validate(raw)
        except ValidationError as exc:
            raise ProtocolError("invalid_response", f"malformed reply from {manifest.domain}: {exc}") from exc
        if reply.role is not Role.BUSINESS_AGENT:
            raise VerificationFailed(manifest.domain, "reply does not carry role 'business_agent'")
        if not verify_model(reply, manifest.public_key):
            raise VerificationFailed(manifest.domain, "reply signature does not verify against the manifest key")
        if reply.in_reply_to != request.message_id or reply.session_id != request.session_id:
            raise VerificationFailed(
                manifest.domain, "reply is not bound to this request (in_reply_to/session mismatch)"
            )
        return reply

    async def _send(
        self, manifest: AgentManifest, request: AgentMessage, *, token: str | None, stream: bool
    ) -> AsyncIterator[StreamEvent]:
        headers = {"Content-Type": "application/json", "Accept": "text/event-stream" if stream else "application/json"}
        if token:
            headers["Authorization"] = f"Bearer {token}"
        body = request.model_dump_json().encode("utf-8")
        async with self.http.stream("POST", manifest.interaction_url, content=body, headers=headers) as response:
            content_type = response.headers.get("content-type", "")
            if response.status_code >= 400 or "text/event-stream" not in content_type:
                raw = await response.aread()
                parsed = self._verify_body(manifest, raw, response.headers)
                if response.status_code >= 400:
                    self._raise_error(manifest, response.status_code, parsed, response.headers)
                reply = self._verify_reply(manifest, request, parsed)
                if reply.structured_data:
                    yield StreamEvent(StreamEventType.DATA, data=reply.structured_data)
                if reply.content:
                    yield StreamEvent(StreamEventType.TOKEN, text=reply.content)
                yield StreamEvent(
                    StreamEventType.MESSAGE,
                    text=reply.content,
                    data=reply.structured_data,
                    message=reply,
                    request=request,
                )
                return

            async for sse in EventSource(response).aiter_sse():
                try:
                    payload = json.loads(sse.data) if sse.data else {}
                except ValueError as exc:
                    raise ProtocolError("invalid_response", f"malformed SSE data for event {sse.event!r}") from exc
                if sse.event == StreamEventType.META.value:
                    yield StreamEvent(StreamEventType.META, data=payload)
                elif sse.event == StreamEventType.TOKEN.value:
                    yield StreamEvent(StreamEventType.TOKEN, text=str(payload.get("text", "")))
                elif sse.event == StreamEventType.DATA.value:
                    yield StreamEvent(StreamEventType.DATA, data=payload)
                elif sse.event == StreamEventType.ERROR.value:
                    self._raise_error(manifest, 200, payload, response.headers)
                elif sse.event == StreamEventType.MESSAGE.value:
                    reply = self._verify_reply(manifest, request, payload)
                    yield StreamEvent(
                        StreamEventType.MESSAGE,
                        text=reply.content,
                        data=reply.structured_data,
                        message=reply,
                        request=request,
                    )
                    return
            raise ProtocolError("invalid_response", f"{manifest.domain} closed the stream without a final message")


class WAPSession:
    """A multi-turn dialogue with a single business agent, sharing one ``session_id``."""

    def __init__(self, client: WAPClient, domain: str, session_id: str | None = None) -> None:
        self.client = client
        self.domain = domain
        self.session_id = session_id or uuid.uuid4().hex
        self.history: list[AgentMessage] = []

    async def stream(
        self, intent: str = "", capability_id: str | None = None, payload: dict[str, Any] | None = None
    ) -> AsyncIterator[StreamEvent]:
        async for event in self.client.query(
            self.domain, intent, capability_id, payload, session_id=self.session_id, stream=True
        ):
            if event.type is StreamEventType.MESSAGE and event.message is not None and event.request is not None:
                self.history.extend([event.request, event.message])
            yield event

    async def send(
        self, intent: str = "", capability_id: str | None = None, payload: dict[str, Any] | None = None
    ) -> InteractionResult:
        result = await self.client.ask(self.domain, intent, capability_id, payload, session_id=self.session_id)
        self.history.extend([result.request, result.message])
        return result

    @property
    def last_reply(self) -> AgentMessage | None:
        for message in reversed(self.history):
            if message.role is Role.BUSINESS_AGENT:
                return message
        return None


__all__ = ["InteractionResult", "StreamEvent", "WAPClient", "WAPSession", "validate_payload"]
