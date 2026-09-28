"""WAPServer: capability registry, manifest signing and message dispatch.

Business developers expose ordinary Python callables as machine-executable
capabilities::

    wap = WAPServer(name="Bakery", domain="bakery.example", private_key=KEY, require_pow=True)

    @wap.action(name="check_pastry_stock", description="Units on hand for a pastry.")
    async def check_pastry_stock(item: str) -> dict:
        return {"item": item, "in_stock": 12}

    wap.mount(app)   # app is a FastAPI instance

Input schemas are generated from the function signature with Pydantic, so the
manifest always matches what the function actually accepts.
"""

from __future__ import annotations

import asyncio
import inspect
import logging
import re
import sys
import time
from collections import OrderedDict
from collections.abc import AsyncIterator, Callable
from dataclasses import dataclass, field
from typing import TYPE_CHECKING, Any, get_type_hints

from pydantic import BaseModel, ConfigDict, TypeAdapter, ValidationError, create_model

from ..spec.crypto import Signer
from ..spec.models import (
    CHALLENGE_PATH,
    INTERACT_PATH,
    AgentManifest,
    AgentMessage,
    Capability,
    ErrorCode,
    RateLimitPolicy,
    Role,
    is_local_authority,
    normalize_authority,
)
from ..spec.pow import PowEngine
from .rate_limiter import RateLimiter

if TYPE_CHECKING:
    from fastapi import FastAPI

logger = logging.getLogger("wap.server")

AuthHandler = Callable[[str], Any]


class WAPProtocolError(Exception):
    """An error that maps directly onto a WAP error response."""

    def __init__(
        self,
        code: ErrorCode,
        message: str,
        *,
        retry_after: float | None = None,
        details: dict[str, Any] | None = None,
        headers: dict[str, str] | None = None,
    ) -> None:
        super().__init__(message)
        self.code = code
        self.message = message
        self.retry_after = retry_after
        self.details = details
        self.headers = headers or {}


@dataclass
class ActionResult:
    """Explicit result type for actions that want to control both text and data."""

    content: str = ""
    data: dict[str, Any] | None = None


@dataclass
class SessionState:
    session_id: str
    owner_key: str | None
    created_at: float = field(default_factory=time.time)
    last_seen: float = field(default_factory=time.time)
    history: list[AgentMessage] = field(default_factory=list)
    state: dict[str, Any] = field(default_factory=dict)


class SessionStore:
    """Bounded LRU store of dialogue sessions bound to the agent key that opened them."""

    def __init__(self, max_sessions: int = 10_000, ttl_seconds: float = 3600.0, max_history: int = 100) -> None:
        self.max_sessions = max_sessions
        self.ttl_seconds = ttl_seconds
        self.max_history = max_history
        self._sessions: OrderedDict[str, SessionState] = OrderedDict()

    def get_or_create(self, session_id: str, owner_key: str | None) -> SessionState:
        now = time.time()
        session = self._sessions.get(session_id)
        if session is not None and now - session.last_seen > self.ttl_seconds:
            del self._sessions[session_id]
            session = None
        if session is None:
            session = SessionState(session_id=session_id, owner_key=owner_key)
            self._sessions[session_id] = session
            while len(self._sessions) > self.max_sessions:
                self._sessions.popitem(last=False)
        elif session.owner_key != owner_key:
            raise WAPProtocolError(ErrorCode.FORBIDDEN, "session belongs to a different agent key")
        session.last_seen = now
        self._sessions.move_to_end(session_id)
        return session

    def record(self, session: SessionState, *messages: AgentMessage) -> None:
        session.history.extend(messages)
        if len(session.history) > self.max_history:
            del session.history[: len(session.history) - self.max_history]

    def get(self, session_id: str) -> SessionState | None:
        return self._sessions.get(session_id)

    def __len__(self) -> int:
        return len(self._sessions)


class ReplayCache:
    """Remembers message ids for the clock-skew window to reject replays."""

    def __init__(self, window_seconds: float = 300.0, max_entries: int = 200_000) -> None:
        self.window_seconds = window_seconds
        self.max_entries = max_entries
        self._seen: OrderedDict[str, float] = OrderedDict()

    def check_and_add(self, key: str, now: float | None = None) -> bool:
        """Return ``False`` if ``key`` was already seen inside the window."""
        now = time.time() if now is None else now
        cutoff = now - 2 * self.window_seconds
        while self._seen:
            oldest_key, oldest_time = next(iter(self._seen.items()))
            if oldest_time >= cutoff and len(self._seen) < self.max_entries:
                break
            del self._seen[oldest_key]
        if key in self._seen:
            return False
        self._seen[key] = now
        return True


@dataclass
class ActionContext:
    """Per-request context injected into actions that declare a parameter of this type."""

    server: WAPServer
    message: AgentMessage
    session: SessionState
    client_ip: str | None = None
    agent_key: str | None = None
    principal: Any = None

    @property
    def session_id(self) -> str:
        return self.session.session_id

    @property
    def intent(self) -> str:
        return self.message.content

    @property
    def history(self) -> list[AgentMessage]:
        return self.session.history

    @property
    def state(self) -> dict[str, Any]:
        return self.session.state

    async def invoke(self, capability_id: str, payload: dict[str, Any] | None = None) -> ActionResult:
        """Run another registered capability and collect its full result (for intent routers)."""
        text: list[str] = []
        data: dict[str, Any] = {}
        async for chunk in self.server.run_capability(capability_id, payload or {}, self):
            if isinstance(chunk, str):
                text.append(chunk)
            else:
                data.update(chunk)
        return ActionResult(content="".join(text), data=data or None)


class _InputBase(BaseModel):
    model_config = ConfigDict(extra="forbid")


@dataclass
class RegisteredAction:
    func: Callable[..., Any]
    capability: Capability
    input_model: type[BaseModel]
    context_param: str | None
    model_param: str | None

    async def call(self, payload: dict[str, Any], ctx: ActionContext) -> Any:
        try:
            validated = self.input_model.model_validate(payload)
        except ValidationError as exc:
            raise WAPProtocolError(
                ErrorCode.VALIDATION_ERROR,
                f"structured_data does not match the input schema of {self.capability.id!r}",
                details={"errors": exc.errors(include_url=False, include_context=False)},
            ) from exc
        if self.model_param is not None:
            kwargs: dict[str, Any] = {self.model_param: validated}
        else:
            kwargs = {name: getattr(validated, name) for name in type(validated).model_fields}
        if self.context_param is not None:
            kwargs[self.context_param] = ctx
        if (
            inspect.isasyncgenfunction(self.func)
            or inspect.iscoroutinefunction(self.func)
            or inspect.isgeneratorfunction(self.func)
        ):
            return self.func(**kwargs)
        # Plain synchronous callables may block (database drivers, SDK calls): run off-loop.
        return await asyncio.to_thread(self.func, **kwargs)


def _json_schema_for(annotation: Any) -> dict[str, Any] | None:
    if annotation is inspect.Signature.empty or annotation is None or annotation is type(None):
        return None
    if annotation in (str, ActionResult):
        return None
    try:
        schema = TypeAdapter(annotation).json_schema()
    except Exception:  # annotation not representable as JSON Schema
        return None
    return schema if schema.get("type") == "object" or "properties" in schema else None


def _build_action(
    func: Callable[..., Any],
    *,
    capability_id: str,
    title: str | None,
    description: str | None,
    requires_auth: bool,
    localns: dict[str, Any] | None = None,
) -> RegisteredAction:
    signature = inspect.signature(func)
    try:
        # localns resolves string annotations naming classes defined in the enclosing
        # function (common with ``from __future__ import annotations``).
        hints = get_type_hints(func, localns=localns, include_extras=True)
    except Exception as exc:
        raise TypeError(f"action {capability_id!r}: cannot resolve type annotations ({exc})") from exc
    fields: dict[str, Any] = {}
    context_param: str | None = None
    model_param: str | None = None
    for param in signature.parameters.values():
        if param.kind in (inspect.Parameter.VAR_POSITIONAL, inspect.Parameter.VAR_KEYWORD):
            raise TypeError(f"action {capability_id!r}: *args/**kwargs are not supported")
        annotation = hints.get(param.name, param.annotation)
        if annotation is ActionContext:
            context_param = param.name
            continue
        if annotation is inspect.Parameter.empty:
            annotation = Any
        default = ... if param.default is inspect.Parameter.empty else param.default
        fields[param.name] = (annotation, default)

    input_model: type[BaseModel]
    model_candidates = [
        name for name, (ann, _) in fields.items() if inspect.isclass(ann) and issubclass(ann, BaseModel)
    ]
    if len(fields) == 1 and model_candidates:
        model_param = model_candidates[0]
        input_model = fields[model_param][0]
    else:
        model_name = "".join(part.capitalize() for part in re.split(r"[^a-zA-Z0-9]", capability_id)) + "Input"
        input_model = create_model(model_name, __base__=_InputBase, **fields)

    input_schema = input_model.model_json_schema()
    input_schema.setdefault("type", "object")
    input_schema.setdefault("properties", {})
    input_schema.pop("title", None)

    doc = inspect.getdoc(func) or ""
    capability = Capability(
        id=capability_id,
        name=title or capability_id.replace("_", " ").replace(".", " ").title(),
        description=description if description is not None else doc,
        input_schema=input_schema,
        output_schema=_json_schema_for(hints.get("return", signature.return_annotation)),
        requires_auth=requires_auth,
        streaming=inspect.isasyncgenfunction(func) or inspect.isgeneratorfunction(func),
    )
    return RegisteredAction(
        func=func, capability=capability, input_model=input_model, context_param=context_param, model_param=model_param
    )


_WORD_RE = re.compile(r"[a-z0-9]+")
_STOPWORDS = frozenset(
    "a an and any are can could do does for from have i is it me my of on or please "
    "the there to what which with you your".split()
)


def _tokens(text: str) -> set[str]:
    words = set(_WORD_RE.findall(text.lower())) - _STOPWORDS
    return {w[:-1] if len(w) > 3 and w.endswith("s") else w for w in words}


class KeywordIntentRouter:
    """Deterministic fallback router used when no custom intent handler is registered.

    Scores every capability by lexical overlap between the intent and the
    capability's id, name and description. If the best capability can be
    invoked with the supplied structured data it is executed; otherwise the
    router replies with a clarification describing what is needed.
    """

    async def __call__(self, intent: str, ctx: ActionContext) -> ActionResult:
        server = ctx.server
        intent_tokens = _tokens(intent)
        best: tuple[float, RegisteredAction] | None = None
        for action in server.actions.values():
            cap = action.capability
            name_tokens = _tokens(f"{cap.id} {cap.name}")
            desc_tokens = _tokens(cap.description)
            score = 2.0 * len(intent_tokens & name_tokens) + len(intent_tokens & desc_tokens)
            if score > 0 and (best is None or score > best[0]):
                best = (score, action)
        if best is None:
            return ActionResult(
                content=(
                    f"{server.name} could not map that request to a capability. "
                    f"Available capabilities: {', '.join(server.actions) or 'none'}."
                ),
                data={"capabilities": [a.capability.model_dump(mode="json") for a in server.actions.values()]},
            )
        action = best[1]
        payload = ctx.message.structured_data or {}
        required = set(action.capability.input_schema.get("required", []))
        missing = sorted(required - set(payload))
        if missing:
            return ActionResult(
                content=(
                    f"I can help with that via '{action.capability.id}', but I need: {', '.join(missing)}. "
                    "Resend the request with these fields in structured_data."
                ),
                data={
                    "needs_input": True,
                    "capability_id": action.capability.id,
                    "missing": missing,
                    "input_schema": action.capability.input_schema,
                },
            )
        if action.capability.requires_auth and ctx.principal is None:
            raise WAPProtocolError(
                ErrorCode.AUTH_REQUIRED, f"capability {action.capability.id!r} requires authorization"
            )
        return await ctx.invoke(action.capability.id, payload)


Chunk = str | dict[str, Any]


async def iterate_result(result: Any, default_content: str = "") -> AsyncIterator[Chunk]:
    """Normalise any supported action return value into a stream of text/data chunks."""
    if inspect.isawaitable(result):
        result = await result
    if inspect.isasyncgen(result):
        async for item in result:
            async for chunk in iterate_result(item):
                yield chunk
        return
    if inspect.isgenerator(result):
        for item in result:
            async for chunk in iterate_result(item):
                yield chunk
        return
    if result is None:
        if default_content:
            yield default_content
        return
    if isinstance(result, ActionResult):
        if result.data is not None:
            yield dict(result.data)
        if result.content:
            yield result.content
        elif default_content:
            yield default_content
        return
    if isinstance(result, str):
        yield result
        return
    if isinstance(result, BaseModel):
        yield result.model_dump(mode="json")
        if default_content:
            yield default_content
        return
    if isinstance(result, dict):
        yield TypeAdapter(dict[str, Any]).dump_python(result, mode="json")
        if default_content:
            yield default_content
        return
    if isinstance(result, (list, tuple, set, int, float, bool)):
        yield {"result": TypeAdapter(Any).dump_python(result, mode="json")}
        if default_content:
            yield default_content
        return
    raise TypeError(f"unsupported action return type: {type(result).__name__}")


class WAPServer:
    """A business agent: owns the signing key, capability registry and abuse controls."""

    def __init__(
        self,
        name: str,
        domain: str,
        private_key: str | None = None,
        require_pow: bool = False,
        *,
        description: str = "",
        pow_difficulty: int = 4,
        pow_ttl_seconds: float = 120.0,
        rate_limit: RateLimitPolicy | None = None,
        base_url: str | None = None,
        manifest_ttl_seconds: float = 3600.0,
        max_clock_skew_seconds: float = 300.0,
        auth_handler: AuthHandler | None = None,
        trust_forwarded_for: bool = False,
    ) -> None:
        self.name = name
        self.domain = normalize_authority(domain)
        self.description = description
        if private_key is None:
            logger.warning(
                "WAPServer %r started without a private key; using an ephemeral key. "
                "Manifests will change identity on every restart. Run `wap keygen` for a persistent key.",
                name,
            )
        self.signer = Signer(private_key)
        self.require_pow = require_pow
        self.pow = PowEngine(difficulty=pow_difficulty, ttl_seconds=pow_ttl_seconds)
        self.rate_limit_policy = rate_limit or RateLimitPolicy()
        self.rate_limiter = RateLimiter(self.rate_limit_policy)
        scheme = "http" if is_local_authority(self.domain) else "https"
        self.base_url = (base_url or f"{scheme}://{self.domain}").rstrip("/")
        self.manifest_ttl_seconds = manifest_ttl_seconds
        self.max_clock_skew_seconds = max_clock_skew_seconds
        self.auth_handler = auth_handler
        self.trust_forwarded_for = trust_forwarded_for
        self.actions: dict[str, RegisteredAction] = {}
        self.sessions = SessionStore()
        self.replay_cache = ReplayCache(window_seconds=max_clock_skew_seconds)
        self._intent_handler: Callable[[str, ActionContext], Any] = KeywordIntentRouter()
        self._manifest: AgentManifest | None = None

    # ------------------------------------------------------------------ registry

    @property
    def public_key(self) -> str:
        return self.signer.public_key

    def action(
        self,
        name: str | None = None,
        description: str | None = None,
        *,
        title: str | None = None,
        requires_auth: bool = False,
    ) -> Callable[[Callable[..., Any]], Callable[..., Any]]:
        """Register a function as a capability. ``name`` becomes the capability id."""

        caller_locals = dict(sys._getframe(1).f_locals)

        def decorator(func: Callable[..., Any]) -> Callable[..., Any]:
            capability_id = name or func.__name__
            if capability_id in self.actions:
                raise ValueError(f"capability {capability_id!r} is already registered")
            if requires_auth and self.auth_handler is None:
                raise ValueError(f"capability {capability_id!r} requires auth but WAPServer has no auth_handler")
            self.actions[capability_id] = _build_action(
                func,
                capability_id=capability_id,
                title=title,
                description=description,
                requires_auth=requires_auth,
                localns=caller_locals,
            )
            self._manifest = None
            return func

        return decorator

    def intent(self, func: Callable[[str, ActionContext], Any]) -> Callable[[str, ActionContext], Any]:
        """Register the handler for free-text intents (no ``capability_id``), e.g. an LLM router."""
        self._intent_handler = func
        return func

    # ------------------------------------------------------------------ manifest

    def build_manifest(self, now: float | None = None) -> AgentManifest:
        now = time.time() if now is None else now
        manifest = AgentManifest(
            domain=self.domain,
            name=self.name,
            description=self.description,
            public_key=self.public_key,
            interaction_url=self.base_url + INTERACT_PATH,
            challenge_url=self.base_url + CHALLENGE_PATH if self.require_pow else None,
            capabilities=[a.capability for a in self.actions.values()],
            pow_required=self.require_pow,
            pow_difficulty=self.pow.difficulty if self.require_pow else None,
            rate_limit_policy=self.rate_limit_policy.model_dump(),
            issued_at=now,
            expires_at=now + self.manifest_ttl_seconds,
        )
        return self.signer.sign_model(manifest)

    def manifest(self) -> AgentManifest:
        """The current signed manifest, re-signed once half its lifetime has elapsed."""
        now = time.time()
        current = self._manifest
        if current is None or current.expires_at is None or now >= current.issued_at + self.manifest_ttl_seconds / 2:
            current = self._manifest = self.build_manifest(now)
        return current

    # ------------------------------------------------------------------ dispatch

    async def authenticate(self, authorization: str | None) -> Any:
        if self.auth_handler is None or not authorization:
            return None
        scheme, _, token = authorization.partition(" ")
        if scheme.lower() != "bearer" or not token:
            raise WAPProtocolError(ErrorCode.AUTH_REQUIRED, "Authorization must use the Bearer scheme")
        principal = self.auth_handler(token.strip())
        if inspect.isawaitable(principal):
            principal = await principal
        if principal is None:
            raise WAPProtocolError(ErrorCode.AUTH_REQUIRED, "bearer token was rejected")
        return principal

    async def run_capability(
        self, capability_id: str, payload: dict[str, Any], ctx: ActionContext
    ) -> AsyncIterator[Chunk]:
        action = self.actions.get(capability_id)
        if action is None:
            raise WAPProtocolError(
                ErrorCode.UNKNOWN_CAPABILITY,
                f"unknown capability {capability_id!r}",
                details={"available": sorted(self.actions)},
            )
        if action.capability.requires_auth and ctx.principal is None:
            raise WAPProtocolError(ErrorCode.AUTH_REQUIRED, f"capability {capability_id!r} requires authorization")
        result = await action.call(payload, ctx)
        async for chunk in iterate_result(result, default_content=f"{action.capability.name} completed."):
            yield chunk

    async def dispatch(self, ctx: ActionContext) -> AsyncIterator[Chunk]:
        """Route a verified user-agent message to a capability or the intent handler."""
        message = ctx.message
        try:
            if message.capability_id:
                async for chunk in self.run_capability(message.capability_id, message.structured_data or {}, ctx):
                    yield chunk
            else:
                result = self._intent_handler(message.content, ctx)
                async for chunk in iterate_result(result):
                    yield chunk
        except WAPProtocolError:
            raise
        except Exception as exc:
            logger.exception("capability %r failed", message.capability_id or "<intent>")
            raise WAPProtocolError(
                ErrorCode.ACTION_FAILED, f"the business agent failed to process the request: {exc}"
            ) from exc

    def reply(self, request: AgentMessage, content: str, data: dict[str, Any] | None) -> AgentMessage:
        """Build and sign the final business-agent message for ``request``."""
        message = AgentMessage(
            session_id=request.session_id,
            role=Role.BUSINESS_AGENT,
            content=content,
            capability_id=request.capability_id,
            structured_data=data,
            in_reply_to=request.message_id,
            public_key=self.public_key,
        )
        return self.signer.sign_model(message)

    # ------------------------------------------------------------------ ASGI

    def mount(self, app: FastAPI) -> FastAPI:
        """Attach discovery, interaction and challenge endpoints to a FastAPI app."""
        from .middleware import inject_routes

        inject_routes(app, self)
        return app

    def create_app(self, **fastapi_kwargs: Any) -> FastAPI:
        """Create a standalone FastAPI application serving only this agent."""
        from fastapi import FastAPI

        fastapi_kwargs.setdefault("title", f"{self.name} (WAP/1.0)")
        return self.mount(FastAPI(**fastapi_kwargs))


__all__ = [
    "ActionContext",
    "ActionResult",
    "KeywordIntentRouter",
    "RegisteredAction",
    "ReplayCache",
    "SessionState",
    "SessionStore",
    "WAPProtocolError",
    "WAPServer",
    "iterate_result",
]
