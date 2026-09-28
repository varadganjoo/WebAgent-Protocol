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
from collections.abc import AsyncIterator, Callable
from contextlib import AsyncExitStack, asynccontextmanager
from dataclasses import dataclass
from typing import TYPE_CHECKING, Any, Literal, get_type_hints

from jsonschema import Draft202012Validator
from jsonschema.exceptions import SchemaError
from pydantic import BaseModel, ConfigDict, TypeAdapter, ValidationError, create_model

from ..spec.conversation import (
    ConversationGuard,
    ConversationLimitError,
    ConversationPolicy,
    reply_fingerprint,
    request_fingerprint,
)
from ..spec.crypto import Signer, endorsement_payload
from ..spec.models import (
    CHALLENGE_PATH,
    EFFECT_RANK,
    INTERACT_PATH,
    AgentManifest,
    AgentMessage,
    Capability,
    Challenge,
    ErrorCode,
    RateLimitPolicy,
    Role,
    is_local_authority,
    normalize_authority,
)
from ..spec.pow import PowEngine, PowError, PowReplayed
from ..storage.base import LockTimeout, StateStore
from ..storage.memory import MemoryStore
from ..storage.meters import RateLimitDecision
from .admission import AdaptivePow, AdmissionDecision, AdmissionHook, AdmissionRequest
from .admission import evaluate as evaluate_admission
from .rate_limiter import RateLimiter
from .state import SessionManager, SessionState

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
    """A capability plus the callable that implements it.

    Two flavours exist: *typed* actions built from a Python signature (validated
    with a generated Pydantic model and called with keyword arguments), and *raw*
    actions registered with an explicit JSON Schema (validated with
    ``jsonschema`` and called as ``func(payload, ctx)``), used e.g. to re-publish
    tools from an existing MCP server.
    """

    func: Callable[..., Any]
    capability: Capability
    input_model: type[BaseModel] | None
    context_param: str | None
    model_param: str | None

    async def call(self, payload: dict[str, Any], ctx: ActionContext) -> Any:
        if self.input_model is None:
            return await self._call_raw(payload, ctx)
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

    async def _call_raw(self, payload: dict[str, Any], ctx: ActionContext) -> Any:
        validator = Draft202012Validator(self.capability.input_schema)
        errors = sorted(validator.iter_errors(payload), key=lambda e: list(e.absolute_path))
        if errors:
            raise WAPProtocolError(
                ErrorCode.VALIDATION_ERROR,
                f"structured_data does not match the input schema of {self.capability.id!r}",
                details={
                    "errors": [
                        {"loc": list(e.absolute_path), "msg": e.message, "type": str(e.validator)} for e in errors
                    ]
                },
            )
        if inspect.iscoroutinefunction(self.func) or inspect.isasyncgenfunction(self.func):
            return self.func(payload, ctx)
        return await asyncio.to_thread(self.func, payload, ctx)


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
    effects: str = "write",
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
        effects=effects,
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


Observer = Callable[[str, dict[str, Any]], None]


class Turn:
    """One request/response exchange, from lock to persisted reply.

    Opening a turn (``await turn.open()``) takes the session lock (shared across
    workers via the store), loads the session, resolves idempotent retries and
    applies the loop guards. Then either :attr:`replay` holds a reply to return
    immediately (an idempotent retry), or the caller dispatches :attr:`ctx` and
    finishes with :meth:`complete` (success) or :meth:`fail` (error). Always call
    :meth:`close` (e.g. in ``finally``) to release the lock.
    """

    def __init__(
        self,
        server: WAPServer,
        message: AgentMessage,
        *,
        owner_key: str | None,
        principal_key: str | None,
        client_ip: str | None,
        agent_key: str | None,
        principal: Any,
        tier: str,
        conversation_policy: ConversationPolicy | Literal[False] | None = None,
    ) -> None:
        self.server = server
        # A per-request override (from the admission hook) replaces the server's loop policy.
        if conversation_policy is False:
            self.policy: ConversationPolicy | None = None
        else:
            self.policy = conversation_policy or server.conversation_policy
        self.message = message
        self.owner_key = owner_key
        self.principal_key = principal_key
        self.client_ip = client_ip
        self.agent_key = agent_key
        self.principal = principal
        self.tier = tier
        self.ctx: ActionContext | None = None
        self.replay: AgentMessage | None = None
        self.started = time.perf_counter()
        self._stack = AsyncExitStack()
        self._idempotency_key: str | None = None
        self._request_fp = request_fingerprint(message.capability_id, message.structured_data, message.content)

    async def __aenter__(self) -> Turn:
        await self.open()
        return self

    async def __aexit__(self, *exc_info: object) -> None:
        await self.close()

    def _principal_guard_key(self) -> str | None:
        return f"guard:{self.principal_key}" if self.principal_key else None

    async def open(self) -> None:
        server, message = self.server, self.message
        try:
            await self._stack.enter_async_context(server.sessions.lock(message.session_id))
        except LockTimeout as exc:
            raise WAPProtocolError(
                ErrorCode.SESSION_BUSY,
                "another request for this session is still being processed; retry shortly",
                retry_after=1.0,
            ) from exc
        try:
            session = await server.sessions.load(message.session_id, self.owner_key)
            if message.idempotency_key:
                self.replay = await self._resolve_idempotency(message.idempotency_key)
                if self.replay is not None:
                    return
            self._check_guards(session, await self._principal_guard())
            self.ctx = ActionContext(
                server=server,
                message=message,
                session=session,
                client_ip=self.client_ip,
                agent_key=self.agent_key,
                principal=self.principal,
            )
        except BaseException:
            await self.fail()
            await self.close()
            raise

    async def _resolve_idempotency(self, key: str) -> AgentMessage | None:
        scope = self.principal_key or self.owner_key or "anonymous"
        self._idempotency_key = f"idem:{scope}:{key}"
        pending = {"state": "pending", "fp": self._request_fp}
        if await self.server.store.add(self._idempotency_key, pending, ttl=self.server.sessions.lock_timeout):
            return None
        record = await self.server.store.get(self._idempotency_key) or {}
        claimed_key, self._idempotency_key = self._idempotency_key, None  # never release someone else's claim
        if record.get("fp") != self._request_fp:
            raise WAPProtocolError(
                ErrorCode.IDEMPOTENCY_CONFLICT,
                "idempotency_key was already used for a different request",
                details={"idempotency_key": key},
            )
        if record.get("state") != "done":
            raise WAPProtocolError(
                ErrorCode.IDEMPOTENCY_CONFLICT,
                "the original request with this idempotency_key is still in progress; retry shortly",
                retry_after=1.0,
                details={"idempotency_key": key},
            )
        self.server.emit("request.idempotent_replay", capability=self.message.capability_id, key=claimed_key)
        return self.server.reply(self.message, record.get("content", ""), record.get("data"))

    async def _principal_guard(self) -> ConversationGuard | None:
        policy = self.policy
        key = self._principal_guard_key()
        if policy is None or key is None:
            return None
        return ConversationGuard.from_dict(policy.across_sessions(), await self.server.store.get(key))

    def _session_guard(self, session: SessionState) -> ConversationGuard | None:
        if self.policy is None:
            return None
        if session.guard is None or session.guard.policy != self.policy:
            data = session.guard.to_dict() if session.guard is not None else None
            session.guard = ConversationGuard.from_dict(self.policy, data)
        return session.guard

    def _check_guards(self, session: SessionState, principal_guard: ConversationGuard | None) -> None:
        for guard in (self._session_guard(session), principal_guard):
            if guard is None:
                continue
            try:
                guard.check(self._request_fp)
            except ConversationLimitError as exc:
                self.server.emit("request.rejected", code=exc.reason, tier=self.tier)
                raise WAPProtocolError(ErrorCode(exc.reason), exc.message, details=exc.details) from exc

    async def complete(self, content: str, data: dict[str, Any] | None) -> AgentMessage:
        """Sign the reply and persist session, guards and idempotency record."""
        if self.ctx is None:
            raise RuntimeError("turn was not opened for dispatch")
        server = self.server
        reply = server.reply(self.message, content, data)
        session = self.ctx.session
        reply_fp = reply_fingerprint(reply.content, reply.structured_data)
        session_guard = self._session_guard(session)
        if session_guard is not None:
            session_guard.record(self._request_fp, reply_fp)
        session.history.extend([self.message, reply])
        try:
            await server.sessions.save(session)
        except TypeError as exc:
            raise WAPProtocolError(ErrorCode.INTERNAL_ERROR, str(exc)) from exc
        guard_key = self._principal_guard_key()
        principal_guard = await self._principal_guard()
        if principal_guard is not None and guard_key is not None:
            principal_guard.record(self._request_fp, reply_fp)
            await server.store.set(guard_key, principal_guard.to_dict(), ttl=principal_guard.policy.window_seconds)
        if self._idempotency_key is not None:
            await server.store.set(
                self._idempotency_key,
                {"state": "done", "fp": self._request_fp, "content": reply.content, "data": reply.structured_data},
                ttl=server.idempotency_ttl_seconds,
            )
            self._idempotency_key = None
        server.emit(
            "request.completed",
            capability=self.message.capability_id,
            tier=self.tier,
            duration_ms=round((time.perf_counter() - self.started) * 1000, 3),
        )
        return reply

    async def fail(self, error: WAPProtocolError | None = None) -> None:
        """Release an idempotency claim so the client may retry after an error."""
        if self._idempotency_key is not None:
            await self.server.store.delete(self._idempotency_key)
            self._idempotency_key = None
        if error is not None:
            self.server.emit(
                "request.failed", code=error.code.value, capability=self.message.capability_id, tier=self.tier
            )

    async def close(self) -> None:
        """Release the session lock (and any unfinished idempotency claim). Safe to call twice."""
        try:
            if self._idempotency_key is not None:
                await self.fail()
        finally:
            await self._stack.aclose()


class WAPServer:
    """A business agent: owns the signing key, capability registry and abuse controls.

    Every protection is configurable; see ``docs/configuration.md``. The defaults suit a
    single-worker server. For several workers or machines pass a shared ``store``
    (e.g. :class:`~wap.storage.RedisStore`) so limits, replay protection and sessions
    are shared.
    """

    def __init__(
        self,
        name: str,
        domain: str,
        private_key: str | None = None,
        require_pow: bool = False,
        *,
        previous_keys: list[str] | None = None,
        description: str = "",
        store: StateStore | None = None,
        pow_difficulty: int = 4,
        pow_ttl_seconds: float = 120.0,
        pow_secret: bytes | None = None,
        adaptive_pow: AdaptivePow | None = None,
        rate_limit: RateLimitPolicy | Literal[False] | None = None,
        ip_rate_limit: RateLimitPolicy | Literal[False] | None = None,
        admission: AdmissionHook | None = None,
        conversation_policy: ConversationPolicy | Literal[False] | None = None,
        base_url: str | None = None,
        manifest_ttl_seconds: float = 3600.0,
        max_clock_skew_seconds: float = 300.0,
        auth_handler: AuthHandler | None = None,
        trust_forwarded_for: bool = False,
        mcp_require_pow: bool | None = None,
        session_ttl_seconds: float = 3600.0,
        session_lock_timeout: float = 120.0,
        session_lock_wait: float = 10.0,
        idempotency_ttl_seconds: float = 86_400.0,
        observer: Observer | None = None,
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
        # Keys this domain rotated away from; each endorses the new manifest so that clients
        # which pinned an old key can follow the rotation. Remove them once clients have migrated.
        self.previous_signers = [Signer(k) for k in (previous_keys or [])]
        self.store: StateStore = store or MemoryStore()
        self.require_pow = require_pow
        # Derived from the signing key unless given, so every worker sharing the key
        # accepts every other worker's challenges without extra configuration.
        self.pow = PowEngine(
            difficulty=pow_difficulty,
            ttl_seconds=pow_ttl_seconds,
            secret=pow_secret or self.signer.derive_secret("wap-pow-v1"),
        )
        self.adaptive_pow = adaptive_pow
        # rate_limit: per-agent-key limits (False disables). ip_rate_limit: per-IP limits,
        # defaulting to the same policy (False disables).
        self.rate_limit_policy: RateLimitPolicy | None = (
            None if rate_limit is False else (rate_limit or RateLimitPolicy())
        )
        if ip_rate_limit is False:
            self.ip_rate_limit_policy: RateLimitPolicy | None = None
        else:
            self.ip_rate_limit_policy = ip_rate_limit or self.rate_limit_policy
        self.rate_limiter = RateLimiter(self.rate_limit_policy or RateLimitPolicy(), self.store)
        self.admission = admission
        scheme = "http" if is_local_authority(self.domain) else "https"
        self.base_url = (base_url or f"{scheme}://{self.domain}").rstrip("/")
        self.manifest_ttl_seconds = manifest_ttl_seconds
        self.max_clock_skew_seconds = max_clock_skew_seconds
        self.auth_handler = auth_handler
        self.trust_forwarded_for = trust_forwarded_for
        # None: the MCP endpoint inherits require_pow. False lets generic MCP clients (which cannot
        # solve challenges) call tools, relying on rate limits alone.
        self.mcp_require_pow = mcp_require_pow
        self.mcp_path: str | None = None
        self._mcp_sources: list[Any] = []
        self.actions: dict[str, RegisteredAction] = {}
        # Loop protection is on by default; pass ConversationPolicy(...) to tune it or False to disable.
        self.conversation_policy: ConversationPolicy | None = (
            None if conversation_policy is False else (conversation_policy or ConversationPolicy())
        )
        self.sessions = SessionManager(
            self.store,
            ttl_seconds=session_ttl_seconds,
            conversation_policy=self.conversation_policy,
            lock_timeout=session_lock_timeout,
            lock_wait=session_lock_wait,
        )
        self.idempotency_ttl_seconds = idempotency_ttl_seconds
        self.observer = observer
        self._intent_handler: Callable[[str, ActionContext], Any] = KeywordIntentRouter()
        self._manifest: AgentManifest | None = None

    def emit(self, event: str, **attributes: Any) -> None:
        """Report an event to the configured observer (metrics, logs, tracing). Never raises."""
        if self.observer is None:
            return
        try:
            self.observer(event, attributes)
        except Exception:  # noqa: BLE001 - observability must not break requests
            logger.exception("observer failed for event %r", event)

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
        effects: Literal["read", "write", "financial"] = "write",
    ) -> Callable[[Callable[..., Any]], Callable[..., Any]]:
        """Register a function as a capability. ``name`` becomes the capability id.

        ``effects`` tells clients what calling it does: ``"read"`` (no side effects; safe to
        retry and never needs confirmation), ``"write"`` (changes state, e.g. a booking) or
        ``"financial"`` (moves money). The default is the conservative ``"write"``.
        """

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
                effects=effects,
                localns=caller_locals,
            )
            self._manifest = None
            return func

        return decorator

    def add_capability(self, capability: Capability, handler: Callable[[dict[str, Any], ActionContext], Any]) -> None:
        """Register a capability with an explicit JSON Schema and a ``handler(payload, ctx)`` callable."""
        if capability.id in self.actions:
            raise ValueError(f"capability {capability.id!r} is already registered")
        if capability.requires_auth and self.auth_handler is None:
            raise ValueError(f"capability {capability.id!r} requires auth but WAPServer has no auth_handler")
        try:
            Draft202012Validator.check_schema(capability.input_schema)
        except SchemaError as exc:
            raise ValueError(f"capability {capability.id!r} has an invalid input_schema: {exc.message}") from exc
        self.actions[capability.id] = RegisteredAction(
            func=handler, capability=capability, input_model=None, context_param=None, model_param=None
        )
        self._manifest = None

    def include_mcp(self, source: Any, *, prefix: str = "", include: set[str] | None = None) -> None:
        """Re-publish an existing MCP server's tools as WAP capabilities when the app starts.

        ``source`` is anything ``mcp.client.client.Client`` accepts (a server object, a
        streamable-HTTP URL, or ``StdioServerParameters``). See :mod:`wap.server.mcp_import`.
        """
        from .mcp_import import MCPToolSource

        self._mcp_sources.append(MCPToolSource(source, prefix=prefix, include=include))

    async def import_mcp(self, source: Any, *, prefix: str = "", include: set[str] | None = None) -> Any:
        """Connect to an MCP server now and register its tools. Returns the live ``MCPToolSource``;
        call its ``aclose()`` when done."""
        from .mcp_import import MCPToolSource

        tool_source = MCPToolSource(source, prefix=prefix, include=include)
        await tool_source.register(self)
        return tool_source

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
            mcp_url=self.base_url + self.mcp_path if self.mcp_path else None,
            capabilities=[a.capability for a in self.actions.values()],
            pow_required=self.require_pow,
            pow_difficulty=self.pow.difficulty if self.require_pow else None,
            rate_limit_policy=self.rate_limit_policy.model_dump() if self.rate_limit_policy else {},
            conversation_policy=self.conversation_policy.as_dict() if self.conversation_policy else None,
            issued_at=now,
            expires_at=now + self.manifest_ttl_seconds,
            previous_keys=[s.public_key for s in self.previous_signers],
        )
        if self.previous_signers:
            payload = endorsement_payload(manifest)
            manifest = manifest.model_copy(
                update={"key_endorsements": {s.public_key: s.sign(payload) for s in self.previous_signers}}
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

    # ------------------------------------------------------------------ admission

    @staticmethod
    def _rate_limited(decision: RateLimitDecision) -> WAPProtocolError:
        return WAPProtocolError(
            ErrorCode.RATE_LIMITED,
            f"rate limit exceeded for {decision.scope or 'client'}",
            retry_after=round(decision.retry_after, 3),
            details={"scope": decision.scope, "limit_per_minute": decision.limit},
            headers=decision.headers(),
        )

    async def limit_ip(self, ip: str | None) -> dict[str, str]:
        """Per-IP rate limit (cheapest check, first in the pipeline). Returns response headers."""
        policy = self.ip_rate_limit_policy
        if policy is None or not ip or "ip" not in policy.scopes:
            return {}
        decision = await self.rate_limiter.check_keys([("ip", f"ip:{ip}")], policy=policy)
        if not decision.allowed:
            self.emit("request.rejected", code="rate_limited", scope="ip")
            raise self._rate_limited(decision)
        return decision.headers()

    async def check_replay(self, message: AgentMessage) -> None:
        """Freshness window and (agent key, message id) de-duplication, shared via the store."""
        now = time.time()
        if abs(now - message.timestamp) > self.max_clock_skew_seconds:
            raise WAPProtocolError(
                ErrorCode.REPLAY_DETECTED,
                f"message timestamp is outside the accepted window (±{int(self.max_clock_skew_seconds)}s)",
                details={"server_time": now},
            )
        key = f"replay:{message.public_key}:{message.message_id}"
        if not await self.store.add(key, 1, ttl=2 * self.max_clock_skew_seconds):
            raise WAPProtocolError(ErrorCode.REPLAY_DETECTED, "message_id has already been processed")

    async def issue_challenge(self) -> Challenge:
        difficulty = self.pow.difficulty
        if self.adaptive_pow is not None:
            difficulty = await self.adaptive_pow.difficulty(self.store, difficulty, record=True)
        self.emit("pow.issued", difficulty=difficulty)
        return self.pow.issue(difficulty=difficulty)

    async def verify_pow(self, seed: str | None, nonce: str | None, *, min_difficulty: int | None = None) -> None:
        """Check a proof-of-work solution and mark its seed spent in the shared store."""
        if seed is None or nonce is None:
            raise WAPProtocolError(
                ErrorCode.POW_REQUIRED,
                "this agent requires proof-of-work; solve the attached challenge and resend",
                details={"challenge": (await self.issue_challenge()).model_dump(mode="json")},
            )
        try:
            result = self.pow.check(seed, nonce, min_difficulty=min_difficulty)
            if not await self.store.add(f"pow:{seed}", 1, ttl=max(1.0, result.expires_at - time.time())):
                raise PowReplayed("challenge has already been used")
        except PowError as exc:
            self.emit("request.rejected", code="pow_invalid", reason=exc.reason)
            raise WAPProtocolError(
                ErrorCode.POW_INVALID,
                f"proof-of-work rejected: {exc}",
                details={"reason": exc.reason, "challenge": (await self.issue_challenge()).model_dump(mode="json")},
            ) from exc

    def pow_required_for(self, transport: str, decision: AdmissionDecision) -> bool:
        if decision.require_pow is not None:
            return decision.require_pow
        if transport == "mcp" and self.mcp_require_pow is not None:
            return self.mcp_require_pow
        return self.require_pow

    async def admit(
        self,
        request: AdmissionRequest,
        *,
        pow_seed: str | None = None,
        pow_nonce: str | None = None,
    ) -> tuple[AdmissionDecision, dict[str, str]]:
        """Run the admission hook, per-key rate limit and proof-of-work for a verified request."""
        decision = await evaluate_admission(self.admission, request)
        if decision.deny:
            self.emit("request.rejected", code="forbidden", tier=decision.tier)
            raise WAPProtocolError(ErrorCode.FORBIDDEN, decision.deny)
        headers: dict[str, str] = {}
        policy = self.rate_limit_policy if decision.rate_limit is None else (decision.rate_limit or None)
        if policy is not None and request.agent_key and "agent_key" in policy.scopes:
            limit = await self.rate_limiter.check_keys([("agent_key", f"key:{request.agent_key}")], policy=policy)
            if not limit.allowed:
                self.emit("request.rejected", code="rate_limited", scope="agent_key", tier=decision.tier)
                raise self._rate_limited(limit)
            headers = limit.headers()
        if self.pow_required_for(request.transport, decision):
            await self.verify_pow(pow_seed, pow_nonce, min_difficulty=decision.pow_difficulty)
        return decision, headers

    # ------------------------------------------------------------------ turns

    def open_turn(
        self,
        message: AgentMessage,
        *,
        owner_key: str | None,
        principal_key: str | None,
        client_ip: str | None = None,
        agent_key: str | None = None,
        principal: Any = None,
        tier: str = "default",
        conversation_policy: ConversationPolicy | Literal[False] | None = None,
    ) -> Turn:
        """Begin one request/response turn (session lock, idempotency, loop guard). See :class:`Turn`."""
        return Turn(
            self,
            message,
            owner_key=owner_key,
            principal_key=principal_key,
            client_ip=client_ip,
            agent_key=agent_key,
            principal=principal,
            tier=tier,
            conversation_policy=conversation_policy,
        )

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
        permitted = ctx.message.max_effects
        effects = action.capability.effects
        if permitted is not None and EFFECT_RANK[effects] > EFFECT_RANK[permitted]:
            raise WAPProtocolError(
                ErrorCode.EFFECTS_NOT_PERMITTED,
                f"{action.capability.name} has {effects!r} effects but this request only permits {permitted!r}; "
                "ask the user to confirm, then call the capability directly",
                details={"capability_id": capability_id, "effects": effects, "payload": payload},
            )
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

    def mount(self, app: FastAPI, *, mcp: bool | None = None, mcp_path: str = "/mcp") -> FastAPI:
        """Attach WAP endpoints to a FastAPI app, plus a standard MCP endpoint at ``mcp_path``.

        ``mcp=None`` (default) enables the MCP endpoint when the ``mcp`` package is installed;
        ``True`` requires it; ``False`` disables it.
        """
        from .middleware import inject_routes

        inject_routes(app, self)
        if self._mcp_sources and not getattr(app.state, "wap_mcp_sources", False):
            app.state.wap_mcp_sources = True
            original = app.router.lifespan_context
            sources = self._mcp_sources

            @asynccontextmanager
            async def lifespan(asgi_app: Any) -> AsyncIterator[Any]:
                try:
                    for source in sources:
                        await source.register(self)
                    async with original(asgi_app) as state:
                        yield state
                finally:
                    for source in sources:
                        await source.aclose()

            app.router.lifespan_context = lifespan
        if mcp is None:
            try:
                import mcp as _mcp_sdk  # noqa: F401
            except ImportError:
                mcp = False
            else:
                mcp = True
        if mcp and getattr(app.state, "wap_mcp", None) is None:
            from .mcp_endpoint import mount_mcp

            app.state.wap_mcp = mount_mcp(app, self, mcp_path)
            self.mcp_path = mcp_path
            self._manifest = None
        return app

    def create_app(self, *, mcp: bool | None = None, **fastapi_kwargs: Any) -> FastAPI:
        """Create a standalone FastAPI application serving only this agent."""
        from fastapi import FastAPI

        fastapi_kwargs.setdefault("title", f"{self.name} (WAP/1.0)")
        return self.mount(FastAPI(**fastapi_kwargs), mcp=mcp)


__all__ = [
    "ActionContext",
    "ActionResult",
    "KeywordIntentRouter",
    "Observer",
    "RegisteredAction",
    "SessionState",
    "Turn",
    "WAPProtocolError",
    "WAPServer",
    "iterate_result",
]
