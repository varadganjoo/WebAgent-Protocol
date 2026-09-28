# Configuration reference

WebAgent Protocol is a library. You run the servers, pick the storage and decide how
strict every protection is. This page lists every setting and its default. The
defaults suit a single-process server and a cautious user agent.

- [Business side: `WAPServer`](#business-side-wapserver)
- [Rate limits](#rate-limits-ratelimitpolicy)
- [Loop protection](#loop-protection-conversationpolicy)
- [Admission tiers](#admission-tiers)
- [Proof-of-work](#proof-of-work)
- [Storage](#storage)
- [Capabilities](#capabilities)
- [Observability](#observability)
- [User side: `WAPClient`](#user-side-wapclient)
- [MCP bridge: `wap-mcp`](#mcp-bridge-wap-mcp)

## Business side: `WAPServer`

```python
from wap.server import WAPServer

wap = WAPServer(name="Golden Crust Bakery", domain="bakery.example", private_key=KEY, require_pow=True)
```

| Parameter | Default | What it does |
|---|---|---|
| `name`, `domain` | required | Display name and the domain the manifest is bound to (`host` or `host:port`). |
| `private_key` | ephemeral | Hex Ed25519 key from `wap keygen`. **Set this in production**, because an ephemeral key changes on every restart. |
| `previous_keys` | `None` | Old private keys that endorse the current key during a [rotation](deployment.md#rotating-keys). |
| `description` | `""` | Shown in the manifest. |
| `store` | `MemoryStore()` | Where limits, sessions, replay and idempotency state live. Use `RedisStore` for more than one worker or machine. |
| `require_pow` | `False` | Require proof-of-work from anonymous callers. |
| `pow_difficulty` | `4` | Leading hex zeros (≈ 65k hashes, ~30 ms in Python). Each +1 is 16× more client work. |
| `pow_ttl_seconds` | `120` | How long a challenge stays valid. |
| `pow_secret` | derived from `private_key` | HMAC secret for challenges. The default is identical on every worker that shares the key. |
| `adaptive_pow` | `None` | `AdaptivePow(...)` raises difficulty under load. |
| `rate_limit` | `RateLimitPolicy()` | Default per-agent-key limits. `False` disables them. |
| `ip_rate_limit` | same as `rate_limit` | Per-IP limits, also applied to discovery and challenges. `False` disables them. |
| `admission` | `None` | Hook that picks a tier per request (see below). |
| `conversation_policy` | `ConversationPolicy()` | Loop protection. `False` disables it. |
| `auth_handler` | `None` | `token -> principal or None` (sync or async), for `Authorization: Bearer`. |
| `trust_forwarded_for` | `False` | Use `X-Forwarded-For` for client IPs. Enable **only** behind a proxy you control. |
| `base_url` | `https://<domain>` | Public base URL if the API lives elsewhere (it must be on the domain or a subdomain). |
| `manifest_ttl_seconds` | `3600` | Manifest lifetime. It is re-signed at half-life. |
| `max_clock_skew_seconds` | `300` | Accepted clock difference, and the replay window. |
| `mcp_require_pow` | inherit | Proof-of-work on `/mcp`. Generic MCP clients cannot solve puzzles, so set `False` if they should be able to call you. |
| `session_ttl_seconds` | `3600` | Idle session expiry. |
| `session_lock_timeout` / `session_lock_wait` | `120` / `10` | Maximum time one turn may hold a session, and how long a concurrent turn waits before `session_busy`. |
| `idempotency_ttl_seconds` | `86400` | How long results are kept for idempotent retries. |
| `observer` | `None` | Callable receiving events (see [Observability](#observability)). |

`wap.mount(app, mcp=None, mcp_path="/mcp")` adds the WAP routes to a FastAPI app. It
also adds the MCP endpoint when the `mcp` package is installed (`mcp=False` turns it
off). For other ASGI frameworks, wrap the app in `WAPDiscoveryMiddleware(app, wap)` to
serve the manifest.

## Rate limits: `RateLimitPolicy`

```python
RateLimitPolicy(requests_per_minute=60, burst=10, scopes=["ip", "agent_key"])
```

Each principal gets a sliding-window counter (`requests_per_minute` over any 60 s)
and a token bucket (`burst`). Rejected requests get `429` with `Retry-After`.

| Goal | Configuration |
|---|---|
| Generous public API | `rate_limit=RateLimitPolicy(requests_per_minute=600, burst=100)` |
| Only limit by IP | `rate_limit=False, ip_rate_limit=RateLimitPolicy(...)` |
| Behind a CDN or proxy | also set `trust_forwarded_for=True` |
| No limits (internal service) | `rate_limit=False, ip_rate_limit=False` |

## Loop protection: `ConversationPolicy`

| Field | Default | Meaning |
|---|---|---|
| `max_turns` | `100` | Turns per session before `conversation_limit`. |
| `max_repeats` | `3` | Same exchange (request and answer) repeated this many times in a row → `loop_detected`. |
| `max_cycle_length` | `3` | Longest detected cycle (for example A-B-A-B ping-pong). |
| `max_identical_requests` | `5` | Same request this many times in a row, even with changing answers, counts as a stall. |
| `window_seconds` | `300` | Only exchanges this recent count. |
| `max_duration_seconds` | `None` | Optional wall-clock limit per session. |
| `max_repeats_across_sessions` | `10` | Looser limit per agent key across fresh sessions. |

Pass `conversation_policy=False` to turn it off, or override it per caller through
admission (for example, a trusted aggregator).

## Admission tiers

```python
from wap.server.admission import AdmissionDecision, AdmissionRequest


async def admission(request: AdmissionRequest) -> AdmissionDecision:
    if request.agent_key in PARTNERS:
        return AdmissionDecision(
            tier="partner",
            rate_limit=RateLimitPolicy(requests_per_minute=6000, burst=500),
            require_pow=False,
            conversation_policy=False,  # aggregator repeats calls for many users
        )
    if request.principal is not None:  # logged-in customer (bearer token)
        return AdmissionDecision(tier="customer", require_pow=False)
    if request.agent_key in BLOCKLIST:
        return AdmissionDecision(deny="blocked")
    return AdmissionDecision()  # defaults


wap = WAPServer(..., admission=admission)
```

`AdmissionRequest` carries `client_ip`, `agent_key` (verified), `principal` (from
`auth_handler`), `capability_id`, `transport` (`"wap"` or `"mcp"`) and `headers`.
`AdmissionDecision` fields are all optional:

- `tier`: a label that appears in observer events.
- `rate_limit`: a policy, or `False` for none.
- `require_pow` and `pow_difficulty`: whether proof-of-work is required, and the
  minimum difficulty.
- `conversation_policy`: a policy, or `False`.
- `deny`: if set, the request is refused and this message is returned.

## Proof-of-work

```python
from wap.server.admission import AdaptivePow

wap = WAPServer(
    ..., require_pow=True, pow_difficulty=4, adaptive_pow=AdaptivePow(threshold=300, window_seconds=10, max_extra=2)
)
```

With `AdaptivePow`, once more than `threshold` challenges are issued in a window,
difficulty rises by 1 for each doubling of load, up to `max_extra`. The level is
shared through the store.

## Storage

| Store | Use when | Install |
|---|---|---|
| `MemoryStore()` (default) | One worker process | included |
| `RedisStore.from_url("redis://host:6379/0", prefix="myapp:")` | Several workers or machines | `pip install "webagent-protocol[redis]"` |

Use `rediss://` URLs for TLS, and give each deployment its own `prefix`. You can also
implement `wap.storage.StateStore` (`get`, `set`, `add`, `delete`, `incr`, `lock`,
`rate_limit`) for another backend. Session `state` written by your actions must be
JSON-serialisable.

## Capabilities

```python
@wap.action(
    name="reserve_item",
    description="Hold pastries for 30 minutes.",
    effects="write",
    requires_auth=False,
    title="Reserve",
)
async def reserve_item(item: str, quantity: int = 1, ctx: ActionContext = None) -> Reservation: ...
```

- **`effects`** is `"read"`, `"write"` (the default) or `"financial"`. It drives
  confirmations, retries and MCP annotations. Mark genuinely side-effect-free actions
  as `"read"`.
- **Parameters** become the input JSON Schema. A parameter typed `ActionContext` is
  injected and gives access to `session_id`, `state` (persisted, JSON only),
  `history`, `principal` and `invoke()`.
- **Return types:** a Pydantic model or `dict` (becomes structured data), `str`,
  `ActionResult(content, data)`, or a generator or async generator for streaming.
- **Other registration paths:** `wap.add_capability(Capability(...), handler)`
  registers a raw JSON-Schema capability, and `wap.include_mcp(mcp_server)`
  re-publishes an existing MCP server's tools.

## Observability

```python
from wap.server.observability import LoggingObserver, MetricsObserver, combine

metrics = MetricsObserver()
wap = WAPServer(..., observer=combine(LoggingObserver(), metrics))
metrics.snapshot()  # {"counters": {...}, "latency_ms": {"reserve_item": {"p50": ..., ...}}}
```

The events are:

- `request.completed` (`capability`, `tier`, `duration_ms`)
- `request.failed` (`code`, `capability`, `tier`)
- `request.rejected` (`code`, plus `scope`, `tier` and `reason` when known)
- `request.idempotent_replay`
- `pow.issued` (`difficulty`)

Any callable works, so you can forward events to Prometheus, OpenTelemetry or
StatsD. Observer errors are logged and never affect requests.

## User side: `WAPClient`

```python
from wap import WAPClient, ConversationPolicy

client = WAPClient(agent_key=KEY, confirm=ask_user, trust_on_first_use=True)
```

| Parameter | Default | What it does |
|---|---|---|
| `agent_key` | ephemeral | Key that signs your requests. Use one per domain for privacy. |
| `confirm` | `None` | `request -> bool` (sync or async), called before actions whose effects are in `confirm_effects`. Declining raises `ConfirmationDeclined`, and nothing is sent. |
| `confirm_effects` | `{"write", "financial"}` | Which effects need confirmation. |
| `max_retries`, `retry_backoff` | `2`, `0.25` | Automatic retries on network or gateway failures. Only `read` calls and calls with an idempotency key are retried. |
| `conversation_policy` | `ConversationPolicy(max_turns=50)` | Local loop protection. `False` disables it. |
| `pinned_keys` | `{}` | `{domain: public_key}`. Endorsed rotations are followed and the pin is updated. |
| `trust_on_first_use` | `False` | Pin each domain's key the first time it is seen. |
| `dns_key_policy` / `txt_resolver` | `"off"` | `"if-present"` or `"require"` checks `_wap.<domain>` TXT records (`pip install "webagent-protocol[dns]"`). |
| `block_private_networks` / `allow_loopback` | `False` / `False` | SSRF guard. Enable it when an LLM chooses the domains. |
| `verify_dns` | `False` | Resolve the host before fetching the manifest. |
| `allow_insecure` | `False` | Allow plain HTTP to non-loopback hosts (testing only). |
| `auth_tokens` | `{}` | `{domain: bearer token}`. |
| `validate_payloads` | `True` | Check payloads against the capability's schema before sending. |
| `timeout`, `http2`, `cache_ttl`, `max_pow_attempts`, `user_agent`, `transport` | | HTTP and cache tuning. |

Per call, `invoke`, `ask` and `query` accept `idempotency_key` (generated automatically
for non-`read` capabilities), `max_effects`, `session_id`, `auth_token` and `stream`.

## MCP bridge: `wap-mcp`

Configure it with environment variables in your MCP host's config, or programmatically
with `BridgeConfig`.

| Variable | Default | What it does |
|---|---|---|
| `WAP_CONFIRM` | `write` | Ask the user before `write` and `financial` actions (`financial` asks only for money; `never` never asks). |
| `WAP_APPROVE_SITES` | off | Ask before adding a newly discovered site's tools. Sites passed on the command line count as pre-approved. |
| `WAP_ALLOWED_DOMAINS` / `WAP_BLOCKED_DOMAINS` | none | Comma-separated patterns such as `*.example.com`. |
| `WAP_ALLOW_PRIVATE_NETWORKS` | off | Private and link-local addresses are blocked by default. |
| `WAP_BLOCK_LOOPBACK` | off | Also block `localhost`, which is allowed by default for local development. |
| `WAP_SUSPICIOUS_TEXT` | `strip` | `strip` removes instruction-like site text; `warn` keeps it with a warning. |
| `WAP_MAX_DESCRIPTION_CHARS` | `1000` | Truncation length for site-written text. |
| `WAP_MAX_TURNS` | `40` | Per-site turn budget for the model. |
| `WAP_DOMAINS` | none | Sites to pre-load (same as command-line arguments). |
| `WAP_AGENT_KEY`, `WAP_PINNED_KEYS`, `WAP_AUTH_TOKENS`, `WAP_ALLOW_INSECURE`, `WAP_TIMEOUT` | | Same as the client settings. |
