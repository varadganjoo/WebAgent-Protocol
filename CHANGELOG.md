# Changelog

All notable changes to this project are documented here. The format follows
[Keep a Changelog](https://keepachangelog.com/en/1.1.0/) and the project uses
[Semantic Versioning](https://semver.org/). The *protocol* version (WAP/1.0) is
versioned separately from the Python package.

## [0.2.0] - 2026-09-28

Production readiness: everything configurable, state shareable across workers, humans in control of side
effects, and interoperable signatures. See [docs/configuration.md](docs/configuration.md) and
[docs/deployment.md](docs/deployment.md).

### Added
- `wap.storage`: pluggable `StateStore` with `MemoryStore` (default) and `RedisStore` (`[redis]` extra).
  Rate limits (an atomic Lua script), replay cache, spent proof-of-work seeds, sessions, loop guards and
  idempotency records are shared across workers and machines. Sessions are locked per turn.
- Admission hook (`AdmissionDecision`) for per-request tiers: custom limits, proof-of-work exemptions or
  minimum difficulty, loop-policy overrides, denials. `AdaptivePow` raises difficulty under load.
- Every protection can be tuned or disabled: `rate_limit=False`, `ip_rate_limit`, `conversation_policy=False`,
  plus session and idempotency TTLs.
- `Capability.effects` (`read` / `write` / `financial`, default `write`), mapped to MCP tool annotations.
- `AgentMessage.idempotency_key` with server-side de-duplication (`X-WAP-Idempotent-Replay`); the client
  adds keys automatically for non-read calls and retries transient failures safely.
- `AgentMessage.max_effects` and the `effects_not_permitted` error: free-text requests cannot trigger
  actions without confirmation.
- `WAPClient(confirm=...)` hook before side effects (`ConfirmationDeclined`).
- `wap-mcp` confirms write and financial actions with the user through MCP elicitation, on both protocol
  generations, bound to the exact call. It can require approval of new sites and enforce domain allow and
  block lists. It sanitises and labels site-written text (tool-poisoning defence) and blocks private networks
  by default.
- RFC 8785 (JCS) canonicalization; `docs/test-vectors.json` and an independent Node.js verifier.
- Key rotation (`previous_keys`, `key_endorsements`) followed automatically by pinned clients;
  trust-on-first-use pinning; optional DNS TXT key anchoring (`[dns]` extra).
- `wap.server.observability`: `LoggingObserver`, `MetricsObserver`, `combine`.
- `examples/load_test.py` (multi-process, real HTTP), property-based fuzz tests, `docs/configuration.md`,
  `docs/deployment.md`.

### Changed
- Discovery moves to `/.well-known/wap.json`. `/.well-known/agent.json` is still served and tried by
  clients, and non-WAP documents there are rejected.
- The proof-of-work HMAC secret is derived from the signing key, so all workers accept each other's
  challenges.
- The request pipeline authenticates before admission; turns (lock, idempotency, loop guard) run just
  before dispatch.
- The client no longer retries a business's `action_failed` (502); only gateway errors without a WAP body
  are treated as transient.

### Fixed
- Integers beyond ±2^53 and non-finite numbers in `structured_data` are rejected cleanly (I-JSON)
  instead of failing signature verification (found by fuzzing).

## [0.1.0] - 2026-09-28

First public release.

### Protocol (WAP/1.0)
- Signed discovery manifest at `/.well-known/agent.json` (RFC 8615) with domain and origin binding.
- Ed25519 signatures over canonical JSON for manifests, requests, replies and every response body (`X-WAP-Signature`).
- Stateless, single-use Hashcash proof-of-work with authenticated difficulty.
- Per-IP and per-agent-key rate limiting (sliding window + token bucket).
- Conversation loop protection (`loop_detected`, `conversation_limit`) and `conversation_policy` in the manifest.
- `mcp_url` manifest member and the `io.webagent/wap` MCP extension ([proposal](docs/mcp_extension.md)).

### Python package (`webagent-protocol`, import `wap`)
- `wap.server`: `WAPServer` with `@wap.action` / `@wap.intent`, schema generation from type hints,
  FastAPI mounting, SSE streaming, sessions, bearer auth.
- `/mcp` endpoint serving the same actions as standard MCP tools (streamable HTTP), with signed results,
  optional proof-of-work and session continuation in `_meta`.
- `WAPServer.include_mcp()` / `import_mcp()` to re-publish an existing MCP server over WAP.
- `wap.client`: `WAPClient` / `WAPSession` with verified discovery, key pinning, SSRF guard, JSON Schema
  validation, automatic proof-of-work, streaming and local loop protection.
- `wap-mcp` bridge: discovered sites become native `<site>__<capability>` tools in MCP hosts, announced to both
  handshake-era and 2026-07-28 clients; loops end with an instruction to report back to the user.
- `wap` CLI: `ask`, `inspect`, `verify`, `keygen`, `serve`.
- Examples: bakery business agent with multi-turn negotiation, shopper agent, benchmark script.
- Documentation: RFC-style specification, MCP extension proposal, whitepaper.

[0.2.0]: https://github.com/varadganjoo/WebAgent-Protocol/releases/tag/v0.2.0
[0.1.0]: https://github.com/varadganjoo/WebAgent-Protocol/releases/tag/v0.1.0
