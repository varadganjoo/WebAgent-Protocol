# Changelog

All notable changes to this project are documented here. The format follows
[Keep a Changelog](https://keepachangelog.com/en/1.1.0/) and the project uses
[Semantic Versioning](https://semver.org/). The *protocol* version (WAP/1.0) is
versioned separately from the Python package.

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

[0.1.0]: https://github.com/varadganjoo/WebAgent-Protocol/releases/tag/v0.1.0
