# SEP: WebAgent Protocol (`io.webagent/wap`): Open-Web Discovery, Signed Results and Admission Control for MCP

| Field | Value |
|---|---|
| **Title** | WebAgent Protocol extension for MCP |
| **Extension identifier** | `io.webagent/wap` |
| **Author** | Varad Ganjoo |
| **Status** | Draft (proposal; not submitted to or endorsed by the MCP maintainers) |
| **Type** | Extensions Track |
| **Created** | 2026-09-28 |
| **Reference implementation** | [`webagent-protocol`](https://github.com/varadganjoo/WebAgent-Protocol) (Python, MIT) |

## Abstract

MCP standardizes how a model host connects to tools, but those tools must be installed ahead of time by the
user. This extension lets **any website publish MCP tools that a host can discover from nothing but a domain
name**, and it adds three properties the open web needs that installed servers don't:

1. **Discovery.** `https://<domain>/.well-known/wap.json` is a signed manifest that lists the site's tools and
   points to its MCP endpoint (`mcp_url`).
2. **Signed results.** Every successful `tools/call` result carries the business's Ed25519-signed reply in
   `_meta["io.webagent/signed_reply"]`. The signature is verifiable against the key in the manifest.
3. **Admission control and loop protection.** Servers can require a proof-of-work solution in
   `_meta["io.webagent/pow"]` before running a tool. They can also refuse to continue conversations that have
   turned into loops (`loop_detected`, `conversation_limit`).

Hosts that don't implement the extension lose nothing. The site's `/mcp` endpoint is an ordinary MCP server,
and every addition lives in `_meta` or in the declared extension settings.

## Motivation

### Tools from the open web

Users increasingly ask assistants to act on businesses they have never "installed": check a bakery's stock,
get a quote from a supplier, book a table. Today the assistant either scrapes the business's website (slow,
fragile, unauthenticated) or needs the user to find, trust, and configure a server by hand. A domain name is
the natural handle users already have, and RFC 8615 well-known URIs are the web's established way to attach
metadata to a domain.

### Why installed-server assumptions break

When a user installs an MCP server, they vouch for it. When a model reaches a tool through a URL it found
itself, three things change:

* **Authenticity.** The host needs to know that the tool results came from the business, not from a proxy, a
  CDN compromise, or a look-alike domain. TLS protects the connection, but it doesn't give the result a
  portable proof of origin that can be kept as a receipt ("the bakery quoted $4.05").
* **Economics.** A public tool endpoint backed by a paid LLM converts every request into cost for the
  business. Without admission control, anyone can drain it cheaply. We call this *token vampirism*.
* **Runaway agent-to-agent conversations.** When the user's model negotiates with the business's model,
  neither is guaranteed to converge. Two LLMs can repeat the same exchange indefinitely, burning both parties'
  budgets.

## Specification

The key words MUST, SHOULD and MAY are to be interpreted as in RFC 2119. The full wire protocol, including
canonical JSON, signature algorithms, and the proof-of-work puzzle, is specified in
[`spec_rfc.md`](spec_rfc.md). This document specifies only how it binds to MCP.

### 1. Discovery

A server implementing this extension MUST publish a WAP manifest at `/.well-known/wap.json` on its domain
(spec §5). The manifest MUST include:

* `mcp_url`: the absolute URL of the site's MCP streamable-HTTP endpoint. Its host MUST equal the manifest's
  domain or be a subdomain of it.
* `public_key`: the Ed25519 domain key.
* `capabilities[]`: one entry per MCP tool. The entry's `id` equals the tool `name`, its `input_schema` equals
  the tool `inputSchema`, and its `output_schema` equals the tool `outputSchema`.

The manifest is itself signed. Clients MUST verify the manifest's signature, domain binding, and origin
binding (spec §5.4) before connecting to `mcp_url`.

### 2. Capability declaration

At initialization the server MUST declare the extension under `ServerCapabilities.extensions` (SEP-2133):

```json
{
  "capabilities": {
    "tools": {"listChanged": false},
    "extensions": {
      "io.webagent/wap": {
        "wap_version": "1.0",
        "manifest_url": "https://bakery.example/.well-known/wap.json",
        "public_key": "8c2fcce1…",
        "pow_required": false,
        "signed_results": true,
        "conversation_policy": {"max_turns": 100, "max_repeats": 3, "max_cycle_length": 3,
                                "window_seconds": 300, "max_identical_requests": 5,
                                "max_repeats_across_sessions": 10}
      }
    }
  }
}
```

A client MUST NOT trust `public_key` from this declaration alone. It MUST take the key from the verified
manifest. The declaration exists so that clients can detect support without an extra request.

### 3. Signed tool results

For every successful `tools/call`, the server MUST include in the result's `_meta`:

| Key | Value |
|---|---|
| `io.webagent/signed_reply` | A WAP `AgentMessage` (spec §7.1) with `role: "business_agent"`, `capability_id` equal to the tool name, `structured_data` equal to the result's `structuredContent`, and `content` equal to the primary text, signed with the domain key. |
| `io.webagent/session_id` | The session the call ran in (§5). |
| `io.webagent/manifest_url` | The manifest URL, so a receipt can be re-verified later. |

A client that implements the extension SHOULD verify `signed_reply` against the manifest key. It SHOULD also
check that the signed `structured_data` equals `structuredContent` before presenting the result as coming
from the business. On failure it MUST treat the result as unverified.

### 4. Admission control (proof-of-work)

A server MAY require proof-of-work for `tools/call`. It advertises this through `pow_required` in the
extension settings.

* When the solution is missing, the server returns a tool result with `isError: true` and
  `_meta["io.webagent/error"].code = "pow_required"`, together with a fresh challenge in
  `_meta["io.webagent/challenge"]` (spec §6.2).
* The client solves the challenge and retries with
  `_meta: {"io.webagent/pow": {"seed": "…", "nonce": "…"}}` in the `tools/call` params.
* Each seed is single-use. Invalid, expired, or replayed solutions return `pow_invalid` with a new challenge.

Hosts that cannot solve challenges will see an explanatory tool error. Servers that want generic MCP clients
to be able to call their tools SHOULD set `pow_required: false` on the MCP endpoint and rely on rate limits
and loop protection. They can keep proof-of-work on the WAP endpoint, as the reference bakery example does.

### 5. Sessions

Stateless streamable-HTTP transports give servers no conversation identity. A client continues a multi-turn
interaction, such as a price negotiation, by echoing `_meta["io.webagent/session_id"]` from a previous
result in the next `tools/call`. The server MUST bind any state or artefact it creates in a session (for
example a price quote) to that session.

### 6. Loop protection

Servers and clients implementing the extension SHOULD run a *conversation guard* (spec §12.2 and
`wap/spec/conversation.py`) over each session. The guard fingerprints each exchange (request plus reply).
Fingerprints ignore message ids, timestamps, signatures, and cosmetic text differences such as case,
whitespace, and punctuation. The guard refuses a request when any of the following holds:

* the same exchange occurred `max_repeats` times in a row;
* a cycle of up to `max_cycle_length` exchanges repeated `max_repeats` times;
* the same request was sent `max_identical_requests` times in a row, even though the answers changed
  (a stall where only counters change);
* the session exhausted `max_turns`.

The server refuses **before running the tool** and returns `isError: true` with
`_meta["io.webagent/error"].code` set to `loop_detected` or `conversation_limit`. A client-side guard SHOULD
stop the host's model earlier and return an instruction to report back to the user instead of retrying.

### 7. Effects, confirmation and idempotency

Each tool's WAP `effects` (`read`, `write`, `financial`; spec §7.7) is exposed in
`_meta["io.webagent/effects"]` and mapped to MCP annotations: `readOnlyHint` for
`read`, `destructiveHint` for `financial`, `idempotentHint` for `read`. Hosts
SHOULD obtain the user's confirmation before calling a `write` or `financial` tool.
A client MAY send `_meta["io.webagent/idempotency_key"]`; a retry with the same key
and arguments returns the original result with `_meta["io.webagent/idempotent_replay"]`
set, and the tool does not run again.

### 8. Host behaviour for discovered sites (informative)

The reference bridge (`wap-mcp`) shows the intended user experience:

1. The model calls `wap_discover("bakery.example")`.
2. The bridge verifies the manifest, registers each capability as a native tool named
   `<site>__<capability>` with the site's own schema, and announces the change. Handshake-era clients receive
   `notifications/tools/list_changed`. Clients on the 2026-07-28 protocol receive a `ToolsListChanged` event
   on their `subscriptions/listen` stream.
3. The model calls `bakery_example__reserve_item` like any other tool. Because the tool has `write`
   effects, the bridge first asks the user through MCP elicitation (a form request on handshake-era
   hosts, an `input_required` round trip on 2026-07-28 hosts), binding the approval to the exact tool
   name and arguments. Hosts that cannot show prompts are refused with an explanation.
4. Free-text requests (`wap_ask`) are sent with `max_effects: "read"`. If the business wants to act,
   it answers `effects_not_permitted` naming the capability and arguments, and the bridge tells the
   model which tool to call so the user can confirm.
5. Site-written text (names, descriptions, schema annotations) is sanitised before it reaches the
   model: invisible and bidirectional-override characters are removed, text is truncated, and
   instruction-like passages are stripped or flagged. Every description is labelled with its origin
   and verified key. Operators can restrict reachable domains and require approval of new sites.

The bridge handles signatures, proof-of-work, sessions, idempotency keys and loop protection.

## Rationale

* **Why a well-known manifest instead of only `/mcp`?** An MCP endpoint answers "what tools do you have?" only
  after a connection is established. A signed, cacheable document lets crawlers, registries, and security
  tools reason about a site's agent without opening sessions. It also gives the key a home that is
  independent of the transport.
* **Why sign results when TLS already exists?** TLS authenticates a connection, not a statement. A signed
  result can be stored, forwarded to another agent, or shown in a dispute, and it survives TLS-terminating
  intermediaries.
* **Why proof-of-work rather than API keys?** Keys require registration, which defeats open discovery. Proof
  of work is permissionless, costs an honest client milliseconds (difficulty 4 ≈ 32 ms in Python), and costs
  the server microseconds to verify. It is a floor, not a wall, and composes with authentication for
  sensitive tools.
* **Why `_meta` and extension settings rather than new methods?** Everything stays backwards compatible. A
  plain MCP client sees a normal server with normal tools.

## Backward Compatibility

The extension adds no required methods and changes no existing semantics:

* Clients unaware of it ignore `_meta` keys and the extension declaration.
* Servers unaware of it simply don't publish a manifest.
* The `/mcp` endpoint of a WAP server passes the official MCP Python SDK client end to end (initialization,
  `tools/list`, `tools/call`) over streamable HTTP.

## Security Implications

* **Trust on first use.** The manifest is only as trustworthy as HTTPS on first contact. Clients SHOULD
  support key pinning and SHOULD alert on key changes.
* **SSRF.** When a model chooses the domain, hosts SHOULD refuse private and loopback destinations. The
  reference bridge does this with `WAP_BLOCK_PRIVATE_NETWORKS=1`.
* **Prompt injection.** A signature proves who said something, not that it is safe. Tool results remain
  untrusted data.
* **DNS rebinding.** The reference `/mcp` endpoint enables the MCP SDK's host and origin validation, bound to
  the manifest domain.
* **Denial of wallet.** Proof-of-work, per-IP and per-key rate limits, and loop guards all run before any tool
  code.

## Reference Implementation

[`webagent-protocol`](https://github.com/varadganjoo/WebAgent-Protocol), MIT licensed:

| Component | Module |
|---|---|
| Serve `@wap.action` functions as WAP **and** MCP (`/mcp`) | `wap/server/mcp_endpoint.py` |
| Re-publish an existing MCP server over WAP | `wap/server/mcp_import.py` (`WAPServer.include_mcp`) |
| Host bridge with dynamic per-site tools | `wap/mcp/bridge.py` (`wap-mcp`) |
| Conversation guard | `wap/spec/conversation.py` |
| Tests (official MCP client over streamable HTTP, stdio, in-memory) | `tests/test_mcp_extension.py`, `tests/test_conversation_guard.py` |

## Open Questions

1. Should the manifest be merged with any future MCP server-metadata document at a well-known location, with
   WAP fields becoming an extension block?
2. Should signed results use a detached JWS so that verifiers can use off-the-shelf libraries?
3. Should loop-protection error codes become standard MCP tool-error annotations?
