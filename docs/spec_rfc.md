```
WebAgent Protocol Working Group                              WAP Authors
Internet-Draft style specification                        September 2026
Intended status: Experimental
Updates: RFC 8615 (well-known URI usage only)


              WebAgent Protocol (WAP) Version 1.0:
     Well-Known Discovery and Signed Negotiation Between AI Agents
                        draft-wap-protocol-1.0
```

## Status of This Memo

This document specifies an experimental protocol for the Internet community. It is
published in the style of an IETF Internet-Draft for precision and reviewability; it
has **not** been submitted to or adopted by the IETF, and it confers no IETF status.
Discussion and errata are handled in the project repository. Distribution of this
memo is unlimited.

## Abstract

The WebAgent Protocol (WAP) lets an autonomous software agent acting for a user
(a *user agent*) discover the machine-executable capabilities that a website's own
agent (a *business agent*) offers, and invoke them over HTTP with schema-validated
inputs, streamed outputs and end-to-end message signatures. Discovery uses a
Well-Known URI (RFC 8615) at `/.well-known/agent.json`. Domain authenticity is
provided by Ed25519 signatures (RFC 8032) over a canonical JSON encoding. Business
agents protect costly back-ends (inventory systems, large language models) with a
stateless Hashcash-style proof-of-work gate and per-principal rate limits.

## Table of Contents

1. Introduction
2. Conventions and Terminology
3. Protocol Overview
4. Canonical JSON and Signatures
5. Discovery: The Agent Manifest
6. Proof-of-Work Challenges
7. Interaction
8. Streaming (Server-Sent Events)
9. Errors
10. HTTP Header Fields
11. State Machines
12. Rate Limiting
13. Security Considerations
14. Privacy Considerations
15. IANA Considerations
16. References
Appendix A. JSON Schemas (informative)
Appendix B. Example Exchange
Appendix C. Conformance Checklist

---

## 1. Introduction

AI agents that act on behalf of people increasingly need to *do* things on websites:
check stock, compare quotes, place holds. Today they do this by rendering and scraping
pages designed for human eyes. That approach is fragile (layouts change), expensive
(pages are mostly markup), ambiguous (prices and availability must be inferred), and
unauthenticated (nothing proves the numbers came from the business).

WAP gives a site a small, explicit contract instead:

* a signed **manifest** that says who the business agent is, which **capabilities**
  it offers and what JSON each capability accepts and returns;
* one **interaction endpoint** that accepts signed messages and answers with signed
  messages, optionally streamed as Server-Sent Events;
* optional **proof-of-work** and **rate limits** so that answering agents cannot be
  used to drain the business's compute or LLM budget.

WAP deliberately reuses existing building blocks (HTTP, JSON Schema, Ed25519, SSE)
and is small enough to implement in an afternoon in any language.

### 1.1. Goals

1. Zero-configuration discovery from a bare domain name.
2. Verifiable binding between a domain and the key that signs its agent's replies.
3. Machine-checkable input contracts so that malformed calls fail before reaching
   the business back-end.
4. Economic asymmetry: rejecting abusive traffic MUST be cheaper for the server than
   generating it is for the client.
5. Streaming-first replies suitable for token-by-token LLM output.

### 1.2. Non-Goals

* Payment settlement, identity federation and end-user consent flows. These MAY be
  layered on top as capabilities.
* Replacing TLS. WAP signatures complement, not substitute, transport security.
* Agent-to-agent routing across more than two parties.

## 2. Conventions and Terminology

The key words "MUST", "MUST NOT", "REQUIRED", "SHALL", "SHALL NOT", "SHOULD",
"SHOULD NOT", "RECOMMENDED", "NOT RECOMMENDED", "MAY", and "OPTIONAL" in this
document are to be interpreted as described in BCP 14 [RFC2119] [RFC8174] when, and
only when, they appear in all capitals, as shown here.

**Business agent**
: The server-side agent operated by (or for) the owner of a domain.

**User agent**
: The client-side agent acting for an end user. (Not to be confused with the HTTP
  `User-Agent` header.)

**Authority**
: A host name or IPv4 literal, optionally followed by `:port`, as in RFC 3986
  Section 3.2 without userinfo. Host names are compared case-insensitively after
  removing a trailing root dot.

**Loopback authority**
: An authority whose host is `localhost`, ends in `.localhost`, or is in
  `127.0.0.0/8`.

**Capability**
: A named, schema-described operation offered by a business agent.

**Agent key**
: An Ed25519 key pair held by a user agent and used to sign its requests. It MAY be
  ephemeral.

**Domain key**
: The Ed25519 key pair whose public half is published in a manifest and which signs
  the manifest and all business-agent messages.

All JSON in this document is I-JSON [RFC7493]. Hexadecimal strings are lower-case.

## 3. Protocol Overview

```
 User agent                                            Business agent (bakery.example)
     |                                                          |
     | GET https://bakery.example/.well-known/agent.json        |
     |--------------------------------------------------------->|
     |            200 AgentManifest (signed) + X-WAP-Signature  |
     |<---------------------------------------------------------|
     | verify signature, domain binding, expiry, pins           |
     |                                                          |
     | [if pow_required] GET /wap/v1/challenge                  |
     |--------------------------------------------------------->|
     |                   200 {"seed": "...", "difficulty": 4}   |
     |<---------------------------------------------------------|
     | find nonce: SHA-256(seed || nonce) has 4 leading "0"s    |
     |                                                          |
     | POST /wap/v1/interact   Accept: text/event-stream        |
     | AgentMessage{role=user_agent, pow_*, public_key, sig}    |
     |--------------------------------------------------------->|
     |       rate limit → version → schema → signature →        |
     |       freshness/replay → agent-key limit → PoW → auth    |
     |                    → dispatch to capability              |
     |      event: meta / token* / data* / message (signed)     |
     |<---------------------------------------------------------|
```

## 4. Canonical JSON and Signatures

### 4.1. Canonical Form

The canonical form of a JSON value *v* is the UTF-8 encoding of *v* serialized with:

1. object members sorted by key, comparing keys by Unicode code point;
2. no insignificant whitespace (separators `,` and `:` only);
3. non-ASCII characters emitted literally (not `\u`-escaped), with only the escapes
   required by RFC 8259 Section 7;
4. numbers in their shortest round-trip representation; a number with an integral
   value MUST be serialized without a fraction or exponent (`1.0` → `1`);
5. `NaN` and infinities are forbidden.

This matches the output of ECMAScript `JSON.stringify` on a key-sorted value and of
Python `json.dumps(v, sort_keys=True, separators=(",", ":"), ensure_ascii=False)`
after integral floats are converted to integers. It is intentionally simpler than
JCS [RFC8785], with which it coincides for all documents defined in this
specification that avoid exponents.

### 4.2. Signing Documents

To sign a JSON object *d* that has a `signature` member (an `AgentManifest` or an
`AgentMessage`):

1. Remove the `signature` member, yielding *d'*.
2. Compute *b* = canonical form of *d'*.
3. Compute *s* = Ed25519-Sign(private_key, *b*) [RFC8032], Section 5.1.6 (pure
   Ed25519, no context, no pre-hash).
4. Set `signature` to the 128-character lower-case hex encoding of *s*.

Verification reverses the process with the public key named by the verifier's policy
(Section 5.4 for manifests, Section 7.2 for messages). An empty or missing
`signature` MUST be treated as invalid.

### 4.3. Response Body Signatures

In addition, every JSON response produced by a WAP endpoint (manifest, challenge,
interaction replies **and** error objects) carries an `X-WAP-Signature` header: the
hex Ed25519 signature, by the domain key, over the exact response body bytes. When
the header is present a client MUST verify it and MUST treat a mismatch as a
verification failure. Servers SHOULD emit JSON bodies in canonical form so that the
body signature and the embedded signature cover identical bytes.

### 4.4. Key Encoding

Public and private keys are the raw 32-byte Ed25519 encodings of RFC 8032, hex
encoded (64 characters). Implementations MAY display a *fingerprint*, defined as
`"SHA256:"` followed by the first 32 hex characters of SHA-256(raw public key).

## 5. Discovery: The Agent Manifest

### 5.1. Location

A business agent for authority *A* MUST serve its manifest at

```
https://A/.well-known/agent.json
```

in response to `GET` and `HEAD`, with media type `application/json`. Plain `http`
MAY be used only for loopback authorities, or when both parties have explicitly
opted in for testing. The response SHOULD include
`Access-Control-Allow-Origin: *` and a `Cache-Control` header with a `max-age` no
greater than the time remaining until `expires_at`.

### 5.2. Manifest Members

| Member | Type | Req. | Description |
|---|---|---|---|
| `wap_version` | string | yes | MUST be `"1.0"`. |
| `domain` | string | yes | Authority this manifest is bound to. |
| `name` | string (1–256) | yes | Display name of the business agent. |
| `description` | string (≤ 8192) | no | Free-text description. |
| `public_key` | string (64 hex) | yes | Domain key. |
| `interaction_url` | absolute URL | yes | Endpoint for Section 7. |
| `challenge_url` | absolute URL | cond. | Required when `pow_required` is true. |
| `capabilities` | array of Capability | yes | May be empty. IDs MUST be unique. |
| `pow_required` | boolean | yes | Whether requests need proof-of-work. |
| `pow_difficulty` | integer 1–16 | cond. | Required when `pow_required` is true. Advisory. |
| `rate_limit_policy` | object | yes | Section 12. |
| `issued_at` | number (Unix s) | yes | Signing time. |
| `expires_at` | number (Unix s) \| null | no | After this instant the manifest is invalid. |
| `signature` | string (128 hex) | yes | Section 4.2, by `public_key`. |

Unknown members MUST cause validation failure in version 1.0 (closed-world). Future
minor versions will relax this through `wap_version` negotiation.

### 5.3. Capability Members

| Member | Type | Req. | Description |
|---|---|---|---|
| `id` | string matching `^[a-z][a-z0-9_.-]{0,63}$` | yes | Stable identifier. |
| `name` | string (1–128) | yes | Human-readable label. |
| `description` | string (≤ 4096) | no | Natural-language description for LLM planners. |
| `input_schema` | JSON Schema (2020-12) | yes | MUST describe an object. Validates `structured_data`. |
| `output_schema` | JSON Schema \| null | no | Describes reply `structured_data`. |
| `requires_auth` | boolean | yes | Whether a bearer token (Section 7.5) is needed. |
| `streaming` | boolean | yes | Whether the capability natively produces incremental tokens. |

### 5.4. Resolution and Verification Algorithm

Given a target string *T* (a bare authority, an authority followed by a path, or an
absolute `http(s)` URL), a client:

1. Derives the authority *A* and scheme. The default scheme is `https`; `http` is
   used by default only for loopback authorities. A client MUST refuse `http` for a
   non-loopback authority unless insecure mode was explicitly enabled.
2. SHOULD, when acting on inputs chosen by a language model or other untrusted
   source, resolve the host and refuse private, loopback, link-local, multicast or
   reserved addresses (Section 13.6).
3. Issues `GET {scheme}://A/.well-known/agent.json` and MUST NOT follow redirects.
   A 3xx response is a discovery failure.
4. Rejects bodies larger than 1 MiB.
5. On a 404 or connection failure for a non-loopback, non-IP, non-`www.` authority,
   MAY retry once at `www.A`; in that case the manifest's `domain` MUST equal
   `www.A`.
6. Parses and validates the manifest per Sections 5.2–5.3.
7. Verifies:
   a. `wap_version` is supported;
   b. `domain` equals the authority actually fetched (**domain binding**);
   c. the embedded signature verifies under `public_key`;
   d. `expires_at`, if present, is in the future;
   e. the host of `interaction_url` and of `challenge_url` equals the host of
      `domain` or is a subdomain of it (**origin binding**), and neither uses `http`
      unless the authority is loopback or insecure mode is enabled;
   f. if the client has a pinned key for `domain`, `public_key` equals it;
   g. if `X-WAP-Signature` is present, it verifies over the raw body.
8. Caches the manifest until the earlier of `expires_at` and a local maximum TTL.
   Concurrent resolutions of the same authority SHOULD be coalesced.

Any failure in step 6–7 MUST abort the interaction with a verification error.

## 6. Proof-of-Work Challenges

### 6.1. Puzzle

A challenge is a pair (*seed*, *difficulty*). A *solution* is a string *nonce* of 1
to 128 characters such that

```
hex( SHA-256( UTF-8(seed) || UTF-8(nonce) ) )
```

begins with *difficulty* ASCII `"0"` characters. The expected number of hash
evaluations for a client is 16^difficulty; verification costs one.

### 6.2. Challenge Object

`GET challenge_url` returns (with `Cache-Control: no-store`):

```json
{
  "algorithm": "sha256-leading-zero-hex",
  "seed": "<hex, 16–256 chars>",
  "difficulty": 4,
  "issued_at": 1790560000.12,
  "expires_at": 1790560120.12
}
```

A server without proof-of-work SHOULD answer this endpoint with `invalid_request`.

### 6.3. Stateless Issuance (RECOMMENDED construction)

Servers SHOULD make challenges self-authenticating so that issuance allocates no
state. The reference construction is:

```
salt   = 16 random bytes
expiry = IEEE-754 binary64 big-endian encoding of expires_at
tag    = HMAC-SHA-256(server_secret, salt || expiry || byte(difficulty))[0..16]
seed   = hex(salt || expiry || tag)                      ; 80 hex characters
```

On verification the server recomputes the tag for each permitted difficulty,
recovers the difficulty the seed was minted for (so a client cannot downgrade it),
checks expiry, checks the solution, and finally records the seed as *spent* until
its expiry. The spent set is the only state, and it is bounded by the issuance rate
times the TTL.

### 6.4. Using a Solution

The client places the seed and nonce in the `pow_seed` and `pow_nonce` members of its
`AgentMessage` (Section 7.1). Both MUST be present or both absent. Each seed MUST be
accepted at most once. Because the message is signed, a solution cannot be moved to
a different request by an on-path attacker without invalidating the signature.

If a request lacks a required solution, the server returns `pow_required` (428); if
the solution is wrong, expired, forged or replayed it returns `pow_invalid` (403).
In both cases the error `details` SHOULD contain a fresh `challenge` object so the
client can retry without an extra round trip. Clients SHOULD bound retries (the
reference client makes at most 3 attempts).

## 7. Interaction

### 7.1. The AgentMessage

| Member | Type | Req. | Description |
|---|---|---|---|
| `wap_version` | `"1.0"` | yes | |
| `message_id` | string (8–128) | yes | Unique per sender key. |
| `session_id` | string (1–128) | yes | Chosen by the user agent; groups turns. |
| `role` | `"user_agent"` \| `"business_agent"` | yes | |
| `content` | string (≤ 65536) | yes | Natural-language text; may be empty. |
| `capability_id` | string \| null | no | Target capability. Null means free-text intent. |
| `structured_data` | object \| null | no | Capability input (requests) or output (replies). |
| `in_reply_to` | string \| null | reply | `message_id` of the request being answered. |
| `timestamp` | number (Unix s) | yes | Sender's clock. |
| `pow_seed` | string \| null | cond. | Section 6.4. |
| `pow_nonce` | string \| null | cond. | Section 6.4. |
| `public_key` | string (64 hex) \| null | cond. | Signer key. REQUIRED for user-agent messages. |
| `signature` | string (128 hex) | yes | Section 4.2. |

### 7.2. Request Processing Pipeline

The server receives `POST interaction_url` with an `application/json` body of at most
256 KiB containing one `AgentMessage`. It MUST perform the following steps **in
order** and MUST NOT invoke capability logic before step 9:

1. **IP rate limit** (Section 12). Failure: `rate_limited`.
2. **Version.** If `X-WAP-Version` is present and its major version is not 1:
   `unsupported_version`.
3. **Envelope.** Parse and validate the `AgentMessage`: `invalid_request`.
   `role` MUST be `user_agent`.
4. **Signature.** `public_key` MUST be present and the signature MUST verify under
   it: `invalid_signature`.
5. **Freshness and replay.** `|now − timestamp|` MUST NOT exceed the server's skew
   window (RECOMMENDED 300 s), and (`public_key`, `message_id`) MUST NOT have been
   seen within twice that window: `replay_detected`.
6. **Agent-key rate limit.** Charged only after step 4 so an attacker cannot exhaust
   another agent's budget by claiming its key.
7. **Proof-of-work**, if enabled (Section 6.4).
8. **Authorization.** If an `Authorization: Bearer <token>` header is present it is
   validated; an invalid token yields `auth_required`. Capabilities with
   `requires_auth: true` require a valid token.
9. **Session binding and dispatch.** A session is bound to the `public_key` that
   created it; a message for an existing `session_id` signed by a different key
   yields `forbidden`. If `capability_id` is set, `structured_data` (or `{}`) MUST
   validate against the capability's `input_schema` (`validation_error`), and an
   undeclared capability yields `unknown_capability`. Otherwise the server's intent
   handler (e.g. an LLM router) processes `content`.

Checks are ordered from cheapest to most expensive; the proof-of-work seed is
consumed only once the request is otherwise known to be well-formed and
authentically signed.

### 7.3. Replies

The reply is a business-agent `AgentMessage` with `role: "business_agent"`,
`in_reply_to` set to the request's `message_id`, the same `session_id` and
`capability_id`, `public_key` set to the domain key, and signed with the domain key.
A client MUST verify, before using any reply content, that:

1. the signature verifies under the **manifest's** `public_key` (not merely under
   the `public_key` member of the reply);
2. `role` is `business_agent`;
3. `in_reply_to` and `session_id` match the request.

If the request carried `Accept: text/event-stream`, the reply is streamed per
Section 8. Otherwise it is returned as a single JSON body with status 200.

### 7.4. Sessions

Sessions let a business agent keep negotiation state (quotes, counter-offers, carts)
across turns. They are identified by the client-chosen `session_id` and bound to the
first agent key that used them. Servers SHOULD expire idle sessions (RECOMMENDED one
hour) and bound their number. Any server-side artefact created in a session (for
example a price quote) SHOULD only be redeemable within the same session.

### 7.5. Authorization

Capabilities with `requires_auth: true` require an `Authorization: Bearer` token
issued out of band (API key, OAuth 2.0 access token, etc.). Token semantics are
defined by the business. Tokens MUST NOT be included in signed message bodies.

## 8. Streaming (Server-Sent Events)

When the request's `Accept` header includes `text/event-stream` and steps 1–9 of
Section 7.2 succeed, the server responds `200` with `Content-Type:
text/event-stream` [HTML Living Standard, §9.2]. Validation errors detected before
the first output (unknown capability, schema violation, authorization) MUST instead
be returned as ordinary HTTP error responses (Section 9).

Each SSE event has an `event` name and a single-line JSON `data` field:

| Event | Data | Cardinality |
|---|---|---|
| `meta` | `{"session_id", "in_reply_to", "capability_id", "wap_version"}` | exactly 1, first |
| `token` | `{"text": "<fragment>"}` | 0..n |
| `data` | an object to be shallow-merged into the reply's `structured_data` | 0..n |
| `message` | the complete signed reply `AgentMessage` | exactly 1, last, on success |
| `error` | an error object (Section 9) | at most 1, last, on failure |

The concatenation of all `token` texts MUST equal the final message's `content`, and
the shallow merge of all `data` objects MUST equal its `structured_data`. Clients
MUST treat `token` and `data` events as *provisional*: only the signed `message`
event is authoritative. A stream that ends without `message` or `error` is a
protocol error. Servers SHOULD send SSE comment keep-alives at least every 15 s.

## 9. Errors

Errors use the HTTP status below and a JSON body:

```json
{"error": {"code": "pow_required", "message": "human readable",
           "retry_after": 1.5, "details": {"challenge": { ... }}}}
```

`retry_after` and `details` are optional. Error bodies are signed with
`X-WAP-Signature` like any other response.

| Code | HTTP | Meaning |
|---|---|---|
| `invalid_request` | 400 | Malformed body, wrong role, body too large, feature not enabled. |
| `unsupported_version` | 400 | `X-WAP-Version` major version not supported; `details.supported` lists versions. |
| `invalid_signature` | 401 | Missing `public_key` or bad signature. |
| `auth_required` | 401 | Missing or rejected bearer token. |
| `forbidden` | 403 | Session owned by a different agent key, or business policy refusal. |
| `pow_invalid` | 403 | Wrong, expired, forged or replayed solution; `details.reason` ∈ {`malformed`, `forged`, `expired`, `replayed`, `insufficient_work`}. |
| `unknown_capability` | 404 | `details.available` lists capability IDs. |
| `replay_detected` | 409 | Duplicate `message_id` or timestamp outside the window. |
| `validation_error` | 422 | `structured_data` violates `input_schema`, or a business rule rejected the values; `details.errors`. |
| `pow_required` | 428 | Proof-of-work needed; `details.challenge` holds a challenge. |
| `rate_limited` | 429 | `Retry-After` header and `retry_after` member give seconds to wait. |
| `internal_error` | 500 | Unexpected server failure. |
| `action_failed` | 502 | The capability's back-end failed. |

Clients MUST ignore unknown members of `details` and SHOULD treat unknown codes by
their HTTP status class.

## 10. HTTP Header Fields

| Header | Direction | Definition |
|---|---|---|
| `X-WAP-Version` | both | Protocol version, `major.minor`. Requests SHOULD send it; servers MUST send `1.0` on all WAP responses. |
| `X-WAP-Signature` | response | Hex Ed25519 signature by the domain key over the exact response body (Section 4.3). |
| `Authorization` | request | `Bearer <token>` for `requires_auth` capabilities. |
| `Accept` | request | `text/event-stream` selects streaming; otherwise JSON. |
| `Retry-After` | response | Integer seconds (RFC 9110 §10.2.3) on 429. |
| `X-RateLimit-Limit` | response | Requests per minute permitted for the principal. |
| `X-RateLimit-Remaining` | response | Estimated remaining requests in the current window. |
| `Cache-Control`, `ETag` | response | On the manifest, per Section 5.1. |

Header names are case-insensitive. The `X-` prefix is retained for compatibility
with deployed intermediaries despite RFC 6648; a future version may register
un-prefixed names.

## 11. State Machines

### 11.1. User Agent (per turn)

```
               resolve()                  verified & !pow_required
  [IDLE] ─────────────────▶ [DISCOVERING] ─────────────────────────▶ [READY]
                                 │  verification failure                │  ▲
                                 ▼                                      │  │ pow_required / pow_invalid
                             [FAILED]                  pow_required     │  │ with details.challenge
                                                   ┌────────────────────┘  │ (attempts < max)
                                                   ▼                       │
                              GET challenge   [CHALLENGED] ──solve──▶ [SOLVED]
                                                                          │
                                   sign & POST                            ▼
  [READY] / [SOLVED] ─────────────────────────────────────────────▶ [SENDING]
                                                                          │
               HTTP error ◀───────────────────────────────────────────────┤
                  │                                          200 SSE/JSON  ▼
                  ▼                    meta/token/data             [STREAMING]
              [FAILED]  ◀── error event / bad signature ──────────────────┤
                                                   verified message event  ▼
                                                                    [COMPLETE]
```

### 11.2. Business Agent Session

```
            first valid message                  message from owner key
  (none) ──────────────────────▶ [ACTIVE] ◀────────────────────────────┐
                                    │  │                                │
                                    │  └────────────────────────────────┘
                 idle > TTL or      │         message from other key
                 LRU eviction       │  ────────────────────────▶ 403 forbidden
                                    ▼                              (state unchanged)
                                [EXPIRED] ── next message ──▶ new [ACTIVE] (fresh state)
```

### 11.3. Proof-of-Work Seed

```
  issue ──▶ [OUTSTANDING] ── valid solution ──▶ [SPENT] ── expires_at ──▶ (forgotten)
                 │                                  │
                 └── expires_at ──▶ [EXPIRED]       └── reuse ──▶ 403 pow_invalid(replayed)
```

## 12. Rate Limiting

`rate_limit_policy` advertises the limits the server enforces:

```json
{"requests_per_minute": 60, "burst": 10, "scopes": ["ip", "agent_key"]}
```

For each scope in `scopes`, the server keeps an independent meter per principal (the
client IP address, or the verified agent public key). A request is admitted only if
every applicable meter admits it, and meters are charged only on admission. The
RECOMMENDED meter combines:

* a **sliding-window counter** bounding sustained throughput to
  `requests_per_minute` over any 60-second window (weighted two-window
  approximation), and
* a **token bucket** of capacity `burst` refilled at `requests_per_minute / 60`
  tokens per second, bounding bursts.

The discovery and challenge endpoints are subject to the IP scope. Servers behind
proxies MUST only honour `X-Forwarded-For` when configured to trust it. Servers
SHOULD bound the number of tracked principals and evict idle ones.

Clients SHOULD honour `Retry-After` and SHOULD NOT retry `rate_limited` responses
automatically without delay.

## 13. Security Considerations

### 13.1. Trust Model

The manifest's authority comes from the fact that it was served over HTTPS from the
domain in question; the embedded signature makes it *portable* (it can be cached,
mirrored or logged and still verified) and lets every subsequent reply be tied to the
same key without trusting intermediaries such as CDNs or TLS-terminating proxies
after first contact. WAP does not by itself defeat an attacker who controls the
domain's origin server or its TLS certificate at discovery time. Clients that need
stronger guarantees SHOULD pin keys (Section 5.4 step 7f) obtained out of band, or
use trust-on-first-use pinning with alerting on change.

### 13.2. Reply Integrity

Because replies are verified against the manifest key, an on-path attacker (or a
compromised intermediary behind TLS termination) cannot alter prices, stock levels
or reservation tokens without detection. The reference test-suite includes a
man-in-the-middle that rewrites prices in both JSON and SSE replies; both are
rejected.

### 13.3. Request Integrity and Replay

User-agent messages are signed by the agent key, bound to a fresh timestamp and a
unique `message_id`, and deduplicated. The proof-of-work solution is inside the
signed body, so it cannot be lifted onto a different request.

### 13.4. Economic Denial of Service ("Token Vampirism")

A business agent backed by a metered LLM converts every inbound request into cost.
Without admission control, an attacker can drain the budget at the price of cheap
HTTP requests. Proof-of-work shifts marginal cost onto the requester; rate limits
bound throughput per principal; the pipeline order in Section 7.2 ensures rejected
requests cost the server microseconds. Difficulty SHOULD be tuned so that the median
legitimate client solves in well under a second (difficulty 4 ≈ 65 536 hashes).
Proof-of-work is not a defence against well-resourced attackers with GPUs or
botnets; it raises the floor and composes with authentication and reputation.

### 13.5. Origin Binding

Manifests MUST NOT direct clients to interaction or challenge endpoints outside the
manifest's domain; otherwise a malicious manifest could turn many user agents into a
reflected flood against a third party.

### 13.6. Server-Side Request Forgery

When the domain to query is chosen by a language model (for example through the MCP
bridge), prompt injection can steer the agent to internal addresses. User agents
SHOULD refuse private, loopback and link-local destinations in that setting, SHOULD
NOT follow redirects, and SHOULD cap response sizes. Note that resolve-then-connect
checks are subject to DNS rebinding; high-assurance deployments should enforce the
policy at the connection layer (e.g. an egress proxy).

### 13.7. Prompt Injection Through Replies

Signed replies prove *who* said something, not that it is safe to follow.
`content` and string values in `structured_data` are untrusted input to the user
agent's model and MUST be treated as data, not instructions.

### 13.8. Key Management

Domain private keys SHOULD be stored in a secrets manager and rotated by publishing a
new manifest. Because manifests expire, rotation completes within one manifest TTL
for clients that do not pin keys. Ephemeral domain keys are acceptable only for
development.

### 13.9. Clock Skew

Timestamps are compared against the server clock with a default ±300 s tolerance.
Deployments SHOULD run NTP.

## 14. Privacy Considerations

Agent keys may be long-lived, which makes a user agent linkable across requests and
domains. User agents SHOULD use a distinct agent key per domain, or ephemeral keys,
unless linkability is desired (for example, for a loyalty relationship). Business
agents SHOULD NOT log `content` beyond what is needed for the transaction and SHOULD
expire session state.

## 15. IANA Considerations

This document requests registration of the following Well-Known URI in the "Well-Known
URIs" registry established by RFC 8615:

* URI suffix: `agent.json`
* Change controller: WebAgent Protocol authors
* Specification document: this document
* Status: provisional

Implementers should be aware that other agent-description formats have used the same
path. A WAP manifest is recognisable by its `wap_version` member; clients encountering
a document without it at this location MUST treat discovery as failed rather than
guess at its semantics.

No other IANA actions are requested. The `X-WAP-*` headers are not registered.

## 16. References

### 16.1. Normative References

* [RFC2119] Bradner, S., "Key words for use in RFCs to Indicate Requirement Levels", BCP 14, RFC 2119.
* [RFC8174] Leiba, B., "Ambiguity of Uppercase vs Lowercase in RFC 2119 Key Words", BCP 14, RFC 8174.
* [RFC3986] Berners-Lee, T., et al., "Uniform Resource Identifier (URI): Generic Syntax", RFC 3986.
* [RFC8259] Bray, T., "The JavaScript Object Notation (JSON) Data Interchange Format", RFC 8259.
* [RFC7493] Bray, T., "The I-JSON Message Format", RFC 7493.
* [RFC8032] Josefsson, S., Liusvaara, I., "Edwards-Curve Digital Signature Algorithm (EdDSA)", RFC 8032.
* [RFC8615] Nottingham, M., "Well-Known Uniform Resource Identifiers (URIs)", RFC 8615.
* [RFC9110] Fielding, R., et al., "HTTP Semantics", RFC 9110.
* [FIPS180-4] NIST, "Secure Hash Standard (SHS)".
* [RFC2104] Krawczyk, H., et al., "HMAC: Keyed-Hashing for Message Authentication", RFC 2104.
* [JSON-SCHEMA] Wright, A., et al., "JSON Schema: A Media Type for Describing JSON Documents", draft 2020-12.
* [HTML] WHATWG, "HTML Living Standard", Section 9.2 Server-sent events.

### 16.2. Informative References

* [RFC8785] Rundgren, A., et al., "JSON Canonicalization Scheme (JCS)", RFC 8785.
* [RFC6648] Saint-Andre, P., et al., "Deprecating the "X-" Prefix", RFC 6648.
* [HASHCASH] Back, A., "Hashcash — A Denial of Service Counter-Measure", 2002.
* [DWORK-NAOR] Dwork, C., Naor, M., "Pricing via Processing or Combatting Junk Mail", CRYPTO 1992.
* [MCP] Anthropic, "Model Context Protocol Specification".

---

## Appendix A. JSON Schemas (informative)

The normative constraints are in Sections 5 and 7; the reference implementation's
Pydantic models (`wap/spec/models.py`) generate equivalent schemas with
`AgentManifest.model_json_schema()` and `AgentMessage.model_json_schema()`.
Abbreviated manifest schema:

```json
{
  "$schema": "https://json-schema.org/draft/2020-12/schema",
  "type": "object",
  "additionalProperties": false,
  "required": ["domain", "name", "public_key", "interaction_url", "signature"],
  "properties": {
    "wap_version": {"const": "1.0"},
    "domain": {"type": "string"},
    "name": {"type": "string", "minLength": 1, "maxLength": 256},
    "description": {"type": "string", "maxLength": 8192},
    "public_key": {"type": "string", "pattern": "^[0-9a-f]{64}$"},
    "interaction_url": {"type": "string", "format": "uri"},
    "challenge_url": {"type": ["string", "null"], "format": "uri"},
    "capabilities": {"type": "array", "items": {"$ref": "#/$defs/Capability"}},
    "pow_required": {"type": "boolean"},
    "pow_difficulty": {"type": ["integer", "null"], "minimum": 1, "maximum": 16},
    "rate_limit_policy": {"type": "object"},
    "issued_at": {"type": "number"},
    "expires_at": {"type": ["number", "null"]},
    "signature": {"type": "string", "pattern": "^[0-9a-f]{128}$"}
  },
  "$defs": {
    "Capability": {
      "type": "object",
      "additionalProperties": false,
      "required": ["id", "name"],
      "properties": {
        "id": {"type": "string", "pattern": "^[a-z][a-z0-9_.-]{0,63}$"},
        "name": {"type": "string", "minLength": 1, "maxLength": 128},
        "description": {"type": "string", "maxLength": 4096},
        "input_schema": {"type": "object"},
        "output_schema": {"type": ["object", "null"]},
        "requires_auth": {"type": "boolean"},
        "streaming": {"type": "boolean"}
      }
    }
  }
}
```

## Appendix B. Example Exchange

Discovery (signatures and keys shortened with `…`):

```http
GET /.well-known/agent.json HTTP/1.1
Host: bakery.example
X-WAP-Version: 1.0

HTTP/1.1 200 OK
Content-Type: application/json
Cache-Control: public, max-age=300
Access-Control-Allow-Origin: *
X-WAP-Version: 1.0
X-WAP-Signature: 3ac98953…

{"capabilities":[{"description":"Check how many units of a pastry are available right now (net of active holds).",
"id":"check_pastry_stock","input_schema":{"additionalProperties":false,"properties":{"item":{"title":"Item",
"type":"string"}},"required":["item"],"type":"object"},"name":"Check Pastry Stock","output_schema":{…},
"requires_auth":false,"streaming":false}],"challenge_url":"https://bakery.example/wap/v1/challenge",
"description":"Neighbourhood sourdough bakery.","domain":"bakery.example","expires_at":1790563600.5,
"interaction_url":"https://bakery.example/wap/v1/interact","issued_at":1790560000.5,"name":"Golden Crust Bakery",
"pow_difficulty":4,"pow_required":true,"public_key":"8c2fcce1…","rate_limit_policy":{"burst":30,
"requests_per_minute":120,"scopes":["ip","agent_key"]},"signature":"5d1e…","wap_version":"1.0"}
```

Streaming interaction:

```http
POST /wap/v1/interact HTTP/1.1
Host: bakery.example
Content-Type: application/json
Accept: text/event-stream
X-WAP-Version: 1.0

{"wap_version":"1.0","message_id":"55421d6c…","session_id":"492b4c11…","role":"user_agent",
 "content":"Do you have Sourdough Croissants today?","capability_id":null,"structured_data":null,
 "in_reply_to":null,"timestamp":1790560010.2,"pow_seed":"a41f…","pow_nonce":"1c3e",
 "public_key":"f00d…","signature":"9b2c…"}

HTTP/1.1 200 OK
Content-Type: text/event-stream; charset=utf-8
X-WAP-Version: 1.0

event: meta
data: {"session_id":"492b4c11…","in_reply_to":"55421d6c…","capability_id":null,"wap_version":"1.0"}

event: data
data: {"item":"Sourdough Croissant","in_stock":true,"available":24,"held":0,"unit_price":4.5}

event: token
data: {"text":"Yes!"}

event: token
data: {"text":" 24"}

…

event: message
data: {"wap_version":"1.0","message_id":"2d34…","session_id":"492b4c11…","role":"business_agent",
       "content":"Yes! 24 x Sourdough Croissant available at $4.50 each.","capability_id":null,
       "structured_data":{"item":"Sourdough Croissant","in_stock":true,"available":24,"held":0,"unit_price":4.5},
       "in_reply_to":"55421d6c…","timestamp":1790560010.3,"pow_seed":null,"pow_nonce":null,
       "public_key":"8c2fcce1…","signature":"f528…"}
```

## Appendix C. Conformance Checklist

A conforming **business agent**:

- [ ] serves a signed manifest at `/.well-known/agent.json` with `X-WAP-Signature`;
- [ ] binds `domain`, `interaction_url` and `challenge_url` to its own origin;
- [ ] implements the Section 7.2 pipeline in order;
- [ ] signs every reply and error body with the domain key;
- [ ] emits SSE events in the order and with the invariants of Section 8;
- [ ] single-uses proof-of-work seeds and binds difficulty to the seed;
- [ ] returns the error codes and statuses of Section 9.

A conforming **user agent**:

- [ ] refuses plain HTTP for non-loopback domains by default and never follows
      discovery redirects;
- [ ] verifies manifest signature, domain binding, origin binding and expiry;
- [ ] verifies every reply against the *manifest* key and checks `in_reply_to`;
- [ ] treats streamed tokens as provisional until the signed `message` event;
- [ ] bounds proof-of-work retries and honours `Retry-After`;
- [ ] treats reply content as untrusted data.

The reference implementation in this repository (`wap/`) is exercised against this
checklist by `tests/`.
