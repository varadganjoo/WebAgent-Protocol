# WebAgent Protocol (WAP): A Decentralized Discovery and Inter-Agent Communication Standard for the Autonomous Web

*Beyond Scraping: Protocol-Mediated Agentic Web*

**WebAgent Protocol authors** · September 2026 · Version 1.0

---

## Abstract

Language-model agents are becoming a primary client of the web, yet they still consume it
through an interface designed for human eyes: rendered HTML. Agents scrape pages, infer
prices and availability from markup, and simulate clicks to act. This approach is costly in
context tokens, fragile under routine redesigns, unauthenticated, and, as agents proliferate on
both sides of a transaction, economically hazardous for businesses whose own agents are
backed by metered models. We present the WebAgent Protocol (WAP), a small open standard that
lets any domain publish a signed, machine-readable description of what its agent can do at
`/.well-known/wap.json` (RFC 8615), and lets any user agent invoke those capabilities with
JSON-Schema-validated inputs, streamed outputs, and Ed25519-signed replies. WAP adds an
asymmetric economic defence, a stateless Hashcash-style proof-of-work gate combined with
per-principal rate limits, so that rejecting abusive traffic costs the business microseconds
while generating it costs the attacker milliseconds to seconds. Because two cooperating language
models can talk past each other forever, WAP also bounds dialogues with a conversation guard that
stops repeated exchanges, ping-pong cycles, and stalls on both sides of the connection. WAP is
designed as an **extension of the Model Context Protocol (MCP)**: the same functions are served as
signed WAP capabilities and as a standard MCP endpoint, and a bridge turns any discovered website into
native tools in MCP hosts. We describe the design, its
threat model and a reference implementation (a FastAPI provider SDK, an async client, a
command-line tool and a Model Context Protocol bridge). On a representative storefront, a WAP
query places about **24× fewer tokens** in the model's context than the raw HTML of the page
does. Relative to aggressively tag-stripped text the token saving is small (about 1.4×). The
larger gains are in correctness, the ability to act, and authenticity.

---

## 1. The Collapse of Visual Scraping in Multi-Agent Ecosystems

### 1.1 How agents use the web today

A contemporary shopping agent that is asked "does Golden Crust have sourdough croissants, and
can you hold a dozen for me?" typically:

1. searches for the business and fetches its homepage;
2. converts HTML to text or an accessibility tree, sometimes with screenshots;
3. asks a model to locate the relevant product, parse "(24 left)" as a stock count and
   "$4.50" as a unit price;
4. navigates a cart or reservation form by predicting clicks and keystrokes;
5. parses a confirmation page to extract the result.

Every step is a guess. Benchmarks of browser-driving agents make the gap concrete: in the
original WebArena evaluation (Zhou et al., 2023), the best model-based agent completed roughly
14% of realistic web tasks against roughly 78% for humans. Much of the failure comes from
perception and navigation of interfaces rather than from reasoning about the user's goal.

### 1.2 Four structural failures

**Cost.** Pages are mostly furniture: navigation, styles, scripts, tracking, cookie banners.
The model pays in context tokens for all of it, on every visit.

**Fragility.** A CSS refactor, an A/B test, or a localized price format silently changes what
the agent reads. Nothing in HTML distinguishes a contract from a presentation detail.

**Authenticity.** An agent cannot tell whether "$4.50" came from the business, a
compromised CDN, an injected advertisement, or an adversarial page crafted to manipulate
agents. Human-oriented pages carry no statement of origin that survives extraction.

**Economics.** Businesses are deploying their own agents: LLM-backed front desks that
quote, negotiate and book. When user agents talk to business agents through chat widgets,
every exchange costs the business model tokens, and nothing stops a script from asking a
million questions. We call this *token vampirism*: extracting value from a counterparty's
metered inference at negligible cost to oneself.

### 1.3 What already exists

Several partial solutions exist. Schema.org/JSON-LD describes *entities* (a bakery, its
opening hours) but not *operations* with inputs and outputs. OpenAPI describes operations but
is aimed at developers integrating ahead of time, has no discovery convention for arbitrary
domains, and says nothing about reply authenticity or abuse economics. `robots.txt`
(RFC 9309) and the `llms.txt` proposal tell crawlers what to read, not what to do. The Model
Context Protocol (MCP) standardizes how a *model host* connects to tools, but those tools are
installed by the user in advance and do not come from the open web. Agent-to-agent
proposals have introduced agent descriptions and task lifecycles, but most leave
cryptographic binding of replies and admission control to deployments.

WAP draws on all of these. It borrows well-known discovery from RFC 8615, schemas from JSON
Schema, the transport-agnostic tool shape from MCP, and cost-shifting from Hashcash, and it
adds the missing pieces: **domain-bound signatures on every reply**, **built-in economic
defence**, and **bounded dialogues**.

WAP positions itself as an extension to MCP rather than a competitor. A WAP server's capabilities are
exactly MCP tools. The same `@wap.action` function is published at `/mcp` as an ordinary MCP tool and
at `/wap/v1/interact` with WAP's envelopes, and the manifest links the two through `mcp_url`. The MCP
endpoint declares an `io.webagent/wap` extension and carries WAP's guarantees in `_meta`, so plain MCP
clients work unchanged and WAP-aware clients gain verification (see `docs/mcp_extension.md`).

---

## 2. Discovery Architecture & Well-Known Semantics

### 2.1 One URL per domain

WAP's only discovery requirement is that a domain serve a signed manifest at
`https://<domain>/.well-known/wap.json`. Given nothing but a domain name, which users say
naturally ("ask the bakery on Mill Lane", "check bakery.example"), an agent can find the
business agent, learn its capabilities, and verify its key. No registry, directory, or central
authority is involved, so the web's existing naming and PKI remain the root of trust.

```
                 ┌────────────────────────── bakery.example ──────────────────────────┐
                 │                                                                    │
  User agent ──▶ │ GET /.well-known/wap.json  ──▶  signed AgentManifest             │
  (or MCP host   │   • public_key (Ed25519)          • capabilities[] + JSON Schemas  │
   via wap-mcp)  │   • interaction_url               • pow_required, rate_limit_policy│
                 │                                                                    │
                 │ GET /wap/v1/challenge        ──▶  {seed, difficulty}   (optional)  │
                 │                                                                    │
                 │ POST /wap/v1/interact        ──▶  SSE: meta, token*, data*,        │
                 │   signed AgentMessage              message (signed)               │
                 └────────────────────────────────────────────────────────────────────┘
```

### 2.2 The manifest as a signed capability contract

A manifest lists capabilities, each with a stable `id`, a natural-language `description` (for
the user agent's planner), an `input_schema` (JSON Schema 2020-12) and an optional
`output_schema`. In the reference SDK these schemas are *derived from code*: a business
developer writes

```python
@wap.action(name="check_pastry_stock", description="Units available right now.")
async def check_pastry_stock(item: str) -> StockLevel: ...
```

and the function signature becomes the published input schema, while the Pydantic return type
becomes the output schema. The contract cannot drift from the implementation because it is
generated from it.

The manifest is signed with the domain key over a canonical JSON form. That signature makes
the manifest portable: it can be cached, mirrored, or embedded in search indexes and still be
verified. It also establishes the key that must sign all later replies.

### 2.3 Bindings that defeat cheap attacks

Clients enforce three bindings on every manifest:

* **Domain binding.** The manifest's `domain` must equal the authority it was fetched from,
  so a manifest copied to another domain is useless there.
* **Origin binding.** `interaction_url` and `challenge_url` must sit on the manifest's
  domain or a subdomain of it. Otherwise a malicious manifest could conscript thousands of
  user agents into a reflected flood against a third party.
* **No redirects.** Discovery refuses 3xx responses, which closes open-redirect and
  cross-domain confusion attacks.

Optional key pinning, together with manifest expiry, gives deployments a path to stronger
trust and to routine key rotation.

### 2.4 Interaction and negotiation

An interaction is a signed `AgentMessage` naming either a `capability_id` with
`structured_data`, or a free-text `content` intent for the business's own router (for
example, an LLM). Messages share a `session_id`, and the server binds each session to the
agent key that opened it. Negotiation state therefore persists across turns and cannot be
hijacked by another agent. In the reference bakery, a three-round bulk-price negotiation
produces a `quote_id` that is redeemable only in the negotiating session:

| Round | Shopper offers | Bakery responds |
|---:|---:|---|
| 1 | $3.60 | counter-offer $4.05 |
| 2 | $3.83 | final offer $4.05 |
| 3 | $4.05 | accepted, quote `Q-…` |
| → | reserve 12 with quote | reservation token `RSV-…`, total $48.60, signed |

Replies stream as Server-Sent Events: `meta`, then any number of `token` and `data`
fragments, then a single signed `message`. Streaming keeps latency low for LLM-backed
business agents. Only the final signed message is authoritative, so no unsigned fragment is
ever trusted.

---

## 3. Asymmetric Economic Defence: Proof-of-Work against Token Vampirism

### 3.1 The problem

Let *c_s* be the business's marginal cost of serving a request (for an LLM-backed agent,
often cents), and *c_a* the attacker's marginal cost of sending one (effectively zero). Any
open endpoint with *c_s ≫ c_a* can be drained. Rate limiting by IP address helps, but IP
addresses are cheap to rotate and IPv6 makes them cheaper still. Rate limiting by API key
requires registration, which defeats open discovery.

### 3.2 Design

WAP combines three mechanisms, ordered from cheapest to most expensive for the server
(Spec §7.2):

1. **Per-IP rate limit** before parsing.
2. **Signature, freshness, and replay checks** (about 0.1 ms).
3. **Per-agent-key rate limit.** This is charged only *after* signature verification, so
   an attacker cannot spend someone else's budget by claiming their key.
4. **Proof-of-work.** A Hashcash puzzle: find `nonce` with
   `SHA-256(seed ‖ nonce)` starting with *d* hexadecimal zeros. The expected client work is
   16^*d* hashes, and verification costs one.

Only then does the business's code run.

The challenge is **stateless to issue**. The seed encodes a random salt, the expiry, and an
HMAC tag over both plus the difficulty, so issuing challenges allocates no memory and a
client cannot downgrade the difficulty. The server remembers only *spent* seeds until they
expire. Because the solution travels inside the signed message, an eavesdropper cannot
transplant it onto another request.

### 3.3 Measured asymmetry

We measured the reference implementation on a 4-vCPU Intel Xeon at 2.10 GHz with Python
3.11.15, single-threaded, using `python examples/benchmark.py`:

| Difficulty *d* | Expected hashes (16^*d*) | Client solve (mean) | Server verify (mean) | Ratio |
|---:|---:|---:|---:|---:|
| 1 | 16 | < 0.1 ms | 6.8 µs | — |
| 2 | 256 | 0.2 ms | 10.6 µs | ~19× |
| 3 | 4,096 | 2.0 ms | 17.1 µs | ~117× |
| 4 | 65,536 | 31.9 ms | 41.7 µs | ~765× |
| 5 | 1,048,576 | 449.6 ms | 92.2 µs | ~4,900× |

Server verification includes HMAC authentication of the seed and the spent-set update, so it
grows slightly with *d* (the verifier tries each permitted difficulty). Pure-Python hashing
also represents a *slow* attacker. Native or GPU solvers run orders of magnitude faster, which
is why proof-of-work in WAP is a **floor, not a wall**. It prices out indiscriminate
high-volume scripts cheaply and composes with rate limits, authentication
(`requires_auth` capabilities), and reputation systems. The default difficulty of 4 adds
roughly 30 ms per request for a legitimate Python client, which is negligible next to a
typical LLM-backed reply. An operator under attack can raise *d*. The reference client
recovers automatically when proof-of-work is switched on after discovery, because the
server's `428` response carries a fresh challenge.

### 3.4 Economic framing

If a business's LLM reply costs *c_s* and an attacker's CPU-second costs *k*, then difficulty
*d* forces the attacker to spend about *k·t(d)* per request. Here *t(d)* is the solve time,
which grows 16× per step. The operator can therefore choose *d* so that *k·t(d)* is a
meaningful fraction of *c_s* for commodity attackers while staying below the latency budget of
honest users. Because the parameter is published in the manifest and bound into every seed,
operators can adapt it in real time without breaking clients.

---

## 4. Cryptographic Trust Verification

### 4.1 Keys and canonical form

Each domain holds an Ed25519 key (RFC 8032). We chose Ed25519 for its deterministic
signatures, small 32-byte keys and 64-byte signatures, speed, and wide library support.
Documents are signed over a canonical JSON serialization: sorted keys, no whitespace, UTF-8,
and integral numbers without fractions. An independent verifier can reproduce this with
`JSON.stringify` or Python's `json.dumps` and nothing else. Our test suite checks this by
verifying a live manifest with only the standard-library `json` module and a raw Ed25519
primitive.

Measured cost: **39 µs to canonicalize and sign** an `AgentMessage`, and **97 µs to verify**
one.

### 4.2 What is signed

| Artifact | Signed by | Verified against | Purpose |
|---|---|---|---|
| Manifest (embedded) | domain key | its own `public_key`, plus domain binding and optional pin | portable authenticity |
| Every JSON response body (`X-WAP-Signature`) | domain key | manifest key | integrity of errors, challenges, replies |
| User-agent request | agent key | key in the request | replay protection, per-key limits, session ownership |
| Business reply (`message`) | domain key | **manifest** key, plus `in_reply_to` binding | non-repudiable answers |

Verifying replies against the *manifest* key instead of the key the reply claims is
essential. Our adversarial tests insert a man-in-the-middle that rewrites `4.5` to `0.5` in
replies. The client rejects the result in both JSON and SSE modes.

### 4.3 Non-repudiation as a feature

Because every quote, stock level, and reservation token is signed by the business, a user
agent can keep a verifiable receipt of what it was told. That matters for consumer disputes,
for auditing autonomous purchases, and for letting downstream agents trust a result that was
relayed to them.

### 4.4 Limits of the trust model

WAP inherits the web's PKI at first contact. An attacker who controls the origin or its TLS
certificate during discovery can publish their own key. Key pinning, manifest expiry, and
out-of-band key publication (for example in DNS or transparency logs, see §6) mitigate this.
Signatures establish *who* said something, not whether it is *safe*: reply text remains
untrusted input to the user agent's model and must not be treated as instructions.

---

## 5. Bounding Agent-to-Agent Dialogues

### 5.1 The failure mode

When a user's assistant negotiates with a business's assistant, both sides are stochastic, both are
polite, and neither owns the decision to stop. In our own testing, a scripted "naive" shopper that
kept offering the same low price against the bakery's final offer would have continued indefinitely.
Every turn cost the shopper a proof-of-work and the bakery a tool invocation, and the user never got
an answer. Rate limits slow such loops down but don't end them.

### 5.2 The conversation guard

WAP fingerprints every exchange as a pair of hashes: one over the request (capability, arguments,
normalized text) and one over the reply. Fingerprints ignore ids, timestamps, signatures, and cosmetic
rephrasing such as case, whitespace, and punctuation, so "Any croissants??" and "any croissants" are
the same request. Within a sliding window, a request is refused when:

* the same exchange has already happened `max_repeats` times in a row (default 3);
* a cycle of up to `max_cycle_length` exchanges has repeated `max_repeats` times, which catches
  offer/counter ping-pong;
* the same request has been sent `max_identical_requests` times in a row (default 5) while only
  counters in the replies changed (a stall);
* the session has used `max_turns`.

A repeated question with a *changing* answer, such as polling stock that is selling out, counts as
progress until the stall threshold.

### 5.3 Defence on both sides

The **business** runs the guard per session and per agent key across sessions. It refuses with
`loop_detected` (409) or `conversation_limit` (429) *before* any tool runs. The **user's side** runs
the same guard locally, and counts error replies as replies, so a model that keeps resending an
invalid request is also stopped. The MCP bridge turns a detected loop into a tool error whose text
tells the model to stop, summarize what it learned, and report back to the user. That is the only
exit that reliably breaks an LLM out of a retry habit.

In a live run, a client repeatedly calling `negotiate_bulk_price` with the same offer through
`wap-mcp` saw a counter-offer, then the bakery's final offer, and was stopped on the sixth call with
that instruction. A different request to the same site still succeeded. Loop protection is on by
default and can be tuned through `ConversationPolicy`.

### 5.4 Consent before consequences

Loops are one way an agent can act against its user's interests; acting without asking is another.
Every WAP capability declares its `effects`: `read`, `write` (a booking or a hold) or
`financial` (moving money). A user agent asks its human before anything that is not `read`. In the
reference MCP bridge this is an MCP elicitation prompt, bound cryptographically to the exact tool
and arguments, so the model cannot reuse an approval for different parameters. Free-text requests
are sent with `max_effects: "read"`. If the business's own agent decides to act, for example
turning "hold two croissants for Ada" into a reservation, it must answer with the action it wanted
to take instead of taking it, and the user confirms it explicitly.

Every non-read request also carries an idempotency key. If a response is lost after the business
has already acted, the client's automatic retry returns the original result instead of acting a
second time. In testing, a connection dropped after a reservation was made led to exactly one hold.

## 6. Performance Benchmarks: Token Reduction vs HTML Scraping

### 6.1 Method

We compare the model context needed to answer *"Is the Sourdough Croissant in stock, and what
does it cost?"* under three strategies:

* **Raw HTML.** The storefront page as served.
* **Visible text.** The same page with `<script>`, `<style>`, and all tags removed and
  whitespace collapsed. This is a strong scraping baseline.
* **WAP.** The single capability schema the planner needs, plus the model-visible result
  (`text` + `structured_data`) that the MCP bridge returns. We also report the full manifest
  and the full signed wire message.

The storefront is a synthetic, server-rendered collection page with typical furniture:
header navigation, filters, six product cards with images and add-to-cart forms, JSON-LD,
analytics, a newsletter form, a footer, and a cookie banner. At 18.8 KB it is **much smaller
than typical production pages**, which often exceed 100 KB of HTML, so the reduction factors
against raw HTML are conservative. Tokens are counted with a byte-level-BPE pre-tokenizer
approximation. Exact model tokenizers differ by roughly ±15%, and the tokenizer files could
not be downloaded in our measurement environment. The script is `examples/benchmark.py`.

### 6.2 Results

| Representation | Bytes | ≈ Tokens | vs raw HTML |
|---|---:|---:|---:|
| Raw HTML storefront | 18,848 | 7,071 | 1.0× |
| Visible text (scripts/styles/tags stripped) | 1,456 | 419 | 16.9× |
| WAP: full manifest (4 capabilities) | 5,059 | 1,458 | 4.8× |
| WAP: one capability schema | 755 | 242 | 29.2× |
| WAP: signed reply on the wire | 662 | 306 | 23.1× |
| WAP: model-visible result (text + structured data) | 158 | 57 | 124.1× |
| **WAP per query (one schema + model-visible result)** | — | **≈ 299** | **23.6×** |

Round-trip latency for a signed, proof-of-work-gated (*d* = 3) capability call through the
full server pipeline, in process with no network: **p50 4.5 ms, p90 10.0 ms** over 30 calls.

### 6.3 Interpretation

* **Against raw HTML**, WAP reduces per-query context by more than an order of magnitude
  (≈ 24× here, and more on heavier real pages).
* **Against well-stripped text**, the token saving is small (≈ 1.4×). We report this
  directly: token count alone does not justify a new protocol. The stripped text in our
  benchmark is short only because this page is simple. More importantly, it still has to be
  *interpreted*. "In stock (24 left)" must be read correctly as a count for the right product
  among six, and nothing in the text says how to act.
* **The full manifest is the most expensive artifact.** Planners should load only the
  schemas they need. Manifests are cacheable for their TTL and verified once, so their cost
  is amortized across queries.
* **Cryptographic material is token-heavy** (hex keys and signatures). The MCP bridge
  therefore verifies signatures itself and hands the model only the verified result and
  metadata, not the raw envelope.

The qualitative gains that tokens do not capture are larger than the token savings:

| Property | Scraping | WAP |
|---|---|---|
| Stock and price read from | inferred from markup | typed fields (`available: 24`, `unit_price: 4.5`) |
| Robust to redesigns | no | yes (contract is versioned) |
| Can *act* (hold, negotiate) | by simulating UI | first-class capabilities with schemas |
| Input validated before execution | no | yes, on both sides (JSON Schema) |
| Origin of data provable | no | Ed25519 over every reply |
| Business protected from abuse | CAPTCHAs aimed at humans | PoW + rate limits aimed at agents |

---

### 6.4 Server throughput

`examples/load_test.py` drives real uvicorn worker processes over HTTP. Every request includes a
challenge fetch, a proof-of-work at difficulty 2, a signed request and a signed reply that the client
verifies. On the same 4-vCPU machine, with the load generator spread over three processes, one worker
served about **580 requests/s** (p50 51 ms, p99 104 ms) with no errors. Multi-worker deployments that
share state through Redis served about 400–425 requests/s on this small machine, where Redis round trips
and a shared CPU outweigh the extra workers; they should be measured on production hardware.

The same test checks correctness under concurrency. Without a shared store, four workers accepted one
replayed message four times and one proof-of-work solution twice. With Redis, both were accepted exactly
once. This is why the reference implementation keeps all protocol state behind a pluggable store.

## 7. Future Work

**Key transparency.** The reference implementation supports key rotation with endorsements and
optional DNS TXT anchoring of keys. An append-only transparency log of manifests would additionally
let anyone audit which keys a domain has used over time.

**Adaptive and memory-hard puzzles.** Difficulty could scale automatically with load or with
per-principal reputation. Memory-hard functions (such as Argon2 or Equihash-style puzzles)
would narrow the gap between commodity and specialized attacker hardware.

**Privacy-preserving admission.** Anonymous, rate-limited tokens (Privacy Pass-style
blind-signed credentials) could replace some proof-of-work for users of trusted user agents
without making them linkable.

**Payments and commitments.** A standard capability profile for signed offers, escrow, and
settlement would turn signed quotes into binding, machine-enforceable contracts.

**Capability ontologies.** Shared vocabularies for common verbs (`check_stock`,
`reserve`, `quote`) would let planners compare businesses without reading each schema.

**Federated search.** Crawlers that index verified manifests would give agents a
decentralized "yellow pages" for capabilities without a central registry.

**Formal verification.** Model-checking the session and proof-of-work state machines
(Spec §11) against replay and reordering adversaries.

---

## 8. Conclusion

The agentic web does not need agents that are better at pretending to be humans. It needs a
way for the two kinds of software agent to talk to each other, and to stop talking when the
conversation stops going anywhere. WAP provides this with one
well-known URL, one signed contract, one endpoint, and an admission-control design that makes
abuse cheaper to reject than to commit. The reference implementation is complete, tested, and
small enough to audit, and a business can adopt it with a decorator and a key.

---

## References

* Back, A. (2002). *Hashcash – A Denial of Service Counter-Measure.*
* Dwork, C., & Naor, M. (1992). Pricing via Processing or Combatting Junk Mail. *CRYPTO '92.*
* Josefsson, S., & Liusvaara, I. (2017). *Edwards-Curve Digital Signature Algorithm (EdDSA).* RFC 8032.
* Nottingham, M. (2019). *Well-Known Uniform Resource Identifiers (URIs).* RFC 8615.
* Koster, M., Illyes, G., Zeller, H., & Sassman, L. (2022). *Robots Exclusion Protocol.* RFC 9309.
* Rundgren, A., Jordan, B., & Erdtman, S. (2020). *JSON Canonicalization Scheme (JCS).* RFC 8785.
* Wright, A., Andrews, H., Hutton, B., & Dennis, G. (2020). *JSON Schema: A Media Type for Describing JSON Documents*, draft 2020-12.
* Zhou, S., et al. (2023). WebArena: A Realistic Web Environment for Building Autonomous Agents. *arXiv:2307.13854.*
* Deng, X., et al. (2023). Mind2Web: Towards a Generalist Agent for the Web. *NeurIPS 2023.*
* Anthropic (2024). *Model Context Protocol Specification.*
* WHATWG. *HTML Living Standard*, §9.2 Server-sent events.
