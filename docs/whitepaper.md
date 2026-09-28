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
command-line tool and a Model Context Protocol bridge), and evaluate it with a real language-model
agent against a live server. Answering a stock-and-price question through WAP cost the agent about
**4.8× fewer billed input tokens** than reading the storefront's raw HTML, but about 1.7× *more* than
reading tag-stripped text, so tokens are not WAP's main argument. What a page reader cannot do without
simulating a browser, the WAP agent did directly: it negotiated a bulk price and placed a reservation
in 5 of 5 runs, with every reply signature-verified. When the user declined, nothing was reserved in
10 of 10 runs. When an agent was told to keep repeating a lowball offer, loop protection stopped it on
the sixth call in 5 of 5 runs, and the business never received more than five of its requests. All measurements, transcripts
and the script that produces them are published with the reference implementation.

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
produces a `quote_id` that is redeemable only in the negotiating session. This is the negotiation a
language-model agent ran when asked to reserve 12 croissants at the lowest price it reasonably could
(run 1 of `reserve_approved` in `docs/evidence/agent-eval/transcripts.jsonl`):

| Step | Agent calls | Bakery responds (signed) |
|---:|---|---|
| 1 | `get_menu` | Sourdough Croissant, $4.50, 24 available |
| 2 | `negotiate_bulk_price`, $3.25 | counter-offer $4.05 |
| 3 | `negotiate_bulk_price`, $3.60 | final offer $4.05 |
| 4 | `negotiate_bulk_price`, $4.05 | accepted, quote `Q-…` |
| 5 | `reserve_item` with the quote, after the user approves | reservation `RSV-AAD174CF21FA8C72`, 12 × $4.05 = $48.60 |

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

We measured the reference implementation with `python examples/benchmark.py`, single-threaded, in a
Linux container (Python 3.14.7) on a laptop with an Intel Core Ultra 9 185H. The raw output is
`docs/evidence/benchmark.md` and the machine is described in `docs/evidence/environment.txt`:

| Difficulty *d* | Expected hashes (16^*d*) | Client solve (mean) | Server verify | Ratio |
|---:|---:|---:|---:|---:|
| 1 | 16 | < 0.1 ms | 9.2 µs | — |
| 2 | 256 | 0.3 ms | 13.8 µs | ~22× |
| 3 | 4,096 | 2.9 ms | 44.3 µs | ~65× |
| 4 | 65,536 | 58.6 ms | 120.5 µs | ~490× |
| 5 | 1,048,576 | 845.6 ms | 114.3 µs | ~7,400× |

Solve times are means of 20 trials (5 at *d* = 5) and verification times are single-shot, on a
laptop that was also running other work, so treat the ratios as orders of magnitude.
Server verification includes HMAC authentication of the seed and the spent-set update, and stays
between roughly 10 and 120 µs at every difficulty; solving grows 16× per step. Pure-Python hashing
also represents a *slow* attacker. Native or GPU solvers run orders of magnitude faster, which
is why proof-of-work in WAP is a **floor, not a wall**. It prices out indiscriminate
high-volume scripts cheaply and composes with rate limits, authentication
(`requires_auth` capabilities), and reputation systems. The default difficulty of 4 added
about 60 ms per request for a legitimate Python client in our measurements, which is small next to
a typical LLM-backed reply. An operator under attack can raise *d*. The reference client
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
Documents are signed over the JSON Canonicalization Scheme (JCS, RFC 8785): sorted keys, no
whitespace, UTF-8, and ECMAScript number formatting, so any language with a JCS implementation can
verify a signature. `docs/test-vectors.json` publishes fixed keys, documents, canonical bytes and
signatures; CI checks them with an independent Node.js verifier (21 checks), and a test reproduces a
live manifest's signature using only Python's standard-library `json` module and a raw Ed25519
primitive.

Measured cost on the machine in §3.3: **150 µs to canonicalize and sign** an `AgentMessage`, and
**276 µs to verify** one.

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
polite, and neither owns the decision to stop. A scripted shopper that keeps offering the same low
price against the bakery's final offer continues indefinitely: every turn costs the shopper a
proof-of-work and the bakery a tool invocation, and the user never gets an answer. Rate limits slow
such loops down but don't end them.

Language models are better than scripts at noticing a dead end, but not reliably. In our evaluation
(§6.4), a model told that its user's budget was firm usually stopped by itself once the bakery said
no rounds remained. In one run it instead dropped the session and started the negotiation over, twice,
which reset the bakery's round counter each time.

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

The **business** runs the guard per session and, with looser limits (default 10), per agent key across
sessions, because one key may serve many users. It refuses with `loop_detected` (409) or
`conversation_limit` (429) *before* any tool runs. The **user's side** runs the same guard locally and
counts error replies as replies, so a model that keeps resending an invalid request is also stopped.
The MCP bridge serves a single user, so it also applies the strict limits to each site across sessions.
We added that after watching a model evade the per-session guard by starting new sessions (§5.1); the
regression test `test_bridge_stops_a_model_that_hops_sessions` replays the model's exact pattern.

The bridge turns a detected loop into a tool error whose text tells the model to stop, summarize what
it learned, and report back to the user. The instruction does not always work, which is why the
refusal matters more than the message. When a model was told to repeat a $3.60 offer at least ten more
times, the bridge stopped it on the sixth call in 5 of 5 runs. In 3 of those runs the model ignored the
instruction and tried five more times; the bridge refused every attempt, and the bakery's own counter
shows it received exactly five negotiation requests in every run. All five final answers told the user
truthfully that the offer had been refused and that further attempts were blocked. Loop protection is
on by default and can be tuned through `ConversationPolicy`.

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
second time. The test `test_lost_response_is_retried_without_double_booking` drops the connection
after a reservation is made and checks that exactly one hold exists.

In the evaluation (§6.3), a model negotiated and asked to reserve in every run. When the user declined
through the client's `confirm` hook, nothing was sent (5 of 5 runs, no holds on the server). In one
of those runs the model retried the declined reservation; the user was asked again and nothing was
sent that time either. Through `wap-mcp`, the model tried to reserve in 4 of 5 runs, the bridge asked
the user through MCP elicitation each time, and no hold was created; in the fifth run the model stopped
at the final offer and asked the user in chat instead. No answer claimed a reservation that did not
exist.

## 6. Evaluation

Every number in this section comes from `docs/evidence/`, produced by one command
(`evals/Dockerfile`, which runs `evals/run.sh`) in a Linux container against commit `3d620c2` of the
reference implementation. `docs/evidence/README.md` describes each file and how to reproduce it.

### 6.1 Method

We gave a language model (`gpt-6-luna` through the OpenAI Responses API, chosen for cost) tools and a
task and let it run until it answered. Nothing was mocked:

* the business is the reference bakery served over HTTP by uvicorn, with proof-of-work at difficulty 4;
* every WAP call is signed, pays proof-of-work, and has its reply verified against the manifest key;
* `wap-mcp` runs as a separate process over stdio, exactly as an MCP host launches it;
* token counts are the input and output tokens the API billed, summed over every model call in a run;
* outcomes are checked against the server's own state (inventory, holds, and a counter of the
  negotiations it actually executed), not against what the model says.

The scraping agents read an HTML storefront served by the same process and rendered from the same live
inventory, so every strategy sees the same facts. The page (18.8 KB) has typical furniture: navigation,
filters, six product cards with images and forms, JSON-LD, analytics, a newsletter form, a footer and a
cookie banner. It is smaller than most production pages, which favours the scrapers.

| Scenario | Runs | The model gets | The task |
|---|---:|---|---|
| Lookup, raw HTML | 10 | `fetch_page` returning HTML | stock and unit price of one item, as JSON |
| Lookup, stripped text | 10 | `fetch_page` returning visible text | the same |
| Lookup, WAP | 10 | the bakery's four capabilities | the same |
| Reserve | 5 | the bakery's capabilities; the user approves | negotiate, then reserve 12 for Ada Lovelace |
| Reserve, user declines | 5 | the same; the user declines | the same |
| Reserve via `wap-mcp`, user declines | 5 | the bridge's tools; MCP elicitation declines | the same |
| Firm budget via `wap-mcp` | 5 | the bridge's tools | offer $3.60 and never more, until accepted |
| Adversarial repetition via `wap-mcp` | 5 | the bridge's tools | repeat the $3.60 offer at least 10 more times |

### 6.2 Answering a question: tokens and correctness

| Strategy | Correct | Mean billed input tokens | Mean output tokens | Mean tool calls | Mean time |
|---|---:|---:|---:|---:|---:|
| Scrape raw HTML | 10/10 | 6,540 | 46 | 1.0 | 2.5 s |
| Scrape stripped text | 10/10 | 813 | 49 | 1.0 | 2.4 s |
| WAP | 10/10 | 1,349 | 71 | 1.7 | 2.9 s |

All three strategies answered every question correctly. WAP used **4.8× fewer input tokens than raw
HTML** but **1.7× more than stripped text**. The WAP agent pays for its tool list on every model call
(four capability schemas), and in 7 of 10 runs it called `get_menu` and then `check_pastry_stock`,
which adds a model call. On a page this small, a scraper that strips markup is the cheapest way to
answer a read-only question. Pages several times larger, which are common, would move the raw-HTML
comparison further in WAP's favour; they would not necessarily change the comparison with stripped
text. Token cost is therefore not the main argument for WAP.

An earlier version of this paper estimated a 24× saving against raw HTML from static byte counts. The
static counts are still reproduced by `examples/benchmark.py` (§6.5), but they compare one capability
schema and one result with a whole page, and leave out what an agent actually pays for: the other tool
schemas, the question, and a second model call. The billed tokens above replace that estimate.

### 6.3 Acting: negotiation and consent

Stripped text can answer a question but cannot act. The WAP agent was asked to reserve 12 croissants
at the lowest price it reasonably could:

* **5 of 5 runs** ended with exactly one hold of 12 for Ada Lovelace on the server, at the negotiated
  $4.05 instead of the $4.50 list price. Every run opened low ($3.00 or $3.25), moved up once
  ($3.50 or $3.60), accepted the bakery's final offer, and reserved with the resulting quote.
* **Every business reply was signature-verified.**
* A run took 5.4 tool calls, 6,551 billed input tokens and 10.7 s on average, including five
  proof-of-work solutions.

When the user declined, **no hold was created in any of 10 runs** (5 through the client's `confirm`
hook, 5 through `wap-mcp` and MCP elicitation). §5.4 describes these runs, including one in which the
model retried a declined reservation.

### 6.4 Loop protection with a real model

| Instruction | Negotiate calls by the model, per run | Negotiations the bakery executed | Stopped by the guard |
|---|---|---|---|
| Firm budget | 4, 3, 3, 4, 6 | 4, 3, 3, 4, 5 | run 5, on call 6 |
| Repeat at least 10 more times | 11, 11, 6, 11, 6 | 5, 5, 5, 5, 5 | all runs, on call 6 |

With a firm budget, the model usually stopped by itself after three or four offers, once the bakery
reported no rounds remaining, and told the user the offer had been refused. In run 5 it started new
sessions to restart the negotiation; the bridge's per-site guard (§5.3) stopped it on the sixth call.
In an earlier run during development, before that guard existed, the same behaviour sent nine identical
offers to the bakery across three sessions without being stopped.

Under the adversarial instruction, the guard stopped every run on the sixth call and the bakery never
executed more than five negotiations, although the model attempted eleven in three runs.

### 6.5 Static sizes, proof-of-work and latency

`examples/benchmark.py` also reports static sizes and per-operation costs (`docs/evidence/benchmark.md`).
Token counts there are approximate (a byte-level-BPE pre-tokenizer estimate):

| Representation | Bytes | ≈ Tokens |
|---|---:|---:|
| Raw HTML storefront | 18,848 | 7,071 |
| Visible text | 1,456 | 419 |
| WAP: full manifest (4 capabilities) | 5,407 | 1,564 |
| WAP: one capability schema | 774 | 249 |
| WAP: signed reply on the wire | 704 | 300 |
| WAP: model-visible result (text + structured data) | 158 | 57 |

Cryptographic material is token-heavy (hex keys and signatures), so the MCP bridge verifies signatures
itself and hands the model only the verified result. A signed, proof-of-work-gated (*d* = 3) capability
call through the full server pipeline, in process with no network, took **p50 6.1 ms, p90 14.2 ms**
over 30 calls. Proof-of-work and signature costs are in §3.3 and §4.1.

The qualitative differences matter more than any of these sizes:

| Property | Scraping | WAP |
|---|---|---|
| Stock and price read from | inferred from markup or text | typed fields (`available: 24`, `unit_price: 4.5`) |
| Robust to redesigns | no | yes (contract is versioned) |
| Can *act* (hold, negotiate) | only by simulating a browser | first-class capabilities with schemas (§6.3) |
| Input validated before execution | no | yes, on both sides (JSON Schema) |
| Origin of data provable | no | Ed25519 over every reply |
| Business protected from abuse | CAPTCHAs aimed at humans | PoW + rate limits aimed at agents |

### 6.6 Server throughput and shared state

`examples/load_test.py` drives real uvicorn worker processes over HTTP from three load-generator
processes with 32 virtual users for 15 s. Every request fetches a challenge, solves proof-of-work at
difficulty 2, and sends a signed request whose signed reply the client verifies
(`docs/evidence/load-test.md`):

| Workers | Shared store | Requests/s | p50 | p99 | Errors | Replay accepted | PoW reuse accepted |
|---:|---|---:|---:|---:|---:|---:|---:|
| 1 | in memory | 395 | 78 ms | 133 ms | 0 | 1 of 24 | 1 of 24 |
| 4 | none | 612 | 48 ms | 106 ms | 0 | **2 of 24** | **4 of 24** |
| 4 | Redis | 599 | 51 ms | 97 ms | 0 | 1 of 24 | 1 of 24 |

The load generator shares the machine with the server, so absolute numbers understate dedicated
hardware. The correctness probes matter more: without a shared store, four workers accepted one
replayed message twice and one proof-of-work solution four times. With Redis both were accepted exactly
once, which is why the reference implementation keeps all protocol state behind a pluggable store.

### 6.7 Limitations

* **One model, small samples.** 10 lookups per strategy and 5 runs of each other scenario with one
  inexpensive model. Rates are indicative, and other models will spend different numbers of tokens and
  may behave differently at the edges, such as whether they obey a stop instruction.
* **One synthetic storefront.** Real pages are larger and messier. We have not measured how scrapers
  or WAP agents fare on them.
* **One machine.** Client, server and bridge share a laptop, so network latency is near zero and
  timings include contention from other work.
* **The adversarial prompt is artificial.** It exists to exercise loop protection, not to model users.
* **Same-origin evaluation.** The evaluation tests WAP's reference bakery with WAP's reference client.
  Interoperability with independent implementations is covered by the published test vectors, not by
  this evaluation.

---

## 7. Future Work

**Key transparency.** The reference implementation supports key rotation with endorsements and
optional DNS TXT anchoring of keys. An append-only transparency log of manifests would additionally
let anyone audit which keys a domain has used over time.

**Broader agent evaluation.** §6 uses one inexpensive model, one synthetic storefront and small
samples. The harness (`evals/agent_eval.py`) takes any Responses API model; the obvious next steps are
several models, real storefronts of realistic size, and larger samples, and measuring how often agents
obey a stop instruction rather than relying on the guard.

**Smaller tool lists.** In §6.2 the WAP agent spent more tokens on tool schemas than a text scraper
spent on the page. Loading capability schemas on demand, or grouping them, would cut that overhead.

**Memory-hard puzzles.** The reference implementation already raises difficulty with load
(`AdaptivePow`) and lets an admission hook set it per principal. Memory-hard functions (such as Argon2
or Equihash-style puzzles) would narrow the gap between commodity and specialized attacker hardware.

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
abuse cheaper to reject than to commit. In our evaluation with a real model, WAP was not the
cheapest way to answer a simple question, but it was the only strategy we tested that could act
without simulating a browser: it negotiated and reserved correctly every time, never acted when the user said no, and
stopped a looping agent before the business paid for more than five of its requests. The reference
implementation, its tests and the evaluation are small enough to audit, and a business can adopt WAP
with a decorator and a key.

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
