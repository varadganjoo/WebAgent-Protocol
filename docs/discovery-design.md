# Universal capability discovery: audit and design

## Acceptance criteria

A client starts with a structured Sydney restaurant query and configured directory providers, with no
restaurant domains. It retrieves two canonical signed manifests, matches the same reservation operation
to different local names, checks availability, obtains consent and books through deterministic code.
Existing WAP/1.0 examples, test vectors, domain discovery and MCP clients continue to work.

## Existing architecture audited before implementation

Reviewed README, spec_rfc, mcp_extension, wire models, crypto/JCS, server action registration/dispatch,
admission/router/state/storage, client resolution/session, MCP import/endpoint/bridge/safety, and tests/examples.

| Mechanism | Reuse point |
| --- | --- |
| Signed canonical discovery | AgentManifest, ManifestResolver, Signer, RFC 8785 JCS |
| Direct structured calls | WAPClient.invoke, WAPServer.action/add_capability/run_capability |
| Tool schemas | Capability.input_schema/output_schema, JSON Schema and Pydantic validation |
| MCP integration | MCPEndpoint, MCPToolSource, WAPBridge; preserve local tool names |
| Verified results/errors | Signed AgentMessage and signed JSON responses, existing typed client errors |
| Abuse controls | RateLimiter/StateStore, proof-of-work admission, bounded request bodies |
| Identity/consent | Domain/TLS/pins/DNS keys, auth_handler/requires_auth, effects and confirm hooks |
| Transaction controls | Turn, session ownership/locks, idempotency keys and stores |
| Dialogue bounds | ConversationGuard at server, client and bridge |

No business LLM is required today: capability_id dispatch already invokes a registered function directly.
Free-text intent routing remains available for negotiation/reasoning, separate from semantic matching.

## Compatibility decision

The current models forbid extra fields, and signatures cover model dumps including defaults. Adding null
members would change old signatures; silently enriching 1.0 would make older clients fail verification.
Therefore retain WAP_VERSION=1.0 for interaction messages and unchanged manifests. Add explicitly versioned
1.1 manifests when discovery/semantic/execution metadata is used. Omit absent new members from dumps.
New clients read 1.0 and 1.1; old clients require an upgrade to read enriched 1.1 manifests. Do not strip
fields from an already signed document or downgrade it. Preserve existing canonicalisation/test vectors.

## Smallest compatible extension

1. Optional capability semantic_operation and semantic_schema_version (exact matching; no name guessing).
   Reference operations describe schema conventions; actual input_schema/output_schema remain authoritative.
   Constraints use JSON Schema, requires_auth/effects/streaming remain the existing fields.
2. Optional execution classification: deterministic, external_service, agent, human_assisted. Descriptive
   only; never alters dispatch, authorisation, confirmation, effects or replay protections. No new job system.
3. Optional signed business discovery metadata: category, geographic coverage and bounded public filters.
4. A directory provider Protocol, local memory reference index, HTTP provider and FastAPI reference service.
   Providers are configured by the caller; no global registry and no transaction forwarding.
5. Registration accepts a canonical domain only, retrieves the signed canonical manifest itself and derives
   an allowlisted projection. No caller-supplied name, tool, key, manifest URL or transaction data is indexed.
6. Client federation isolates provider failures, bounds pages/timeouts, fetches current manifests with cache
   bypass, checks freshness/digest and filters again using verified metadata. Unknown operations fall back to
   ordinary schema-based discovery; no automatic invocation of unknown operations.
7. MCP tools expose optional metadata in io.webagent namespaced _meta. Directory search is optional bridge
   functionality; existing bridge configuration and built-in tools stay unchanged when no providers exist.

## Trust and abuse boundaries

Assets: domain signing keys, tool authorisation/consent, reservations and availability, caller network,
directory integrity and public search privacy. Actors: business owners, directory operators, clients and
malicious registrants/providers. Directory entries are hints, never identity credentials or permissions.

Domain ownership is established only by retrieval over canonical HTTPS plus existing signature/domain/key
checks; this does not certify legal identity, truth of claims, schema compliance or safety. Reject redirects,
userinfo, arbitrary manifest URLs, private/link-local targets, malformed metadata, expired/future entries and
unsupported versions. Use the existing network policy with explicit local-development exceptions; deployment
egress controls are required against DNS rebinding (the current resolver checks DNS before HTTP connection).
Never auto-follow schema URLs. Bound pages, index size, body size, metadata lengths, registration/search rates
and outbound timeouts. Authenticated registration protects reference-service enumeration/SSRF budgets;
domain fetch remains mandatory even for authenticated callers. Do not log queries, exact user coordinates,
customer details, credentials or reservations in the directory. No ranking or recommendation inferred from
signature verification. Stale/poisoned hints are excluded and errors reported without trusting directory keys.

## Alternatives and trade-offs

Selected optional signed 1.1 metadata plus a separate discovery index over an incompatible execution layer
or a mandatory central registry. A separate unsigned sidecar would preserve old clients but would detach
business semantics from the signed source of authority. Exact version matching is intentionally conservative;
schema subtyping, fuzzy intent search, live directory availability and asynchronous jobs are deferred.

## Implementation and validation plan

- [x] Phase 1: audit/design, check venv, install existing dev extras and run baseline tests.
- [x] Phase 2: metadata models, reference vocabulary/matching, unchanged signed-vector tests.
- [x] Phase 3: execution metadata, server/decorator/MCP integration, consent regression tests.
- [x] Phase 4: directory models/providers/service/client/bridge; adversarial registration and search tests.
- [x] Phase 5: deterministic two-restaurant demo with injected clock, permissions and idempotent booking.
- [x] Phase 6: full pytest, Ruff, Python/Node test vectors, build, executable demo and security review.
- [x] Phase 7: README/spec/MCP/configuration/tutorial/changelog and verification evidence.

## Completed validation

See [discovery-validation.md](discovery-validation.md) for the final file inventory, APIs, test results,
independent review corrections and remaining deployment controls. The final Windows/Python 3.14 suite passes
360 tests with 16 Redis-only skips. The built core-only wheel also passes signature and semantic-invocation
checks on Python 3.11 with the Pydantic 2.12 minimum, without FastAPI or MCP installed.

## Enterprise procedure scope

Apply enterprise-app-dev routing/release evidence; Ponytail minimal implementation; Superpowers design,
planning, test-first implementation and verification; OWASP trust-boundary/API/security review and scans;
Spellbook FastAPI/API/security conventions; Sentry correctness review. Minimalist product brainstorming is
excluded because the user supplied acceptance criteria and scope. Anthropic browser/accessibility procedures
are N/A: this is a Python library and HTTP service without a browser UI. No deployment or certification is
requested. GENiiPulse-specific remediation catalogs are N/A; apply the five IBM security principles through
early negative tests, no new runtime dependencies, continuous regression tests, outcome checks and zero trust.
