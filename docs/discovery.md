# Business discovery and semantic capabilities (experimental)

Domain discovery answers "what can bakery.example do?" Directory discovery answers "which participating
businesses match this structured request?" The directory only supplies candidates. Each business domain
remains authoritative for its signed manifest, policies, capability schemas and execution results.

## Signed metadata and versions

Unchanged servers emit 1.0 manifests. Setting `WAPServer(discovery=BusinessDiscovery(...))`, or advertising
any semantic/execution capability metadata, opts into signed manifest **1.1**. New clients accept 1.0 and
1.1; strict older clients must upgrade before consuming 1.1. No signed document is downgraded or stripped.
Absent new fields are omitted, preserving the exact canonical representation/signatures of 1.0. Interaction
messages, headers, paths, JCS/Ed25519 and WAP/1.0 admission/auth/session/idempotency rules are unchanged.

```python
from wap.spec.discovery import BusinessDiscovery, GeoPoint, ServiceArea

metadata = BusinessDiscovery(
    category="restaurant",
    location=GeoPoint(latitude=-33.8688, longitude=151.2093),
    service_areas=[ServiceArea(country="AU", region="NSW", locality="Sydney")],
    attributes={"outdoor": True},
)
```

`discovery.schema_version` is `1.0`. Country codes are two uppercase letters. Areas use exact normalized
text comparison, not a geocoding provider: an omitted region/locality/postcode in business coverage denotes
broader coverage. `location` describes the business's advertised point; radius search compares this point,
not a delivery polygon. `service_areas` describes where services are offered. All values are public claims.
Attributes are bounded categorical strings/booleans, not arbitrary queries, customer data or descriptions.

`Capability` adds optional `semantic_operation`, `semantic_schema_version`, and `execution` fields.
Use existing `input_schema`, `output_schema`, JSON Schema constraints, `requires_auth`, `effects` and
`streaming`; do not duplicate them in semantic metadata. Operation syntax is a dot namespace ending `.vN`,
for example `hospitality.restaurant.reservation.create.v1`. Schema revisions use `major.minor`, e.g. `1.0`.

`wap.spec.semantics.reference_operations()` returns reference input/output schema definitions for:

| Group | Operation suffixes |
| --- | --- |
| `hospitality.restaurant` | `availability.search.v1`, `reservation.create.v1`, `reservation.modify.v1`, `reservation.cancel.v1`, `reservation.retrieve.v1`, `policies.retrieve.v1` |
| `retail` | `inventory.check.v1`, `pricing.retrieve.v1`, `order.create.v1`, `order.status.retrieve.v1` |
| `services.appointment` | `availability.search.v1`, `book.v1`, `reschedule.v1`, `cancel.v1` |

These are reference conventions, not a closed registry. Policy retrieval returns documented dietary and
accessibility information, not an assurance that a venue suits a particular medical need. Custom operations
are permitted. Unknown operations, missing schema versions and unsupported revisions are still visible in
ordinary capability discovery; `match_operation` returns no automatic match. Applications may use the actual
schemas manually. Never execute an identifier or treat it as an instruction.

Automatic matching requires **exact operation and exact known schema revision**, currently `1.0`. A change
in semantic meaning needs a new `.vN`; a schema revision is separately declared and explicitly supported by
the client. No implicit major/minor coercion or fuzzy name matching occurs. Multiple matches are ambiguous.
Clients still validate against actual business constraints; a shared identifier does not prove schema
substitutability. `invoke_operation` validates the reference input/output as well as the actual input/output,
rejects non-local schema references, and uses the existing direct invocation pipeline. Optional schema URLs
are not fetched. Writes require a confirmation hook even when execution is advertised as deterministic.
Known reservation/appointment mutations require at least `write`; order creation requires `financial`.
Candidates advertising weaker effects are rejected for semantic invocation, rather than silently trusted or
having their signed metadata rewritten. Existing ordinary tool invocation behavior remains unchanged.

Execution is descriptive: deterministic application code, external_service API integration, agent reasoning,
or human_assisted workflow. Classification changes no permissions or effects. Existing streaming/output
schemas describe result format. Polling, async job lifecycles and offers are left to custom capabilities and
existing structured sessions; this extension does not invent a new workflow protocol.

## Directory API and providers

Import public types from `wap.directory`:

- `DirectoryProvider.search(DirectoryQuery) -> DirectoryPage` is an async structural interface.
- `MemoryDirectory(client, clock=..., max_entries=10000, max_age=3600, timeout=10)` is the local reference
  index. `register(domain)` retrieves the canonical signed manifest and atomically replaces that domain's
  projected entry. The index is single-process and ephemeral, with at most eight registration fetches at once.
- `HTTPDirectory(origin, http=...)` borrows an explicitly configured HTTP client and adapts the HTTP API.
- `DirectoryClient(client, providers, timeout=10).search(query)` federates 1–8 named providers; the equivalent
  convenience API is `WAPClient.search_businesses(query, providers, timeout=10)`.
- `create_directory_app(index, registration_token=...)`, from `wap.directory.server`, supplies a FastAPI app
  using the existing server extra. The operator token is required, at least 16 characters, and is an admission
  control for registration, not proof of business identity. Public search is rate limited.

No new runtime dependency is required. A provider may use another storage/search engine behind the same
interface. Providers are explicitly configured; neither manifests nor search results can install providers.

HTTP requests are JSON POSTs:

```text
POST /wap-directory/v1/registrations
Authorization: Bearer <operator-managed-token>
{"domain": "restaurant.example"}

POST /wap-directory/v1/search
{"directory_version":"1.0", "category":"restaurant",
 "operation":"hospitality.restaurant.reservation.create.v1",
 "semantic_schema_version":"1.0", "area":{"country":"AU","locality":"Sydney"},
 "filters":{"outdoor":true}, "protocol_versions":["1.1"], "limit":20,"offset":0}
```

The registration endpoint accepts only a bare canonical domain. It derives all fields from an HTTPS-fetched,
signature/domain-verified, expiring manifest with signed discovery metadata. Local loopback HTTP requires an
explicit development exception. Submitted names, arbitrary manifest URLs, keys, schemas and capabilities are
never accepted as registrations. Invalid bodies return 422, oversized bodies 413, unauthenticated registration
401, exhausted budgets 429, failed canonical registration 502; stable `detail.code` identifies the error.

An entry includes name/domain, canonical `manifest_url`, local capability ids, semantic ids/schema versions,
business discovery metadata/version, protocol version, `indexed_at`, `manifest_issued_at`, `expires_at`, digest,
key fingerprint and the provider's verification method. This is a compact projection: it contains no complete
tool schemas, credentials, reservations, user identities or transaction data. Provider timestamps/fingerprints
are advisory. `expires_at` is bounded by the manifest expiry and index maximum age. Refresh by re-registering;
expired entries are pruned on search/registration. Withdrawal becomes effective on client re-verification,
with old public metadata retained in the index at most until expiry.

Queries support category, semantic operation, local capability id, exact public attributes, service area,
point/radius, protocol versions and semantic schema revision. Pages are sorted by canonical domain and return
at most 50 entries plus `next_offset`. Request the next page from that provider using its offset. Federation
returns `next_offsets` keyed by provider; call a provider individually if its offset differs. Offset pagination
is not a snapshot and concurrent index updates can shift pages. Dedupe by canonical domain.

`BusinessSearchResult.businesses` contains `VerifiedBusiness(manifest, sources)` objects, with no directory
tool definitions substituted into the manifest. Errors are isolated per provider/domain in `errors`; useful
results survive another provider's failure. Provider search and manifest verification each have a bounded
phase budget. A changed digest/key is not automatically fraudulent: the client retrieves fresh canonical
metadata, follows its configured pin/rotation policy and filters again. A live business no longer matching
the query is excluded. The directory key never becomes an independently trusted pin.

## Security and privacy boundaries

The index and client require `WAPClient(block_private_networks=True)`. `allow_loopback=True` is only for
explicit local development. Canonical retrieval bypasses cache and rejects noncanonical/legacy fallback
locations and redirects. Advertised endpoints are also checked against the network policy. Business discovery
does not relax TLS, manifest signatures/domain binding, expiry, optional pins/DNS anchoring, admission,
authentication, consent, idempotency or loop protection. Directory-provided URL/metadata fields are validated;
clients choose the canonical URL themselves. Schemas cannot trigger remote reference retrieval on this path.

**Network limit:** the inherited resolver validates DNS before opening HTTP connections; it does not pin
the connection to that resolved address. Public deployments MUST add an outbound proxy/firewall that blocks
private, loopback, link-local and metadata-service destinations, including during DNS rebinding. Do not expose
an unrestricted directory fetcher to the Internet. The reference registration token and rate/concurrency
budgets reduce abuse but do not replace egress control. A legal business identity, honest capabilities and
correct execution cannot be established from self-signed metadata alone.

Only public metadata is indexed, with strict bounds and no free-text intent, user identity or customer data.
Send the least precise geographic filter sufficient for a search; a provider necessarily sees the query and
network origin. The reference implementation does not store queries or log bodies/tokens. Deployments must
set their own access-log retention and abuse monitoring without collecting unnecessary user data. Public
search can still be enumerated within quotas; no protocol can guarantee prevention of distributed scraping.

All names, capabilities, filters, policy text and signed replies remain third-party data. Signatures establish
attribution, not truth or safety. The MCP bridge sanitizes and labels site text. Directory search never adds
site tools or grants site approval; `wap_discover` and the existing action-confirmation flow still apply.
Directory poisoning may suppress results; independent verification cannot guarantee completeness or fairness.

## Limits and extension points

The vocabulary and directory HTTP format are experimental. Providers may implement durable indexes and
geospatial search; future revisions may define schema compatibility proofs and asynchronous workflow metadata.
The memory index is not a multi-worker production database. The restaurant example's in-memory booking ledger
is not crash-durable: production tools must commit inventory, ownership and idempotency in their transactional
business database. Do not infer exactly-once external side effects from HTTP retries alone.
