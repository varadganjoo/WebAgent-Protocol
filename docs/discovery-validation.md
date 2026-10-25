# Universal capability discovery: implementation and validation

Local validation completed on 2026-10-24, against the checkout based on
`8f70702fbc1e204b938bd7996e9a4967f37becab`, before feature-branch publication. No release or deployment
was performed.

Runtime/test snapshot SHA256: `1e0b4e9b263d965df9c564dd657ac65ed41a9564878c5386b9da5bf5424521d5`.
This identifies the five-environment matrix below. Before committing, the test-vector JSON file's CRLF
line endings were normalized to the repository's required LF convention; its parsed values and signed
canonical bytes did not change. The resulting commit-source snapshot is
`325f90c3c5fd4af68b4fe6adb4b9bba1c35b75d7dc2e62b795ea8716d3b9fa33`. The full Windows suite was rerun
against disposable Redis after normalization: **376 passed, zero skips, 49.61 seconds**. Ruff, vector
generation checks and the 24-check JavaScript verifier passed again. Python implementation files were
unchanged from the matrix snapshot.
The snapshot hashes the sorted relative paths and SHA256 file contents of `pyproject.toml`, all Python
sources under `wap/` and `tests/`, test vectors/JavaScript verifier, vector generator and both restaurant
examples. Documentation-only completion notes are excluded. The implementation is unreleased; the existing
package version remains 0.2.0. Build artifacts are local validation artifacts, not a newly published 0.2.0.

## Architecture delivered

- The existing signed manifest, canonical JSON, direct invocation, admission, authentication, consent,
  sessions, idempotency, loop protection, errors and structured results remain the execution architecture.
- Optional signed 1.1 manifest metadata describes public business discovery, semantic operations/schema
  versions, and advertised execution type. Unchanged manifests/messages retain 1.0 and old signed bytes.
- Configurable directory providers support structured category/operation/capability/version, area/point/radius
  and public-attribute queries. The local memory implementation, HTTP adapter and reference FastAPI service
  share one small interface. Registration derives metadata from the canonical signed business manifest.
- Federation independently re-fetches canonical manifests, applies key/domain/network/expiry checks and
  authoritative filters, isolates failures and deduplicates domains. Provider keys are never trusted pins.
- Fourteen reference operations support conservative exact matching and direct schema-checked invocation.
  Known mutation semantics cannot claim weaker effects to skip consent. No business LLM is required.
- MCP exports/imports optional namespaced capability metadata; the bridge optionally exposes business search.
  Existing domain discovery, dynamic tool registration and approval flow continue to work.

## New public APIs and wire metadata

| Surface | Additions |
| --- | --- |
| `Capability` | optional `semantic_operation`, `semantic_schema_version`, `execution` |
| `AgentManifest` | optional `discovery`; explicit supported manifest version `1.1` |
| `wap.spec.discovery` | `BusinessDiscovery`, `ServiceArea`, `GeoPoint` |
| `wap.spec.semantics` | `reference_operations()`, `match_operation(...)`, reference operation constants |
| `WAPServer` | optional `discovery=...`; `action` accepts optional semantic/schema/execution metadata |
| `WAPClient` | `search_businesses(query, providers, timeout=...)`; `invoke_operation(domain, operation, payload, schema_version=..., session_id=..., auth_token=..., idempotency_key=...)` |
| `wap.directory` | `DirectoryProvider`, `MemoryDirectory`, `HTTPDirectory`, `DirectoryClient`, query/page/entry/result types, `DirectoryError` |
| Reference service | `create_directory_app(directory, registration_token=...)`; POST `/wap-directory/v1/search` and `/wap-directory/v1/registrations` |
| MCP | optional `_meta` keys `io.webagent/semantic_operation`, `io.webagent/semantic_schema_version`, `io.webagent/execution`; optional `wap_search_businesses` tool and `WAP_DIRECTORIES` setting |

Schemas and transaction effects/auth fields are reused. Unknown/custom semantic identifiers remain visible
through ordinary schema-based discovery. Automatic matching supports exact known schema 1.0; unsupported or
ambiguous operations fail closed. Existing `invoke` defaults are unchanged; semantic writes require a hook.

## Demonstrated result

`python examples/restaurant_demo.py --approve` found these options without restaurant domains on the personal side:

| Verified business | Actual local tool | Standard operation | Offered table |
| --- | --- | --- | --- |
| Harbour Garden | `reserve_table` | `hospitality.restaurant.reservation.create.v1` | 4 people, outdoor, 2026-10-25 19:00 UTC+11 |
| Sydney Courtyard | `create_booking` | same operation/schema 1.0 | 4 people, outdoor, 2026-10-25 19:15 UTC+11 |

The client requested approval and obtained a verified structured `status="confirmed"` response from Harbour
Garden. Tests cover decline, duplicate retry, concurrent capacity rejection and cancellation ownership.
The same journey also passed over real HTTP with three loopback services on ports 8800–8802, which were
stopped after verification. No real payments, accounts or reservations were created. The injected business
clock is fixed; manifest freshness and request security continue to use real protocol time.

## Validation evidence

Environment: Windows, dedicated `.venv`, CPython 3.14.7; Linux/amd64 in Docker Desktop, with separate
container-local venvs for Python 3.11–3.14 and Node.js 24.22.1. A disposable Redis 8.10.2 container provided
shared test state; Windows accessed a random loopback-only port, while Linux containers used an isolated
Docker network. No Redis subscription or cloud service was used. Official image digest:
`redis@sha256:0bf6577d7774e592b29d093e3ac9390eb91e13d72c21e506afce736de5e0eeb0`.
Python 3.11.0/Pydantic 2.12.0 wheel validation used a separate core-only venv with isolated imports.

| Check | Result | Evidence |
| --- | --- | --- |
| Windows suite after final runtime edit | PASS | `python -m pytest -q -rs`, with `WAP_TEST_REDIS_URL`: **376 passed, zero skips**, 59.57 seconds |
| Static checks | PASS | `ruff check .`; `ruff format --check .` |
| Current test vectors | PASS | `python examples/generate_test_vectors.py --check` |
| Independent JavaScript verification | PASS | `node tests/interop/verify_vectors.mjs docs/test-vectors.json`: **24 checks** |
| Existing signed-vector compatibility | PASS | Every pre-existing vector entry exactly equals the base revision; only the additional discovery vector was added |
| Package build | PASS | `python -m build --no-isolation`: wheel and sdist built successfully |
| Core-only wheel at minimum versions | PASS | Installed current wheel on Python 3.11/Pydantic 2.12.0; legacy/1.1 signatures and verified semantic invocation passed, with no MCP/FastAPI installed |
| CLI acceptance demonstration | PASS | Both independently named restaurants discovered, structured availability, approval and verified confirmation |
| Real loopback HTTP acceptance | PASS | Reference directory plus two live restaurant services; no business-side LLM |
| Existing benchmark smoke test | PASS | `python examples/benchmark.py` completed; no new universal performance claim inferred |
| Dependency audit | PASS for resolved environment | `pip-audit 2.10.1`, current advisory lookup on 2026-10-24: **68 packages, zero known vulnerabilities reported**; raw `dependency-audit.json` |
| Secret review | PASS within changed scope | Manual pattern scan and contextual review; only existing negative URL fixtures matched, no production credentials added; fixed vector keys and fictional demo token are public test data |
| Independent source review | PASS after corrections | Three important findings reproduced and corrected with failing-then-passing tests; no critical findings reported |
| Redis integrations | PASS | All 16 previously skipped Redis tests ran in the full suites: store contract, atomic concurrency, TTL, Lua rate-limit parity, shared sessions, rate limits, single-use PoW and cross-instance idempotency |
| Explicit unavailable test Redis | PASS (negative check) | A configured unreachable URL produces a connection failure with zero skips; the assertion harness checked the expected pytest failure |
| Four real HTTP workers sharing Redis | PASS | Existing load script, 8 users/5 seconds, PoW difficulty 2: 91 successful requests, zero errors; replay accepted **1/24**, PoW reuse accepted **1/24**. Local correctness smoke, not a deployment capacity measurement |
| Linux Python matrix | PASS | Full suites, lint/format, vectors/Node verification, restaurant demo, benchmark smoke and wheel/sdist builds; per-runtime results below |
| macOS | NOT RUN locally | No macOS runtime on this Windows host; the existing GitHub Actions matrix covers macOS after PR publication |
| Deployment egress/TLS/durability/load | NOT VERIFIED | No deployment requested; operator controls remain required |
| Browser UI/accessibility/IaC | N/A | No UI or infrastructure deployment was added |
| Formal ASVS/organisation compliance | NOT CLAIMED | General OWASP/enterprise review applied; the installed guidance pack's indexed `data/asvs` supplement was absent |

The first sandbox test attempts hung before application code because Windows asyncio's socket-pair creation
was blocked. Tests were rerun with loopback permission, and the task's stalled processes were stopped. A
sandbox temp-directory failure during packaging was resolved by using a workspace-local build temp directory.
These were environment failures, not suppressed test failures. All final executed acceptance/static/build
checks above passed; macOS and deployment controls remain unverified.

The Docker follow-up replaced the original Windows result of 360 passed/16 skipped with full Redis
coverage. `tests/test_storage.py` now optionally uses `WAP_TEST_REDIS_URL`, falling back to its existing
throwaway `redis-server` fixture when unset. The README includes disposable Docker instructions. Tests
use distinct key prefixes and never flush an operator's database; use a disposable test instance anyway.

The first Linux Python 3.11 run found an uncaught `RecursionError` in registration JSON parsing for the
existing 2,000-level nested-input regression. It initially reported 375 passed/1 failed. Registration now
returns the existing `422 invalid_registration` response for this parser failure. The same test and full
matrix passed after the fix; authentication, body bounds and rate limits were retained.

Final matrix results (pytest reports rounded to hundredths of a second):

| Environment | Python | Passed | Failed/errors | Skipped | Seconds |
| --- | --- | --- | --- | --- | --- |
| Windows | 3.14.7 | 376 | 0 | 0 | 59.57 |
| Linux container | 3.11.16 | 376 | 0 | 0 | 22.15 |
| Linux container | 3.12.15 | 376 | 0 | 0 | 23.22 |
| Linux container | 3.13.15 | 376 | 0 | 0 | 22.07 |
| Linux container | 3.14.7 | 376 | 0 | 0 | 21.45 |

Every Linux run copied the checkout into a writable container workspace from a read-only source mount,
verified the runtime/test snapshot above, created a venv and installed `.[all,dev]`. Each then ran pytest,
Ruff lint/format, test-vector generation checks, the 24-check Node verifier, the explicitly approved
fictional restaurant demo, benchmark smoke and isolated wheel/sdist builds. This checks Linux under Docker,
not every Linux distribution or a macOS host. Fresh Windows packaging and minimum-version core-wheel
validation also passed after the parser fix.

Raw JUnit, dependency lists, build and command logs are retained locally under the ignored
`.venv/validation/results/` directory. The negative unreachable-Redis JUnit intentionally contains its
expected connection failure; it is separate from the five passing suite reports. Disposable test
containers, their network and temporary validation image tags were removed. Downloaded base-image/build
caches remain available for subsequent tests; no existing containers or application data were modified.

## Independent review corrections and additional regression fixes

- Reject known reservation/appointment mutations advertised as `read`; require financial effects for known
  order creation. Preserve signed metadata rather than rewriting it. The no-hook/mislabelled-write test failed
  before the change and passes afterward.
- Copy only party/time/seating from availability data; derive domain/name/tool from the verified manifest.
  A signed response with extra identity fields can no longer redirect booking selection.
- Catch ordinary exceptions at provider/source boundaries, report sanitized failures and preserve cancellation.
  Healthy provider results survive `RuntimeError` and `OSError` from another provider.
- Use the resolver's returned verified manifest record, so `cache_ttl=0` does not break canonical registration.
- Bound serialized pages as well as item counts, keeping large valid results below the HTTP response budget.
- Always validate actual business input constraints on semantic calls, including when legacy payload validation
  is disabled. Unresolvable output-schema references produce a typed `invalid_semantic_result` error.
- Handle deeply nested registration JSON consistently on Python 3.11 by catching the parser's `RecursionError`
  at the existing invalid-registration boundary; the existing adversarial input test caught the regression.

The reviewer accepted the explicitly documented deployment egress and durability boundaries; they were not
independently verified. No minor findings were deferred.

## Files created (18)

- `wap/spec/discovery.py`, `wap/spec/semantics.py`
- `wap/directory/__init__.py`, `wap/directory/models.py`, `wap/directory/providers.py`,
  `wap/directory/client.py`, `wap/directory/server.py`
- `examples/restaurant_server.py`, `examples/restaurant_demo.py`
- `tests/test_semantics.py`, `tests/test_directory.py`, `tests/test_restaurant_discovery.py`,
  `tests/test_discovery_mcp.py`
- `docs/discovery-design.md`, `docs/discovery.md`, `docs/restaurant-tutorial.md`,
  `docs/discovery-validation.md`, `docs/dependency-audit.json`

## Files modified (16)

- `wap/spec/models.py`
- `wap/server/app.py`, `wap/server/mcp_endpoint.py`, `wap/server/mcp_import.py`
- `wap/client/resolver.py`, `wap/client/session.py`, `wap/mcp/bridge.py`
- `examples/generate_test_vectors.py`, `tests/interop/verify_vectors.mjs`, `docs/test-vectors.json`
- `tests/test_storage.py` (optional disposable test Redis URL)
- `README.md`, `CHANGELOG.md`, `docs/spec_rfc.md`, `docs/mcp_extension.md`, `docs/configuration.md`

No runtime dependencies were added and no existing tests were removed or weakened.

## Compatibility, trade-offs and remaining limits

The central compatibility decision is explicit 1.1 enriched manifests. Strict older readers reject them,
so businesses adopting metadata need updated clients. Unchanged 1.0 manifests, signatures, interaction
messages, direct domain discovery, public APIs and MCP behavior are retained. The signed representation is
never stripped or silently downgraded. Exact operation/schema matching favors explicit support over guessed
substitutability; custom/unknown capabilities remain callable through ordinary schemas.

This is experimental interoperability, not a globally adopted directory/vocabulary. The reference index is
bounded single-process memory, offset pages are not snapshots, and geographic coverage uses simple areas and
point radius rather than geocoded polygons. Directory results cannot establish legal identity, honest claims,
completeness or ranking fairness. Semantic/execution declarations cannot certify business behavior.

For public hosting, the deployment owner must configure TLS and outbound egress restrictions against DNS
rebinding: the inherited DNS precheck does not pin the eventual connection address. Production booking tools
must persist ownership, inventory and idempotency transactionally in their business database. The demo ledger
and directory intentionally reset on restart. Signing-key ownership means demo callers must retain their key;
anonymous native MCP booking is refused, while the signed WAP bridge works.

Recommended later extensions are durable/provider-specific indexes, transactional real-business adapters,
operator admission/token lifecycle and observability, and evidence from independent deployments. Schema
subtyping, arbitrary intent ranking, asynchronous jobs, offer lifecycles, binary transport and additional LLM
calls were deliberately excluded from this extension. No production readiness certification is asserted.
