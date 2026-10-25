# Make your restaurant bookable by any WAP-compatible AI agent without running an LLM

This tutorial targets clients implementing the experimental directory/semantic extension. Existing WAP and
MCP clients still discover tools by domain; interoperability with every deployed host is not claimed.

## Run the complete demonstration

From the repository root, create/activate a venv and install the existing extras:

```bash
python -m venv .venv
# Windows: .venv\Scripts\activate
# macOS/Linux: source .venv/bin/activate
python -m pip install -e ".[all,dev]"
python examples/restaurant_demo.py
```

It prints two comparable Sydney options, then asks for approval before booking. `--approve` explicitly
simulates approval for automated demonstrations. Both restaurants have fictional inventory and ephemeral
keys. The injected clock is 2026-10-24 at 12:00 with UTC+11, so the requested date is always October 25.
Harbour Garden offers 19:00 via `reserve_table`; Sydney Courtyard offers 19:15 via `create_booking`.
Both advertise `hospitality.restaurant.reservation.create.v1` with semantic schema `1.0`. No LLM runs.
The default demonstration serializes real HTTP/JSON messages through an in-process ASGI transport.

For real loopback HTTP, start the same three applications:

```powershell
$env:WAP_DIRECTORY_REGISTRATION_TOKEN = 'choose-a-long-local-development-token'
python examples/restaurant_demo.py --serve
```

On macOS/Linux use `export WAP_DIRECTORY_REGISTRATION_TOKEN=...`. Ports 8800, 8801 and 8802 must be free.
Keep the process running. It registers both signed manifests with the directory at startup. Ctrl+C stops all
three servers. A second terminal can act as a personal agent:

```python
import asyncio
from wap import WAPClient
from wap.directory import HTTPDirectory
from examples.restaurant_demo import find_and_book


async def main():
    async def confirm(request):
        return input(request.summary() + " Approve? [y/N] ").lower() == "y"

    async with WAPClient(block_private_networks=True, allow_loopback=True, confirm=confirm) as client:
        providers = {"local": HTTPDirectory("http://127.0.0.1:8800", http=client.http)}
        result = await find_and_book(client, providers)
        print(result)


asyncio.run(main())
```

The personal side knows only the configured directory origin. `find_and_book` has no restaurant domain list.
It searches, verifies current business manifests, checks structured availability, prefers outdoor seating,
asks for consent, and invokes the business's actual local tool. A declined confirmation sends no booking.
The final confirmation is verified against the domain manifest key.

## Publish your tools

The complete deterministic business implementation is [`examples/restaurant_server.py`](../examples/restaurant_server.py).
It exposes availability, creation, cancellation and documented dietary/accessibility policies through existing
WAP infrastructure, with validation, signed errors, proof-of-work, rate limits, ownership and idempotency.

For an application with an existing booking service:

```python
from datetime import datetime
from typing import Annotated
from pydantic import Field
from wap.server import WAPServer
from wap.spec.discovery import BusinessDiscovery, ServiceArea

wap = WAPServer(
    name="Your Restaurant",
    domain="restaurant.example",
    private_key=KEY,
    discovery=BusinessDiscovery(category="restaurant", service_areas=[ServiceArea(country="AU", locality="Sydney")]),
)


@wap.action(
    name="create_booking",
    effects="write",
    execution="deterministic",
    semantic_operation="hospitality.restaurant.reservation.create.v1",
    semantic_schema_version="1.0",
)
async def create_booking(party_size: Annotated[int, Field(ge=1, le=12)], start_time: datetime, seating: str) -> dict:
    return await booking_service.reserve(party_size, start_time, seating)


wap.mount(existing_fastapi_app)
```

`KEY`, `booking_service` and `existing_fastapi_app` are your application's existing dependencies; this fragment
illustrates integration, while the full demonstration above is executable unchanged. Meet the reference output
contract (`reservation_id`, `party_size`, `start_time`, `seating`, `status`) and publish your actual constraints.
The discovery metadata is signed together with the rest of the 1.1 manifest.

Supply durable keys, TLS, an authenticated business workflow and transactional inventory/idempotency storage.
The example uses signing-key ownership for cancellations, so callers must retain their key. Anonymous native
MCP writes cannot establish that ownership and are refused in this example; use the signed WAP bridge or add
business authentication to a native MCP integration. Policies are documented claims, not dietary guarantees.

## Register and search

An operator hosts `create_directory_app(MemoryDirectory(client), registration_token=...)`, with a strict-network
WAP client and egress controls. In production, owners submit only their domain using an operator-approved token:

```bash
curl -X POST https://directory.example/wap-directory/v1/registrations \
  -H "Authorization: Bearer $DIRECTORY_TOKEN" -H "Content-Type: application/json" \
  -d '{"domain":"restaurant.example"}'
```

The directory retrieves the canonical manifest itself. Refresh registration before its advertised expiry.
The business can register with several independent providers; no particular provider is mandatory.

```python
from wap.directory import DirectoryQuery, HTTPDirectory, ServiceArea
from wap.spec.semantics import RESERVATION_CREATE, match_operation

providers = {"community": HTTPDirectory("https://directory.example", http=client.http)}
found = await client.search_businesses(
    DirectoryQuery(
        category="restaurant",
        operation=RESERVATION_CREATE,
        semantic_schema_version="1.0",
        area=ServiceArea(country="AU", locality="Sydney"),
        filters={"outdoor": True},
    ),
    providers,
)
for business in found.businesses:
    print(business.manifest.domain, [c.id for c in match_operation(business.manifest, RESERVATION_CREATE)])
```

For a selected option, call `client.invoke_operation(domain, RESERVATION_CREATE, validated_payload,
idempotency_key=stable_booking_attempt_key)`. Reuse the key for retries of the same intended booking. This calls
the matched local capability directly. Unknown semantics require normal schema-based discovery and invocation.
The server never needs to interpret a natural-language booking request.

Existing MCP servers can participate through `include_mcp`/`import_mcp`, as before. Optional namespaced tool
metadata is described in [the MCP binding](mcp_extension.md). The bridge exposes structured business search
when `WAP_DIRECTORIES` is configured; subsequent site discovery and action approval use the existing flow.
Read the [directory trust model and limits](discovery.md) before public hosting.
