"""Run: python examples/restaurant_demo.py [--approve]

Runs the complete HTTP/JSON WAP journey in process using ASGI transports. The explicit --approve flag
is a simulated user approval for fictional bookings; otherwise asks interactively. No external services.
Use --serve to expose the reference directory and both restaurants on loopback ports 8800-8802.
"""

from __future__ import annotations

import argparse
import asyncio
import json
from contextlib import asynccontextmanager
from datetime import datetime, timedelta, timezone

import httpx

from examples.restaurant_server import create_restaurant
from wap import WAPClient
from wap.directory import DirectoryQuery, HTTPDirectory, MemoryDirectory, ServiceArea
from wap.directory.server import create_directory_app
from wap.spec.crypto import generate_keypair
from wap.spec.semantics import AVAILABILITY, RESERVATION_CREATE, match_operation

FIXED_NOW = datetime(2026, 10, 24, 12, tzinfo=timezone(timedelta(hours=11)))


class LocalTransport(httpx.AsyncBaseTransport):
    def __init__(self, apps):
        self.apps = apps

    async def handle_async_request(self, request):
        authority = f"{request.url.host}:{request.url.port}"
        if authority not in self.apps:
            raise httpx.ConnectError("unknown local demonstration service", request=request)
        return await httpx.ASGITransport(app=self.apps[authority]).handle_async_request(request)


def restaurants():
    return [
        create_restaurant(
            "127.0.0.1:8801",
            "Harbour Garden",
            clock=lambda: FIXED_NOW,
            booking_name="reserve_table",
            private_key=generate_keypair().private_key,
        ),
        create_restaurant(
            "127.0.0.1:8802",
            "Sydney Courtyard",
            clock=lambda: FIXED_NOW,
            booking_name="create_booking",
            minutes=15,
            private_key=generate_keypair().private_key,
        ),
    ]


@asynccontextmanager
async def local_services(confirm=lambda request: True):
    services = restaurants()
    apps = {server.domain: app for server, app, state in services}
    async with WAPClient(
        transport=LocalTransport(apps), block_private_networks=True, allow_loopback=True, confirm=confirm
    ) as client:
        directory = MemoryDirectory(client)
        for server, _app, _state in services:
            await directory.register(server.domain)
        apps["127.0.0.1:8800"] = create_directory_app(directory, registration_token="fictional-development-only")
        yield client, {"local": HTTPDirectory("http://127.0.0.1:8800", http=client.http)}, services


async def find_and_book(client, providers):
    desired = (FIXED_NOW + timedelta(days=1)).replace(hour=19, minute=0)
    found = await client.search_businesses(
        DirectoryQuery(
            category="restaurant",
            operation=RESERVATION_CREATE,
            semantic_schema_version="1.0",
            area=ServiceArea(country="AU", locality="Sydney"),
        ),
        providers,
    )
    if not found.businesses:
        raise RuntimeError(f"no verified restaurants found: {found.errors}")
    options = []
    for business in found.businesses:
        manifest = business.manifest
        available = await client.invoke_operation(
            manifest.domain, AVAILABILITY, {"party_size": 4, "start_time": desired.isoformat()}
        )
        for slot in available.structured_data["slots"]:
            options.append(
                {
                    **{key: slot[key] for key in ("party_size", "start_time", "seating")},
                    "domain": manifest.domain,
                    "name": manifest.name,
                    "tool": match_operation(manifest, RESERVATION_CREATE)[0].id,
                }
            )
    # Outdoor is a preference; retain comparable indoor options when no outdoor slot is available.
    options.sort(key=lambda o: (o["seating"] != "outdoor", o["start_time"], o["domain"]))
    comparable = [
        next(o for o in options if o["domain"] == b.manifest.domain)
        for b in found.businesses
        if any(o["domain"] == b.manifest.domain for o in options)
    ]
    if not options:
        raise RuntimeError("no matching tables available")
    chosen = options[0]
    print(json.dumps({"options": comparable}, indent=2))
    confirmation = await client.invoke_operation(
        chosen["domain"],
        RESERVATION_CREATE,
        {k: chosen[k] for k in ("party_size", "start_time", "seating")},
        idempotency_key="demo-booking-0001",
    )
    return {
        "options": comparable,
        "confirmation": confirmation.structured_data,
        "verified": confirmation.verified,
        "domain": chosen["domain"],
    }


async def demo(confirm):
    async with local_services(confirm=confirm) as (client, providers, services):
        return await find_and_book(client, providers)


async def serve():
    import os

    import uvicorn

    token = os.environ.get("WAP_DIRECTORY_REGISTRATION_TOKEN")
    if not token:
        raise ValueError("set WAP_DIRECTORY_REGISTRATION_TOKEN (at least 16 characters)")
    services = restaurants()
    async with WAPClient(block_private_networks=True, allow_loopback=True) as client:
        directory = MemoryDirectory(client)
        apps = [create_directory_app(directory, registration_token=token), *(app for _, app, _ in services)]
        servers = [
            uvicorn.Server(uvicorn.Config(app, host="127.0.0.1", port=8800 + i, log_level="warning"))
            for i, app in enumerate(apps)
        ]
        tasks = [asyncio.create_task(server.serve()) for server in servers]
        try:
            for _ in range(100):
                if all(server.started for server in servers):
                    break
                if any(task.done() for task in tasks):
                    raise RuntimeError("a local service failed to start")
                await asyncio.sleep(0.1)
            else:
                raise TimeoutError("local services did not start within 10 seconds")
            for server, _, _ in services:
                await directory.register(server.domain)
            print("Directory http://127.0.0.1:8800; restaurants on ports 8801 and 8802. Ctrl+C to stop.")
            await asyncio.gather(*tasks)
        finally:
            for server in servers:
                server.should_exit = True
            await asyncio.gather(*tasks, return_exceptions=True)


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--approve", action="store_true", help="simulate explicit approval of the fictional booking")
    parser.add_argument("--serve", action="store_true", help="serve the directory and restaurants on loopback")
    args = parser.parse_args()
    if args.serve:
        asyncio.run(serve())
        return

    def confirm(request):
        print(request.summary())
        return args.approve or input("Approve this fictional reservation? [y/N] ").strip().lower() == "y"

    print(json.dumps(asyncio.run(demo(confirm)), indent=2))


if __name__ == "__main__":
    main()
