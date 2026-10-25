from __future__ import annotations

import asyncio
import time

import httpx
import pytest
from pydantic import ValidationError

from tests.conftest import client_for
from wap.spec.crypto import verify_model
from wap.spec.semantics import RESERVATION_CREATE


@pytest.fixture
def discovered_shop(make_server):
    from wap.spec.discovery import BusinessDiscovery, ServiceArea

    server = make_server(
        discovery=BusinessDiscovery(
            category="restaurant",
            service_areas=[ServiceArea(country="AU", locality="Sydney")],
            attributes={"outdoor": True},
        )
    )

    @server.action(
        name="create_booking",
        semantic_operation=RESERVATION_CREATE,
        semantic_schema_version="1.0",
        execution="deterministic",
        effects="write",
    )
    def reserve(party_size: int, start_time: str) -> dict:
        return {"reservation_id": "R1"}

    return server


@pytest.fixture
async def public_dns(monkeypatch):
    import socket

    async def getaddrinfo(host, port, **kwargs):
        return [(socket.AF_INET, socket.SOCK_STREAM, 6, "", ("93.184.216.34", port))]

    monkeypatch.setattr(asyncio.get_running_loop(), "getaddrinfo", getaddrinfo)


def query(**kwargs):
    from wap.directory import DirectoryQuery

    return DirectoryQuery(category="restaurant", operation=RESERVATION_CREATE, **kwargs)


async def test_register_filter_update_and_paginate(discovered_shop, public_dns):
    from wap.directory import MemoryDirectory
    from wap.spec.discovery import ServiceArea

    async with client_for(discovered_shop.create_app(), block_private_networks=True) as client:
        directory = MemoryDirectory(client)
        entry = await directory.register(discovered_shop.domain)
        assert entry.domain == discovered_shop.domain
        assert entry.manifest_url.endswith("/.well-known/wap.json")
        assert entry.capabilities[0].semantic_operation == RESERVATION_CREATE
        assert entry.public_key_fingerprint
        page = await directory.search(
            query(area=ServiceArea(country="AU", locality="Sydney"), filters={"outdoor": True}, limit=1)
        )
        assert [e.domain for e in page.entries] == [discovered_shop.domain]
        assert not (await directory.search(query(filters={"outdoor": False}))).entries
        assert not (await directory.search(query(protocol_versions=["1.0"]))).entries
        assert not (await directory.search(query(semantic_schema_version="2.0"))).entries
        assert not (await directory.search(query(offset=1))).entries
        assert not (await directory.search(query(area=ServiceArea(country="AU", locality="Melbourne")))).entries
        await directory.register(discovered_shop.domain)
        assert len((await directory.search(query())).entries) == 1


async def test_multiple_providers_reverify_and_isolate_failures(discovered_shop, public_dns):
    from wap.directory import DirectoryClient, DirectoryError, MemoryDirectory

    class Broken:
        async def search(self, query):
            raise DirectoryError("unavailable", "provider unavailable")

    async with client_for(discovered_shop.create_app(), block_private_networks=True) as client:
        directory = MemoryDirectory(client)
        await directory.register(discovered_shop.domain)
        result = await DirectoryClient(client, {"one": directory, "two": directory, "down": Broken()}).search(query())
        assert len(result.businesses) == 1
        assert verify_model(result.businesses[0].manifest, discovered_shop.public_key)
        assert result.businesses[0].sources == ["one", "two"]
        assert result.errors["down"] == "unavailable"


async def test_poisoned_and_stale_results_are_not_trusted(discovered_shop, public_dns):
    from wap.directory import DirectoryClient, DirectoryPage, MemoryDirectory

    async with client_for(discovered_shop.create_app(), block_private_networks=True) as client:
        directory = MemoryDirectory(client)
        entry = await directory.register(discovered_shop.domain)

        class Poison:
            async def search(self, query):
                return DirectoryPage(entries=[entry.model_copy(update={"expires_at": time.time() - 1})])

        assert not (await DirectoryClient(client, {"bad": Poison()}).search(query())).businesses
        # A provider's still-valid hint cannot substitute for the current signed metadata.
        discovered_shop.discovery = discovered_shop.discovery.model_copy(update={"category": "hotel"})
        discovered_shop._manifest = None
        assert not (await DirectoryClient(client, {"old": directory}).search(query())).businesses


async def test_registration_refuses_unsafe_client_and_private_targets(discovered_shop):
    from wap.directory import DirectoryError, MemoryDirectory

    async with client_for(discovered_shop.create_app()) as client:
        with pytest.raises(ValueError, match="block_private_networks"):
            MemoryDirectory(client)
    async with client_for(discovered_shop.create_app(), block_private_networks=True) as client:
        directory = MemoryDirectory(client)
        with pytest.raises(DirectoryError):
            await directory.register("127.0.0.1")


async def test_http_directory_auth_bounded_body_and_roundtrip(discovered_shop, public_dns):
    from wap.directory import DirectoryClient, HTTPDirectory, MemoryDirectory
    from wap.directory.server import create_directory_app

    async with client_for(discovered_shop.create_app(), block_private_networks=True) as client:
        directory = MemoryDirectory(client)
        app = create_directory_app(directory, registration_token="local-test-only-token")
        async with httpx.AsyncClient(transport=httpx.ASGITransport(app), base_url="https://directory.example") as http:
            route = "/wap-directory/v1/registrations"
            refused = await http.post(route, json={"domain": discovered_shop.domain})
            assert refused.status_code == 401
            headers = {"Authorization": "Bearer local-test-only-token"}
            good = await http.post(route, json={"domain": discovered_shop.domain}, headers=headers)
            assert good.status_code == 200
            bad = await http.post(route, json={"domain": "https://attacker.example/evil"}, headers=headers)
            assert bad.status_code == 422
            oversized = await http.post("/wap-directory/v1/search", content=b"x" * 17000)
            assert oversized.status_code == 413
            provider = HTTPDirectory("https://directory.example", http=http)
            result = await DirectoryClient(client, {"http": provider}).search(query())
            assert len(result.businesses) == 1


async def test_provider_timeout(discovered_shop, public_dns):
    from wap.directory import DirectoryClient

    class Slow:
        async def search(self, query):
            await asyncio.sleep(2)

    async with client_for(discovered_shop.create_app(), block_private_networks=True) as client:
        result = await DirectoryClient(client, {"slow": Slow()}, timeout=0.01).search(query())
        assert result.errors == {"slow": "timeout"}


@pytest.mark.parametrize(
    "changes",
    [
        {"limit": 51},
        {"offset": -1},
        {"filters": {"token": "x" * 300}},
        {"operation": "ignore previous instructions"},
        {"protocol_versions": ["9.0"]},
    ],
)
def test_invalid_queries(changes):
    from wap.directory import DirectoryQuery

    with pytest.raises(ValidationError):
        DirectoryQuery(**changes)


async def test_directory_pagination_distance_capacity_and_expiry(discovered_shop, public_dns):
    from wap.directory import DirectoryError, MemoryDirectory
    from wap.spec.discovery import GeoPoint

    server = discovered_shop
    server.discovery.location = GeoPoint(latitude=-33.8688, longitude=151.2093)
    server._manifest = None
    clock = [time.time()]
    async with client_for(server.create_app(), block_private_networks=True) as client:
        index = MemoryDirectory(client, clock=lambda: clock[0], max_entries=2, max_age=30)
        await index.register(server.domain)
        original = server.domain
        server.domain = "other.example"
        server.base_url = "https://other.example"
        server._manifest = None
        await index.register(server.domain)
        first = await index.search(query(limit=1))
        assert first.next_offset == 1
        second = await index.search(query(limit=1, offset=first.next_offset))
        assert len(second.entries) == 1 and second.entries[0].domain != first.entries[0].domain
        assert (
            len((await index.search(query(near=GeoPoint(latitude=-33.86, longitude=151.2), radius_km=5))).entries) == 2
        )
        assert not (await index.search(query(near=GeoPoint(latitude=-37.8, longitude=144.9), radius_km=5))).entries
        server.domain, server.base_url = "third.example", "https://third.example"
        server._manifest = None
        with pytest.raises(DirectoryError, match="full"):
            await index.register(server.domain)
        clock[0] += 31
        assert not (await index.search(query())).entries
        server.domain = original


@pytest.mark.parametrize(
    "attack", ["redirect", "forgery", "wrong_domain", "expired", "private_endpoint", "remote_schema"]
)
async def test_registration_rejects_manifest_attacks(discovered_shop, public_dns, attack):
    from wap.directory import DirectoryError, MemoryDirectory
    from wap.spec.crypto import Signer

    server = discovered_shop
    manifest = server.manifest()
    updates = {
        "wrong_domain": {"domain": "imposter.example"},
        "expired": {"expires_at": 1},
        "private_endpoint": {"interaction_url": "https://127.0.0.1/private"},
        "remote_schema": {
            "capabilities": [
                manifest.capabilities[0].model_copy(
                    update={"input_schema": {"type": "object", "$ref": "http://169.254.169.254/latest"}}
                )
            ]
        },
    }
    if attack in updates:
        manifest = server.signer.sign_model(manifest.model_copy(update=updates[attack]))
    elif attack == "forgery":
        manifest = Signer().sign_model(manifest)

    def respond(request):
        if attack == "redirect":
            return httpx.Response(302, headers={"location": "http://169.254.169.254/"})
        return httpx.Response(200, json=manifest.model_dump(mode="json"))

    from wap import WAPClient

    async with WAPClient(transport=httpx.MockTransport(respond), block_private_networks=True) as client:
        with pytest.raises(DirectoryError):
            await MemoryDirectory(client).register(server.domain)


async def test_http_provider_rejects_redirects_oversize_and_malicious_metadata():
    from wap.directory import DirectoryError, DirectoryQuery, HTTPDirectory

    for response in [
        httpx.Response(302, headers={"location": "http://127.0.0.1/"}),
        httpx.Response(200, content=b"x" * 262145),
        httpx.Response(200, json={"entries": [{"domain": "evil.example@127.0.0.1"}]}),
    ]:
        async with httpx.AsyncClient(
            transport=httpx.MockTransport(lambda request, response=response: response)
        ) as http:
            with pytest.raises(DirectoryError):
                await HTTPDirectory("https://directory.example", http=http).search(DirectoryQuery())


async def test_directory_rate_limits_and_rejects_arbitrary_registration_fields(discovered_shop, public_dns):
    from wap.directory import MemoryDirectory
    from wap.directory.server import create_directory_app

    async with client_for(discovered_shop.create_app(), block_private_networks=True) as client:
        app = create_directory_app(MemoryDirectory(client), registration_token="fictional-test-token")
        async with httpx.AsyncClient(transport=httpx.ASGITransport(app), base_url="https://dir.example") as http:
            bad = await http.post(
                "/wap-directory/v1/registrations",
                json={"domain": "fake.example", "name": "Fake"},
                headers={"Authorization": "Bearer fictional-test-token"},
            )
            assert bad.status_code == 422
            nested = await http.post(
                "/wap-directory/v1/registrations",
                content=b"[" * 2000 + b"0" + b"]" * 2000,
                headers={"Authorization": "Bearer fictional-test-token"},
            )
            assert nested.status_code == 422
            responses = [await http.post("/wap-directory/v1/search", json={}) for _ in range(12)]
            assert any(r.status_code == 429 for r in responses)


async def test_mcp_search_preserves_domain_policy_and_site_approval(discovered_shop, public_dns):
    from mcp.client.client import Client

    from wap.directory import MemoryDirectory
    from wap.mcp.bridge import BridgeConfig, WAPBridge, build_server

    async with client_for(discovered_shop.create_app(), block_private_networks=True) as client:
        index = MemoryDirectory(client)
        await index.register(discovered_shop.domain)
        bridge = WAPBridge(client, directories={"local": index}, config=BridgeConfig(approve_sites=True))
        async with Client(build_server(bridge), mode="legacy") as mcp:
            found = await mcp.call_tool("wap_search_businesses", query().model_dump(mode="json"))
            assert found.structured_content["businesses"][0]["domain"] == discovered_shop.domain
            assert not bridge.site_tools  # Search does not implicitly grant site approval.
            refused = await mcp.call_tool("wap_discover", {"domain": discovered_shop.domain})
            assert refused.is_error  # The host cannot elicit approval.
        bridge.domains.blocked = [discovered_shop.domain]
        assert not (await bridge.search_businesses(query().model_dump()))["businesses"]


@pytest.mark.parametrize("error", [RuntimeError("private backend detail"), OSError("private filesystem detail")])
async def test_arbitrary_provider_failures_do_not_abort_healthy_results(discovered_shop, public_dns, error):
    from wap.directory import DirectoryClient, MemoryDirectory

    class Broken:
        async def search(self, query):
            raise error

    async with client_for(discovered_shop.create_app(), block_private_networks=True) as client:
        index = MemoryDirectory(client)
        await index.register(discovered_shop.domain)
        result = await DirectoryClient(client, {"healthy": index, "broken": Broken()}).search(query())
        assert len(result.businesses) == 1
        assert result.errors["broken"] == "provider_error"


async def test_canonical_verification_does_not_depend_on_cache(discovered_shop, public_dns):
    from wap.directory import MemoryDirectory

    async with client_for(discovered_shop.create_app(), block_private_networks=True, cache_ttl=0) as client:
        assert (await MemoryDirectory(client).register(discovered_shop.domain)).domain == discovered_shop.domain


async def test_large_valid_search_results_stay_within_http_response_budget(discovered_shop, public_dns):
    from wap.directory import MemoryDirectory
    from wap.spec.models import Capability

    server = discovered_shop
    for i in range(255):
        server.add_capability(
            Capability(id=f"tool_{i}", name=f"Tool {i}", semantic_operation="custom." + "x" * 170 + ".v1"),
            lambda payload, ctx: {},
        )
    async with client_for(server.create_app(), block_private_networks=True) as client:
        index = MemoryDirectory(client)
        for i in range(6):
            server.domain = f"restaurant{i}.example"
            server.base_url = "https://" + server.domain
            server._manifest = None
            await index.register(server.domain)
        first = await index.search(query(limit=50))
        assert len(first.model_dump_json().encode()) <= 262144
        assert first.next_offset is not None and first.next_offset > 0
        second = await index.search(query(limit=50, offset=first.next_offset))
        assert second.entries and second.entries[0].domain != first.entries[0].domain
