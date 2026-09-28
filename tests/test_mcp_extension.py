"""WAP as an MCP extension: business-side /mcp endpoint, dynamic bridge tools, and MCP → WAP import."""

from __future__ import annotations

import asyncio
from collections.abc import AsyncIterator
from contextlib import asynccontextmanager

import anyio
import httpx
import httpx2
import pytest
from mcp.client.client import Client
from mcp.client.streamable_http import streamable_http_client
from mcp.server.mcpserver import MCPServer
from mcp.shared.exceptions import MCPError
from pydantic import BaseModel

from examples.bakery_server import create_bakery
from tests.conftest import client_for
from wap.client import ProtocolError
from wap.mcp.bridge import BUILTIN_TOOLS, WAPBridge, build_server, main, preload, site_slug
from wap.server import WAPServer
from wap.server.mcp_endpoint import EXTENSION_ID, META_CHALLENGE, META_POW, META_SESSION_ID, META_SIGNED_REPLY
from wap.server.mcp_import import capability_id_for
from wap.spec.crypto import verify_model
from wap.spec.models import AgentManifest, AgentMessage, RateLimitPolicy
from wap.spec.pow import solve

BAKERY = "bakery.example"
ITEM = "Sourdough Croissant"


@asynccontextmanager
async def running(app) -> AsyncIterator[None]:
    """Run the ASGI lifespan (starts the MCP session manager and MCP imports)."""
    async with app.router.lifespan_context(app):
        yield


@asynccontextmanager
async def mcp_http_client(app, domain: str = BAKERY) -> AsyncIterator[Client]:
    """The official MCP client talking streamable HTTP to ``app`` in-process."""
    http = httpx2.AsyncClient(transport=httpx2.ASGITransport(app=app), base_url=f"https://{domain}")
    async with Client(streamable_http_client(f"https://{domain}/mcp", http_client=http)) as client:
        yield client


@pytest.fixture
def bakery(keypair):
    return create_bakery(BAKERY, private_key=keypair.private_key, pow_difficulty=2)


class TestBusinessMCPEndpoint:
    async def test_manifest_advertises_mcp_url(self, bakery) -> None:
        wap, app, _ = bakery
        manifest = wap.manifest()
        assert manifest.mcp_url == f"https://{BAKERY}/mcp"
        async with client_for(app) as client:
            assert (await client.discover(BAKERY)).mcp_url == manifest.mcp_url

    async def test_declares_wap_extension(self, bakery) -> None:
        wap, app, _ = bakery
        async with running(app), mcp_http_client(app) as mcp:
            extension = mcp.server_capabilities.extensions[EXTENSION_ID]
        assert extension["manifest_url"] == f"https://{BAKERY}/.well-known/agent.json"
        assert extension["public_key"] == wap.public_key
        assert extension["signed_results"] is True
        assert extension["conversation_policy"]["max_repeats"] == 3

    async def test_tools_mirror_capabilities(self, bakery) -> None:
        wap, app, _ = bakery
        async with running(app), mcp_http_client(app) as mcp:
            tools = {t.name: t for t in (await mcp.list_tools()).tools}
        assert set(tools) == set(wap.actions)
        for cap in wap.manifest().capabilities:
            assert tools[cap.id].input_schema == cap.input_schema
            assert tools[cap.id].description == cap.description
        assert tools["check_pastry_stock"].output_schema["properties"]["available"]["type"] == "integer"

    async def test_proof_of_work_over_mcp_and_signed_results(self, keypair) -> None:
        wap, app, _ = create_bakery(BAKERY, private_key=keypair.private_key, pow_difficulty=2, mcp_require_pow=None)
        async with running(app), mcp_http_client(app) as mcp:
            refused = await mcp.call_tool("check_pastry_stock", {"item": ITEM})
            assert refused.is_error and "pow_required" in refused.content[0].text
            challenge = refused.meta[META_CHALLENGE]
            solution = {"seed": challenge["seed"], "nonce": solve(challenge["seed"], challenge["difficulty"])}
            ok = await mcp.call_tool("check_pastry_stock", {"item": ITEM}, meta={META_POW: solution})
            reused = await mcp.call_tool("check_pastry_stock", {"item": ITEM}, meta={META_POW: solution})
        assert not ok.is_error
        assert ok.structured_content["available"] == 24
        signed = AgentMessage.model_validate(ok.meta[META_SIGNED_REPLY])
        assert verify_model(signed, wap.public_key)
        assert signed.structured_data == ok.structured_content
        assert reused.is_error and "pow_invalid" in reused.content[0].text

    async def test_plain_mcp_clients_when_pow_disabled_for_mcp(self, keypair) -> None:
        wap, app, _ = create_bakery(BAKERY, private_key=keypair.private_key, pow_difficulty=2)
        assert wap.mcp_require_pow is False
        async with running(app), mcp_http_client(app) as mcp:
            result = await mcp.call_tool("get_menu", {})
            bad = await mcp.call_tool("check_pastry_stock", {"flavour": "x"})
            unknown_item = await mcp.call_tool("check_pastry_stock", {"item": "Kouign-amann"})
            with pytest.raises(MCPError):
                await mcp.call_tool("bake_cake", {})
        assert not result.is_error and len(result.structured_content["items"]) == 6
        assert bad.is_error and "validation_error" in bad.content[0].text
        assert unknown_item.is_error and "Kouign-amann" in unknown_item.content[0].text
        # WAP clients still pay proof-of-work on the WAP endpoint.
        assert wap.manifest().pow_required

    async def test_session_continuation_over_mcp(self, keypair) -> None:
        wap, app, _ = create_bakery(BAKERY, private_key=keypair.private_key, require_pow=False)
        async with running(app), mcp_http_client(app) as mcp:
            args = {"item": ITEM, "quantity": 12, "offered_unit_price": 3.6}
            first = await mcp.call_tool("negotiate_bulk_price", args)
            session = {META_SESSION_ID: first.meta[META_SESSION_ID]}
            args["offered_unit_price"] = 3.8
            second = await mcp.call_tool("negotiate_bulk_price", args, meta=session)
            fresh = await mcp.call_tool("negotiate_bulk_price", args)
        assert first.structured_content["round"] == 1
        assert second.structured_content["round"] == 2  # same session → state carried over
        assert fresh.structured_content["round"] == 1

    async def test_mcp_rate_limited(self, keypair) -> None:
        _, app, _ = create_bakery(
            BAKERY, private_key=keypair.private_key, require_pow=False, rate_limit=RateLimitPolicy(burst=2)
        )
        async with running(app), mcp_http_client(app) as mcp:
            results = [await mcp.call_tool("get_menu", {}) for _ in range(3)]
        assert [r.is_error for r in results] == [False, False, True]
        assert "rate_limited" in results[-1].content[0].text

    async def test_mcp_can_be_disabled(self, make_server) -> None:
        server: WAPServer = make_server()
        server.action(name="ping")(lambda: "pong")
        app = server.create_app(mcp=False)
        assert server.manifest().mcp_url is None
        async with httpx.AsyncClient(transport=httpx.ASGITransport(app=app), base_url="https://shop.example") as http:
            assert (await http.post("/mcp", json={})).status_code in (404, 405)

    async def test_endpoint_reports_missing_lifespan(self, bakery) -> None:
        _, app, _ = bakery
        async with httpx.AsyncClient(transport=httpx.ASGITransport(app=app), base_url=f"https://{BAKERY}") as http:
            response = await http.post("/mcp", json={"jsonrpc": "2.0", "id": 1, "method": "ping"})
        assert response.status_code == 503

    async def test_dns_rebinding_protection(self, bakery) -> None:
        _, app, _ = bakery
        async with running(app):
            http = httpx2.AsyncClient(transport=httpx2.ASGITransport(app=app), base_url="https://evil.example")
            response = await http.post(
                "/mcp",
                json={"jsonrpc": "2.0", "id": 1, "method": "ping"},
                headers={"Accept": "application/json, text/event-stream"},
            )
        assert response.status_code in (400, 403, 421)


class TestDynamicBridgeTools:
    async def test_discover_adds_native_tools(self, bakery) -> None:
        _, app, _ = bakery
        bridge = WAPBridge(client_for(app))
        async with Client(build_server(bridge)) as mcp:
            before = [t.name for t in (await mcp.list_tools()).tools]
            assert before == [t.name for t in BUILTIN_TOOLS]
            discovered = await mcp.call_tool("wap_discover", {"domain": BAKERY})
            after = {t.name: t for t in (await mcp.list_tools()).tools}
            stock = await mcp.call_tool("bakery_example__check_pastry_stock", {"item": ITEM})
        await bridge.aclose()
        assert discovered.structured_content["tools_added"] == [
            "bakery_example__get_menu",
            "bakery_example__check_pastry_stock",
            "bakery_example__negotiate_bulk_price",
            "bakery_example__reserve_item",
        ]
        tool = after["bakery_example__check_pastry_stock"]
        assert tool.input_schema["required"] == ["item"]
        assert "Golden Crust Bakery" in tool.description and "SHA256:" in tool.description
        assert not stock.is_error
        assert stock.structured_content["available"] == 24
        assert stock.meta["io.webagent/verified"] is True

    async def test_list_changed_legacy_notification(self, bakery) -> None:
        _, app, _ = bakery
        bridge = WAPBridge(client_for(app))
        received: list[str] = []

        async def handler(message) -> None:
            received.append(getattr(message, "method", type(message).__name__))

        async with Client(build_server(bridge), mode="legacy", message_handler=handler) as mcp:
            assert mcp.server_capabilities.tools.list_changed is True
            await mcp.call_tool("wap_discover", {"domain": BAKERY})
            await anyio.sleep(0.05)
        await bridge.aclose()
        assert "notifications/tools/list_changed" in received

    async def test_list_changed_modern_subscription(self, bakery) -> None:
        _, app, _ = bakery
        bridge = WAPBridge(client_for(app))
        async with Client(build_server(bridge)) as mcp:
            assert mcp.server_capabilities.tools.list_changed is True
            async with mcp.listen(tools_list_changed=True) as events:
                await mcp.call_tool("wap_discover", {"domain": BAKERY})
                with anyio.fail_after(2):
                    event = await events.__anext__()
        await bridge.aclose()
        assert type(event).__name__ == "ToolsListChanged"

    async def test_site_tools_keep_negotiation_state(self, bakery) -> None:
        _, app, _ = bakery
        bridge = WAPBridge(client_for(app))
        async with Client(build_server(bridge)) as mcp:
            await mcp.call_tool("wap_discover", {"domain": BAKERY})
            tool = "bakery_example__negotiate_bulk_price"
            first = await mcp.call_tool(tool, {"item": ITEM, "quantity": 12, "offered_unit_price": 3.6})
            counter = first.structured_content["counter_unit_price"]
            second = await mcp.call_tool(tool, {"item": ITEM, "quantity": 12, "offered_unit_price": counter})
            invalid = await mcp.call_tool("bakery_example__reserve_item", {"qty": "many"})
            with pytest.raises(MCPError):
                await mcp.call_tool("elsewhere__do_thing", {})
        await bridge.aclose()
        assert second.structured_content["status"] == "accepted"
        assert invalid.is_error and "SchemaValidationError" in invalid.content[0].text

    async def test_failed_discovery_adds_nothing(self) -> None:
        bridge = WAPBridge(WAPClient_unreachable())
        async with Client(build_server(bridge)) as mcp:
            result = await mcp.call_tool("wap_discover", {"domain": "missing.example"})
            names = [t.name for t in (await mcp.list_tools()).tools]
        await bridge.aclose()
        assert result.is_error and result.structured_content["ok"] is False
        assert names == [t.name for t in BUILTIN_TOOLS]

    async def test_preload(self, bakery) -> None:
        _, app, _ = bakery
        bridge = WAPBridge(client_for(app))
        await preload(bridge, [BAKERY, "missing.example"])
        await bridge.aclose()
        assert "bakery_example__reserve_item" in bridge.site_tools

    def test_slug_and_help(self, capsys) -> None:
        assert site_slug("localhost:8000") == "localhost_8000"
        assert site_slug("Bakery.Example") == "bakery_example"
        main(["--help"])
        assert "wap-mcp" in capsys.readouterr().out


def WAPClient_unreachable():  # noqa: N802 - reads like a constructor in the test above
    from wap import WAPClient

    return WAPClient(transport=httpx.MockTransport(lambda request: httpx.Response(404)))


class Stock(BaseModel):
    sku: str
    quantity: int


def inventory_mcp() -> MCPServer:
    tools = MCPServer("inventory")
    levels = {"W-1": 7}

    @tools.tool(description="Units on hand for a SKU.")
    def check_stock(sku: str) -> Stock:
        if sku not in levels:
            raise ValueError(f"unknown sku {sku}")
        return Stock(sku=sku, quantity=levels[sku])

    @tools.tool(name="Order-Parts", description="Order parts from the supplier.")
    def order_parts(sku: str, quantity: int) -> str:
        levels[sku] = levels.get(sku, 0) + quantity
        return f"ordered {quantity} x {sku}"

    return tools


class TestImportFromMCP:
    def test_capability_ids(self) -> None:
        assert capability_id_for("check_stock") == "check_stock"
        assert capability_id_for("Order-Parts") == "order-parts"
        assert capability_id_for("9lives") == "t_9lives"
        assert capability_id_for("do thing!", prefix="acme.") == "acme.do_thing"

    async def test_include_mcp_publishes_tools_over_wap(self, make_server) -> None:
        server: WAPServer = make_server(domain="acme.example")
        server.include_mcp(inventory_mcp())
        app = server.create_app()
        async with running(app):
            manifest: AgentManifest = server.manifest()
            assert {c.id for c in manifest.capabilities} == {"check_stock", "order-parts"}
            stock_cap = manifest.get_capability("check_stock")
            assert stock_cap.input_schema["required"] == ["sku"]
            assert stock_cap.output_schema["properties"]["quantity"]["type"] == "integer"
            async with client_for(app) as client:
                result = await client.invoke("acme.example", "check_stock", {"sku": "W-1"})
                ordered = await client.invoke("acme.example", "order-parts", {"sku": "W-1", "quantity": 5})
                again = await client.invoke("acme.example", "check_stock", {"sku": "W-1"})
                with pytest.raises(ProtocolError) as failure:
                    await client.invoke("acme.example", "check_stock", {"sku": "nope"})
            # Server-side JSON Schema validation of imported tools (client-side validation switched off).
            async with client_for(app, validate_payloads=False) as unchecked:
                with pytest.raises(ProtocolError) as invalid:
                    await unchecked.invoke("acme.example", "order-parts", {"sku": "W-1", "quantity": "x"})
        assert result.verified and result.structured_data == {"sku": "W-1", "quantity": 7}
        assert "ordered 5 x W-1" in ordered.text
        assert again.structured_data["quantity"] == 12
        assert failure.value.code == "action_failed"
        assert invalid.value.code == "validation_error"
        assert invalid.value.details["errors"][0]["loc"] == ["quantity"]

    async def test_round_trip_mcp_to_wap_to_mcp(self, make_server) -> None:
        """An existing MCP server, re-published through WAP, is reachable again as MCP at /mcp."""
        server: WAPServer = make_server(domain="acme.example")
        server.include_mcp(inventory_mcp(), include={"check_stock"})
        app = server.create_app()
        async with running(app), mcp_http_client(app, "acme.example") as mcp:
            tools = [t.name for t in (await mcp.list_tools()).tools]
            result = await mcp.call_tool("check_stock", {"sku": "W-1"})
        assert tools == ["check_stock"]
        assert result.structured_content == {"sku": "W-1", "quantity": 7}
        assert verify_model(AgentMessage.model_validate(result.meta[META_SIGNED_REPLY]), server.public_key)

    async def test_import_mcp_now(self, make_server) -> None:
        server: WAPServer = make_server(domain="acme.example")
        source = await server.import_mcp(inventory_mcp(), prefix="inv.")
        try:
            assert source.capability_ids == ["inv.check_stock", "inv.order-parts"]
            async with client_for(server.create_app(mcp=False)) as client:
                result = await client.invoke("acme.example", "inv.check_stock", {"sku": "W-1"})
            assert result.structured_data["quantity"] == 7
        finally:
            await source.aclose()

    async def test_add_capability_rejects_bad_schema(self, make_server) -> None:
        from wap.spec.models import Capability

        server: WAPServer = make_server()
        with pytest.raises(ValueError, match="invalid input_schema"):
            server.add_capability(
                Capability(id="bad", name="Bad", input_schema={"type": "object", "properties": 5}), lambda p, c: None
            )

    async def test_concurrent_imported_calls(self, make_server) -> None:
        server: WAPServer = make_server(domain="acme.example")
        server.include_mcp(inventory_mcp())
        app = server.create_app()
        async with running(app), client_for(app) as client:
            results = await asyncio.gather(
                *(client.invoke("acme.example", "check_stock", {"sku": "W-1"}, session_id=f"s{i}") for i in range(8))
            )
        assert all(r.structured_data["quantity"] == 7 for r in results)


async def test_mcp_idempotency_key(keypair) -> None:
    from wap.server.mcp_endpoint import META_IDEMPOTENCY_KEY

    _, app, inventory = create_bakery(BAKERY, private_key=keypair.private_key, require_pow=False)
    args = {"item": "Almond Croissant", "quantity": 2, "customer_name": "Ada"}
    async with running(app), mcp_http_client(app) as mcp:
        first = await mcp.call_tool("reserve_item", args, meta={META_IDEMPOTENCY_KEY: "mcp-order-0001"})
        retry = await mcp.call_tool("reserve_item", args, meta={META_IDEMPOTENCY_KEY: "mcp-order-0001"})
    assert retry.structured_content == first.structured_content
    assert retry.meta["io.webagent/idempotent_replay"] is True
    assert inventory.pastries["almond croissant"].stock == 10
