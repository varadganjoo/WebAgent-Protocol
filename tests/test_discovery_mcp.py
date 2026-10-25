from __future__ import annotations

from mcp.client.client import Client

from examples.restaurant_demo import FIXED_NOW
from examples.restaurant_server import create_restaurant
from tests.conftest import client_for
from tests.test_mcp_extension import mcp_http_client, running
from wap.mcp.bridge import WAPBridge, build_server
from wap.server import WAPServer
from wap.spec.semantics import AVAILABILITY


async def test_extended_manifest_tools_work_with_official_mcp_client(keypair):
    server, app, _ = create_restaurant(
        "bakery.example", "Test Restaurant", clock=lambda: FIXED_NOW, private_key=keypair.private_key
    )
    server.mcp_require_pow = False
    async with running(app), mcp_http_client(app) as mcp:
        tools = (await mcp.list_tools()).tools
        availability = next(t for t in tools if t.name == "available_tables")
        assert availability.meta["io.webagent/semantic_operation"] == AVAILABILITY
        assert availability.meta["io.webagent/execution"] == "deterministic"
        result = await mcp.call_tool("available_tables", {"party_size": 4, "start_time": "2026-10-25T19:00:00+11:00"})
        assert not result.is_error and result.structured_content["slots"]


async def test_bridge_preserves_metadata_and_legacy_tool_flow(keypair):
    server, app, _ = create_restaurant(
        "bakery.example", "Test Restaurant", clock=lambda: FIXED_NOW, private_key=keypair.private_key
    )
    bridge = WAPBridge(client_for(app))
    try:
        async with Client(build_server(bridge)) as mcp:
            await mcp.call_tool("wap_discover", {"domain": "bakery.example"})
            tools = (await mcp.list_tools()).tools
            tool = next(t for t in tools if t.name.endswith("__available_tables"))
            assert tool.meta["io.webagent/semantic_schema_version"] == "1.0"
            result = await mcp.call_tool(tool.name, {"party_size": 4, "start_time": "2026-10-25T19:00:00+11:00"})
            assert not result.is_error and result.structured_content["slots"]
    finally:
        await bridge.aclose()


async def test_existing_mcp_tool_import_can_carry_optional_metadata(keypair):
    import mcp_types as types
    from mcp.server.lowlevel import Server

    async def list_tools(ctx, params):
        return types.ListToolsResult(
            tools=[
                types.Tool(
                    name="lookup",
                    input_schema={"type": "object"},
                    meta={
                        "io.webagent/semantic_operation": AVAILABILITY,
                        "io.webagent/semantic_schema_version": "1.0",
                        "io.webagent/execution": "external_service",
                    },
                )
            ]
        )

    source = Server("inventory", on_list_tools=list_tools)
    wap = WAPServer(name="Imported", domain="import.example", private_key=keypair.private_key)
    imported = await wap.import_mcp(source)
    try:
        cap = wap.manifest().get_capability("lookup")
        assert cap.semantic_operation == AVAILABILITY and cap.execution == "external_service"
        assert cap.effects == "write"  # Imported hints cannot silently relax consent.
        assert wap.manifest().wap_version == "1.1"
    finally:
        await imported.aclose()
