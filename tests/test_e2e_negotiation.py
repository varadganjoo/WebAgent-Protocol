"""End-to-end: a shopper agent discovers the bakery, streams answers, negotiates and reserves."""

from __future__ import annotations

import asyncio
import json
from collections.abc import AsyncIterator

import httpx
import pytest
from typer.testing import CliRunner

from examples.bakery_server import create_bakery
from tests.conftest import client_for
from wap.cli import main as cli
from wap.client import (
    AuthRequired,
    ProofOfWorkFailed,
    ProtocolError,
    RateLimited,
    VerificationFailed,
    WAPClient,
)
from wap.mcp.bridge import WAPBridge, build_server
from wap.server import WAPServer
from wap.spec.crypto import verify_model
from wap.spec.models import RateLimitPolicy, StreamEventType

BAKERY = "bakery.example"
ITEM = "Sourdough Croissant"


@pytest.fixture
def bakery(keypair):
    return create_bakery(BAKERY, private_key=keypair.private_key, pow_difficulty=2)


@pytest.fixture
async def shopper(bakery) -> AsyncIterator[WAPClient]:
    _, app, _ = bakery
    async with client_for(app) as client:
        yield client


class TestShopperJourney:
    async def test_discovery_advertises_bakery(self, bakery, shopper: WAPClient) -> None:
        wap, _, _ = bakery
        manifest = await shopper.discover(BAKERY)
        assert manifest.name == "Golden Crust Bakery"
        assert manifest.pow_required and manifest.pow_difficulty == 2
        assert [c.id for c in manifest.capabilities] == [
            "get_menu",
            "check_pastry_stock",
            "negotiate_bulk_price",
            "reserve_item",
        ]
        assert manifest.public_key == wap.public_key

    async def test_streamed_natural_language_answer(self, shopper: WAPClient) -> None:
        events = [e async for e in shopper.query(BAKERY, "Do you have Sourdough Croissants today?")]
        types = [e.type for e in events]
        assert types[0] is StreamEventType.META
        assert types[-1] is StreamEventType.MESSAGE
        assert types.count(StreamEventType.TOKEN) > 3  # streamed word by word
        streamed = "".join(e.text for e in events if e.type is StreamEventType.TOKEN)
        final = events[-1].message
        assert streamed == final.content == "Yes! 24 x Sourdough Croissant available at $4.50 each."
        assert final.structured_data["available"] == 24
        assert events[-1].request.pow_nonce is not None

    async def test_full_negotiation_and_reservation(self, bakery, shopper: WAPClient) -> None:
        wap, _, inventory = bakery
        stock = await shopper.invoke(BAKERY, "check_pastry_stock", {"item": ITEM})
        assert stock.pow_solved and stock.verified
        assert stock.structured_data["available"] == 24

        session = shopper.session(BAKERY)
        offers = [3.60, 3.80, 4.05]
        statuses = []
        quote_id = None
        for offer in offers:
            turn = await session.send(
                capability_id="negotiate_bulk_price",
                payload={"item": ITEM, "quantity": 12, "offered_unit_price": offer},
            )
            statuses.append((turn.structured_data["status"], turn.structured_data.get("counter_unit_price")))
            quote_id = turn.structured_data.get("quote_id")
        assert statuses == [("counter_offer", 4.05), ("final_offer", 4.05), ("accepted", None)]
        assert quote_id and quote_id.startswith("Q-")

        # The quote is bound to the negotiating session: another session cannot redeem it.
        with pytest.raises(ProtocolError) as info:
            await shopper.invoke(
                BAKERY, "reserve_item", {"item": ITEM, "quantity": 12, "quote_id": quote_id, "customer_name": "Mallory"}
            )
        assert info.value.code == "validation_error"

        reservation = await session.send(
            capability_id="reserve_item",
            payload={"item": ITEM, "quantity": 12, "customer_name": "Ada Lovelace", "quote_id": quote_id},
        )
        hold = reservation.structured_data
        assert hold["reservation_token"].startswith("RSV-")
        assert hold["unit_price"] == 4.05 and hold["total"] == 48.60 and hold["quote_applied"] is True
        assert verify_model(reservation.message, wap.public_key)
        assert inventory.pastries["sourdough croissant"].stock == 12
        assert len(session.history) == 8
        assert session.last_reply.structured_data["reservation_token"] == hold["reservation_token"]

        # Quotes are single use.
        with pytest.raises(ProtocolError):
            await session.send(
                capability_id="reserve_item", payload={"item": ITEM, "quantity": 12, "quote_id": quote_id}
            )

        after = await shopper.invoke(BAKERY, "check_pastry_stock", {"item": ITEM})
        assert after.structured_data["available"] == 12
        assert after.structured_data["held"] == 12

    async def test_natural_language_negotiation_turns(self, shopper: WAPClient) -> None:
        session = shopper.session(BAKERY)
        first = await session.send("I'd like 12 pain au chocolat at $3.50 each")
        assert first.structured_data["status"] == "counter_offer"
        counter = first.structured_data["counter_unit_price"]
        second = await session.send(f"OK, 12 pain au chocolat at ${counter:.2f}")
        assert second.structured_data["status"] == "accepted"
        quote_id = second.structured_data["quote_id"]
        assert quote_id in second.text
        hold = await session.send("please hold 12 pain au chocolat for Grace Hopper", payload={"quote_id": quote_id})
        assert hold.structured_data["customer_name"] == "Grace Hopper"
        assert hold.structured_data["quote_applied"] is True
        assert hold.structured_data["unit_price"] == counter
        streamed = [e async for e in session.stream("do you still have pain au chocolat?")]
        assert streamed[-1].message.structured_data["available"] == 6
        assert len(session.history) == 8

    async def test_natural_language_reservation(self, shopper: WAPClient) -> None:
        result = await shopper.ask(BAKERY, "Please hold 2 almond croissants for Ada")
        assert result.structured_data["customer_name"] == "Ada"
        assert result.structured_data["quantity"] == 2
        assert "Reservation token: RSV-" in result.text

    async def test_menu_via_intent(self, shopper: WAPClient) -> None:
        result = await shopper.ask(BAKERY, "What's on the menu?")
        names = [i["name"] for i in result.structured_data["items"]]
        assert ITEM in names and result.text.startswith("Today we're baking")

    async def test_unknown_pastry(self, shopper: WAPClient) -> None:
        with pytest.raises(ProtocolError) as info:
            await shopper.invoke(BAKERY, "check_pastry_stock", {"item": "Kouign-amann"})
        assert info.value.code == "validation_error"
        assert ITEM in info.value.details["menu"]

    async def test_concurrent_shoppers_cannot_oversell(self, bakery) -> None:
        _, app, inventory = bakery
        clients = [client_for(app) for _ in range(8)]
        try:
            results = await asyncio.gather(
                *(
                    c.invoke(
                        BAKERY, "reserve_item", {"item": "Almond Croissant", "quantity": 3, "customer_name": f"c{i}"}
                    )
                    for i, c in enumerate(clients)
                ),
                return_exceptions=True,
            )
        finally:
            await asyncio.gather(*(c.aclose() for c in clients))
        successes = [r for r in results if not isinstance(r, Exception)]
        failures = [r for r in results if isinstance(r, ProtocolError)]
        assert len(successes) == 4 and len(failures) == 4  # 12 in stock, 3 each
        assert inventory.pastries["almond croissant"].stock == 0
        assert len({r.structured_data["reservation_token"] for r in successes}) == 4


class Tamper(httpx.AsyncBaseTransport):
    """A man-in-the-middle that rewrites prices in business-agent replies."""

    def __init__(self, app) -> None:
        self.inner = httpx.ASGITransport(app=app)

    async def handle_async_request(self, request: httpx.Request) -> httpx.Response:
        response = await self.inner.handle_async_request(request)
        if request.url.path != "/wap/v1/interact":
            return response
        body = await response.aread()
        forged = body.replace(b"4.5", b"0.5")
        headers = [(k, v) for k, v in response.headers.raw if k.lower() != b"content-length"]
        return httpx.Response(response.status_code, headers=headers, content=forged)


class TestAdversarial:
    @pytest.mark.parametrize("stream", [True, False])
    async def test_tampered_reply_is_detected(self, bakery, stream: bool) -> None:
        _, app, _ = bakery
        async with WAPClient(transport=Tamper(app)) as client:
            with pytest.raises(VerificationFailed):
                await client.ask(BAKERY, capability_id="check_pastry_stock", payload={"item": ITEM}, stream=stream)

    async def test_client_recovers_when_pow_is_enabled_after_discovery(self, make_server) -> None:
        server: WAPServer = make_server(domain=BAKERY)
        server.action(name="ping")(lambda: "pong")
        async with client_for(server.create_app()) as client:
            assert not (await client.discover(BAKERY)).pow_required
            server.require_pow = True  # e.g. operator turns on PoW during an attack
            result = await client.invoke(BAKERY, "ping")
        assert result.text == "pong" and result.pow_solved

    async def test_pow_gives_up_after_max_attempts(self, make_server) -> None:
        server: WAPServer = make_server(domain=BAKERY, require_pow=True)
        server.action(name="ping")(lambda: "pong")
        original = server.pow.verify

        def always_reject(seed, nonce, now=None, *, consume=True):
            from wap.spec.pow import PowExpired

            raise PowExpired("challenge has expired")

        server.pow.verify = always_reject  # type: ignore[method-assign]
        async with client_for(server.create_app(), max_pow_attempts=2) as client:
            with pytest.raises(ProofOfWorkFailed):
                await client.invoke(BAKERY, "ping")
        server.pow.verify = original  # type: ignore[method-assign]

    async def test_rate_limited_is_typed(self, keypair) -> None:
        _, app, _ = create_bakery(
            BAKERY,
            private_key=keypair.private_key,
            require_pow=False,
            rate_limit=RateLimitPolicy(requests_per_minute=60, burst=3),
        )
        async with client_for(app) as client:
            await client.discover(BAKERY)  # 1
            await client.invoke(BAKERY, "get_menu")  # 2
            await client.invoke(BAKERY, "get_menu")  # 3
            with pytest.raises(RateLimited) as info:
                await client.invoke(BAKERY, "get_menu")
        assert info.value.retry_after and info.value.retry_after > 0
        assert info.value.status_code == 429

    async def test_auth_required_is_typed(self, make_server) -> None:
        server: WAPServer = make_server(domain=BAKERY, auth_handler=lambda token: "vip" if token == "t0k" else None)

        @server.action(name="vip_menu", requires_auth=True)
        def vip_menu() -> dict:
            return {"items": ["truffle croissant"]}

        app = server.create_app()
        async with client_for(app) as client:
            with pytest.raises(AuthRequired):
                await client.invoke(BAKERY, "vip_menu")
            ok = await client.invoke(BAKERY, "vip_menu", auth_token="t0k")
        assert ok.structured_data == {"items": ["truffle croissant"]}
        async with client_for(app, auth_tokens={BAKERY: "t0k"}) as client:
            assert (await client.invoke(BAKERY, "vip_menu")).structured_data["items"]


class TestMCPBridge:
    async def test_tools_are_registered(self) -> None:
        server = build_server(WAPBridge(WAPClient()))
        tools = await server.list_tools()
        names = {t.name for t in tools}
        assert {"wap_discover", "wap_interact", "wap_ask"} <= names
        interact = next(t for t in tools if t.name == "wap_interact")
        schema = interact.inputSchema if hasattr(interact, "inputSchema") else interact.input_schema
        assert set(schema["required"]) == {"domain", "capability"}

    async def test_bridge_round_trip(self, bakery) -> None:
        _, app, _ = bakery
        bridge = WAPBridge(client_for(app))
        try:
            discovered = await bridge.discover(BAKERY)
            assert discovered["ok"] and discovered["verified"]
            assert discovered["manifest"]["pow_required"] is True
            ids = [c["id"] for c in discovered["manifest"]["capabilities"]]
            assert "reserve_item" in ids

            stock = await bridge.interact(BAKERY, "check_pastry_stock", {"item": ITEM})
            assert stock["ok"] and stock["verified"] and stock["pow_solved"]
            assert stock["structured_data"]["available"] == 24
            json.dumps(stock)  # MCP results must be JSON serialisable

            first = await bridge.interact(
                BAKERY, "negotiate_bulk_price", {"item": ITEM, "quantity": 6, "offered_unit_price": 4.0}
            )
            second = await bridge.interact(
                BAKERY,
                "negotiate_bulk_price",
                {"item": ITEM, "quantity": 6, "offered_unit_price": first["structured_data"]["counter_unit_price"]},
                session_id=first["session_id"],
            )
            assert second["structured_data"]["status"] == "accepted"
            assert second["session_id"] == first["session_id"]

            answer = await bridge.ask(BAKERY, "what do you bake?")
            assert answer["ok"] and "Today we're baking" in answer["text"]

            bad = await bridge.interact(BAKERY, "check_pastry_stock", {"flavour": "x"})
            assert bad["ok"] is False and bad["error"]["type"] == "SchemaValidationError"
            missing = await bridge.interact(BAKERY, "bake_cake", {})
            assert missing["ok"] is False and missing["error"]["type"] == "CapabilityNotFound"
            invalid = await bridge.discover("not a domain")
            assert invalid["ok"] is False
        finally:
            await bridge.aclose()


class TestCLI:
    def test_keygen(self, tmp_path) -> None:
        runner = CliRunner()
        result = runner.invoke(cli.app, ["keygen", "--json"])
        assert result.exit_code == 0, result.output
        document = json.loads(result.output)
        assert len(document["private_key"]) == 64 and len(document["public_key"]) == 64

        key_file = tmp_path / "bakery.key"
        result = runner.invoke(cli.app, ["keygen", "--out", str(key_file)])
        assert result.exit_code == 0
        assert len(key_file.read_text().strip()) == 64
        assert oct(key_file.stat().st_mode & 0o777) == "0o600"
        assert runner.invoke(cli.app, ["keygen", "--out", str(key_file)]).exit_code == 1

    def test_ask_inspect_verify(self, bakery, monkeypatch: pytest.MonkeyPatch) -> None:
        wap, app, _ = bakery
        monkeypatch.setattr(cli, "_client", lambda *args, **kwargs: client_for(app))
        runner = CliRunner()

        asked = runner.invoke(cli.app, ["ask", BAKERY, "Do you have sourdough croissants?", "--json"])
        assert asked.exit_code == 0, asked.output
        payload = json.loads(asked.output)
        assert payload["verified"] and payload["pow_solved"]
        assert payload["structured_data"]["item"] == ITEM

        streamed = runner.invoke(cli.app, ["ask", BAKERY, "-c", "check_pastry_stock", "-d", '{"item": "baguette"}'])
        assert streamed.exit_code == 0, streamed.output
        assert "signature verified" in streamed.output and "Baguette" in streamed.output

        inspected = runner.invoke(cli.app, ["inspect", BAKERY])
        assert inspected.exit_code == 0, inspected.output
        assert "Golden Crust Bakery" in inspected.output and "negotiate_bulk_price" in inspected.output

        raw = runner.invoke(cli.app, ["inspect", BAKERY, "--raw"])
        assert json.loads(raw.output)["public_key"] == wap.public_key

        verified = runner.invoke(cli.app, ["verify", BAKERY])
        assert verified.exit_code == 0 and "pass" in verified.output

        failing = runner.invoke(cli.app, ["ask", BAKERY, "-c", "check_pastry_stock", "-d", '{"nope": 1}'])
        assert failing.exit_code == 1

    def test_version(self) -> None:
        result = CliRunner().invoke(cli.app, ["--version"])
        assert result.exit_code == 0 and "WAP/1.0" in result.output
