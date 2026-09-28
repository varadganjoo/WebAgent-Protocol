"""Loop protection: agents must not talk to each other in circles forever."""

from __future__ import annotations

from collections.abc import Callable

import httpx
import pytest
from mcp.client.client import Client

from examples.bakery_server import create_bakery
from tests.conftest import DOMAIN, client_for
from wap.client import ProtocolError, WAPClient
from wap.client.exceptions import ConversationLimitReached, ConversationStopped, LoopDetected
from wap.mcp.bridge import STOP_INSTRUCTION, WAPBridge, build_server
from wap.server import WAPServer
from wap.spec.conversation import (
    ConversationGuard,
    ConversationLimitError,
    ConversationPolicy,
    normalize_text,
    reply_fingerprint,
    request_fingerprint,
)

BAKERY = "bakery.example"
ITEM = "Sourdough Croissant"


class TestGuard:
    def run(self, guard: ConversationGuard, exchanges: list[tuple[str, str]], now: float = 1000.0) -> None:
        for request, reply in exchanges:
            guard.check(request, now=now)
            guard.record(request, reply, now=now)

    def test_same_question_same_answer(self) -> None:
        guard = ConversationGuard(ConversationPolicy(max_repeats=3))
        self.run(guard, [("A", "x")] * 3)
        with pytest.raises(ConversationLimitError) as info:
            guard.check("A", now=1000.0)
        assert info.value.reason == "loop_detected"
        assert info.value.details == {"cycle_length": 1, "repeats": 3}
        guard.check("B", now=1000.0)  # asking something new is fine

    def test_changing_answers_are_progress(self) -> None:
        guard = ConversationGuard(ConversationPolicy(max_repeats=3, max_identical_requests=100))
        self.run(guard, [("stock?", f"{n} left") for n in range(20)])

    def test_stall_with_changing_counters(self) -> None:
        """Same request over and over, where only a counter in the answer changes."""
        guard = ConversationGuard(ConversationPolicy(max_identical_requests=5))
        self.run(guard, [("offer 3.00", f"final offer 4.05, round {n}") for n in range(5)])
        with pytest.raises(ConversationLimitError) as info:
            guard.check("offer 3.00", now=1000.0)
        assert info.value.details == {"identical_requests": 5}

    @pytest.mark.parametrize("cycle", [2, 3])
    def test_ping_pong_cycles(self, cycle: int) -> None:
        guard = ConversationGuard(ConversationPolicy(max_repeats=3, max_cycle_length=3))
        block = [(f"offer-{i}", f"counter-{i}") for i in range(cycle)]
        self.run(guard, block * 3)
        with pytest.raises(ConversationLimitError) as info:
            guard.check("offer-0", now=1000.0)
        assert info.value.details["cycle_length"] == cycle

    def test_repeats_expire_after_window(self) -> None:
        guard = ConversationGuard(ConversationPolicy(max_repeats=3, window_seconds=60))
        self.run(guard, [("A", "x")] * 3, now=1000.0)
        guard.check("A", now=1061.0)

    def test_turn_limit(self) -> None:
        guard = ConversationGuard(ConversationPolicy(max_turns=3))
        self.run(guard, [(f"q{i}", f"a{i}") for i in range(3)])
        with pytest.raises(ConversationLimitError) as info:
            guard.check("q9")
        assert info.value.reason == "conversation_limit"

    def test_fingerprints_ignore_cosmetic_rephrasing(self) -> None:
        assert normalize_text("Do you have  CROISSANTS??") == "do you have croissants"
        assert request_fingerprint(None, None, "Any croissants?") == request_fingerprint(None, None, "any croissants")
        assert request_fingerprint("x", {"a": 1, "b": 2}, "") == request_fingerprint("x", {"b": 2, "a": 1}, "")
        assert request_fingerprint("x", {"a": 1}, "") != request_fingerprint("x", {"a": 2}, "")
        assert reply_fingerprint("ok", {"n": 1}) != reply_fingerprint("ok", {"n": 2})


class TestBusinessSide:
    """The business agent refuses to keep feeding a loop, before running any tool."""

    @pytest.fixture
    def counted(self, make_server: Callable[..., WAPServer]) -> tuple[WAPServer, list[str]]:
        server = make_server(conversation_policy=ConversationPolicy(max_repeats=3, max_turns=8))
        calls: list[str] = []

        @server.action(name="quote")
        def quote(item: str) -> dict:
            calls.append(item)
            return {"item": item, "price": 4.5}

        return server, calls

    async def test_manifest_publishes_policy(self, counted) -> None:
        server, _ = counted
        policy = server.manifest().conversation_policy
        assert policy["max_repeats"] == 3 and policy["max_turns"] == 8

    async def test_server_stops_a_loop_without_running_the_tool(self, counted) -> None:
        server, calls = counted
        # Client-side guard disabled so the business agent's own protection is exercised.
        lenient = ConversationPolicy(max_repeats=1000, max_repeats_across_sessions=1000)
        async with client_for(server.create_app(mcp=False), conversation_policy=lenient) as client:
            session = client.session(DOMAIN)
            for _ in range(3):
                await session.send(capability_id="quote", payload={"item": "pie"})
            with pytest.raises(LoopDetected) as info:
                await session.send(capability_id="quote", payload={"item": "pie"})
            await session.send(capability_id="quote", payload={"item": "cake"})  # new question → allowed
        assert info.value.status_code == 409 and info.value.code == "loop_detected"
        assert calls == ["pie", "pie", "pie", "cake"]

    async def test_server_turn_limit(self, counted) -> None:
        server, calls = counted
        lenient = ConversationPolicy(max_turns=1000)
        async with client_for(server.create_app(mcp=False), conversation_policy=lenient) as client:
            session = client.session(DOMAIN)
            for i in range(8):
                await session.send(capability_id="quote", payload={"item": f"item-{i}"})
            with pytest.raises(ConversationLimitReached) as info:
                await session.send(capability_id="quote", payload={"item": "one-more"})
        assert info.value.status_code == 429
        assert len(calls) == 8

    async def test_loops_across_fresh_sessions(self, make_server: Callable[..., WAPServer]) -> None:
        server = make_server(conversation_policy=ConversationPolicy(max_repeats_across_sessions=4))
        server.action(name="menu")(lambda: {"items": ["pie"]})
        lenient = ConversationPolicy(max_repeats=1000, max_repeats_across_sessions=1000)
        async with client_for(server.create_app(mcp=False), conversation_policy=lenient) as client:
            for _ in range(4):
                await client.invoke(DOMAIN, "menu")  # a new session every time
            with pytest.raises(LoopDetected):
                await client.invoke(DOMAIN, "menu")
        # A different agent key is unaffected.
        async with client_for(server.create_app(mcp=False)) as other:
            assert (await other.invoke(DOMAIN, "menu")).structured_data == {"items": ["pie"]}


class TestUserSide:
    """The user's own agent stops itself before wasting the user's money and the business's time."""

    async def test_client_stops_locally_without_a_request(self, keypair) -> None:
        _, app, _ = create_bakery(BAKERY, private_key=keypair.private_key, require_pow=False)
        requests: list[str] = []
        inner = httpx.ASGITransport(app=app)

        class Counting(httpx.AsyncBaseTransport):
            async def handle_async_request(self, request: httpx.Request) -> httpx.Response:
                requests.append(request.url.path)
                return await inner.handle_async_request(request)

        async with WAPClient(transport=Counting(), conversation_policy=ConversationPolicy(max_repeats=3)) as client:
            session = client.session(BAKERY)
            for _ in range(3):
                await session.send("Do you have sourdough croissants?")
            sent = requests.count("/wap/v1/interact")
            with pytest.raises(LoopDetected) as info:
                await session.send("do you have SOURDOUGH croissants??")
        assert info.value.status_code is None  # refused locally
        assert requests.count("/wap/v1/interact") == sent == 3

    async def test_stalled_negotiation_is_cut_off(self, keypair) -> None:
        """A naive agent keeps offering the same low price after the bakery's final offer."""
        _, app, _ = create_bakery(BAKERY, private_key=keypair.private_key, require_pow=False)
        outcomes = []
        async with client_for(app) as client:
            session = client.session(BAKERY)
            with pytest.raises(LoopDetected):
                for _ in range(20):
                    turn = await session.send(
                        capability_id="negotiate_bulk_price",
                        payload={"item": ITEM, "quantity": 12, "offered_unit_price": 3.0},
                    )
                    outcomes.append(turn.structured_data["status"])
        assert outcomes[:2] == ["counter_offer", "final_offer"]
        assert len(outcomes) < 8  # stopped long before 20 rounds

    async def test_repeated_errors_count_as_a_loop(self, keypair) -> None:
        _, app, _ = create_bakery(BAKERY, private_key=keypair.private_key, require_pow=False)
        async with client_for(app) as client:
            session = client.session(BAKERY)
            for _ in range(3):
                with pytest.raises(ProtocolError) as info:
                    await session.send(capability_id="check_pastry_stock", payload={"item": "Kouign-amann"})
                assert not isinstance(info.value, ConversationStopped)
            with pytest.raises(LoopDetected):
                await session.send(capability_id="check_pastry_stock", payload={"item": "Kouign-amann"})

    async def test_mcp_bridge_tells_the_model_to_stop(self, keypair) -> None:
        _, app, _ = create_bakery(BAKERY, private_key=keypair.private_key, pow_difficulty=2)
        bridge = WAPBridge(client_for(app))
        async with Client(build_server(bridge)) as mcp:
            await mcp.call_tool("wap_discover", {"domain": BAKERY})
            tool = "bakery_example__negotiate_bulk_price"
            args = {"item": ITEM, "quantity": 12, "offered_unit_price": 3.0}
            results = [await mcp.call_tool(tool, args) for _ in range(6)]
            other = await mcp.call_tool("bakery_example__get_menu", {})
        await bridge.aclose()
        stopped = [r for r in results if r.is_error]
        assert stopped, "the bridge never stopped the loop"
        assert "LoopDetected" in stopped[0].content[0].text
        assert STOP_INSTRUCTION in stopped[0].content[0].text
        assert not other.is_error  # a genuinely different request still works

    async def test_bridge_stops_repeated_failing_calls(self, keypair) -> None:
        _, app, _ = create_bakery(BAKERY, private_key=keypair.private_key, require_pow=False)
        bridge = WAPBridge(client_for(app), conversation_policy=ConversationPolicy(max_repeats=2))
        outcomes = [await bridge.interact(BAKERY, "check_pastry_stock", {"flavour": "x"}) for _ in range(3)]
        await bridge.aclose()
        assert [o["error"]["type"] for o in outcomes] == [
            "SchemaValidationError",
            "SchemaValidationError",
            "LoopDetected",
        ]
        assert outcomes[-1]["error"]["instruction"] == STOP_INSTRUCTION
