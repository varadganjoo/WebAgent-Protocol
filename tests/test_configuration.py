"""Operators choose their own protections: limits, tiers, proof-of-work and loop guards."""

from __future__ import annotations

from collections.abc import Callable
from typing import Any

import pytest

from tests.conftest import DOMAIN, client_for
from wap.client import ProofOfWorkFailed, ProtocolError, RateLimited, WAPClient
from wap.client.exceptions import LoopDetected
from wap.server import WAPServer
from wap.server.admission import AdaptivePow, AdmissionDecision, AdmissionRequest
from wap.spec.conversation import ConversationPolicy
from wap.spec.crypto import Signer
from wap.spec.models import RateLimitPolicy
from wap.spec.pow import solve
from wap.storage import MemoryStore

LENIENT_CLIENT = ConversationPolicy(
    max_repeats=10_000, max_identical_requests=10_000, max_repeats_across_sessions=10_000
)


def with_ping(server: WAPServer) -> WAPServer:
    server.action(name="ping", effects="read")(lambda: {"pong": True})
    return server


class TestDisablingProtections:
    async def test_rate_limits_can_be_disabled(self, make_server: Callable[..., WAPServer]) -> None:
        server = with_ping(make_server(rate_limit=False, ip_rate_limit=False, conversation_policy=False))
        assert server.manifest().rate_limit_policy == {}
        assert server.manifest().conversation_policy is None
        async with client_for(server.create_app(mcp=False), conversation_policy=False) as client:
            for _ in range(60):
                await client.invoke(DOMAIN, "ping", session_id="one-session")
        # No 429, and 60 identical requests in one session were allowed.

    async def test_ip_limit_only(self, make_server: Callable[..., WAPServer]) -> None:
        server = with_ping(make_server(rate_limit=False, ip_rate_limit=RateLimitPolicy(burst=3)))
        async with client_for(server.create_app(mcp=False), conversation_policy=LENIENT_CLIENT) as client:
            with pytest.raises(RateLimited) as info:
                for i in range(10):
                    await client.invoke(DOMAIN, "ping", session_id=f"s{i}")
        assert info.value.details["scope"] == "ip"

    async def test_loop_protection_can_be_tuned(self, make_server: Callable[..., WAPServer]) -> None:
        server = with_ping(make_server(conversation_policy=ConversationPolicy(max_repeats=5)))
        async with client_for(server.create_app(mcp=False), conversation_policy=LENIENT_CLIENT) as client:
            session = client.session(DOMAIN)
            for _ in range(5):
                await session.send(capability_id="ping")
            with pytest.raises(LoopDetected):
                await session.send(capability_id="ping")

    async def test_client_side_guard_can_be_disabled(self) -> None:
        client = WAPClient(conversation_policy=False)
        assert client.conversation_guards(DOMAIN, "s") == []
        await client.aclose()


class TestAdmissionTiers:
    @pytest.fixture
    def partner(self) -> Signer:
        return Signer()

    @pytest.fixture
    def tiered(self, make_server: Callable[..., WAPServer], partner: Signer) -> WAPServer:
        blocked = Signer()
        seen: list[AdmissionRequest] = []

        def admission(request: AdmissionRequest) -> AdmissionDecision:
            seen.append(request)
            if request.agent_key == partner.public_key:
                return AdmissionDecision(
                    tier="partner",
                    rate_limit=RateLimitPolicy(requests_per_minute=10_000, burst=1_000),
                    require_pow=False,
                    conversation_policy=False,  # an aggregator repeats calls for many end users
                )
            if request.agent_key == blocked.public_key:
                return AdmissionDecision(deny="this agent is blocked")
            if request.principal is not None:
                return AdmissionDecision(tier="customer", require_pow=False)
            return AdmissionDecision()

        server = make_server(
            require_pow=True,
            pow_difficulty=2,
            rate_limit=RateLimitPolicy(burst=3),
            ip_rate_limit=False,
            admission=admission,
            auth_handler=lambda token: {"customer": "c-1"} if token == "loyal" else None,
        )
        server.blocked = blocked  # type: ignore[attr-defined]
        server.seen = seen  # type: ignore[attr-defined]
        return with_ping(server)

    async def test_default_tier_pays_pow_and_is_limited(self, tiered: WAPServer) -> None:
        async with client_for(tiered.create_app(mcp=False), conversation_policy=LENIENT_CLIENT) as client:
            first = await client.invoke(DOMAIN, "ping", session_id="d1")
            assert first.pow_solved
            with pytest.raises(RateLimited):
                for i in range(5):
                    await client.invoke(DOMAIN, "ping", session_id=f"d{i + 2}")

    async def test_partner_tier_skips_pow_and_has_higher_limits(self, tiered: WAPServer, partner: Signer) -> None:
        events: list[tuple[str, dict[str, Any]]] = []
        tiered.observer = lambda name, attrs: events.append((name, attrs))
        async with client_for(
            tiered.create_app(mcp=False), agent_key=partner, conversation_policy=LENIENT_CLIENT
        ) as client:
            # The manifest says PoW is required, so the client solves one anyway; the partner
            # tier is exempt, which the server confirms by accepting requests with no solution.
            for i in range(20):
                await client.invoke(DOMAIN, "ping", session_id=f"p{i}")
        completed = [attrs for name, attrs in events if name == "request.completed"]
        assert len(completed) == 20 and all(a["tier"] == "partner" for a in completed)
        assert tiered.seen[-1].transport == "wap" and tiered.seen[-1].agent_key == partner.public_key

    async def test_partner_needs_no_solution(self, tiered: WAPServer, partner: Signer) -> None:
        import httpx

        from wap.spec.models import AgentMessage

        message = partner.sign_model(
            AgentMessage(session_id="raw-1", role="user_agent", capability_id="ping", public_key=partner.public_key)
        )
        async with httpx.AsyncClient(
            transport=httpx.ASGITransport(app=tiered.create_app(mcp=False)), base_url=f"https://{DOMAIN}"
        ) as http:
            response = await http.post("/wap/v1/interact", content=message.model_dump_json())
        assert response.status_code == 200

    async def test_denied_agent(self, tiered: WAPServer) -> None:
        async with client_for(tiered.create_app(mcp=False), agent_key=tiered.blocked) as client:
            with pytest.raises(ProtocolError) as info:
                await client.invoke(DOMAIN, "ping")
        assert info.value.code == "forbidden" and "blocked" in info.value.message

    async def test_authenticated_customer_skips_pow(self, tiered: WAPServer) -> None:
        seen = tiered.seen
        async with client_for(tiered.create_app(mcp=False), auth_tokens={DOMAIN: "loyal"}) as client:
            await client.invoke(DOMAIN, "ping")
        assert seen[-1].principal == {"customer": "c-1"}

    async def test_tier_minimum_difficulty(self, make_server: Callable[..., WAPServer]) -> None:
        server = with_ping(
            make_server(
                require_pow=True,
                pow_difficulty=1,
                admission=lambda request: AdmissionDecision(tier="suspicious", pow_difficulty=3),
            )
        )
        challenge = await server.issue_challenge()  # difficulty 1
        with pytest.raises(Exception) as info:
            await server.verify_pow(challenge.seed, solve(challenge.seed, 1), min_difficulty=3)
        assert info.value.details["reason"] == "insufficient_work"
        async with client_for(server.create_app(mcp=False)) as client:
            with pytest.raises(ProofOfWorkFailed):
                await client.invoke(DOMAIN, "ping")


class TestAdaptivePow:
    async def test_difficulty_rises_under_load_and_falls_back(self) -> None:
        store = MemoryStore()
        adaptive = AdaptivePow(threshold=10, window_seconds=10, max_extra=2)
        now = 1_000.0
        levels = [await adaptive.difficulty(store, 3, record=True, now=now) for _ in range(50)]
        assert levels[0] == 3 and levels[9] == 3
        assert levels[10] == 4  # just over the threshold
        assert levels[-1] == 5  # capped at base + max_extra
        assert await adaptive.difficulty(store, 3, record=False, now=now + 25) == 3  # next windows are quiet

    async def test_server_issues_harder_challenges_under_load(self, make_server: Callable[..., WAPServer]) -> None:
        server = make_server(require_pow=True, pow_difficulty=2, adaptive_pow=AdaptivePow(threshold=3, max_extra=1))
        issued = [(await server.issue_challenge()).difficulty for _ in range(6)]
        assert issued[:3] == [2, 2, 2] and issued[-1] == 3

    def test_invalid_parameters(self) -> None:
        with pytest.raises(ValueError):
            AdaptivePow(threshold=0)


class TestObserver:
    async def test_events_and_failing_observer(self, make_server: Callable[..., WAPServer]) -> None:
        events: list[str] = []

        def observer(name: str, attrs: dict[str, Any]) -> None:
            events.append(name)
            raise RuntimeError("metrics backend down")  # must never break requests

        server = with_ping(make_server(observer=observer, require_pow=True))
        async with client_for(server.create_app(mcp=False)) as client:
            await client.invoke(DOMAIN, "ping")
        assert "pow.issued" in events and "request.completed" in events

    async def test_rejections_are_reported(self, make_server: Callable[..., WAPServer]) -> None:
        events: list[tuple[str, dict[str, Any]]] = []
        server = with_ping(
            make_server(
                observer=lambda n, a: events.append((n, a)), rate_limit=RateLimitPolicy(burst=1), ip_rate_limit=False
            )
        )
        async with client_for(server.create_app(mcp=False), conversation_policy=LENIENT_CLIENT) as client:
            await client.invoke(DOMAIN, "ping", session_id="a")
            with pytest.raises(RateLimited):
                await client.invoke(DOMAIN, "ping", session_id="b")
        assert ("request.rejected", {"code": "rate_limited", "scope": "agent_key", "tier": "default"}) in events
