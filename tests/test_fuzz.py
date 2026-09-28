"""Property-based tests: hostile or random input must never crash anything or bypass a check."""

from __future__ import annotations

import asyncio
import json

import httpx
import pytest
from hypothesis import HealthCheck, given, settings
from hypothesis import strategies as st
from pydantic import ValidationError

from tests.conftest import DOMAIN
from wap.client import ManifestNotFound, RateLimited, VerificationFailed
from wap.client.resolver import ManifestResolver
from wap.mcp.safety import Sanitizer, SanitizerReport, clean_text
from wap.server import WAPServer
from wap.server.observability import LoggingObserver, MetricsObserver, combine
from wap.spec.crypto import Signer
from wap.spec.models import AgentManifest, AgentMessage, ErrorCode, RateLimitPolicy, normalize_authority
from wap.spec.pow import PowEngine, PowError
from wap.storage.meters import MeterTable

FUZZ = settings(max_examples=120, deadline=None, suppress_health_check=[HealthCheck.function_scoped_fixture])
json_values = st.recursive(
    st.none() | st.booleans() | st.integers() | st.floats(allow_nan=False) | st.text(max_size=20),
    lambda children: st.lists(children, max_size=3) | st.dictionaries(st.text(max_size=10), children, max_size=3),
    max_leaves=8,
)
VALID_CODES = {code.value for code in ErrorCode}


def fuzz_server() -> WAPServer:
    server = WAPServer(
        name="Fuzz",
        domain=DOMAIN,
        private_key=Signer().export_private_key(),
        rate_limit=False,
        ip_rate_limit=False,
        conversation_policy=False,
    )

    @server.action(name="price", effects="read")
    def price(sku: str, quantity: int = 1) -> dict:
        return {"sku": sku, "total": 2.5 * quantity}

    return server


APP = fuzz_server().create_app(mcp=False)


def post(body: bytes, headers: dict[str, str] | None = None) -> httpx.Response:
    async def go() -> httpx.Response:
        async with httpx.AsyncClient(transport=httpx.ASGITransport(app=APP), base_url=f"https://{DOMAIN}") as http:
            return await http.post("/wap/v1/interact", content=body, headers=headers or {})

    return asyncio.run(go())


def assert_wap_error(response: httpx.Response) -> None:
    assert response.status_code < 500, response.text
    if response.status_code >= 400:
        assert response.json()["error"]["code"] in VALID_CODES
        assert response.headers["x-wap-signature"]


@FUZZ
@given(st.binary(max_size=400))
def test_random_bytes_never_crash_the_server(body: bytes) -> None:
    assert_wap_error(post(body))


@FUZZ
@given(st.dictionaries(st.sampled_from(list(AgentMessage.model_fields) + ["junk"]), json_values, max_size=8))
def test_random_envelopes_never_crash_the_server(fields: dict) -> None:
    response = post(json.dumps(fields).encode())
    assert_wap_error(response)
    assert response.status_code != 200  # unsigned random envelopes must never be accepted


@FUZZ
@given(payload=st.dictionaries(st.text(max_size=8), json_values, max_size=4), content=st.text(max_size=40))
def test_signed_requests_with_random_payloads(payload: dict, content: str) -> None:
    signer = Signer()
    try:
        unsigned = AgentMessage(
            session_id="fuzz-session",
            role="user_agent",
            content=content,
            capability_id="price",
            structured_data=payload,
            public_key=signer.public_key,
        )
    except ValidationError:
        # e.g. integers beyond ±2**53: the server must reject the raw JSON cleanly instead.
        raw = {"session_id": "s", "role": "user_agent", "structured_data": payload, "signature": "00" * 64}
        assert post(json.dumps(raw).encode()).status_code == 400
        return
    message = signer.sign_model(unsigned)
    response = post(message.model_dump_json().encode(), {"X-WAP-Version": "1.0"})
    assert_wap_error(response)
    if response.status_code == 200:
        assert isinstance(payload.get("sku"), str)


@given(st.text(max_size=80))
def test_authority_parsing_only_raises_value_error(text: str) -> None:
    try:
        assert normalize_authority(text) == normalize_authority(normalize_authority(text))
    except ValueError:
        pass


@given(seed=st.text(max_size=100), nonce=st.text(max_size=150))
def test_pow_verification_only_raises_pow_errors(seed: str, nonce: str) -> None:
    engine = PowEngine(difficulty=1)
    with pytest.raises(PowError):
        engine.verify(seed, nonce)  # a random seed is never one this engine issued


@FUZZ
@given(json_values)
def test_hostile_manifest_documents(document) -> None:
    body = json.dumps(document).encode()

    async def go() -> None:
        http = httpx.AsyncClient(transport=httpx.MockTransport(lambda request: httpx.Response(200, content=body)))
        try:
            await ManifestResolver(http, www_fallback=False).resolve(DOMAIN)
        except (ManifestNotFound, VerificationFailed):
            pass
        finally:
            await http.aclose()

    asyncio.run(go())
    try:
        AgentManifest.model_validate(document)
    except ValidationError:
        pass


@given(st.text(max_size=3000), st.integers(min_value=1, max_value=500))
def test_sanitizer_bounds(text: str, limit: int) -> None:
    cleaned = clean_text(text, limit)
    assert len(cleaned) <= limit
    assert not any(ch in cleaned for ch in "​‮﻿")
    Sanitizer(max_chars=limit).schema({"description": text, "properties": {"x": {"title": text}}}, SanitizerReport())


@given(
    st.lists(st.floats(min_value=0, max_value=5, allow_nan=False), min_size=1, max_size=300),
    st.integers(min_value=1, max_value=20),
    st.integers(min_value=1, max_value=120),
)
def test_rate_limiter_never_exceeds_burst_plus_refill(gaps: list[float], burst: int, per_minute: int) -> None:
    """Token-bucket bound: admitted <= burst + rate * elapsed, whatever the arrival pattern."""
    table = MeterTable()
    now = start = 1_000_000.0
    admitted = 0
    for gap in gaps:
        now += gap
        decision = table.check([("ip", "ip:x")], limit=per_minute, window=60.0, burst=burst, cost=1.0, now=now)
        admitted += decision.allowed
    assert admitted <= burst + per_minute / 60.0 * (now - start) + 1e-9


def test_metrics_and_logging_observers() -> None:
    metrics = MetricsObserver()
    logged: list[str] = []

    class Capture(LoggingObserver):
        def __call__(self, event, attributes) -> None:  # type: ignore[override]
            logged.append(event)
            super().__call__(event, attributes)

    def broken(event, attributes) -> None:
        raise RuntimeError("sink down")

    observe = combine(broken, metrics, Capture())
    for ms in range(1, 101):
        observe("request.completed", {"capability": "price", "tier": "default", "duration_ms": float(ms)})
    observe("request.rejected", {"code": "rate_limited", "scope": "ip"})
    assert metrics.count("request.completed") == 100
    assert metrics.count("request.rejected", "rate_limited") == 1
    assert metrics.percentile("price", 50) == 50.0 and metrics.percentile("price", 99) == 99.0
    snapshot = metrics.snapshot()
    assert snapshot["latency_ms"]["price"]["p95"] == 95.0
    assert len(logged) == 101


async def test_observer_wired_into_server() -> None:
    from tests.conftest import client_for

    metrics = MetricsObserver()
    server = WAPServer(
        name="Obs",
        domain=DOMAIN,
        private_key=Signer().export_private_key(),
        observer=metrics,
        rate_limit=RateLimitPolicy(burst=2),
        ip_rate_limit=False,
    )
    server.action(name="ping", effects="read")(lambda: "pong")
    async with client_for(server.create_app(mcp=False)) as client:
        for i in range(2):
            await client.invoke(DOMAIN, "ping", session_id=f"s{i}")
        with pytest.raises(RateLimited):
            await client.invoke(DOMAIN, "ping", session_id="s9")
    assert metrics.count("request.completed") == 2
    assert metrics.count("request.rejected", "rate_limited") == 1
