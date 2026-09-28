from __future__ import annotations

import json
import time
from collections.abc import AsyncIterator, Callable
from typing import Any

import httpx
import pytest
from fastapi import FastAPI
from pydantic import BaseModel
from starlette.applications import Starlette
from starlette.responses import PlainTextResponse
from starlette.routing import Route

from tests.conftest import DOMAIN
from wap.server import ActionContext, ActionResult, WAPDiscoveryMiddleware, WAPProtocolError, WAPServer
from wap.spec.crypto import Signer, verify_bytes, verify_model
from wap.spec.models import AgentManifest, AgentMessage, ErrorCode, RateLimitPolicy
from wap.spec.pow import check_solution, solve

BASE = f"https://{DOMAIN}"


def http_for(app) -> httpx.AsyncClient:
    return httpx.AsyncClient(transport=httpx.ASGITransport(app=app), base_url=BASE)


def signed(signer: Signer, **fields: Any) -> AgentMessage:
    fields.setdefault("session_id", f"session-{signer.public_key[:12]}")
    fields.setdefault("role", "user_agent")
    fields.setdefault("public_key", signer.public_key)
    return signer.sign_model(AgentMessage(**fields))


async def post(http: httpx.AsyncClient, message: AgentMessage, headers: dict[str, str] | None = None) -> httpx.Response:
    return await http.post(
        "/wap/v1/interact",
        content=message.model_dump_json(),
        headers={"Content-Type": "application/json", **(headers or {})},
    )


def parse_sse(text: str) -> list[tuple[str, Any]]:
    events = []
    for block in text.replace("\r\n", "\n").split("\n\n"):
        name, data = None, []
        for line in block.split("\n"):
            if line.startswith("event:"):
                name = line[6:].strip()
            elif line.startswith("data:"):
                data.append(line[5:].strip())
        if name:
            events.append((name, json.loads("\n".join(data))))
    return events


@pytest.fixture
async def http(shop: WAPServer) -> AsyncIterator[httpx.AsyncClient]:
    async with http_for(shop.create_app()) as client:
        yield client


class TestDiscovery:
    async def test_well_known_manifest(self, shop: WAPServer, http: httpx.AsyncClient) -> None:
        response = await http.get("/.well-known/wap.json")
        legacy = await http.get("/.well-known/agent.json")
        assert legacy.status_code == 200 and legacy.json() == response.json()
        assert response.status_code == 200
        assert response.headers["x-wap-version"] == "1.0"
        assert response.headers["access-control-allow-origin"] == "*"
        assert "max-age" in response.headers["cache-control"]
        assert verify_bytes(shop.public_key, response.content, response.headers["x-wap-signature"])
        manifest = AgentManifest.model_validate(response.json())
        assert verify_model(manifest, shop.public_key)
        assert manifest.domain == DOMAIN
        assert manifest.interaction_url == f"https://{DOMAIN}/wap/v1/interact"
        assert manifest.pow_required is False and manifest.challenge_url is None
        assert [c.id for c in manifest.capabilities] == ["get_price", "list_items"]

    async def test_generated_schemas(self, http: httpx.AsyncClient) -> None:
        manifest = AgentManifest.model_validate((await http.get("/.well-known/agent.json")).json())
        schema = manifest.get_capability("get_price").input_schema
        assert schema["type"] == "object"
        assert schema["required"] == ["sku"]
        assert schema["properties"]["sku"]["type"] == "string"
        assert schema["properties"]["quantity"] == {"default": 1, "title": "Quantity", "type": "integer"}
        assert schema["additionalProperties"] is False

    async def test_pydantic_models_and_context_injection(self, make_server: Callable[..., WAPServer]) -> None:
        server = make_server()

        class Order(BaseModel):
            item: str
            quantity: int = 1

        class Receipt(BaseModel):
            order_id: str
            item: str

        @server.action(name="place_order", title="Place an order")
        async def place_order(order: Order, ctx: ActionContext) -> Receipt:
            """Create an order."""
            return Receipt(order_id=f"{ctx.session_id}/1", item=order.item)

        cap = server.manifest().get_capability("place_order")
        assert cap.name == "Place an order"
        assert cap.description == "Create an order."
        assert set(cap.input_schema["properties"]) == {"item", "quantity"}
        assert "ctx" not in cap.input_schema["properties"]
        assert set(cap.output_schema["properties"]) == {"order_id", "item"}

        async with http_for(server.create_app()) as http:
            request = signed(Signer(), capability_id="place_order", structured_data={"item": "pie"})
            response = await post(http, request)
        assert response.status_code == 200
        assert response.json()["structured_data"] == {"order_id": f"{request.session_id}/1", "item": "pie"}

    async def test_manifest_is_cached_and_invalidated(self, shop: WAPServer) -> None:
        first = shop.manifest()
        assert shop.manifest() is first

        @shop.action(name="new_action")
        def new_action() -> str:
            return "hi"

        second = shop.manifest()
        assert second is not first
        assert second.get_capability("new_action") is not None

    def test_duplicate_and_auth_registration_errors(self, shop: WAPServer) -> None:
        with pytest.raises(ValueError, match="already registered"):
            shop.action(name="get_price")(lambda: None)
        with pytest.raises(ValueError, match="auth_handler"):
            shop.action(name="secret", requires_auth=True)(lambda: None)

    def test_mount_twice_is_idempotent_but_exclusive(
        self, shop: WAPServer, make_server: Callable[..., WAPServer]
    ) -> None:
        app = FastAPI()
        shop.mount(app)
        shop.mount(app)
        assert app.state.wap_server is shop
        paths = app.openapi()["paths"]
        assert {"/.well-known/wap.json", "/wap/v1/interact", "/wap/v1/challenge"} <= set(paths)
        with pytest.raises(RuntimeError):
            make_server().mount(app)

    async def test_discovery_middleware_for_plain_asgi(self, shop: WAPServer) -> None:
        async def homepage(request):
            return PlainTextResponse("hello")

        app = WAPDiscoveryMiddleware(Starlette(routes=[Route("/", homepage)]), shop)
        async with http_for(app) as http:
            manifest = await http.get("/.well-known/agent.json")
            head = await http.head("/.well-known/agent.json")
            options = await http.options("/.well-known/agent.json")
            post_resp = await http.post("/.well-known/agent.json")
            home = await http.get("/")
        assert manifest.status_code == 200
        assert verify_bytes(shop.public_key, manifest.content, manifest.headers["x-wap-signature"])
        assert AgentManifest.model_validate(manifest.json()).domain == DOMAIN
        assert head.status_code == 200 and head.content == b""
        assert options.status_code == 204
        assert post_resp.status_code == 405
        assert home.text == "hello"


class TestInteraction:
    async def test_json_reply_is_signed(self, shop: WAPServer, http: httpx.AsyncClient) -> None:
        request = signed(Signer(), capability_id="get_price", structured_data={"sku": "W-1", "quantity": 4})
        response = await post(http, request)
        assert response.status_code == 200
        assert verify_bytes(shop.public_key, response.content, response.headers["x-wap-signature"])
        reply = AgentMessage.model_validate(response.json())
        assert verify_model(reply, shop.public_key)
        assert reply.role.value == "business_agent"
        assert reply.in_reply_to == request.message_id
        assert reply.structured_data == {"sku": "W-1", "quantity": 4, "total": 10.0}
        assert reply.content == "Get Price completed."
        assert "x-ratelimit-remaining" in response.headers

    async def test_sse_stream(self, shop: WAPServer, http: httpx.AsyncClient) -> None:
        request = signed(Signer(), capability_id="list_items")
        response = await post(http, request, {"Accept": "text/event-stream"})
        assert response.status_code == 200
        assert response.headers["content-type"].startswith("text/event-stream")
        events = parse_sse(response.text)
        names = [name for name, _ in events]
        assert names[0] == "meta" and names[-1] == "message"
        assert "data" in names and "token" in names
        assert events[0][1]["in_reply_to"] == request.message_id
        final = AgentMessage.model_validate(events[-1][1])
        assert verify_model(final, shop.public_key)
        tokens = "".join(payload["text"] for name, payload in events if name == "token")
        assert tokens == final.content
        assert final.structured_data == {"items": ["widget", "gadget"]}

    async def test_streaming_generator_action(self, make_server: Callable[..., WAPServer]) -> None:
        server = make_server()

        @server.action(name="story")
        async def story(topic: str):
            for word in ["Once", " upon", " a", f" {topic}"]:
                yield word
            yield {"words": 4}

        assert server.manifest().get_capability("story").streaming is True
        async with http_for(server.create_app()) as http:
            response = await post(
                http,
                signed(Signer(), capability_id="story", structured_data={"topic": "loaf"}),
                {"Accept": "text/event-stream"},
            )
        events = parse_sse(response.text)
        assert [p["text"] for n, p in events if n == "token"] == ["Once", " upon", " a", " loaf"]
        assert AgentMessage.model_validate(events[-1][1]).structured_data == {"words": 4}

    async def test_action_result_and_sync_generator(self, make_server: Callable[..., WAPServer]) -> None:
        server = make_server()

        @server.action(name="explicit")
        def explicit() -> ActionResult:
            return ActionResult(content="custom text", data={"k": "v"})

        @server.action(name="gen")
        def gen():
            yield "a"
            yield {"x": 1}
            yield ActionResult(content="b", data={"y": 2})

        async with http_for(server.create_app()) as http:
            r1 = (await post(http, signed(Signer(), capability_id="explicit"))).json()
            r2 = (await post(http, signed(Signer(), capability_id="gen"))).json()
        assert (r1["content"], r1["structured_data"]) == ("custom text", {"k": "v"})
        assert (r2["content"], r2["structured_data"]) == ("ab", {"x": 1, "y": 2})

    async def test_default_intent_router(self, http: httpx.AsyncClient) -> None:
        reply = (await post(http, signed(Signer(), content="Please list your catalogue items"))).json()
        assert reply["structured_data"] == {"items": ["widget", "gadget"]}

        needs = (await post(http, signed(Signer(), content="what is the price of a widget"))).json()
        assert needs["structured_data"]["needs_input"] is True
        assert needs["structured_data"]["missing"] == ["sku"]

        filled = (
            await post(http, signed(Signer(), content="what is the price", structured_data={"sku": "W-9"}))
        ).json()
        assert filled["structured_data"]["total"] == 2.5

        unknown = (await post(http, signed(Signer(), content="zzzz qqqq"))).json()
        assert "could not map" in unknown["content"]

    async def test_custom_intent_handler_and_session_history(self, make_server: Callable[..., WAPServer]) -> None:
        server = make_server()

        @server.intent
        async def echo(intent: str, ctx: ActionContext) -> str:
            ctx.state["turns"] = ctx.state.get("turns", 0) + 1
            return f"turn {ctx.state['turns']}: {intent} (history={len(ctx.history)})"

        signer = Signer()
        async with http_for(server.create_app()) as http:
            first = (await post(http, signed(signer, content="hello"))).json()
            second = (await post(http, signed(signer, content="again"))).json()
        assert first["content"] == "turn 1: hello (history=0)"
        assert second["content"] == "turn 2: again (history=2)"
        session = await server.sessions.get(f"session-{signer.public_key[:12]}")
        assert len(session.history) == 4


class TestErrors:
    async def expect_error(self, response: httpx.Response, status: int, code: ErrorCode) -> dict:
        assert response.status_code == status, response.text
        body = response.json()
        assert body["error"]["code"] == code.value
        return body["error"]

    async def test_invalid_json(self, http: httpx.AsyncClient) -> None:
        response = await http.post(
            "/wap/v1/interact", content=b"{not json", headers={"Content-Type": "application/json"}
        )
        await self.expect_error(response, 400, ErrorCode.INVALID_REQUEST)

    async def test_oversized_body(self, http: httpx.AsyncClient) -> None:
        response = await http.post("/wap/v1/interact", content=b"x" * (300 * 1024))
        await self.expect_error(response, 400, ErrorCode.INVALID_REQUEST)

    async def test_unsupported_version(self, http: httpx.AsyncClient) -> None:
        response = await post(http, signed(Signer(), content="hi"), {"X-WAP-Version": "2.0"})
        error = await self.expect_error(response, 400, ErrorCode.UNSUPPORTED_VERSION)
        assert error["details"]["supported"] == ["1.0"]

    async def test_business_role_rejected(self, http: httpx.AsyncClient) -> None:
        response = await post(http, signed(Signer(), role="business_agent", content="hi"))
        await self.expect_error(response, 400, ErrorCode.INVALID_REQUEST)

    async def test_missing_or_bad_signature(self, http: httpx.AsyncClient) -> None:
        signer = Signer()
        unsigned = AgentMessage(session_id="s", role="user_agent", content="hi", public_key=signer.public_key)
        await self.expect_error(await post(http, unsigned), 401, ErrorCode.INVALID_SIGNATURE)

        tampered = signed(signer, content="1 widget").model_copy(update={"content": "999 widgets"})
        await self.expect_error(await post(http, tampered), 401, ErrorCode.INVALID_SIGNATURE)

        impostor = signed(signer, content="hi").model_copy(update={"public_key": Signer().public_key})
        await self.expect_error(await post(http, impostor), 401, ErrorCode.INVALID_SIGNATURE)

        no_key = Signer().sign_model(AgentMessage(session_id="s", role="user_agent", content="hi"))
        await self.expect_error(await post(http, no_key), 401, ErrorCode.INVALID_SIGNATURE)

    async def test_replay_and_stale(self, http: httpx.AsyncClient) -> None:
        signer = Signer()
        message = signed(signer, content="list items")
        assert (await post(http, message)).status_code == 200
        await self.expect_error(await post(http, message), 409, ErrorCode.REPLAY_DETECTED)
        stale = signed(signer, content="hi", timestamp=time.time() - 3600)
        await self.expect_error(await post(http, stale), 409, ErrorCode.REPLAY_DETECTED)

    async def test_unknown_capability(self, http: httpx.AsyncClient) -> None:
        response = await post(http, signed(Signer(), capability_id="launch_rocket"))
        error = await self.expect_error(response, 404, ErrorCode.UNKNOWN_CAPABILITY)
        assert error["details"]["available"] == ["get_price", "list_items"]

    async def test_validation_error(self, http: httpx.AsyncClient) -> None:
        for payload in ({}, {"sku": "x", "quantity": "many"}, {"sku": "x", "extra": 1}):
            response = await post(http, signed(Signer(), capability_id="get_price", structured_data=payload))
            error = await self.expect_error(response, 422, ErrorCode.VALIDATION_ERROR)
            assert error["details"]["errors"]

    async def test_validation_error_with_streaming_accept(self, http: httpx.AsyncClient) -> None:
        response = await post(
            http, signed(Signer(), capability_id="get_price", structured_data={}), {"Accept": "text/event-stream"}
        )
        await self.expect_error(response, 422, ErrorCode.VALIDATION_ERROR)

    async def test_action_failure(self, make_server: Callable[..., WAPServer]) -> None:
        server = make_server()

        @server.action(name="explode")
        async def explode() -> dict:
            raise RuntimeError("oven on fire")

        @server.action(name="explode_later")
        async def explode_later():
            yield "partial "
            raise WAPProtocolError(ErrorCode.FORBIDDEN, "not today")

        async with http_for(server.create_app()) as http:
            error = await self.expect_error(
                await post(http, signed(Signer(), capability_id="explode")), 502, ErrorCode.ACTION_FAILED
            )
            assert "oven on fire" in error["message"]
            stream = await post(http, signed(Signer(), capability_id="explode_later"), {"Accept": "text/event-stream"})
            assert stream.status_code == 200
            events = parse_sse(stream.text)
            assert events[-1][0] == "error" and events[-1][1]["error"]["code"] == "forbidden"

    async def test_rate_limit(self, make_server: Callable[..., WAPServer]) -> None:
        server = make_server(rate_limit=RateLimitPolicy(requests_per_minute=60, burst=2))
        server.action(name="ping")(lambda: "pong")
        async with http_for(server.create_app()) as http:
            codes = [(await post(http, signed(Signer(), capability_id="ping"))).status_code for _ in range(3)]
            assert codes == [200, 200, 429]
            blocked = await post(http, signed(Signer(), capability_id="ping"))
        error = await self.expect_error(blocked, 429, ErrorCode.RATE_LIMITED)
        assert int(blocked.headers["retry-after"]) >= 1
        assert error["retry_after"] > 0
        assert error["details"]["scope"] == "ip"

    async def test_per_agent_key_limit(self, make_server: Callable[..., WAPServer]) -> None:
        server = make_server(rate_limit=RateLimitPolicy(requests_per_minute=60, burst=2, scopes=["agent_key"]))
        server.action(name="ping")(lambda: "pong")
        signer = Signer()
        async with http_for(server.create_app()) as http:
            codes = [(await post(http, signed(signer, capability_id="ping"))).status_code for _ in range(3)]
            other = await post(http, signed(Signer(), capability_id="ping"))
        assert codes == [200, 200, 429]
        assert other.status_code == 200

    async def test_session_bound_to_agent_key(self, http: httpx.AsyncClient) -> None:
        assert (await post(http, signed(Signer(), session_id="shared", content="list items"))).status_code == 200
        hijack = await post(http, signed(Signer(), session_id="shared", content="list items"))
        await self.expect_error(hijack, 403, ErrorCode.FORBIDDEN)


class TestProofOfWorkGate:
    @pytest.fixture
    def pow_server(self, make_server: Callable[..., WAPServer]) -> WAPServer:
        server = make_server(require_pow=True, pow_difficulty=2)
        server.action(name="expensive", description="Calls a paid LLM")(lambda: {"tokens": 1000})
        return server

    async def test_manifest_advertises_pow(self, pow_server: WAPServer) -> None:
        manifest = pow_server.manifest()
        assert manifest.pow_required and manifest.pow_difficulty == 2
        assert manifest.challenge_url == f"https://{DOMAIN}/wap/v1/challenge"

    async def test_full_pow_flow(self, pow_server: WAPServer) -> None:
        async with http_for(pow_server.create_app()) as http:
            missing = await post(http, signed(Signer(), capability_id="expensive"))
            assert missing.status_code == 428
            attached = missing.json()["error"]["details"]["challenge"]
            assert attached["difficulty"] == 2

            challenge_response = await http.get("/wap/v1/challenge")
            assert challenge_response.status_code == 200
            assert challenge_response.headers["cache-control"] == "no-store"
            assert verify_bytes(
                pow_server.public_key, challenge_response.content, challenge_response.headers["x-wap-signature"]
            )
            challenge = challenge_response.json()

            nonce = solve(challenge["seed"], challenge["difficulty"])
            ok = await post(
                http, signed(Signer(), capability_id="expensive", pow_seed=challenge["seed"], pow_nonce=nonce)
            )
            assert ok.status_code == 200
            assert ok.json()["structured_data"] == {"tokens": 1000}

            reused = await post(
                http, signed(Signer(), capability_id="expensive", pow_seed=challenge["seed"], pow_nonce=nonce)
            )
            assert reused.status_code == 403
            assert reused.json()["error"]["details"]["reason"] == "replayed"
            assert "challenge" in reused.json()["error"]["details"]

    async def test_wrong_nonce(self, pow_server: WAPServer) -> None:
        async with http_for(pow_server.create_app()) as http:
            seed = (await http.get("/wap/v1/challenge")).json()["seed"]
            bad = next(format(i, "x") for i in range(1000) if not check_solution(seed, format(i, "x"), 2))
            response = await post(http, signed(Signer(), capability_id="expensive", pow_seed=seed, pow_nonce=bad))
        assert response.status_code == 403
        assert response.json()["error"]["details"]["reason"] == "insufficient_work"

    async def test_challenge_disabled_without_pow(self, http: httpx.AsyncClient) -> None:
        response = await http.get("/wap/v1/challenge")
        assert response.status_code == 400


class TestAuthorization:
    async def test_bearer_auth(self, make_server: Callable[..., WAPServer]) -> None:
        async def check_token(token: str) -> dict | None:
            return {"account": "acme"} if token == "s3cret" else None

        server = make_server(auth_handler=check_token)

        @server.action(name="wholesale_prices", requires_auth=True)
        async def wholesale_prices(ctx: ActionContext) -> dict:
            return {"account": ctx.principal["account"], "discount": 0.2}

        assert server.manifest().get_capability("wholesale_prices").requires_auth
        async with http_for(server.create_app()) as http:
            anonymous = await post(http, signed(Signer(), capability_id="wholesale_prices"))
            wrong = await post(
                http, signed(Signer(), capability_id="wholesale_prices"), {"Authorization": "Bearer nope"}
            )
            basic = await post(http, signed(Signer(), capability_id="wholesale_prices"), {"Authorization": "Basic abc"})
            good = await post(
                http, signed(Signer(), capability_id="wholesale_prices"), {"Authorization": "Bearer s3cret"}
            )
        assert anonymous.status_code == 401 and anonymous.json()["error"]["code"] == "auth_required"
        assert wrong.status_code == 401
        assert basic.status_code == 401
        assert good.status_code == 200
        assert good.json()["structured_data"] == {"account": "acme", "discount": 0.2}


def test_domain_is_validated() -> None:
    with pytest.raises(ValueError):
        WAPServer(name="x", domain="https://bad")


def test_local_domain_uses_http(keypair) -> None:
    server = WAPServer(name="Local", domain="localhost:8000", private_key=keypair.private_key)
    assert server.manifest().interaction_url == "http://localhost:8000/wap/v1/interact"
    custom = WAPServer(
        name="C", domain="shop.example", private_key=keypair.private_key, base_url="https://api.shop.example/"
    )
    assert custom.manifest().interaction_url == "https://api.shop.example/wap/v1/interact"
