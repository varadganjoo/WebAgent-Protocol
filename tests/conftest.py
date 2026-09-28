from __future__ import annotations

import sys
from collections.abc import AsyncIterator, Callable
from pathlib import Path

import httpx
import pytest

ROOT = Path(__file__).resolve().parent.parent
if str(ROOT) not in sys.path:
    sys.path.insert(0, str(ROOT))

from wap.client import WAPClient  # noqa: E402
from wap.server import WAPServer  # noqa: E402
from wap.spec.crypto import KeyPair, generate_keypair  # noqa: E402
from wap.spec.models import RateLimitPolicy  # noqa: E402

DOMAIN = "shop.example"


@pytest.fixture
def keypair() -> KeyPair:
    return generate_keypair()


@pytest.fixture
def make_server(keypair: KeyPair) -> Callable[..., WAPServer]:
    def factory(**kwargs) -> WAPServer:
        kwargs.setdefault("name", "Test Shop")
        kwargs.setdefault("domain", DOMAIN)
        kwargs.setdefault("private_key", keypair.private_key)
        kwargs.setdefault("pow_difficulty", 2)
        kwargs.setdefault("rate_limit", RateLimitPolicy(requests_per_minute=1000, burst=1000))
        return WAPServer(**kwargs)

    return factory


@pytest.fixture
def shop(make_server: Callable[..., WAPServer]) -> WAPServer:
    server = make_server(description="Widgets and gadgets")

    @server.action(name="get_price", description="Get the price of a widget")
    async def get_price(sku: str, quantity: int = 1) -> dict:
        return {"sku": sku, "quantity": quantity, "total": 2.5 * quantity}

    @server.action(name="list_items", description="List catalogue items")
    def list_items() -> dict:
        return {"items": ["widget", "gadget"]}

    return server


def client_for(app, **kwargs) -> WAPClient:
    return WAPClient(transport=httpx.ASGITransport(app=app), **kwargs)


@pytest.fixture
async def shop_client(shop: WAPServer) -> AsyncIterator[WAPClient]:
    async with client_for(shop.create_app()) as client:
        yield client
