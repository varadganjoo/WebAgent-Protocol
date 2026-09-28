"""Example business agent: an artisan bakery exposing live inventory over WAP.

Run it::

    python examples/bakery_server.py            # serves http://localhost:8000
    # or
    wap serve examples.bakery_server:app --port 8000

Then talk to it::

    wap inspect localhost:8000
    wap ask localhost:8000 "what's on the menu?"
    wap ask localhost:8000 -c check_pastry_stock -d '{"item": "Sourdough Croissant"}'

Capabilities:

* ``get_menu``               list pastries, prices and live availability
* ``check_pastry_stock``     units available for one item (net of active holds)
* ``negotiate_bulk_price``   multi-turn bulk-price negotiation producing a signed quote
* ``reserve_item``           place a time-limited hold and return a reservation token

The bakery also registers a free-text intent handler so that natural-language
requests ("hold 2 almond croissants for Ada") are routed to the right capability.
"""

from __future__ import annotations

import asyncio
import os
import re
import secrets
import time
from dataclasses import dataclass, field
from typing import Any

from fastapi import FastAPI
from pydantic import BaseModel, Field

from wap.server import ActionContext, ActionResult, KeywordIntentRouter, WAPProtocolError, WAPServer
from wap.spec.models import ErrorCode, RateLimitPolicy

HOLD_SECONDS = 30 * 60
QUOTE_SECONDS = 10 * 60
MAX_NEGOTIATION_ROUNDS = 3


@dataclass
class Pastry:
    name: str
    unit_price: float
    stock: int
    description: str


@dataclass
class Hold:
    token: str
    item: str
    quantity: int
    unit_price: float
    customer_name: str
    expires_at: float


@dataclass
class Quote:
    quote_id: str
    session_id: str
    item: str
    quantity: int
    unit_price: float
    expires_at: float


@dataclass
class Inventory:
    pastries: dict[str, Pastry]
    holds: dict[str, Hold] = field(default_factory=dict)
    quotes: dict[str, Quote] = field(default_factory=dict)
    lock: asyncio.Lock = field(default_factory=asyncio.Lock)

    def _expire(self, now: float) -> None:
        for token in [t for t, h in self.holds.items() if h.expires_at <= now]:
            hold = self.holds.pop(token)
            self.pastries[hold.item].stock += hold.quantity
        for quote_id in [q for q, quote in self.quotes.items() if quote.expires_at <= now]:
            del self.quotes[quote_id]

    def find(self, query: str) -> Pastry:
        wanted = _normalize(query)
        for key, pastry in self.pastries.items():
            if wanted == key:
                return pastry
        candidates = [p for key, p in self.pastries.items() if wanted in key or key in wanted]
        if len(candidates) == 1:
            return candidates[0]
        wanted_tokens = set(wanted.split())
        scored = sorted(
            ((len(wanted_tokens & set(key.split())), p) for key, p in self.pastries.items()),
            key=lambda item: item[0],
            reverse=True,
        )
        if scored and scored[0][0] > 0 and (len(scored) == 1 or scored[0][0] > scored[1][0]):
            return scored[0][1]
        raise WAPProtocolError(
            ErrorCode.VALIDATION_ERROR,
            f"we don't bake anything called {query!r}",
            details={"menu": [p.name for p in self.pastries.values()]},
        )

    def held(self, item: str) -> int:
        return sum(h.quantity for h in self.holds.values() if h.item == item)


def _normalize(text: str) -> str:
    words = re.findall(r"[a-z]+", text.lower())
    return " ".join(w[:-1] if len(w) > 3 and w.endswith("s") and not w.endswith("ss") else w for w in words)


def default_inventory() -> Inventory:
    items = [
        Pastry("Sourdough Croissant", 4.50, 24, "72-hour fermented, laminated with cultured butter."),
        Pastry("Pain au Chocolat", 4.75, 18, "Two batons of 70% dark chocolate."),
        Pastry("Almond Croissant", 5.25, 12, "Twice-baked with frangipane and toasted almonds."),
        Pastry("Cardamom Bun", 4.00, 20, "Swedish-style knot with freshly ground cardamom."),
        Pastry("Country Sourdough Loaf", 9.00, 10, "900 g, 20% whole wheat, dark bake."),
        Pastry("Baguette", 3.50, 30, "Poolish baguette, baked every two hours."),
    ]
    return Inventory({_normalize(p.name): p for p in items})


def bulk_discount(quantity: int) -> float:
    if quantity >= 24:
        return 0.15
    if quantity >= 12:
        return 0.10
    if quantity >= 6:
        return 0.05
    return 0.0


class MenuItem(BaseModel):
    name: str
    unit_price: float
    available: int
    description: str


class Menu(BaseModel):
    bakery: str
    currency: str = "USD"
    items: list[MenuItem]


class StockLevel(BaseModel):
    item: str
    in_stock: bool
    available: int
    held: int
    unit_price: float


class Reservation(BaseModel):
    reservation_token: str
    item: str
    quantity: int
    unit_price: float
    total: float
    customer_name: str
    expires_at: float
    quote_applied: bool


class NegotiationOutcome(BaseModel):
    status: str = Field(description="accepted | counter_offer | final_offer | rejected")
    item: str
    quantity: int
    list_unit_price: float
    offered_unit_price: float
    counter_unit_price: float | None = None
    quote_id: str | None = None
    round: int
    rounds_remaining: int


def create_bakery(
    domain: str = "localhost:8000",
    *,
    private_key: str | None = None,
    require_pow: bool = True,
    pow_difficulty: int = 4,
    rate_limit: RateLimitPolicy | None = None,
    inventory: Inventory | None = None,
) -> tuple[WAPServer, FastAPI, Inventory]:
    """Build the bakery agent. Returns ``(wap_server, fastapi_app, inventory)``."""
    inv = inventory or default_inventory()
    wap = WAPServer(
        name="Golden Crust Bakery",
        domain=domain,
        private_key=private_key,
        require_pow=require_pow,
        description="Neighbourhood sourdough bakery. Live pastry inventory, bulk quotes and pickup holds.",
        pow_difficulty=pow_difficulty,
        rate_limit=rate_limit or RateLimitPolicy(requests_per_minute=120, burst=30),
    )

    @wap.action(name="get_menu", description="List every pastry with its price and live availability.")
    async def get_menu() -> Menu:
        async with inv.lock:
            inv._expire(time.time())
            return Menu(
                bakery=wap.name,
                items=[
                    MenuItem(name=p.name, unit_price=p.unit_price, available=p.stock, description=p.description)
                    for p in inv.pastries.values()
                ],
            )

    @wap.action(
        name="check_pastry_stock",
        description="Check how many units of a pastry are available right now (net of active holds).",
    )
    async def check_pastry_stock(item: str) -> StockLevel:
        async with inv.lock:
            inv._expire(time.time())
            pastry = inv.find(item)
            return StockLevel(
                item=pastry.name,
                in_stock=pastry.stock > 0,
                available=pastry.stock,
                held=inv.held(pastry.name),
                unit_price=pastry.unit_price,
            )

    @wap.action(
        name="negotiate_bulk_price",
        description=(
            "Negotiate a unit price for a bulk order (6+ units). Send an offer; the bakery accepts, "
            "counters, or makes a final offer. Accepted offers return a quote_id valid for 10 minutes "
            "that reserve_item will honour within the same session."
        ),
    )
    async def negotiate_bulk_price(
        item: str,
        quantity: int = Field(ge=1, le=500),
        offered_unit_price: float = Field(gt=0),
        ctx: ActionContext = None,  # type: ignore[assignment]
    ) -> NegotiationOutcome:
        async with inv.lock:
            now = time.time()
            inv._expire(now)
            pastry = inv.find(item)
            negotiations: dict[str, Any] = ctx.state.setdefault("negotiations", {})
            thread = negotiations.setdefault(pastry.name, {"round": 0, "last_counter": pastry.unit_price})
            thread["round"] += 1
            rnd = thread["round"]
            floor = round(pastry.unit_price * (1 - bulk_discount(quantity)), 2)
            remaining = max(0, MAX_NEGOTIATION_ROUNDS - rnd)
            base = dict(
                item=pastry.name,
                quantity=quantity,
                list_unit_price=pastry.unit_price,
                offered_unit_price=offered_unit_price,
                round=rnd,
                rounds_remaining=remaining,
            )
            if quantity > pastry.stock:
                return NegotiationOutcome(status="rejected", **base)
            accept_at = min(thread["last_counter"], pastry.unit_price)
            if offered_unit_price >= floor or offered_unit_price >= accept_at:
                quote = Quote(
                    quote_id="Q-" + secrets.token_hex(6).upper(),
                    session_id=ctx.session_id,
                    item=pastry.name,
                    quantity=quantity,
                    unit_price=round(offered_unit_price, 2),
                    expires_at=now + QUOTE_SECONDS,
                )
                inv.quotes[quote.quote_id] = quote
                negotiations.pop(pastry.name, None)
                return NegotiationOutcome(status="accepted", quote_id=quote.quote_id, **base)
            if rnd >= MAX_NEGOTIATION_ROUNDS or floor >= thread["last_counter"]:
                thread["last_counter"] = floor
                return NegotiationOutcome(status="final_offer", counter_unit_price=floor, **base)
            counter = round(max(floor, (thread["last_counter"] + offered_unit_price) / 2), 2)
            thread["last_counter"] = counter
            return NegotiationOutcome(status="counter_offer", counter_unit_price=counter, **base)

    @wap.action(
        name="reserve_item",
        description=(
            "Hold pastries for pickup for 30 minutes. Returns a reservation_token to present at the counter. "
            "Pass a quote_id from negotiate_bulk_price to lock in a negotiated price."
        ),
    )
    async def reserve_item(
        item: str,
        quantity: int = Field(default=1, ge=1, le=500),
        customer_name: str = Field(default="WAP guest", min_length=1, max_length=80),
        quote_id: str | None = None,
        ctx: ActionContext = None,  # type: ignore[assignment]
    ) -> Reservation:
        async with inv.lock:
            now = time.time()
            inv._expire(now)
            pastry = inv.find(item)
            if quantity > pastry.stock:
                raise WAPProtocolError(
                    ErrorCode.VALIDATION_ERROR,
                    f"only {pastry.stock} x {pastry.name} available",
                    details={"available": pastry.stock},
                )
            unit_price = pastry.unit_price
            quote_applied = False
            if quote_id is not None:
                quote = inv.quotes.get(quote_id)
                if (
                    quote is None
                    or quote.session_id != ctx.session_id
                    or quote.item != pastry.name
                    or quote.quantity != quantity
                ):
                    raise WAPProtocolError(
                        ErrorCode.VALIDATION_ERROR,
                        "quote_id is unknown, expired, or does not match this session, item and quantity",
                    )
                unit_price = quote.unit_price
                quote_applied = True
                del inv.quotes[quote_id]
            pastry.stock -= quantity
            hold = Hold(
                token="RSV-" + secrets.token_hex(8).upper(),
                item=pastry.name,
                quantity=quantity,
                unit_price=unit_price,
                customer_name=customer_name,
                expires_at=now + HOLD_SECONDS,
            )
            inv.holds[hold.token] = hold
            return Reservation(
                reservation_token=hold.token,
                item=hold.item,
                quantity=quantity,
                unit_price=unit_price,
                total=round(unit_price * quantity, 2),
                customer_name=customer_name,
                expires_at=hold.expires_at,
                quote_applied=quote_applied,
            )

    fallback = KeywordIntentRouter()

    @wap.intent
    async def understand(intent: str, ctx: ActionContext) -> Any:
        """Rule-based natural-language front desk. Swap for an LLM tool-calling loop in production."""
        text = intent.lower()
        extra = ctx.message.structured_data or {}
        item_name = None
        for pastry in sorted(inv.pastries.values(), key=lambda p: -len(p.name)):
            if _normalize(pastry.name) in _normalize(text):
                item_name = pastry.name
                break
        numbers = re.findall(r"\b(\d{1,3})\b(?!\.\d)", text)
        quantity = int(numbers[0]) if numbers else int(extra.get("quantity", 1))
        price = re.search(r"\$\s*(\d+(?:\.\d{1,2})?)", text)

        if item_name is None and re.search(r"\b(menu|sell|offer|have|bake)\b", text):
            menu = await ctx.invoke("get_menu")
            names = ", ".join(i["name"] for i in (menu.data or {}).get("items", []))
            return ActionResult(content=f"Today we're baking: {names}.", data=menu.data)
        if item_name and price:
            outcome = await ctx.invoke(
                "negotiate_bulk_price",
                {"item": item_name, "quantity": quantity, "offered_unit_price": float(price.group(1))},
            )
            data = outcome.data or {}
            status = data.get("status")
            if status == "accepted":
                msg = f"Deal: {quantity} x {item_name} at ${data['offered_unit_price']:.2f}. Quote {data['quote_id']}."
            elif status in ("counter_offer", "final_offer"):
                label = "Our final offer" if status == "final_offer" else "We can do"
                msg = f"{label} ${data['counter_unit_price']:.2f} each for {quantity} x {item_name}."
            else:
                msg = f"Sorry, we can't fill {quantity} x {item_name} right now."
            return ActionResult(content=msg, data=data)
        if item_name and re.search(r"\b(reserve|hold|order|book|save|put aside)\b", text):
            name_match = re.search(r"\bfor ([A-Z][a-zA-Z'-]+(?: [A-Z][a-zA-Z'-]+)?)", intent)
            customer = extra.get("customer_name") or (name_match.group(1) if name_match else "WAP guest")
            payload: dict[str, Any] = {"item": item_name, "quantity": quantity, "customer_name": customer}
            if extra.get("quote_id"):
                payload["quote_id"] = extra["quote_id"]
            result = await ctx.invoke("reserve_item", payload)
            data = result.data or {}
            return ActionResult(
                content=(
                    f"Held {data['quantity']} x {data['item']} for {data['customer_name']} "
                    f"(${data['total']:.2f}). Reservation token: {data['reservation_token']}."
                ),
                data=data,
            )
        if item_name:
            stock = await ctx.invoke("check_pastry_stock", {"item": item_name})
            data = stock.data or {}
            if data.get("available", 0) > 0:
                msg = f"Yes! {data['available']} x {data['item']} available at ${data['unit_price']:.2f} each."
            else:
                msg = f"Sorry, {data['item']} is sold out for now."
            return ActionResult(content=msg, data=data)
        return await fallback(intent, ctx)

    app = FastAPI(title="Golden Crust Bakery", version="1.0.0")

    @app.get("/")
    async def home() -> dict[str, str]:
        return {"bakery": wap.name, "agent_manifest": "/.well-known/agent.json"}

    wap.mount(app)
    return wap, app, inv


wap, app, inventory = create_bakery(
    domain=os.environ.get("BAKERY_DOMAIN", "localhost:8000"),
    private_key=os.environ.get("WAP_PRIVATE_KEY") or None,
    pow_difficulty=int(os.environ.get("BAKERY_POW_DIFFICULTY", "4")),
)


if __name__ == "__main__":
    import uvicorn

    port = int(os.environ.get("PORT", "8000"))
    print(f"Golden Crust Bakery agent · key {wap.signer.fingerprint} · http://localhost:{port}/.well-known/agent.json")
    uvicorn.run(app, host=os.environ.get("HOST", "127.0.0.1"), port=port)
