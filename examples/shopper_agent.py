"""Example user agent: discovers the bakery, checks stock, negotiates and places a hold.

Start the bakery first (``python examples/bakery_server.py``), then::

    python examples/shopper_agent.py                 # talks to localhost:8000
    python examples/shopper_agent.py bakery.example  # any WAP-enabled domain

The script prints every protocol step: manifest verification, proof-of-work,
streamed tokens, the multi-turn price negotiation and the final signed
reservation token.
"""

from __future__ import annotations

import asyncio
import sys
import time

from rich.console import Console
from rich.table import Table

from wap import WAPClient
from wap.spec.crypto import fingerprint
from wap.spec.models import StreamEventType

console = Console()
ITEM = "Sourdough Croissant"
QUANTITY = 12
OPENING_OFFER = 3.60


async def run(domain: str) -> str:
    async with WAPClient() as client:
        # 1. Discovery: GET /.well-known/agent.json, verify Ed25519 signature and domain binding.
        manifest = await client.discover(domain)
        console.rule(f"[bold]{manifest.name}")
        console.print(f"verified manifest for [cyan]{manifest.domain}[/] · key {fingerprint(manifest.public_key)}")
        console.print(
            f"proof-of-work: {'difficulty ' + str(manifest.pow_difficulty) if manifest.pow_required else 'off'} · "
            f"capabilities: {', '.join(c.id for c in manifest.capabilities)}"
        )

        # 2. Free-text query, streamed over SSE token by token.
        console.print("\n[bold]› Do you have Sourdough Croissants today?[/]")
        async for event in client.query(domain, f"Do you have {ITEM}s today?"):
            if event.type is StreamEventType.TOKEN:
                console.print(event.text, end="", highlight=False)
        console.print()

        # 3. Structured capability call with schema validation and automatic PoW.
        started = time.perf_counter()
        stock = await client.invoke(domain, "check_pastry_stock", {"item": ITEM})
        data = stock.structured_data or {}
        console.print(
            f"\n[bold]check_pastry_stock[/] → {data['available']} available at ${data['unit_price']:.2f} "
            f"[dim](PoW solved: {stock.pow_solved}, {time.perf_counter() - started:.2f}s)[/]"
        )
        if data["available"] < QUANTITY:
            raise SystemExit(f"only {data['available']} left; not enough for {QUANTITY}")

        # 4. Multi-turn negotiation in one session (the server keeps per-session state).
        session = client.session(domain)
        table = Table(title=f"Negotiating {QUANTITY} x {ITEM}")
        for column in ("round", "we offer", "bakery says", "counter"):
            table.add_column(column)
        offer = OPENING_OFFER
        quote_id = None
        for _ in range(4):
            turn = await session.send(
                capability_id="negotiate_bulk_price",
                payload={"item": ITEM, "quantity": QUANTITY, "offered_unit_price": offer},
            )
            outcome = turn.structured_data or {}
            counter = outcome.get("counter_unit_price")
            table.add_row(
                str(outcome["round"]), f"${offer:.2f}", outcome["status"], f"${counter:.2f}" if counter else "—"
            )
            if outcome["status"] == "accepted":
                quote_id = outcome["quote_id"]
                break
            if outcome["status"] == "rejected":
                break
            # Meet the bakery's counter part-way, or accept a final offer.
            offer = counter if outcome["status"] == "final_offer" else round((offer + counter) / 2, 2)
        console.print(table)
        if quote_id is None:
            raise SystemExit("negotiation failed")

        # 5. Place the hold using the negotiated quote.
        reservation = await session.send(
            capability_id="reserve_item",
            payload={"item": ITEM, "quantity": QUANTITY, "customer_name": "Ada Lovelace", "quote_id": quote_id},
        )
        hold = reservation.structured_data or {}
        console.print(
            f"\n[green]✔ reservation confirmed[/] {hold['quantity']} x {hold['item']} @ ${hold['unit_price']:.2f} "
            f"= ${hold['total']:.2f}"
        )
        console.print(f"[bold]reservation token:[/] [yellow]{hold['reservation_token']}[/]")
        console.print(f"[dim]signed by {manifest.domain}: {reservation.message.signature[:32]}…[/]")
        return str(hold["reservation_token"])


def main() -> None:
    domain = sys.argv[1] if len(sys.argv) > 1 else "localhost:8000"
    asyncio.run(run(domain))


if __name__ == "__main__":
    main()
