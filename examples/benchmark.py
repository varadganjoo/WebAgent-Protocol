"""Reproducible micro-benchmarks behind the numbers in docs/whitepaper.md.

    python examples/benchmark.py            # prints Markdown tables

Measures:

1. **Context cost** of answering "is the Sourdough Croissant in stock and what
   does it cost?" by (a) feeding raw storefront HTML to a model, (b) feeding
   tag-stripped visible text, and (c) using WAP (manifest + one signed reply).
   The storefront is a synthetic but structurally typical server-rendered
   page; it is *smaller* than most production pages, so the reduction factor
   is conservative.
2. **Proof-of-work cost** for clients at difficulties 1-5 versus the server's
   single-hash verification cost.
3. **Signature cost** (Ed25519 sign / verify of a canonical AgentMessage).
4. **Round-trip latency** of a signed, PoW-gated capability call through the
   full server pipeline (in-process ASGI transport, so network time excluded).

Token counts use a GPT-style pre-tokenizer approximation (the regex split used
by byte-level BPE tokenizers, with long words charged one token per 4
characters). It tracks cl100k-style counts within roughly ±15% on English
prose and markup; exact counts vary by model tokenizer.
"""

from __future__ import annotations

import asyncio
import html
import json
import re
import statistics
import sys
import time
from pathlib import Path

import httpx

sys.path.insert(0, str(Path(__file__).resolve().parent.parent))

from examples.bakery_server import Inventory, create_bakery, default_inventory  # noqa: E402
from wap import WAPClient  # noqa: E402
from wap.spec.conversation import ConversationPolicy  # noqa: E402
from wap.spec.crypto import Signer, verify_model  # noqa: E402
from wap.spec.models import AgentMessage, RateLimitPolicy  # noqa: E402
from wap.spec.pow import PowEngine, solve  # noqa: E402

_PRETOKEN_RE = re.compile(r"""'s|'t|'re|'ve|'m|'ll|'d| ?[A-Za-z]+| ?\d{1,3}| ?[^\sA-Za-z\d]+|\s+(?!\S)|\s+""")


def approx_tokens(text: str) -> int:
    total = 0
    for piece in _PRETOKEN_RE.findall(text):
        stripped = piece.strip()
        total += max(1, (len(stripped) + 3) // 4) if stripped.isalpha() and len(stripped) > 6 else 1
    return total


# The latency loop deliberately repeats one identical call, which loop protection would
# (correctly) stop after a few repeats; a benchmark is a legitimate poller, so it opts out.
POLLING = ConversationPolicy(
    max_turns=10_000, max_repeats=10_000, max_identical_requests=10_000, max_repeats_across_sessions=10_000
)


def storefront_html(inventory: Inventory | None = None) -> str:
    """A server-rendered bakery storefront with the usual page furniture (live stock if given ``inventory``)."""
    inventory = inventory or default_inventory()
    cards = []
    for i, p in enumerate(inventory.pastries.values()):
        cards.append(
            f"""
      <article class="product-card product-card--{i} js-product" data-sku="GC-{1000 + i}" data-price="{p.unit_price}">
        <a class="product-card__link" href="/products/{p.name.lower().replace(" ", "-")}">
          <picture class="product-card__media">
            <source srcset="/cdn/img/{i}-400.webp 400w, /cdn/img/{i}-800.webp 800w" type="image/webp">
            <img src="/cdn/img/{i}-400.jpg" alt="{html.escape(p.name)}" loading="lazy" width="400" height="400">
          </picture>
          <h3 class="product-card__title">{html.escape(p.name)}</h3>
        </a>
        <p class="product-card__desc">{html.escape(p.description)}</p>
        <div class="product-card__meta">
          <span class="price price--regular"><span class="visually-hidden">Price</span>${p.unit_price:.2f}</span>
          <span class="stock-badge {"stock-badge--in" if p.stock else "stock-badge--out"}">
            {"In stock" if p.stock else "Sold out"} <span class="stock-count">({p.stock} left)</span></span>
        </div>
        <form class="product-form" action="/cart/add" method="post">
          <input type="hidden" name="id" value="GC-{1000 + i}"><input type="hidden" name="csrf" value="9f8e7d6c5b4a">
          <label for="qty-{i}" class="visually-hidden">Quantity</label>
          <select id="qty-{i}" name="quantity">{"".join(f"<option>{n}</option>" for n in range(1, 13))}</select>
          <button type="submit" class="btn btn--primary">Add to order</button>
        </form>
      </article>"""
        )
    nav = "".join(
        f'<li class="nav__item"><a class="nav__link" href="/{x.lower()}">{x}</a></li>'
        for x in [
            "Shop",
            "Bread",
            "Pastries",
            "Cakes",
            "Catering",
            "Wholesale",
            "Our Story",
            "Visit",
            "Journal",
            "Gift Cards",
        ]
    )
    css = "\n".join(
        f".c{i}{{margin:0 auto;padding:{i % 5}rem;display:flex;gap:1rem;color:#3b2f2f;font:400 1rem/1.5 system-ui}}"
        for i in range(60)
    )
    return f"""<!doctype html>
<html lang="en"><head>
<meta charset="utf-8"><meta name="viewport" content="width=device-width,initial-scale=1">
<title>Golden Crust Bakery — Fresh Pastries Daily</title>
<meta name="description" content="Neighbourhood sourdough bakery. Order pastries for pickup.">
<meta property="og:title" content="Golden Crust Bakery"><meta property="og:image" content="/cdn/og.jpg">
<link rel="preconnect" href="https://fonts.gstatic.com"><link rel="stylesheet" href="/assets/theme.4f2a9c.css">
<style>{css}</style>
<script>window.dataLayer=window.dataLayer||[];function gtag(){{dataLayer.push(arguments)}}gtag('js',new Date());
gtag('config','G-XXXXXXX',{{anonymize_ip:true}});</script>
<script type="application/ld+json">{{"@context":"https://schema.org","@type":"Bakery","name":"Golden Crust Bakery",
"address":{{"@type":"PostalAddress","streetAddress":"12 Mill Lane","addressLocality":"Springfield"}},
"openingHours":"Tu-Su 07:00-15:00","telephone":"+1-555-0100"}}</script>
</head><body class="template-collection c1">
<div class="announcement-bar c2"><p>Free local delivery on orders over $40 · Order by 6pm for next-day pickup</p></div>
<header class="site-header c3"><a class="logo" href="/"><img src="/cdn/logo.svg" alt="Golden Crust Bakery"></a>
<nav class="nav" aria-label="Main"><ul class="nav__list">{nav}</ul></nav>
<div class="header-actions"><a href="/search" aria-label="Search">Search</a><a href="/account">Account</a>
<a href="/cart" class="cart-link">Cart (<span class="cart-count">0</span>)</a></div></header>
<main id="main" class="c4"><nav class="breadcrumbs"><a href="/">Home</a> / <a href="/pastries">Pastries</a></nav>
<h1 class="collection__title">Pastries</h1>
<p class="collection__intro">Laminated by hand every morning. Availability updates live throughout the day.</p>
<div class="filters"><button class="filter" data-filter="all">All</button><button class="filter" data-filter="vegan">Vegan</button>
<button class="filter" data-filter="nut-free">Nut-free</button><select class="sort"><option>Featured</option>
<option>Price, low to high</option><option>Price, high to low</option></select></div>
<section class="product-grid c5">{"".join(cards)}
</section></main>
<aside class="newsletter c6"><h2>Get the weekly bake schedule</h2><form action="/subscribe" method="post">
<input type="email" name="email" placeholder="you@example.com"><button>Subscribe</button></form></aside>
<footer class="site-footer c7"><div class="footer-cols"><div><h4>Visit</h4><p>12 Mill Lane, Springfield</p>
<p>Tue–Sun 7am–3pm</p></div><div><h4>Help</h4><ul><li><a href="/faq">FAQ</a></li><li><a href="/allergens">Allergens</a></li>
<li><a href="/shipping">Shipping</a></li><li><a href="/contact">Contact</a></li></ul></div></div>
<p class="legal">© 2026 Golden Crust Bakery · <a href="/privacy">Privacy</a> · <a href="/terms">Terms</a></p></footer>
<div id="cookie-banner" class="cookie c8" role="dialog"><p>We use cookies to improve your experience.</p>
<button class="accept">Accept</button><button class="decline">Decline</button></div>
<script src="/assets/vendor.8c1d.js" defer></script><script src="/assets/theme.4f2a9c.js" defer></script>
</body></html>"""


def visible_text(page: str) -> str:
    page = re.sub(r"(?is)<(script|style)[^>]*>.*?</\1>", " ", page)
    page = re.sub(r"(?s)<[^>]+>", " ", page)
    return re.sub(r"\s+", " ", html.unescape(page)).strip()


def timeit(fn, repeat: int) -> float:
    start = time.perf_counter()
    for _ in range(repeat):
        fn()
    return (time.perf_counter() - start) / repeat


async def wap_context() -> tuple[str, str, list[float]]:
    signer = Signer()
    _, app, _ = create_bakery(
        "bakery.example",
        private_key=signer.export_private_key(),
        pow_difficulty=3,
        rate_limit=RateLimitPolicy(requests_per_minute=10_000, burst=10_000),
        conversation_policy=POLLING,
    )
    async with WAPClient(transport=httpx.ASGITransport(app=app), conversation_policy=POLLING) as client:
        manifest = await client.discover("bakery.example")
        latencies = []
        reply = None
        for _ in range(30):
            started = time.perf_counter()
            reply = await client.invoke("bakery.example", "check_pastry_stock", {"item": "Sourdough Croissant"})
            latencies.append(time.perf_counter() - started)
    assert reply is not None
    return manifest.model_dump_json(), reply.message.model_dump_json(), latencies


def main() -> None:
    sys.stdout.reconfigure(encoding="utf-8")  # tables use ≈ and × (Windows defaults to a legacy codepage)
    page = storefront_html()
    text = visible_text(page)
    manifest_json, reply_json, latencies = asyncio.run(wap_context())
    manifest_capability_only = json.dumps(
        [c for c in json.loads(manifest_json)["capabilities"] if c["id"] == "check_pastry_stock"]
    )

    reply = json.loads(reply_json)
    model_visible = json.dumps({"text": reply["content"], "structured_data": reply["structured_data"]})
    rows = [
        ("Raw HTML storefront", len(page), approx_tokens(page)),
        ("Visible text (scripts/styles/tags stripped)", len(text), approx_tokens(text)),
        ("WAP: full manifest (4 capabilities)", len(manifest_json), approx_tokens(manifest_json)),
        ("WAP: one capability schema", len(manifest_capability_only), approx_tokens(manifest_capability_only)),
        ("WAP: signed reply on the wire (check_pastry_stock)", len(reply_json), approx_tokens(reply_json)),
        ("WAP: model-visible result (text + structured_data)", len(model_visible), approx_tokens(model_visible)),
    ]
    print("## Context cost\n")
    print("| Representation | Bytes | ≈ Tokens | vs raw HTML |")
    print("|---|---:|---:|---:|")
    raw_tokens = rows[0][2]
    for name, size, tokens in rows:
        print(f"| {name} | {size:,} | {tokens:,} | {raw_tokens / tokens:.1f}× |")
    per_query = approx_tokens(manifest_capability_only) + approx_tokens(model_visible)
    print(
        f"\nWAP per-query model context (one schema + model-visible result): ≈{per_query} tokens "
        f"→ {raw_tokens / per_query:.1f}× less than raw HTML"
    )

    print("\n## Proof-of-work asymmetry\n")
    print("| Difficulty | Expected hashes | Client solve (mean of 20) | Server verify |")
    print("|---:|---:|---:|---:|")
    for difficulty in range(1, 6):
        engine = PowEngine(difficulty=difficulty)
        trials = 20 if difficulty < 5 else 5
        solve_times, verify_times = [], []
        for _ in range(trials):
            challenge = engine.issue()
            started = time.perf_counter()
            nonce = solve(challenge.seed, difficulty)
            solve_times.append(time.perf_counter() - started)
            started = time.perf_counter()
            engine.verify(challenge.seed, nonce)
            verify_times.append(time.perf_counter() - started)
        print(
            f"| {difficulty} | {16**difficulty:,} | {statistics.mean(solve_times) * 1000:,.1f} ms "
            f"| {statistics.mean(verify_times) * 1e6:,.1f} µs |"
        )
    print("\n(difficulty 5 averaged over 5 trials)")

    signer = Signer()
    message = AgentMessage(
        session_id="bench", role="user_agent", content="x" * 200, structured_data={"item": "croissant"}
    )
    signed = signer.sign_model(message)
    sign_us = timeit(lambda: signer.sign_model(message), 2000) * 1e6
    verify_us = timeit(lambda: verify_model(signed, signer.public_key), 2000) * 1e6
    print("\n## Signatures\n")
    print(f"Ed25519 sign (canonicalise + sign): {sign_us:.1f} µs · verify: {verify_us:.1f} µs")

    latencies.sort()
    print("\n## In-process round trip (PoW d=3, signed request + signed reply, 30 calls)\n")
    print(
        f"p50 {statistics.median(latencies) * 1000:.1f} ms · "
        f"p90 {latencies[int(len(latencies) * 0.9) - 1] * 1000:.1f} ms · max {latencies[-1] * 1000:.1f} ms"
    )


if __name__ == "__main__":
    main()
