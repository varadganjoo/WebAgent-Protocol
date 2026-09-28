"""Real-network load and correctness test against uvicorn worker processes.

    python examples/load_test.py --workers 1
    python examples/load_test.py --workers 4 --redis-url redis://127.0.0.1:6379/0
    python examples/load_test.py --workers 4                 # no shared store: shows what breaks

It starts ``uvicorn examples.bakery_server:app --workers N`` on a free port (all
workers share one signing key), then:

1. **Throughput**: ``--users`` virtual users, each a :class:`WAPClient` with its
   own agent key, call ``check_pastry_stock`` over real HTTP (signed requests,
   proof-of-work at ``--pow-difficulty``, signed replies verified client-side)
   for ``--seconds`` seconds. Reports requests/s and latency percentiles.
2. **Replay across workers**: one signed message is sent ``--probes`` times
   concurrently; the kernel spreads the connections over the workers. Exactly one
   must be accepted.
3. **Proof-of-work reuse across workers**: ``--probes`` different messages carry
   the *same* solved challenge. Exactly one must be accepted.

The load generator runs on the same machine as the server, so absolute numbers
understate what dedicated hardware would do.
"""

from __future__ import annotations

import argparse
import asyncio
import os
import signal
import socket
import statistics
import subprocess
import sys
import time
import uuid
from collections import Counter
from pathlib import Path

import httpx

ROOT = Path(__file__).resolve().parent.parent
sys.path.insert(0, str(ROOT))

from wap import WAPClient  # noqa: E402
from wap.spec.crypto import Signer, generate_keypair  # noqa: E402
from wap.spec.models import AgentMessage  # noqa: E402
from wap.spec.pow import solve  # noqa: E402

ITEMS = ["Sourdough Croissant", "Pain au Chocolat", "Almond Croissant", "Cardamom Bun", "Baguette"]


def free_port() -> int:
    with socket.socket() as s:
        s.bind(("127.0.0.1", 0))
        return s.getsockname()[1]


def start_server(port: int, workers: int, redis_url: str | None, pow_difficulty: int) -> subprocess.Popen:
    env = {
        **os.environ,
        "WAP_PRIVATE_KEY": generate_keypair().private_key,
        "BAKERY_DOMAIN": f"localhost:{port}",
        "BAKERY_POW_DIFFICULTY": str(pow_difficulty),
        "BAKERY_RATE_LIMIT_RPM": "10000000",
        "BAKERY_RATE_LIMIT_BURST": "1000000",
        "BAKERY_REDIS_PREFIX": f"load:{uuid.uuid4().hex}:",
    }
    if redis_url:
        env["BAKERY_REDIS_URL"] = redis_url
    else:
        env.pop("BAKERY_REDIS_URL", None)
    return subprocess.Popen(
        [
            sys.executable,
            "-m",
            "uvicorn",
            "examples.bakery_server:app",
            "--port",
            str(port),
            "--workers",
            str(workers),
            "--log-level",
            "warning",
            "--no-access-log",
        ],
        cwd=ROOT,
        env=env,
        stdout=subprocess.DEVNULL,
        stderr=subprocess.PIPE,
        start_new_session=True,
    )


def stop_server(server: subprocess.Popen) -> None:
    """Stop uvicorn and all of its workers."""
    if sys.platform == "win32":
        subprocess.run(["taskkill", "/F", "/T", "/PID", str(server.pid)], capture_output=True, check=False)
    else:
        os.killpg(server.pid, signal.SIGTERM)
    server.wait(timeout=15)


async def wait_ready(base: str, timeout: float = 30.0) -> None:
    deadline = time.time() + timeout
    async with httpx.AsyncClient() as http:
        while time.time() < deadline:
            try:
                if (await http.get(base + "/.well-known/wap.json")).status_code == 200:
                    return
            except httpx.TransportError:
                pass
            await asyncio.sleep(0.2)
    raise RuntimeError("server did not start")


async def throughput(domain: str, users: int, seconds: float, keep_samples: bool = False) -> dict:
    latencies: list[float] = []
    errors: Counter[str] = Counter()
    stop = time.perf_counter() + seconds

    async def user(index: int) -> None:
        # Independent stock lookups: a fresh session per request, as a real agent would use.
        async with WAPClient(timeout=30, max_retries=0) as client:
            await client.discover(domain)
            i = index
            while time.perf_counter() < stop:
                started = time.perf_counter()
                try:
                    await client.invoke(domain, "check_pastry_stock", {"item": ITEMS[i % len(ITEMS)]})
                    latencies.append(time.perf_counter() - started)
                except Exception as exc:  # noqa: BLE001 - counted and reported by type
                    errors[getattr(exc, "code", type(exc).__name__)] += 1
                i += 1

    started = time.perf_counter()
    await asyncio.gather(*(user(i) for i in range(users)))
    elapsed = time.perf_counter() - started
    latencies.sort()

    def pct(q: float) -> float:
        return latencies[min(len(latencies) - 1, int(q / 100 * len(latencies)))] * 1000 if latencies else float("nan")

    return {
        "requests": len(latencies),
        "errors": sum(errors.values()),
        "error_types": dict(errors),
        "rps": len(latencies) / elapsed,
        "p50": pct(50),
        "p95": pct(95),
        "p99": pct(99),
        "mean": statistics.fmean(latencies) * 1000 if latencies else float("nan"),
        **({"samples": latencies} if keep_samples else {}),
    }


def _throughput_process(domain: str, users: int, seconds: float) -> dict:
    return asyncio.run(throughput(domain, users, seconds, keep_samples=True))


async def throughput_multi(domain: str, users: int, seconds: float, processes: int) -> dict:
    """Spread virtual users over several load-generator processes (the client is CPU-heavy)."""
    if processes <= 1:
        return await throughput(domain, users, seconds)
    from concurrent.futures import ProcessPoolExecutor

    loop = asyncio.get_running_loop()
    share = [users // processes + (1 if i < users % processes else 0) for i in range(processes)]
    with ProcessPoolExecutor(max_workers=processes) as pool:
        parts = await asyncio.gather(
            *(loop.run_in_executor(pool, _throughput_process, domain, n, seconds) for n in share if n)
        )
    latencies = sorted(x for part in parts for x in part["samples"])
    errors: Counter[str] = Counter()
    for part in parts:
        errors.update(part["error_types"])

    def pct(q: float) -> float:
        return latencies[min(len(latencies) - 1, int(q / 100 * len(latencies)))] * 1000 if latencies else float("nan")

    return {
        "requests": len(latencies),
        "errors": sum(errors.values()),
        "error_types": dict(errors),
        "rps": sum(part["rps"] for part in parts),
        "p50": pct(50),
        "p95": pct(95),
        "p99": pct(99),
    }


async def replay_probe(base: str, probes: int) -> int:
    """Send one signed message ``probes`` times at once over separate connections."""
    signer = Signer()
    async with httpx.AsyncClient() as http:
        challenge = (await http.get(base + "/wap/v1/challenge")).json()
        message = signer.sign_model(
            AgentMessage(
                session_id=f"replay-{uuid.uuid4().hex}",
                role="user_agent",
                capability_id="get_menu",
                pow_seed=challenge["seed"],
                pow_nonce=solve(challenge["seed"], challenge["difficulty"]),
                public_key=signer.public_key,
            )
        )
        body = message.model_dump_json()

    async def send() -> int:
        async with httpx.AsyncClient(headers={"Connection": "close"}) as fresh:
            return (await fresh.post(base + "/wap/v1/interact", content=body)).status_code

    codes = await asyncio.gather(*(send() for _ in range(probes)))
    return sum(1 for c in codes if c == 200)


async def pow_reuse_probe(base: str, probes: int) -> int:
    """``probes`` distinct signed messages that all carry the same solved challenge."""
    async with httpx.AsyncClient() as http:
        challenge = (await http.get(base + "/wap/v1/challenge")).json()
    nonce = solve(challenge["seed"], challenge["difficulty"])
    bodies = []
    for _ in range(probes):
        signer = Signer()
        bodies.append(
            signer.sign_model(
                AgentMessage(
                    session_id=f"pow-{uuid.uuid4().hex}",
                    role="user_agent",
                    capability_id="get_menu",
                    pow_seed=challenge["seed"],
                    pow_nonce=nonce,
                    public_key=signer.public_key,
                )
            ).model_dump_json()
        )

    async def send(body: str) -> int:
        async with httpx.AsyncClient(headers={"Connection": "close"}) as fresh:
            return (await fresh.post(base + "/wap/v1/interact", content=body)).status_code

    codes = await asyncio.gather(*(send(b) for b in bodies))
    return sum(1 for c in codes if c == 200)


async def run(args: argparse.Namespace) -> None:
    port = free_port()
    base = f"http://localhost:{port}"
    server = start_server(port, args.workers, args.redis_url, args.pow_difficulty)
    try:
        await wait_ready(base)
        await asyncio.sleep(1.0 if args.workers > 1 else 0.2)  # let every worker finish booting
        stats = await throughput_multi(f"localhost:{port}", args.users, args.seconds, args.client_processes)
        replays = await replay_probe(base, args.probes)
        reuses = await pow_reuse_probe(base, args.probes)
    finally:
        stop_server(server)
    store = "redis" if args.redis_url else "memory"
    row = [
        args.workers,
        store,
        args.users,
        args.pow_difficulty,
        f"{stats['requests']:,}",
        stats["errors"],
        f"{stats['rps']:,.0f}",
        f"{stats['p50']:.1f}",
        f"{stats['p95']:.1f}",
        f"{stats['p99']:.1f}",
        f"{replays}/{args.probes}",
        f"{reuses}/{args.probes}",
    ]
    print("| " + " | ".join(str(cell) for cell in row) + " |")
    if stats["error_types"]:
        print(f"errors by type: {stats['error_types']}", file=sys.stderr)


def main() -> None:
    parser = argparse.ArgumentParser(description=__doc__, formatter_class=argparse.RawDescriptionHelpFormatter)
    parser.add_argument("--workers", type=int, default=1)
    parser.add_argument("--redis-url", default=None)
    parser.add_argument("--users", type=int, default=32)
    parser.add_argument("--seconds", type=float, default=15.0)
    parser.add_argument("--pow-difficulty", type=int, default=2)
    parser.add_argument("--probes", type=int, default=24)
    parser.add_argument("--client-processes", type=int, default=1, help="load-generator processes")
    parser.add_argument("--header", action="store_true", help="print the Markdown table header first")
    args = parser.parse_args()
    if args.header:
        print(
            "| workers | store | users | PoW | requests | errors | req/s | p50 ms | p95 ms | p99 ms "
            "| replay accepted | PoW reuse accepted |"
        )
        print("|---:|---|---:|---:|---:|---:|---:|---:|---:|---:|---:|---:|")
    asyncio.run(run(args))


if __name__ == "__main__":
    main()
