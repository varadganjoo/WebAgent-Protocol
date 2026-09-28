"""State storage backends, and multi-instance deployments sharing one Redis."""

from __future__ import annotations

import asyncio
import shutil
import socket
import subprocess
import time
from collections.abc import AsyncIterator, Iterator

import pytest

from examples.bakery_server import create_bakery
from tests.conftest import client_for
from wap.client import ProtocolError, RateLimited
from wap.spec.crypto import generate_keypair
from wap.spec.models import RateLimitPolicy
from wap.spec.pow import solve
from wap.storage import LockTimeout, MemoryStore, StateStore
from wap.storage.meters import MeterTable

BAKERY = "bakery.example"


def _free_port() -> int:
    with socket.socket() as s:
        s.bind(("127.0.0.1", 0))
        return s.getsockname()[1]


@pytest.fixture(scope="session")
def redis_url(tmp_path_factory) -> Iterator[str]:
    """A throwaway real redis-server (skipped when the binary is not installed)."""
    binary = shutil.which("redis-server")
    if binary is None:
        pytest.skip("redis-server not installed")
    port = _free_port()
    workdir = tmp_path_factory.mktemp("redis")
    proc = subprocess.Popen(
        [binary, "--port", str(port), "--save", "", "--appendonly", "no", "--dir", str(workdir)],
        stdout=subprocess.DEVNULL,
        stderr=subprocess.DEVNULL,
    )
    deadline = time.time() + 10
    while time.time() < deadline:
        try:
            with socket.create_connection(("127.0.0.1", port), timeout=0.2):
                break
        except OSError:
            time.sleep(0.05)
    else:
        proc.kill()
        pytest.skip("redis-server did not start")
    yield f"redis://127.0.0.1:{port}/0"
    proc.terminate()
    proc.wait(timeout=5)


@pytest.fixture
async def redis_store(redis_url) -> AsyncIterator[StateStore]:
    from wap.storage import RedisStore

    store = RedisStore.from_url(redis_url, prefix=f"test:{time.time_ns()}:")
    yield store
    await store.aclose()


@pytest.fixture(params=["memory", "redis"])
async def store(request) -> AsyncIterator[StateStore]:
    if request.param == "memory":
        yield MemoryStore()
        return
    from wap.storage import RedisStore

    redis = RedisStore.from_url(request.getfixturevalue("redis_url"), prefix=f"test:{time.time_ns()}:")
    yield redis
    await redis.aclose()


class TestStoreContract:
    """Both backends must behave identically."""

    async def test_protocol(self, store: StateStore) -> None:
        assert isinstance(store, StateStore)

    async def test_get_set_delete(self, store: StateStore) -> None:
        assert await store.get("k") is None
        await store.set("k", {"a": [1, 2], "b": "ü"})
        assert await store.get("k") == {"a": [1, 2], "b": "ü"}
        await store.delete("k")
        assert await store.get("k") is None

    async def test_ttl(self, store: StateStore) -> None:
        await store.set("short", 1, ttl=0.15)
        assert await store.get("short") == 1
        await asyncio.sleep(0.3)
        assert await store.get("short") is None

    async def test_add_is_set_if_absent(self, store: StateStore) -> None:
        assert await store.add("once", "first", ttl=10)
        assert not await store.add("once", "second", ttl=10)
        assert await store.get("once") == "first"

    async def test_add_is_atomic_under_concurrency(self, store: StateStore) -> None:
        results = await asyncio.gather(*(store.add("race", i, ttl=10) for i in range(50)))
        assert sum(results) == 1

    async def test_incr(self, store: StateStore) -> None:
        values = await asyncio.gather(*(store.incr("counter", ttl=10) for _ in range(20)))
        assert sorted(values) == list(range(1, 21))

    async def test_lock_excludes_and_times_out(self, store: StateStore) -> None:
        order: list[str] = []

        async def worker(name: str) -> None:
            async with store.lock("res", timeout=5, wait=5):
                order.append(f"{name}-in")
                await asyncio.sleep(0.05)
                order.append(f"{name}-out")

        await asyncio.gather(worker("a"), worker("b"))
        assert order in (["a-in", "a-out", "b-in", "b-out"], ["b-in", "b-out", "a-in", "a-out"])

        async with store.lock("held", timeout=5, wait=1):
            with pytest.raises(LockTimeout):
                async with store.lock("held", timeout=5, wait=0.1):
                    pass

    async def test_rate_limit_burst_and_isolation(self, store: StateStore) -> None:
        now = 1_000_000.0
        kwargs = {"limit": 60, "window": 60.0, "burst": 3, "cost": 1.0}
        decisions = [await store.rate_limit([("ip", "ip:1")], now=now, **kwargs) for _ in range(4)]
        assert [d.allowed for d in decisions] == [True, True, True, False]
        assert decisions[-1].retry_after == pytest.approx(1.0, rel=0.01)
        assert decisions[-1].scope == "ip"
        assert (await store.rate_limit([("ip", "ip:2")], now=now, **kwargs)).allowed
        assert (await store.rate_limit([("ip", "ip:1")], now=now + 1.0, **kwargs)).allowed

    async def test_rate_limit_rejections_charge_nothing(self, store: StateStore) -> None:
        now = 2_000_000.0
        kwargs = {"limit": 60, "window": 60.0, "burst": 1, "cost": 1.0}
        assert (await store.rate_limit([("ip", "ip:x")], now=now, **kwargs)).allowed
        blocked = await store.rate_limit([("ip", "ip:x"), ("agent_key", "key:k")], now=now, **kwargs)
        assert not blocked.allowed
        assert (await store.rate_limit([("agent_key", "key:k")], now=now, **kwargs)).allowed


@pytest.mark.parametrize("seed", [0, 1, 2])
async def test_redis_rate_limit_matches_memory_algorithm(redis_store, seed: int) -> None:
    """The Lua implementation makes the same decisions as the in-process meters."""
    import random

    rng = random.Random(seed)
    table = MeterTable()
    now = 5_000_000.0
    for _ in range(200):
        now += rng.choice([0.0, 0.05, 0.3, 1.5, 7.0])
        keys = rng.choice([[("ip", "ip:a")], [("ip", "ip:a"), ("agent_key", "key:b")], [("agent_key", "key:b")]])
        kwargs = {"limit": 20, "window": 10.0, "burst": 4, "cost": 1.0, "now": now}
        expected = table.check(keys, **kwargs)
        actual = await redis_store.rate_limit(keys, **kwargs)
        assert actual.allowed == expected.allowed
        assert actual.retry_after == pytest.approx(expected.retry_after, abs=1e-6)


class TestMultiInstance:
    """Two independent server instances (think: two workers or machines) sharing one Redis."""

    @pytest.fixture
    async def pair(self, redis_url):
        from wap.storage import RedisStore

        key = generate_keypair().private_key
        prefix = f"multi:{time.time_ns()}:"
        stores = [RedisStore.from_url(redis_url, prefix=prefix) for _ in range(2)]
        instances = [
            create_bakery(BAKERY, private_key=key, pow_difficulty=2, store=s, rate_limit=RateLimitPolicy(burst=50))
            for s in stores
        ]
        yield instances
        for s in stores:
            await s.aclose()

    async def test_session_state_follows_the_conversation_across_instances(self, pair) -> None:
        (_, app_a, _), (_, app_b, _) = pair
        async with client_for(app_a) as client_a, client_for(app_b) as client_b:
            client_b.signer = client_a.signer  # same user agent, load-balanced across instances
            session = "shared-session-0001"
            args = {"item": "Sourdough Croissant", "quantity": 12}
            first = await client_a.invoke(
                BAKERY, "negotiate_bulk_price", {**args, "offered_unit_price": 3.6}, session_id=session
            )
            second = await client_b.invoke(
                BAKERY, "negotiate_bulk_price", {**args, "offered_unit_price": 3.8}, session_id=session
            )
        assert first.structured_data["round"] == 1
        assert second.structured_data["round"] == 2

    async def test_proof_of_work_seed_single_use_across_instances(self, pair) -> None:
        (wap_a, app_a, _), (wap_b, _, _) = pair
        challenge = await wap_a.issue_challenge()
        nonce = solve(challenge.seed, challenge.difficulty)
        await wap_a.verify_pow(challenge.seed, nonce)  # instance B also recognises A's seed...
        with pytest.raises(Exception) as info:
            await wap_b.verify_pow(challenge.seed, nonce)  # ...and knows it is spent
        assert info.value.details["reason"] == "replayed"

    async def test_rate_limits_are_shared(self, redis_url) -> None:
        from wap.storage import RedisStore

        key = generate_keypair().private_key
        prefix = f"rl:{time.time_ns()}:"
        stores = [RedisStore.from_url(redis_url, prefix=prefix) for _ in range(2)]
        apps = [
            create_bakery(
                BAKERY,
                private_key=key,
                require_pow=False,
                store=s,
                rate_limit=RateLimitPolicy(requests_per_minute=60, burst=4),
            )[1]
            for s in stores
        ]
        try:
            async with client_for(apps[0]) as a, client_for(apps[1]) as b:
                b.signer = a.signer
                outcomes = []
                for i in range(6):
                    client = a if i % 2 == 0 else b
                    try:
                        await client.invoke(BAKERY, "get_menu", session_id=f"s{i}")
                        outcomes.append("ok")
                    except RateLimited:
                        outcomes.append("429")
        finally:
            for s in stores:
                await s.aclose()
        # One burst budget of 4, shared by both instances (discovery also counts per IP).
        assert outcomes.count("ok") < 6 and "429" in outcomes

    async def test_idempotent_retry_on_another_instance(self, pair) -> None:
        (_, app_a, inv_a), (_, app_b, _) = pair
        async with client_for(app_a) as a, client_for(app_b) as b:
            b.signer = a.signer
            payload = {"item": "Almond Croissant", "quantity": 2, "customer_name": "Ada"}
            first = await a.invoke(BAKERY, "reserve_item", payload, idempotency_key="order-7f3a9c21")
            retry = await b.invoke(BAKERY, "reserve_item", payload, idempotency_key="order-7f3a9c21")
            with pytest.raises(ProtocolError) as conflict:
                await b.invoke(BAKERY, "reserve_item", {**payload, "quantity": 3}, idempotency_key="order-7f3a9c21")
        assert retry.structured_data == first.structured_data  # same reservation token, not a second hold
        assert conflict.value.code == "idempotency_conflict"
