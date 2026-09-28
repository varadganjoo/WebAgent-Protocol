from __future__ import annotations

import asyncio
import hashlib

import pytest

from wap.server.rate_limiter import RateLimiter, SlidingWindowCounter, TokenBucket
from wap.spec.crypto import (
    KeyFormatError,
    Signer,
    canonical_json,
    fingerprint,
    generate_keypair,
    load_private_key,
    load_public_key,
    sign_bytes,
    sign_model,
    signing_payload,
    verify_bytes,
    verify_model,
)
from wap.spec.models import AgentManifest, AgentMessage, RateLimitPolicy
from wap.spec.pow import (
    SEED_HEX_LENGTH,
    PowEngine,
    PowExpired,
    PowForged,
    PowInsufficient,
    PowMalformed,
    PowReplayed,
    check_solution,
    pow_digest,
    solve,
    solve_async,
)

# --------------------------------------------------------------------------- crypto


class TestKeys:
    def test_generate_keypair(self) -> None:
        pair = generate_keypair()
        assert len(pair.private_key) == 64 and len(pair.public_key) == 64
        assert Signer(pair.private_key).public_key == pair.public_key
        assert pair.fingerprint == fingerprint(pair.public_key)
        assert pair.fingerprint.startswith("SHA256:")

    def test_keys_are_unique(self) -> None:
        assert generate_keypair().public_key != generate_keypair().public_key

    @pytest.mark.parametrize("bad", ["", "zz" * 32, "ab" * 31, "ab" * 33])
    def test_bad_key_material(self, bad: str) -> None:
        with pytest.raises(KeyFormatError):
            load_private_key(bad)
        with pytest.raises(KeyFormatError):
            load_public_key(bad)

    def test_signer_from_env_and_file(self, monkeypatch: pytest.MonkeyPatch, tmp_path) -> None:
        pair = generate_keypair()
        monkeypatch.setenv("WAP_PRIVATE_KEY", pair.private_key)
        assert Signer.from_env().public_key == pair.public_key
        key_file = tmp_path / "bakery.key"
        key_file.write_text(pair.private_key + "\n")
        assert Signer.from_file(key_file).public_key == pair.public_key
        monkeypatch.delenv("WAP_PRIVATE_KEY")
        with pytest.raises(KeyFormatError):
            Signer.from_env()

    def test_export_round_trip(self) -> None:
        signer = Signer()
        assert Signer(signer.export_private_key()).public_key == signer.public_key


class TestCanonicalJson:
    def test_key_order_and_whitespace_independent(self) -> None:
        assert canonical_json({"b": 1, "a": [1, {"d": 2, "c": 3}]}) == b'{"a":[1,{"c":3,"d":2}],"b":1}'

    def test_integral_floats_normalised(self) -> None:
        assert canonical_json({"x": 1.0}) == canonical_json({"x": 1})
        assert canonical_json({"x": 1.5}) == b'{"x":1.5}'

    def test_unicode_preserved(self) -> None:
        assert canonical_json({"name": "Café"}) == '{"name":"Café"}'.encode()

    def test_rejects_nan(self) -> None:
        with pytest.raises(ValueError):
            canonical_json({"x": float("nan")})


class TestSignatures:
    def test_sign_and_verify_bytes(self) -> None:
        pair = generate_keypair()
        sig = sign_bytes(pair.private_key, b"hello")
        assert verify_bytes(pair.public_key, b"hello", sig)
        assert not verify_bytes(pair.public_key, b"hellO", sig)
        assert not verify_bytes(generate_keypair().public_key, b"hello", sig)
        assert not verify_bytes(pair.public_key, b"hello", "00" * 64)
        assert not verify_bytes(pair.public_key, b"hello", "not-hex")

    def test_message_signature(self) -> None:
        signer = Signer()
        msg = AgentMessage(session_id="s", role="user_agent", content="2 croissants", public_key=signer.public_key)
        signed = signer.sign_model(msg)
        assert signed.signature and msg.signature == ""
        assert verify_model(signed, signer.public_key)
        tampered = signed.model_copy(update={"content": "200 croissants"})
        assert not verify_model(tampered, signer.public_key)
        assert not verify_model(msg, signer.public_key)

    def test_signature_survives_json_round_trip(self) -> None:
        signer = Signer()
        signed = signer.sign_model(
            AgentMessage(session_id="s", role="user_agent", structured_data={"z": 1, "a": [1.0, 2.5]})
        )
        again = AgentMessage.model_validate_json(signed.model_dump_json())
        assert verify_model(again, signer.public_key)

    def test_manifest_signature(self) -> None:
        pair = generate_keypair()
        manifest = AgentManifest(
            domain="bakery.example",
            name="Bakery",
            public_key=pair.public_key,
            interaction_url="https://bakery.example/wap/v1/interact",
        )
        signed = sign_model(manifest, pair.private_key)
        assert verify_model(signed, pair.public_key)
        assert not verify_model(signed.model_copy(update={"domain": "evil.example"}), pair.public_key)
        assert signing_payload(signed) == signing_payload(manifest)

    def test_sign_model_requires_signature_field(self) -> None:
        with pytest.raises(TypeError):
            sign_model(RateLimitPolicy(), Signer().export_private_key())


# --------------------------------------------------------------------------- proof of work


class TestProofOfWork:
    def test_solve_and_check(self) -> None:
        seed = "ab" * 20
        nonce = solve(seed, 3)
        assert check_solution(seed, nonce, 3)
        assert pow_digest(seed, nonce).startswith("000")
        assert pow_digest(seed, nonce) == hashlib.sha256((seed + nonce).encode()).hexdigest()

    def test_check_rejects_bad_nonces(self) -> None:
        assert not check_solution("ab" * 20, "", 1)
        assert not check_solution("ab" * 20, "x" * 200, 1)

    def test_solve_bounded(self) -> None:
        with pytest.raises(RuntimeError):
            solve("ab" * 20, 16, max_iterations=10)
        with pytest.raises(ValueError):
            solve("ab" * 20, 0)

    async def test_solve_async(self) -> None:
        nonce = await solve_async("cd" * 20, 2)
        assert check_solution("cd" * 20, nonce, 2)

    def test_engine_issue_and_verify(self) -> None:
        engine = PowEngine(difficulty=3, ttl_seconds=60)
        challenge = engine.issue()
        assert len(challenge.seed) == SEED_HEX_LENGTH
        assert challenge.difficulty == 3
        assert challenge.expires_at - challenge.issued_at == pytest.approx(60)
        nonce = solve(challenge.seed, challenge.difficulty)
        result = engine.verify(challenge.seed, nonce)
        assert result.difficulty == 3
        assert engine.spent_count() == 1

    def test_engine_rejects_replay(self) -> None:
        engine = PowEngine(difficulty=2)
        challenge = engine.issue()
        nonce = solve(challenge.seed, 2)
        engine.verify(challenge.seed, nonce)
        with pytest.raises(PowReplayed):
            engine.verify(challenge.seed, nonce)

    def test_engine_rejects_insufficient_work(self) -> None:
        engine = PowEngine(difficulty=4)
        challenge = engine.issue()
        bad = next(n for n in (format(i, "x") for i in range(10_000)) if not check_solution(challenge.seed, n, 4))
        with pytest.raises(PowInsufficient):
            engine.verify(challenge.seed, bad)

    def test_engine_rejects_expired(self) -> None:
        engine = PowEngine(difficulty=1, ttl_seconds=10)
        challenge = engine.issue(now=1000.0)
        nonce = solve(challenge.seed, 1)
        with pytest.raises(PowExpired):
            engine.verify(challenge.seed, nonce, now=1011.0)

    def test_engine_rejects_foreign_seeds(self) -> None:
        engine = PowEngine(difficulty=1)
        other = PowEngine(difficulty=1)
        challenge = other.issue()
        with pytest.raises(PowForged):
            engine.verify(challenge.seed, solve(challenge.seed, 1))
        with pytest.raises(PowMalformed):
            engine.verify("ab" * 10, "1")
        with pytest.raises(PowMalformed):
            engine.verify("zz" * (SEED_HEX_LENGTH // 2), "1")
        with pytest.raises(PowMalformed):
            engine.verify(challenge.seed, "")

    def test_difficulty_is_authenticated(self) -> None:
        """A client cannot downgrade difficulty: it is bound into the seed's HMAC."""
        engine = PowEngine(difficulty=1, secret=b"k" * 32)
        hard = engine.issue(difficulty=5)
        easy_nonce = next(
            n
            for n in (format(i, "x") for i in range(100_000))
            if check_solution(hard.seed, n, 1) and not check_solution(hard.seed, n, 5)
        )
        with pytest.raises(PowInsufficient):
            engine.verify(hard.seed, easy_nonce)

    def test_expected_work_scales_with_difficulty(self) -> None:
        """Average iterations grow ~16x per difficulty step (asymmetric cost)."""

        def iterations(seed: str, difficulty: int) -> int:
            return int(solve(seed, difficulty), 16) + 1

        seeds = [format(i, "x") * 20 for i in range(1, 25)]
        d1 = sum(iterations(s, 1) for s in seeds) / len(seeds)
        d2 = sum(iterations(s, 2) for s in seeds) / len(seeds)
        assert d2 > 4 * d1

    def test_engine_parameter_validation(self) -> None:
        with pytest.raises(ValueError):
            PowEngine(difficulty=0)
        with pytest.raises(ValueError):
            PowEngine(ttl_seconds=0)
        with pytest.raises(ValueError):
            PowEngine().issue(difficulty=17)

    def test_spent_set_is_bounded(self) -> None:
        engine = PowEngine(difficulty=1, max_spent=2)
        for _ in range(2):
            c = engine.issue()
            engine.verify(c.seed, solve(c.seed, 1))
        c = engine.issue()
        with pytest.raises(PowReplayed, match="outstanding"):
            engine.verify(c.seed, solve(c.seed, 1))


# --------------------------------------------------------------------------- rate limiting


class FakeClock:
    def __init__(self, now: float = 1000.0) -> None:
        self.now = now

    def __call__(self) -> float:
        return self.now


class TestRateLimiting:
    def test_token_bucket(self) -> None:
        bucket = TokenBucket(capacity=2, rate=1.0, now=0.0)
        assert bucket.peek(0.0) == 0
        bucket.consume(0.0)
        bucket.consume(0.0)
        assert bucket.peek(0.0) == pytest.approx(1.0)
        assert bucket.peek(0.5) == pytest.approx(0.5)
        assert bucket.peek(1.0) == 0

    def test_sliding_window(self) -> None:
        window = SlidingWindowCounter(limit=4, window=60.0, now=0.0)
        for _ in range(4):
            assert window.peek(1.0) == 0
            window.consume(1.0)
        assert window.peek(1.0) == pytest.approx(59.0)
        # Half-way through the next window, half the previous window's weight remains.
        assert window.estimate(90.0) == pytest.approx(2.0)
        assert window.peek(90.0) == 0
        # Two windows later everything has aged out.
        assert window.estimate(200.0) == 0

    async def test_burst_then_429(self) -> None:
        clock = FakeClock()
        limiter = RateLimiter(RateLimitPolicy(requests_per_minute=60, burst=3), clock=clock)
        decisions = [await limiter.check(ip="1.2.3.4") for _ in range(4)]
        assert [d.allowed for d in decisions] == [True, True, True, False]
        blocked = decisions[-1]
        assert blocked.scope == "ip"
        assert blocked.retry_after == pytest.approx(1.0)
        assert blocked.headers()["Retry-After"] == "1"
        clock.now += 1.0
        assert (await limiter.check(ip="1.2.3.4")).allowed

    async def test_sustained_rate_enforced_by_window(self) -> None:
        clock = FakeClock(0.0)
        limiter = RateLimiter(RateLimitPolicy(requests_per_minute=5, burst=5), clock=clock)
        allowed = 0
        for _ in range(60):
            if (await limiter.check(ip="9.9.9.9")).allowed:
                allowed += 1
            clock.now += 0.5  # 2 req/s attempted for 30 s
        assert allowed <= 5 + 3  # window + bucket refill tolerance, far below 60 attempts

    async def test_scopes_are_independent(self) -> None:
        limiter = RateLimiter(RateLimitPolicy(requests_per_minute=60, burst=1), clock=FakeClock())
        assert (await limiter.check(ip="1.1.1.1", agent_key="k1")).allowed
        assert not (await limiter.check(ip="1.1.1.1", agent_key="k2")).allowed  # same IP
        assert not (await limiter.check(ip="2.2.2.2", agent_key="k1")).allowed  # same agent key
        assert (await limiter.check(ip="3.3.3.3", agent_key="k3")).allowed

    async def test_rejected_requests_do_not_consume(self) -> None:
        clock = FakeClock()
        limiter = RateLimiter(RateLimitPolicy(requests_per_minute=60, burst=1), clock=clock)
        assert (await limiter.check(ip="1.1.1.1")).allowed
        # k9 is blocked because of the IP; its own budget must remain intact.
        assert not (await limiter.check(ip="1.1.1.1", agent_key="k9")).allowed
        assert (await limiter.check(ip="5.5.5.5", agent_key="k9")).allowed

    async def test_ip_only_policy_ignores_agent_key(self) -> None:
        limiter = RateLimiter(RateLimitPolicy(burst=1, scopes=["ip"]), clock=FakeClock())
        assert (await limiter.check(ip="1.1.1.1", agent_key="k")).allowed
        assert (await limiter.check(ip="2.2.2.2", agent_key="k")).allowed

    async def test_no_principal_is_allowed(self) -> None:
        limiter = RateLimiter(RateLimitPolicy(burst=1))
        assert (await limiter.check()).allowed

    async def test_idle_keys_are_collected(self) -> None:
        clock = FakeClock()
        limiter = RateLimiter(RateLimitPolicy(), clock=clock, idle_ttl=100, window_seconds=60)
        for i in range(10):
            await limiter.check(ip=f"10.0.0.{i}")
        assert limiter.tracked_keys() == 10
        clock.now += 1000
        await limiter.check(ip="10.0.1.1")
        assert limiter.tracked_keys() == 1

    async def test_max_keys_bound(self) -> None:
        limiter = RateLimiter(RateLimitPolicy(), clock=FakeClock(), max_keys=5)
        for i in range(20):
            await limiter.check(ip=f"10.0.0.{i}")
        assert limiter.tracked_keys() <= 5

    async def test_concurrent_checks_are_consistent(self) -> None:
        limiter = RateLimiter(RateLimitPolicy(requests_per_minute=1000, burst=10), clock=FakeClock())
        results = await asyncio.gather(*(limiter.check(agent_key="k") for _ in range(50)))
        assert sum(r.allowed for r in results) == 10
