"""Hashcash-style proof-of-work used to defend business agents against token draining.

A challenge is ``{"seed": "<hex>", "difficulty": N}``. A client solves it by
finding a ``nonce`` such that ``SHA256(seed + nonce)`` (UTF-8 concatenation,
hex digest) starts with ``N`` ``"0"`` characters. The expected work is
``16**N`` hash evaluations for the client and exactly one for the server.

Challenges are *stateless* to issue: the seed embeds a random salt, its expiry
time and an HMAC tag computed with a server secret, so the server does not need
to remember what it handed out. It only remembers *spent* seeds (until they
expire) so a solution cannot be replayed.
"""

from __future__ import annotations

import asyncio
import hashlib
import hmac
import itertools
import os
import secrets
import struct
import threading
import time
from dataclasses import dataclass

from .models import Challenge

_SALT_BYTES = 16
_EXPIRY_BYTES = 8
_TAG_BYTES = 16
SEED_HEX_LENGTH = 2 * (_SALT_BYTES + _EXPIRY_BYTES + _TAG_BYTES)
MAX_NONCE_LENGTH = 128


class PowError(Exception):
    """Base class for proof-of-work verification failures."""

    reason = "invalid"


class PowMalformed(PowError):
    reason = "malformed"


class PowForged(PowError):
    reason = "forged"


class PowExpired(PowError):
    reason = "expired"


class PowReplayed(PowError):
    reason = "replayed"


class PowInsufficient(PowError):
    reason = "insufficient_work"


def pow_digest(seed: str, nonce: str) -> str:
    return hashlib.sha256((seed + nonce).encode("utf-8")).hexdigest()


def check_solution(seed: str, nonce: str, difficulty: int) -> bool:
    """Return ``True`` iff ``nonce`` solves ``seed`` at ``difficulty``."""
    if not nonce or len(nonce) > MAX_NONCE_LENGTH:
        return False
    return pow_digest(seed, nonce).startswith("0" * difficulty)


def solve(seed: str, difficulty: int, *, start: int = 0, max_iterations: int | None = None) -> str:
    """Find a nonce for ``seed`` by brute force. CPU bound; see :func:`solve_async`."""
    if difficulty < 1:
        raise ValueError("difficulty must be >= 1")
    target = "0" * difficulty
    prefix = hashlib.sha256(seed.encode("utf-8"))
    counter = itertools.count(start) if max_iterations is None else range(start, start + max_iterations)
    for i in counter:
        nonce = format(i, "x")
        h = prefix.copy()
        h.update(nonce.encode("ascii"))
        if h.hexdigest().startswith(target):
            return nonce
    raise RuntimeError(f"no solution found within {max_iterations} iterations")


async def solve_async(seed: str, difficulty: int) -> str:
    """Solve a challenge in a worker thread so the event loop stays responsive."""
    return await asyncio.to_thread(solve, seed, difficulty)


def solve_challenge(challenge: Challenge) -> str:
    return solve(challenge.seed, challenge.difficulty)


@dataclass(frozen=True)
class PowVerification:
    seed: str
    nonce: str
    difficulty: int
    expires_at: float


class PowEngine:
    """Issues and verifies stateless, single-use proof-of-work challenges."""

    def __init__(
        self,
        difficulty: int = 4,
        ttl_seconds: float = 120.0,
        secret: bytes | None = None,
        max_spent: int = 100_000,
    ) -> None:
        if not 1 <= difficulty <= 16:
            raise ValueError("difficulty must be between 1 and 16")
        if ttl_seconds <= 0:
            raise ValueError("ttl_seconds must be positive")
        self.difficulty = difficulty
        self.ttl_seconds = ttl_seconds
        self._secret = secret or os.urandom(32)
        self._spent: dict[str, float] = {}
        self._max_spent = max_spent
        self._lock = threading.Lock()

    def _tag(self, salt: bytes, expiry: bytes, difficulty: int) -> bytes:
        mac = hmac.new(self._secret, salt + expiry + bytes([difficulty]), hashlib.sha256)
        return mac.digest()[:_TAG_BYTES]

    def issue(self, difficulty: int | None = None, now: float | None = None) -> Challenge:
        """Mint a new challenge. The difficulty is authenticated by the seed's HMAC."""
        difficulty = self.difficulty if difficulty is None else difficulty
        if not 1 <= difficulty <= 16:
            raise ValueError("difficulty must be between 1 and 16")
        now = time.time() if now is None else now
        expires_at = now + self.ttl_seconds
        salt = secrets.token_bytes(_SALT_BYTES)
        expiry = struct.pack(">d", expires_at)
        seed = (salt + expiry + self._tag(salt, expiry, difficulty)).hex()
        return Challenge(seed=seed, difficulty=difficulty, issued_at=now, expires_at=expires_at)

    def _decode(self, seed: str) -> tuple[bytes, bytes, bytes, float]:
        if len(seed) != SEED_HEX_LENGTH:
            raise PowMalformed("seed has the wrong length")
        try:
            raw = bytes.fromhex(seed)
        except ValueError as exc:
            raise PowMalformed("seed is not hex") from exc
        salt = raw[:_SALT_BYTES]
        expiry = raw[_SALT_BYTES : _SALT_BYTES + _EXPIRY_BYTES]
        tag = raw[_SALT_BYTES + _EXPIRY_BYTES :]
        (expires_at,) = struct.unpack(">d", expiry)
        return salt, expiry, tag, expires_at

    def _authenticate(self, seed: str) -> tuple[int, float]:
        """Recover the difficulty bound into ``seed`` and its expiry, or raise."""
        salt, expiry, tag, expires_at = self._decode(seed)
        for difficulty in range(1, 17):
            if hmac.compare_digest(tag, self._tag(salt, expiry, difficulty)):
                return difficulty, expires_at
        raise PowForged("seed was not issued by this server")

    def _prune(self, now: float) -> None:
        expired = [s for s, exp in self._spent.items() if exp <= now]
        for s in expired:
            del self._spent[s]

    def verify(self, seed: str, nonce: str, now: float | None = None, *, consume: bool = True) -> PowVerification:
        """Verify a solution and (by default) mark the seed as spent.

        Raises a :class:`PowError` subclass describing why verification failed.
        """
        now = time.time() if now is None else now
        if not isinstance(nonce, str) or not nonce or len(nonce) > MAX_NONCE_LENGTH:
            raise PowMalformed("nonce is missing or too long")
        difficulty, expires_at = self._authenticate(seed)
        if expires_at <= now:
            raise PowExpired("challenge has expired")
        if not check_solution(seed, nonce, difficulty):
            raise PowInsufficient(f"hash does not have {difficulty} leading zeros")
        with self._lock:
            if seed in self._spent:
                raise PowReplayed("challenge has already been used")
            if consume:
                if len(self._spent) >= self._max_spent:
                    self._prune(now)
                if len(self._spent) >= self._max_spent:
                    raise PowReplayed("too many outstanding solutions; retry shortly")
                self._spent[seed] = expires_at
        return PowVerification(seed=seed, nonce=nonce, difficulty=difficulty, expires_at=expires_at)

    def spent_count(self) -> int:
        with self._lock:
            self._prune(time.time())
            return len(self._spent)


__all__ = [
    "MAX_NONCE_LENGTH",
    "PowEngine",
    "PowError",
    "PowExpired",
    "PowForged",
    "PowInsufficient",
    "PowMalformed",
    "PowReplayed",
    "PowVerification",
    "SEED_HEX_LENGTH",
    "check_solution",
    "pow_digest",
    "solve",
    "solve_async",
    "solve_challenge",
]
