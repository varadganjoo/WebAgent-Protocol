"""Ed25519 signing, verification and key management for WAP.

Signatures are computed over the *canonical JSON* form of a document: the
object is serialised with sorted keys, no insignificant whitespace, UTF-8
encoding, and the ``signature`` member removed. This makes signatures
independent of the JSON library and key ordering used by either peer.
"""

from __future__ import annotations

import hashlib
import json
import math
import os
from dataclasses import dataclass
from pathlib import Path
from typing import Any, TypeVar

from cryptography.exceptions import InvalidSignature
from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey, Ed25519PublicKey
from pydantic import BaseModel

SignedModelT = TypeVar("SignedModelT", bound=BaseModel)

PRIVATE_KEY_ENV = "WAP_PRIVATE_KEY"


class KeyFormatError(ValueError):
    """Raised when key material is not a valid hex-encoded Ed25519 key."""


def _normalize_floats(value: Any) -> Any:
    """Render integral floats as ints so ``1.0`` and ``1`` canonicalise identically."""
    if isinstance(value, float):
        if not math.isfinite(value):
            raise ValueError("non-finite numbers cannot be canonicalised")
        return int(value) if value.is_integer() else value
    if isinstance(value, dict):
        return {k: _normalize_floats(v) for k, v in value.items()}
    if isinstance(value, (list, tuple)):
        return [_normalize_floats(v) for v in value]
    return value


def canonical_json(obj: Any) -> bytes:
    """Serialise ``obj`` into the canonical byte form used for signing."""
    if isinstance(obj, BaseModel):
        obj = obj.model_dump(mode="json")
    return json.dumps(
        _normalize_floats(obj),
        sort_keys=True,
        separators=(",", ":"),
        ensure_ascii=False,
        allow_nan=False,
    ).encode("utf-8")


def signing_payload(model: BaseModel) -> bytes:
    """Canonical bytes of ``model`` with its ``signature`` field excluded."""
    return canonical_json(model.model_dump(mode="json", exclude={"signature"}))


def _decode_hex(value: str, length: int, what: str) -> bytes:
    try:
        raw = bytes.fromhex(value.strip())
    except (ValueError, AttributeError) as exc:
        raise KeyFormatError(f"{what} is not valid hex") from exc
    if len(raw) != length:
        raise KeyFormatError(f"{what} must be {length} bytes ({length * 2} hex chars), got {len(raw)}")
    return raw


def load_private_key(private_key_hex: str) -> Ed25519PrivateKey:
    """Load a raw 32-byte Ed25519 private key (seed) from hex."""
    return Ed25519PrivateKey.from_private_bytes(_decode_hex(private_key_hex, 32, "private key"))


def load_public_key(public_key_hex: str) -> Ed25519PublicKey:
    """Load a raw 32-byte Ed25519 public key from hex."""
    return Ed25519PublicKey.from_public_bytes(_decode_hex(public_key_hex, 32, "public key"))


def private_key_to_hex(key: Ed25519PrivateKey) -> str:
    return key.private_bytes(
        encoding=serialization.Encoding.Raw,
        format=serialization.PrivateFormat.Raw,
        encryption_algorithm=serialization.NoEncryption(),
    ).hex()


def public_key_to_hex(key: Ed25519PublicKey) -> str:
    return key.public_bytes(encoding=serialization.Encoding.Raw, format=serialization.PublicFormat.Raw).hex()


def fingerprint(public_key_hex: str) -> str:
    """Short, human-comparable fingerprint of a public key (``SHA256:<16 hex>``)."""
    raw = _decode_hex(public_key_hex, 32, "public key")
    return "SHA256:" + hashlib.sha256(raw).hexdigest()[:32]


@dataclass(frozen=True)
class KeyPair:
    private_key: str
    public_key: str

    @property
    def fingerprint(self) -> str:
        return fingerprint(self.public_key)


def generate_keypair() -> KeyPair:
    """Generate a fresh Ed25519 key pair, both halves hex-encoded."""
    key = Ed25519PrivateKey.generate()
    return KeyPair(private_key=private_key_to_hex(key), public_key=public_key_to_hex(key.public_key()))


def sign_bytes(private_key: Ed25519PrivateKey | str, data: bytes) -> str:
    if isinstance(private_key, str):
        private_key = load_private_key(private_key)
    return private_key.sign(data).hex()


def verify_bytes(public_key: Ed25519PublicKey | str, data: bytes, signature_hex: str) -> bool:
    """Return ``True`` iff ``signature_hex`` is a valid signature of ``data``."""
    try:
        if isinstance(public_key, str):
            public_key = load_public_key(public_key)
        signature = _decode_hex(signature_hex, 64, "signature")
        public_key.verify(signature, data)
    except (InvalidSignature, KeyFormatError, ValueError):
        return False
    return True


def sign_model(model: SignedModelT, private_key: Ed25519PrivateKey | str) -> SignedModelT:
    """Return a copy of ``model`` with its ``signature`` field populated."""
    if "signature" not in type(model).model_fields:
        raise TypeError(f"{type(model).__name__} has no signature field")
    signature = sign_bytes(private_key, signing_payload(model))
    return model.model_copy(update={"signature": signature})


def verify_model(model: BaseModel, public_key: Ed25519PublicKey | str) -> bool:
    """Verify the embedded ``signature`` of ``model`` against ``public_key``."""
    signature = getattr(model, "signature", "")
    if not signature:
        return False
    return verify_bytes(public_key, signing_payload(model), signature)


class Signer:
    """Holds a private key and signs WAP documents on behalf of an agent."""

    def __init__(self, private_key: Ed25519PrivateKey | str | None = None) -> None:
        if private_key is None:
            private_key = Ed25519PrivateKey.generate()
        elif isinstance(private_key, str):
            private_key = load_private_key(private_key)
        self._key = private_key
        self.public_key = public_key_to_hex(private_key.public_key())

    @classmethod
    def from_env(cls, variable: str = PRIVATE_KEY_ENV) -> Signer:
        value = os.environ.get(variable)
        if not value:
            raise KeyFormatError(f"environment variable {variable} is not set")
        return cls(value)

    @classmethod
    def from_file(cls, path: str | Path) -> Signer:
        return cls(Path(path).read_text(encoding="utf-8").strip())

    @property
    def fingerprint(self) -> str:
        return fingerprint(self.public_key)

    def export_private_key(self) -> str:
        return private_key_to_hex(self._key)

    def sign(self, data: bytes) -> str:
        return self._key.sign(data).hex()

    def sign_model(self, model: SignedModelT) -> SignedModelT:
        return sign_model(model, self._key)

    def derive_secret(self, purpose: str, length: int = 32) -> bytes:
        """Derive a symmetric secret bound to this key (HKDF-SHA256), e.g. for proof-of-work HMACs.

        Every worker holding the same private key derives the same secret, so no extra
        secret has to be distributed across a deployment.
        """
        from cryptography.hazmat.primitives import hashes
        from cryptography.hazmat.primitives.kdf.hkdf import HKDF

        seed = bytes.fromhex(self.export_private_key())
        return HKDF(algorithm=hashes.SHA256(), length=length, salt=None, info=purpose.encode()).derive(seed)


__all__ = [
    "KeyFormatError",
    "KeyPair",
    "PRIVATE_KEY_ENV",
    "Signer",
    "canonical_json",
    "fingerprint",
    "generate_keypair",
    "load_private_key",
    "load_public_key",
    "private_key_to_hex",
    "public_key_to_hex",
    "sign_bytes",
    "sign_model",
    "signing_payload",
    "verify_bytes",
    "verify_model",
]
