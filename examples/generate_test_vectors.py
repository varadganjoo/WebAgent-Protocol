"""Generate docs/test-vectors.json: fixed inputs and outputs for independent WAP implementations.

    python examples/generate_test_vectors.py            # rewrite the file
    python examples/generate_test_vectors.py --check    # exit 1 if the file is stale

Every value is deterministic (fixed keys, timestamps and ids; Ed25519 signatures
are deterministic), so implementations in other languages can check that they
produce byte-identical canonical JSON, signatures and proof-of-work digests.
``tests/interop/verify_vectors.mjs`` verifies the file with Node.js alone.
"""

from __future__ import annotations

import hashlib
import json
import sys
from pathlib import Path
from typing import Any

sys.path.insert(0, str(Path(__file__).resolve().parent.parent))

from wap.spec.crypto import Signer, endorsement_payload, signing_payload  # noqa: E402
from wap.spec.jcs import canonicalize  # noqa: E402
from wap.spec.models import AgentManifest, AgentMessage, Capability  # noqa: E402
from wap.spec.pow import pow_digest, solve  # noqa: E402

OUTPUT = Path(__file__).resolve().parent.parent / "docs" / "test-vectors.json"


def key(label: str) -> Signer:
    return Signer(hashlib.sha256(f"wap test vector key: {label}".encode()).hexdigest())


JCS_CASES: list[Any] = [
    {"b": 2, "a": 1, "c": {"z": [3, 2, 1], "y": None, "x": True}},
    {"numbers": [0, -0.0, 1.0, 4.5, 0.002, 1e-7, 1e-6, 1e21, 1e20, 333333333.3333333, 5e-324, -1.5e300]},
    {"strings": ["é", "€", "\U0001f600", " ", "tab\there", 'quote"back\\slash', "\u0001\u001f"]},
    {"": 1, "\U0001f600": 2, "a": 3, "é": 4, "A": 5},  # UTF-16 code-unit ordering
    [1, "two", [3, {"four": 4}], None, False],
]


def build() -> dict[str, Any]:
    domain_key = key("bakery.example")
    old_key = key("bakery.example previous")
    agent_key = key("shopper agent")

    manifest = AgentManifest(
        domain="bakery.example",
        name="Golden Crust Bakery",
        description="Test-vector manifest.",
        public_key=domain_key.public_key,
        interaction_url="https://bakery.example/wap/v1/interact",
        challenge_url="https://bakery.example/wap/v1/challenge",
        mcp_url="https://bakery.example/mcp",
        capabilities=[
            Capability(
                id="check_pastry_stock",
                name="Check Pastry Stock",
                description="Units available right now.",
                effects="read",
                input_schema={"type": "object", "properties": {"item": {"type": "string"}}, "required": ["item"]},
            )
        ],
        pow_required=True,
        pow_difficulty=4,
        rate_limit_policy={"requests_per_minute": 120, "burst": 30, "scopes": ["ip", "agent_key"]},
        issued_at=1790000000.5,
        expires_at=1790003600.5,
    )
    signed_manifest = domain_key.sign_model(manifest)

    rotated = manifest.model_copy(update={"previous_keys": [old_key.public_key]})
    rotated = rotated.model_copy(
        update={"key_endorsements": {old_key.public_key: old_key.sign(endorsement_payload(rotated))}}
    )
    rotated = domain_key.sign_model(rotated)

    request = agent_key.sign_model(
        AgentMessage(
            message_id="0123456789abcdef0123456789abcdef",
            session_id="test-vector-session",
            role="user_agent",
            content="",
            capability_id="check_pastry_stock",
            structured_data={"item": "Sourdough Croissant"},
            timestamp=1790000100.25,
            idempotency_key=None,
            public_key=agent_key.public_key,
        )
    )
    reply = domain_key.sign_model(
        AgentMessage(
            message_id="fedcba9876543210fedcba9876543210",
            session_id="test-vector-session",
            role="business_agent",
            content="Yes! 24 x Sourdough Croissant available at $4.50 each.",
            capability_id="check_pastry_stock",
            structured_data={"item": "Sourdough Croissant", "available": 24, "unit_price": 4.5},
            in_reply_to=request.message_id,
            timestamp=1790000100.75,
            public_key=domain_key.public_key,
        )
    )

    seed = hashlib.sha256(b"wap test vector seed").hexdigest() * 2 + "00" * 8
    nonce = solve(seed, 4)

    def signed_doc(model: Any) -> dict[str, Any]:
        return {
            "document": model.model_dump(mode="json"),
            "signing_payload": signing_payload(model).decode("utf-8"),
            "signature": model.signature,
        }

    return {
        "description": (
            "WebAgent Protocol 1.0 test vectors. Canonical form is RFC 8785 (JCS); signatures are pure Ed25519 "
            "(RFC 8032) over the UTF-8 canonical bytes of the document without its 'signature' member; keys and "
            "signatures are lower-case hex."
        ),
        "keys": {
            "domain": {"private_key": domain_key.export_private_key(), "public_key": domain_key.public_key},
            "previous_domain_key": {"private_key": old_key.export_private_key(), "public_key": old_key.public_key},
            "agent": {"private_key": agent_key.export_private_key(), "public_key": agent_key.public_key},
        },
        "jcs": [{"input": case, "canonical": canonicalize(case).decode("utf-8")} for case in JCS_CASES],
        "manifest": signed_doc(signed_manifest),
        "rotated_manifest": {
            **signed_doc(rotated),
            "endorsement_payload": endorsement_payload(rotated).decode("utf-8"),
        },
        "request": signed_doc(request),
        "reply": signed_doc(reply),
        "proof_of_work": {
            "algorithm": "sha256-leading-zero-hex",
            "seed": seed,
            "difficulty": 4,
            "nonce": nonce,
            "digest": pow_digest(seed, nonce),
        },
    }


def render() -> str:
    return json.dumps(build(), indent=2, ensure_ascii=False) + "\n"


def main() -> None:
    content = render()
    if "--check" in sys.argv:
        if not OUTPUT.exists() or OUTPUT.read_text(encoding="utf-8") != content:
            print(f"{OUTPUT} is stale; run python examples/generate_test_vectors.py")
            raise SystemExit(1)
        print("test vectors are up to date")
        return
    OUTPUT.write_text(content, encoding="utf-8")
    print(f"wrote {OUTPUT}")


if __name__ == "__main__":
    main()
