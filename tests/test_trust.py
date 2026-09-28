"""Cross-language canonical JSON, published test vectors, key rotation, TOFU pinning and DNS anchoring."""

from __future__ import annotations

import json
import shutil
import subprocess
import sys
import time
from collections.abc import Callable
from pathlib import Path

import pytest
from hypothesis import HealthCheck, given, settings
from hypothesis import strategies as st

from tests.conftest import DOMAIN, client_for
from wap.client import VerificationFailed
from wap.client.dnskey import parse_keys, txt_record_for
from wap.server import WAPServer
from wap.spec.crypto import Signer, verify_endorsement, verify_model
from wap.spec.jcs import CanonicalizationError, canonicalize, format_number

ROOT = Path(__file__).resolve().parent.parent
NODE = shutil.which("node")
needs_node = pytest.mark.skipif(NODE is None, reason="node is not installed")

JS_CANONICALIZE = """
const canon = (v) => v === null || typeof v !== "object" ? JSON.stringify(v)
  : Array.isArray(v) ? "[" + v.map(canon).join(",") + "]"
  : "{" + Object.keys(v).sort().map(k => JSON.stringify(k) + ":" + canon(v[k])).join(",") + "}";
const inputs = JSON.parse(require("fs").readFileSync(0, "utf8"));
console.log(JSON.stringify(inputs.map(canon)));
"""


def node_canonical(values: list) -> list[str]:
    result = subprocess.run(
        [NODE, "-e", JS_CANONICALIZE],
        input=json.dumps(values),
        capture_output=True,
        text=True,
        encoding="utf-8",
        check=True,
    )
    return json.loads(result.stdout)


class TestJCS:
    @pytest.mark.parametrize(
        ("value", "expected"),
        [
            (0.0, "0"),
            (-0.0, "0"),
            (1.0, "1"),
            (4.5, "4.5"),
            (0.002, "0.002"),
            (1e-7, "1e-7"),
            (1e-6, "0.000001"),
            (1e21, "1e+21"),
            (1e20, "100000000000000000000"),
            (5e-324, "5e-324"),
            (1.7976931348623157e308, "1.7976931348623157e+308"),
            (2**53, "9007199254740992"),
        ],
    )
    def test_numbers(self, value, expected: str) -> None:
        assert format_number(value) == expected

    def test_rejections(self) -> None:
        for bad in (float("nan"), float("inf"), 2**53 + 1, {1: "x"}, {"a": object()}):
            with pytest.raises(CanonicalizationError):
                canonicalize(bad if isinstance(bad, dict) else [bad])

    def test_utf16_member_ordering(self) -> None:
        # U+E000 sorts *after* U+1F600's surrogate pair in UTF-16, the opposite of code-point order.
        assert canonicalize({"": 1, "\U0001f600": 2}) == '{"😀":2,"":1}'.encode()

    @needs_node
    @settings(max_examples=150, deadline=None, suppress_health_check=[HealthCheck.too_slow])
    @given(
        st.lists(
            st.recursive(
                st.none()
                | st.booleans()
                | st.integers(min_value=-(2**53), max_value=2**53)
                | st.floats(allow_nan=False, allow_infinity=False)
                | st.text(),
                lambda children: st.lists(children, max_size=4) | st.dictionaries(st.text(), children, max_size=4),
                max_leaves=12,
            ),
            min_size=1,
            max_size=8,
        )
    )
    def test_matches_ecmascript(self, values: list) -> None:
        # Surrogate-containing strings can't round-trip through JSON text; hypothesis rarely makes them.
        try:
            payload = json.dumps(values, allow_nan=False)
            json.loads(payload)
        except (ValueError, UnicodeEncodeError):
            return
        try:
            ours = [canonicalize(v).decode("utf-8") for v in values]
        except UnicodeEncodeError:
            return
        assert ours == node_canonical(values)


class TestVectors:
    def test_vectors_are_current(self) -> None:
        result = subprocess.run(
            [sys.executable, str(ROOT / "examples" / "generate_test_vectors.py"), "--check"],
            capture_output=True,
            text=True,
        )
        assert result.returncode == 0, result.stdout + result.stderr

    @needs_node
    def test_vectors_verify_in_javascript(self) -> None:
        result = subprocess.run(
            [NODE, str(ROOT / "tests" / "interop" / "verify_vectors.mjs"), str(ROOT / "docs" / "test-vectors.json")],
            capture_output=True,
            text=True,
        )
        assert result.returncode == 0, result.stderr
        assert result.stdout.startswith("ok ")

    def test_vectors_verify_in_python(self) -> None:
        from wap.spec.models import AgentManifest, AgentMessage

        vectors = json.loads((ROOT / "docs" / "test-vectors.json").read_text())
        manifest = AgentManifest.model_validate(vectors["manifest"]["document"])
        assert verify_model(manifest, vectors["keys"]["domain"]["public_key"])
        rotated = AgentManifest.model_validate(vectors["rotated_manifest"]["document"])
        assert verify_endorsement(rotated, vectors["keys"]["previous_domain_key"]["public_key"])
        reply = AgentMessage.model_validate(vectors["reply"]["document"])
        assert verify_model(reply, vectors["keys"]["domain"]["public_key"])


class TestKeyRotation:
    async def test_pinned_client_follows_endorsed_rotation(self, make_server: Callable[..., WAPServer]) -> None:
        old, new = Signer(), Signer()
        changes: list[tuple[str, str, str]] = []
        rotated = make_server(private_key=new.export_private_key(), previous_keys=[old.export_private_key()])
        rotated.action(name="ping", effects="read")(lambda: "pong")
        manifest = rotated.manifest()
        assert manifest.previous_keys == [old.public_key]
        assert verify_endorsement(manifest, old.public_key)

        async with client_for(rotated.create_app(mcp=False), pinned_keys={DOMAIN: old.public_key}) as client:
            client.resolver.on_key_change = lambda *args: changes.append(args)
            discovered = await client.discover(DOMAIN)
            assert discovered.public_key == new.public_key
            assert client.resolver.pinned_keys[DOMAIN] == new.public_key  # pin migrated
            assert (await client.invoke(DOMAIN, "ping")).verified
        assert changes == [(DOMAIN, old.public_key, new.public_key)]

    async def test_unendorsed_key_change_is_rejected(self, make_server: Callable[..., WAPServer]) -> None:
        pinned, attacker, unrelated = Signer(), Signer(), Signer()
        # The attacker lists the pinned key as "previous" but cannot produce its endorsement.
        hijacked = make_server(
            private_key=attacker.export_private_key(), previous_keys=[unrelated.export_private_key()]
        )
        manifest = hijacked.manifest()
        forged = manifest.model_copy(update={"previous_keys": [pinned.public_key], "key_endorsements": {}})
        assert not verify_endorsement(forged, pinned.public_key)
        async with client_for(hijacked.create_app(mcp=False), pinned_keys={DOMAIN: pinned.public_key}) as client:
            with pytest.raises(VerificationFailed, match="did not endorse"):
                await client.discover(DOMAIN)

    def test_endorsement_breaks_if_manifest_is_altered(self) -> None:
        old, new = Signer(), Signer()
        server = WAPServer(
            name="S", domain=DOMAIN, private_key=new.export_private_key(), previous_keys=[old.export_private_key()]
        )
        manifest = server.manifest()
        altered = manifest.model_copy(update={"interaction_url": "https://shop.example/elsewhere"})
        assert verify_endorsement(manifest, old.public_key)
        assert not verify_endorsement(altered, old.public_key)

    async def test_trust_on_first_use(self, make_server: Callable[..., WAPServer]) -> None:
        server = make_server()
        async with client_for(server.create_app(mcp=False), trust_on_first_use=True) as client:
            await client.discover(DOMAIN)
            assert client.resolver.pinned_keys[DOMAIN] == server.public_key
        impostor = make_server(private_key=Signer().export_private_key())
        async with client_for(impostor.create_app(mcp=False), trust_on_first_use=True) as client:
            client.resolver.pinned_keys[DOMAIN] = server.public_key  # remembered from before
            with pytest.raises(VerificationFailed):
                await client.discover(DOMAIN)


class TestDNSAnchoring:
    def test_record_format(self) -> None:
        key = Signer().public_key
        assert parse_keys([txt_record_for(key), "v=spf1 -all", "v=wap1; k=zz"]) == {key}

    @pytest.mark.parametrize(
        ("records", "policy", "ok"),
        [
            ("match", "if-present", True),
            ("match", "require", True),
            ("other", "if-present", False),
            ("none", "if-present", True),
            ("none", "require", False),
        ],
    )
    async def test_policies(self, make_server: Callable[..., WAPServer], records: str, policy: str, ok: bool) -> None:
        server = make_server()
        published = {
            "match": [txt_record_for(server.public_key)],
            "other": [txt_record_for(Signer().public_key)],
            "none": [],
        }[records]
        lookups: list[str] = []

        async def resolver(name: str) -> list[str]:
            lookups.append(name)
            return published

        async with client_for(server.create_app(mcp=False), dns_key_policy=policy, txt_resolver=resolver) as client:
            if ok:
                await client.discover(DOMAIN)
            else:
                with pytest.raises(VerificationFailed):
                    await client.discover(DOMAIN)
        assert lookups == [f"_wap.{DOMAIN}"]


def test_manifest_timestamps_survive_round_trip() -> None:
    server = WAPServer(name="S", domain=DOMAIN, private_key=Signer().export_private_key())
    manifest = server.manifest()
    again = type(manifest).model_validate_json(manifest.model_dump_json())
    assert verify_model(again, server.public_key) and again.issued_at <= time.time()
