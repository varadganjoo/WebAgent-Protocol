from __future__ import annotations

import json
import time
from collections.abc import Callable

import httpx
import pytest

from tests.conftest import DOMAIN, client_for
from wap.client import (
    CapabilityNotFound,
    InsecureTransport,
    ManifestNotFound,
    ManifestResolver,
    SchemaValidationError,
    VerificationFailed,
    WAPClient,
    parse_target,
)
from wap.server import WAPServer
from wap.spec.crypto import Signer, canonical_json
from wap.spec.models import AgentManifest, Capability


def signed_manifest(signer: Signer, **overrides) -> AgentManifest:
    fields = dict(
        domain=DOMAIN,
        name="Shop",
        public_key=signer.public_key,
        interaction_url=f"https://{DOMAIN}/wap/v1/interact",
        capabilities=[
            Capability(
                id="get_price",
                name="Get price",
                input_schema={
                    "type": "object",
                    "properties": {"sku": {"type": "string"}, "quantity": {"type": "integer", "minimum": 1}},
                    "required": ["sku"],
                    "additionalProperties": False,
                },
            )
        ],
        expires_at=time.time() + 3600,
    )
    fields.update(overrides)
    return signer.sign_model(AgentManifest(**fields))


class Recorder:
    """httpx MockTransport handler serving canned manifests and counting requests."""

    def __init__(self, routes: dict[str, Callable[[httpx.Request], httpx.Response]]) -> None:
        self.routes = routes
        self.calls: list[str] = []

    def __call__(self, request: httpx.Request) -> httpx.Response:
        url = str(request.url)
        self.calls.append(url)
        handler = self.routes.get(url)
        if handler is None:
            return httpx.Response(404, json={"error": {"code": "invalid_request", "message": "not found"}})
        return handler(request)


def serve_manifest(manifest: AgentManifest, signer: Signer | None = None, *, header: bool = True):
    def handler(_: httpx.Request) -> httpx.Response:
        body = canonical_json(manifest.model_dump(mode="json"))
        headers = {"Content-Type": "application/json"}
        if header and signer is not None:
            headers["X-WAP-Signature"] = signer.sign(body)
        return httpx.Response(200, content=body, headers=headers)

    return handler


def resolver_for(recorder: Recorder, **kwargs) -> ManifestResolver:
    return ManifestResolver(httpx.AsyncClient(transport=httpx.MockTransport(recorder)), **kwargs)


URL = f"https://{DOMAIN}/.well-known/agent.json"


class TestParseTarget:
    @pytest.mark.parametrize(
        ("target", "authority", "scheme"),
        [
            ("shop.example", "shop.example", "https"),
            ("Shop.Example/some/page", "shop.example", "https"),
            ("https://shop.example/pricing?x=1", "shop.example", "https"),
            ("localhost:8000", "localhost:8000", "http"),
            ("http://localhost:8000", "localhost:8000", "http"),
            ("https://localhost:8443", "localhost:8443", "https"),
            ("127.0.0.1:9000", "127.0.0.1:9000", "http"),
        ],
    )
    def test_targets(self, target: str, authority: str, scheme: str) -> None:
        parsed = parse_target(target)
        assert (parsed.authority, parsed.scheme) == (authority, scheme)
        assert parsed.manifest_url == f"{scheme}://{authority}/.well-known/agent.json"

    def test_insecure_http_refused(self) -> None:
        with pytest.raises(InsecureTransport):
            parse_target("http://shop.example")
        assert parse_target("http://shop.example", allow_insecure=True).scheme == "http"

    @pytest.mark.parametrize("bad", ["ftp://shop.example", "https://user:pw@shop.example", "not a domain"])
    def test_invalid(self, bad: str) -> None:
        with pytest.raises(ValueError):
            parse_target(bad)


class TestResolver:
    async def test_resolves_verifies_and_caches(self) -> None:
        signer = Signer()
        recorder = Recorder({URL: serve_manifest(signed_manifest(signer), signer)})
        resolver = resolver_for(recorder)
        detailed = await resolver.resolve_detailed(DOMAIN)
        assert detailed.manifest.public_key == signer.public_key
        assert detailed.header_signature_verified
        assert detailed.fingerprint == signer.fingerprint
        await resolver.resolve("https://shop.example/any/page")
        assert len(recorder.calls) == 1
        assert resolver.cached(DOMAIN) is not None
        await resolver.resolve(DOMAIN, force_refresh=True)
        assert len(recorder.calls) == 2
        resolver.invalidate(DOMAIN)
        assert resolver.cached(DOMAIN) is None
        await resolver.resolve(DOMAIN)
        assert len(recorder.calls) == 3

    async def test_cache_ttl_respects_manifest_expiry(self) -> None:
        signer = Signer()
        manifest = signed_manifest(signer, expires_at=time.time() + 5)
        resolver = resolver_for(Recorder({URL: serve_manifest(manifest, signer)}), cache_ttl=600)
        detailed = await resolver.resolve_detailed(DOMAIN)
        assert detailed.cache_expires_at <= time.time() + 5

    async def test_concurrent_resolutions_are_coalesced(self) -> None:
        import asyncio

        signer = Signer()
        recorder = Recorder({URL: serve_manifest(signed_manifest(signer), signer)})
        resolver = resolver_for(recorder)
        await asyncio.gather(*(resolver.resolve(DOMAIN) for _ in range(10)))
        assert len(recorder.calls) == 1

    async def test_missing_manifest(self) -> None:
        resolver = resolver_for(Recorder({}))
        with pytest.raises(ManifestNotFound) as info:
            await resolver.resolve(DOMAIN)
        assert info.value.status_code == 404

    async def test_www_fallback(self) -> None:
        signer = Signer()
        www = signed_manifest(signer, domain=f"www.{DOMAIN}", interaction_url=f"https://www.{DOMAIN}/wap/v1/interact")
        recorder = Recorder({f"https://www.{DOMAIN}/.well-known/agent.json": serve_manifest(www, signer)})
        manifest = await resolver_for(recorder).resolve(DOMAIN)
        assert manifest.domain == f"www.{DOMAIN}"
        assert recorder.calls == [URL, f"https://www.{DOMAIN}/.well-known/agent.json"]

        no_fallback = Recorder({f"https://www.{DOMAIN}/.well-known/agent.json": serve_manifest(www, signer)})
        with pytest.raises(ManifestNotFound):
            await resolver_for(no_fallback, www_fallback=False).resolve(DOMAIN)

    async def test_redirects_are_not_followed(self) -> None:
        recorder = Recorder({URL: lambda r: httpx.Response(302, headers={"Location": "https://evil.example/x"})})
        with pytest.raises(ManifestNotFound, match="redirect"):
            await resolver_for(recorder, www_fallback=False).resolve(DOMAIN)
        assert recorder.calls == [URL]

    async def test_not_json(self) -> None:
        recorder = Recorder({URL: lambda r: httpx.Response(200, content=b"<html>shop</html>")})
        with pytest.raises(ManifestNotFound, match="JSON"):
            await resolver_for(recorder, www_fallback=False).resolve(DOMAIN)

    async def test_schema_invalid(self) -> None:
        recorder = Recorder({URL: lambda r: httpx.Response(200, json={"wap_version": "1.0", "name": "x"})})
        with pytest.raises(VerificationFailed, match="schema"):
            await resolver_for(recorder).resolve(DOMAIN)

    async def test_domain_binding(self) -> None:
        signer = Signer()
        other = signed_manifest(signer, domain="other.example", interaction_url="https://other.example/wap/v1/interact")
        with pytest.raises(VerificationFailed, match="bound to"):
            await resolver_for(Recorder({URL: serve_manifest(other, signer)})).resolve(DOMAIN)

    async def test_tampered_manifest(self) -> None:
        signer = Signer()
        tampered = signed_manifest(signer).model_copy(update={"name": "Totally Legit Shop"})
        with pytest.raises(VerificationFailed, match="signature"):
            await resolver_for(Recorder({URL: serve_manifest(tampered, signer, header=False)})).resolve(DOMAIN)

    async def test_unsigned_manifest(self) -> None:
        signer = Signer()
        unsigned = signed_manifest(signer).model_copy(update={"signature": ""})
        with pytest.raises(VerificationFailed):
            await resolver_for(Recorder({URL: serve_manifest(unsigned, header=False)})).resolve(DOMAIN)

    async def test_key_substitution(self) -> None:
        """An attacker re-signing with their own key must not pass a pinned-key check."""
        attacker = Signer()
        forged = signed_manifest(attacker)
        genuine = Signer()
        resolver = resolver_for(
            Recorder({URL: serve_manifest(forged, attacker)}), pinned_keys={DOMAIN: genuine.public_key}
        )
        with pytest.raises(VerificationFailed, match="pinned"):
            await resolver.resolve(DOMAIN)
        resolver.pin(DOMAIN, attacker.public_key)
        assert (await resolver.resolve(DOMAIN)).public_key == attacker.public_key

    async def test_bad_header_signature(self) -> None:
        signer = Signer()
        manifest = signed_manifest(signer)

        def handler(_: httpx.Request) -> httpx.Response:
            body = canonical_json(manifest.model_dump(mode="json"))
            return httpx.Response(200, content=body, headers={"X-WAP-Signature": Signer().sign(body)})

        with pytest.raises(VerificationFailed, match="X-WAP-Signature"):
            await resolver_for(Recorder({URL: handler})).resolve(DOMAIN)

    async def test_expired_manifest(self) -> None:
        signer = Signer()
        expired = signed_manifest(signer, issued_at=time.time() - 7200, expires_at=time.time() - 3600)
        with pytest.raises(VerificationFailed, match="expired"):
            await resolver_for(Recorder({URL: serve_manifest(expired, signer)})).resolve(DOMAIN)

    @pytest.mark.parametrize(
        "url",
        ["https://victim.example/api", "https://shop.example.evil.example/x", "http://shop.example/wap/v1/interact"],
    )
    async def test_interaction_url_must_stay_on_origin(self, url: str) -> None:
        signer = Signer()
        manifest = signed_manifest(signer, interaction_url=url)
        with pytest.raises(VerificationFailed):
            await resolver_for(Recorder({URL: serve_manifest(manifest, signer)})).resolve(DOMAIN)

    async def test_subdomain_interaction_url_allowed(self) -> None:
        signer = Signer()
        manifest = signed_manifest(signer, interaction_url=f"https://agents.{DOMAIN}/wap/v1/interact")
        resolved = await resolver_for(Recorder({URL: serve_manifest(manifest, signer)})).resolve(DOMAIN)
        assert resolved.interaction_url.startswith("https://agents.")

    async def test_oversized_manifest(self) -> None:
        recorder = Recorder({URL: lambda r: httpx.Response(200, content=b" " * (2 * 1024 * 1024))})
        with pytest.raises(ManifestNotFound, match="exceeds"):
            await resolver_for(recorder, www_fallback=False).resolve(DOMAIN)

    async def test_private_network_blocking(self) -> None:
        signer = Signer()
        recorder = Recorder(
            {"http://127.0.0.1:9/.well-known/agent.json": serve_manifest(signed_manifest(signer), signer)}
        )
        with pytest.raises(VerificationFailed, match="non-public"):
            await resolver_for(recorder, block_private_networks=True).resolve("127.0.0.1:9")
        assert recorder.calls == []


class TestClientDiscovery:
    async def test_discover_against_live_asgi_server(self, shop: WAPServer, shop_client: WAPClient) -> None:
        manifest = await shop_client.discover(DOMAIN)
        assert manifest.public_key == shop.public_key
        assert {c.id for c in manifest.capabilities} == {"get_price", "list_items"}

    async def test_capability_lookup(self, shop_client: WAPClient) -> None:
        with pytest.raises(CapabilityNotFound) as info:
            async for _ in shop_client.query(DOMAIN, capability_id="fly_to_moon"):
                pass
        assert info.value.available == ["get_price", "list_items"]

    async def test_client_side_schema_validation(self, shop: WAPServer) -> None:
        calls: list[str] = []
        app = shop.create_app()
        transport = httpx.ASGITransport(app=app)

        class Counting(httpx.AsyncBaseTransport):
            async def handle_async_request(self, request: httpx.Request) -> httpx.Response:
                calls.append(request.url.path)
                return await transport.handle_async_request(request)

        async with WAPClient(transport=Counting()) as client:
            with pytest.raises(SchemaValidationError) as info:
                await client.invoke(DOMAIN, "get_price", {"quantity": "lots"})
        assert any("sku" in e for e in info.value.errors)
        assert any("quantity" in e for e in info.value.errors)
        assert "/wap/v1/interact" not in calls  # rejected before touching the business backend

    async def test_intent_or_capability_required(self, shop_client: WAPClient) -> None:
        with pytest.raises(ValueError):
            await shop_client.ask(DOMAIN)

    async def test_pinned_key_via_client(self, shop: WAPServer) -> None:
        async with client_for(shop.create_app(), pinned_keys={DOMAIN: Signer().public_key}) as client:
            with pytest.raises(VerificationFailed):
                await client.discover(DOMAIN)
        async with client_for(shop.create_app(), pinned_keys={DOMAIN: shop.public_key}) as client:
            assert (await client.discover(DOMAIN)).domain == DOMAIN

    async def test_third_party_verifier_interop(self, shop: WAPServer) -> None:
        """A verifier using only the stdlib json module and raw Ed25519 reproduces the signature."""
        from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PublicKey

        async with httpx.AsyncClient(transport=httpx.ASGITransport(app=shop.create_app())) as http:
            document = (await http.get(f"https://{DOMAIN}/.well-known/agent.json")).json()
        signature = bytes.fromhex(document.pop("signature"))
        payload = json.dumps(document, sort_keys=True, separators=(",", ":"), ensure_ascii=False).encode()
        Ed25519PublicKey.from_public_bytes(bytes.fromhex(document["public_key"])).verify(signature, payload)
