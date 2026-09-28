"""Well-known manifest resolution, verification and caching.

Resolution algorithm (``docs/spec_rfc.md`` Section 5):

1. Normalise the target into an authority and a base URL. HTTPS is mandatory
   except for loopback authorities (``localhost``, ``127.0.0.0/8``) or when the
   caller explicitly opts into ``allow_insecure``.
2. Optionally resolve the host through DNS and refuse private, loopback or
   link-local addresses (SSRF protection for LLM-driven callers).
3. ``GET {base}/.well-known/agent.json`` without following redirects. On 404 or
   a connection failure for an apex domain, fall back once to ``www.{domain}``.
4. Validate the document against :class:`AgentManifest`, verify the embedded
   Ed25519 signature, verify ``X-WAP-Signature`` over the raw body when
   present, enforce domain binding, pinned keys and expiry.
5. Cache the verified manifest until ``min(cache_ttl, expires_at)``.
"""

from __future__ import annotations

import asyncio
import ipaddress
import json
import socket
import time
from collections.abc import Callable
from dataclasses import dataclass
from typing import Literal
from urllib.parse import urlsplit

import httpx
from pydantic import ValidationError

from ..spec.crypto import fingerprint, verify_bytes, verify_endorsement, verify_model
from ..spec.models import (
    HEADER_SIGNATURE,
    WAP_VERSION,
    WELL_KNOWN_PATH,
    WELL_KNOWN_PATHS,
    AgentManifest,
    authority_host,
    is_local_authority,
    normalize_authority,
)
from .dnskey import TxtResolver, check_dns_key
from .exceptions import InsecureTransport, ManifestNotFound, VerificationFailed

MAX_MANIFEST_BYTES = 1024 * 1024


@dataclass(frozen=True)
class Target:
    authority: str
    scheme: str

    @property
    def base_url(self) -> str:
        return f"{self.scheme}://{self.authority}"

    @property
    def manifest_url(self) -> str:
        return self.base_url + WELL_KNOWN_PATH

    def url_for(self, path: str) -> str:
        return self.base_url + path


@dataclass(frozen=True)
class ResolvedManifest:
    manifest: AgentManifest
    url: str
    fetched_at: float
    cache_expires_at: float
    header_signature_verified: bool

    @property
    def fingerprint(self) -> str:
        return fingerprint(self.manifest.public_key)


def parse_target(target: str, *, allow_insecure: bool = False) -> Target:
    """Turn ``bakery.example``, ``localhost:8000`` or ``https://bakery.example/x`` into a :class:`Target`."""
    raw = target.strip()
    if "://" in raw:
        parts = urlsplit(raw)
        scheme = parts.scheme.lower()
        if scheme not in ("http", "https"):
            raise ValueError(f"unsupported URL scheme {parts.scheme!r}")
        if parts.username or parts.password:
            raise ValueError("URLs with credentials are not allowed")
        authority = normalize_authority(parts.netloc)
    else:
        authority = normalize_authority(raw.split("/", 1)[0])
        scheme = "http" if is_local_authority(authority) else "https"
    if scheme == "http" and not (is_local_authority(authority) or allow_insecure):
        raise InsecureTransport(
            f"refusing plain HTTP for non-loopback domain {authority!r}; pass allow_insecure=True to override"
        )
    return Target(authority=authority, scheme=scheme)


def _host_is_within(host: str, domain_host: str) -> bool:
    return host == domain_host or host.endswith("." + domain_host)


def _is_ip_literal(host: str) -> bool:
    try:
        ipaddress.ip_address(host)
    except ValueError:
        return False
    return True


def _is_public_address(address: str) -> bool:
    ip = ipaddress.ip_address(address)
    return not (
        ip.is_private or ip.is_loopback or ip.is_link_local or ip.is_multicast or ip.is_reserved or ip.is_unspecified
    )


class ManifestResolver:
    """Fetches, verifies and caches :class:`AgentManifest` documents."""

    def __init__(
        self,
        http: httpx.AsyncClient,
        *,
        cache_ttl: float = 300.0,
        pinned_keys: dict[str, str] | None = None,
        allow_insecure: bool = False,
        verify_dns: bool = False,
        block_private_networks: bool = False,
        allow_loopback: bool = False,
        www_fallback: bool = True,
        trust_on_first_use: bool = False,
        on_key_change: Callable[[str, str, str], None] | None = None,
        dns_key_policy: Literal["off", "if-present", "require"] = "off",
        txt_resolver: TxtResolver | None = None,
    ) -> None:
        self.http = http
        self.cache_ttl = cache_ttl
        self.pinned_keys = {normalize_authority(k): v.lower() for k, v in (pinned_keys or {}).items()}
        self.allow_insecure = allow_insecure
        self.verify_dns = verify_dns or block_private_networks
        self.block_private_networks = block_private_networks
        # With block_private_networks, still allow 127.0.0.0/8 / ::1 (local development).
        self.allow_loopback = allow_loopback
        self.www_fallback = www_fallback
        # With trust_on_first_use, the first verified key for a domain is pinned automatically.
        self.trust_on_first_use = trust_on_first_use
        # Called as on_key_change(domain, old_key, new_key) when a pinned key rotates (endorsed).
        self.on_key_change = on_key_change
        self.dns_key_policy = dns_key_policy
        self.txt_resolver = txt_resolver
        self._cache: dict[str, ResolvedManifest] = {}
        self._locks: dict[str, asyncio.Lock] = {}

    # ------------------------------------------------------------------ public API

    async def resolve(self, target: str, *, force_refresh: bool = False) -> AgentManifest:
        return (await self.resolve_detailed(target, force_refresh=force_refresh)).manifest

    async def resolve_detailed(self, target: str, *, force_refresh: bool = False) -> ResolvedManifest:
        parsed = parse_target(target, allow_insecure=self.allow_insecure)
        key = parsed.authority
        cached = self._cache.get(key)
        if cached is not None and not force_refresh and time.time() < cached.cache_expires_at:
            return cached
        lock = self._locks.setdefault(key, asyncio.Lock())
        async with lock:
            cached = self._cache.get(key)
            if cached is not None and not force_refresh and time.time() < cached.cache_expires_at:
                return cached
            resolved = await self._fetch_with_fallback(parsed)
            self._cache[key] = resolved
            return resolved

    def cached(self, target: str) -> ResolvedManifest | None:
        parsed = parse_target(target, allow_insecure=True)
        entry = self._cache.get(parsed.authority)
        if entry is None or time.time() >= entry.cache_expires_at:
            return None
        return entry

    def invalidate(self, target: str | None = None) -> None:
        if target is None:
            self._cache.clear()
        else:
            self._cache.pop(parse_target(target, allow_insecure=True).authority, None)

    def pin(self, domain: str, public_key: str) -> None:
        self.pinned_keys[normalize_authority(domain)] = public_key.lower()

    # ------------------------------------------------------------------ internals

    async def _check_dns(self, target: Target) -> None:
        host = authority_host(target.authority)
        if _is_ip_literal(host):
            addresses = [host]
        else:
            port = int(target.authority.rsplit(":", 1)[1]) if ":" in target.authority else 443
            loop = asyncio.get_running_loop()
            try:
                infos = await loop.getaddrinfo(host, port, type=socket.SOCK_STREAM)
            except socket.gaierror as exc:
                raise ManifestNotFound(target.authority, f"DNS resolution failed: {exc}") from exc
            addresses = sorted({str(info[4][0]) for info in infos})
            if not addresses:
                raise ManifestNotFound(target.authority, "DNS returned no addresses")
        if self.block_private_networks:
            blocked = [
                a
                for a in addresses
                if not _is_public_address(a) and not (self.allow_loopback and ipaddress.ip_address(a).is_loopback)
            ]
            if blocked:
                raise VerificationFailed(
                    target.authority, f"resolves to non-public address(es) {blocked}; blocked by policy"
                )

    async def _fetch_paths(self, target: Target, *, expected: str) -> ResolvedManifest:
        """Try ``/.well-known/wap.json``, then the legacy ``/.well-known/agent.json``."""
        first_error: ManifestNotFound | None = None
        for path in WELL_KNOWN_PATHS:
            try:
                return await self._fetch(target, expected=expected, path=path)
            except ManifestNotFound as exc:
                # Only fall back when the primary path is simply absent.
                if exc.status_code != 404:
                    raise
                first_error = first_error or exc
        assert first_error is not None
        raise first_error

    async def _fetch_with_fallback(self, target: Target) -> ResolvedManifest:
        try:
            return await self._fetch_paths(target, expected=target.authority)
        except ManifestNotFound as first_error:
            host = authority_host(target.authority)
            is_ip = _is_ip_literal(host)
            if not self.www_fallback or host.startswith("www.") or is_local_authority(target.authority) or is_ip:
                raise
            alternate = Target(authority="www." + target.authority, scheme=target.scheme)
            try:
                return await self._fetch_paths(alternate, expected=alternate.authority)
            except ManifestNotFound:
                raise first_error from None

    async def _fetch(self, target: Target, *, expected: str, path: str = WELL_KNOWN_PATH) -> ResolvedManifest:
        if self.verify_dns:
            await self._check_dns(target)
        url = target.url_for(path)
        try:
            async with self.http.stream(
                "GET", url, headers={"Accept": "application/json", "X-WAP-Version": WAP_VERSION}, follow_redirects=False
            ) as response:
                if response.status_code in (301, 302, 303, 307, 308):
                    raise ManifestNotFound(
                        target.authority,
                        f"manifest endpoint redirected to {response.headers.get('location')!r}; "
                        "redirects are not followed",
                        url=url,
                        status_code=response.status_code,
                    )
                if response.status_code != 200:
                    raise ManifestNotFound(
                        target.authority,
                        f"HTTP {response.status_code} from {url}",
                        url=url,
                        status_code=response.status_code,
                    )
                body = bytearray()
                async for piece in response.aiter_bytes():
                    body.extend(piece)
                    if len(body) > MAX_MANIFEST_BYTES:
                        raise ManifestNotFound(
                            target.authority, f"manifest exceeds {MAX_MANIFEST_BYTES} bytes", url=url
                        )
                header_signature = response.headers.get(HEADER_SIGNATURE)
        except httpx.HTTPError as exc:
            raise ManifestNotFound(target.authority, f"could not fetch {url}: {exc!s}", url=url) from exc

        try:
            document = json.loads(bytes(body))
        except ValueError as exc:
            raise ManifestNotFound(target.authority, "manifest is not valid JSON", url=url) from exc
        if not isinstance(document, dict) or "wap_version" not in document:
            raise ManifestNotFound(
                target.authority,
                f"{url} is not a WAP manifest (no wap_version); it may be another agent-description format",
                url=url,
            )
        try:
            manifest = AgentManifest.model_validate(document)
        except ValidationError as exc:
            raise VerificationFailed(target.authority, f"manifest failed schema validation: {exc}") from exc

        self._verify(manifest, expected=expected)
        if self.dns_key_policy != "off":
            await check_dns_key(manifest, required=self.dns_key_policy == "require", txt_resolver=self.txt_resolver)
        header_ok = False
        if header_signature:
            if not verify_bytes(manifest.public_key, bytes(body), header_signature):
                raise VerificationFailed(target.authority, "X-WAP-Signature header does not match the response body")
            header_ok = True

        now = time.time()
        ttl = self.cache_ttl
        if manifest.expires_at is not None:
            ttl = min(ttl, manifest.expires_at - now)
        return ResolvedManifest(
            manifest=manifest,
            url=url,
            fetched_at=now,
            cache_expires_at=now + max(0.0, ttl),
            header_signature_verified=header_ok,
        )

    def _verify(self, manifest: AgentManifest, *, expected: str) -> None:
        if manifest.wap_version != WAP_VERSION:
            raise VerificationFailed(expected, f"unsupported wap_version {manifest.wap_version!r}")
        if manifest.domain != expected:
            raise VerificationFailed(
                expected, f"manifest is bound to {manifest.domain!r}, not the requested domain {expected!r}"
            )
        if not verify_model(manifest, manifest.public_key):
            raise VerificationFailed(expected, "manifest signature is missing or invalid")
        if manifest.is_expired():
            raise VerificationFailed(expected, "manifest has expired")
        domain_host = authority_host(manifest.domain)
        for label, url in (
            ("interaction_url", manifest.interaction_url),
            ("challenge_url", manifest.challenge_url),
            ("mcp_url", manifest.mcp_url),
        ):
            if url is None:
                continue
            parts = urlsplit(url)
            host = (parts.hostname or "").lower()
            if not _host_is_within(host, domain_host):
                raise VerificationFailed(
                    expected, f"{label} host {host!r} is outside the manifest domain {domain_host!r}"
                )
            if parts.scheme == "http" and not (is_local_authority(parts.netloc) or self.allow_insecure):
                raise VerificationFailed(expected, f"{label} uses plain HTTP")
        pinned = self.pinned_keys.get(manifest.domain)
        if pinned is not None and pinned != manifest.public_key:
            if not verify_endorsement(manifest, pinned):
                raise VerificationFailed(
                    expected,
                    f"public key {fingerprint(manifest.public_key)} does not match pinned key {fingerprint(pinned)} "
                    "and the pinned key did not endorse it",
                )
            # Rotation endorsed by the key we trusted: follow it.
            self.pinned_keys[manifest.domain] = manifest.public_key
            if self.on_key_change is not None:
                self.on_key_change(manifest.domain, pinned, manifest.public_key)
        elif pinned is None and self.trust_on_first_use:
            self.pinned_keys[manifest.domain] = manifest.public_key


__all__ = ["ManifestResolver", "ResolvedManifest", "Target", "parse_target"]
