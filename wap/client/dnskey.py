"""Optional DNS anchoring of a domain's WAP key.

A domain can publish its key (or keys, during a rotation) in DNS::

    _wap.bakery.example.  TXT  "v=wap1; k=8c2fcce14c053b08152248cd13ebab41e783abae46d51140f6954d22d7f3a1b2"

A client configured with ``dns_key_policy="if-present"`` rejects a manifest whose
key is not among the published ones; with ``"require"`` it also rejects domains
that publish none. An attacker who compromises only the web server (or its TLS
certificate) then cannot substitute a key without also controlling DNS; with
DNSSEC this becomes a strong independent anchor.

Lookups use ``dnspython`` (``pip install "webagent-protocol[dns]"``) unless a
custom async ``txt_resolver`` is supplied (e.g. a DNS-over-HTTPS client).
"""

from __future__ import annotations

import re
from collections.abc import Awaitable, Callable

from ..spec.crypto import fingerprint
from ..spec.models import AgentManifest, authority_host
from .exceptions import VerificationFailed

TxtResolver = Callable[[str], Awaitable[list[str]]]

_KEY_RE = re.compile(r"(?:^|;)\s*k\s*=\s*([0-9a-fA-F]{64})\s*(?:;|$)")
_VERSION_RE = re.compile(r"^\s*v\s*=\s*wap1\s*(?:;|$)")


def record_name(domain: str) -> str:
    return f"_wap.{authority_host(domain)}"


def txt_record_for(public_key: str) -> str:
    """The TXT record value a domain publishes for ``public_key``."""
    return f"v=wap1; k={public_key.lower()}"


def parse_keys(records: list[str]) -> set[str]:
    keys: set[str] = set()
    for record in records:
        if not _VERSION_RE.match(record):
            continue
        match = _KEY_RE.search(record)
        if match:
            keys.add(match.group(1).lower())
    return keys


async def dnspython_txt(name: str) -> list[str]:
    try:
        import dns.asyncresolver
        import dns.exception
        import dns.resolver
    except ImportError as exc:  # pragma: no cover - depends on the optional extra
        raise VerificationFailed(name, 'DNS key checks need dnspython: pip install "webagent-protocol[dns]"') from exc
    try:
        answer = await dns.asyncresolver.resolve(name, "TXT")
    except (dns.resolver.NXDOMAIN, dns.resolver.NoAnswer):
        return []
    except dns.exception.DNSException as exc:
        raise VerificationFailed(name, f"DNS lookup failed: {exc}") from exc
    return [b"".join(r.strings).decode("utf-8", "replace") for r in answer]


async def check_dns_key(manifest: AgentManifest, *, required: bool, txt_resolver: TxtResolver | None = None) -> None:
    name = record_name(manifest.domain)
    keys = parse_keys(await (txt_resolver or dnspython_txt)(name))
    if not keys:
        if required:
            raise VerificationFailed(manifest.domain, f"no WAP key published at {name} (DNS key policy: require)")
        return
    if manifest.public_key not in keys:
        raise VerificationFailed(
            manifest.domain,
            f"manifest key {fingerprint(manifest.public_key)} is not among the keys published at {name}",
        )


__all__ = ["TxtResolver", "check_dns_key", "dnspython_txt", "parse_keys", "record_name", "txt_record_for"]
