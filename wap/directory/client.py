"""Federated search followed by canonical business verification and authoritative filtering."""

from __future__ import annotations

import asyncio
import time
from collections.abc import Callable, Mapping
from dataclasses import dataclass, field

import httpx

from ..client.exceptions import WAPError
from ..client.session import WAPClient
from ..spec.models import AgentManifest
from .models import DirectoryPage, DirectoryQuery, matches, project_manifest
from .providers import DirectoryError, DirectoryProvider, canonical_manifest, require_network_policy


@dataclass
class VerifiedBusiness:
    manifest: AgentManifest
    sources: list[str] = field(default_factory=list)


@dataclass
class BusinessSearchResult:
    businesses: list[VerifiedBusiness] = field(default_factory=list)
    next_offsets: dict[str, int] = field(default_factory=dict)
    errors: dict[str, str] = field(default_factory=dict)


class DirectoryClient:
    def __init__(
        self,
        client: WAPClient,
        providers: Mapping[str, DirectoryProvider],
        *,
        timeout: float = 10,
        allow_domain: Callable[[str], bool] | None = None,
    ) -> None:
        require_network_policy(client)
        if not 1 <= len(providers) <= 8 or timeout <= 0:
            raise ValueError("configure 1-8 directory providers and a positive timeout")
        self.client, self.providers, self.timeout = client, dict(providers), timeout
        self.allow_domain = allow_domain

    async def search(self, query: DirectoryQuery) -> BusinessSearchResult:
        query = DirectoryQuery.model_validate(query.model_dump())
        result = BusinessSearchResult()
        verified: dict[str, VerifiedBusiness] = {}
        fetched: dict[str, AgentManifest] = {}

        async def page_for(provider: DirectoryProvider) -> DirectoryPage | Exception:
            try:
                async with asyncio.timeout(self.timeout):
                    page = await provider.search(query)
                    return DirectoryPage.model_validate(page.model_dump() if isinstance(page, DirectoryPage) else page)
            except (WAPError, ValueError, httpx.HTTPError, TimeoutError) as exc:
                return exc
            except Exception:
                return DirectoryError("provider_error", "directory provider failed")

        pages = await asyncio.gather(*(page_for(p) for p in self.providers.values()))
        deadline = asyncio.get_running_loop().time() + self.timeout
        for (name, _), page in zip(self.providers.items(), pages, strict=True):
            if isinstance(page, Exception):
                result.errors[name] = (
                    "timeout" if isinstance(page, TimeoutError) else getattr(page, "code", "invalid_response")
                )
                continue
            if len(page.entries) > query.limit or (page.next_offset is not None and page.next_offset <= query.offset):
                result.errors[name] = "invalid_pagination"
                continue
            if page.next_offset is not None:
                result.next_offsets[name] = page.next_offset
            for entry in page.entries:
                key = f"{name}:{entry.domain}"
                if self.allow_domain is not None and not self.allow_domain(entry.domain):
                    result.errors[key] = "domain_not_allowed"
                    continue
                if entry.expires_at <= time.time() or entry.indexed_at > time.time() + 300:
                    result.errors[key] = "stale"
                    continue
                try:
                    async with asyncio.timeout_at(deadline):
                        manifest = fetched.get(entry.domain)
                        if manifest is None:
                            manifest = fetched[entry.domain] = await canonical_manifest(self.client, entry.domain)
                        current = project_manifest(manifest, time.time())
                    if not matches(current, query):
                        result.errors[key] = "no_longer_matches"
                        continue
                except Exception:  # Isolate malformed sources as well as network/verification errors.
                    result.errors[key] = "verification_failed"
                    continue
                if entry.domain not in verified:
                    verified[entry.domain] = VerifiedBusiness(manifest=manifest)
                if name not in verified[entry.domain].sources:
                    verified[entry.domain].sources.append(name)
        result.businesses = list(verified.values())
        return result
