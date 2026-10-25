"""Replaceable directory providers. No provider executes business transactions."""

from __future__ import annotations

import asyncio
import time
from collections.abc import Callable
from typing import Protocol

import httpx
from pydantic import ValidationError

from ..client.exceptions import WAPError
from ..client.resolver import parse_target
from ..client.session import WAPClient
from ..spec.models import AgentManifest, normalize_authority
from ..spec.semantics import check_local_schema
from .models import DIRECTORY_PATH, DirectoryEntry, DirectoryPage, DirectoryQuery, matches, project_manifest


class DirectoryError(WAPError):
    def __init__(self, code: str, message: str) -> None:
        self.code = code
        super().__init__(message)


class DirectoryProvider(Protocol):
    async def search(self, query: DirectoryQuery) -> DirectoryPage: ...


def require_network_policy(client: WAPClient) -> None:
    if not client.resolver.block_private_networks:
        raise ValueError("directory discovery requires WAPClient(block_private_networks=True)")


async def canonical_manifest(client: WAPClient, domain: str) -> AgentManifest:
    require_network_policy(client)
    domain = normalize_authority(domain)
    resolved = await client.resolver.resolve_detailed(domain, force_refresh=True)
    manifest = resolved.manifest
    if manifest.domain != domain or resolved.url != parse_target(domain).manifest_url:
        raise DirectoryError("noncanonical", "business must publish its canonical WAP manifest")
    # All later discovery/invocation requests use the same network policy. Check advertised endpoints too.
    for url in [manifest.interaction_url, manifest.challenge_url, manifest.mcp_url]:
        if url:
            await client.resolver._check_dns(parse_target(url))
    for capability in manifest.capabilities:
        check_local_schema(capability.input_schema)
        if capability.output_schema:
            check_local_schema(capability.output_schema)
    return manifest


class MemoryDirectory:
    """Bounded single-process reference index; register/update only from canonical signed manifests."""

    def __init__(
        self,
        client: WAPClient,
        *,
        clock: Callable[[], float] = time.time,
        max_entries: int = 10000,
        max_age: float = 3600,
        timeout: float = 10,
    ) -> None:
        require_network_policy(client)
        if max_entries < 1 or max_age <= 0 or timeout <= 0:
            raise ValueError("directory bounds must be positive")
        self.client, self.clock = client, clock
        self.max_entries, self.max_age, self.timeout = max_entries, max_age, timeout
        self._entries: dict[str, DirectoryEntry] = {}
        self._fetches = asyncio.Semaphore(8)

    async def register(self, domain: str) -> DirectoryEntry:
        try:
            async with asyncio.timeout(self.timeout), self._fetches:
                manifest = await canonical_manifest(self.client, domain)
                entry = project_manifest(manifest, self.clock(), max_age=self.max_age)
        except Exception as exc:  # Untrusted source parsing must not escape the registration boundary.
            raise DirectoryError("registration_failed", "canonical manifest registration failed") from exc
        self._prune()
        if entry.domain not in self._entries and len(self._entries) >= self.max_entries:
            raise DirectoryError("capacity", "directory index is full")
        self._entries[entry.domain] = entry.model_copy(deep=True)
        return entry

    def _prune(self) -> None:
        now = self.clock()
        self._entries = {k: e for k, e in self._entries.items() if e.expires_at > now}

    async def search(self, query: DirectoryQuery) -> DirectoryPage:
        query = DirectoryQuery.model_validate(query.model_dump())
        self._prune()
        entries = [e for _, e in sorted(self._entries.items()) if matches(e, query)]
        selected = []
        size = 0
        for entry in entries[query.offset : query.offset + query.limit]:
            entry_size = len(entry.model_dump_json().encode("utf-8")) + 1
            if size + entry_size > 240000:
                break
            selected.append(entry.model_copy(deep=True))
            size += entry_size
        end = query.offset + len(selected)
        return DirectoryPage(entries=selected, next_offset=end if end < len(entries) else None)


class HTTPDirectory:
    """HTTP adapter for an explicitly configured provider origin; borrows the caller's HTTP client."""

    def __init__(self, origin: str, *, http: httpx.AsyncClient) -> None:
        target = parse_target(origin)
        if origin.rstrip("/") != target.base_url:
            raise ValueError("directory origin must be canonical http(s) origin without a path")
        self.url, self.http = target.base_url + DIRECTORY_PATH + "/search", http

    async def search(self, query: DirectoryQuery) -> DirectoryPage:
        try:
            async with self.http.stream(
                "POST", self.url, json=query.model_dump(mode="json"), follow_redirects=False
            ) as response:
                if response.status_code != 200:
                    raise DirectoryError("http_error", f"directory returned HTTP {response.status_code}")
                body = bytearray()
                async for chunk in response.aiter_bytes():
                    body.extend(chunk)
                    if len(body) > 262144:
                        raise DirectoryError("response_too_large", "directory response exceeds 256 KiB")
            return DirectoryPage.model_validate_json(body)
        except (httpx.HTTPError, ValidationError) as exc:
            raise DirectoryError("invalid_response", "directory request failed or returned invalid metadata") from exc
