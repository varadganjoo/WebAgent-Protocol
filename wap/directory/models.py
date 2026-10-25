"""Directory wire format, independent of the WAP transaction protocol."""

from __future__ import annotations

import hashlib
import math
from typing import Annotated, Literal

from pydantic import Field, field_validator, model_validator

from ..client.resolver import parse_target
from ..spec.crypto import canonical_json, fingerprint
from ..spec.discovery import BusinessDiscovery, DiscoveryModel, FilterValue, GeoPoint, Identifier, ServiceArea
from ..spec.models import AgentManifest, Capability, normalize_authority

DIRECTORY_PATH = "/wap-directory/v1"
SemanticId = Annotated[str, Field(max_length=192, pattern=r"^[a-z][a-z0-9_]*(?:\.[a-z][a-z0-9_]*)+\.v[1-9][0-9]*$")]
SchemaVersion = Annotated[str, Field(max_length=24, pattern=r"^[1-9][0-9]*\.[0-9]+$")]


class DirectoryQuery(DiscoveryModel):
    directory_version: Literal["1.0"] = "1.0"
    category: Identifier | None = None
    operation: SemanticId | None = None
    capability_id: Identifier | None = None
    area: ServiceArea | None = None
    near: GeoPoint | None = None
    radius_km: float = Field(default=25, gt=0, le=1000)
    filters: dict[Identifier, FilterValue] = Field(default_factory=dict, max_length=16)
    protocol_versions: list[Literal["1.0", "1.1"]] = Field(
        default_factory=lambda: ["1.0", "1.1"], min_length=1, max_length=2
    )
    semantic_schema_version: SchemaVersion | None = None
    limit: int = Field(default=20, ge=1, le=50)
    offset: int = Field(default=0, ge=0, le=100000)


class IndexedCapability(DiscoveryModel):
    id: Identifier
    semantic_operation: SemanticId | None = None
    semantic_schema_version: SchemaVersion | None = None


class DirectoryEntry(DiscoveryModel):
    domain: str
    name: str = Field(min_length=1, max_length=256)
    manifest_url: str
    protocol_version: Literal["1.0", "1.1"]
    discovery: BusinessDiscovery
    capabilities: list[IndexedCapability] = Field(max_length=256)
    manifest_sha256: str = Field(pattern=r"^[a-f0-9]{64}$")
    public_key_fingerprint: str = Field(pattern=r"^SHA256:[a-f0-9]{32}$")
    indexed_at: float
    manifest_issued_at: float
    expires_at: float
    verification: Literal["canonical-https-signature", "local-development"]

    @field_validator("domain")
    @classmethod
    def _domain(cls, value: str) -> str:
        return normalize_authority(value)

    @field_validator("name")
    @classmethod
    def _label(cls, value: str) -> str:
        if not value.isprintable():
            raise ValueError("business name must be printable")
        return value

    @model_validator(mode="after")
    def _canonical_url(self) -> DirectoryEntry:
        if self.manifest_url != parse_target(self.domain).manifest_url:
            raise ValueError("directory manifest_url must be the canonical domain well-known URL")
        if self.expires_at <= self.indexed_at or self.manifest_issued_at > self.indexed_at + 300:
            raise ValueError("invalid directory freshness interval")
        return self


class DirectoryPage(DiscoveryModel):
    directory_version: Literal["1.0"] = "1.0"
    entries: list[DirectoryEntry] = Field(default_factory=list, max_length=50)
    next_offset: int | None = Field(default=None, ge=0, le=100000)


def project_manifest(manifest: AgentManifest, now: float, *, max_age: float = 3600) -> DirectoryEntry:
    if manifest.discovery is None or manifest.expires_at is None:
        raise ValueError("registration requires discovery metadata and an expiring signed manifest")
    target = parse_target(manifest.domain)
    return DirectoryEntry(
        domain=manifest.domain,
        name=manifest.name,
        manifest_url=target.manifest_url,
        protocol_version=manifest.wap_version,
        discovery=manifest.discovery,
        capabilities=[
            IndexedCapability(
                id=c.id, semantic_operation=c.semantic_operation, semantic_schema_version=c.semantic_schema_version
            )
            for c in manifest.capabilities
        ],
        manifest_sha256=hashlib.sha256(canonical_json(manifest)).hexdigest(),
        public_key_fingerprint=fingerprint(manifest.public_key),
        indexed_at=now,
        manifest_issued_at=manifest.issued_at,
        expires_at=min(manifest.expires_at, now + max_age),
        verification="canonical-https-signature" if target.scheme == "https" else "local-development",
    )


def matching_capabilities(entry: DirectoryEntry, query: DirectoryQuery) -> list[IndexedCapability | Capability]:
    return [
        c
        for c in entry.capabilities
        if (query.operation is None or c.semantic_operation == query.operation)
        and (query.capability_id is None or c.id == query.capability_id)
        and (query.semantic_schema_version is None or c.semantic_schema_version == query.semantic_schema_version)
    ]


def matches(entry: DirectoryEntry, query: DirectoryQuery) -> bool:
    info = entry.discovery
    if query.category and info.category != query.category:
        return False
    if entry.protocol_version not in query.protocol_versions or not matching_capabilities(entry, query):
        return False
    if any(
        info.attributes.get(k) != v or type(info.attributes.get(k)) is not type(v) for k, v in query.filters.items()
    ):
        return False
    if query.area and not any(
        all(
            actual is None or desired is None or actual.casefold() == desired.casefold()
            for key, desired in query.area.model_dump().items()
            for actual in [getattr(area, key)]
        )
        for area in info.service_areas
    ):
        return False
    if query.near:
        if info.location is None:
            return False
        lat1, lat2 = map(math.radians, (query.near.latitude, info.location.latitude))
        delta = math.radians(info.location.longitude - query.near.longitude)
        haversine = math.sin((lat2 - lat1) / 2) ** 2 + math.cos(lat1) * math.cos(lat2) * math.sin(delta / 2) ** 2
        if 6371 * 2 * math.asin(math.sqrt(min(1, haversine))) > query.radius_km:
            return False
    return True
