"""Public, signed business discovery metadata; never customer or transaction data."""

from __future__ import annotations

from typing import Annotated, Literal

from pydantic import BaseModel, ConfigDict, Field, field_validator

Identifier = Annotated[str, Field(pattern=r"^[a-z][a-z0-9_.-]{0,95}$")]
AreaName = Annotated[str, Field(min_length=1, max_length=80, pattern=r"^[\w .'-]+$")]
FilterValue = bool | Annotated[str, Field(min_length=1, max_length=80, pattern=r"^[a-z0-9_. -]+$")]


class DiscoveryModel(BaseModel):
    model_config = ConfigDict(extra="forbid", allow_inf_nan=False)


class GeoPoint(DiscoveryModel):
    latitude: float = Field(ge=-90, le=90)
    longitude: float = Field(ge=-180, le=180)


class ServiceArea(DiscoveryModel):
    country: str = Field(pattern=r"^[A-Z]{2}$")
    region: AreaName | None = None
    locality: AreaName | None = None
    postal_code: AreaName | None = None


class BusinessDiscovery(DiscoveryModel):
    schema_version: Literal["1.0"] = "1.0"
    category: Identifier
    location: GeoPoint | None = None
    service_areas: list[ServiceArea] = Field(default_factory=list, max_length=32)
    attributes: dict[Identifier, FilterValue] = Field(default_factory=dict, max_length=32)

    @field_validator("attributes")
    @classmethod
    def _public_attributes(cls, value: dict) -> dict:
        # ASVS V2.2: no free-form secrets or user-specific filters in a public index.
        reserved = {"password", "token", "secret", "email", "customer", "authorization", "address", "phone"}
        if any(key in reserved for key in value):
            raise ValueError("attributes must contain public business characteristics only")
        return value
