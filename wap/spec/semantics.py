"""Optional reference vocabulary. Identifiers are data, never instructions or permissions."""

from __future__ import annotations

from copy import deepcopy
from typing import Any

from .models import EFFECT_RANK, AgentManifest, Capability

RESTAURANT = "hospitality.restaurant."
AVAILABILITY = RESTAURANT + "availability.search.v1"
RESERVATION_CREATE = RESTAURANT + "reservation.create.v1"
RESERVATION_CANCEL = RESTAURANT + "reservation.cancel.v1"
POLICIES = RESTAURANT + "policies.retrieve.v1"


def _object(properties: dict[str, Any], required: list[str]) -> dict[str, Any]:
    return {"type": "object", "properties": properties, "required": required}


_STRING = {"type": "string", "minLength": 1, "maxLength": 256}
_TIME = {"type": "string", "format": "date-time"}
_PARTY = {"type": "integer", "minimum": 1, "maximum": 100}
_BOOKING = {"party_size": _PARTY, "start_time": _TIME, "seating": {"enum": ["indoor", "outdoor"]}}
_ID = {"reservation_id": _STRING}
_RESERVATION = _object(
    {**_ID, **_BOOKING, "status": {"enum": ["confirmed", "cancelled"]}},
    ["reservation_id", "party_size", "start_time", "seating", "status"],
)

_OPERATIONS: dict[str, dict[str, Any]] = {
    AVAILABILITY: {
        "input_schema": _object(_BOOKING, ["party_size", "start_time"]),
        "output_schema": _object({"slots": {"type": "array", "items": _object(_BOOKING, list(_BOOKING))}}, ["slots"]),
    },
    RESERVATION_CREATE: {"input_schema": _object(_BOOKING, list(_BOOKING)), "output_schema": _RESERVATION},
    RESTAURANT + "reservation.modify.v1": {
        "input_schema": _object({**_ID, **_BOOKING}, list(_ID)),
        "output_schema": _RESERVATION,
    },
    RESERVATION_CANCEL: {"input_schema": _object(_ID, list(_ID)), "output_schema": _RESERVATION},
    RESTAURANT + "reservation.retrieve.v1": {"input_schema": _object(_ID, list(_ID)), "output_schema": _RESERVATION},
    POLICIES: {
        "input_schema": _object({}, []),
        "output_schema": _object({"dietary": _STRING, "accessibility": _STRING}, ["dietary", "accessibility"]),
    },
    "retail.inventory.check.v1": {
        "input_schema": _object({"sku": _STRING}, ["sku"]),
        "output_schema": _object({"available": {"type": "integer", "minimum": 0}}, ["available"]),
    },
    "retail.pricing.retrieve.v1": {
        "input_schema": _object({"sku": _STRING}, ["sku"]),
        "output_schema": _object({"amount": _STRING, "currency": _STRING}, ["amount", "currency"]),
    },
    "retail.order.create.v1": {
        "input_schema": _object(
            {
                "items": {
                    "type": "array",
                    "minItems": 1,
                    "items": _object(
                        {"sku": _STRING, "quantity": {"type": "integer", "minimum": 1}}, ["sku", "quantity"]
                    ),
                }
            },
            ["items"],
        ),
        "output_schema": _object({"order_id": _STRING}, ["order_id"]),
    },
    "retail.order.status.retrieve.v1": {
        "input_schema": _object({"order_id": _STRING}, ["order_id"]),
        "output_schema": _object({"status": _STRING}, ["status"]),
    },
    "services.appointment.availability.search.v1": {
        "input_schema": _object({"service": _STRING, "start_time": _TIME}, ["service", "start_time"]),
        "output_schema": _object({"slots": {"type": "array", "items": _TIME}}, ["slots"]),
    },
    "services.appointment.book.v1": {
        "input_schema": _object({"service": _STRING, "start_time": _TIME}, ["service", "start_time"]),
        "output_schema": _object({"appointment_id": _STRING}, ["appointment_id"]),
    },
    "services.appointment.reschedule.v1": {
        "input_schema": _object({"appointment_id": _STRING, "start_time": _TIME}, ["appointment_id", "start_time"]),
        "output_schema": _object({"appointment_id": _STRING, "start_time": _TIME}, ["appointment_id", "start_time"]),
    },
    "services.appointment.cancel.v1": {
        "input_schema": _object({"appointment_id": _STRING}, ["appointment_id"]),
        "output_schema": _object({"status": _STRING}, ["status"]),
    },
}


for _operation in (
    RESERVATION_CREATE,
    RESERVATION_CANCEL,
    RESTAURANT + "reservation.modify.v1",
    "services.appointment.book.v1",
    "services.appointment.reschedule.v1",
    "services.appointment.cancel.v1",
):
    _OPERATIONS[_operation]["minimum_effects"] = "write"
_OPERATIONS["retail.order.create.v1"]["minimum_effects"] = "financial"


def reference_operations() -> dict[str, dict[str, Any]]:
    """Return independent copies of reference input/output schemas, all at semantic schema 1.0.

    Constraints belong in the actual capability schemas. Schema references are never fetched.
    Money amounts are decimal strings, with an explicit currency.
    """
    return deepcopy(_OPERATIONS)


def match_operation(manifest: AgentManifest, operation: str, *, schema_version: str = "1.0") -> list[Capability]:
    """Recognise a known operation/version exactly; otherwise fall back to get_capability/listing.

    A match is a candidate, not proof of substitutability. Always validate actual arguments against
    its business input_schema and inspect effects/auth/constraints before invoking the local id.
    """
    if operation not in _OPERATIONS or schema_version != "1.0":
        return []
    return [
        c
        for c in manifest.capabilities
        if c.semantic_operation == operation
        and c.semantic_schema_version == schema_version
        and EFFECT_RANK[c.effects] >= EFFECT_RANK[_OPERATIONS[operation].get("minimum_effects", "read")]
    ]


def check_local_schema(schema: dict[str, Any]) -> None:
    """Discovery must not turn schema references into network requests or local file reads."""
    pending: list[Any] = [schema]
    while pending:
        value = pending.pop()
        if isinstance(value, dict):
            for key, item in value.items():
                if key in ("$ref", "$dynamicRef") and (not isinstance(item, str) or not item.startswith("#")):
                    raise ValueError("directory/semantic schemas support local fragment references only")
                pending.append(item)
        elif isinstance(value, list):
            pending.extend(value)
