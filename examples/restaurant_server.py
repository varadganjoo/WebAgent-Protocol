"""Deterministic restaurant tools. No LLM, real customer data or external bookings.

Use create_restaurant() in an existing FastAPI deployment. The demonstration clock is injected.
"""

from __future__ import annotations

import asyncio
import uuid
from collections.abc import Callable
from dataclasses import dataclass, field
from datetime import datetime, timedelta
from typing import Annotated, Literal

from pydantic import AwareDatetime, BaseModel, ConfigDict, Field

from wap.server import ActionContext, WAPServer
from wap.server.app import WAPProtocolError
from wap.spec.discovery import BusinessDiscovery, GeoPoint, ServiceArea
from wap.spec.models import ErrorCode, RateLimitPolicy
from wap.spec.semantics import AVAILABILITY, POLICIES, RESERVATION_CANCEL, RESERVATION_CREATE


class AvailabilityInput(BaseModel):
    model_config = ConfigDict(extra="forbid")
    party_size: Annotated[int, Field(ge=1, le=12, strict=True)]
    start_time: AwareDatetime
    seating: Literal["indoor", "outdoor"] | None = None


class BookingInput(AvailabilityInput):
    seating: Literal["indoor", "outdoor"]


class Reservation(BookingInput):
    reservation_id: str
    status: Literal["confirmed", "cancelled"]


class AvailabilityResult(BaseModel):
    slots: list[BookingInput]


class Policies(BaseModel):
    dietary: str
    accessibility: str


@dataclass
class RestaurantState:
    clock: Callable[[], datetime]
    slot: datetime
    capacities: dict[str, int] = field(default_factory=lambda: {"outdoor": 6, "indoor": 8})
    reservations: dict[str, Reservation] = field(default_factory=dict)
    owners: dict[str, str] = field(default_factory=dict)
    lock: asyncio.Lock = field(default_factory=asyncio.Lock)

    def remaining(self, seating: str) -> int:
        return self.capacities[seating] - sum(
            r.party_size for r in self.reservations.values() if r.status == "confirmed" and r.seating == seating
        )


def create_restaurant(
    domain: str,
    name: str,
    *,
    clock: Callable[[], datetime],
    booking_name: str = "reserve_table",
    minutes: int = 0,
    private_key: str | None = None,
):
    """Return (WAPServer, FastAPI app, state). Production storage must commit bookings durably."""
    tomorrow = clock() + timedelta(days=1)
    slot = tomorrow.replace(hour=19, minute=minutes, second=0, microsecond=0)
    state = RestaurantState(clock=clock, slot=slot)
    server = WAPServer(
        name=name,
        domain=domain,
        private_key=private_key,
        require_pow=True,
        pow_difficulty=2,
        rate_limit=RateLimitPolicy(requests_per_minute=600, burst=100),
        discovery=BusinessDiscovery(
            category="restaurant",
            location=GeoPoint(latitude=-33.8688, longitude=151.2093),
            service_areas=[ServiceArea(country="AU", region="NSW", locality="Sydney")],
            attributes={"outdoor": True},
        ),
    )

    @server.action(
        name="available_tables" if booking_name == "reserve_table" else "find_slots",
        effects="read",
        semantic_operation=AVAILABILITY,
        semantic_schema_version="1.0",
        execution="deterministic",
    )
    async def availability(request: AvailabilityInput) -> AvailabilityResult:
        if request.start_time <= state.clock():
            raise WAPProtocolError(ErrorCode.VALIDATION_ERROR, "start_time must be in the future")
        async with state.lock:
            near_time = abs((state.slot - request.start_time).total_seconds()) <= 1800
            slots = [
                BookingInput(party_size=request.party_size, start_time=state.slot, seating=seating)
                for seating in state.capacities
                if near_time
                and state.remaining(seating) >= request.party_size
                and (request.seating is None or request.seating == seating)
            ]
        return AvailabilityResult(slots=slots)

    @server.action(
        name=booking_name,
        effects="write",
        semantic_operation=RESERVATION_CREATE,
        semantic_schema_version="1.0",
        execution="deterministic",
    )
    async def book(request: BookingInput, ctx: ActionContext) -> Reservation:
        if ctx.message.public_key is None:
            raise WAPProtocolError(ErrorCode.AUTH_REQUIRED, "reservations require a signed WAP request")
        # ASVS V2.3: inventory mutation is atomic; WAP's idempotency store handles duplicate retries.
        async with state.lock:
            if request.start_time != state.slot or request.start_time <= state.clock():
                raise WAPProtocolError(ErrorCode.VALIDATION_ERROR, "requested slot is not offered")
            if state.remaining(request.seating) < request.party_size:
                raise WAPProtocolError(ErrorCode.VALIDATION_ERROR, "requested slot no longer has capacity")
            reservation = Reservation(**request.model_dump(), reservation_id=uuid.uuid4().hex, status="confirmed")
            state.reservations[reservation.reservation_id] = reservation
            state.owners[reservation.reservation_id] = ctx.message.public_key
            return reservation

    @server.action(
        name="cancel_table" if booking_name == "reserve_table" else "cancel_booking",
        effects="write",
        semantic_operation=RESERVATION_CANCEL,
        semantic_schema_version="1.0",
        execution="deterministic",
    )
    async def cancel(
        reservation_id: Annotated[str, Field(min_length=1, max_length=128)], ctx: ActionContext
    ) -> Reservation:
        async with state.lock:
            reservation = state.reservations.get(reservation_id)
            # Ownership is checked against the verified request key, not a caller-supplied customer id.
            if reservation is None or state.owners[reservation_id] != ctx.message.public_key:
                raise WAPProtocolError(ErrorCode.FORBIDDEN, "reservation is unavailable to this caller")
            reservation = reservation.model_copy(update={"status": "cancelled"})
            state.reservations[reservation_id] = reservation
            return reservation

    @server.action(
        name="house_policies",
        effects="read",
        semantic_operation=POLICIES,
        semantic_schema_version="1.0",
        execution="deterministic",
    )
    def policies() -> Policies:
        return Policies(
            dietary="Vegetarian and gluten-free options; shared kitchen, contact staff about allergies.",
            accessibility="Step-free dining room and accessible toilet; outdoor tables have level access.",
        )

    @server.intent
    def no_business_llm(intent: str, ctx: ActionContext):
        raise WAPProtocolError(ErrorCode.UNKNOWN_CAPABILITY, "use an advertised structured capability")

    return server, server.create_app(), state
