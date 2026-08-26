"""Typed data structures for a deterministic lifecycle state machine."""

from __future__ import annotations

from collections.abc import Mapping
from datetime import UTC, datetime
from enum import StrEnum
from types import MappingProxyType
from typing import Annotated, Literal
from uuid import UUID

from pydantic import BaseModel, ConfigDict, Field, model_validator

GENESIS_HASH = "0" * 64
Sha256 = Annotated[str, Field(pattern=r"^[0-9a-f]{64}$")]
PositiveSequence = Annotated[int, Field(strict=True, ge=1)]


class Model(BaseModel):
    """Base model that rejects unrecognized fields."""

    model_config = ConfigDict(extra="forbid", frozen=True)


class LifecycleState(StrEnum):
    """Possible states for one run."""

    INITIAL = "INITIAL"
    CREATED = "CREATED"
    ACTIVE = "ACTIVE"
    COMPLETED = "COMPLETED"
    FAILED = "FAILED"


class LifecycleEventType(StrEnum):
    """Events accepted by the public state machine."""

    RUN_CREATED = "RUN_CREATED"
    WORK_STARTED = "WORK_STARTED"
    WORK_COMPLETED = "WORK_COMPLETED"
    WORK_FAILED = "WORK_FAILED"


class LifecycleTransition(Model):
    """One permitted event-driven lifecycle transition."""

    event_type: LifecycleEventType
    source_state: LifecycleState
    target_state: LifecycleState


class LifecycleDescription(Model):
    """Typed representation of the public lifecycle-description document."""

    schema_version: Literal["rsd.lifecycle-description.v1"]
    states: tuple[LifecycleState, ...]
    transitions: tuple[LifecycleTransition, ...]


ALLOWED_LIFECYCLE_TRANSITIONS: Mapping[
    tuple[LifecycleState, LifecycleEventType], LifecycleState
] = MappingProxyType(
    {
        (LifecycleState.INITIAL, LifecycleEventType.RUN_CREATED): LifecycleState.CREATED,
        (LifecycleState.CREATED, LifecycleEventType.WORK_STARTED): LifecycleState.ACTIVE,
        (LifecycleState.ACTIVE, LifecycleEventType.WORK_COMPLETED): LifecycleState.COMPLETED,
        (LifecycleState.ACTIVE, LifecycleEventType.WORK_FAILED): LifecycleState.FAILED,
    }
)


class LifecycleEventIntent(Model):
    """Caller-supplied portion of a new lifecycle event."""

    run_id: UUID
    event_type: LifecycleEventType
    detail: Annotated[str, Field(min_length=1, max_length=1_000)]


class LifecycleEvent(Model):
    """Immutable event with ordering and integrity fields assigned at ingress."""

    schema_version: Literal["rsd.lifecycle-event.v1"] = "rsd.lifecycle-event.v1"
    event_id: UUID
    run_id: UUID
    sequence: PositiveSequence
    occurred_at: datetime
    event_type: LifecycleEventType
    detail: Annotated[str, Field(min_length=1, max_length=1_000)]
    prior_event_hash: Sha256 = GENESIS_HASH
    event_hash: Sha256

    model_config = ConfigDict(extra="forbid", frozen=True, strict=True)

    @model_validator(mode="after")
    def timestamp_is_utc(self) -> LifecycleEvent:
        if self.occurred_at.tzinfo is None:
            raise ValueError("occurred_at must include a timezone")
        if self.occurred_at.utcoffset() != UTC.utcoffset(self.occurred_at):
            raise ValueError("occurred_at must use UTC")
        return self


class LifecycleRunProjection(Model):
    """Current state produced by reducing an ordered event stream."""

    schema_version: Literal["rsd.lifecycle-projection.v1"] = "rsd.lifecycle-projection.v1"
    run_id: UUID
    state: LifecycleState = LifecycleState.INITIAL
    last_sequence: Annotated[int, Field(strict=True, ge=0)] = 0
    last_event_hash: Sha256 = GENESIS_HASH
    event_stream_hash: Sha256 = GENESIS_HASH
    projection_checksum: Sha256 = GENESIS_HASH

    model_config = ConfigDict(extra="forbid", frozen=True, strict=True)
