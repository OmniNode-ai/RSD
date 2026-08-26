"""Typed data structures for a deterministic lifecycle state machine."""

from __future__ import annotations

from datetime import UTC, datetime
from enum import StrEnum
from typing import Annotated, Literal
from uuid import UUID

from pydantic import BaseModel, ConfigDict, Field, model_validator

GENESIS_HASH = "0" * 64
Sha256 = Annotated[str, Field(pattern=r"^[0-9a-f]{64}$")]


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
    sequence: Annotated[int, Field(ge=1)]
    occurred_at: datetime
    event_type: LifecycleEventType
    detail: Annotated[str, Field(min_length=1, max_length=1_000)]
    prior_event_hash: Sha256 = GENESIS_HASH
    event_hash: Sha256

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
    last_sequence: int = 0
    last_event_hash: Sha256 = GENESIS_HASH
    event_stream_hash: Sha256 = GENESIS_HASH
    projection_checksum: Sha256 = GENESIS_HASH
