"""Pure lifecycle state reduction."""

from __future__ import annotations

from datetime import datetime
from uuid import UUID

from pydantic import ValidationError

from omninode_rsd.lifecycle.hashing import (
    advance_event_stream_hash,
    advance_transition_checksum,
    compute_event_hash,
    compute_projection_checksum,
)
from omninode_rsd.lifecycle.models import (
    ALLOWED_LIFECYCLE_TRANSITIONS,
    GENESIS_HASH,
    LifecycleEvent,
    LifecycleEventType,
    LifecycleRunProjection,
    LifecycleState,
    strict_model_values,
)

_EVENT_FIELD_NAMES = frozenset(LifecycleEvent.model_fields)
_PROJECTION_FIELD_NAMES = frozenset(LifecycleRunProjection.model_fields)
_EVENT_STRING_FIELD_NAMES = frozenset(
    {"schema_version", "detail", "prior_event_hash", "event_hash"}
)
_PROJECTION_STRING_FIELD_NAMES = frozenset(
    {"schema_version", "last_event_hash", "event_stream_hash", "projection_checksum"}
)


class LifecycleReductionError(ValueError):
    """Raised when an event cannot advance a projection."""


def reduce_lifecycle_event(
    projection: LifecycleRunProjection, event: LifecycleEvent
) -> LifecycleRunProjection:
    """Validate a projection, then validate and apply one lifecycle event.

    Projection reconstruction, checksum validation, and lifecycle invariants
    happen before event reconstruction, run matching, and event admission.
    These checks detect materialized-state tampering but do not prove a
    projection corresponds to an event prefix; use replay for that proof.
    """

    validated_projection = validate_lifecycle_projection(projection)
    validated_event = validate_lifecycle_event(event)
    if validated_projection.run_id != validated_event.run_id:
        raise LifecycleReductionError("event does not belong to this run")
    if compute_event_hash(validated_event) != validated_event.event_hash:
        raise LifecycleReductionError("event hash does not match its contents")
    if validated_event.sequence != validated_projection.last_sequence + 1:
        raise LifecycleReductionError("event sequence is not contiguous")
    expected_prior_hash = (
        validated_projection.last_event_hash if validated_projection.last_sequence else GENESIS_HASH
    )
    if validated_event.prior_event_hash != expected_prior_hash:
        raise LifecycleReductionError("event chain does not match the projection")
    target_state = ALLOWED_LIFECYCLE_TRANSITIONS.get(
        (validated_projection.state, validated_event.event_type)
    )
    if target_state is None:
        raise LifecycleReductionError("event is not valid for the current state")
    updated = validated_projection.model_copy(
        update={
            "state": target_state,
            "last_sequence": validated_event.sequence,
            "last_event_hash": validated_event.event_hash,
            "event_stream_hash": advance_event_stream_hash(
                validated_projection.event_stream_hash, validated_event
            ),
        }
    )
    return updated.model_copy(update={"projection_checksum": compute_projection_checksum(updated)})


def validate_lifecycle_projection(projection: LifecycleRunProjection) -> LifecycleRunProjection:
    """Strictly reconstruct and verify one materialized lifecycle projection."""

    try:
        values = strict_model_values(
            projection,
            expected_type=LifecycleRunProjection,
            field_names=_PROJECTION_FIELD_NAMES,
        )
        if values is None:
            raise LifecycleReductionError("projection is not valid")
        if type(values["run_id"]) is not UUID:
            raise LifecycleReductionError("projection is not valid")
        if type(values["state"]) is not LifecycleState:
            raise LifecycleReductionError("projection is not valid")
        if type(values["last_sequence"]) is not int:
            raise LifecycleReductionError("projection is not valid")
        if any(
            type(values[field_name]) is not str for field_name in _PROJECTION_STRING_FIELD_NAMES
        ):
            raise LifecycleReductionError("projection is not valid")
        validated = LifecycleRunProjection.model_validate(values)
    except (AttributeError, KeyError, RuntimeError, TypeError, ValidationError) as error:
        raise LifecycleReductionError("projection is not valid") from error
    if compute_projection_checksum(validated) != validated.projection_checksum:
        raise LifecycleReductionError("projection checksum does not match its contents")
    expected_sequences = {
        LifecycleState.INITIAL: 0,
        LifecycleState.CREATED: 1,
        LifecycleState.ACTIVE: 2,
        LifecycleState.COMPLETED: 3,
        LifecycleState.FAILED: 3,
    }
    if validated.last_sequence != expected_sequences[validated.state]:
        raise LifecycleReductionError("projection is not valid")
    if validated.state is LifecycleState.INITIAL:
        if validated.last_event_hash != GENESIS_HASH or validated.event_stream_hash != GENESIS_HASH:
            raise LifecycleReductionError("projection is not valid")
    elif validated.last_event_hash == GENESIS_HASH or validated.event_stream_hash == GENESIS_HASH:
        raise LifecycleReductionError("projection is not valid")
    return validated


def validate_lifecycle_event(event: LifecycleEvent) -> LifecycleEvent:
    """Strictly reconstruct one lifecycle event at a trust boundary."""

    try:
        values = strict_model_values(
            event,
            expected_type=LifecycleEvent,
            field_names=_EVENT_FIELD_NAMES,
        )
        if values is None:
            raise LifecycleReductionError("event is not valid")
        if type(values["event_id"]) is not UUID or type(values["run_id"]) is not UUID:
            raise LifecycleReductionError("event is not valid")
        if type(values["event_type"]) is not LifecycleEventType:
            raise LifecycleReductionError("event is not valid")
        if type(values["occurred_at"]) is not datetime:
            raise LifecycleReductionError("event is not valid")
        if type(values["sequence"]) is not int:
            raise LifecycleReductionError("event is not valid")
        if any(type(values[field_name]) is not str for field_name in _EVENT_STRING_FIELD_NAMES):
            raise LifecycleReductionError("event is not valid")
        return LifecycleEvent.model_validate(values)
    except (AttributeError, KeyError, RuntimeError, TypeError, ValidationError) as error:
        raise LifecycleReductionError("event is not valid") from error


def transition_checksum(events: tuple[LifecycleEvent, ...]) -> str:
    """Calculate a stable checksum for a sequence of lifecycle transitions."""

    checksum = GENESIS_HASH
    for event in events:
        checksum = advance_transition_checksum(checksum, event)
    return checksum
