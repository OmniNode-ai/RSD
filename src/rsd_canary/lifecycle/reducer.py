"""Pure lifecycle state reduction."""

from __future__ import annotations

from pydantic import ValidationError

from rsd_canary.lifecycle.hashing import (
    advance_event_stream_hash,
    advance_transition_checksum,
    compute_event_hash,
    compute_projection_checksum,
)
from rsd_canary.lifecycle.models import (
    ALLOWED_LIFECYCLE_TRANSITIONS,
    GENESIS_HASH,
    LifecycleEvent,
    LifecycleRunProjection,
    LifecycleState,
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

    validated_projection = _validate_projection(projection)
    validated_event = _validate_event(event)
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


def _validate_projection(projection: LifecycleRunProjection) -> LifecycleRunProjection:
    try:
        values = {
            field_name: getattr(projection, field_name)
            for field_name in LifecycleRunProjection.model_fields
        }
        validated = LifecycleRunProjection.model_validate(values)
    except (AttributeError, ValidationError) as error:
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


def _validate_event(event: LifecycleEvent) -> LifecycleEvent:
    try:
        values = {
            field_name: getattr(event, field_name) for field_name in LifecycleEvent.model_fields
        }
        return LifecycleEvent.model_validate(values)
    except (AttributeError, ValidationError) as error:
        raise LifecycleReductionError("event is not valid") from error


def transition_checksum(events: tuple[LifecycleEvent, ...]) -> str:
    """Calculate a stable checksum for a sequence of lifecycle transitions."""

    checksum = GENESIS_HASH
    for event in events:
        checksum = advance_transition_checksum(checksum, event)
    return checksum
