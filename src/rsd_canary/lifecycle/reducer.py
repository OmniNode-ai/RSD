"""Pure lifecycle state reduction."""

from __future__ import annotations

from rsd_canary.lifecycle.hashing import (
    advance_event_stream_hash,
    advance_transition_checksum,
    compute_event_hash,
    compute_projection_checksum,
)
from rsd_canary.lifecycle.models import (
    GENESIS_HASH,
    LifecycleEvent,
    LifecycleEventType,
    LifecycleRunProjection,
    LifecycleState,
)


class LifecycleReductionError(ValueError):
    """Raised when an event cannot advance a projection."""


_TRANSITIONS = {
    (LifecycleState.INITIAL, LifecycleEventType.RUN_CREATED): LifecycleState.CREATED,
    (LifecycleState.CREATED, LifecycleEventType.WORK_STARTED): LifecycleState.ACTIVE,
    (LifecycleState.ACTIVE, LifecycleEventType.WORK_COMPLETED): LifecycleState.COMPLETED,
    (LifecycleState.ACTIVE, LifecycleEventType.WORK_FAILED): LifecycleState.FAILED,
}


def reduce_lifecycle_event(
    projection: LifecycleRunProjection, event: LifecycleEvent
) -> LifecycleRunProjection:
    """Validate and apply one event to its current projection."""

    if projection.run_id != event.run_id:
        raise LifecycleReductionError("event does not belong to this run")
    if compute_event_hash(event) != event.event_hash:
        raise LifecycleReductionError("event hash does not match its contents")
    if event.sequence != projection.last_sequence + 1:
        raise LifecycleReductionError("event sequence is not contiguous")
    expected_prior_hash = projection.last_event_hash if projection.last_sequence else GENESIS_HASH
    if event.prior_event_hash != expected_prior_hash:
        raise LifecycleReductionError("event chain does not match the projection")
    target_state = _TRANSITIONS.get((projection.state, event.event_type))
    if target_state is None:
        raise LifecycleReductionError("event is not valid for the current state")
    updated = projection.model_copy(
        update={
            "state": target_state,
            "last_sequence": event.sequence,
            "last_event_hash": event.event_hash,
            "event_stream_hash": advance_event_stream_hash(projection.event_stream_hash, event),
        }
    )
    return updated.model_copy(update={"projection_checksum": compute_projection_checksum(updated)})


def transition_checksum(events: tuple[LifecycleEvent, ...]) -> str:
    """Calculate a stable checksum for a sequence of lifecycle transitions."""

    checksum = GENESIS_HASH
    for event in events:
        checksum = advance_transition_checksum(checksum, event)
    return checksum
