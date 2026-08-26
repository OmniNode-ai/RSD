"""Tests for valid and invalid state transitions."""

from __future__ import annotations

import pytest

from rsd_canary.lifecycle.hashing import compute_event_hash, compute_projection_checksum
from rsd_canary.lifecycle.models import (
    GENESIS_HASH,
    LifecycleEventType,
    LifecycleState,
)
from rsd_canary.lifecycle.projection import empty_projection
from rsd_canary.lifecycle.reducer import LifecycleReductionError, reduce_lifecycle_event

from .support import event_stream


def test_reducer_reaches_completed_state() -> None:
    events = event_stream()
    projection = empty_projection(events[0].run_id)
    for event in events:
        projection = reduce_lifecycle_event(projection, event)

    assert projection.state is LifecycleState.COMPLETED
    assert projection.last_sequence == 3


def test_reducer_rejects_invalid_first_event() -> None:
    event = event_stream()[1]
    with pytest.raises(LifecycleReductionError, match="contiguous"):
        reduce_lifecycle_event(empty_projection(event.run_id), event)


def test_reducer_rejects_forged_projection_before_reduction() -> None:
    event = event_stream()[0]
    forged_projection = empty_projection(event.run_id).model_copy(update={"last_sequence": True})

    with pytest.raises(LifecycleReductionError, match=r"^projection is not valid$"):
        reduce_lifecycle_event(forged_projection, event)


def test_reducer_rejects_forged_projection_checksum_type() -> None:
    event = event_stream()[0]
    forged_projection = empty_projection(event.run_id).model_copy(
        update={"projection_checksum": "not-a-hash"}
    )

    with pytest.raises(LifecycleReductionError, match=r"^projection is not valid$"):
        reduce_lifecycle_event(forged_projection, event)


def test_empty_projection_has_a_canonical_checksum() -> None:
    projection = empty_projection(event_stream()[0].run_id)

    assert projection.projection_checksum == compute_projection_checksum(projection)


def test_reducer_rejects_stale_projection_checksum_before_event_matching() -> None:
    event = event_stream()[0]
    stale_projection = empty_projection(event.run_id).model_copy(
        update={"projection_checksum": GENESIS_HASH}
    )

    with pytest.raises(
        LifecycleReductionError, match=r"^projection checksum does not match its contents$"
    ):
        reduce_lifecycle_event(stale_projection, event)


@pytest.mark.parametrize(
    "updates",
    (
        {"state": LifecycleState.CREATED},
        {"state": LifecycleState.CREATED, "last_sequence": 1},
    ),
)
def test_reducer_rejects_recomputed_checksum_with_incoherent_projection_state(
    updates: dict[str, object],
) -> None:
    event = event_stream()[0]
    forged_projection = empty_projection(event.run_id).model_copy(update=updates)
    forged_projection = forged_projection.model_copy(
        update={"projection_checksum": compute_projection_checksum(forged_projection)}
    )

    with pytest.raises(LifecycleReductionError, match=r"^projection is not valid$"):
        reduce_lifecycle_event(forged_projection, event)


@pytest.mark.parametrize(
    "last_event", (LifecycleEventType.WORK_COMPLETED, LifecycleEventType.WORK_FAILED)
)
def test_reducer_results_have_valid_checksums(last_event: LifecycleEventType) -> None:
    events = event_stream(last_event)
    projection = empty_projection(events[0].run_id)

    for event in events:
        projection = reduce_lifecycle_event(projection, event)
        assert projection.projection_checksum == compute_projection_checksum(projection)

    unsigned_terminal_event = events[-1].model_copy(
        update={
            "sequence": projection.last_sequence + 1,
            "event_type": LifecycleEventType.RUN_CREATED,
            "prior_event_hash": projection.last_event_hash,
            "event_hash": GENESIS_HASH,
        }
    )
    terminal_event = unsigned_terminal_event.model_copy(
        update={"event_hash": compute_event_hash(unsigned_terminal_event)}
    )
    with pytest.raises(LifecycleReductionError, match="current state"):
        reduce_lifecycle_event(projection, terminal_event)
