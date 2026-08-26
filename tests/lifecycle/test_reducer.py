"""Tests for valid and invalid state transitions."""

from __future__ import annotations

import pytest

from rsd_canary.lifecycle.models import LifecycleState
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
