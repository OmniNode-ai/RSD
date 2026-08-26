"""Tests for append-only event storage."""

from __future__ import annotations

import pytest

from rsd_canary.lifecycle.event_log import InMemoryEventLog

from .support import event_stream


def test_log_returns_events_in_append_order() -> None:
    log = InMemoryEventLog()
    events = event_stream()
    for event in events:
        log.append(event)

    assert log.events_for(events[0].run_id) == events


def test_log_rejects_out_of_order_event() -> None:
    log = InMemoryEventLog()
    events = event_stream()

    with pytest.raises(ValueError, match="contiguous"):
        log.append(events[1])
