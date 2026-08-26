"""Tests for deterministic replay."""

from __future__ import annotations

from rsd_canary.lifecycle.replay import replay_lifecycle

from .support import event_stream


def test_replay_is_deterministic() -> None:
    events = event_stream()

    assert replay_lifecycle(events) == replay_lifecycle(events)
