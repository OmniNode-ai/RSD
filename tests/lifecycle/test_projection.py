"""Tests for projecting complete event streams."""

from __future__ import annotations

from omninode_rsd.lifecycle.models import LifecycleEventType, LifecycleState
from omninode_rsd.lifecycle.projection import project_events

from .support import event_stream


def test_project_events_handles_failed_work() -> None:
    projection = project_events(event_stream(LifecycleEventType.WORK_FAILED))

    assert projection.state is LifecycleState.FAILED
