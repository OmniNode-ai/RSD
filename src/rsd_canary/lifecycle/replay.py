"""Replay ordered lifecycle events into a verified projection."""

from __future__ import annotations

from dataclasses import dataclass

from rsd_canary.lifecycle.models import LifecycleEvent, LifecycleRunProjection
from rsd_canary.lifecycle.projection import project_events
from rsd_canary.lifecycle.reducer import transition_checksum


@dataclass(frozen=True)
class LifecycleReplay:
    """Projection and checksum produced from one event stream."""

    projection: LifecycleRunProjection
    replay_checksum: str


def replay_lifecycle(events: tuple[LifecycleEvent, ...]) -> LifecycleReplay:
    """Reduce a non-empty event stream and return its deterministic checksum."""

    projection = project_events(events)
    return LifecycleReplay(projection=projection, replay_checksum=transition_checksum(events))
