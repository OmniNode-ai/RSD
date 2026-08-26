"""Projection helpers for lifecycle event streams."""

from __future__ import annotations

from uuid import UUID

from rsd_canary.lifecycle.models import LifecycleEvent, LifecycleRunProjection
from rsd_canary.lifecycle.reducer import reduce_lifecycle_event


def empty_projection(run_id: UUID) -> LifecycleRunProjection:
    """Create the initial projection for a run."""

    return LifecycleRunProjection(run_id=run_id)


def project_events(events: tuple[LifecycleEvent, ...]) -> LifecycleRunProjection:
    """Build a projection from a non-empty ordered event tuple."""

    if not events:
        raise ValueError("at least one event is required")
    projection = empty_projection(events[0].run_id)
    for event in events:
        projection = reduce_lifecycle_event(projection, event)
    return projection
