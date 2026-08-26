"""Shared lifecycle test helpers."""

from __future__ import annotations

from datetime import UTC, datetime, timedelta
from uuid import UUID

from rsd_canary.lifecycle.ingress import InMemorySequenceAllocator, LifecycleEventIngress
from rsd_canary.lifecycle.models import LifecycleEvent, LifecycleEventIntent, LifecycleEventType

RUN_ID = UUID("00000000-0000-0000-0000-000000000001")
EVENT_IDS = (
    UUID("00000000-0000-0000-0000-000000000011"),
    UUID("00000000-0000-0000-0000-000000000012"),
    UUID("00000000-0000-0000-0000-000000000013"),
)


def event_stream(
    last_event: LifecycleEventType = LifecycleEventType.WORK_COMPLETED,
) -> tuple[LifecycleEvent, ...]:
    """Create a deterministic valid stream ending in the requested work event."""

    index = 0

    def event_id() -> UUID:
        nonlocal index
        value = EVENT_IDS[index]
        index += 1
        return value

    clock_value = datetime(2026, 1, 1, tzinfo=UTC)

    def clock() -> datetime:
        nonlocal clock_value
        value = clock_value
        clock_value += timedelta(seconds=1)
        return value

    ingress = LifecycleEventIngress(
        InMemorySequenceAllocator(), event_id_factory=event_id, clock=clock
    )
    event_types = (
        LifecycleEventType.RUN_CREATED,
        LifecycleEventType.WORK_STARTED,
        last_event,
    )
    return tuple(
        ingress.ingest(
            LifecycleEventIntent(run_id=RUN_ID, event_type=event_type, detail=event_type.value)
        )
        for event_type in event_types
    )
