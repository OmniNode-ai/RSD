"""Creation boundary for lifecycle events."""

from __future__ import annotations

from collections.abc import Callable
from datetime import UTC, datetime
from typing import Protocol
from uuid import UUID, uuid4

from rsd_canary.lifecycle.hashing import compute_event_hash
from rsd_canary.lifecycle.models import GENESIS_HASH, LifecycleEvent, LifecycleEventIntent


class SequenceAllocator(Protocol):
    """Assign the next positive sequence number for a run."""

    def next_sequence(self, run_id: UUID) -> int: ...


class InMemorySequenceAllocator:
    """Simple allocator suitable for a single-process application or tests."""

    def __init__(self) -> None:
        self._next_by_run: dict[UUID, int] = {}

    def next_sequence(self, run_id: UUID) -> int:
        sequence = self._next_by_run.get(run_id, 1)
        self._next_by_run[run_id] = sequence + 1
        return sequence


def _utc_now() -> datetime:
    return datetime.now(UTC)


class LifecycleEventIngress:
    """Validate an intent and add identifiers, time, ordering, and its hash."""

    def __init__(
        self,
        sequence_allocator: SequenceAllocator,
        *,
        event_id_factory: Callable[[], UUID] = uuid4,
        clock: Callable[[], datetime] = _utc_now,
    ) -> None:
        self._sequence_allocator = sequence_allocator
        self._event_id_factory = event_id_factory
        self._clock = clock
        self._last_hash_by_run: dict[UUID, str] = {}

    def ingest(self, intent: LifecycleEventIntent | dict[str, object]) -> LifecycleEvent:
        """Produce the next immutable event for an input intent."""

        validated = LifecycleEventIntent.model_validate(intent)
        event_id = self._event_id_factory()
        if not isinstance(event_id, UUID):
            raise TypeError("event_id factory must return a UUID")
        occurred_at = self._clock()
        if occurred_at.tzinfo is None or occurred_at.utcoffset() != UTC.utcoffset(occurred_at):
            raise ValueError("clock must return a UTC timestamp")
        sequence = self._sequence_allocator.next_sequence(validated.run_id)
        if sequence < 1:
            raise ValueError("sequence allocator must return a positive value")
        event = LifecycleEvent(
            event_id=event_id,
            run_id=validated.run_id,
            sequence=sequence,
            occurred_at=occurred_at,
            event_type=validated.event_type,
            detail=validated.detail,
            prior_event_hash=self._last_hash_by_run.get(validated.run_id, GENESIS_HASH),
            event_hash=GENESIS_HASH,
        )
        event = event.model_copy(update={"event_hash": compute_event_hash(event)})
        self._last_hash_by_run[validated.run_id] = event.event_hash
        return event
