"""A small append-only event-log interface and in-memory implementation."""

from __future__ import annotations

from typing import Protocol
from uuid import UUID

from rsd_canary.lifecycle.hashing import compute_event_hash
from rsd_canary.lifecycle.models import GENESIS_HASH, LifecycleEvent


class LifecycleEventLog(Protocol):
    """Storage surface for ordered lifecycle events."""

    def append(self, event: LifecycleEvent) -> None: ...

    def events_for(self, run_id: UUID) -> tuple[LifecycleEvent, ...]: ...


class InMemoryEventLog:
    """Append-only event log for examples, tests, and local applications."""

    def __init__(self) -> None:
        self._events_by_run: dict[UUID, list[LifecycleEvent]] = {}

    def append(self, event: LifecycleEvent) -> None:
        """Store an event after checking its hash and chain position."""

        if compute_event_hash(event) != event.event_hash:
            raise ValueError("event hash does not match its contents")
        events = self._events_by_run.setdefault(event.run_id, [])
        expected_sequence = len(events) + 1
        expected_prior_hash = events[-1].event_hash if events else GENESIS_HASH
        if event.sequence != expected_sequence:
            raise ValueError("event sequence is not contiguous")
        if event.prior_event_hash != expected_prior_hash:
            raise ValueError("event chain does not match the prior event")
        events.append(event)

    def events_for(self, run_id: UUID) -> tuple[LifecycleEvent, ...]:
        """Return a snapshot of the event stream for one run."""

        return tuple(self._events_by_run.get(run_id, []))
