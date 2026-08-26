"""A small append-only event-log interface and in-memory implementation."""

from __future__ import annotations

from threading import RLock
from typing import Protocol
from uuid import UUID

from pydantic import ValidationError

from rsd_canary.lifecycle.hashing import compute_event_hash
from rsd_canary.lifecycle.ingress import LifecycleEventIngress
from rsd_canary.lifecycle.models import (
    ALLOWED_LIFECYCLE_TRANSITIONS,
    GENESIS_HASH,
    LifecycleEvent,
    LifecycleEventIntent,
    LifecycleState,
)


class LifecycleEventLog(Protocol):
    """Storage surface for ordered lifecycle events."""

    def append(self, event: LifecycleEvent) -> None: ...

    def ingest(
        self, intent: LifecycleEventIntent | dict[str, object], builder: LifecycleEventIngress
    ) -> LifecycleEvent: ...

    def events_for(self, run_id: UUID) -> tuple[LifecycleEvent, ...]: ...


class InMemoryEventLog:
    """Append-only event log for examples, tests, and local applications."""

    def __init__(self) -> None:
        self._events_by_run: dict[UUID, list[LifecycleEvent]] = {}
        self._event_ids: set[UUID] = set()
        self._lock = RLock()

    def append(self, event: LifecycleEvent) -> None:
        """Store an event after checking integrity, order, and state transition."""

        with self._lock:
            self._append_validated(event)

    def ingest(
        self, intent: LifecycleEventIntent | dict[str, object], builder: LifecycleEventIngress
    ) -> LifecycleEvent:
        """Atomically construct and append an event using this log's run authority.

        Builder callbacks execute while this log's reentrant lock is held so its
        identifier, timestamp, and resulting event are admitted atomically.
        """

        validated_intent = LifecycleEventIntent.model_validate(intent)
        with self._lock:
            events = self._events_by_run.get(validated_intent.run_id, [])
            current_state = self._current_state(events)
            if (current_state, validated_intent.event_type) not in ALLOWED_LIFECYCLE_TRANSITIONS:
                raise ValueError("event is not valid for the current state")
            expected_sequence = len(events) + 1
            expected_prior_hash = events[-1].event_hash if events else GENESIS_HASH
            event = builder.build(
                validated_intent,
                sequence=expected_sequence,
                prior_event_hash=expected_prior_hash,
            )
            self._append_validated(event)
            return event

    def _append_validated(self, event: LifecycleEvent) -> None:
        validated_event = self._validate_event(event)
        if compute_event_hash(validated_event) != validated_event.event_hash:
            raise ValueError("event hash does not match its contents")
        if validated_event.event_id in self._event_ids:
            raise ValueError("event_id is already present")
        events = self._events_by_run.get(validated_event.run_id, [])
        expected_sequence = len(events) + 1
        expected_prior_hash = events[-1].event_hash if events else GENESIS_HASH
        if validated_event.sequence != expected_sequence:
            raise ValueError("event sequence is not contiguous")
        if validated_event.prior_event_hash != expected_prior_hash:
            raise ValueError("event chain does not match the prior event")
        current_state = self._current_state(events)
        if (current_state, validated_event.event_type) not in ALLOWED_LIFECYCLE_TRANSITIONS:
            raise ValueError("event is not valid for the current state")
        self._events_by_run.setdefault(validated_event.run_id, []).append(validated_event)
        self._event_ids.add(validated_event.event_id)

    @staticmethod
    def _validate_event(event: LifecycleEvent) -> LifecycleEvent:
        try:
            values = {
                field_name: getattr(event, field_name) for field_name in LifecycleEvent.model_fields
            }
            return LifecycleEvent.model_validate(values)
        except (AttributeError, ValidationError) as error:
            raise ValueError("event is not valid") from error

    @staticmethod
    def _current_state(events: list[LifecycleEvent]) -> LifecycleState:
        current_state = LifecycleState.INITIAL
        for stored_event in events:
            next_state = ALLOWED_LIFECYCLE_TRANSITIONS.get((current_state, stored_event.event_type))
            if next_state is None:
                raise ValueError("stored event stream has an invalid lifecycle transition")
            current_state = next_state
        return current_state

    def events_for(self, run_id: UUID) -> tuple[LifecycleEvent, ...]:
        """Return a snapshot of the event stream for one run."""

        with self._lock:
            return tuple(self._events_by_run.get(run_id, []))
