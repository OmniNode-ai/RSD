"""Tests for append-only event storage."""

from __future__ import annotations

from concurrent.futures import ThreadPoolExecutor
from threading import Barrier, Event
from uuid import UUID

import pytest

from rsd_canary.lifecycle.event_log import InMemoryEventLog
from rsd_canary.lifecycle.hashing import compute_event_hash
from rsd_canary.lifecycle.ingress import LifecycleEventIngress
from rsd_canary.lifecycle.models import (
    GENESIS_HASH,
    LifecycleEvent,
    LifecycleEventIntent,
    LifecycleEventType,
)

from .support import event_stream


def _resign(event: LifecycleEvent) -> LifecycleEvent:
    unsigned = event.model_copy(update={"event_hash": GENESIS_HASH})
    return unsigned.model_copy(update={"event_hash": compute_event_hash(unsigned)})


def _first_event(event_type: LifecycleEventType) -> LifecycleEvent:
    created = LifecycleEventIngress().build(
        LifecycleEventIntent(
            run_id=event_stream()[0].run_id,
            event_type=LifecycleEventType.RUN_CREATED,
            detail="created",
        ),
        sequence=1,
    )
    return _resign(created.model_copy(update={"event_type": event_type}))


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


def test_log_rejects_invalid_first_event_without_storage_mutation() -> None:
    log = InMemoryEventLog()
    event = _first_event(LifecycleEventType.WORK_STARTED)

    with pytest.raises(ValueError, match="current state"):
        log.append(event)

    assert log.events_for(event.run_id) == ()


def test_log_rejects_invalid_transition_after_valid_prefix_without_mutation() -> None:
    log = InMemoryEventLog()
    first, second, *_ = event_stream()
    invalid_second = _resign(
        second.model_copy(update={"event_type": LifecycleEventType.RUN_CREATED})
    )
    log.append(first)

    with pytest.raises(ValueError, match="current state"):
        log.append(invalid_second)

    assert log.events_for(first.run_id) == (first,)


def test_log_rejects_terminal_transition_without_mutation() -> None:
    log = InMemoryEventLog()
    events = event_stream()
    for event in events:
        log.append(event)
    terminal_append = _resign(
        events[-1].model_copy(
            update={
                "sequence": 4,
                "event_id": UUID("00000000-0000-0000-0000-000000000099"),
                "event_type": LifecycleEventType.WORK_FAILED,
                "prior_event_hash": events[-1].event_hash,
            }
        )
    )

    with pytest.raises(ValueError, match="current state"):
        log.append(terminal_append)

    assert log.events_for(events[0].run_id) == events


@pytest.mark.parametrize(
    "last_event", (LifecycleEventType.WORK_COMPLETED, LifecycleEventType.WORK_FAILED)
)
def test_log_accepts_completed_and_failed_streams(last_event: LifecycleEventType) -> None:
    log = InMemoryEventLog()
    events = event_stream(last_event)

    for event in events:
        log.append(event)

    assert log.events_for(events[0].run_id) == events


def test_log_preserves_hash_check_before_sequence_check() -> None:
    log = InMemoryEventLog()
    invalid_event = event_stream()[1].model_copy(update={"event_hash": GENESIS_HASH})

    with pytest.raises(ValueError, match="hash"):
        log.append(invalid_event)

    assert log.events_for(invalid_event.run_id) == ()


@pytest.mark.parametrize("sequence", (True, 1.0))
@pytest.mark.filterwarnings("ignore:Pydantic serializer warnings:UserWarning")
def test_log_rejects_forged_non_integer_sequence_without_mutation(sequence: object) -> None:
    log = InMemoryEventLog()
    event = _resign(event_stream()[0].model_copy(update={"sequence": sequence}))

    with pytest.raises(ValueError, match="event is not valid"):
        log.append(event)

    assert log.events_for(event.run_id) == ()


def test_log_rejects_duplicate_event_id_in_same_run_without_mutation() -> None:
    log = InMemoryEventLog()
    event = event_stream()[0]
    log.append(event)

    with pytest.raises(ValueError, match=r"^event_id is already present$"):
        log.append(event)

    assert log.events_for(event.run_id) == (event,)


def test_log_rejects_duplicate_event_id_across_runs_without_mutation() -> None:
    log = InMemoryEventLog()
    event = event_stream()[0]
    other_run = UUID("00000000-0000-0000-0000-000000000002")
    conflicting_event = _resign(event.model_copy(update={"run_id": other_run}))
    log.append(event)

    with pytest.raises(ValueError, match=r"^event_id is already present$"):
        log.append(conflicting_event)

    assert log.events_for(other_run) == ()


def test_log_rejects_gap_duplicate_sequence_and_wrong_prior_hash_without_mutation() -> None:
    first, second, third = event_stream()
    cases = (
        (third, "contiguous"),
        (_resign(second.model_copy(update={"sequence": 1})), "contiguous"),
        (_resign(second.model_copy(update={"prior_event_hash": GENESIS_HASH})), "prior event"),
    )

    for candidate, message in cases:
        log = InMemoryEventLog()
        log.append(first)

        with pytest.raises(ValueError, match=message):
            log.append(candidate)

        assert log.events_for(first.run_id) == (first,)


@pytest.mark.parametrize(
    "last_event", (LifecycleEventType.WORK_COMPLETED, LifecycleEventType.WORK_FAILED)
)
def test_log_rejects_append_after_either_terminal_state(last_event: LifecycleEventType) -> None:
    log = InMemoryEventLog()
    events = event_stream(last_event)
    for event in events:
        log.append(event)
    candidate = _resign(
        events[-1].model_copy(
            update={
                "sequence": 4,
                "event_id": UUID("00000000-0000-0000-0000-000000000099"),
                "event_type": LifecycleEventType.RUN_CREATED,
                "prior_event_hash": events[-1].event_hash,
            }
        )
    )

    with pytest.raises(ValueError, match="current state"):
        log.append(candidate)

    assert log.events_for(events[0].run_id) == events


def test_log_returns_an_immutable_snapshot() -> None:
    log = InMemoryEventLog()
    first, second, *_ = event_stream()
    log.append(first)
    snapshot = log.events_for(first.run_id)

    log.append(second)

    assert snapshot == (first,)
    assert log.events_for(first.run_id) == (first, second)


def test_log_admits_only_one_concurrent_duplicate_event() -> None:
    log = InMemoryEventLog()
    event = event_stream()[0]
    barrier = Barrier(2)

    def append_once() -> str:
        barrier.wait()
        try:
            log.append(event)
        except ValueError as error:
            return str(error)
        return "accepted"

    with ThreadPoolExecutor(max_workers=2) as executor:
        outcomes = list(executor.map(lambda _: append_once(), range(2)))

    assert sorted(outcomes) == ["accepted", "event_id is already present"]
    assert log.events_for(event.run_id) == (event,)


@pytest.mark.parametrize(
    ("field", "value"),
    (
        ("run_id", "not-a-uuid"),
        ("event_id", "not-a-uuid"),
        ("event_type", "RUN_CREATED"),
        ("occurred_at", "2026-01-01T00:00:00Z"),
        ("prior_event_hash", "not-a-hash"),
        ("event_hash", "not-a-hash"),
    ),
)
@pytest.mark.filterwarnings("ignore:Pydantic serializer warnings:UserWarning")
def test_log_rejects_forged_event_fields_without_mutation(field: str, value: object) -> None:
    log = InMemoryEventLog()
    event = event_stream()[0].model_copy(update={field: value})

    with pytest.raises(ValueError, match=r"^event is not valid$"):
        log.append(event)

    assert log.events_for(event_stream()[0].run_id) == ()


def test_atomic_ingest_recovers_from_duplicate_id_with_stateless_builder() -> None:
    event_ids = iter(
        (
            UUID("00000000-0000-0000-0000-000000000011"),
            UUID("00000000-0000-0000-0000-000000000011"),
            UUID("00000000-0000-0000-0000-000000000012"),
        )
    )
    builder = LifecycleEventIngress(event_id_factory=lambda: next(event_ids))
    log = InMemoryEventLog()
    created_intent = LifecycleEventIntent(
        run_id=UUID("00000000-0000-0000-0000-000000000001"),
        event_type=LifecycleEventType.RUN_CREATED,
        detail="created",
    )
    started_intent = created_intent.model_copy(
        update={"event_type": LifecycleEventType.WORK_STARTED, "detail": "started"}
    )
    first = log.ingest(created_intent, builder)

    with pytest.raises(ValueError, match=r"^event_id is already present$"):
        log.ingest(started_intent, builder)

    second = log.ingest(started_intent, builder)
    assert log.events_for(first.run_id) == (first, second)
    assert second.sequence == 2
    assert second.prior_event_hash == first.event_hash


def test_atomic_ingest_is_thread_safe_across_runs() -> None:
    log = InMemoryEventLog()
    builder = LifecycleEventIngress()
    run_ids = tuple(UUID(int=value) for value in range(1, 17))

    def ingest_created(run_id: UUID) -> LifecycleEvent:
        return log.ingest(
            LifecycleEventIntent(
                run_id=run_id,
                event_type=LifecycleEventType.RUN_CREATED,
                detail="created",
            ),
            builder,
        )

    with ThreadPoolExecutor(max_workers=8) as executor:
        events = tuple(executor.map(ingest_created, run_ids))

    assert all(event.sequence == 1 and event.prior_event_hash == GENESIS_HASH for event in events)
    assert all(log.events_for(event.run_id) == (event,) for event in events)


def test_atomic_ingest_serializes_competing_transitions_for_one_run() -> None:
    log = InMemoryEventLog()
    builder = LifecycleEventIngress()
    run_id = UUID("00000000-0000-0000-0000-000000000001")
    log.ingest(
        LifecycleEventIntent(
            run_id=run_id,
            event_type=LifecycleEventType.RUN_CREATED,
            detail="created",
        ),
        builder,
    )
    barrier = Barrier(2)

    def start_work() -> LifecycleEvent | str:
        barrier.wait()
        try:
            return log.ingest(
                LifecycleEventIntent(
                    run_id=run_id,
                    event_type=LifecycleEventType.WORK_STARTED,
                    detail="started",
                ),
                builder,
            )
        except ValueError as error:
            return str(error)

    with ThreadPoolExecutor(max_workers=2) as executor:
        outcomes = tuple(executor.map(lambda _: start_work(), range(2)))

    accepted = [outcome for outcome in outcomes if isinstance(outcome, LifecycleEvent)]
    assert len(accepted) == 1
    events = log.events_for(run_id)
    assert [event.sequence for event in events] == [1, 2]
    assert events[1].prior_event_hash == events[0].event_hash


def test_atomic_ingest_handles_builder_callback_contention_without_chain_gaps() -> None:
    callback_entered = Event()
    release_callback = Event()
    event_ids = iter(
        (
            UUID("00000000-0000-0000-0000-000000000011"),
            UUID("00000000-0000-0000-0000-000000000012"),
        )
    )

    def event_id() -> UUID:
        value = next(event_ids)
        if value.int == 17:
            callback_entered.set()
            assert release_callback.wait(timeout=2)
        return value

    log = InMemoryEventLog()
    builder = LifecycleEventIngress(event_id_factory=event_id)
    run_id = UUID("00000000-0000-0000-0000-000000000001")
    created = LifecycleEventIntent(
        run_id=run_id,
        event_type=LifecycleEventType.RUN_CREATED,
        detail="created",
    )
    started = created.model_copy(
        update={"event_type": LifecycleEventType.WORK_STARTED, "detail": "started"}
    )

    with ThreadPoolExecutor(max_workers=2) as executor:
        first = executor.submit(log.ingest, created, builder)
        assert callback_entered.wait(timeout=2)
        second = executor.submit(log.ingest, started, builder)
        release_callback.set()
        events = (first.result(timeout=2), second.result(timeout=2))

    assert [event.sequence for event in events] == [1, 2]
    assert events[1].prior_event_hash == events[0].event_hash
