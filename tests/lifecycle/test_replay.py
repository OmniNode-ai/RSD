"""Tests for deterministic replay and replay-artifact verification."""

from __future__ import annotations

from dataclasses import dataclass, replace
from datetime import timedelta
from uuid import UUID

import pytest

from omninode_rsd.lifecycle.hashing import compute_event_hash, compute_projection_checksum
from omninode_rsd.lifecycle.models import (
    GENESIS_HASH,
    LifecycleEvent,
    LifecycleEventType,
    LifecycleState,
)
from omninode_rsd.lifecycle.replay import (
    LifecycleReplay,
    LifecycleReplayArtifactError,
    LifecycleReplayInputError,
    LifecycleReplayMismatchError,
    LifecycleReplayRunMismatchError,
    replay_lifecycle,
    verify_lifecycle_replay,
)

from .support import event_stream


@dataclass(frozen=True)
class _FakeReplay:
    projection: object
    replay_checksum: object


class _ReplaySubclass(LifecycleReplay):
    """Subclass that must not be treated as the exact replay artifact."""


class _EvilStr(str):
    def __eq__(self, other: object) -> bool:
        raise RuntimeError("checksum equality must not run")

    def __ne__(self, other: object) -> bool:
        raise RuntimeError("checksum inequality must not run")


class _EvilUUID(UUID):
    def __eq__(self, other: object) -> bool:
        raise RuntimeError("UUID equality must not run")

    def __hash__(self) -> int:
        raise RuntimeError("UUID hashing must not run")


class _HostileTuple(tuple[LifecycleEvent, ...]):
    def __iter__(self) -> object:
        raise RuntimeError("tuple iteration must not run")

    def __len__(self) -> int:
        raise RuntimeError("tuple length must not run")

    def __getitem__(self, index: object) -> object:
        raise RuntimeError("tuple indexing must not run")


class _HostileList(list[LifecycleEvent]):
    def __iter__(self) -> object:
        raise RuntimeError("list iteration must not run")

    def __len__(self) -> int:
        raise RuntimeError("list length must not run")

    def __getitem__(self, index: object) -> object:
        raise RuntimeError("list indexing must not run")


def _resign(event: LifecycleEvent) -> LifecycleEvent:
    unsigned = event.model_copy(update={"event_hash": GENESIS_HASH})
    return unsigned.model_copy(update={"event_hash": compute_event_hash(unsigned)})


def test_replay_is_deterministic() -> None:
    events = event_stream()

    assert replay_lifecycle(events) == replay_lifecycle(events)


def test_verifier_accepts_canonical_artifact_and_list_snapshot_without_mutation() -> None:
    events = event_stream()
    event_list = list(events)
    replay = replay_lifecycle(events)

    assert verify_lifecycle_replay(event_list, replay) is None
    assert event_list == list(events)
    assert replay == replay_lifecycle(events)


def test_verifier_accepts_exact_tuple_snapshot_without_mutation() -> None:
    events = event_stream()
    replay = replay_lifecycle(events)

    assert type(events) is tuple
    assert verify_lifecycle_replay(events, replay) is None
    assert events == event_stream()


@pytest.mark.parametrize(
    "last_event", (LifecycleEventType.WORK_COMPLETED, LifecycleEventType.WORK_FAILED)
)
def test_verifier_accepts_both_terminal_artifacts(last_event: LifecycleEventType) -> None:
    events = event_stream(last_event)

    verify_lifecycle_replay(events, replay_lifecycle(events))


def test_verifier_rejects_empty_input() -> None:
    with pytest.raises(LifecycleReplayInputError, match=r"^replay input must not be empty$"):
        verify_lifecycle_replay((), replay_lifecycle(event_stream()))


@pytest.mark.parametrize("events", ((event for event in ()), set()))
def test_verifier_rejects_non_snapshot_containers(events: object) -> None:
    with pytest.raises(LifecycleReplayInputError, match=r"^replay input must be a tuple or list$"):
        verify_lifecycle_replay(events, replay_lifecycle(event_stream()))  # type: ignore[arg-type]


@pytest.mark.parametrize("container", (_HostileTuple, _HostileList))
def test_verifier_rejects_container_subclasses_before_callbacks(
    container: type[tuple[LifecycleEvent, ...]] | type[list[LifecycleEvent]],
) -> None:
    hostile_events = container(event_stream())

    with pytest.raises(LifecycleReplayInputError, match=r"^replay input must be a tuple or list$"):
        verify_lifecycle_replay(hostile_events, replay_lifecycle(event_stream()))


def test_verifier_rejects_non_artifact_before_inspecting_events() -> None:
    with pytest.raises(LifecycleReplayArtifactError, match=r"^replay artifact is not valid$"):
        verify_lifecycle_replay([], object())  # type: ignore[arg-type]


def test_verifier_rejects_fake_and_subclass_artifacts_before_input_access() -> None:
    events = event_stream()
    replay = replay_lifecycle(events)
    subclass = _ReplaySubclass(replay.projection, replay.replay_checksum)

    for artifact in (_FakeReplay(replay.projection, replay.replay_checksum), subclass):
        with pytest.raises(LifecycleReplayArtifactError, match=r"^replay artifact is not valid$"):
            verify_lifecycle_replay(events, artifact)  # type: ignore[arg-type]


@pytest.mark.parametrize(
    ("events", "message"),
    (
        (lambda: tuple(reversed(event_stream())), "event sequence is not contiguous"),
        (lambda: (event_stream()[0], event_stream()[2]), "event sequence is not contiguous"),
    ),
)
def test_verifier_maps_reordered_and_dropped_events_to_input_errors(
    events: object, message: str
) -> None:
    stream = events()  # type: ignore[operator]

    with pytest.raises(LifecycleReplayInputError, match=message):
        verify_lifecycle_replay(stream, replay_lifecycle(event_stream()))


def test_verifier_rejects_mixed_run_input() -> None:
    first, second, third = event_stream()
    mixed_second = _resign(second.model_copy(update={"run_id": UUID(int=2)}))

    with pytest.raises(LifecycleReplayInputError, match="event does not belong"):
        verify_lifecycle_replay((first, mixed_second, third), replay_lifecycle(event_stream()))


def test_verifier_rejects_duplicate_event_id_before_replay() -> None:
    first, second, third = event_stream()
    duplicate_second = _resign(second.model_copy(update={"event_id": first.event_id}))

    with pytest.raises(LifecycleReplayInputError, match="event_id is duplicated"):
        verify_lifecycle_replay((first, duplicate_second, third), replay_lifecycle(event_stream()))


@pytest.mark.filterwarnings("ignore:Pydantic serializer warnings:UserWarning")
def test_verifier_rejects_evil_uuid_before_run_comparison_or_event_id_set_use() -> None:
    first, second, third = event_stream()
    foreign_run = second.model_copy(
        update={"run_id": _EvilUUID("00000000-0000-0000-0000-000000000002")}
    )
    duplicate_id = second.model_copy(update={"event_id": _EvilUUID(str(first.event_id))})

    for forged in (foreign_run, duplicate_id):
        with pytest.raises(
            LifecycleReplayInputError, match=r"^replay input is not valid: event is not valid$"
        ):
            verify_lifecycle_replay((first, forged, third), replay_lifecycle(event_stream()))


def test_verifier_maps_resigned_hash_content_tampering_to_input_error() -> None:
    events = event_stream()
    tampered = events[0].model_copy(update={"detail": "tampered"})

    with pytest.raises(LifecycleReplayInputError, match="event hash does not match"):
        verify_lifecycle_replay((tampered, *events[1:]), replay_lifecycle(events))


@pytest.mark.parametrize(
    ("field", "value"),
    (
        ("run_id", "not-a-uuid"),
        ("event_id", "not-a-uuid"),
        ("event_type", "RUN_CREATED"),
        ("occurred_at", "2026-01-01T00:00:00Z"),
        ("event_hash", "not-a-hash"),
    ),
)
def test_verifier_rejects_forged_event_model_fields(field: str, value: object) -> None:
    events = event_stream()
    forged = events[0].model_copy(update={field: value})

    with pytest.raises(
        LifecycleReplayInputError, match=r"^replay input is not valid: event is not valid$"
    ):
        verify_lifecycle_replay((forged, *events[1:]), replay_lifecycle(events))


def test_verifier_rejects_string_subclass_at_event_trust_boundary() -> None:
    events = event_stream()
    forged = events[0].model_copy(update={"event_hash": _EvilStr(events[0].event_hash)})

    with pytest.raises(LifecycleReplayInputError, match=r"^replay input is not valid:"):
        verify_lifecycle_replay((forged, *events[1:]), replay_lifecycle(events))


def test_verifier_rejects_timestamp_only_resigned_event_tampering() -> None:
    first, second, third = event_stream()
    changed_second = _resign(
        second.model_copy(update={"occurred_at": second.occurred_at + timedelta(1)})
    )
    changed_third = _resign(
        third.model_copy(update={"prior_event_hash": changed_second.event_hash})
    )
    changed_events = (first, changed_second, changed_third)

    assert (
        replay_lifecycle(changed_events).replay_checksum
        == replay_lifecycle((first, second, third)).replay_checksum
    )
    with pytest.raises(LifecycleReplayMismatchError, match="replay projection"):
        verify_lifecycle_replay(changed_events, replay_lifecycle((first, second, third)))


def test_verifier_rejects_stale_shorter_and_tampered_projections() -> None:
    events = event_stream()
    replay = replay_lifecycle(events)
    stale_projection = replay.projection.model_copy(update={"projection_checksum": GENESIS_HASH})
    shorter_replay = replay_lifecycle(events[:2])
    tampered_projection = replay.projection.model_copy(update={"state": LifecycleState.FAILED})
    tampered_projection = tampered_projection.model_copy(
        update={"projection_checksum": compute_projection_checksum(tampered_projection)}
    )

    with pytest.raises(
        LifecycleReplayArtifactError,
        match=r"^replay artifact is not valid: projection checksum does not match its contents$",
    ):
        verify_lifecycle_replay(events, replace(replay, projection=stale_projection))
    with pytest.raises(LifecycleReplayMismatchError, match="replay projection"):
        verify_lifecycle_replay(events, shorter_replay)
    with pytest.raises(LifecycleReplayMismatchError, match="replay projection"):
        verify_lifecycle_replay(events, replace(replay, projection=tampered_projection))


def test_verifier_rejects_forged_artifact_projection_field() -> None:
    events = event_stream()

    with pytest.raises(LifecycleReplayArtifactError, match="replay artifact is not valid"):
        verify_lifecycle_replay(
            events,
            replace(replay_lifecycle(events), projection=object()),  # type: ignore[arg-type]
        )


def test_verifier_rejects_recomputed_but_incoherent_projection() -> None:
    events = event_stream()
    replay = replay_lifecycle(events)
    incoherent_projection = replay.projection.model_copy(update={"state": LifecycleState.CREATED})
    incoherent_projection = incoherent_projection.model_copy(
        update={"projection_checksum": compute_projection_checksum(incoherent_projection)}
    )

    with pytest.raises(LifecycleReplayArtifactError, match="projection is not valid"):
        verify_lifecycle_replay(events, replace(replay, projection=incoherent_projection))


@pytest.mark.parametrize("checksum", ("not-a-hash", "A" * 64))
def test_verifier_rejects_noncanonical_artifact_checksums(checksum: str) -> None:
    events = event_stream()

    with pytest.raises(
        LifecycleReplayArtifactError,
        match=r"^replay artifact checksum is not a lowercase SHA-256 digest$",
    ):
        verify_lifecycle_replay(events, replace(replay_lifecycle(events), replay_checksum=checksum))


def test_verifier_rejects_checksum_string_subclass_before_comparison() -> None:
    events = event_stream()
    replay = replace(
        replay_lifecycle(events), replay_checksum=_EvilStr(replay_lifecycle(events).replay_checksum)
    )

    with pytest.raises(
        LifecycleReplayArtifactError,
        match=r"^replay artifact checksum is not a lowercase SHA-256 digest$",
    ):
        verify_lifecycle_replay(events, replay)


def test_verifier_rejects_valid_but_mismatched_artifact_checksum() -> None:
    events = event_stream()

    with pytest.raises(
        LifecycleReplayMismatchError, match=r"^replay checksum does not match the event stream$"
    ):
        verify_lifecycle_replay(
            events,
            replace(replay_lifecycle(events), replay_checksum="f" * 64),
        )


def test_verifier_rejects_artifact_run_mismatch_before_projection_comparison() -> None:
    events = event_stream()
    replay = replay_lifecycle(events)
    other_run_projection = replay.projection.model_copy(update={"run_id": UUID(int=2)})
    other_run_projection = other_run_projection.model_copy(
        update={"projection_checksum": compute_projection_checksum(other_run_projection)}
    )

    with pytest.raises(
        LifecycleReplayRunMismatchError,
        match=r"^replay artifact run_id does not match the event stream$",
    ):
        verify_lifecycle_replay(events, replace(replay, projection=other_run_projection))


def test_verifier_rejects_terminal_tail_as_replay_input() -> None:
    events = event_stream()
    terminal_tail = _resign(
        events[-1].model_copy(
            update={
                "event_id": UUID(int=99),
                "sequence": 4,
                "event_type": LifecycleEventType.RUN_CREATED,
                "prior_event_hash": events[-1].event_hash,
            }
        )
    )

    with pytest.raises(LifecycleReplayInputError, match="current state"):
        verify_lifecycle_replay((*events, terminal_tail), replay_lifecycle(events))
