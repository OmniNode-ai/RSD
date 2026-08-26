"""Tests for valid and invalid state transitions."""

from __future__ import annotations

from dataclasses import dataclass
from datetime import UTC, datetime
from enum import StrEnum
from uuid import UUID

import pytest

from rsd_canary.lifecycle.hashing import compute_event_hash, compute_projection_checksum
from rsd_canary.lifecycle.models import (
    GENESIS_HASH,
    LifecycleEvent,
    LifecycleEventIntent,
    LifecycleEventType,
    LifecycleRunProjection,
    LifecycleState,
)
from rsd_canary.lifecycle.projection import empty_projection
from rsd_canary.lifecycle.reducer import (
    LifecycleReductionError,
    reduce_lifecycle_event,
    validate_lifecycle_event,
    validate_lifecycle_projection,
)

from .support import event_stream


@dataclass
class _FakeEvent:
    """Duck-shaped object that must never cross the event trust boundary."""


class _RaisingEvent:
    @property
    def event_id(self) -> object:
        raise RuntimeError("must not be accessed")


@dataclass
class _FakeProjection:
    """Duck-shaped object that must never cross the projection trust boundary."""


class _RaisingProjection:
    @property
    def run_id(self) -> object:
        raise RuntimeError("must not be accessed")


class _EventSubclass(LifecycleEvent):
    """Subclass that must not be treated as the exact event contract."""


class _ProjectionSubclass(LifecycleRunProjection):
    """Subclass that must not be treated as the exact projection contract."""


class _EvilStr(str):
    def __eq__(self, other: object) -> bool:
        raise RuntimeError("digest equality must not run")


class _EvilUUID(UUID):
    def __eq__(self, other: object) -> bool:
        raise RuntimeError("UUID equality must not run")

    def __hash__(self) -> int:
        raise RuntimeError("UUID hashing must not run")


class _EvilDatetime(datetime):
    def isoformat(self, *args: object, **kwargs: object) -> str:
        raise RuntimeError("timestamp serialization must not run")


class _ForeignEventType(StrEnum):
    RUN_CREATED = "RUN_CREATED"


class _ForeignState(StrEnum):
    INITIAL = "INITIAL"


class _EvilInt(int):
    pass


def test_reducer_reaches_completed_state() -> None:
    events = event_stream()
    projection = empty_projection(events[0].run_id)
    for event in events:
        projection = reduce_lifecycle_event(projection, event)

    assert projection.state is LifecycleState.COMPLETED
    assert projection.last_sequence == 3


def test_reducer_rejects_invalid_first_event() -> None:
    event = event_stream()[1]
    with pytest.raises(LifecycleReductionError, match="contiguous"):
        reduce_lifecycle_event(empty_projection(event.run_id), event)


def test_reducer_rejects_forged_projection_before_reduction() -> None:
    event = event_stream()[0]
    forged_projection = empty_projection(event.run_id).model_copy(update={"last_sequence": True})

    with pytest.raises(LifecycleReductionError, match=r"^projection is not valid$"):
        reduce_lifecycle_event(forged_projection, event)


def test_reducer_rejects_forged_projection_checksum_type() -> None:
    event = event_stream()[0]
    forged_projection = empty_projection(event.run_id).model_copy(
        update={"projection_checksum": "not-a-hash"}
    )

    with pytest.raises(LifecycleReductionError, match=r"^projection is not valid$"):
        reduce_lifecycle_event(forged_projection, event)


def test_empty_projection_has_a_canonical_checksum() -> None:
    projection = empty_projection(event_stream()[0].run_id)

    assert projection.projection_checksum == compute_projection_checksum(projection)


def test_reducer_rejects_stale_projection_checksum_before_event_matching() -> None:
    event = event_stream()[0]
    stale_projection = empty_projection(event.run_id).model_copy(
        update={"projection_checksum": GENESIS_HASH}
    )

    with pytest.raises(
        LifecycleReductionError, match=r"^projection checksum does not match its contents$"
    ):
        reduce_lifecycle_event(stale_projection, event)


@pytest.mark.parametrize(
    "updates",
    (
        {"state": LifecycleState.CREATED},
        {"state": LifecycleState.CREATED, "last_sequence": 1},
    ),
)
def test_reducer_rejects_recomputed_checksum_with_incoherent_projection_state(
    updates: dict[str, object],
) -> None:
    event = event_stream()[0]
    forged_projection = empty_projection(event.run_id).model_copy(update=updates)
    forged_projection = forged_projection.model_copy(
        update={"projection_checksum": compute_projection_checksum(forged_projection)}
    )

    with pytest.raises(LifecycleReductionError, match=r"^projection is not valid$"):
        reduce_lifecycle_event(forged_projection, event)


@pytest.mark.parametrize(
    "last_event", (LifecycleEventType.WORK_COMPLETED, LifecycleEventType.WORK_FAILED)
)
def test_reducer_results_have_valid_checksums(last_event: LifecycleEventType) -> None:
    events = event_stream(last_event)
    projection = empty_projection(events[0].run_id)

    for event in events:
        projection = reduce_lifecycle_event(projection, event)
        assert projection.projection_checksum == compute_projection_checksum(projection)

    unsigned_terminal_event = events[-1].model_copy(
        update={
            "sequence": projection.last_sequence + 1,
            "event_type": LifecycleEventType.RUN_CREATED,
            "prior_event_hash": projection.last_event_hash,
            "event_hash": GENESIS_HASH,
        }
    )
    terminal_event = unsigned_terminal_event.model_copy(
        update={"event_hash": compute_event_hash(unsigned_terminal_event)}
    )
    with pytest.raises(LifecycleReductionError, match="current state"):
        reduce_lifecycle_event(projection, terminal_event)


def test_trust_validators_accept_exact_pydantic_models() -> None:
    event = event_stream()[0]
    projection = empty_projection(event.run_id)

    assert validate_lifecycle_event(event) == event
    assert validate_lifecycle_projection(projection) == projection


def test_exact_models_expose_only_declared_pydantic_2_instance_fields() -> None:
    event = event_stream()[0]
    projection = empty_projection(event.run_id)
    intent = LifecycleEventIntent(
        run_id=event.run_id,
        event_type=LifecycleEventType.RUN_CREATED,
        detail="created",
    )

    assert frozenset(vars(event)) == frozenset(LifecycleEvent.model_fields)
    assert frozenset(vars(projection)) == frozenset(LifecycleRunProjection.model_fields)
    assert frozenset(vars(intent)) == frozenset(LifecycleEventIntent.model_fields)


@pytest.mark.parametrize("candidate", (_FakeEvent(), _RaisingEvent()))
def test_event_validator_rejects_foreign_objects_without_attribute_access(
    candidate: object,
) -> None:
    with pytest.raises(LifecycleReductionError, match=r"^event is not valid$"):
        validate_lifecycle_event(candidate)  # type: ignore[arg-type]


def test_event_validator_rejects_subclass_unknown_and_missing_fields() -> None:
    event = event_stream()[0]
    subclass = _EventSubclass(**event.model_dump(mode="python"))
    unknown = event.model_copy(update={"unexpected": "value"})
    missing = event.model_copy()
    missing.__dict__.pop("detail")

    for candidate in (subclass, unknown, missing):
        with pytest.raises(LifecycleReductionError, match=r"^event is not valid$"):
            validate_lifecycle_event(candidate)


@pytest.mark.parametrize("candidate", (_FakeProjection(), _RaisingProjection()))
def test_projection_validator_rejects_foreign_objects_without_attribute_access(
    candidate: object,
) -> None:
    with pytest.raises(LifecycleReductionError, match=r"^projection is not valid$"):
        validate_lifecycle_projection(candidate)  # type: ignore[arg-type]


def test_projection_validator_rejects_subclass_unknown_and_missing_fields() -> None:
    projection = empty_projection(event_stream()[0].run_id)
    subclass = _ProjectionSubclass(**projection.model_dump(mode="python"))
    unknown = projection.model_copy(update={"unexpected": "value"})
    missing = projection.model_copy()
    missing.__dict__.pop("last_event_hash")

    for candidate in (subclass, unknown, missing):
        with pytest.raises(LifecycleReductionError, match=r"^projection is not valid$"):
            validate_lifecycle_projection(candidate)


def test_projection_validator_rejects_digest_string_subclass_before_checksum_comparison() -> None:
    projection = empty_projection(event_stream()[0].run_id).model_copy(
        update={"projection_checksum": _EvilStr(GENESIS_HASH)}
    )

    with pytest.raises(LifecycleReductionError, match=r"^projection is not valid$"):
        validate_lifecycle_projection(projection)


@pytest.mark.parametrize(
    ("field", "value"),
    (
        ("run_id", _EvilUUID("00000000-0000-0000-0000-000000000002")),
        ("event_id", _EvilUUID("00000000-0000-0000-0000-000000000012")),
        ("event_type", _ForeignEventType.RUN_CREATED),
        ("occurred_at", _EvilDatetime(2026, 1, 1, tzinfo=UTC)),
        ("sequence", _EvilInt(1)),
        ("detail", _EvilStr("created")),
    ),
)
@pytest.mark.filterwarnings("ignore:Pydantic serializer warnings:UserWarning")
def test_event_validator_rejects_scalar_subclasses_before_they_can_execute(
    field: str, value: object
) -> None:
    event = event_stream()[0].model_copy(update={field: value})

    with pytest.raises(LifecycleReductionError, match=r"^event is not valid$"):
        validate_lifecycle_event(event)


@pytest.mark.parametrize(
    ("field", "value"),
    (
        ("run_id", _EvilUUID("00000000-0000-0000-0000-000000000002")),
        ("state", _ForeignState.INITIAL),
        ("last_sequence", _EvilInt(0)),
        ("projection_checksum", _EvilStr(GENESIS_HASH)),
    ),
)
@pytest.mark.filterwarnings("ignore:Pydantic serializer warnings:UserWarning")
def test_projection_validator_rejects_scalar_subclasses_before_they_can_execute(
    field: str, value: object
) -> None:
    projection = empty_projection(event_stream()[0].run_id).model_copy(update={field: value})

    with pytest.raises(LifecycleReductionError, match=r"^projection is not valid$"):
        validate_lifecycle_projection(projection)
