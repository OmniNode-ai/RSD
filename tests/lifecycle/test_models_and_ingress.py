"""Tests for lifecycle models and stateless event construction."""

from __future__ import annotations

from datetime import UTC, datetime
from enum import StrEnum
from uuid import UUID

import pytest
from pydantic import ValidationError

from omninode_rsd.lifecycle.ingress import LifecycleEventIngress
from omninode_rsd.lifecycle.models import LifecycleEvent, LifecycleEventIntent, LifecycleEventType


class _IntentSubclass(LifecycleEventIntent):
    """Subclass that must not cross the intent trust boundary."""


class _EvilUUID(UUID):
    def __hash__(self) -> int:
        raise RuntimeError("UUID hashing must not run")


class _ForeignEventType(StrEnum):
    RUN_CREATED = "RUN_CREATED"


class _EvilStr(str):
    pass


class _EvilDatetime(datetime):
    def isoformat(self, *args: object, **kwargs: object) -> str:
        raise RuntimeError("timestamp serialization must not run")


def test_builder_uses_authoritative_sequence_and_prior_hash() -> None:
    ingress = LifecycleEventIngress(
        event_id_factory=lambda: UUID("00000000-0000-0000-0000-000000000011"),
        clock=lambda: datetime(2026, 1, 1, tzinfo=UTC),
    )
    intent = LifecycleEventIntent(
        run_id=UUID("00000000-0000-0000-0000-000000000001"),
        event_type=LifecycleEventType.RUN_CREATED,
        detail="created",
    )

    event = ingress.build(intent, sequence=1)

    assert event.sequence == 1
    assert event.prior_event_hash == "0" * 64


def test_intent_rejects_empty_detail() -> None:
    with pytest.raises(ValidationError):
        LifecycleEventIntent(
            run_id=UUID("00000000-0000-0000-0000-000000000001"),
            event_type=LifecycleEventType.RUN_CREATED,
            detail="",
        )


@pytest.mark.parametrize("sequence", (True, 1.0))
def test_event_rejects_non_integer_sequence(sequence: object) -> None:
    values = {
        "event_id": UUID("00000000-0000-0000-0000-000000000011"),
        "run_id": UUID("00000000-0000-0000-0000-000000000001"),
        "sequence": sequence,
        "occurred_at": datetime(2026, 1, 1, tzinfo=UTC),
        "event_type": LifecycleEventType.RUN_CREATED,
        "detail": "created",
        "prior_event_hash": "0" * 64,
        "event_hash": "0" * 64,
    }

    with pytest.raises(ValidationError):
        LifecycleEvent.model_validate(values)


@pytest.mark.parametrize("sequence", (True, 1.0, 0))
def test_builder_rejects_invalid_authoritative_sequence(sequence: object) -> None:
    ingress = LifecycleEventIngress()
    intent = LifecycleEventIntent(
        run_id=UUID("00000000-0000-0000-0000-000000000001"),
        event_type=LifecycleEventType.RUN_CREATED,
        detail="created",
    )

    with pytest.raises(ValueError, match="event is not valid"):
        ingress.build(intent, sequence=sequence)  # type: ignore[arg-type]


@pytest.mark.parametrize(
    ("field", "value"),
    (
        ("run_id", _EvilUUID("00000000-0000-0000-0000-000000000002")),
        ("event_type", _ForeignEventType.RUN_CREATED),
        ("detail", _EvilStr("created")),
    ),
)
def test_builder_rejects_forged_intent_scalars_before_callbacks(field: str, value: object) -> None:
    intent = LifecycleEventIntent(
        run_id=UUID("00000000-0000-0000-0000-000000000001"),
        event_type=LifecycleEventType.RUN_CREATED,
        detail="created",
    ).model_copy(update={field: value})
    ingress = LifecycleEventIngress(
        event_id_factory=lambda: (_ for _ in ()).throw(AssertionError())
    )

    with pytest.raises(ValueError, match=r"^intent is not valid$"):
        ingress.build(intent, sequence=1)


def test_builder_rejects_intent_subclass_before_callbacks() -> None:
    intent = _IntentSubclass(
        run_id=UUID("00000000-0000-0000-0000-000000000001"),
        event_type=LifecycleEventType.RUN_CREATED,
        detail="created",
    )
    ingress = LifecycleEventIngress(
        event_id_factory=lambda: (_ for _ in ()).throw(AssertionError())
    )

    with pytest.raises(ValueError, match=r"^intent is not valid$"):
        ingress.build(intent, sequence=1)


def test_builder_rejects_intent_unknown_and_missing_fields_before_callbacks() -> None:
    intent = LifecycleEventIntent(
        run_id=UUID("00000000-0000-0000-0000-000000000001"),
        event_type=LifecycleEventType.RUN_CREATED,
        detail="created",
    )
    unknown = intent.model_copy(update={"unexpected": "value"})
    missing = intent.model_copy()
    missing.__dict__.pop("detail")
    ingress = LifecycleEventIngress(
        event_id_factory=lambda: (_ for _ in ()).throw(AssertionError())
    )

    for forged in (unknown, missing):
        with pytest.raises(ValueError, match=r"^intent is not valid$"):
            ingress.build(forged, sequence=1)


def test_builder_rejects_uuid_subclass_from_factory_before_hashing() -> None:
    ingress = LifecycleEventIngress(
        event_id_factory=lambda: _EvilUUID("00000000-0000-0000-0000-000000000011")
    )
    intent = LifecycleEventIntent(
        run_id=UUID("00000000-0000-0000-0000-000000000001"),
        event_type=LifecycleEventType.RUN_CREATED,
        detail="created",
    )

    with pytest.raises(TypeError, match=r"^event_id factory must return a UUID$"):
        ingress.build(intent, sequence=1)


def test_builder_rejects_datetime_subclass_from_clock_before_hashing() -> None:
    ingress = LifecycleEventIngress(clock=lambda: _EvilDatetime(2026, 1, 1, tzinfo=UTC))
    intent = LifecycleEventIntent(
        run_id=UUID("00000000-0000-0000-0000-000000000001"),
        event_type=LifecycleEventType.RUN_CREATED,
        detail="created",
    )

    with pytest.raises(ValueError, match=r"^clock must return a UTC timestamp$"):
        ingress.build(intent, sequence=1)
