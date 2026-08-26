"""Stateless construction boundary for lifecycle events."""

from __future__ import annotations

from collections.abc import Callable
from datetime import UTC, datetime
from uuid import UUID, uuid4

from pydantic import ValidationError

from rsd_canary.lifecycle.hashing import compute_event_hash
from rsd_canary.lifecycle.models import (
    GENESIS_HASH,
    LifecycleEvent,
    LifecycleEventIntent,
    LifecycleEventType,
    strict_model_values,
)
from rsd_canary.lifecycle.reducer import LifecycleReductionError, validate_lifecycle_event

_INTENT_FIELD_NAMES = frozenset(LifecycleEventIntent.model_fields)


def _strict_mapping_values(values: object, field_names: frozenset[str]) -> dict[str, object] | None:
    """Return an exact built-in-dict field set without invoking foreign methods."""

    if type(values) is not dict or len(values) != len(field_names):
        return None
    keys = tuple(values)
    if any(type(key) is not str for key in keys) or frozenset(keys) != field_names:
        return None
    return {field_name: values[field_name] for field_name in field_names}


def validate_lifecycle_event_intent(
    intent: LifecycleEventIntent | dict[str, object],
) -> LifecycleEventIntent:
    """Strictly reconstruct caller intent before any builder callback runs."""

    if type(intent) is LifecycleEventIntent:
        values = strict_model_values(
            intent,
            expected_type=LifecycleEventIntent,
            field_names=_INTENT_FIELD_NAMES,
        )
    else:
        values = _strict_mapping_values(intent, _INTENT_FIELD_NAMES)
    if values is None:
        raise ValueError("intent is not valid")
    if (
        type(values["run_id"]) is not UUID
        or type(values["event_type"]) is not LifecycleEventType
        or type(values["detail"]) is not str
    ):
        raise ValueError("intent is not valid")
    try:
        return LifecycleEventIntent.model_validate(values)
    except ValidationError as error:
        raise ValueError("intent is not valid") from error


def _utc_now() -> datetime:
    return datetime.now(UTC)


class LifecycleEventIngress:
    """Build a validated event from authority supplied by an event log.

    This class intentionally holds no run state, sequence, or hash-chain state.
    Callers must provide the authoritative sequence number and prior event hash.
    """

    def __init__(
        self,
        *,
        event_id_factory: Callable[[], UUID] = uuid4,
        clock: Callable[[], datetime] = _utc_now,
    ) -> None:
        self._event_id_factory = event_id_factory
        self._clock = clock

    def build(
        self,
        intent: LifecycleEventIntent | dict[str, object],
        *,
        sequence: int,
        prior_event_hash: str = GENESIS_HASH,
    ) -> LifecycleEvent:
        """Build one immutable event without retaining any run-specific state."""

        validated = validate_lifecycle_event_intent(intent)
        if type(sequence) is not int or type(prior_event_hash) is not str:
            raise ValueError("event is not valid")
        event_id = self._event_id_factory()
        if type(event_id) is not UUID:
            raise TypeError("event_id factory must return a UUID")
        occurred_at = self._clock()
        if type(occurred_at) is not datetime:
            raise ValueError("clock must return a UTC timestamp")
        if occurred_at.tzinfo is None or occurred_at.utcoffset() != UTC.utcoffset(occurred_at):
            raise ValueError("clock must return a UTC timestamp")
        try:
            event = LifecycleEvent(
                event_id=event_id,
                run_id=validated.run_id,
                sequence=sequence,
                occurred_at=occurred_at,
                event_type=validated.event_type,
                detail=validated.detail,
                prior_event_hash=prior_event_hash,
                event_hash=GENESIS_HASH,
            )
        except ValidationError as error:
            raise ValueError("event is not valid") from error
        try:
            unsigned_event = validate_lifecycle_event(event)
            signed_event = unsigned_event.model_copy(
                update={"event_hash": compute_event_hash(unsigned_event)}
            )
            return validate_lifecycle_event(signed_event)
        except LifecycleReductionError as error:
            raise ValueError("event is not valid") from error
