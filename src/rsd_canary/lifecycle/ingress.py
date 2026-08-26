"""Stateless construction boundary for lifecycle events."""

from __future__ import annotations

from collections.abc import Callable
from datetime import UTC, datetime
from uuid import UUID, uuid4

from pydantic import ValidationError

from rsd_canary.lifecycle.hashing import compute_event_hash
from rsd_canary.lifecycle.models import GENESIS_HASH, LifecycleEvent, LifecycleEventIntent


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

        validated = LifecycleEventIntent.model_validate(intent)
        event_id = self._event_id_factory()
        if not isinstance(event_id, UUID):
            raise TypeError("event_id factory must return a UUID")
        occurred_at = self._clock()
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
        return event.model_copy(update={"event_hash": compute_event_hash(event)})
