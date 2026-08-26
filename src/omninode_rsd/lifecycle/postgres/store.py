"""Endpoint-agnostic PostgreSQL storage for deterministic lifecycle events."""

from __future__ import annotations

import json
from collections.abc import Callable, Mapping
from contextlib import AbstractContextManager
from datetime import datetime
from typing import Protocol, TypeVar
from uuid import UUID

from pydantic import ValidationError

from omninode_rsd.lifecycle.event_log import LifecycleEventLog
from omninode_rsd.lifecycle.hashing import canonical_json, compute_event_hash
from omninode_rsd.lifecycle.ingress import LifecycleEventIngress, validate_lifecycle_event_intent
from omninode_rsd.lifecycle.models import (
    LifecycleEvent,
    LifecycleEventIntent,
    LifecycleEventType,
    LifecycleRunProjection,
    LifecycleState,
)
from omninode_rsd.lifecycle.projection import empty_projection
from omninode_rsd.lifecycle.reducer import (
    LifecycleReductionError,
    reduce_lifecycle_event,
    validate_lifecycle_event,
    validate_lifecycle_projection,
)
from omninode_rsd.lifecycle.replay import LifecycleReplay, replay_lifecycle

_EVENT_COLUMNS = (
    "event_id",
    "run_id",
    "sequence",
    "occurred_at",
    "event_type",
    "detail",
    "prior_event_hash",
    "event_hash",
    "event_json",
)
_HEAD_COLUMNS = (
    "run_id",
    "state",
    "last_sequence",
    "last_event_hash",
    "event_stream_hash",
    "projection_checksum",
    "projection_json",
)
_Result = TypeVar("_Result")

_READ_COMMITTED_SQL = "SET TRANSACTION ISOLATION LEVEL READ COMMITTED;"
_LOCK_RUN_SQL = "SELECT pg_advisory_xact_lock(hashtextextended(%s::text, 0));"
_SELECT_EVENTS_SQL = """
SELECT event_id, run_id, sequence, occurred_at, event_type, detail,
       prior_event_hash, event_hash, event_json
FROM rsd_canary.lifecycle_events
WHERE run_id = %s
ORDER BY sequence ASC
"""
_SELECT_HEAD_FOR_UPDATE_SQL = """
SELECT run_id, state, last_sequence, last_event_hash, event_stream_hash,
       projection_checksum, projection_json
FROM rsd_canary.lifecycle_run_heads
WHERE run_id = %s
FOR UPDATE
"""
_INSERT_EVENT_SQL = """
INSERT INTO rsd_canary.lifecycle_events (
    event_id, run_id, sequence, occurred_at, event_type, detail,
    prior_event_hash, event_hash, event_json
) VALUES (%s, %s, %s, %s, %s, %s, %s, %s, %s::jsonb)
"""
_INSERT_HEAD_SQL = """
INSERT INTO rsd_canary.lifecycle_run_heads (
    run_id, state, last_sequence, last_event_hash, event_stream_hash,
    projection_checksum, projection_json
) VALUES (%s, %s, %s, %s, %s, %s, %s::jsonb)
"""
_UPDATE_HEAD_SQL = """
UPDATE rsd_canary.lifecycle_run_heads
SET state = %s,
    last_sequence = %s,
    last_event_hash = %s,
    event_stream_hash = %s,
    projection_checksum = %s,
    projection_json = %s::jsonb
WHERE run_id = %s
"""


class PostgresResult(Protocol):
    """Minimal result protocol used by the endpoint-agnostic store."""

    def fetchone(self) -> Mapping[str, object] | tuple[object, ...] | None: ...

    def fetchall(self) -> list[Mapping[str, object] | tuple[object, ...]]: ...


class PostgresConnection(Protocol):
    """Minimal PostgreSQL connection protocol required by the store."""

    def execute(self, query: str, params: tuple[object, ...] = ()) -> PostgresResult: ...

    def transaction(self) -> AbstractContextManager[object]: ...


type PostgresConnectionFactory = Callable[[], AbstractContextManager[PostgresConnection]]


class LifecycleStoreError(RuntimeError):
    """Base class for PostgreSQL lifecycle store failures."""


class LifecycleStoreConflictError(LifecycleStoreError):
    """Raised when an event conflicts with the durable lifecycle stream."""


class LifecycleStoreCorruptionError(LifecycleStoreError):
    """Raised when stored lifecycle rows fail canonical verification."""


class LifecycleStoreTransientError(LifecycleStoreError):
    """Raised for retryable database failures; this store never retries itself."""


class LifecycleStoreUnavailableError(LifecycleStoreError):
    """Raised when the injected database connection cannot complete an operation."""


class DurableLifecycleEventLog(LifecycleEventLog, Protocol):
    """Lifecycle event storage that also exposes durable projections and replays."""

    def projection_for(self, run_id: UUID) -> LifecycleRunProjection: ...

    def replay_for(self, run_id: UUID) -> LifecycleReplay | None: ...


class PostgresLifecycleEventLog:
    """Append-only lifecycle log backed by an injected PostgreSQL connection factory.

    This trusted runtime adapter boundary validates canonical event hashes and
    projections, but it is not a database authorization system. External
    canonical provisioning must assign a NOLOGIN owner and grant this adapter
    only its required lifecycle operations. The factory owns driver selection,
    connection setup, and configuration. This class performs no DDL,
    configuration lookup, connection-pool creation, or automatic retry. Each
    ingestion operation uses one `READ COMMITTED` transaction and takes a
    transaction-scoped advisory lock for its run before reading or writing
    lifecycle state. The lock coordinates only authorized adapter writers;
    strict database ACLs must prevent bypass writes by other identities.
    """

    def __init__(self, connection_factory: PostgresConnectionFactory) -> None:
        self._connection_factory = connection_factory

    def append(self, event: LifecycleEvent) -> None:
        """Validate and durably append one already-constructed lifecycle event."""

        validated_event = self._validate_append_event(event)
        self._run_transaction(
            validated_event.run_id,
            lambda connection: self._append_in_transaction(connection, validated_event),
        )

    def ingest(
        self, intent: LifecycleEventIntent | dict[str, object], builder: LifecycleEventIngress
    ) -> LifecycleEvent:
        """Atomically construct, append, and project one lifecycle event."""

        validated_intent = validate_lifecycle_event_intent(intent)

        def ingest_in_transaction(connection: PostgresConnection) -> LifecycleEvent:
            _, projection, has_head = self._load_verified_run(connection, validated_intent.run_id)
            event = builder.build(
                validated_intent,
                sequence=projection.last_sequence + 1,
                prior_event_hash=projection.last_event_hash,
            )
            self._append_in_transaction(
                connection,
                event,
                projection=projection,
                has_head=has_head,
            )
            return event

        return self._run_transaction(validated_intent.run_id, ingest_in_transaction)

    def events_for(self, run_id: UUID) -> tuple[LifecycleEvent, ...]:
        """Return a verified immutable snapshot of one durable event stream."""

        events, _, _ = self._run_transaction(
            run_id, lambda connection: self._load_verified_run(connection, run_id)
        )
        return events

    def projection_for(self, run_id: UUID) -> LifecycleRunProjection:
        """Return the verified durable projection, or the canonical empty projection."""

        _, projection, _ = self._run_transaction(
            run_id, lambda connection: self._load_verified_run(connection, run_id)
        )
        return projection

    def replay_for(self, run_id: UUID) -> LifecycleReplay | None:
        """Return a verified replay for a durable stream, or ``None`` when absent."""

        events, _, has_head = self._run_transaction(
            run_id, lambda connection: self._load_verified_run(connection, run_id)
        )
        return replay_lifecycle(events) if has_head else None

    def _run_transaction(
        self, run_id: UUID, operation: Callable[[PostgresConnection], _Result]
    ) -> _Result:
        try:
            with self._connection_factory() as connection, connection.transaction():
                connection.execute(_READ_COMMITTED_SQL)
                connection.execute(_LOCK_RUN_SQL, (str(run_id),))
                return operation(connection)
        except LifecycleStoreError:
            raise
        except (TypeError, ValueError):
            raise
        except Exception as error:
            raise self._driver_error(error) from None

    def _append_in_transaction(
        self,
        connection: PostgresConnection,
        event: LifecycleEvent,
        *,
        projection: LifecycleRunProjection | None = None,
        has_head: bool | None = None,
    ) -> None:
        validated_event = self._validate_append_event(event)
        if projection is None or has_head is None:
            _, projection, has_head = self._load_verified_run(connection, validated_event.run_id)
        try:
            updated_projection = reduce_lifecycle_event(projection, validated_event)
        except LifecycleReductionError as error:
            raise LifecycleStoreConflictError(
                "event conflicts with the current lifecycle state"
            ) from error
        connection.execute(_INSERT_EVENT_SQL, self._event_parameters(validated_event))
        if has_head:
            connection.execute(_UPDATE_HEAD_SQL, self._update_head_parameters(updated_projection))
        else:
            connection.execute(_INSERT_HEAD_SQL, self._head_parameters(updated_projection))

    def _load_verified_run(
        self, connection: PostgresConnection, run_id: UUID
    ) -> tuple[tuple[LifecycleEvent, ...], LifecycleRunProjection, bool]:
        head_row = connection.execute(_SELECT_HEAD_FOR_UPDATE_SQL, (run_id,)).fetchone()
        event_rows = connection.execute(_SELECT_EVENTS_SQL, (run_id,)).fetchall()
        events = tuple(self._event_from_row(row) for row in event_rows)
        if any(event.run_id != run_id for event in events):
            raise LifecycleStoreCorruptionError("stored event does not belong to the requested run")
        head = self._projection_from_row(head_row) if head_row is not None else None
        if head is not None and head.run_id != run_id:
            raise LifecycleStoreCorruptionError(
                "stored projection does not belong to the requested run"
            )
        if head is None:
            if events:
                raise LifecycleStoreCorruptionError("event stream has no durable projection")
            return (), empty_projection(run_id), False
        if not events:
            raise LifecycleStoreCorruptionError("durable projection has no event stream")
        try:
            replay = replay_lifecycle(events)
        except (LifecycleReductionError, ValueError) as error:
            raise LifecycleStoreCorruptionError("stored event stream is not valid") from error
        if replay.projection != head:
            raise LifecycleStoreCorruptionError("stored projection does not match its event stream")
        return events, head, True

    @staticmethod
    def _validate_append_event(event: LifecycleEvent) -> LifecycleEvent:
        try:
            validated_event = validate_lifecycle_event(event)
        except LifecycleReductionError as error:
            raise ValueError("event is not valid") from error
        if compute_event_hash(validated_event) != validated_event.event_hash:
            raise ValueError("event hash does not match its contents")
        return validated_event

    @staticmethod
    def _event_from_row(row: Mapping[str, object] | tuple[object, ...]) -> LifecycleEvent:
        values = _row_values(row, _EVENT_COLUMNS)
        try:
            event_id = _uuid_value(values["event_id"])
            run_id = _uuid_value(values["run_id"])
            sequence = _integer_value(values["sequence"])
            occurred_at = _datetime_value(values["occurred_at"])
            event_type = LifecycleEventType(_string_value(values["event_type"]))
            event = LifecycleEvent(
                event_id=event_id,
                run_id=run_id,
                sequence=sequence,
                occurred_at=occurred_at,
                event_type=event_type,
                detail=_string_value(values["detail"]),
                prior_event_hash=_string_value(values["prior_event_hash"]),
                event_hash=_string_value(values["event_hash"]),
            )
            validated = validate_lifecycle_event(event)
        except (LifecycleReductionError, TypeError, ValidationError, ValueError) as error:
            raise LifecycleStoreCorruptionError("stored event row is not valid") from error
        if compute_event_hash(validated) != validated.event_hash:
            raise LifecycleStoreCorruptionError("stored event hash does not match its contents")
        _require_canonical_json(values["event_json"], validated.model_dump(mode="python"))
        return validated

    @staticmethod
    def _projection_from_row(
        row: Mapping[str, object] | tuple[object, ...],
    ) -> LifecycleRunProjection:
        values = _row_values(row, _HEAD_COLUMNS)
        try:
            projection = LifecycleRunProjection(
                run_id=_uuid_value(values["run_id"]),
                state=LifecycleState(_string_value(values["state"])),
                last_sequence=_integer_value(values["last_sequence"]),
                last_event_hash=_string_value(values["last_event_hash"]),
                event_stream_hash=_string_value(values["event_stream_hash"]),
                projection_checksum=_string_value(values["projection_checksum"]),
            )
            validated = validate_lifecycle_projection(projection)
        except (LifecycleReductionError, TypeError, ValidationError, ValueError) as error:
            raise LifecycleStoreCorruptionError("stored projection row is not valid") from error
        _require_canonical_json(values["projection_json"], validated.model_dump(mode="python"))
        return validated

    @staticmethod
    def _event_parameters(event: LifecycleEvent) -> tuple[object, ...]:
        return (
            event.event_id,
            event.run_id,
            event.sequence,
            event.occurred_at,
            event.event_type.value,
            event.detail,
            event.prior_event_hash,
            event.event_hash,
            canonical_json(event.model_dump(mode="python")).decode("utf-8"),
        )

    @staticmethod
    def _head_parameters(projection: LifecycleRunProjection) -> tuple[object, ...]:
        return (
            projection.run_id,
            projection.state.value,
            projection.last_sequence,
            projection.last_event_hash,
            projection.event_stream_hash,
            projection.projection_checksum,
            canonical_json(projection.model_dump(mode="python")).decode("utf-8"),
        )

    @classmethod
    def _update_head_parameters(cls, projection: LifecycleRunProjection) -> tuple[object, ...]:
        return (*cls._head_parameters(projection)[1:], projection.run_id)

    @staticmethod
    def _driver_error(error: Exception) -> LifecycleStoreError:
        state = getattr(error, "sqlstate", None)
        if type(state) is not str:
            state = getattr(error, "pgcode", None)
        if state == "23505":
            return LifecycleStoreConflictError("durable lifecycle store conflict")
        if state in {"40001", "40P01", "55P03"}:
            return LifecycleStoreTransientError("durable lifecycle store transaction is transient")
        return LifecycleStoreUnavailableError("durable lifecycle store is unavailable")


def _row_values(
    row: Mapping[str, object] | tuple[object, ...], columns: tuple[str, ...]
) -> dict[str, object]:
    if type(row) is tuple:
        if len(row) != len(columns):
            raise LifecycleStoreCorruptionError("stored row has an unexpected shape")
        return dict(zip(columns, row, strict=True))
    if isinstance(row, Mapping) and set(row) == set(columns):
        return {column: row[column] for column in columns}
    raise LifecycleStoreCorruptionError("stored row has an unexpected shape")


def _uuid_value(value: object) -> UUID:
    if type(value) is not UUID:
        raise TypeError("stored UUID is not valid")
    return value


def _integer_value(value: object) -> int:
    if type(value) is not int:
        raise TypeError("stored integer is not valid")
    return value


def _datetime_value(value: object) -> datetime:
    if type(value) is not datetime:
        raise TypeError("stored timestamp is not valid")
    return value


def _string_value(value: object) -> str:
    if type(value) is not str:
        raise TypeError("stored text is not valid")
    return value


def _require_canonical_json(value: object, expected: object) -> None:
    if type(value) is not dict:
        raise LifecycleStoreCorruptionError("stored canonical JSON is not valid")
    expected_json = json.loads(canonical_json(expected))
    if value != expected_json:
        raise LifecycleStoreCorruptionError("stored canonical JSON does not match row values")
