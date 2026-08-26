"""Protocol-fake tests for the endpoint-agnostic PostgreSQL lifecycle store."""

from __future__ import annotations

import json
from contextlib import AbstractContextManager
from datetime import UTC, datetime
from pathlib import Path
from uuid import UUID

import pytest

from omninode_rsd.lifecycle import (
    LifecycleEventIngress,
    LifecycleEventIntent,
    LifecycleEventType,
)
from omninode_rsd.lifecycle.postgres import (
    LifecycleStoreConflictError,
    LifecycleStoreCorruptionError,
    LifecycleStoreTransientError,
    LifecycleStoreUnavailableError,
    PostgresLifecycleEventLog,
)

from .support import EVENT_IDS, RUN_ID, event_stream


class _Result:
    def __init__(self, rows: list[dict[str, object]]) -> None:
        self._rows = rows

    def fetchone(self) -> dict[str, object] | None:
        return self._rows[0] if self._rows else None

    def fetchall(self) -> list[dict[str, object]]:
        return list(self._rows)


class _DriverError(Exception):
    def __init__(self, sqlstate: str) -> None:
        self.sqlstate = sqlstate


class _Transaction(AbstractContextManager[object]):
    def __init__(self, database: _Database) -> None:
        self._database = database

    def __enter__(self) -> object:
        self._database.transactions.append("begin")
        return self

    def __exit__(self, exc_type: object, exc: object, traceback: object) -> None:
        self._database.transactions.append("rollback" if exc_type is not None else "commit")


class _Database:
    def __init__(self) -> None:
        self.events: dict[UUID, list[dict[str, object]]] = {}
        self.heads: dict[UUID, dict[str, object]] = {}
        self.calls: list[tuple[str, tuple[object, ...]]] = []
        self.transactions: list[str] = []
        self.fail_on: tuple[str, _DriverError] | None = None


class _Connection(AbstractContextManager["_Connection"]):
    def __init__(self, database: _Database) -> None:
        self._database = database

    def __enter__(self) -> _Connection:
        return self

    def __exit__(self, exc_type: object, exc: object, traceback: object) -> None:
        return None

    def transaction(self) -> _Transaction:
        return _Transaction(self._database)

    def execute(self, query: str, params: tuple[object, ...] = ()) -> _Result:
        normalized = " ".join(query.split())
        self._database.calls.append((normalized, params))
        if self._database.fail_on is not None and normalized.startswith(self._database.fail_on[0]):
            raise self._database.fail_on[1]
        if normalized == "SET TRANSACTION ISOLATION LEVEL READ COMMITTED;":
            return _Result([])
        if normalized.startswith("SELECT pg_advisory_xact_lock"):
            return _Result([])
        if normalized.startswith("SELECT run_id, state"):
            run_id = _uuid(params[0])
            head = self._database.heads.get(run_id)
            return _Result([head] if head is not None else [])
        if normalized.startswith("SELECT event_id, run_id"):
            run_id = _uuid(params[0])
            return _Result(self._database.events.get(run_id, []))
        if normalized.startswith("INSERT INTO rsd_canary.lifecycle_events"):
            (
                event_id,
                run_id,
                sequence,
                occurred_at,
                event_type,
                detail,
                prior_hash,
                event_hash,
                payload,
            ) = params
            event_run_id = _uuid(run_id)
            self._database.events.setdefault(event_run_id, []).append(
                {
                    "event_id": event_id,
                    "run_id": event_run_id,
                    "sequence": sequence,
                    "occurred_at": occurred_at,
                    "event_type": event_type,
                    "detail": detail,
                    "prior_event_hash": prior_hash,
                    "event_hash": event_hash,
                    "event_json": json.loads(_text(payload)),
                }
            )
            return _Result([])
        if normalized.startswith("INSERT INTO rsd_canary.lifecycle_run_heads"):
            self._database.heads[_uuid(params[0])] = _head_row(params)
            return _Result([])
        if normalized.startswith("UPDATE rsd_canary.lifecycle_run_heads"):
            self._database.heads[_uuid(params[-1])] = _head_row((params[-1], *params[:-1]))
            return _Result([])
        raise AssertionError(f"unexpected query: {normalized}")


class _ConnectionFactory:
    def __init__(self, database: _Database) -> None:
        self._database = database

    def __call__(self) -> _Connection:
        return _Connection(self._database)


def _uuid(value: object) -> UUID:
    assert type(value) is UUID
    return value


def _text(value: object) -> str:
    assert type(value) is str
    return value


def _head_row(params: tuple[object, ...]) -> dict[str, object]:
    run_id, state, sequence, last_hash, stream_hash, checksum, payload = params
    return {
        "run_id": run_id,
        "state": state,
        "last_sequence": sequence,
        "last_event_hash": last_hash,
        "event_stream_hash": stream_hash,
        "projection_checksum": checksum,
        "projection_json": json.loads(_text(payload)),
    }


def _builder(event_id: UUID) -> LifecycleEventIngress:
    return LifecycleEventIngress(
        event_id_factory=lambda: event_id,
        clock=lambda: datetime(2026, 1, 1, tzinfo=UTC),
    )


def _store(database: _Database) -> PostgresLifecycleEventLog:
    return PostgresLifecycleEventLog(_ConnectionFactory(database))


def test_ingest_uses_one_advisory_locked_transaction_and_projects_durable_state() -> None:
    database = _Database()
    store = _store(database)
    intent = LifecycleEventIntent(
        run_id=RUN_ID,
        event_type=LifecycleEventType.RUN_CREATED,
        detail="created",
    )

    event = store.ingest(intent, _builder(EVENT_IDS[0]))

    assert database.transactions == ["begin", "commit"]
    statements = [query for query, _ in database.calls]
    assert statements[0] == "SET TRANSACTION ISOLATION LEVEL READ COMMITTED;"
    assert statements[1].startswith("SELECT pg_advisory_xact_lock")
    assert "FOR UPDATE" in statements[2]
    assert statements.index(
        next(
            query
            for query in statements
            if query.startswith("INSERT INTO rsd_canary.lifecycle_events")
        )
    ) < statements.index(
        next(
            query
            for query in statements
            if query.startswith("INSERT INTO rsd_canary.lifecycle_run_heads")
        )
    )
    assert store.events_for(RUN_ID) == (event,)
    assert store.projection_for(RUN_ID).last_event_hash == event.event_hash
    assert store.replay_for(RUN_ID) is not None


def test_append_preserves_event_log_behavior_and_updates_existing_head() -> None:
    database = _Database()
    store = _store(database)
    first, second, *_ = event_stream()

    store.append(first)
    store.append(second)

    assert store.events_for(RUN_ID) == (first, second)
    assert store.projection_for(RUN_ID).last_sequence == 2
    assert any(
        query.startswith("UPDATE rsd_canary.lifecycle_run_heads") for query, _ in database.calls
    )


def test_missing_run_has_empty_projection_and_no_replay() -> None:
    database = _Database()
    store = _store(database)

    assert store.events_for(RUN_ID) == ()
    assert store.projection_for(RUN_ID).last_sequence == 0
    assert store.replay_for(RUN_ID) is None


def test_read_rejects_tampered_canonical_json_before_returning_event() -> None:
    database = _Database()
    store = _store(database)
    event = store.ingest(
        LifecycleEventIntent(
            run_id=RUN_ID,
            event_type=LifecycleEventType.RUN_CREATED,
            detail="created",
        ),
        _builder(EVENT_IDS[0]),
    )
    database.events[RUN_ID][0]["event_json"] = {"event_id": str(event.event_id)}

    with pytest.raises(LifecycleStoreCorruptionError, match="canonical JSON"):
        store.events_for(RUN_ID)


def test_read_accepts_exact_mapping_subclasses_returned_by_database_drivers() -> None:
    class DriverRow(dict[str, object]):
        """Representative mapping subclass returned by a database driver."""

    database = _Database()
    store = _store(database)
    event = store.ingest(
        LifecycleEventIntent(
            run_id=RUN_ID,
            event_type=LifecycleEventType.RUN_CREATED,
            detail="created",
        ),
        _builder(EVENT_IDS[0]),
    )
    database.events[RUN_ID][0] = DriverRow(database.events[RUN_ID][0])
    database.heads[RUN_ID] = DriverRow(database.heads[RUN_ID])

    assert store.events_for(RUN_ID) == (event,)
    database.events[RUN_ID][0] = DriverRow({**database.events[RUN_ID][0], "unexpected": "column"})
    with pytest.raises(LifecycleStoreCorruptionError, match="unexpected shape"):
        store.events_for(RUN_ID)


def test_insert_conflict_is_typed_and_does_not_retry_or_update_the_head() -> None:
    database = _Database()
    database.fail_on = ("INSERT INTO rsd_canary.lifecycle_events", _DriverError("23505"))
    store = _store(database)

    with pytest.raises(LifecycleStoreConflictError) as raised:
        store.ingest(
            LifecycleEventIntent(
                run_id=RUN_ID,
                event_type=LifecycleEventType.RUN_CREATED,
                detail="created",
            ),
            _builder(EVENT_IDS[0]),
        )

    assert raised.value.__cause__ is None
    assert database.events == {}
    assert database.heads == {}
    assert (
        sum(
            query.startswith("INSERT INTO rsd_canary.lifecycle_events")
            for query, _ in database.calls
        )
        == 1
    )


@pytest.mark.parametrize(
    ("sqlstate", "error_type"),
    [
        ("23505", LifecycleStoreConflictError),
        ("40001", LifecycleStoreTransientError),
        ("08006", LifecycleStoreUnavailableError),
    ],
)
def test_driver_failures_are_typed_and_never_retried_or_leaked(
    sqlstate: str, error_type: type[Exception]
) -> None:
    database = _Database()
    database.fail_on = ("SELECT pg_advisory_xact_lock", _DriverError(sqlstate))
    store = _store(database)

    with pytest.raises(error_type) as raised:
        store.events_for(RUN_ID)

    assert raised.value.__cause__ is None
    assert database.transactions == ["begin", "rollback"]
    assert len(database.calls) == 2


def test_store_has_no_driver_or_connection_configuration_dependency() -> None:
    import omninode_rsd.lifecycle.postgres.store as store_module

    source = Path(store_module.__file__).read_text(encoding="utf-8")
    assert "psycopg" not in source
    assert "os.environ" not in source
