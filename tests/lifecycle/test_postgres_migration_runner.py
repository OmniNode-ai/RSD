"""Protocol-fake tests for transactional PostgreSQL lifecycle migration application."""

from __future__ import annotations

from concurrent.futures import ThreadPoolExecutor
from contextlib import AbstractContextManager
from threading import Barrier, Lock

import pytest

from omninode_rsd.lifecycle.postgres import (
    MigrationConnectionStateError,
    MigrationLedgerVerificationError,
    PostgresLifecycleMigrationRunner,
    discover_lifecycle_migrations,
)


class _DriverRow(dict[str, object]):
    """Representative mapping subclass returned by a PostgreSQL driver."""


class _Result:
    def __init__(self, rows: list[_DriverRow]) -> None:
        self._rows = rows

    def fetchone(self) -> _DriverRow | None:
        return self._rows[0] if self._rows else None

    def fetchall(self) -> list[_DriverRow]:
        return list(self._rows)


class _Database:
    def __init__(self) -> None:
        self.schema_exists = False
        self.ledger: list[_DriverRow] = []
        self.calls: list[tuple[str, tuple[object, ...]]] = []
        self.transactions: list[str] = []
        self.fail_on: str | None = None
        self.commit_failure: Exception | None = None
        self.rollback_failure: Exception | None = None
        self.force_not_idle = False
        self.idle_checks = 0
        self.context_entries = 0
        self.context_exits = 0
        self.incompatible_ledger = False
        self.catalog_relation_override: object | None = None
        self.use_catalog_relation_override = False
        self._snapshot: tuple[bool, list[_DriverRow]] | None = None

    def begin(self) -> None:
        assert self._snapshot is None
        self._snapshot = (self.schema_exists, [self._copy_row(row) for row in self.ledger])
        self.transactions.append("begin")

    def commit(self) -> None:
        assert self._snapshot is not None
        self.transactions.append("commit")
        if self.commit_failure is not None:
            raise self.commit_failure
        self._snapshot = None

    def rollback(self) -> None:
        assert self._snapshot is not None
        self.transactions.append("rollback")
        if self.rollback_failure is not None:
            raise self.rollback_failure
        self.schema_exists, self.ledger = self._snapshot
        self._snapshot = None

    def is_transaction_idle(self) -> bool:
        self.idle_checks += 1
        return not self.force_not_idle and self._snapshot is None

    @staticmethod
    def _copy_row(row: _DriverRow) -> _DriverRow:
        return _DriverRow(row)


class _Connection(AbstractContextManager["_Connection"]):
    def __init__(self, database: _Database) -> None:
        self._database = database

    def __enter__(self) -> _Connection:
        self._database.context_entries += 1
        return self

    def __exit__(self, exc_type: object, exc: object, traceback: object) -> None:
        self._database.context_exits += 1
        return None

    def commit(self) -> None:
        self._database.commit()

    def rollback(self) -> None:
        self._database.rollback()

    def is_transaction_idle(self) -> bool:
        return self._database.is_transaction_idle()

    def execute(self, query: str, params: tuple[object, ...] = ()) -> _Result:
        normalized = " ".join(query.split())
        self._database.calls.append((normalized, params))
        if self._database.fail_on is not None and normalized.startswith(self._database.fail_on):
            raise RuntimeError("database execution failed")
        if normalized == "BEGIN;":
            self._database.begin()
            return _Result([])
        if normalized.startswith("SELECT pg_advisory_xact_lock"):
            return _Result([])
        if normalized.startswith("SELECT to_regclass"):
            relation_name: object | None = (
                "rsd_canary.schema_migrations" if self._database.schema_exists else None
            )
            if self._database.use_catalog_relation_override:
                relation_name = self._database.catalog_relation_override
            return _Result([_DriverRow(relation_name=relation_name)])
        if normalized.startswith("SELECT version, name, checksum"):
            if self._database.incompatible_ledger:
                raise RuntimeError("schema_migrations has an incompatible shape")
            return _Result([_Database._copy_row(row) for row in self._database.ledger])
        if normalized.startswith("CREATE SCHEMA rsd_canary;"):
            self._database.schema_exists = True
            return _Result([])
        if normalized.startswith("INSERT INTO rsd_canary.schema_migrations"):
            version, name, checksum = params
            self._database.ledger.append(_DriverRow(version=version, name=name, checksum=checksum))
            return _Result([])
        raise AssertionError(f"unexpected query: {normalized}")


class _ConnectionFactory:
    def __init__(self, database: _Database) -> None:
        self._database = database
        self.calls = 0
        self.connections: list[_Connection] = []

    def __call__(self) -> _Connection:
        self.calls += 1
        connection = _Connection(self._database)
        self.connections.append(connection)
        return connection


class _ConcurrentBootstrapDatabase:
    """Small lock-aware fake proving fresh bootstrap is serialized before probing."""

    def __init__(self) -> None:
        self.schema_exists = False
        self.ledger: list[_DriverRow] = []
        self.migration_executions = 0
        self.ledger_reads = 0
        self._begin_barrier = Barrier(2)
        self._migration_lock = Lock()


class _ConcurrentBootstrapConnection(AbstractContextManager["_ConcurrentBootstrapConnection"]):
    def __init__(self, database: _ConcurrentBootstrapDatabase) -> None:
        self._database = database
        self._transaction_started = False
        self._migration_lock_held = False

    def __enter__(self) -> _ConcurrentBootstrapConnection:
        return self

    def __exit__(self, exc_type: object, exc: object, traceback: object) -> None:
        if self._migration_lock_held:
            self._database._migration_lock.release()
            self._migration_lock_held = False
        return None

    def commit(self) -> None:
        assert self._transaction_started
        self._transaction_started = False
        assert self._migration_lock_held
        self._database._migration_lock.release()
        self._migration_lock_held = False

    def rollback(self) -> None:
        assert self._transaction_started
        self._transaction_started = False
        if self._migration_lock_held:
            self._database._migration_lock.release()
            self._migration_lock_held = False

    def is_transaction_idle(self) -> bool:
        return not self._transaction_started

    def execute(self, query: str, params: tuple[object, ...] = ()) -> _Result:
        normalized = " ".join(query.split())
        if normalized == "BEGIN;":
            assert not self._transaction_started
            self._transaction_started = True
            self._database._begin_barrier.wait(timeout=5)
            return _Result([])
        if normalized.startswith("SELECT pg_advisory_xact_lock"):
            assert self._database._migration_lock.acquire(timeout=5)
            self._migration_lock_held = True
            return _Result([])
        if normalized.startswith("SELECT to_regclass"):
            relation_name = "rsd_canary.schema_migrations" if self._database.schema_exists else None
            return _Result([_DriverRow(relation_name=relation_name)])
        if normalized.startswith("SELECT version, name, checksum"):
            self._database.ledger_reads += 1
            return _Result([_Database._copy_row(row) for row in self._database.ledger])
        if normalized.startswith("CREATE SCHEMA rsd_canary;"):
            assert not self._database.schema_exists
            self._database.schema_exists = True
            self._database.migration_executions += 1
            return _Result([])
        if normalized.startswith("INSERT INTO rsd_canary.schema_migrations"):
            version, name, checksum = params
            self._database.ledger.append(_DriverRow(version=version, name=name, checksum=checksum))
            return _Result([])
        raise AssertionError(f"unexpected query: {normalized}")


class _ConcurrentBootstrapConnectionFactory:
    def __init__(self, database: _ConcurrentBootstrapDatabase) -> None:
        self._database = database

    def __call__(self) -> _ConcurrentBootstrapConnection:
        return _ConcurrentBootstrapConnection(self._database)


def _runner(database: _Database) -> PostgresLifecycleMigrationRunner:
    return PostgresLifecycleMigrationRunner(_ConnectionFactory(database))


def test_runner_locks_validates_and_records_each_pending_resource_in_one_transaction() -> None:
    database = _Database()
    manifest = discover_lifecycle_migrations()
    factory = _ConnectionFactory(database)
    runner = PostgresLifecycleMigrationRunner(factory)

    applied = runner.apply_pending()

    assert applied == manifest
    assert database.transactions == ["begin", "commit"]
    statements = [query for query, _ in database.calls]
    assert statements[:3] == [
        "BEGIN;",
        "SELECT pg_advisory_xact_lock(hashtextextended(%s::text, 0));",
        "SELECT to_regclass('rsd_canary.schema_migrations')::text AS relation_name;",
    ]
    migration_index = statements.index(" ".join(manifest[0].content.split()))
    assert (
        "SELECT version, name, checksum FROM rsd_canary.schema_migrations ORDER BY version ASC"
        not in statements[:migration_index]
    )
    ledger_index = statements.index(
        "INSERT INTO rsd_canary.schema_migrations (version, name, checksum) VALUES (%s, %s, %s)"
    )
    assert migration_index < ledger_index
    assert database.ledger == [
        _DriverRow(
            version=manifest[0].version,
            name=manifest[0].name,
            checksum=manifest[0].sha256,
        )
    ]

    assert runner.apply_pending() == ()
    assert database.transactions == ["begin", "commit", "begin", "commit"]
    assert sum(query.startswith("CREATE SCHEMA rsd_canary;") for query, _ in database.calls) == 1
    assert factory.calls == 2
    assert factory.connections[0] is not factory.connections[1]
    assert database.idle_checks == 2
    assert database.context_entries == database.context_exits == 2


def test_runner_reads_the_ledger_only_after_a_present_catalog_probe() -> None:
    database = _Database()
    migration = discover_lifecycle_migrations()[0]
    database.schema_exists = True
    database.ledger = [
        _DriverRow(
            version=migration.version,
            name=migration.name,
            checksum=migration.sha256,
        )
    ]

    assert _runner(database).apply_pending() == ()

    assert [query for query, _ in database.calls] == [
        "BEGIN;",
        "SELECT pg_advisory_xact_lock(hashtextextended(%s::text, 0));",
        "SELECT to_regclass('rsd_canary.schema_migrations')::text AS relation_name;",
        "SELECT version, name, checksum FROM rsd_canary.schema_migrations ORDER BY version ASC",
    ]
    assert database.transactions == ["begin", "commit"]


def test_runner_rejects_an_unexpected_catalog_relation_identity() -> None:
    database = _Database()
    database.use_catalog_relation_override = True
    database.catalog_relation_override = "rsd_canary.unexpected_relation"

    with pytest.raises(MigrationLedgerVerificationError, match="relation check is not valid"):
        _runner(database).apply_pending()

    assert database.transactions == ["begin", "rollback"]


def test_runner_fails_closed_when_an_existing_ledger_has_an_incompatible_shape() -> None:
    database = _Database()
    database.schema_exists = True
    database.incompatible_ledger = True

    with pytest.raises(RuntimeError, match="incompatible shape"):
        _runner(database).apply_pending()

    statements = [query for query, _ in database.calls]
    assert statements == [
        "BEGIN;",
        "SELECT pg_advisory_xact_lock(hashtextextended(%s::text, 0));",
        "SELECT to_regclass('rsd_canary.schema_migrations')::text AS relation_name;",
        "SELECT version, name, checksum FROM rsd_canary.schema_migrations ORDER BY version ASC",
    ]
    assert database.transactions == ["begin", "rollback"]


def test_concurrent_fresh_bootstrap_serializes_before_the_catalog_probe() -> None:
    database = _ConcurrentBootstrapDatabase()
    runner = PostgresLifecycleMigrationRunner(_ConcurrentBootstrapConnectionFactory(database))
    manifest = discover_lifecycle_migrations()

    with ThreadPoolExecutor(max_workers=2) as executor:
        first = executor.submit(runner.apply_pending)
        second = executor.submit(runner.apply_pending)
        results = (first.result(timeout=5), second.result(timeout=5))

    assert sorted(results, key=len) == [(), manifest]
    assert database.migration_executions == 1
    assert database.ledger_reads == 1
    assert database.ledger == [
        _DriverRow(
            version=manifest[0].version,
            name=manifest[0].name,
            checksum=manifest[0].sha256,
        )
    ]


def test_runner_rejects_non_idle_connection_before_beginning_a_transaction() -> None:
    database = _Database()
    database.force_not_idle = True
    factory = _ConnectionFactory(database)

    with pytest.raises(MigrationConnectionStateError, match="fresh transaction-idle lease"):
        PostgresLifecycleMigrationRunner(factory).apply_pending()

    assert database.calls == []
    assert database.transactions == []
    assert database.idle_checks == 1
    assert factory.calls == 1
    assert database.context_entries == database.context_exits == 1


def test_runner_rolls_back_ddl_and_ledger_when_recording_fails() -> None:
    database = _Database()
    database.fail_on = "INSERT INTO rsd_canary.schema_migrations"

    with pytest.raises(RuntimeError, match="database execution failed"):
        _runner(database).apply_pending()

    assert database.transactions == ["begin", "rollback"]
    assert database.schema_exists is False
    assert database.ledger == []


def test_runner_rejects_ledger_drift_before_executing_packaged_ddl() -> None:
    database = _Database()
    migration = discover_lifecycle_migrations()[0]
    database.schema_exists = True
    database.ledger = [
        _DriverRow(
            version=migration.version,
            name=migration.name,
            checksum="0" * 64,
        )
    ]

    with pytest.raises(MigrationLedgerVerificationError, match="checksum drift"):
        _runner(database).apply_pending()

    assert database.transactions == ["begin", "rollback"]
    assert not any(query.startswith("CREATE SCHEMA rsd_canary;") for query, _ in database.calls)


def test_commit_failure_rolls_back_once_and_keeps_its_ambiguous_outcome_note() -> None:
    database = _Database()
    commit_error = RuntimeError("commit failed")
    database.commit_failure = commit_error

    with pytest.raises(RuntimeError, match="commit failed") as raised:
        _runner(database).apply_pending()

    assert raised.value is commit_error
    assert raised.value.__cause__ is None
    assert database.transactions == ["begin", "commit", "rollback"]
    assert database.transactions.count("rollback") == 1
    assert database.schema_exists is False
    assert database.ledger == []
    assert any("reconcile the migration ledger" in note for note in raised.value.__notes__)


def test_commit_and_rollback_failures_preserve_commit_failure_with_rollback_context() -> None:
    database = _Database()
    commit_error = RuntimeError("commit failed")
    rollback_error = RuntimeError("rollback failed")
    database.commit_failure = commit_error
    database.rollback_failure = rollback_error

    with pytest.raises(RuntimeError, match="commit failed") as raised:
        _runner(database).apply_pending()

    assert raised.value is commit_error
    assert raised.value.__cause__ is rollback_error
    assert database.transactions == ["begin", "commit", "rollback"]
    assert database.transactions.count("rollback") == 1
    assert any("rollback also failed" in note for note in raised.value.__notes__)
    assert any(
        "rollback failure: RuntimeError: rollback failed" in note for note in raised.value.__notes__
    )
