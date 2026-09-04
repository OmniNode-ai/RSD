"""Opt-in PostgreSQL integration coverage through an externally injected factory.

An external test plugin or local test configuration supplies a
``postgres_lifecycle_connection_factory`` fixture only when
``--postgres-integration`` is selected.  The fixture must target a fresh,
disposable isolated database for each test and return a fresh transaction-
capable connection context manager for every call against that target. Each
yielded connection must report an idle transaction state before the migration
runner starts. This suite never discovers or configures a database.
"""

from __future__ import annotations

import json
from collections.abc import Callable, Iterator, Mapping
from concurrent.futures import ThreadPoolExecutor
from contextlib import AbstractContextManager, contextmanager
from datetime import UTC, datetime
from typing import Protocol, cast

import pytest

from omninode_rsd.lifecycle import (
    LifecycleEventIngress,
    LifecycleEventIntent,
    LifecycleEventType,
)
from omninode_rsd.lifecycle.postgres import (
    DelegationClaimIdentityV1,
    DelegationClaimResult,
    LifecycleMigration,
    LifecycleStoreCorruptionError,
    PostgresDelegationClaimStore,
    PostgresLifecycleEventLog,
    PostgresLifecycleMigrationRunner,
    discover_lifecycle_migrations,
)

from .support import EVENT_IDS, RUN_ID

pytestmark = pytest.mark.integration


class _Result(Protocol):
    def fetchone(self) -> Mapping[str, object] | tuple[object, ...] | None: ...

    def fetchall(self) -> list[Mapping[str, object] | tuple[object, ...]]: ...


class _Connection(Protocol):
    def execute(self, query: str, params: tuple[object, ...] = ()) -> _Result: ...

    def commit(self) -> None: ...

    def rollback(self) -> None: ...

    def is_transaction_idle(self) -> bool: ...

    def transaction(self) -> AbstractContextManager[object]: ...


type _ConnectionFactory = Callable[[], AbstractContextManager[_Connection]]


def _connection_factory(request: pytest.FixtureRequest) -> _ConnectionFactory:
    if not request.config.getoption("--postgres-integration"):
        pytest.skip("PostgreSQL integration is opt-in; pass --postgres-integration with a fixture")
    try:
        fixture = request.getfixturevalue("postgres_lifecycle_connection_factory")
    except pytest.FixtureLookupError:
        pytest.fail(
            "--postgres-integration requires postgres_lifecycle_connection_factory "
            "from a test plugin"
        )
    if not callable(fixture):
        pytest.fail("postgres_lifecycle_connection_factory must be callable")
    return cast(_ConnectionFactory, fixture)


def _bootstrap_fresh_target(factory: _ConnectionFactory) -> PostgresLifecycleMigrationRunner:
    runner = PostgresLifecycleMigrationRunner(factory)
    assert runner.apply_pending() == discover_lifecycle_migrations()
    return runner


def _with_rsd_canary_search_path(factory: _ConnectionFactory) -> _ConnectionFactory:
    """Yield idle migration leases where the durable schema is search-path visible."""

    @contextmanager
    def configured_connection() -> Iterator[_Connection]:
        with factory() as connection:
            connection.execute("SET search_path TO rsd_canary, public;")
            connection.commit()
            assert connection.is_transaction_idle() is True
            yield connection

    return configured_connection


def _scalar(
    connection: _Connection,
    query: str,
    params: tuple[object, ...] = (),
) -> object:
    row = connection.execute(query, params).fetchone()
    assert row is not None
    if type(row) is tuple:
        assert len(row) == 1
        return row[0]
    assert isinstance(row, Mapping)
    assert set(row) == {"value"}
    return row["value"]


def _assert_migration_ledger_is_absent(factory: _ConnectionFactory) -> None:
    """Prove the runner, rather than the fixture, owns fresh-target bootstrap."""

    with factory() as connection:
        connection.execute("BEGIN;")
        try:
            relation_name = _scalar(
                connection,
                "SELECT to_regclass(%s)::text AS value",
                ("rsd_canary.schema_migrations",),
            )
        except Exception:
            connection.rollback()
            raise
        connection.commit()
    assert relation_name is None


def _builder() -> LifecycleEventIngress:
    return LifecycleEventIngress(
        event_id_factory=lambda: EVENT_IDS[0],
        clock=lambda: datetime(2026, 1, 1, tzinfo=UTC),
    )


def _claim_identity() -> DelegationClaimIdentityV1:
    return DelegationClaimIdentityV1(
        schema_version="rsd.delegation-claim-identity.v1",
        authorization_digest="a" * 64,
        claim_binding_sha256="b" * 64,
    )


def _expect_database_error(
    factory: _ConnectionFactory,
    query: str,
    params: tuple[object, ...],
    expected_message: str,
) -> None:
    with factory() as connection:
        connection.execute("BEGIN;")
        try:
            connection.execute(query, params)
        except Exception as error:
            connection.rollback()
            assert expected_message in str(error).lower()
        else:
            connection.rollback()
            pytest.fail("database operation unexpectedly succeeded")


def test_runner_bootstraps_a_fresh_target_then_reruns_and_rolls_back_atomically(
    request: pytest.FixtureRequest,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    factory = _connection_factory(request)
    _assert_migration_ledger_is_absent(factory)
    runner = _bootstrap_fresh_target(factory)
    manifest = discover_lifecycle_migrations()

    assert runner.apply_pending() == ()
    with factory() as connection:
        connection.execute("BEGIN;")
        assert _scalar(
            connection,
            "SELECT count(*) AS value FROM rsd_canary.schema_migrations",
        ) == len(manifest)
        connection.commit()

    import omninode_rsd.lifecycle.postgres.migrations as migrations

    committed_then_rolled_back = LifecycleMigration.from_content(
        version=manifest[-1].version + 1,
        name="atomic_probe",
        content="CREATE TABLE rsd_canary.atomic_probe (id BIGINT PRIMARY KEY);\n",
    )
    broken = LifecycleMigration.from_content(
        version=committed_then_rolled_back.version + 1,
        name="rollback_probe",
        content="SELECT 1 / 0;\n",
    )
    monkeypatch.setattr(
        migrations,
        "discover_lifecycle_migrations",
        lambda: (*manifest, committed_then_rolled_back, broken),
    )
    try:
        runner.apply_pending()
    except Exception as error:
        assert "division by zero" in str(error).lower()
    else:
        pytest.fail("broken migration unexpectedly succeeded")

    with factory() as connection:
        connection.execute("BEGIN;")
        assert _scalar(
            connection,
            "SELECT count(*) AS value FROM rsd_canary.schema_migrations",
        ) == len(manifest)
        assert (
            _scalar(
                connection,
                "SELECT to_regclass(%s)::text AS value",
                ("rsd_canary.atomic_probe",),
            )
            is None
        )
        connection.commit()


def test_runner_reruns_when_the_ledger_is_visible_through_search_path(
    request: pytest.FixtureRequest,
) -> None:
    factory = _with_rsd_canary_search_path(_connection_factory(request))
    runner = _bootstrap_fresh_target(factory)

    assert runner.apply_pending() == ()


def test_append_read_tamper_trigger_and_foreign_key_constraints_are_real_postgresql_behavior(
    request: pytest.FixtureRequest,
) -> None:
    factory = _connection_factory(request)
    _bootstrap_fresh_target(factory)
    store = PostgresLifecycleEventLog(factory)
    event = store.ingest(
        LifecycleEventIntent(
            run_id=RUN_ID,
            event_type=LifecycleEventType.RUN_CREATED,
            detail="created",
        ),
        _builder(),
    )

    assert store.events_for(RUN_ID) == (event,)
    _expect_database_error(
        factory,
        "UPDATE rsd_canary.lifecycle_events SET detail = detail WHERE run_id = %s",
        (RUN_ID,),
        "append-only",
    )

    missing_run_id = EVENT_IDS[1]
    missing_hash = "a" * 64
    projection = json.dumps(
        {
            "schema_version": "rsd.lifecycle-projection.v1",
            "run_id": str(missing_run_id),
            "state": "CREATED",
            "last_sequence": 1,
            "last_event_hash": missing_hash,
            "event_stream_hash": missing_hash,
            "projection_checksum": missing_hash,
        }
    )
    _expect_database_error(
        factory,
        """
        INSERT INTO rsd_canary.lifecycle_run_heads (
            run_id, state, last_sequence, last_event_hash, event_stream_hash,
            projection_checksum, projection_json
        ) VALUES (%s, %s, %s, %s, %s, %s, %s::jsonb)
        """,
        (
            missing_run_id,
            "CREATED",
            1,
            missing_hash,
            missing_hash,
            missing_hash,
            projection,
        ),
        "foreign key",
    )

    with factory() as connection:
        connection.execute("BEGIN;")
        connection.execute(
            "UPDATE rsd_canary.lifecycle_run_heads SET projection_checksum = %s WHERE run_id = %s",
            ("0" * 64, RUN_ID),
        )
        connection.commit()
    with pytest.raises(LifecycleStoreCorruptionError):
        store.events_for(RUN_ID)


def test_concurrent_migration_runners_record_one_manifest_prefix(
    request: pytest.FixtureRequest,
) -> None:
    factory = _connection_factory(request)
    manifest = discover_lifecycle_migrations()
    runner = PostgresLifecycleMigrationRunner(factory)

    with ThreadPoolExecutor(max_workers=2) as executor:
        first = executor.submit(runner.apply_pending)
        second = executor.submit(runner.apply_pending)
        results = (first.result(timeout=10), second.result(timeout=10))

    assert sorted(results, key=len) == [(), manifest]
    with factory() as connection:
        connection.execute("BEGIN;")
        assert _scalar(
            connection,
            "SELECT count(*) AS value FROM rsd_canary.schema_migrations",
        ) == len(manifest)
        connection.commit()


def test_delegation_claim_is_atomic_idempotent_and_append_only(
    request: pytest.FixtureRequest,
) -> None:
    factory = _connection_factory(request)
    _bootstrap_fresh_target(factory)
    store = PostgresDelegationClaimStore(factory)

    with ThreadPoolExecutor(max_workers=2) as executor:
        results = tuple(executor.map(lambda _: store.claim(_claim_identity()), range(2)))

    assert sorted(results) == [
        DelegationClaimResult.CLAIMED,
        DelegationClaimResult.NOT_CLAIMED,
    ]
    _expect_database_error(
        factory,
        "UPDATE rsd_canary.delegation_claims SET claim_binding_sha256 = claim_binding_sha256",
        (),
        "append-only",
    )
