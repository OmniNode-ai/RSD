"""Transactional adapter for applying packaged lifecycle migrations.

The adapter receives a caller-owned connection context manager.  It has no
endpoint, credential, pool, or runtime-configuration surface.
"""

from __future__ import annotations

from collections.abc import Callable, Mapping
from contextlib import AbstractContextManager
from typing import Final, Protocol

from omninode_rsd.lifecycle.postgres.migrations import (
    AppliedLifecycleMigration,
    LifecycleMigration,
    MigrationLedgerVerificationError,
    pending_lifecycle_migrations,
)

_BEGIN_SQL: Final[str] = "BEGIN;"
_MIGRATION_LOCK_SQL: Final[str] = "SELECT pg_advisory_xact_lock(hashtextextended(%s::text, 0));"
_MIGRATION_LOCK_KEY: Final[str] = "rsd_canary.lifecycle_migrations"
_LEDGER_EXISTS_SQL: Final[str] = (
    "SELECT to_regclass('rsd_canary.schema_migrations') IS NOT NULL AS relation_exists;"
)
_READ_LEDGER_SQL: Final[str] = """
SELECT version, name, checksum
FROM rsd_canary.schema_migrations
ORDER BY version ASC
"""
_INSERT_LEDGER_SQL: Final[str] = """
INSERT INTO rsd_canary.schema_migrations (version, name, checksum)
VALUES (%s, %s, %s)
"""
_LEDGER_EXISTS_COLUMNS: Final[tuple[str, ...]] = ("relation_exists",)


class PostgresMigrationResult(Protocol):
    """Minimal result protocol required by the transactional migration adapter."""

    def fetchone(self) -> Mapping[str, object] | tuple[object, ...] | None: ...

    def fetchall(self) -> list[Mapping[str, object] | tuple[object, ...]]: ...


class PostgresMigrationConnection(Protocol):
    """One invocation-owned, transaction-idle PostgreSQL connection lease.

    The factory must yield a dedicated lease for every runner invocation.  It
    must not wrap caller-owned transactional work, and it may release or close
    the lease only through its own context-manager exit semantics.  If a login
    migrator enters a separately provisioned NOLOGIN owner role, the factory
    must complete that caller-owned setup before yielding this idle lease. The
    runner never calls a close or release method itself.
    """

    def execute(self, query: str, params: tuple[object, ...] = ()) -> PostgresMigrationResult: ...

    def commit(self) -> None: ...

    def rollback(self) -> None: ...

    def is_transaction_idle(self) -> bool:
        """Return ``True`` only when no transaction is active on this lease."""


type PostgresMigrationConnectionFactory = Callable[
    [], AbstractContextManager[PostgresMigrationConnection]
]


class MigrationConnectionStateError(RuntimeError):
    """Raised when a factory yields a connection that cannot own a migration transaction."""


class PostgresLifecycleMigrationRunner:
    """Apply the packaged manifest in one runner-owned PostgreSQL transaction.

    This is a trusted, privileged adapter boundary.  External canonical
    provisioning owns the database and identities: it must assign a NOLOGIN
    owner and grant this adapter only the migration operations it requires. A
    login migrator may enter that separately provisioned owner role before its
    factory yields an idle lease; this runner accepts no role names and does
    not configure roles. The runner never creates roles, grants privileges,
    reads configuration, or accepts a database endpoint. It validates an
    existing ledger against the packaged manifest before it executes any
    pending SQL.
    """

    def __init__(self, connection_factory: PostgresMigrationConnectionFactory) -> None:
        self._connection_factory = connection_factory

    def apply_pending(self) -> tuple[LifecycleMigration, ...]:
        """Apply and record the exact pending manifest suffix atomically.

        The transaction-scoped advisory lock serializes only callers that use
        this adapter and whose database ACL prevents bypass writes.  It is not
        an authorization boundary for independently privileged database users.
        The factory must yield a fresh, exclusive connection lease whose
        ``is_transaction_idle()`` method returns ``True`` immediately before
        the runner begins its transaction. A commit failure has an ambiguous
        outcome even if rollback succeeds, so operators must reconcile the
        migration ledger with the packaged manifest before retrying.
        """

        with self._connection_factory() as connection:
            transaction_started = False
            commit_attempted = False
            try:
                if connection.is_transaction_idle() is not True:
                    raise MigrationConnectionStateError(
                        "migration connection must be a fresh transaction-idle lease"
                    )
                connection.execute(_BEGIN_SQL)
                transaction_started = True
                connection.execute(_MIGRATION_LOCK_SQL, (_MIGRATION_LOCK_KEY,))
                applied = self._read_applied_migrations(connection)
                pending = pending_lifecycle_migrations(applied)
                for migration in pending:
                    connection.execute(migration.content)
                    connection.execute(
                        _INSERT_LEDGER_SQL,
                        (migration.version, migration.name, migration.sha256),
                    )
                commit_attempted = True
                connection.commit()
                return pending
            except Exception as primary_error:
                if commit_attempted:
                    primary_error.add_note(
                        "migration commit failed; transaction outcome is ambiguous; "
                        "reconcile the migration ledger before retrying"
                    )
                if transaction_started:
                    try:
                        connection.rollback()
                    except Exception as rollback_error:
                        primary_error.add_note(
                            "migration rollback also failed; transaction outcome "
                            "remains ambiguous; reconcile the migration ledger before retrying"
                        )
                        primary_error.add_note(
                            f"rollback failure: {type(rollback_error).__name__}: {rollback_error}"
                        )
                        raise primary_error from rollback_error
                raise

    @staticmethod
    def _read_applied_migrations(
        connection: PostgresMigrationConnection,
    ) -> tuple[AppliedLifecycleMigration, ...]:
        existence_row = connection.execute(_LEDGER_EXISTS_SQL).fetchone()
        if existence_row is None:
            raise MigrationLedgerVerificationError(
                "migration ledger relation check returned no row"
            )
        relation_exists = _row_values(existence_row, _LEDGER_EXISTS_COLUMNS)["relation_exists"]
        if type(relation_exists) is not bool:
            raise MigrationLedgerVerificationError("migration ledger relation check is not valid")
        if not relation_exists:
            return ()
        return tuple(
            AppliedLifecycleMigration.from_row(row)
            for row in connection.execute(_READ_LEDGER_SQL).fetchall()
        )


def _row_values(
    row: Mapping[str, object] | tuple[object, ...], columns: tuple[str, ...]
) -> dict[str, object]:
    if type(row) is tuple:
        if len(row) != len(columns):
            raise MigrationLedgerVerificationError("migration ledger row has an unexpected shape")
        return dict(zip(columns, row, strict=True))
    if isinstance(row, Mapping) and set(row) == set(columns):
        return {column: row[column] for column in columns}
    raise MigrationLedgerVerificationError("migration ledger row has an unexpected shape")
