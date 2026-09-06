"""Endpoint-agnostic PostgreSQL lifecycle adapters and schema migrations.

All adapters receive caller-owned connection context managers.  This package
does not discover endpoints, credentials, pools, or runtime configuration.
"""

from omninode_rsd.lifecycle.postgres.claim_store import (
    DelegationClaimIdentityV1,
    DelegationClaimResult,
    DelegationClaimStoreCorruptionError,
    DelegationClaimStoreError,
    DelegationClaimStoreUnavailableError,
    PostgresDelegationClaimStore,
)
from omninode_rsd.lifecycle.postgres.migrations import (
    AppliedLifecycleMigration,
    LifecycleMigration,
    MigrationDiscoveryError,
    MigrationLedgerVerificationError,
    discover_lifecycle_migrations,
    pending_lifecycle_migrations,
)
from omninode_rsd.lifecycle.postgres.migrations.runner import (
    MigrationConnectionStateError,
    PostgresLifecycleMigrationRunner,
    PostgresMigrationConnection,
    PostgresMigrationConnectionFactory,
    PostgresMigrationResult,
)
from omninode_rsd.lifecycle.postgres.store import (
    DurableLifecycleEventLog,
    LifecycleStoreConflictError,
    LifecycleStoreCorruptionError,
    LifecycleStoreError,
    LifecycleStoreTransientError,
    LifecycleStoreUnavailableError,
    PostgresConnection,
    PostgresConnectionFactory,
    PostgresLifecycleEventLog,
    PostgresResult,
)

_DELEGATED_CANARY_EXPORTS = frozenset(
    {
        "AsyncPostgresConnection",
        "AsyncPostgresConnectionFactory",
        "AsyncPostgresDelegatedCanaryStore",
        "AsyncPostgresResult",
        "DelegatedCanaryAttemptIdentityV2",
        "DelegatedCanaryDispatchDisposition",
        "DelegatedCanaryPrepareDisposition",
        "DelegatedCanaryReconciliationDisposition",
        "DelegatedCanaryReconciliationIdentityV1",
        "DelegatedCanaryStoreAmbiguousCommitError",
        "DelegatedCanaryStoreConflictError",
        "DelegatedCanaryStoreCorruptionError",
        "DelegatedCanaryStoreError",
        "DelegatedCanaryStoreUnavailableError",
        "DelegatedCanaryTerminalDisposition",
        "RawDelegationExecutionAuthorityV2",
    }
)


def __getattr__(name: str) -> object:
    """Load the canary adapter after the lifecycle aggregate is initialized.

    ``delegation`` imports the lifecycle aggregate, while the canary adapter
    depends on ``delegation_execution``.  Keeping only this new dependency at
    the package boundary prevents that pre-existing cycle; the resolved
    symbols are cached in the module and are otherwise ordinary exports.
    """

    if name not in _DELEGATED_CANARY_EXPORTS:
        raise AttributeError(f"module {__name__!r} has no attribute {name!r}")
    from omninode_rsd.lifecycle.postgres import delegated_canary_store

    value = getattr(delegated_canary_store, name)
    globals()[name] = value
    return value


__all__ = [
    "AppliedLifecycleMigration",
    "AsyncPostgresConnection",
    "AsyncPostgresConnectionFactory",
    "AsyncPostgresDelegatedCanaryStore",
    "AsyncPostgresResult",
    "DelegatedCanaryAttemptIdentityV2",
    "DelegatedCanaryDispatchDisposition",
    "DelegatedCanaryPrepareDisposition",
    "DelegatedCanaryReconciliationDisposition",
    "DelegatedCanaryReconciliationIdentityV1",
    "DelegatedCanaryStoreAmbiguousCommitError",
    "DelegatedCanaryStoreConflictError",
    "DelegatedCanaryStoreCorruptionError",
    "DelegatedCanaryStoreError",
    "DelegatedCanaryStoreUnavailableError",
    "DelegatedCanaryTerminalDisposition",
    "DelegationClaimIdentityV1",
    "DelegationClaimResult",
    "DelegationClaimStoreCorruptionError",
    "DelegationClaimStoreError",
    "DelegationClaimStoreUnavailableError",
    "DurableLifecycleEventLog",
    "LifecycleMigration",
    "LifecycleStoreConflictError",
    "LifecycleStoreCorruptionError",
    "LifecycleStoreError",
    "LifecycleStoreTransientError",
    "LifecycleStoreUnavailableError",
    "MigrationConnectionStateError",
    "MigrationDiscoveryError",
    "MigrationLedgerVerificationError",
    "PostgresConnection",
    "PostgresConnectionFactory",
    "PostgresDelegationClaimStore",
    "PostgresLifecycleEventLog",
    "PostgresLifecycleMigrationRunner",
    "PostgresMigrationConnection",
    "PostgresMigrationConnectionFactory",
    "PostgresMigrationResult",
    "PostgresResult",
    "RawDelegationExecutionAuthorityV2",
    "discover_lifecycle_migrations",
    "pending_lifecycle_migrations",
]
