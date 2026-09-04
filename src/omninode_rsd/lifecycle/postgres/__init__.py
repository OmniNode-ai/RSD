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

__all__ = [
    "AppliedLifecycleMigration",
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
    "discover_lifecycle_migrations",
    "pending_lifecycle_migrations",
]
