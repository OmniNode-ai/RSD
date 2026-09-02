# omninode-rsd

[![License: MIT](https://img.shields.io/badge/License-MIT-yellow.svg)](LICENSE)

`omninode-rsd` is a small Python library for creating, storing, and replaying
deterministic lifecycle events. It has no network client, service endpoint, or
deployment configuration.

## Breaking package rename (pre-1.0)

The distribution is now `omninode-rsd` and its Python import root is
`omninode_rsd`. The former `rsd-canary` distribution and `rsd_canary` imports
are removed; this release provides no compatibility package or re-export.
Remove the former distribution from an environment before installing this one
to avoid retaining obsolete package files.

## PostgreSQL lifecycle schema

The package includes a versioned PostgreSQL schema migration manifest for the
durable lifecycle store. `discover_lifecycle_migrations()` only reads packaged
resources and reports their version, name, SQL content, and SHA-256 digest. It
never opens a database connection, reads configuration, or executes DDL.

`PostgresLifecycleMigrationRunner` applies the manifest through a
caller-supplied connection context manager. It starts the transaction, acquires
a transaction-scoped migration advisory lock, then probes the fixed ledger
relation. If it is absent, the applied prefix is empty and migration `001` plus
its ledger row are created in that same transaction. If it is present, the
runner reads the ledger, verifies its typed `version`, `name`, and `checksum`
rows are the exact ordered manifest prefix, executes each pending resource,
records its matching ledger row, and commits. Any failure rolls back the same
transaction. The packaged SQL resource contains no transaction control,
endpoint, credential, or role configuration. The runner never re-runs an
applied migration or repairs drift in place.
`001_create_lifecycle_store.sql` deliberately has no fail-open `IF NOT EXISTS`
clauses: an existing or incompatible object aborts the migration for operator
investigation.

Each runner invocation requires a fresh, exclusive connection lease whose
adapter reports an idle transaction state before the runner issues `BEGIN`.
The factory context owns connection release or closure; the runner never closes
or returns it directly. A commit error leaves the database outcome ambiguous,
including when the subsequent rollback reports success. Operators must inspect
the migration ledger against the packaged manifest before retrying; when both
commit and rollback fail, the original commit error retains the rollback error
as its cause and records the reconciliation requirement.

The PostgreSQL adapters are trusted boundaries, not authorization systems.
External canonical provisioning MUST assign a dedicated NOLOGIN owner to the
`rsd_canary` schema and every lifecycle object. This literal is a persisted
PostgreSQL schema identifier, intentionally distinct from the renamed Python
import root. A login migrator may enter that separately provisioned owner role
before its injected factory yields an idle lease; role selection is caller-owned
and the runner has no role-name configuration surface. Provisioning MUST grant
the runtime adapter exactly `USAGE` on the schema, `SELECT` and `INSERT` on
`lifecycle_events`, and `SELECT`, `INSERT`, and `UPDATE` on
`lifecycle_run_heads`; it must not grant that adapter access to
`schema_migrations`, or `UPDATE`, `DELETE`, or `TRUNCATE` on lifecycle events.
The reviewed migration adapter receives only the DDL and ledger read/insert
authority required for its controlled invocation. The package does not create
roles, set ownership, or grant privileges. The schema revokes `PUBLIC` access,
and has no `SECURITY DEFINER` function.

`PostgresLifecycleEventLog` accepts a caller-supplied callable that returns a
connection context manager. The caller owns its database driver and connection
configuration; the adapter has no DSN parsing, pool creation, migration
execution, or retry loop. It recomputes and verifies canonical event hashes and
projections on every write and read, without duplicating the Python hash logic
in SQL. Each ingestion uses one `READ COMMITTED` transaction and locks the
target run. That advisory lock coordinates only trusted adapter writers whose
strict database ACLs prevent bypass writes; it is not protection against other
independently privileged database users.

## Development

Use Python 3.12 or newer and uv:

```sh
uv sync --all-groups
uv run pytest
uv run mypy src/ --strict
uv run ruff format --check src/ tests/
uv run ruff check src/ tests/
```

`omninode-rsd` depends exactly on `omninode-grant-verifier` 0.1.0. The verifier
distribution exclusively owns the `omninode_grant_verifier` import package; the
root wheel does not include it. Until the verifier is published to a package
index, release both public artifacts together in a wheelhouse or release bundle.

The PostgreSQL integration suite is opt-in. It runs only with
`--postgres-integration` and an externally injected
`postgres_lifecycle_connection_factory` fixture for a fresh disposable isolated
database per test. The runner, rather than the fixture, bootstraps the fresh
schema and migration ledger; the package never discovers or configures that
database.

The bundled YAML file documents the states and transitions supported by the
library.

## Event ingestion

Use `InMemoryEventLog.ingest(intent, LifecycleEventIngress())` for in-memory
event creation. The log owns the run's sequence, prior hash, and lifecycle
state so construction and admission occur atomically. `append(event)` remains
available when an already constructed event must be verified and admitted.
The builder's event-ID and clock callbacks run inside the log's atomic critical
section, so they must be non-blocking and must not wait on other threads or
acquire locks in reverse order.

Use `parse_lifecycle_description()` from `omninode_rsd.lifecycle`
when a typed lifecycle-description model is needed; use
`load_lifecycle_description()` for the compatible dictionary representation.

## Replay verification

`verify_lifecycle_replay(events, replay)` validates a supplied replay artifact
without mutating either input. It accepts only an exact built-in `tuple` or
`list` event snapshot (not subclasses), then checks non-emptiness, strict event reconstruction, event identity
uniqueness, canonical replay input, artifact projection integrity, replay
checksum format, run identity, exact projection equality, and the transition
checksum. The projection event-stream hash and replay checksum intentionally
remain separate hash domains: the former includes persisted event observations,
while the latter uses deterministic transition material. Verification is a
trust boundary: it snapshots a supplied list but does not retain or mutate it.
It establishes correspondence with the supplied stream, not authenticity of a
self-consistent forged stream; provenance must be established separately.

The verifier's public messages are stable: `replay artifact is not valid`,
`replay input must be a tuple or list`, `replay input must not be empty`,
`replay input is not valid: <reason>`, `replay artifact is not valid: <reason>`,
`replay artifact checksum is not a lowercase SHA-256 digest`,
`replay artifact run_id does not match the event stream`,
`replay projection does not match the event stream`, and
`replay checksum does not match the event stream`.

## License

[MIT](LICENSE)
