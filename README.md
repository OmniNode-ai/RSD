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

The PostgreSQL integration suite is opt-in. It runs only with
`--postgres-integration` and an externally injected
`postgres_lifecycle_connection_factory` fixture for a fresh disposable isolated
database per test. The runner, rather than the fixture, bootstraps the fresh
schema and migration ledger; the package never discovers or configures that
database.

The bundled YAML file documents the states and transitions supported by the
library.

## Phase-B authorization

Phase-B has two non-interchangeable authorization stages. Phase-A remains a
compiler only and never authorizes either stage.

1. `InitialProvisioningIntentV1` is a signed pre-creation contract. It
   contains planned stable names, host authority, database/schema/role intent,
   immutable images, provider references, native transport policy, retention,
   owner/approver, and governed evidence hashes. It deliberately has no
   database OID, container ID, network ID, workload ID, volume ID, or runtime
   fingerprint. `provision_initial_journal()` explicitly creates its separate
   durable journal and external genesis tombstone. No authorization path
   creates or recreates that journal implicitly.
2. `authorize_initial_provisioning_and_execute()` accepts only the typed
   `create_isolated_empty_resources_v1` scope. Its callback receives an
   immutable `InitialProvisioningExecutionContext` containing the planned
   intent and provider expectations, not an observed proposal or a journal.
   The only accepted callback result is an
   `InitialProvisioningEffectReceiptV1` with newly observed resource IDs.
   Seed, backup, restore, reset, swap, and data-access operations are outside
   that scope.
3. A trusted signer must then issue `ObservedCandidateAttestationV1`. It binds
   the exact intent hash and creation-receipt hash to the actual PostgreSQL
   OID and service/network/workload/volume/container IDs. The existing
   `ProposalV1` and `RuntimeContractV1` are post-observation contracts: their
   actual identities, planned fields, and evidence must exactly match the
   attestation before `authorize_and_execute()` can admit an observed
   lifecycle effect.

Both stages have distinct Ed25519 signature domains, SQLite operation kinds,
journal state machines, idempotency domains, and external replay-tombstone
kinds. A receipt from either stage is audit data, never a bearer grant.
`InitialProvisioningJournalStatus` exposes only read-only diagnostics. An
interrupted initial genesis remains blocked until a signed
`InitialJournalGenesisReconciliationReceiptV1` either confirms the already
durable database-and-anchor pair or records an abandonment; reconciliation
never retries creation or clears the external tombstone.

`DisposableTransportProfile` is the canonical public transport enum:
`tls_verified_v1` and `unpublished_loopback_or_network_v1`. Planning inputs
must map to these exact native values before constructing the public contract:

| Planning profile | Native public value |
| --- | --- |
| verified TLS listener | `tls_verified_v1` |
| unpublished loopback or isolated-network listener | `unpublished_loopback_or_network_v1` |

Legacy spellings are not accepted.

`omninode_rsd.lifecycle.authorize_and_execute()` is the observed-lifecycle
mutation-admission boundary for a disposable acceptance workflow. It accepts
an injected Ed25519 trust anchor, leased provider-provenance adapter, provider
fingerprint policy, owner-only `SQLiteAuthorizationJournal` and
`SQLiteInitialProvisioningJournal`, mandatory `ProtocolReplayAuthority` plus
typed `ReplayAuthorityPolicyV1`, and one effect callback. It requires actual
detached-signature sidecars for the proposal, final contract, and evidence
artifacts; Phase-A signature markers alone never authorize.

The verifier uses its trusted UTC clock rather than a caller-provided time. It
reads bounded owner-only artifact files through one open root-directory
descriptor, runs Phase-A before and after provider inspection, and rejects
changed content, sidecars, unsafe file metadata, stale evidence, expired
retention, signer mismatch, provider mismatch, and replayed journal claims.
It first acquires a strict canonical-parent advisory lock keyed by the opened
parent/root device-and-inode identities and holds the root descriptor through
provider leasing, journal claim, effect execution, and terminal journal
transition. Path spelling aliases therefore converge on one lock, while root
replacement, rename, or lock replacement is checked before and after each
boundary. Lock acquisition is bounded: a concurrent writer receives a typed
busy error and a recursive lease receives a typed reentrant error.

The observed callback receives only immutable `VerifiedExecutionContext`: parsed
proposal/final-contract models, exact provider expectations, and a derived
idempotency key. It receives no artifact path, nonce, or journal handle. It
must return an `EffectReceiptV1` bound to that operation and idempotency key.
Before any observed effect can be admitted, a separate caller must explicitly
complete the initial stage above and invoke `provision_journal()` once with a
trusted Ed25519-signed `JournalGenesisReceiptV1`. That receipt commits to the
operation/proposal/final hashes, expected owner and approver, canonical journal path, fresh journal ID,
and journal schema digest, including the exact replay-policy digest.
Provisioning writes an owner-only pending marker before it claims a
create-once external genesis tombstone and creates the database. The
authorization path claims a second, operation tombstone before its local
journal claim or effect. That operation tombstone binds the signed journal ID,
operation, proposal, contract, final provider provenance, and derived
idempotency hashes. Local journal failure, deletion, rollback, or row removal
cannot release either tombstone. The authorization path never provisions or
recreates a journal: an absent journal, missing genesis artifact, moved
database/anchor, or incomplete genesis blocks before an effect. A pending
genesis can become current only through signed
`JournalGenesisReconciliationReceiptV1` recovery evidence; abandoned and
rotated identities remain blocked.

The replay authority is an explicit external trust boundary, not a convenience
cache: callers must inject a durable atomic create-once implementation and
there is no in-memory or default production adapter. `MacOSKeychainReplayAuthority`
uses Security.framework generic-password creation only. Its typed policy
supplies service and account namespace; neither is read from process
configuration or environment files. It stores only a public tombstone binding hash, never overwrites an
existing item, and treats duplicate/conflicting items as replay. The Keychain
tombstone is the governed external record that survives local file rollback;
deleting it is an explicit out-of-band governed destructive action, never an
authorization recovery step.

Tombstone accounts are derived from the typed replay policy, stage-specific
operation kind, and operation ID rather than a mutable local journal path. The
stored binding separately commits the journal identity and every applicable
intent, proposal, contract, provider, and idempotency hash. Moving local files
therefore cannot make a logical operation claimable again.

### Provider-crypto bootstrap

Provider material has a separate create-only bootstrap boundary. It is not a
runtime secret-delivery API and it does not authorize an effect by itself.
`SignerGenesisV1` is issuer-signed with its own Ed25519 domain and binds the
initial-intent digest, Keychain service/account/version/reference hash, seed
fingerprint, derived public key, and public-key fingerprint. The signer can
only be provisioned or loaded after that signature and intent binding are
verified; duplicate Keychain rows fail closed.

`ReplayAuthorityPolicyArtifactV1` signs the exact replay service and account
prefix plus the typed replay-policy digest. Initial journal provisioning writes
that immutable artifact before it claims a tombstone, and both authorization
stages re-read and verify it before they can claim an operation tombstone.

`ProviderMaterialPolicyV1`, `ProviderFingerprintAttestationV1`, and the
pending `ProviderMaterialGenesisV1` bind the exact intent, owner, approver,
retention, purpose, provider reference, version, encoding, and value-free
fingerprint for every material item. The material genesis is persisted only
after the matching policy and before any Keychain write. A completed
attestation is written only after all create-once rows succeed. Any duplicate,
partial, missing, changed, malformed, or interrupted state is diagnostic-only
and blocks automatic retry or replacement.

For macOS Keychain material, the immutable account name carries its declared
version as a `.v<version>` suffix, in addition to the signed reference hash.
This makes a version transition a distinct create-once item rather than an
interpretation of an older row.

The public material policy has fixed purpose-to-format bindings: commitment
HMAC and backup AES-256-GCM keys are each 32 raw bytes; the normal Infisical
encryption key is 16 random bytes in 32 lower-case hex characters; Infisical
auth secret is 32 random bytes in canonical standard Base64; each Valkey
password is a distinct 32-random-byte unpadded Base64URL value; and the TLS
trust anchor is exactly one canonical PEM X.509 CA certificate. Fingerprints
must be pairwise distinct, so HMAC and AEAD key material cannot be
cross-substituted. The FIPS-specific Infisical encryption-key spelling is not
accepted by this policy version.

The macOS implementation calls Security.framework directly with create-only
generic-password operations; it does not invoke a Keychain command-line tool,
update or delete an item, read configuration, or return a provider value to an
authorization callback. Values are accepted only as bounded in-memory
`bytearray` instances and overwritten best-effort after use. Adapter failures
are surfaced only as generic value-redacted errors.

This boundary intentionally represents a CA trust anchor only. TLS server
certificate and associated signing-key generation, custody, installation, and
runtime termination are not defined or authorized here; they require a separate
signed intent and policy amendment before any provisioning work.

The observed SQLite journal requires an owner-only directory and database file, uses
`BEGIN IMMEDIATE`, `DELETE` journaling, and `FULL` synchronous durability. A
one-time, `O_EXCL` anchor in that directory binds a random journal ID, canonical
path digest, schema digests, and database device/inode/link-count to matching
database metadata; that metadata also pins the anchor file identity and signed
genesis digest. Every open rechecks those bindings; a missing, renamed,
replaced, copied, or mismatched database/anchor/genesis fails closed and is
surfaced by the read-only `migration_status()` diagnostic. Rotation and
automatic recreation are intentionally unsupported. Its operation ID is unique and binds
the proposal/final hashes. Legacy nonce-ledger tables are detected before any
effect and are never silently replaced. A durable per-operation OS lease is
held through the effect and commit, so recovery rejects a live executor. It
records `claimed`, `in_progress`, `committed`, or
`failed_recovery_required`; a fresh nonce cannot retry an existing operation.
A crash after an effect starts is never retried automatically. An operator may
only reconcile that ambiguity with a typed Ed25519-signed
`ReconciliationReceiptV1` stating the effect committed; otherwise it remains
recovery-required. Provider and callback failures are returned as generic,
value-redacted authorization errors, and the journal records only fixed failure
codes. Immediately before provider leasing, the executor pins the exact
database, anchor, and genesis-marker device/inode/link-count; every pre-effect,
post-effect, and terminal check rejects replacement. The journal additionally
rejects all persistent SQLite views and triggers, so the validated schema has
no hidden executable database paths.

Detached sidecars use canonical standard base64 and Ed25519 domain-separated
bytes containing the artifact name and SHA-256 of canonical signed content.
For evidence models, canonical signed content omits only the embedded
`detached_signature_sha256` marker. The marker must equal the SHA-256 of the
actual sidecar signature, so it is covered without a circular signature input.
The raw artifact digest is independently checked against both the sidecar and
the Phase-A final contract.

The `rsd-infisical-disposable-lifecycle authorize --root <directory>` and
`rsd-lifecycle-authorize authorize --root <directory>` commands are
deliberately read-only. They have no trust-anchor or provider-value command
line arguments and therefore block until an embedding runtime injects those
trusted boundaries.

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
