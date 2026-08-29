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

1. `AllocationIntentV2` is a signed pre-creation contract. It
   contains only the two isolated-network plans, empty volume plans, and exact
   empty PostgreSQL database/schema/role/ACL plan, plus its future topology,
   provider references, native transport policy, retention,
   owner/approver, executor/PostgreSQL-control policy commitments, and governed
   evidence hashes. It deliberately has no database OID, container ID, network
   ID, workload ID, volume ID, or runtime fingerprint.
   `provision_allocation_journal()` explicitly creates its separate durable
   journal and external genesis tombstone. No authorization path creates or
   recreates that journal implicitly.
2. `authorize_allocation_and_execute()` accepts only the typed
   `allocate_isolated_empty_resources_v2` scope. It supplies a value-free,
   immutable `AllocationExecutionContext` only to an injected
   `AllocationExecutor` while holding separate bounded executor and PostgreSQL
   control leases. The only accepted effect output is an
   `AllocationEffectReceiptV2` with newly observed network/volume/database and
   ACL identities and an explicit zero-container/no-publication assertion.
   Seed, backup, restore, reset, swap, data access, application/cache container
   creation, and service start are outside that scope.
3. A trusted signer must issue `ObservedAllocationAttestationV1` over that
   exact allocation receipt before a second stage is even considered.
   `MaterializationIntentV1` then binds that allocation observation, the exact
   future four-component topology, immutable image/config commitments,
   provider-material attestation, executor policy, secret-capability policy,
   and secret-handling policy.
   `authorize_materialization_and_execute()` is the only boundary that can
   pass the future executor an opaque `SecretMaterialLease`; it cannot return
   or construct a raw secret mapping.
4. `MaterializationEffectReceiptV1` is the first receipt permitted to record
   the four final container/workload identities. It requires exactly one
   allowed attachment per component, fixed IP/alias bindings, isolated user
   network mode, empty port bindings, and disabled host networking/publication.
   A trusted `ObservedRuntimeAttestationV1` binds that receipt to the actual
   post-runtime `ProposalV1` and `RuntimeContractV1` before
   `authorize_and_execute()` can admit an observed lifecycle effect.

Allocation and materialization have distinct Ed25519 signature domains, SQLite operation kinds,
journal state machines, idempotency domains, and external replay-tombstone
kinds. A receipt from either stage is audit data, never a bearer grant.
`AllocationJournalStatus` exposes only read-only diagnostics. An
interrupted allocation genesis remains blocked until a signed
`AllocationJournalGenesisReconciliationReceiptV1` either confirms the already
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

`tls_verified_v1` remains a canonical schema value, but it is not provisionable
by this release. Until a separately signed TLS-termination amendment defines
server certificate and server signing-key custody, every Phase-B journal and effect
boundary rejects that profile with
`tls_termination_amendment_required` before a provider lease, local create,
external tombstone, or callback can run.
The same strict canonical-and-signed transport check is performed before any
provider-crypto readiness or Keychain signer load, so a manually pre-populated
TLS-profile provider state is not reported as usable.

`omninode_rsd.lifecycle.authorize_and_execute()` is the observed-lifecycle
mutation-admission boundary for a disposable acceptance workflow. It accepts
an injected Ed25519 trust anchor, leased provider-provenance adapter, owner-only
`SQLiteAuthorizationJournal` and
`SQLiteAllocationJournal`, mandatory `ProtocolReplayAuthority` plus
typed `ReplayAuthorityPolicyV1`, and one effect callback. It requires actual
detached-signature sidecars for the proposal, final contract, and evidence
artifacts; Phase-A signature markers alone never authorize.

The verifier uses its trusted UTC clock rather than a caller-provided time. At
every bootstrap, journal, and effect boundary it round-trips signed models into
their exact canonical typed forms, so raw strings, enum subclasses, and
`model_copy()`/`model_construct()` type drift cannot bypass transport policy.
It reads bounded owner-only artifact files through one open root-directory
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
complete the allocation stage above and invoke `provision_journal()` once with a
trusted Ed25519-signed `JournalGenesisReceiptV1`. That receipt commits to the
operation/proposal/final hashes, expected owner and approver, canonical journal path, fresh journal ID,
and journal schema digest, including the exact replay-policy digest.
Observed journal genesis also requires the caller's exact signed allocation intent,
a committed `allocated` predecessor, and a committed materialization predecessor
in the allocation journal. Before
it can claim its external tombstone, it descriptor-reopens and verifies the
immutable allocation replay-policy artifact; a transient caller policy, a missing
preimage, or an observed-genesis-before-allocation attempt fails closed.
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
allocation-intent digest, Keychain service/account/version/reference hash, seed
fingerprint, derived public key, and public-key fingerprint. The signer can
only be provisioned or loaded after that signature and intent binding are
verified; duplicate Keychain rows fail closed.

`ReplayAuthorityPolicyArtifactV1` signs the exact replay service and account
prefix plus the typed replay-policy digest. Allocation journal provisioning writes
that immutable artifact before it claims a tombstone, and both authorization
stages re-read and verify it before they can claim an operation tombstone.

`ProviderMaterialPolicyV2`, `ProviderFingerprintAttestationV2`,
`MaterialGenerationReceiptV1`, and the pending `ProviderMaterialGenesisV2`
bind the exact intent, owner, approver, retention, purpose, provider reference,
version, encoding, generator identity, and value-free fingerprint for every
material item. The production bootstrap uses Security.framework
`SecRandomCopyBytes` directly to fill bounded mutable buffers; it records the
signed generation receipt before the pending genesis and before any Keychain
write. The pending genesis separately signs the canonical generation-receipt
digest, so a later receipt substitution cannot be treated as the preimage for
an existing create-only state. The receipt records the selected OS generator
and resulting public fingerprints, not a post-hoc proof of entropy. A completed attestation is
written only after all create-once rows succeed. Any duplicate, partial,
missing, changed, malformed, or interrupted state is diagnostic-only and
blocks automatic retry or replacement.

Authorization never accepts material policy, genesis, or fingerprint models
from its caller. Under the held artifact-root descriptor it loads the persisted
issuer-signed `SignerGenesisV1`, policy, generation receipt, pending genesis,
and terminal attestation; verifies their canonical hashes, Ed25519 domains,
intent/owner/approver/reference bindings, distinct fingerprints, generator
receipt bindings, and declared formats; and rechecks that exact five-file
snapshot before an effect and before commit. A manually populated Keychain item
without this verified terminal artifact set cannot reach an effect.
`provider_material_genesis_status()` is deliberately a structural diagnostic
only: its `structurally_complete_unverified` result is never an authorization
signal.

For macOS Keychain material, the immutable account name carries its declared
version as a `.v<version>` suffix, in addition to the signed reference hash.
This makes a version transition a distinct create-once item rather than an
interpretation of an older row.

The material policy also carries the signer Keychain reference and seed
fingerprint. That signer item, every material purpose/reference, and every
material fingerprint must be pairwise distinct, so an Ed25519 seed cannot be
reused as HMAC, AEAD, or application material.

Before any Keychain `SecItemAdd`, the signed `SignerGenesisV1` trust anchor is
created or proven byte-identical, fsynced with its owner-only directory,
descriptor-reopened, and signature/binding verified. Material provisioning
holds that descriptor-relative root through its create-only writes and
rechecks the signer genesis before each write; an absent, substituted, or
orphaned signer state fails closed.

The public material policy has fixed purpose-to-format bindings: commitment
HMAC and backup AES-256-GCM keys are each 32 raw bytes; the normal Infisical
encryption key is 16 random bytes in 32 lower-case hex characters; Infisical
auth secret is 32 random bytes in canonical standard Base64; each primary and
restore Valkey password and the distinct PostgreSQL application-login password
are 32-random-byte unpadded Base64URL values; and the TLS trust anchor is
exactly one canonical PEM X.509 CA certificate. Fingerprints must be pairwise
distinct, so HMAC, AEAD, signer, and application material cannot be
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
signed intent and policy amendment. Consequently, a TLS-profile intent is
blocked before any provisioning work in this release.

### Narrow secret-handling boundary

`SecretHandlingPolicyV1` records the only accepted disposable secret sinks for
this profile: the two named Infisical target processes may receive their
bounded values through their target-process environment, and the two named
Valkey target processes may receive their bounded values through stdin-backed
configuration. It is not a general trust grant for host processes, governed
services, other containers, or arbitrary workloads. The signed policy requires
host environment, Docker configuration environment, command arguments, labels,
logs, receipts, disk plaintext, and public artifacts to remain forbidden.
The future executor receives only an opaque `SecretMaterialLease` and must
enforce those sink restrictions before any provider read.

The policy fixes restart behavior to `no`. The public authorization boundary
models a fresh signed `rsd.start-runtime-intent.v2` with `start_runtime_v2`
scope, a globally fresh delivery nonce, external replay tombstone, durable
start journal state, and fresh bounded Keychain redelivery for every start or
restart. No existing start or materialization receipt can be reused as restart
authority.

### Planned wrapper and local target-delivery contracts

`ContainerBootstrapWrapperManifestV1` replaces the former opaque wrapper hash.
It separately signs one immutable wrapper/derived-image declaration for each
primary/restore Infisical and Valkey component: planned wrapper bytes and build
provenance digests, the complete base/derived OCI digest chain, executable
path/mode and `linux/amd64` requirements, exec-form Entrypoint/Cmd merge,
PID1 signal forwarding/reaping/exit behavior, no-disk/no-log requirements, and
the local attach-protocol commitment. A manifest is a planned contract only:
this release contains neither wrapper bytes nor a build toolchain, image
inspection evidence, or live PID1 proof.

`TargetDeliveryMapV1` signs the exact four target routes plus independent
`primary_database` and `restore_database` identities. It binds the five
provider fingerprints, each exact Infisical variable or Valkey `requirepass`
field, and value-free PostgreSQL/Valkey URI grammars. URI grammar commitments
contain only authorities, role/database/cache identities, approved password
reference fingerprints, and rendered byte counts; they never persist or return
a URI, password, verifier, environment mapping, or target file. The primary
and restore PostgreSQL transitions remain distinct: both keep their database
owner NOLOGIN while a separate observed-OID-bound application login/verifier
transition is authorized only at materialization.

`ContainerBootstrapAttachProtocolV1` and the pure
`container_attach` codec describe the future daemon-to-container stdin boundary
separately from the Mac-to-daemon remote-session framing. A local request binds
operation, component/container, derived-image, wrapper, protocol, target-map, nonce,
channel, and session commitments before `ready_v1`, `claimed_v1`, ordered
ordinal-tagged binary chunks, redacted terminal acknowledgement, and clean EOF.
Chunk descriptors carry only format/count/fingerprint metadata. Buffers are
mutable and zeroized best-effort on every codec path; any failure after the
first chunk becomes non-retryable `attach_ambiguous_v1`. This is not a Docker
attach adapter or a wrapper implementation, and it does not make
materialization or start executable.

### Remote executor transport boundary

The library now supplies an offline-testable transport boundary for a separately
authorized remote executor. It canonical-loads signed transport and installation
artifacts through owner-only, no-follow descriptors; sends versioned bounded
binary frames with value-free JSON metadata and five opaque delivery chunks;
and requires the daemon to durably claim a session before accepting any chunk.
Both ends impose one-session deadlines and aggregate frame limits; a stalled,
partial, duplicate, or oversized stream fails closed and a fresh authorization
is required after any delivery attempt.

Allocation uses a distinct zero-chunk request and cannot carry delivery bytes.
Every allocation, materialization, and start request carries a trusted-signer
`RemoteEffectAuthorizationWitnessV1` binding the already-claimed external replay
tombstone, journal, idempotency key, intent/predecessor, executor policy, host
and Engine fingerprints, and signed plan/artifact chain. The daemon verifies
that witness before its local claim. The witness also commits a domain-separated
complete Engine/PostgreSQL checkpoint sequence. A future backend can request
only the daemon-selected next kind and target, and must durably complete its
filtered projection before a later step is available. An incomplete or
ambiguous checkpoint cannot be adopted or retried automatically. Terminal
allocation/materialization/start envelopes embed a separately executor-signed,
typed filtered receipt and its canonical digest. They do not treat a raw Engine
payload or a standalone backend-receipt hash as effect evidence. The metadata
envelope is bounded to 16 KiB even when it carries the four filtered container
inspections; secret chunks remain separate opaque bounded frames. The daemon
and client verifier reject future-dated inner executor receipts.

The exposed backend contract is deliberately narrow: it can claim and complete
only the next signed operation with a SHA-256 of a filtered projection. It
receives no Docker socket, raw Engine response, raw PostgreSQL result, or
journal connection.

### Sealed zero-secret allocation backend

This release includes one concrete, allocation-only Linux adapter:
`SealedAllocationBackendV1`. It is not a general Docker client and is never
selected by a caller-supplied socket, URL, callback, SQL string, or command.
Production construction descriptor-loads and signature-verifies the exact
allocation intent, executor policy, Docker Engine policy, and PostgreSQL
prepared-control policy from an owner-only, no-follow artifact root. Its
signed Unix socket policy pins the canonical path digest, device, inode, owner,
group, and mode; the live adapter rechecks that identity and Linux peer
credentials before and after each connection. Its parent directories must be
root-owned and non-writable, so the root-controlled Engine/executor remains the
explicit TCB for the unavoidable pathname-based AF_UNIX connect.

The adapter permits only Engine ping/version/info, the pinned control-image and
control-container inspections, exact named internal-network and local-volume
absence/create/inspect operations, and fixed control-container `exec`
create/inspect/start calls.
It rejects preexisting names rather than adopting them, does not pull, delete,
prune, update, restart, connect networks, read logs/events, or create runtime
containers, and persists a durable signed-plan checkpoint before every Engine
call. A timeout, EOF, status/framing failure, or crash after a claim is
ambiguous: no retry, adoption, cleanup, or automatic recovery is permitted.

PostgreSQL allocation uses a fixed signed `psql` argv and stdin-only templates
for NOLOGIN role creation, database creation, schema/ACL creation, and typed
state observation. Before that it proves the signed `psql` binary checksum in
the pinned control image. SQL, raw Engine data, Docker paths/labels, psql
output, and any secret are excluded from journal state and receipts. The
adapter reports a full typed `AllocatedResourceSetV2` with zero containers and
no host publication. Its read-only reconciliation path can only inspect the
known allocation names plus fixed PostgreSQL presence/observation queries; it
produces a signed, non-resumable reconciliation receipt and never repairs or
continues partial state.

Materialization and start remain `NoMutationBackend` operations. The sealed
allocation backend raises `backend_unavailable` for both, and
`serve_systemd_activated_allocation_session()` accepts only an allocation
transport request from that sealed adapter. No generic allocation CLI creates
or installs an Engine control path.

The client builds one fixed OpenSSH invocation with strict host-key checking,
no forwarding, no interactive authentication, no control socket, and pinned
owner-only known-hosts and identity references inherited by descriptor at exec.
It never puts a delivery value in
arguments, its child environment, metadata, a receipt, or an exception.

On the executor side, the ForceCommand relay is a bounded frame relay to an
AF_UNIX daemon. A signed non-root Secure Shell user UID and signed non-root
socket group/GID are both required: the render-only installation creates the
socket through a root-owned systemd socket unit at exact `0660` mode, while the
daemon separately validates the kernel peer UID. After forwarding its one request, it waits for client EOF,
rejects any trailing byte, emits a relay-authentication clean-EOF frame, and only then
half-closes the UDS. The daemon requires both that frame and UDS EOF before a
backend can observe delivery bytes; a bare close is never effect authority.
The terminal client receipt parser likewise requires clean Secure Shell stdout EOF, so
unknown appended frames cannot be ignored. The daemon validates kernel peer
credentials, disables core dumps, requires signed swap/page-lock preflight,
uses an attestation key loaded from a systemd credential descriptor, and records `MATERIALIZED`,
`START_CLAIMED`, `START_AMBIGUOUS`, `STARTED`, or `ABANDONED` durable states.
An ambiguous session has no automatic retry path. Recovery requires a receipt
signed by the verified signer-genesis trust anchor and bound to the exact
journal, allocation, transport policy, and request/session commitments. The
render-only installation CLI emits non-secret systemd socket/service and sshd
text, including an explicit `AuthorizedKeysFile`, plus a complete restricted
`authorized_keys` entry whose exact `ssh-ed25519` wire blob is bound to the
pinned client-key fingerprint; it never writes or installs any output. The
future installation effect must account for the signed account-to-UID and
group-to-GID mappings before the transport becomes usable; the relay and
daemon independently recheck them at runtime. The service renderer also
creates an exact owner-only systemd state directory and grants only that
directory write access through `ProtectSystem=strict`, so a separately
provisioned SQLite session journal has a durable bounded location. Its named
socket descriptor is consumed only by `serve_systemd_activated_session()`,
which validates the root-owned path identity, group, mode, descriptor name,
and one-listener systemd activation contract before accepting a connection.
The exact rendered executable is a separately signed installation artifact
that must construct the sealed daemon engine and call that adapter. The
default `NoMutationBackend` is rejected before the activated listener is
opened, so this public package cannot accidentally accept delivery material
without a separately reviewed concrete backend.

This release still provides no configured executor installation, network
connection, Docker daemon, PostgreSQL instance, or service-mutation backend.
`NoMutationBackend` remains the safe default unless a separately installed,
attested executable constructs the sealed allocation adapter from its verified
artifact root. A future deployment must separately install and attest that
policy and satisfy the existing signed authorization and external replay gates.

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
