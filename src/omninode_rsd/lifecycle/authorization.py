"""Locked Phase-B verification and effect execution for lifecycle artifacts.

``authorize_and_execute`` is the sole public mutation-admission boundary. It
holds an owner-only artifact-root advisory lock, verifies signed artifacts and
leased provider provenance, durably records an operation, invokes one effect,
and durably records the terminal outcome. It never retrieves provider values
or invokes an external service itself.
"""

from __future__ import annotations

import argparse
import base64
import binascii
import copy
import ctypes
import errno
import fcntl
import hashlib
import hmac
import json
import os
import re
import secrets
import sqlite3
import stat
import sys
import uuid
from collections.abc import Callable, Mapping, Sequence
from contextlib import AbstractContextManager, suppress
from dataclasses import dataclass, field
from datetime import UTC, datetime, timedelta
from enum import StrEnum
from pathlib import Path
from threading import Lock, get_ident
from typing import Any, Final, Literal, Protocol, cast

import yaml
from cryptography.exceptions import InvalidSignature
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PublicKey
from pydantic import BaseModel, ConfigDict, Field, ValidationError, model_validator

from omninode_rsd.lifecycle.infisical_disposable import (
    ApprovalEvidenceV1,
    DisposablePreflightError,
    DisposableTransportProfile,
    GovernedBaselineV1,
    InitialProvisioningEffectReceiptV1,
    InitialProvisioningIntentV1,
    ObservedCandidateAttestationV1,
    PreflightPaths,
    PreflightReceiptV1,
    ProposalV1,
    ProviderDeclarationV1,
    ProviderReferenceV1,
    RegistryVerificationV1,
    RuntimeContractV1,
    TargetAttestationV1,
    _OwnerOnlyReader,
    _UniqueLoader,
    compile_preflight,
    initial_provisioning_intent_sha256,
    validate_observed_candidate_transition,
)
from omninode_rsd.lifecycle.provider_crypto import (
    ReplayAuthorityPolicyArtifactV1,
    SignerGenesisV1,
    _load_verified_provider_material_bundle_from_reader_at,
    _load_verified_signer_genesis_from_reader,
    verify_replay_authority_policy_artifact,
)

_SHA256: Final = r"^[0-9a-f]{64}$"
_IDENTIFIER: Final = r"^[A-Za-z][A-Za-z0-9_.-]{0,127}$"
_UUID: Final = r"^[0-9a-f]{8}-[0-9a-f]{4}-[1-5][0-9a-f]{3}-[89ab][0-9a-f]{3}-[0-9a-f]{12}$"
_STAGE_ATTESTATION_FRESHNESS: Final = timedelta(minutes=15)
_MAX_ARTIFACT_BYTES: Final = 131_072
_ARTIFACT_NAMES: Final[tuple[str, ...]] = (
    "proposal.yaml",
    "runtime-contract.yaml",
    "approval.yaml",
    "governed-baseline.yaml",
    "target-attestation.yaml",
    "provider-declaration.yaml",
    "registry-verification.yaml",
    "postgres-overlay.yaml",
)
_JOURNAL_GENESIS_ARTIFACT_NAME: Final = "journal-genesis.yaml"
_INITIAL_INTENT_ARTIFACT_NAME: Final = "initial-provisioning-intent.yaml"
_INITIAL_RECEIPT_ARTIFACT_NAME: Final = "initial-provisioning-receipt.yaml"
_OBSERVED_ATTESTATION_ARTIFACT_NAME: Final = "observed-candidate-attestation.yaml"
_REPLAY_POLICY_ARTIFACT_NAME: Final = "replay-authority-policy.yaml"
_MARKED_EVIDENCE_NAMES: Final[frozenset[str]] = frozenset(_ARTIFACT_NAMES[2:-1])
_SIGNATURE_DOMAIN: Final = b"omninode-rsd.authorization.ed25519.v3\x00"
_INITIAL_INTENT_SIGNATURE_DOMAIN: Final = b"omninode-rsd.initial-provisioning-intent.ed25519.v1\x00"
_OBSERVED_ATTESTATION_SIGNATURE_DOMAIN: Final = (
    b"omninode-rsd.observed-candidate-attestation.ed25519.v1\x00"
)
_INITIAL_EFFECT_RECEIPT_DOMAIN: Final = b"omninode-rsd.initial-provisioning-effect-receipt.v1\x00"
_IDEMPOTENCY_DOMAIN: Final = b"omninode-rsd.authorization.effect.v1\x00"
_INITIAL_IDEMPOTENCY_DOMAIN: Final = b"omninode-rsd.initial-provisioning-effect.v1\x00"
_RECONCILIATION_DOMAIN: Final = b"omninode-rsd.authorization.reconciliation.v1\x00"
_JOURNAL_GENESIS_DOMAIN: Final = b"omninode-rsd.authorization.journal-genesis.v1\x00"
_JOURNAL_GENESIS_RECONCILIATION_DOMAIN: Final = (
    b"omninode-rsd.authorization.journal-genesis-reconciliation.v1\x00"
)
_INITIAL_JOURNAL_GENESIS_RECONCILIATION_DOMAIN: Final = (
    b"omninode-rsd.initial-provisioning-journal-genesis-reconciliation.v1\x00"
)
_REPLAY_TOMBSTONE_DOMAIN: Final = b"omninode-rsd.authorization.replay-tombstone.v1\x00"
_REPLAY_ACCOUNT_DOMAIN: Final = b"omninode-rsd.authorization.replay-account.v1\x00"
_ARTIFACT_LOCK_PREFIX: Final = ".rsd-authorization-root-"
_OPERATION_LEASE_PREFIX: Final = ".rsd-authorization-operation-"
_JOURNAL_IDENTITY_LEASE_PREFIX: Final = ".rsd-authorization-journal-identity-"
_JOURNAL_ANCHOR_PREFIX: Final = ".rsd-authorization-journal-anchor-"
_JOURNAL_GENESIS_MARKER_PREFIX: Final = ".rsd-authorization-journal-genesis-"
_INITIAL_JOURNAL_ANCHOR_PREFIX: Final = ".rsd-initial-provisioning-journal-anchor-"
_INITIAL_JOURNAL_MARKER_PREFIX: Final = ".rsd-initial-provisioning-journal-marker-"
_VERIFIED_CAPABILITY: Final = object()
_GENESIS_CAPABILITY: Final = object()
_INITIAL_VERIFIED_CAPABILITY: Final = object()
_INITIAL_INTENT_CAPABILITY: Final = object()
_JOURNAL_PIN_CAPABILITY: Final = object()
_INITIAL_JOURNAL_PIN_CAPABILITY: Final = object()
_TEST_CLOCK_CAPABILITY: Final = object()
_SYSTEM_CLOCK_CAPABILITY: Final = object()
_SAFE_CALL_FAILURE: Final = object()
_OPERATION_TABLE: Final = "authorization_operation_journal"
_JOURNAL_METADATA_TABLE: Final = "authorization_journal_metadata"
_INITIAL_OPERATION_TABLE: Final = "initial_provisioning_operation_journal"
_INITIAL_JOURNAL_METADATA_TABLE: Final = "initial_provisioning_journal_metadata"
_LEGACY_OPERATION_TABLE: Final = "authorization_nonce_journal"
_JOURNAL_SCHEMA_VERSION: Final = "rsd.authorization-journal.v1"
_INITIAL_JOURNAL_SCHEMA_VERSION: Final = "rsd.initial-provisioning-journal.v1"
_JOURNAL_ANCHOR_SCHEMA_VERSION: Final = "rsd.authorization-journal-anchor.v1"
_JOURNAL_GENESIS_MARKER_SCHEMA_VERSION: Final = "rsd.authorization-journal-genesis-marker.v1"
_JOURNAL_OPERATION_DOMAIN: Final = "rsd.observed-lifecycle-operation.v1"
_OBSERVED_OPERATION_KIND: Final = "observed_lifecycle_v1"
_INITIAL_OPERATION_KIND: Final = "initial_provisioning_v1"
_OPERATION_SCHEMA: Final = f"""
CREATE TABLE IF NOT EXISTS {_OPERATION_TABLE} (
    operation_id TEXT PRIMARY KEY NOT NULL,
    operation_kind TEXT NOT NULL CHECK (operation_kind = '{_OBSERVED_OPERATION_KIND}'),
    nonce TEXT NOT NULL UNIQUE,
    proposal_sha256 TEXT NOT NULL,
    contract_sha256 TEXT NOT NULL,
    provider_provenance_sha256 TEXT NOT NULL,
    idempotency_key TEXT NOT NULL,
    state TEXT NOT NULL,
    effect_receipt_sha256 TEXT,
    failure_phase TEXT,
    created_at TEXT NOT NULL,
    updated_at TEXT NOT NULL,
    CHECK (state IN ('claimed', 'in_progress', 'committed', 'failed_recovery_required'))
) WITHOUT ROWID
"""
_JOURNAL_METADATA_SCHEMA: Final = f"""
CREATE TABLE IF NOT EXISTS {_JOURNAL_METADATA_TABLE} (
    singleton INTEGER PRIMARY KEY NOT NULL CHECK (singleton = 1),
    journal_uuid TEXT NOT NULL,
    journal_path_sha256 TEXT NOT NULL,
    operation_schema_sha256 TEXT NOT NULL,
    metadata_schema_sha256 TEXT NOT NULL,
    genesis_sha256 TEXT NOT NULL,
    anchor_dev INTEGER NOT NULL,
    anchor_ino INTEGER NOT NULL,
    anchor_nlink INTEGER NOT NULL,
    schema_version TEXT NOT NULL
) WITHOUT ROWID
"""
_INITIAL_OPERATION_SCHEMA: Final = f"""
CREATE TABLE IF NOT EXISTS {_INITIAL_OPERATION_TABLE} (
    provisioning_operation_id TEXT PRIMARY KEY NOT NULL,
    operation_kind TEXT NOT NULL CHECK (operation_kind = '{_INITIAL_OPERATION_KIND}'),
    operation_scope TEXT NOT NULL CHECK (operation_scope = 'create_isolated_empty_resources_v1'),
    intent_sha256 TEXT NOT NULL,
    nonce TEXT NOT NULL UNIQUE,
    provider_provenance_sha256 TEXT NOT NULL,
    idempotency_key TEXT NOT NULL,
    state TEXT NOT NULL,
    effect_receipt_sha256 TEXT,
    observed_resources_sha256 TEXT,
    failure_phase TEXT,
    created_at TEXT NOT NULL,
    updated_at TEXT NOT NULL,
    CHECK (state IN ('claimed', 'in_progress', 'provisioned_empty', 'failed_recovery_required'))
) WITHOUT ROWID
"""
_INITIAL_JOURNAL_METADATA_SCHEMA: Final = f"""
CREATE TABLE IF NOT EXISTS {_INITIAL_JOURNAL_METADATA_TABLE} (
    singleton INTEGER PRIMARY KEY NOT NULL CHECK (singleton = 1),
    journal_uuid TEXT NOT NULL,
    journal_path_sha256 TEXT NOT NULL,
    journal_schema_sha256 TEXT NOT NULL,
    intent_sha256 TEXT NOT NULL,
    anchor_dev INTEGER NOT NULL,
    anchor_ino INTEGER NOT NULL,
    anchor_nlink INTEGER NOT NULL,
    schema_version TEXT NOT NULL
) WITHOUT ROWID
"""
_ARTIFACT_LOCK_REGISTRY: dict[tuple[int, int, int, int], int] = {}
_ARTIFACT_LOCK_REGISTRY_GUARD = Lock()


class _Model(BaseModel):
    model_config = ConfigDict(extra="forbid", frozen=True, strict=True, validate_default=True)


class AuthorizationError(RuntimeError):
    """Value-redacted fail-closed authorization error."""

    def __init__(self, phase: str) -> None:
        self.phase = phase
        super().__init__(f"authorization failed at phase: {phase}")


class AuthorizationOperationState(StrEnum):
    """Durable lifecycle states for one one-shot authorization operation."""

    CLAIMED = "claimed"
    IN_PROGRESS = "in_progress"
    COMMITTED = "committed"
    FAILED_RECOVERY_REQUIRED = "failed_recovery_required"


class AuthorizationOperationKind(StrEnum):
    """Journal scopes are explicit and never interchangeable."""

    INITIAL_PROVISIONING = _INITIAL_OPERATION_KIND
    OBSERVED_LIFECYCLE = _OBSERVED_OPERATION_KIND


class InitialProvisioningOperationState(StrEnum):
    """Durable states for a one-time empty-resource creation operation."""

    CLAIMED = "claimed"
    IN_PROGRESS = "in_progress"
    PROVISIONED_EMPTY = "provisioned_empty"
    FAILED_RECOVERY_REQUIRED = "failed_recovery_required"


class JournalMigrationStatus(StrEnum):
    """Read-only classification of a journal before it is used for an effect."""

    ABSENT = "absent"
    EMPTY = "empty"
    CURRENT = "current"
    LEGACY_DETECTED = "legacy_detected"
    ANCHOR_MISSING = "anchor_missing"
    GENESIS_MISSING = "genesis_missing"
    JOURNAL_MISSING = "journal_missing"
    PROVISIONING_INCOMPLETE = "provisioning_incomplete"
    IDENTITY_MISMATCH = "identity_mismatch"
    UNKNOWN = "unknown"


class DetachedAuthorizationSignatureV1(_Model):
    """Detached sidecar for one raw artifact and its canonical signed content."""

    schema_version: Literal["rsd.authorization-signature.v3"]
    artifact_name: str = Field(pattern=r"^[a-z][a-z0-9-]*[.]yaml$")
    artifact_sha256: str = Field(pattern=_SHA256)
    signed_content_sha256: str = Field(pattern=_SHA256)
    signer_key_id: str = Field(pattern=_IDENTIFIER)
    algorithm: Literal["ed25519"]
    signature_base64: str = Field(min_length=4, max_length=256)

    @model_validator(mode="after")
    def supported_artifact(self) -> DetachedAuthorizationSignatureV1:
        if self.artifact_name not in _ARTIFACT_NAMES:
            raise ValueError("artifact is not authorization material")
        if len(_canonical_base64(self.signature_base64)) != 64:
            raise ValueError("Ed25519 signature has wrong length")
        return self


class TrustedEd25519SignerV1(_Model):
    """Injected Ed25519 trust anchor; no configuration lookup occurs here."""

    key_id: str = Field(pattern=_IDENTIFIER)
    public_key_base64: str = Field(min_length=4, max_length=128)
    public_key_fingerprint_sha256: str = Field(pattern=_SHA256)

    @model_validator(mode="after")
    def fingerprint_binds_key(self) -> TrustedEd25519SignerV1:
        key = _canonical_base64(self.public_key_base64)
        if len(key) != 32 or hashlib.sha256(key).hexdigest() != self.public_key_fingerprint_sha256:
            raise ValueError("public key fingerprint does not bind key")
        return self

    def key(self) -> Ed25519PublicKey:
        return Ed25519PublicKey.from_public_bytes(_canonical_base64(self.public_key_base64))


class ReplayAuthorityClaimResult(StrEnum):
    """The only valid outcomes of one external create-once attempt."""

    CREATED = "created"
    DUPLICATE_SAME = "duplicate_same"
    DUPLICATE_CONFLICT = "duplicate_conflict"
    UNAVAILABLE = "unavailable"


class ReplayAuthorityPolicyV1(_Model):
    """Typed, injected namespace for governed external replay tombstones."""

    schema_version: Literal["rsd.replay-authority-policy.v1"]
    service: str = Field(pattern=_IDENTIFIER, min_length=1, max_length=128)
    account_prefix: str = Field(pattern=_IDENTIFIER, min_length=1, max_length=48)

    def sha256(self) -> str:
        material = self.model_dump(mode="json")
        return _digest(json.dumps(material, sort_keys=True, separators=(",", ":")).encode("utf-8"))


class ReplayTombstoneV1(_Model):
    """Value-free, immutable binding written once by an external authority."""

    schema_version: Literal["rsd.replay-tombstone.v1"]
    kind: Literal[
        "initial_genesis",
        "initial_operation",
        "observed_genesis",
        "observed_operation",
    ]
    operation_kind: Literal["initial_provisioning_v1", "observed_lifecycle_v1"]
    service: str = Field(pattern=_IDENTIFIER, min_length=1, max_length=128)
    account: str = Field(pattern=_IDENTIFIER, min_length=1, max_length=128)
    journal_genesis_id: str = Field(pattern=_UUID)
    operation_id: str = Field(min_length=1, max_length=256)
    proposal_sha256: str | None = Field(default=None, pattern=_SHA256)
    contract_sha256: str | None = Field(default=None, pattern=_SHA256)
    initial_provisioning_intent_sha256: str | None = Field(default=None, pattern=_SHA256)
    provider_provenance_sha256: str | None = None
    idempotency_key: str | None = None

    @model_validator(mode="after")
    def canonical_binding(self) -> ReplayTombstoneV1:
        try:
            parsed_uuid = uuid.UUID(self.journal_genesis_id)
        except ValueError:
            raise ValueError("replay tombstone binding is invalid") from None
        if str(parsed_uuid) != self.journal_genesis_id:
            raise ValueError("replay tombstone binding is invalid")
        observed = self.kind in {"observed_genesis", "observed_operation"}
        operation = self.kind in {"initial_operation", "observed_operation"}
        if observed != (self.operation_kind == _OBSERVED_OPERATION_KIND):
            raise ValueError("replay tombstone binding is invalid")
        if observed:
            if (
                type(self.proposal_sha256) is not str
                or type(self.contract_sha256) is not str
                or self.initial_provisioning_intent_sha256 is not None
            ):
                raise ValueError("replay tombstone binding is invalid")
        elif (
            type(self.initial_provisioning_intent_sha256) is not str
            or self.proposal_sha256 is not None
            or self.contract_sha256 is not None
        ):
            raise ValueError("replay tombstone binding is invalid")
        if operation:
            if (
                type(self.provider_provenance_sha256) is not str
                or re.fullmatch(_SHA256, self.provider_provenance_sha256) is None
                or type(self.idempotency_key) is not str
                or re.fullmatch(_SHA256, self.idempotency_key) is None
            ):
                raise ValueError("replay tombstone binding is invalid")
        elif self.provider_provenance_sha256 is not None or self.idempotency_key is not None:
            raise ValueError("replay tombstone binding is invalid")
        return self

    def binding_sha256(self) -> str:
        return _replay_tombstone_sha256(self)

    def value_bytes(self) -> bytes:
        return self.binding_sha256().encode("ascii")


class ProtocolReplayAuthority(Protocol):
    """External, atomic, create-once replay authority with no permissive mode."""

    def claim_once(self, tombstone: ReplayTombstoneV1) -> ReplayAuthorityClaimResult: ...


class _KeychainGenericPasswordStore(Protocol):
    """Narrow testable transport for Security.framework generic-password calls."""

    def add_if_absent(self, service: str, account: str, value: bytes) -> bytes | None: ...


class MacOSKeychainReplayAuthority:
    """Security.framework-backed external replay tombstones for macOS runtimes.

    The stored value is only the SHA-256 binding of public identifiers. Neither
    the adapter nor its caller accepts a secret value, and it never overwrites
    an existing keychain item.
    """

    def __init__(
        self,
        policy: ReplayAuthorityPolicyV1,
        *,
        _store: _KeychainGenericPasswordStore | None = None,
    ) -> None:
        if type(policy) is not ReplayAuthorityPolicyV1:
            raise ValueError("replay authority policy is invalid")
        self._policy = policy
        self._store = _SecurityFrameworkGenericPasswordStore() if _store is None else _store

    def claim_once(self, tombstone: ReplayTombstoneV1) -> ReplayAuthorityClaimResult:
        if (
            type(tombstone) is not ReplayTombstoneV1
            or tombstone.service != self._policy.service
            or not tombstone.account.startswith(f"{self._policy.account_prefix}.")
        ):
            return ReplayAuthorityClaimResult.DUPLICATE_CONFLICT
        value = tombstone.value_bytes()
        try:
            existing = self._store.add_if_absent(tombstone.service, tombstone.account, value)
        except Exception:
            return ReplayAuthorityClaimResult.UNAVAILABLE
        if existing is None:
            return ReplayAuthorityClaimResult.CREATED
        if type(existing) is not bytes:
            return ReplayAuthorityClaimResult.UNAVAILABLE
        return (
            ReplayAuthorityClaimResult.DUPLICATE_SAME
            if hmac.compare_digest(existing, value)
            else ReplayAuthorityClaimResult.DUPLICATE_CONFLICT
        )


@dataclass(frozen=True, slots=True)
class ProviderProvenance:
    """Value-free metadata supplied by one provider snapshot lease."""

    provider: str
    service: str
    account: str
    version: int
    reference_sha256: str
    fingerprint_sha256: str


class ProviderSnapshotLease(Protocol):
    """A lease that keeps referenced provider metadata stable through an effect.

    ``recheck`` must fail or return different metadata if the referenced item
    can no longer be proven to be the same version and fingerprint observed by
    ``inspect``. Implementations that retrieve values do so only inside their
    own lease and never expose those values through this package.
    """

    def inspect(self, reference: ProviderReferenceV1) -> ProviderProvenance | None: ...

    def recheck(self, reference: ProviderReferenceV1) -> ProviderProvenance | None: ...


class ProviderProvenanceAdapter(Protocol):
    """Acquire one leased provider snapshot for the supplied references."""

    def acquire(
        self, references: tuple[ProviderReferenceV1, ...]
    ) -> AbstractContextManager[ProviderSnapshotLease]: ...


class ProviderExpectationV1(_Model):
    """Exact value-free provider binding visible to the effect callback."""

    provider: str = Field(pattern=_IDENTIFIER)
    service: str = Field(pattern=_IDENTIFIER)
    account: str = Field(pattern=_IDENTIFIER)
    version: int = Field(ge=1)
    reference_sha256: str = Field(pattern=_SHA256)
    fingerprint_sha256: str = Field(pattern=_SHA256)


@dataclass(frozen=True, slots=True)
class VerifiedExecutionContext:
    """Immutable effect input with no artifact root, nonce, or journal handle."""

    operation_kind: Literal["observed_lifecycle_v1"]
    operation_id: str
    idempotency_key: str
    proposal: ProposalV1
    final_contract: RuntimeContractV1
    provider_expectations: tuple[ProviderExpectationV1, ...]
    proposal_sha256: str
    contract_sha256: str
    provider_provenance_sha256: str


class EffectReceiptV1(_Model):
    """Effect-owned receipt explicitly bound to one execution context."""

    schema_version: Literal["rsd.lifecycle-effect-receipt.v1"]
    operation_kind: Literal["observed_lifecycle_v1"]
    operation_id: str
    idempotency_key: str = Field(pattern=_SHA256)
    effect_receipt_sha256: str = Field(pattern=_SHA256)


class ReconciliationReceiptV1(_Model):
    """Signed operator evidence that an ambiguous effect committed exactly once."""

    schema_version: Literal["rsd.lifecycle-effect-reconciliation.v1"]
    outcome: Literal["effect_committed"]
    operation_id: str
    idempotency_key: str = Field(pattern=_SHA256)
    effect_receipt_sha256: str = Field(pattern=_SHA256)
    signer_key_id: str = Field(pattern=_IDENTIFIER)
    signature_base64: str = Field(min_length=4, max_length=256)

    @model_validator(mode="after")
    def canonical_signature(self) -> ReconciliationReceiptV1:
        if len(_canonical_base64(self.signature_base64)) != 64:
            raise ValueError("Ed25519 signature has wrong length")
        return self


class JournalGenesisReceiptV1(_Model):
    """Signed, one-time journal identity authorization for one artifact set."""

    schema_version: Literal["rsd.authorization-journal-genesis.v1"]
    operation_domain: Literal["rsd.observed-lifecycle-operation.v1"]
    operation_kind: Literal["observed_lifecycle_v1"]
    operation_id: str = Field(min_length=1, max_length=256)
    proposal_sha256: str = Field(pattern=_SHA256)
    contract_sha256: str = Field(pattern=_SHA256)
    disposal_owner: str = Field(pattern=_IDENTIFIER)
    approver_identity: str = Field(pattern=_IDENTIFIER)
    journal_path: str = Field(min_length=1, max_length=4096)
    journal_path_sha256: str = Field(pattern=_SHA256)
    journal_uuid: str = Field(min_length=36, max_length=36)
    journal_schema_sha256: str = Field(pattern=_SHA256)
    replay_policy_sha256: str = Field(pattern=_SHA256)
    created_at: str = Field(min_length=20, max_length=40)
    signer_key_id: str = Field(pattern=_IDENTIFIER)
    signature_base64: str = Field(min_length=4, max_length=256)

    @model_validator(mode="after")
    def canonical_fields(self) -> JournalGenesisReceiptV1:
        try:
            parsed_uuid = uuid.UUID(self.journal_uuid)
            created = datetime.fromisoformat(self.created_at.removesuffix("Z") + "+00:00")
        except ValueError:
            raise ValueError("journal genesis fields are invalid") from None
        if (
            str(parsed_uuid) != self.journal_uuid
            or not self.created_at.endswith("Z")
            or not Path(self.journal_path).is_absolute()
            or os.path.normpath(self.journal_path) != self.journal_path
            or created.tzinfo is None
            or created.utcoffset() is None
            or len(_canonical_base64(self.signature_base64)) != 64
        ):
            raise ValueError("journal genesis fields are invalid")
        return self


class JournalGenesisReconciliationReceiptV1(_Model):
    """Signed reconciliation for an interrupted one-time journal genesis."""

    schema_version: Literal["rsd.authorization-journal-genesis-reconciliation.v1"]
    outcome: Literal["provisioning_completed", "provisioning_abandoned"]
    journal_uuid: str = Field(min_length=36, max_length=36)
    journal_path_sha256: str = Field(pattern=_SHA256)
    genesis_sha256: str = Field(pattern=_SHA256)
    created_at: str = Field(min_length=20, max_length=40)
    signer_key_id: str = Field(pattern=_IDENTIFIER)
    signature_base64: str = Field(min_length=4, max_length=256)

    @model_validator(mode="after")
    def canonical_fields(self) -> JournalGenesisReconciliationReceiptV1:
        try:
            parsed_uuid = uuid.UUID(self.journal_uuid)
            created = datetime.fromisoformat(self.created_at.removesuffix("Z") + "+00:00")
        except ValueError:
            raise ValueError("journal genesis reconciliation fields are invalid") from None
        if (
            str(parsed_uuid) != self.journal_uuid
            or not self.created_at.endswith("Z")
            or created.tzinfo is None
            or created.utcoffset() is None
            or len(_canonical_base64(self.signature_base64)) != 64
        ):
            raise ValueError("journal genesis reconciliation fields are invalid")
        return self


class InitialJournalGenesisReconciliationReceiptV1(_Model):
    """Signed resolution of an interrupted initial-journal genesis.

    A completed reconciliation may only expose a database and anchor that were
    already durably created before the interruption.  It never retries or
    recreates those objects after an external genesis tombstone exists.
    """

    schema_version: Literal["rsd.initial-provisioning-journal-genesis-reconciliation.v1"]
    outcome: Literal["provisioning_completed", "provisioning_abandoned"]
    journal_uuid: str = Field(pattern=_UUID)
    journal_path_sha256: str = Field(pattern=_SHA256)
    intent_sha256: str = Field(pattern=_SHA256)
    created_at: str = Field(min_length=20, max_length=40)
    signer_key_id: str = Field(pattern=_IDENTIFIER)
    signature_base64: str = Field(min_length=4, max_length=256)

    @model_validator(mode="after")
    def canonical_fields(self) -> InitialJournalGenesisReconciliationReceiptV1:
        try:
            created = datetime.fromisoformat(self.created_at.removesuffix("Z") + "+00:00")
        except ValueError:
            raise ValueError("initial journal reconciliation fields are invalid") from None
        if (
            not self.created_at.endswith("Z")
            or created.tzinfo is None
            or created.utcoffset() is None
            or len(_canonical_base64(self.signature_base64)) != 64
        ):
            raise ValueError("initial journal reconciliation fields are invalid")
        return self


class JournalProvisioningReceiptV1(_Model):
    """Value-free result of explicit, one-time journal provisioning."""

    schema_version: Literal["rsd.authorization-journal-provisioning-receipt.v1"]
    status: Literal["provisioned"]
    journal_uuid: str
    genesis_sha256: str = Field(pattern=_SHA256)
    provisioned_at: str


class ExecutionReceiptV1(_Model):
    """Non-consumable audit result returned only after a committed effect."""

    schema_version: Literal["rsd.lifecycle-execution-receipt.v1"]
    status: Literal["committed"]
    operation_kind: Literal["observed_lifecycle_v1"]
    operation_id: str
    idempotency_key: str = Field(pattern=_SHA256)
    effect_receipt_sha256: str = Field(pattern=_SHA256)
    proposal_sha256: str = Field(pattern=_SHA256)
    contract_sha256: str = Field(pattern=_SHA256)
    provider_provenance_sha256: str = Field(pattern=_SHA256)
    committed_at: str


@dataclass(frozen=True, slots=True)
class InitialProvisioningExecutionContext:
    """Opaque, bounded input for initial empty-resource creation only."""

    operation_kind: Literal["initial_provisioning_v1"]
    operation_scope: Literal["create_isolated_empty_resources_v1"]
    provisioning_operation_id: str
    intent: InitialProvisioningIntentV1
    provider_expectations: tuple[ProviderExpectationV1, ...]
    intent_sha256: str
    idempotency_key: str
    provider_provenance_sha256: str


class InitialJournalProvisioningReceiptV1(_Model):
    """Audit output for explicit pre-creation journal provisioning."""

    schema_version: Literal["rsd.initial-provisioning-journal-provisioning-receipt.v1"]
    status: Literal["provisioned"]
    operation_kind: Literal["initial_provisioning_v1"]
    provisioning_operation_id: str = Field(pattern=_UUID)
    journal_uuid: str = Field(pattern=_UUID)
    intent_sha256: str = Field(pattern=_SHA256)
    provisioned_at: str


class InitialProvisioningExecutionReceiptV1(_Model):
    """Non-bearer audit result after the bounded initial effect commits."""

    schema_version: Literal["rsd.initial-provisioning-execution-receipt.v1"]
    status: Literal["provisioned_empty"]
    operation_kind: Literal["initial_provisioning_v1"]
    operation_scope: Literal["create_isolated_empty_resources_v1"]
    provisioning_operation_id: str = Field(pattern=_UUID)
    intent_sha256: str = Field(pattern=_SHA256)
    idempotency_key: str = Field(pattern=_SHA256)
    effect_receipt_sha256: str = Field(pattern=_SHA256)
    observed_resources_sha256: str = Field(pattern=_SHA256)
    committed_at: str


@dataclass(frozen=True, slots=True)
class AuthorizationPaths:
    """Fixed artifact names prevent caller-selected substitution paths."""

    root: Path

    def preflight(self) -> PreflightPaths:
        return PreflightPaths(root=self.root)

    @staticmethod
    def signature_name(artifact_name: str) -> str:
        return f"{artifact_name}.authorization.yaml"

    @staticmethod
    def journal_genesis_name() -> str:
        return _JOURNAL_GENESIS_ARTIFACT_NAME

    @staticmethod
    def initial_intent_name() -> str:
        """Fixed artifact name for the signed pre-creation intent."""

        return _INITIAL_INTENT_ARTIFACT_NAME

    @staticmethod
    def initial_receipt_name() -> str:
        """Fixed artifact name for the bounded creation receipt."""

        return _INITIAL_RECEIPT_ARTIFACT_NAME

    @staticmethod
    def observed_attestation_name() -> str:
        """Fixed artifact name for the signed post-creation observation."""

        return _OBSERVED_ATTESTATION_ARTIFACT_NAME

    @staticmethod
    def replay_policy_name() -> str:
        """Fixed signed preimage for the external replay namespace."""

        return _REPLAY_POLICY_ARTIFACT_NAME


@dataclass(frozen=True, slots=True)
class _ArtifactVerification:
    receipt: PreflightReceiptV1
    proposal: ProposalV1
    final_contract: RuntimeContractV1


@dataclass(frozen=True, slots=True)
class _InitialStageArtifacts:
    """Root-bound planned-to-observed material, never returned to callers."""

    intent: InitialProvisioningIntentV1
    receipt: InitialProvisioningEffectReceiptV1
    attestation: ObservedCandidateAttestationV1


@dataclass(frozen=True, slots=True)
class _VerifiedExecution:
    """Opaque internal operation material that the public API never returns."""

    context: VerifiedExecutionContext
    nonce: str
    authorized_at: str
    capability: object = field(repr=False, compare=False)


@dataclass(frozen=True, slots=True)
class _VerifiedGenesis:
    """Opaque result of signed genesis verification used only by provisioning."""

    receipt: JournalGenesisReceiptV1
    artifact_sha256: str
    capability: object = field(repr=False, compare=False)


@dataclass(frozen=True, slots=True)
class _VerifiedInitialIntent:
    """Signature-verified intent admitted only to initial journal provisioning."""

    intent: InitialProvisioningIntentV1
    intent_sha256: str
    capability: object = field(repr=False, compare=False)


@dataclass(frozen=True, slots=True)
class _VerifiedInitialProvisioning:
    """Capability-bound local claim for the bounded pre-observation effect."""

    context: InitialProvisioningExecutionContext
    nonce: str
    authorized_at: str
    capability: object = field(repr=False, compare=False)


@dataclass(frozen=True, slots=True)
class _ProviderArtifactSigner:
    """Public verifier reconstructed only from an issuer-approved genesis."""

    genesis: SignerGenesisV1
    _public_key: Ed25519PublicKey = field(repr=False, compare=False)

    @classmethod
    def from_genesis(cls, genesis: SignerGenesisV1) -> _ProviderArtifactSigner:
        if type(genesis) is not SignerGenesisV1:
            raise AuthorizationError("provider_material_attestation")
        try:
            return cls(
                genesis=genesis,
                _public_key=Ed25519PublicKey.from_public_bytes(
                    _canonical_base64(genesis.public_key_base64)
                ),
            )
        except (InvalidSignature, ValueError, binascii.Error):
            raise AuthorizationError("provider_material_attestation") from None

    @property
    def key_id(self) -> str:
        return self.genesis.key_id

    @property
    def public_key_fingerprint_sha256(self) -> str:
        return self.genesis.public_key_fingerprint_sha256

    def key(self) -> Ed25519PublicKey:
        return self._public_key


def _digest(data: bytes) -> str:
    return hashlib.sha256(data).hexdigest()


def _canonical_json_bytes(value: Mapping[str, object]) -> bytes:
    try:
        return json.dumps(value, sort_keys=True, separators=(",", ":")).encode("utf-8")
    except (TypeError, ValueError):
        raise AuthorizationError("replay_authority_binding") from None


def _replay_tombstone_sha256(tombstone: ReplayTombstoneV1) -> str:
    if type(tombstone) is not ReplayTombstoneV1:
        raise AuthorizationError("replay_authority_binding")
    return _digest(
        _REPLAY_TOMBSTONE_DOMAIN + _canonical_json_bytes(tombstone.model_dump(mode="json"))
    )


def _replay_account(
    policy: ReplayAuthorityPolicyV1,
    *,
    kind: Literal[
        "initial_genesis",
        "initial_operation",
        "observed_genesis",
        "observed_operation",
    ],
    operation_id: str,
) -> str:
    if (
        type(policy) is not ReplayAuthorityPolicyV1
        or type(operation_id) is not str
        or not operation_id
    ):
        raise AuthorizationError("replay_authority_binding")
    scope = {
        "kind": kind,
        "operation_id": operation_id,
        "policy_sha256": policy.sha256(),
    }
    account_digest = _digest(_REPLAY_ACCOUNT_DOMAIN + _canonical_json_bytes(scope))
    stage = "i" if kind.startswith("initial_") else "o"
    return f"{policy.account_prefix}.{stage}.{account_digest}"


def _genesis_tombstone(
    policy: ReplayAuthorityPolicyV1,
    verified: _VerifiedGenesis,
) -> ReplayTombstoneV1:
    if type(verified) is not _VerifiedGenesis or verified.capability is not _GENESIS_CAPABILITY:
        raise AuthorizationError("replay_authority_binding")
    receipt = verified.receipt
    return ReplayTombstoneV1(
        schema_version="rsd.replay-tombstone.v1",
        kind="observed_genesis",
        operation_kind=_OBSERVED_OPERATION_KIND,
        service=policy.service,
        account=_replay_account(
            policy,
            kind="observed_genesis",
            operation_id=receipt.operation_id,
        ),
        journal_genesis_id=receipt.journal_uuid,
        operation_id=receipt.operation_id,
        proposal_sha256=receipt.proposal_sha256,
        contract_sha256=receipt.contract_sha256,
    )


def _operation_tombstone(
    policy: ReplayAuthorityPolicyV1,
    genesis: _VerifiedGenesis,
    context: VerifiedExecutionContext,
) -> ReplayTombstoneV1:
    if (
        type(genesis) is not _VerifiedGenesis
        or genesis.capability is not _GENESIS_CAPABILITY
        or type(context) is not VerifiedExecutionContext
    ):
        raise AuthorizationError("replay_authority_binding")
    receipt = genesis.receipt
    return ReplayTombstoneV1(
        schema_version="rsd.replay-tombstone.v1",
        kind="observed_operation",
        operation_kind=_OBSERVED_OPERATION_KIND,
        service=policy.service,
        account=_replay_account(
            policy,
            kind="observed_operation",
            operation_id=context.operation_id,
        ),
        journal_genesis_id=receipt.journal_uuid,
        operation_id=context.operation_id,
        proposal_sha256=context.proposal_sha256,
        contract_sha256=context.contract_sha256,
        provider_provenance_sha256=context.provider_provenance_sha256,
        idempotency_key=context.idempotency_key,
    )


def _initial_genesis_tombstone(
    policy: ReplayAuthorityPolicyV1,
    verified: _VerifiedInitialIntent,
) -> ReplayTombstoneV1:
    if (
        type(verified) is not _VerifiedInitialIntent
        or verified.capability is not _INITIAL_INTENT_CAPABILITY
    ):
        raise AuthorizationError("replay_authority_binding")
    intent = verified.intent
    return ReplayTombstoneV1(
        schema_version="rsd.replay-tombstone.v1",
        kind="initial_genesis",
        operation_kind=_INITIAL_OPERATION_KIND,
        service=policy.service,
        account=_replay_account(
            policy,
            kind="initial_genesis",
            operation_id=intent.provisioning_operation_id,
        ),
        journal_genesis_id=intent.journal_uuid,
        operation_id=intent.provisioning_operation_id,
        initial_provisioning_intent_sha256=verified.intent_sha256,
    )


def _initial_operation_tombstone(
    policy: ReplayAuthorityPolicyV1,
    verified: _VerifiedInitialProvisioning,
) -> ReplayTombstoneV1:
    if (
        type(verified) is not _VerifiedInitialProvisioning
        or verified.capability is not _INITIAL_VERIFIED_CAPABILITY
    ):
        raise AuthorizationError("replay_authority_binding")
    context = verified.context
    return ReplayTombstoneV1(
        schema_version="rsd.replay-tombstone.v1",
        kind="initial_operation",
        operation_kind=_INITIAL_OPERATION_KIND,
        service=policy.service,
        account=_replay_account(
            policy,
            kind="initial_operation",
            operation_id=context.provisioning_operation_id,
        ),
        journal_genesis_id=context.intent.journal_uuid,
        operation_id=context.provisioning_operation_id,
        initial_provisioning_intent_sha256=context.intent_sha256,
        provider_provenance_sha256=context.provider_provenance_sha256,
        idempotency_key=context.idempotency_key,
    )


def _claim_replay_tombstone(
    authority: ProtocolReplayAuthority,
    tombstone: ReplayTombstoneV1,
    *,
    phase: str,
) -> None:
    method = _replay_claim_method(authority)
    result = _safe_call(lambda: method(tombstone))
    if result is ReplayAuthorityClaimResult.CREATED:
        return
    if result in {
        ReplayAuthorityClaimResult.DUPLICATE_SAME,
        ReplayAuthorityClaimResult.DUPLICATE_CONFLICT,
    }:
        raise AuthorizationError(phase)
    raise AuthorizationError("replay_authority_failure")


def _replay_claim_method(
    authority: ProtocolReplayAuthority,
) -> Callable[[ReplayTombstoneV1], object]:
    """Validate the required injected boundary without invoking a claim."""

    method = _safe_call(lambda: authority.claim_once)
    if method is _SAFE_CALL_FAILURE or not callable(method):
        raise AuthorizationError("replay_authority_failure")
    return cast(Callable[[ReplayTombstoneV1], object], method)


class _SecurityFrameworkGenericPasswordStore:
    """Minimal Security.framework bridge with create-only generic-password writes."""

    _ERR_SEC_SUCCESS: Final = 0
    _ERR_SEC_DUPLICATE_ITEM: Final = -25299
    _UTF8: Final = 0x08000100

    def __init__(self) -> None:
        if sys.platform != "darwin":
            raise RuntimeError("Security.framework is unavailable")
        self._security: Any = ctypes.CDLL("/System/Library/Frameworks/Security.framework/Security")
        self._core: Any = ctypes.CDLL(
            "/System/Library/Frameworks/CoreFoundation.framework/CoreFoundation"
        )
        self._configure_symbols()
        self._class = self._symbol(self._security, "kSecClass")
        self._generic_password = self._symbol(self._security, "kSecClassGenericPassword")
        self._service = self._symbol(self._security, "kSecAttrService")
        self._account = self._symbol(self._security, "kSecAttrAccount")
        self._value_data = self._symbol(self._security, "kSecValueData")
        self._return_data = self._symbol(self._security, "kSecReturnData")
        self._match_limit = self._symbol(self._security, "kSecMatchLimit")
        self._match_limit_one = self._symbol(self._security, "kSecMatchLimitOne")
        self._boolean_true = self._symbol(self._core, "kCFBooleanTrue")

    def _configure_symbols(self) -> None:
        pointer = ctypes.c_void_p
        self._security.SecItemAdd.argtypes = [pointer, pointer]
        self._security.SecItemAdd.restype = ctypes.c_int32
        self._security.SecItemCopyMatching.argtypes = [pointer, ctypes.POINTER(pointer)]
        self._security.SecItemCopyMatching.restype = ctypes.c_int32
        self._core.CFStringCreateWithCString.argtypes = [pointer, ctypes.c_char_p, ctypes.c_uint32]
        self._core.CFStringCreateWithCString.restype = pointer
        self._core.CFDataCreate.argtypes = [pointer, ctypes.POINTER(ctypes.c_ubyte), ctypes.c_long]
        self._core.CFDataCreate.restype = pointer
        self._core.CFDataGetLength.argtypes = [pointer]
        self._core.CFDataGetLength.restype = ctypes.c_long
        self._core.CFDataGetBytePtr.argtypes = [pointer]
        self._core.CFDataGetBytePtr.restype = ctypes.POINTER(ctypes.c_ubyte)
        self._core.CFDictionaryCreateMutable.argtypes = [pointer, ctypes.c_long, pointer, pointer]
        self._core.CFDictionaryCreateMutable.restype = pointer
        self._core.CFDictionarySetValue.argtypes = [pointer, pointer, pointer]
        self._core.CFDictionarySetValue.restype = None
        self._core.CFRelease.argtypes = [pointer]
        self._core.CFRelease.restype = None

    @staticmethod
    def _symbol(library: Any, name: str) -> int:
        pointer = ctypes.c_void_p.in_dll(library, name).value
        if pointer is None:
            raise RuntimeError("Security.framework symbol is unavailable")
        return int(pointer)

    def _release(self, value: Any) -> None:
        if value:
            self._core.CFRelease(ctypes.c_void_p(value))

    def _string(self, value: str) -> Any:
        result = self._core.CFStringCreateWithCString(None, value.encode("utf-8"), self._UTF8)
        if not result:
            raise RuntimeError("Security.framework allocation failed")
        return result

    def _data(self, value: bytes) -> Any:
        buffer = (ctypes.c_ubyte * len(value)).from_buffer_copy(value)
        result = self._core.CFDataCreate(None, buffer, len(value))
        if not result:
            raise RuntimeError("Security.framework allocation failed")
        return result

    def _dictionary(self, entries: list[tuple[int, Any]]) -> Any:
        result = self._core.CFDictionaryCreateMutable(None, 0, None, None)
        if not result:
            raise RuntimeError("Security.framework allocation failed")
        for key, value in entries:
            self._core.CFDictionarySetValue(result, ctypes.c_void_p(key), ctypes.c_void_p(value))
        return result

    def _existing_value(self, service: str, account: str) -> bytes:
        service_value = self._string(service)
        account_value = self._string(account)
        query: Any = None
        result = ctypes.c_void_p()
        try:
            query = self._dictionary(
                [
                    (self._class, self._generic_password),
                    (self._service, service_value),
                    (self._account, account_value),
                    (self._return_data, self._boolean_true),
                    (self._match_limit, self._match_limit_one),
                ]
            )
            status = self._security.SecItemCopyMatching(query, ctypes.byref(result))
            if status != self._ERR_SEC_SUCCESS or not result.value:
                raise RuntimeError("Security.framework lookup failed")
            length = self._core.CFDataGetLength(result)
            pointer = self._core.CFDataGetBytePtr(result)
            if length < 0 or not pointer:
                raise RuntimeError("Security.framework lookup failed")
            return ctypes.string_at(pointer, length)
        finally:
            if result.value:
                self._release(result.value)
            if query:
                self._release(query)
            self._release(account_value)
            self._release(service_value)

    def add_if_absent(self, service: str, account: str, value: bytes) -> bytes | None:
        service_value = self._string(service)
        account_value = self._string(account)
        data_value = self._data(value)
        attributes: Any = None
        try:
            attributes = self._dictionary(
                [
                    (self._class, self._generic_password),
                    (self._service, service_value),
                    (self._account, account_value),
                    (self._value_data, data_value),
                ]
            )
            status = self._security.SecItemAdd(attributes, None)
            if status == self._ERR_SEC_SUCCESS:
                return None
            if status == self._ERR_SEC_DUPLICATE_ITEM:
                return self._existing_value(service, account)
            raise RuntimeError("Security.framework create failed")
        finally:
            if attributes:
                self._release(attributes)
            self._release(data_value)
            self._release(account_value)
            self._release(service_value)


def _canonical_base64(value: str) -> bytes:
    """Decode standard base64 only when its spelling is unique and canonical."""

    try:
        decoded = base64.b64decode(value, validate=True)
    except (binascii.Error, ValueError):
        raise ValueError("base64 is invalid") from None
    if base64.b64encode(decoded).decode("ascii") != value:
        raise ValueError("base64 is not canonical")
    return decoded


def _parse_document(raw: bytes, *, phase: str) -> dict[str, object]:
    try:
        document = yaml.load(raw.decode("utf-8"), Loader=_UniqueLoader)
        if type(document) is not dict or not all(type(key) is str for key in document):
            raise TypeError
        return document
    except (UnicodeDecodeError, TypeError, yaml.YAMLError):
        raise AuthorizationError(phase) from None


def _parse_signature(raw: bytes) -> DetachedAuthorizationSignatureV1:
    try:
        return DetachedAuthorizationSignatureV1.model_validate(
            _parse_document(raw, phase="signature_artifact")
        )
    except (AuthorizationError, ValidationError, ValueError):
        raise AuthorizationError("signature_artifact") from None


def _canonical_signed_content(artifact_name: str, artifact: bytes) -> bytes:
    """Canonical JSON with only the evidence signature digest omitted.

    The omitted marker is SHA-256 of the actual sidecar signature. The signer,
    key fingerprint, algorithm, and every other artifact field remain covered
    by Ed25519; raw hashes are independently checked against Phase-A bindings.
    """

    document = _parse_document(artifact, phase="artifact_content")
    normalized = copy.deepcopy(document)
    if artifact_name in _MARKED_EVIDENCE_NAMES:
        marker = normalized.get("signature")
        if type(marker) is not dict or set(marker) != {
            "algorithm",
            "detached_signature_sha256",
            "signer_key_id",
            "signer_public_key_fingerprint_sha256",
        }:
            raise AuthorizationError("signature_marker")
        digest = marker.pop("detached_signature_sha256")
        if type(digest) is not str or re.fullmatch(_SHA256, digest) is None:
            raise AuthorizationError("signature_marker")
    try:
        return json.dumps(normalized, sort_keys=True, separators=(",", ":")).encode("utf-8")
    except (TypeError, ValueError):
        raise AuthorizationError("artifact_content") from None


def _signature_message(artifact_name: str, signed_content_sha256: str) -> bytes:
    """Ed25519 input: fixed domain, artifact name, canonical-content digest."""

    return (
        _SIGNATURE_DOMAIN
        + artifact_name.encode("ascii")
        + b"\x00"
        + signed_content_sha256.encode("ascii")
    )


def _journal_genesis_message(receipt: JournalGenesisReceiptV1) -> bytes:
    material = receipt.model_dump(mode="json", exclude={"signature_base64"})
    return _JOURNAL_GENESIS_DOMAIN + json.dumps(
        material, sort_keys=True, separators=(",", ":")
    ).encode("utf-8")


def _verify_journal_genesis_signature(
    receipt: JournalGenesisReceiptV1, *, signer: TrustedEd25519SignerV1
) -> None:
    if (
        type(receipt) is not JournalGenesisReceiptV1
        or type(signer) is not TrustedEd25519SignerV1
        or receipt.signer_key_id != signer.key_id
    ):
        raise AuthorizationError("journal_genesis_signature")
    try:
        signature = _canonical_base64(receipt.signature_base64)
        signer.key().verify(signature, _journal_genesis_message(receipt))
    except (InvalidSignature, ValueError, binascii.Error):
        raise AuthorizationError("journal_genesis_signature") from None


def _direct_signature_message(domain: bytes, model: BaseModel) -> bytes:
    """Canonical domain-separated bytes for an embedded Ed25519 signature."""

    try:
        material = model.model_dump(mode="json", exclude={"signature_base64"})
        return domain + json.dumps(material, sort_keys=True, separators=(",", ":")).encode("utf-8")
    except (TypeError, ValueError):
        raise AuthorizationError("initial_stage_signature") from None


def _initial_intent_message(intent: InitialProvisioningIntentV1) -> bytes:
    if type(intent) is not InitialProvisioningIntentV1:
        raise AuthorizationError("initial_intent_signature")
    return _direct_signature_message(_INITIAL_INTENT_SIGNATURE_DOMAIN, intent)


def _observed_candidate_attestation_message(attestation: ObservedCandidateAttestationV1) -> bytes:
    if type(attestation) is not ObservedCandidateAttestationV1:
        raise AuthorizationError("observed_attestation_signature")
    return _direct_signature_message(_OBSERVED_ATTESTATION_SIGNATURE_DOMAIN, attestation)


def _verify_initial_intent_signature(
    intent: InitialProvisioningIntentV1, *, signer: TrustedEd25519SignerV1
) -> None:
    if (
        type(intent) is not InitialProvisioningIntentV1
        or type(signer) is not TrustedEd25519SignerV1
        or intent.signer_key_id != signer.key_id
    ):
        raise AuthorizationError("initial_intent_signature")
    try:
        signer.key().verify(
            _canonical_base64(intent.signature_base64), _initial_intent_message(intent)
        )
    except (InvalidSignature, ValueError, binascii.Error):
        raise AuthorizationError("initial_intent_signature") from None


def _verify_observed_candidate_attestation_signature(
    attestation: ObservedCandidateAttestationV1,
    *,
    signer: TrustedEd25519SignerV1,
) -> None:
    if (
        type(attestation) is not ObservedCandidateAttestationV1
        or type(signer) is not TrustedEd25519SignerV1
        or attestation.signer_key_id != signer.key_id
    ):
        raise AuthorizationError("observed_attestation_signature")
    try:
        signer.key().verify(
            _canonical_base64(attestation.signature_base64),
            _observed_candidate_attestation_message(attestation),
        )
    except (InvalidSignature, ValueError, binascii.Error):
        raise AuthorizationError("observed_attestation_signature") from None


def _initial_intent_artifact_bytes(intent: InitialProvisioningIntentV1) -> bytes:
    try:
        return yaml.safe_dump(intent.model_dump(mode="json"), sort_keys=True).encode("utf-8")
    except (TypeError, ValueError, yaml.YAMLError):
        raise AuthorizationError("initial_intent_artifact") from None


def _initial_receipt_artifact_bytes(receipt: InitialProvisioningEffectReceiptV1) -> bytes:
    try:
        return yaml.safe_dump(receipt.model_dump(mode="json"), sort_keys=True).encode("utf-8")
    except (TypeError, ValueError, yaml.YAMLError):
        raise AuthorizationError("initial_receipt_artifact") from None


def _journal_genesis_artifact_bytes(receipt: JournalGenesisReceiptV1) -> bytes:
    try:
        return yaml.safe_dump(receipt.model_dump(mode="json"), sort_keys=True).encode("utf-8")
    except (TypeError, ValueError, yaml.YAMLError):
        raise AuthorizationError("journal_genesis_artifact") from None


def _replay_policy_artifact_bytes(artifact: ReplayAuthorityPolicyArtifactV1) -> bytes:
    try:
        return yaml.safe_dump(artifact.model_dump(mode="json"), sort_keys=True).encode("utf-8")
    except (TypeError, ValueError, yaml.YAMLError):
        raise AuthorizationError("replay_policy_artifact") from None


def _verify_signature(
    *,
    sidecar: DetachedAuthorizationSignatureV1,
    artifact_name: str,
    artifact: bytes,
    signer: TrustedEd25519SignerV1,
) -> bytes:
    if (
        sidecar.artifact_name != artifact_name
        or sidecar.artifact_sha256 != _digest(artifact)
        or sidecar.signer_key_id != signer.key_id
        or sidecar.signed_content_sha256
        != _digest(_canonical_signed_content(artifact_name, artifact))
    ):
        raise AuthorizationError("signature_binding")
    try:
        signature = _canonical_base64(sidecar.signature_base64)
        signer.key().verify(
            signature,
            _signature_message(artifact_name, sidecar.signed_content_sha256),
        )
        return signature
    except (InvalidSignature, ValueError, binascii.Error):
        raise AuthorizationError("signature_verification") from None


def _verify_embedded_marker(
    *, signature: bytes, model: object, signer: TrustedEd25519SignerV1
) -> None:
    marker = getattr(model, "signature", None)
    if marker is None or (
        marker.algorithm != "ed25519-detached-v1"
        or marker.signer_key_id != signer.key_id
        or marker.signer_public_key_fingerprint_sha256 != signer.public_key_fingerprint_sha256
        or marker.detached_signature_sha256 != _digest(signature)
    ):
        raise AuthorizationError("signature_marker")


def _receipt_snapshot(
    paths: AuthorizationPaths,
    *,
    now: datetime,
    reader: _OwnerOnlyReader,
) -> tuple[PreflightReceiptV1, dict[str, bytes]]:
    try:
        receipt = compile_preflight(paths.preflight(), now=now, _reader=reader)
    except DisposablePreflightError as error:
        raise AuthorizationError(f"phase_a_{error.phase}") from None
    snapshot: dict[str, bytes] = {}
    try:
        for name in _ARTIFACT_NAMES:
            snapshot[name] = reader.read(name)
            snapshot[AuthorizationPaths.signature_name(name)] = reader.read(
                AuthorizationPaths.signature_name(name)
            )
    except DisposablePreflightError:
        raise AuthorizationError("artifact_snapshot") from None
    return receipt, snapshot


def _same_artifact_receipt(first: PreflightReceiptV1, second: PreflightReceiptV1) -> bool:
    """Compare Phase-A commitments without its local compilation timestamp."""

    return first.model_dump(exclude={"emitted_at"}) == second.model_dump(exclude={"emitted_at"})


def _verify_artifact_snapshot(
    paths: AuthorizationPaths,
    *,
    signer: TrustedEd25519SignerV1,
    expected_disposal_owner: str,
    expected_approver_identity: str,
    now: datetime,
    reader: _OwnerOnlyReader,
) -> tuple[_ArtifactVerification, dict[str, bytes]]:
    first, snapshot = _receipt_snapshot(paths, now=now, reader=reader)
    evidence_models: dict[str, BaseModel] = {}
    model_types: Mapping[str, type[BaseModel] | None] = {
        "approval.yaml": ApprovalEvidenceV1,
        "governed-baseline.yaml": GovernedBaselineV1,
        "target-attestation.yaml": TargetAttestationV1,
        "provider-declaration.yaml": ProviderDeclarationV1,
        "registry-verification.yaml": RegistryVerificationV1,
        "postgres-overlay.yaml": None,
    }
    for name in _ARTIFACT_NAMES:
        artifact = snapshot[name]
        sidecar = _parse_signature(snapshot[AuthorizationPaths.signature_name(name)])
        signature = _verify_signature(
            sidecar=sidecar, artifact_name=name, artifact=artifact, signer=signer
        )
        model_type = model_types.get(name)
        if model_type is not None:
            try:
                parsed = model_type.model_validate(
                    _parse_document(artifact, phase="evidence_model")
                )
            except (AuthorizationError, ValidationError):
                raise AuthorizationError("evidence_model") from None
            evidence_models[name] = parsed
            _verify_embedded_marker(signature=signature, model=parsed, signer=signer)
    try:
        proposal = ProposalV1.model_validate(
            _parse_document(snapshot["proposal.yaml"], phase="proposal")
        )
        final_contract = RuntimeContractV1.model_validate(
            _parse_document(snapshot["runtime-contract.yaml"], phase="contract")
        )
    except (AuthorizationError, ValidationError):
        raise AuthorizationError("proposal_contract") from None
    if datetime.fromisoformat(proposal.retention_expires_at.removesuffix("Z") + "+00:00") <= now:
        raise AuthorizationError("retention")
    approval = evidence_models.get("approval.yaml")
    if (
        type(expected_disposal_owner) is not str
        or type(expected_approver_identity) is not str
        or proposal.disposal_owner != expected_disposal_owner
        or not isinstance(approval, ApprovalEvidenceV1)
        or approval.approver_identity != expected_approver_identity
    ):
        raise AuthorizationError("owner_approval")
    return _ArtifactVerification(first, proposal, final_contract), snapshot


def _verify_journal_genesis_artifact(
    paths: AuthorizationPaths,
    *,
    artifacts: _ArtifactVerification,
    signer: TrustedEd25519SignerV1,
    expected_disposal_owner: str,
    expected_approver_identity: str,
    journal: SQLiteAuthorizationJournal,
    replay_policy: ReplayAuthorityPolicyV1,
    now: datetime,
    reader: _OwnerOnlyReader,
) -> tuple[_VerifiedGenesis, bytes]:
    """Verify the signed root genesis artifact against this exact journal path."""

    try:
        raw = reader.read(paths.journal_genesis_name())
    except DisposablePreflightError:
        raise AuthorizationError("journal_genesis_artifact") from None
    try:
        receipt = JournalGenesisReceiptV1.model_validate(
            _parse_document(raw, phase="journal_genesis_artifact")
        )
    except (AuthorizationError, ValidationError, ValueError):
        raise AuthorizationError("journal_genesis_artifact") from None
    _verify_journal_genesis_binding(
        receipt,
        artifacts=artifacts,
        signer=signer,
        expected_disposal_owner=expected_disposal_owner,
        expected_approver_identity=expected_approver_identity,
        journal=journal,
        replay_policy=replay_policy,
        now=now,
    )
    return (
        _VerifiedGenesis(
            receipt=receipt,
            artifact_sha256=_digest(raw),
            capability=_GENESIS_CAPABILITY,
        ),
        raw,
    )


def _verify_journal_genesis_binding(
    receipt: JournalGenesisReceiptV1,
    *,
    artifacts: _ArtifactVerification,
    signer: TrustedEd25519SignerV1,
    expected_disposal_owner: str,
    expected_approver_identity: str,
    journal: SQLiteAuthorizationJournal,
    replay_policy: ReplayAuthorityPolicyV1,
    now: datetime,
) -> None:
    if type(replay_policy) is not ReplayAuthorityPolicyV1:
        raise AuthorizationError("replay_authority_policy")
    _verify_journal_genesis_signature(receipt, signer=signer)
    try:
        created = datetime.fromisoformat(receipt.created_at.removesuffix("Z") + "+00:00")
    except ValueError:
        raise AuthorizationError("journal_genesis_artifact") from None
    if (
        created.tzinfo is None
        or created.utcoffset() is None
        or created.astimezone(UTC) > now
        or receipt.operation_domain != _JOURNAL_OPERATION_DOMAIN
        or receipt.operation_id != artifacts.receipt.operation_id
        or receipt.proposal_sha256 != artifacts.receipt.proposal_sha256
        or receipt.contract_sha256 != artifacts.receipt.contract_sha256
        or receipt.disposal_owner != expected_disposal_owner
        or receipt.approver_identity != expected_approver_identity
        or receipt.journal_path != str(journal._path)
        or receipt.journal_path_sha256 != journal._path_sha256()
        or receipt.journal_schema_sha256 != journal.journal_schema_sha256()
        or receipt.replay_policy_sha256 != replay_policy.sha256()
    ):
        raise AuthorizationError("journal_genesis_binding")


def _verify_authorization_artifact_snapshot(
    paths: AuthorizationPaths,
    *,
    signer: TrustedEd25519SignerV1,
    expected_disposal_owner: str,
    expected_approver_identity: str,
    journal: SQLiteAuthorizationJournal,
    replay_policy: ReplayAuthorityPolicyV1,
    now: datetime,
    reader: _OwnerOnlyReader,
) -> tuple[_ArtifactVerification, _VerifiedGenesis, dict[str, bytes]]:
    artifacts, snapshot = _verify_artifact_snapshot(
        paths,
        signer=signer,
        expected_disposal_owner=expected_disposal_owner,
        expected_approver_identity=expected_approver_identity,
        now=now,
        reader=reader,
    )
    genesis, raw = _verify_journal_genesis_artifact(
        paths,
        artifacts=artifacts,
        signer=signer,
        expected_disposal_owner=expected_disposal_owner,
        expected_approver_identity=expected_approver_identity,
        journal=journal,
        replay_policy=replay_policy,
        now=now,
        reader=reader,
    )
    snapshot[paths.journal_genesis_name()] = raw
    return artifacts, genesis, snapshot


def _read_initial_stage_artifacts(
    paths: AuthorizationPaths,
    *,
    signer: TrustedEd25519SignerV1,
    expected_disposal_owner: str,
    expected_approver_identity: str,
    now: datetime,
    reader: _OwnerOnlyReader,
) -> tuple[_InitialStageArtifacts, dict[str, bytes]]:
    """Read and verify the signed stage hand-off through the locked root fd."""

    names = (
        paths.initial_intent_name(),
        paths.initial_receipt_name(),
        paths.observed_attestation_name(),
    )
    try:
        raw = {name: reader.read(name) for name in names}
        intent = InitialProvisioningIntentV1.model_validate(
            _parse_document(raw[paths.initial_intent_name()], phase="initial_intent_artifact")
        )
        receipt = InitialProvisioningEffectReceiptV1.model_validate(
            _parse_document(raw[paths.initial_receipt_name()], phase="initial_receipt_artifact")
        )
        attestation = ObservedCandidateAttestationV1.model_validate(
            _parse_document(
                raw[paths.observed_attestation_name()], phase="observed_attestation_artifact"
            )
        )
    except (AuthorizationError, DisposablePreflightError, ValidationError, ValueError):
        raise AuthorizationError("initial_stage_artifact") from None
    _verify_initial_intent_signature(intent, signer=signer)
    _verify_observed_candidate_attestation_signature(attestation, signer=signer)
    try:
        created = datetime.fromisoformat(intent.created_at.removesuffix("Z") + "+00:00")
        completed = datetime.fromisoformat(receipt.completed_at.removesuffix("Z") + "+00:00")
        observed = datetime.fromisoformat(attestation.observed_at.removesuffix("Z") + "+00:00")
        retained = datetime.fromisoformat(intent.retention_expires_at.removesuffix("Z") + "+00:00")
    except ValueError:
        raise AuthorizationError("initial_stage_freshness") from None
    if (
        created.tzinfo is None
        or completed.tzinfo is None
        or observed.tzinfo is None
        or retained.tzinfo is None
        or created.astimezone(UTC) > now
        or completed.astimezone(UTC) > now
        or observed.astimezone(UTC) > now
        or completed.astimezone(UTC) < created.astimezone(UTC)
        or observed.astimezone(UTC) < completed.astimezone(UTC)
        or now - observed.astimezone(UTC) > _STAGE_ATTESTATION_FRESHNESS
        or retained.astimezone(UTC) <= now
        or intent.disposal_owner != expected_disposal_owner
        or intent.approver_identity != expected_approver_identity
    ):
        raise AuthorizationError("initial_stage_freshness")
    return _InitialStageArtifacts(intent, receipt, attestation), raw


def _read_verified_initial_intent(
    paths: AuthorizationPaths,
    *,
    signer: TrustedEd25519SignerV1,
    expected_disposal_owner: str,
    expected_approver_identity: str,
    now: datetime,
    reader: _OwnerOnlyReader,
) -> tuple[_VerifiedInitialIntent, bytes]:
    """Read the root-bound signed intent without constructing any journal."""

    try:
        raw = reader.read(paths.initial_intent_name())
        intent = InitialProvisioningIntentV1.model_validate(
            _parse_document(raw, phase="initial_intent_artifact")
        )
    except (AuthorizationError, DisposablePreflightError, ValidationError, ValueError):
        raise AuthorizationError("initial_intent_artifact") from None
    _verify_initial_intent_signature(intent, signer=signer)
    try:
        created = datetime.fromisoformat(intent.created_at.removesuffix("Z") + "+00:00")
        retention = datetime.fromisoformat(intent.retention_expires_at.removesuffix("Z") + "+00:00")
    except ValueError:
        raise AuthorizationError("initial_intent_freshness") from None
    if (
        created.tzinfo is None
        or retention.tzinfo is None
        or created.astimezone(UTC) > now
        or now - created.astimezone(UTC) > _STAGE_ATTESTATION_FRESHNESS
        or retention.astimezone(UTC) <= now
        or intent.disposal_owner != expected_disposal_owner
        or intent.approver_identity != expected_approver_identity
    ):
        raise AuthorizationError("initial_intent_freshness")
    return (
        _VerifiedInitialIntent(
            intent=intent,
            intent_sha256=initial_provisioning_intent_sha256(intent),
            capability=_INITIAL_INTENT_CAPABILITY,
        ),
        raw,
    )


def _read_replay_policy_artifact(
    paths: AuthorizationPaths,
    *,
    signer: TrustedEd25519SignerV1,
    initial_intent: InitialProvisioningIntentV1,
    replay_policy: ReplayAuthorityPolicyV1,
    reader: _OwnerOnlyReader,
) -> tuple[ReplayAuthorityPolicyArtifactV1, bytes]:
    """Verify the root-persisted replay policy before a tombstone is claimed."""

    def read_and_verify() -> tuple[ReplayAuthorityPolicyArtifactV1, bytes]:
        raw = reader.read(paths.replay_policy_name())
        artifact = ReplayAuthorityPolicyArtifactV1.model_validate(
            _parse_document(raw, phase="replay_policy_artifact")
        )
        verify_replay_authority_policy_artifact(
            artifact,
            signer=signer,
            initial_intent=initial_intent,
            expected_policy_sha256=replay_policy.sha256(),
        )
        return artifact, raw

    result = _safe_call(read_and_verify)
    if (
        type(result) is not tuple
        or len(result) != 2
        or type(result[0]) is not ReplayAuthorityPolicyArtifactV1
        or type(result[1]) is not bytes
    ):
        raise AuthorizationError("replay_policy_artifact")
    return result[0], result[1]


def _trusted_provider_fingerprints(
    *,
    signer: TrustedEd25519SignerV1,
    initial_intent: InitialProvisioningIntentV1,
    expected_disposal_owner: str,
    expected_approver_identity: str,
    now: datetime,
    reader: _OwnerOnlyReader,
) -> tuple[dict[str, str], tuple[str, str, str, str]]:
    """Load the completed material state from the locked artifact root only.

    Caller models are deliberately not accepted here.  The signer genesis,
    policy, pending manifest, and terminal attestation are all descriptor-
    relative, owner-only files. Their raw hashes become part of the repeated
    authorization snapshot so a replacement cannot survive to an effect.
    """

    def verify() -> tuple[dict[str, str], tuple[str, str, str, str]]:
        signer_genesis, signer_hash = _load_verified_signer_genesis_from_reader(
            reader,
            issuer=signer,
            initial_intent=initial_intent,
        )
        provider_signer = _ProviderArtifactSigner.from_genesis(signer_genesis)
        _policy, _genesis, attestation, material_hashes = (
            _load_verified_provider_material_bundle_from_reader_at(
                reader,
                signer=provider_signer,
                signer_genesis=signer_genesis,
                issuer=signer,
                initial_intent=initial_intent,
                expected_disposal_owner=expected_disposal_owner,
                expected_approver_identity=expected_approver_identity,
                now=now,
            )
        )
        return attestation.fingerprint_by_reference(), (signer_hash, *material_hashes)

    result = _safe_call(verify)
    if (
        type(result) is not tuple
        or len(result) != 2
        or type(result[0]) is not dict
        or type(result[1]) is not tuple
        or len(result[1]) != 4
        or not all(
            type(reference) is str and type(fingerprint) is str
            for reference, fingerprint in result[0].items()
        )
        or not all(
            type(value) is str and re.fullmatch(_SHA256, value) is not None for value in result[1]
        )
    ):
        raise AuthorizationError("provider_material_attestation")
    return result[0], result[1]


def _safe_call(call: Callable[[], object]) -> object:
    """Discard arbitrary adapter or callback failures before they escape a boundary."""

    try:
        return call()
    except Exception:
        return _SAFE_CALL_FAILURE


def _provider_item(
    lease: ProviderSnapshotLease, reference: ProviderReferenceV1, *, recheck: bool
) -> ProviderProvenance | None:
    method_name = "recheck" if recheck else "inspect"
    method = _safe_call(lambda: getattr(lease, method_name))
    if method is _SAFE_CALL_FAILURE or not callable(method):
        raise AuthorizationError("provider_failure")
    item = _safe_call(lambda: method(reference))
    if item is _SAFE_CALL_FAILURE:
        raise AuthorizationError("provider_failure")
    if item is None:
        return None
    candidate = cast(ProviderProvenance, item)
    fields = _safe_call(
        lambda: (
            candidate.provider,
            candidate.service,
            candidate.account,
            candidate.version,
            candidate.reference_sha256,
            candidate.fingerprint_sha256,
        )
    )
    if fields is _SAFE_CALL_FAILURE or type(fields) is not tuple or len(fields) != 6:
        raise AuthorizationError("provider_failure")
    provider, service, account, version, reference_sha256, fingerprint_sha256 = fields
    if (
        type(provider) is not str
        or type(service) is not str
        or type(account) is not str
        or type(version) is not int
        or type(reference_sha256) is not str
        or type(fingerprint_sha256) is not str
    ):
        raise AuthorizationError("provider_provenance")
    return ProviderProvenance(
        provider=provider,
        service=service,
        account=account,
        version=version,
        reference_sha256=reference_sha256,
        fingerprint_sha256=fingerprint_sha256,
    )


def _provider_expectation(item: ProviderProvenance) -> ProviderExpectationV1:
    expected = _safe_call(
        lambda: ProviderExpectationV1(
            provider=item.provider,
            service=item.service,
            account=item.account,
            version=item.version,
            reference_sha256=item.reference_sha256,
            fingerprint_sha256=item.fingerprint_sha256,
        )
    )
    if type(expected) is not ProviderExpectationV1:
        raise AuthorizationError("provider_provenance")
    return expected


def _provider_commitment(
    *,
    references: tuple[ProviderReferenceV1, ...],
    lease: ProviderSnapshotLease,
    fingerprints: Mapping[str, str],
    recheck: bool,
) -> tuple[str, tuple[ProviderExpectationV1, ...]]:
    if set(fingerprints) != {reference.reference_sha256 for reference in references}:
        raise AuthorizationError("provider_policy")
    if any(
        type(value) is not str or re.fullmatch(_SHA256, value) is None
        for value in fingerprints.values()
    ):
        raise AuthorizationError("provider_policy")
    expected: list[ProviderExpectationV1] = []
    observed: list[dict[str, object]] = []
    for reference in references:
        item = _provider_item(lease, reference, recheck=recheck)
        expected_fingerprint = fingerprints[reference.reference_sha256]
        if item is None or (
            item.provider != reference.provider
            or item.service != reference.service
            or item.account != reference.account
            or item.version != reference.version
            or item.reference_sha256 != reference.reference_sha256
            or item.fingerprint_sha256 != expected_fingerprint
        ):
            raise AuthorizationError("provider_provenance")
        expected.append(_provider_expectation(item))
        observed.append(expected[-1].model_dump(mode="json"))
    return (
        _digest(json.dumps(observed, sort_keys=True, separators=(",", ":")).encode()),
        tuple(expected),
    )


def _idempotency_key(
    *, operation_id: str, proposal_sha256: str, contract_sha256: str, provider_sha256: str
) -> str:
    material = "\x00".join(
        (operation_id, proposal_sha256, contract_sha256, provider_sha256)
    ).encode("ascii")
    return _digest(_IDEMPOTENCY_DOMAIN + material)


def _initial_idempotency_key(
    *, provisioning_operation_id: str, intent_sha256: str, provider_sha256: str
) -> str:
    material = "\x00".join((provisioning_operation_id, intent_sha256, provider_sha256)).encode(
        "ascii"
    )
    return _digest(_INITIAL_IDEMPOTENCY_DOMAIN + material)


class ArtifactRootLease:
    """A canonical-parent lock and stable directory descriptor for artifacts.

    The lock is placed beside the canonical root rather than inside it.  That
    makes root replacement, renaming, and lock-file replacement observable
    while the original directory descriptor remains the only read capability.
    """

    def __init__(self, root: Path) -> None:
        self._requested_root = root
        self._canonical_root: Path | None = None
        self._parent: Path | None = None
        self._lock_name: str | None = None
        self._lock_key: tuple[int, int, int, int] | None = None
        self._parent_identity: tuple[int, int] | None = None
        self._root_identity: tuple[int, int] | None = None
        self._lock_identity: tuple[int, int] | None = None
        self._parent_descriptor: int | None = None
        self._root_descriptor: int | None = None
        self._lock_descriptor: int | None = None

    @staticmethod
    def _validate_directory_details(details: os.stat_result, phase: str) -> tuple[int, int]:
        if (
            not stat.S_ISDIR(details.st_mode)
            or stat.S_ISLNK(details.st_mode)
            or details.st_uid != os.getuid()
            or stat.S_IMODE(details.st_mode) != 0o700
        ):
            raise AuthorizationError(phase)
        return (details.st_dev, details.st_ino)

    @staticmethod
    def _validate_file_details(details: os.stat_result, phase: str) -> tuple[int, int]:
        if (
            not stat.S_ISREG(details.st_mode)
            or stat.S_ISLNK(details.st_mode)
            or details.st_uid != os.getuid()
            or stat.S_IMODE(details.st_mode) != 0o600
            or details.st_nlink != 1
        ):
            raise AuthorizationError(phase)
        return (details.st_dev, details.st_ino)

    @classmethod
    def _directory_identity(cls, path: Path, phase: str) -> tuple[int, int]:
        try:
            return cls._validate_directory_details(os.lstat(path), phase)
        except AuthorizationError:
            raise
        except OSError:
            raise AuthorizationError(phase) from None

    @classmethod
    def _file_identity_at(cls, descriptor: int, name: str, phase: str) -> tuple[int, int]:
        try:
            return cls._validate_file_details(os.lstat(name, dir_fd=descriptor), phase)
        except AuthorizationError:
            raise
        except OSError:
            raise AuthorizationError(phase) from None

    @classmethod
    def _open_directory(cls, path: Path, phase: str) -> tuple[int, tuple[int, int]]:
        before = cls._directory_identity(path, phase)
        descriptor: int | None = None
        try:
            descriptor = os.open(
                path,
                os.O_RDONLY
                | getattr(os, "O_DIRECTORY", 0)
                | getattr(os, "O_CLOEXEC", 0)
                | getattr(os, "O_NOFOLLOW", 0),
            )
            after = cls._validate_directory_details(os.fstat(descriptor), phase)
        except AuthorizationError:
            if descriptor is not None:
                with suppress(OSError):
                    os.close(descriptor)
            raise
        except OSError:
            if descriptor is not None:
                with suppress(OSError):
                    os.close(descriptor)
            raise AuthorizationError(phase) from None
        if before != after:
            with suppress(OSError):
                os.close(descriptor)
            raise AuthorizationError(phase)
        return descriptor, after

    @classmethod
    def _open_lock_file(cls, parent_descriptor: int, name: str) -> tuple[int, tuple[int, int]]:
        try:
            before = cls._file_identity_at(parent_descriptor, name, "artifact_lock_file")
        except AuthorizationError:
            try:
                os.lstat(name, dir_fd=parent_descriptor)
            except FileNotFoundError:
                flags = (
                    os.O_RDWR
                    | os.O_CREAT
                    | os.O_EXCL
                    | getattr(os, "O_CLOEXEC", 0)
                    | getattr(os, "O_NOFOLLOW", 0)
                )
                try:
                    created = os.open(name, flags, 0o600, dir_fd=parent_descriptor)
                except FileExistsError:
                    pass
                except OSError:
                    raise AuthorizationError("artifact_lock_file") from None
                else:
                    try:
                        cls._validate_file_details(os.fstat(created), "artifact_lock_file")
                    finally:
                        with suppress(OSError):
                            os.close(created)
            except OSError:
                raise AuthorizationError("artifact_lock_file") from None
            before = cls._file_identity_at(parent_descriptor, name, "artifact_lock_file")
        descriptor: int | None = None
        try:
            descriptor = os.open(
                name,
                os.O_RDWR | getattr(os, "O_CLOEXEC", 0) | getattr(os, "O_NOFOLLOW", 0),
                dir_fd=parent_descriptor,
            )
            after = cls._validate_file_details(os.fstat(descriptor), "artifact_lock_file")
        except AuthorizationError:
            if descriptor is not None:
                with suppress(OSError):
                    os.close(descriptor)
            raise
        except OSError:
            if descriptor is not None:
                with suppress(OSError):
                    os.close(descriptor)
            raise AuthorizationError("artifact_lock_file") from None
        assert descriptor is not None
        if before != after or before != cls._file_identity_at(
            parent_descriptor, name, "artifact_lock_file"
        ):
            with suppress(OSError):
                os.close(descriptor)
            raise AuthorizationError("artifact_lock_file")
        return descriptor, after

    @staticmethod
    def _canonicalize_root(root: Path) -> Path:
        try:
            details = os.lstat(root)
        except OSError:
            raise AuthorizationError("artifact_lock_root") from None
        if stat.S_ISLNK(details.st_mode):
            raise AuthorizationError("artifact_lock_root")
        canonical = Path(os.path.realpath(root))
        ArtifactRootLease._directory_identity(canonical, "artifact_lock_root")
        return canonical

    @staticmethod
    def _lock_name_for_identities(
        parent_identity: tuple[int, int], root_identity: tuple[int, int]
    ) -> tuple[str, tuple[int, int, int, int]]:
        """Name one parent-anchored lock from opened directory identities.

        The key deliberately contains device and inode values, not the spelling
        of the path.  That makes aliases of the same directory converge while
        the path checks in ``assert_stable`` still reject replacement.
        """

        key = (*parent_identity, *root_identity)
        material = ":".join(str(value) for value in key).encode("ascii")
        return f"{_ARTIFACT_LOCK_PREFIX}{_digest(material)}.lock", key

    @staticmethod
    def _claim_process_lock(key: tuple[int, int, int, int]) -> None:
        """Reject same-process recursive and concurrent leases before flock.

        BSD ``flock`` ownership is process-oriented, so a second descriptor in
        the same process may not block itself.  This registry preserves the
        one-effect-at-a-time invariant without relying on that platform detail.
        """

        current = get_ident()
        with _ARTIFACT_LOCK_REGISTRY_GUARD:
            owner = _ARTIFACT_LOCK_REGISTRY.get(key)
            if owner is not None:
                phase = "artifact_lock_reentrant" if owner == current else "artifact_lock_busy"
                raise AuthorizationError(phase)
            _ARTIFACT_LOCK_REGISTRY[key] = current

    @staticmethod
    def _release_process_lock(key: tuple[int, int, int, int] | None) -> None:
        if key is None:
            return
        with _ARTIFACT_LOCK_REGISTRY_GUARD:
            _ARTIFACT_LOCK_REGISTRY.pop(key, None)

    def __enter__(self) -> ArtifactRootLease:
        canonical = self._canonicalize_root(self._requested_root)
        parent = canonical.parent
        parent_descriptor: int | None = None
        root_descriptor: int | None = None
        lock_descriptor: int | None = None
        lock_key: tuple[int, int, int, int] | None = None
        process_lock_claimed = False
        try:
            parent_descriptor, parent_identity = self._open_directory(parent, "artifact_lock_root")
            root_descriptor, root_identity = self._open_directory(canonical, "artifact_lock_root")
            lock_name, lock_key = self._lock_name_for_identities(parent_identity, root_identity)
            self._claim_process_lock(lock_key)
            process_lock_claimed = True
            lock_descriptor, lock_identity = self._open_lock_file(parent_descriptor, lock_name)
            try:
                fcntl.flock(lock_descriptor, fcntl.LOCK_EX | fcntl.LOCK_NB)
            except OSError as error:
                if error.errno in {errno.EACCES, errno.EAGAIN}:
                    raise AuthorizationError("artifact_lock_busy") from None
                raise AuthorizationError("artifact_lock_file") from None
            self._canonical_root = canonical
            self._parent = parent
            self._lock_name = lock_name
            self._lock_key = lock_key
            self._parent_identity = parent_identity
            self._root_identity = root_identity
            self._lock_identity = lock_identity
            self._parent_descriptor = parent_descriptor
            self._root_descriptor = root_descriptor
            self._lock_descriptor = lock_descriptor
            self.assert_stable()
            return self
        except AuthorizationError:
            self._close_descriptors(lock_descriptor, root_descriptor, parent_descriptor)
            if process_lock_claimed:
                self._release_process_lock(lock_key)
            raise
        except OSError:
            self._close_descriptors(lock_descriptor, root_descriptor, parent_descriptor)
            if process_lock_claimed:
                self._release_process_lock(lock_key)
            raise AuthorizationError("artifact_lock_file") from None

    @staticmethod
    def _close_descriptors(
        lock_descriptor: int | None,
        root_descriptor: int | None,
        parent_descriptor: int | None,
    ) -> None:
        if lock_descriptor is not None:
            with suppress(OSError):
                fcntl.flock(lock_descriptor, fcntl.LOCK_UN)
            with suppress(OSError):
                os.close(lock_descriptor)
        for descriptor in (root_descriptor, parent_descriptor):
            if descriptor is not None:
                with suppress(OSError):
                    os.close(descriptor)

    def assert_stable(self) -> None:
        """Fail closed if any locked path or descriptor identity changed."""

        if (
            self._canonical_root is None
            or self._parent is None
            or self._lock_name is None
            or self._parent_identity is None
            or self._root_identity is None
            or self._lock_identity is None
            or self._parent_descriptor is None
            or self._root_descriptor is None
            or self._lock_descriptor is None
        ):
            raise AuthorizationError("artifact_lock_state")
        if self._directory_identity(self._parent, "artifact_lock_root") != self._parent_identity:
            raise AuthorizationError("artifact_lock_root")
        if (
            self._directory_identity(self._canonical_root, "artifact_lock_root")
            != self._root_identity
        ):
            raise AuthorizationError("artifact_lock_root")
        try:
            parent_identity = self._validate_directory_details(
                os.fstat(self._parent_descriptor), "artifact_lock_root"
            )
            root_identity = self._validate_directory_details(
                os.fstat(self._root_descriptor), "artifact_lock_root"
            )
            lock_identity = self._validate_file_details(
                os.fstat(self._lock_descriptor), "artifact_lock_file"
            )
        except AuthorizationError:
            raise
        except OSError:
            raise AuthorizationError("artifact_lock_state") from None
        if (
            parent_identity != self._parent_identity
            or root_identity != self._root_identity
            or lock_identity != self._lock_identity
            or self._file_identity_at(
                self._parent_descriptor, self._lock_name, "artifact_lock_file"
            )
            != self._lock_identity
        ):
            raise AuthorizationError("artifact_lock_state")

    def reader(self) -> _OwnerOnlyReader:
        """Return a reader bound to the locked root descriptor."""

        self.assert_stable()
        assert self._canonical_root is not None
        assert self._root_descriptor is not None
        return _OwnerOnlyReader(self._canonical_root, root_fd=self._root_descriptor)

    def write_once(self, name: str, payload: bytes, *, phase: str) -> None:
        """Create one bounded, owner-only artifact through the locked root fd."""

        if (
            "/" in name
            or name.startswith(".")
            or type(payload) is not bytes
            or len(payload) > _MAX_ARTIFACT_BYTES
        ):
            raise AuthorizationError(phase)
        self.assert_stable()
        assert self._root_descriptor is not None
        flags = os.O_WRONLY | os.O_CREAT | os.O_EXCL | getattr(os, "O_CLOEXEC", 0)
        flags |= getattr(os, "O_NOFOLLOW", 0)
        try:
            descriptor = os.open(name, flags, 0o600, dir_fd=self._root_descriptor)
        except FileExistsError:
            raise AuthorizationError(phase) from None
        except OSError:
            raise AuthorizationError(phase) from None
        try:
            details = self._validate_file_details(os.fstat(descriptor), phase)
            remaining = memoryview(payload)
            while remaining:
                written = os.write(descriptor, remaining)
                if written <= 0:
                    raise AuthorizationError(phase)
                remaining = remaining[written:]
            os.fsync(descriptor)
            if details != self._file_identity_at(self._root_descriptor, name, phase):
                raise AuthorizationError(phase)
        except AuthorizationError:
            raise
        except OSError:
            raise AuthorizationError(phase) from None
        finally:
            with suppress(OSError):
                os.close(descriptor)
        try:
            # ``fsync`` of the new file does not itself make its directory
            # entry durable.  The replay-policy preimage is deliberately
            # persisted before an irreversible external tombstone claim, so
            # make both pieces durable while holding the anchored root lease.
            os.fsync(self._root_descriptor)
        except OSError:
            raise AuthorizationError(phase) from None
        self.assert_stable()

    def read_optional(self, name: str, *, phase: str) -> bytes | None:
        """Read one existing owner-only artifact, or prove its absence.

        This is intentionally lease-local: callers must not reopen the root
        by path between an absence check and a subsequent create-once write.
        """

        if "/" in name or name.startswith("."):
            raise AuthorizationError(phase)
        self.assert_stable()
        assert self._root_descriptor is not None
        try:
            details = os.lstat(name, dir_fd=self._root_descriptor)
        except FileNotFoundError:
            return None
        except OSError:
            raise AuthorizationError(phase) from None
        try:
            self._validate_file_details(details, phase)
            return self.reader().read(name)
        except (AuthorizationError, DisposablePreflightError):
            raise AuthorizationError(phase) from None

    def write_once_or_require_exact(self, name: str, payload: bytes, *, phase: str) -> None:
        """Persist one immutable file, accepting only byte-identical recovery."""

        existing = self.read_optional(name, phase=phase)
        if existing is None:
            self.write_once(name, payload, phase=phase)
            return
        if not hmac.compare_digest(existing, payload):
            raise AuthorizationError(phase)

    def assert_absent(self, name: str, *, phase: str) -> None:
        """Require that an artifact name is absent through the locked root fd."""

        if "/" in name or name.startswith("."):
            raise AuthorizationError(phase)
        self.assert_stable()
        assert self._root_descriptor is not None
        try:
            os.lstat(name, dir_fd=self._root_descriptor)
        except FileNotFoundError:
            return
        except OSError:
            raise AuthorizationError(phase) from None
        raise AuthorizationError(phase)

    def __exit__(self, exception_type: object, exception: object, traceback: object) -> None:
        del exception_type, exception, traceback
        self._close_descriptors(
            self._lock_descriptor, self._root_descriptor, self._parent_descriptor
        )
        self._release_process_lock(self._lock_key)
        self._canonical_root = None
        self._parent = None
        self._lock_name = None
        self._lock_key = None
        self._parent_identity = None
        self._root_identity = None
        self._lock_identity = None
        self._parent_descriptor = None
        self._root_descriptor = None
        self._lock_descriptor = None


class _OperationLease:
    """One durable, owner-only advisory lease file per operation identifier."""

    def __init__(
        self,
        journal: SQLiteAuthorizationJournal,
        operation_id: str,
        *,
        nonblocking: bool,
        prefix: str = _OPERATION_LEASE_PREFIX,
    ) -> None:
        self._journal = journal
        self._operation_id = operation_id
        self._nonblocking = nonblocking
        self._parent_descriptor: int | None = None
        self._file_descriptor: int | None = None
        self._parent_identity: tuple[int, int] | None = None
        self._file_identity: tuple[int, int] | None = None
        self._name = f"{prefix}{_digest(operation_id.encode())}.lock"

    @staticmethod
    def _open_file(parent_descriptor: int, name: str) -> tuple[int, tuple[int, int]]:
        try:
            before = ArtifactRootLease._file_identity_at(parent_descriptor, name, "operation_lease")
        except AuthorizationError:
            try:
                os.lstat(name, dir_fd=parent_descriptor)
            except FileNotFoundError:
                flags = (
                    os.O_RDWR
                    | os.O_CREAT
                    | os.O_EXCL
                    | getattr(os, "O_CLOEXEC", 0)
                    | getattr(os, "O_NOFOLLOW", 0)
                )
                try:
                    created = os.open(name, flags, 0o600, dir_fd=parent_descriptor)
                except FileExistsError:
                    pass
                except OSError:
                    raise AuthorizationError("operation_lease") from None
                else:
                    try:
                        ArtifactRootLease._validate_file_details(
                            os.fstat(created), "operation_lease"
                        )
                    finally:
                        with suppress(OSError):
                            os.close(created)
            except OSError:
                raise AuthorizationError("operation_lease") from None
            before = ArtifactRootLease._file_identity_at(parent_descriptor, name, "operation_lease")
        descriptor: int | None = None
        try:
            descriptor = os.open(
                name,
                os.O_RDWR | getattr(os, "O_CLOEXEC", 0) | getattr(os, "O_NOFOLLOW", 0),
                dir_fd=parent_descriptor,
            )
            after = ArtifactRootLease._validate_file_details(
                os.fstat(descriptor), "operation_lease"
            )
        except AuthorizationError:
            if descriptor is not None:
                with suppress(OSError):
                    os.close(descriptor)
            raise
        except OSError:
            if descriptor is not None:
                with suppress(OSError):
                    os.close(descriptor)
            raise AuthorizationError("operation_lease") from None
        assert descriptor is not None
        if before != after or before != ArtifactRootLease._file_identity_at(
            parent_descriptor, name, "operation_lease"
        ):
            with suppress(OSError):
                os.close(descriptor)
            raise AuthorizationError("operation_lease")
        return descriptor, after

    def __enter__(self) -> _OperationLease:
        if not self._journal._path.is_absolute():
            raise AuthorizationError("journal_path")
        parent_descriptor: int | None = None
        file_descriptor: int | None = None
        try:
            parent_descriptor, parent_identity = ArtifactRootLease._open_directory(
                self._journal._path.parent, "journal_directory"
            )
            file_descriptor, file_identity = self._open_file(parent_descriptor, self._name)
            lock_flags = fcntl.LOCK_EX | (fcntl.LOCK_NB if self._nonblocking else 0)
            try:
                fcntl.flock(file_descriptor, lock_flags)
            except BlockingIOError:
                raise AuthorizationError("operation_live") from None
            self._parent_descriptor = parent_descriptor
            self._file_descriptor = file_descriptor
            self._parent_identity = parent_identity
            self._file_identity = file_identity
            self.assert_stable()
            return self
        except AuthorizationError:
            self._close(file_descriptor, parent_descriptor)
            raise
        except OSError:
            self._close(file_descriptor, parent_descriptor)
            raise AuthorizationError("operation_lease") from None

    @staticmethod
    def _close(file_descriptor: int | None, parent_descriptor: int | None) -> None:
        if file_descriptor is not None:
            with suppress(OSError):
                fcntl.flock(file_descriptor, fcntl.LOCK_UN)
            with suppress(OSError):
                os.close(file_descriptor)
        if parent_descriptor is not None:
            with suppress(OSError):
                os.close(parent_descriptor)

    def assert_stable(self) -> None:
        if (
            self._parent_descriptor is None
            or self._file_descriptor is None
            or self._parent_identity is None
            or self._file_identity is None
        ):
            raise AuthorizationError("operation_lease")
        if (
            ArtifactRootLease._directory_identity(self._journal._path.parent, "journal_directory")
            != self._parent_identity
        ):
            raise AuthorizationError("operation_lease")
        try:
            parent_identity = ArtifactRootLease._validate_directory_details(
                os.fstat(self._parent_descriptor), "journal_directory"
            )
            file_identity = ArtifactRootLease._validate_file_details(
                os.fstat(self._file_descriptor), "operation_lease"
            )
        except AuthorizationError:
            raise
        except OSError:
            raise AuthorizationError("operation_lease") from None
        if (
            parent_identity != self._parent_identity
            or file_identity != self._file_identity
            or ArtifactRootLease._file_identity_at(
                self._parent_descriptor, self._name, "operation_lease"
            )
            != self._file_identity
        ):
            raise AuthorizationError("operation_lease")

    def __exit__(self, exception_type: object, exception: object, traceback: object) -> None:
        del exception_type, exception, traceback
        self._close(self._file_descriptor, self._parent_descriptor)
        self._parent_descriptor = None
        self._file_descriptor = None
        self._parent_identity = None
        self._file_identity = None


@dataclass(frozen=True, slots=True)
class _JournalIdentity:
    """Pinned identity shared by the SQLite metadata row and anchor file."""

    journal_uuid: str
    journal_path_sha256: str
    operation_schema_sha256: str
    metadata_schema_sha256: str
    genesis_sha256: str
    anchor_dev: int
    anchor_ino: int
    anchor_nlink: int
    database_dev: int
    database_ino: int
    database_nlink: int


@dataclass(frozen=True, slots=True)
class _JournalExecutionPin:
    """Exact local journal objects observed before provider/effect admission.

    This is intentionally internal and capability-bound.  It is not an
    authorization grant; it only lets the executor detect replacement of the
    database, anchor, or signed-genesis marker after its first local snapshot.
    """

    identity: _JournalIdentity
    database_details: tuple[int, int, int]
    anchor_details: tuple[int, int, int]
    marker_details: tuple[int, int, int]
    capability: object = field(repr=False, compare=False)


@dataclass(frozen=True, slots=True)
class _JournalGenesisMarker:
    """Owner-only durable state for one signed journal genesis receipt."""

    state: Literal["pending", "current", "abandon"]
    journal_uuid: str
    journal_path_sha256: str
    journal_schema_sha256: str
    genesis_sha256: str
    proposal_sha256: str
    contract_sha256: str
    operation_id: str
    disposal_owner: str
    approver_identity: str
    created_at: str


class SQLiteAuthorizationJournal:
    """Owner-only SQLite store for one-shot operation state transitions."""

    def __init__(self, path: Path) -> None:
        self._requested_path = path
        self._path = Path(os.path.realpath(path))

    def _validate_path(self) -> None:
        requested = self._requested_path
        if not requested.is_absolute() or not requested.name or requested.name in {".", ".."}:
            raise AuthorizationError("journal_path")
        self._validate_owner_directory(requested.parent)
        try:
            requested_details = os.lstat(requested)
        except FileNotFoundError:
            return
        except OSError:
            raise AuthorizationError("journal_path") from None
        if stat.S_ISLNK(requested_details.st_mode):
            raise AuthorizationError("journal_path")

    def _anchor_path(self) -> Path:
        """Return the deterministic parent anchor path for diagnostics/tests."""

        self._validate_path()
        digest = _digest(os.fsencode(str(self._path)))
        return self._path.parent / f"{_JOURNAL_ANCHOR_PREFIX}{digest}.json"

    def _genesis_marker_path(self) -> Path:
        """Return the durable receipt marker that forbids genesis replay."""

        self._validate_path()
        digest = _digest(os.fsencode(str(self._path)))
        return self._path.parent / f"{_JOURNAL_GENESIS_MARKER_PREFIX}{digest}.json"

    @staticmethod
    def _schema_sha256(schema: str) -> str:
        normalized = re.sub(r"\s+", "", schema.replace("IF NOT EXISTS ", "").lower())
        return _digest(normalized.encode("ascii"))

    @classmethod
    def _expected_operation_schema_sha256(cls) -> str:
        return cls._schema_sha256(_OPERATION_SCHEMA)

    @classmethod
    def _expected_metadata_schema_sha256(cls) -> str:
        return cls._schema_sha256(_JOURNAL_METADATA_SCHEMA)

    def _path_sha256(self) -> str:
        return _digest(os.fsencode(str(self._path)))

    @classmethod
    def journal_schema_sha256(cls) -> str:
        """Stable commitment required by a signed genesis receipt."""

        material = {
            "metadata_schema_sha256": cls._expected_metadata_schema_sha256(),
            "operation_schema_sha256": cls._expected_operation_schema_sha256(),
            "schema_version": _JOURNAL_SCHEMA_VERSION,
        }
        return _digest(json.dumps(material, sort_keys=True, separators=(",", ":")).encode())

    def _identity_lease(self) -> _OperationLease:
        self._validate_path()
        return _OperationLease(
            self,
            self._path_sha256(),
            nonblocking=False,
            prefix=_JOURNAL_IDENTITY_LEASE_PREFIX,
        )

    @staticmethod
    def _table_names(connection: sqlite3.Connection) -> set[str]:
        rows = connection.execute(
            "SELECT name FROM sqlite_master WHERE type = 'table' ORDER BY name"
        ).fetchall()
        if not all(type(row[0]) is str for row in rows):
            raise AuthorizationError("journal_schema")
        return {row[0] for row in rows}

    @classmethod
    def _reject_incompatible_tables(cls, connection: sqlite3.Connection) -> None:
        names = cls._table_names(connection)
        if _LEGACY_OPERATION_TABLE in names:
            raise AuthorizationError("journal_legacy_detected")
        if names - {_OPERATION_TABLE, _JOURNAL_METADATA_TABLE}:
            raise AuthorizationError("journal_schema")

    @staticmethod
    def _reject_executable_schema_objects(connection: sqlite3.Connection) -> None:
        """Forbid persistent SQLite code paths outside the exact table schema."""

        rows = connection.execute(
            "SELECT type, name FROM sqlite_master WHERE type IN ('trigger', 'view')"
        ).fetchall()
        if rows:
            raise AuthorizationError("journal_schema")

    def migration_status(self) -> JournalMigrationStatus:
        """Inspect journal format without creating or changing any file."""

        self._validate_path()
        database_details = self._owner_file_details_or_none(self._path, "journal_path")
        anchor_path = self._anchor_path()
        anchor_details = self._owner_file_details_or_none(anchor_path, "journal_anchor")
        marker_details = self._owner_file_details_or_none(
            self._genesis_marker_path(), "journal_genesis_marker"
        )
        marker: _JournalGenesisMarker | None = None
        if marker_details is not None:
            try:
                marker = self._read_genesis_marker()
            except AuthorizationError:
                return JournalMigrationStatus.IDENTITY_MISMATCH
            if marker.state != "current":
                return JournalMigrationStatus.PROVISIONING_INCOMPLETE
        if database_details is None and anchor_details is None:
            return (
                JournalMigrationStatus.JOURNAL_MISSING
                if marker is not None
                else JournalMigrationStatus.ABSENT
            )
        if database_details is None:
            return JournalMigrationStatus.JOURNAL_MISSING
        self._validate_companions()
        try:
            connection = sqlite3.connect(
                f"{self._path.as_uri()}?mode=ro",
                uri=True,
                isolation_level=None,
                timeout=5.0,
            )
        except sqlite3.Error:
            raise AuthorizationError("journal_open") from None
        try:
            connection.execute("PRAGMA trusted_schema = OFF")
            names = self._table_names(connection)
            if _LEGACY_OPERATION_TABLE in names:
                return JournalMigrationStatus.LEGACY_DETECTED
            if marker is None:
                return JournalMigrationStatus.GENESIS_MISSING
            if anchor_details is None:
                return JournalMigrationStatus.ANCHOR_MISSING
            try:
                anchor = self._read_anchor()
            except AuthorizationError:
                return JournalMigrationStatus.IDENTITY_MISMATCH
            if database_details != (
                anchor.database_dev,
                anchor.database_ino,
                anchor.database_nlink,
            ):
                return JournalMigrationStatus.IDENTITY_MISMATCH
            if names != {_OPERATION_TABLE, _JOURNAL_METADATA_TABLE}:
                return JournalMigrationStatus.UNKNOWN
            try:
                self._validate_schema(connection)
                metadata = self._metadata_identity(connection, database_details)
            except AuthorizationError:
                return JournalMigrationStatus.IDENTITY_MISMATCH
            if anchor != metadata:
                return JournalMigrationStatus.IDENTITY_MISMATCH
            if not self._marker_matches_identity(marker, metadata):
                return JournalMigrationStatus.IDENTITY_MISMATCH
            return JournalMigrationStatus.CURRENT
        except AuthorizationError:
            raise
        except sqlite3.Error:
            raise AuthorizationError("journal_open") from None
        finally:
            connection.close()

    @staticmethod
    def _validate_owner_directory(path: Path) -> tuple[int, int]:
        try:
            details = os.lstat(path)
        except OSError:
            raise AuthorizationError("journal_directory") from None
        if (
            not stat.S_ISDIR(details.st_mode)
            or stat.S_ISLNK(details.st_mode)
            or details.st_uid != os.getuid()
            or stat.S_IMODE(details.st_mode) != 0o700
        ):
            raise AuthorizationError("journal_directory")
        return (details.st_dev, details.st_ino)

    @staticmethod
    def _validate_owner_file_details(details: os.stat_result, phase: str) -> tuple[int, int, int]:
        if (
            not stat.S_ISREG(details.st_mode)
            or stat.S_ISLNK(details.st_mode)
            or details.st_uid != os.getuid()
            or stat.S_IMODE(details.st_mode) != 0o600
            or details.st_nlink != 1
        ):
            raise AuthorizationError(phase)
        return (details.st_dev, details.st_ino, details.st_nlink)

    @classmethod
    def _owner_file_details(cls, path: Path, phase: str) -> tuple[int, int, int]:
        try:
            details = os.lstat(path)
        except OSError:
            raise AuthorizationError(phase) from None
        return cls._validate_owner_file_details(details, phase)

    @classmethod
    def _owner_file_details_or_none(cls, path: Path, phase: str) -> tuple[int, int, int] | None:
        try:
            details = os.lstat(path)
        except FileNotFoundError:
            return None
        except OSError:
            raise AuthorizationError(phase) from None
        return cls._validate_owner_file_details(details, phase)

    def _create_database_file(self) -> tuple[int, int, int]:
        flags = os.O_RDWR | os.O_CREAT | os.O_EXCL | getattr(os, "O_CLOEXEC", 0)
        flags |= getattr(os, "O_NOFOLLOW", 0)
        try:
            descriptor = os.open(self._path, flags, 0o600)
        except FileExistsError:
            raise AuthorizationError("journal_identity_mismatch") from None
        except OSError:
            raise AuthorizationError("journal_path") from None
        try:
            details = self._validate_owner_file_details(os.fstat(descriptor), "journal_path")
            os.fsync(descriptor)
            return details
        except AuthorizationError:
            raise
        except OSError:
            raise AuthorizationError("journal_durability") from None
        finally:
            with suppress(OSError):
                os.close(descriptor)

    def _validate_companions(self) -> None:
        for suffix in ("-journal", "-wal", "-shm"):
            candidate = self._path.with_name(f"{self._path.name}{suffix}")
            try:
                os.lstat(candidate)
            except FileNotFoundError:
                continue
            except OSError:
                raise AuthorizationError("journal_path") from None
            self._owner_file_details(candidate, "journal_path")

    @staticmethod
    def _marker_bytes(marker: _JournalGenesisMarker) -> bytes:
        payload = {
            "approver_identity": marker.approver_identity,
            "contract_sha256": marker.contract_sha256,
            "created_at": marker.created_at,
            "disposal_owner": marker.disposal_owner,
            "genesis_sha256": marker.genesis_sha256,
            "journal_path_sha256": marker.journal_path_sha256,
            "journal_schema_sha256": marker.journal_schema_sha256,
            "journal_uuid": marker.journal_uuid,
            "marker_schema_version": _JOURNAL_GENESIS_MARKER_SCHEMA_VERSION,
            "operation_id": marker.operation_id,
            "proposal_sha256": marker.proposal_sha256,
            "state": marker.state,
        }
        return json.dumps(payload, sort_keys=True, separators=(",", ":")).encode("ascii") + b"\n"

    @staticmethod
    def _marker_from_verified(
        verified: _VerifiedGenesis, *, state: Literal["pending", "current", "abandon"]
    ) -> _JournalGenesisMarker:
        receipt = verified.receipt
        return _JournalGenesisMarker(
            state=state,
            journal_uuid=receipt.journal_uuid,
            journal_path_sha256=receipt.journal_path_sha256,
            journal_schema_sha256=receipt.journal_schema_sha256,
            genesis_sha256=verified.artifact_sha256,
            proposal_sha256=receipt.proposal_sha256,
            contract_sha256=receipt.contract_sha256,
            operation_id=receipt.operation_id,
            disposal_owner=receipt.disposal_owner,
            approver_identity=receipt.approver_identity,
            created_at=receipt.created_at,
        )

    def _write_genesis_marker(self, marker: _JournalGenesisMarker) -> None:
        path = self._genesis_marker_path()
        flags = os.O_WRONLY | os.O_CREAT | os.O_EXCL | getattr(os, "O_CLOEXEC", 0)
        flags |= getattr(os, "O_NOFOLLOW", 0)
        try:
            descriptor = os.open(path, flags, 0o600)
        except FileExistsError:
            raise AuthorizationError("journal_genesis_replayed") from None
        except OSError:
            raise AuthorizationError("journal_genesis_marker") from None
        try:
            self._validate_owner_file_details(os.fstat(descriptor), "journal_genesis_marker")
            remaining = memoryview(self._marker_bytes(marker))
            while remaining:
                written = os.write(descriptor, remaining)
                if written <= 0:
                    raise AuthorizationError("journal_genesis_marker")
                remaining = remaining[written:]
            os.fsync(descriptor)
        except AuthorizationError:
            raise
        except OSError:
            raise AuthorizationError("journal_genesis_marker") from None
        finally:
            with suppress(OSError):
                os.close(descriptor)

    def _read_genesis_marker(self) -> _JournalGenesisMarker:
        path = self._genesis_marker_path()
        self._owner_file_details(path, "journal_genesis_marker")
        flags = os.O_RDONLY | getattr(os, "O_CLOEXEC", 0) | getattr(os, "O_NOFOLLOW", 0)
        try:
            descriptor = os.open(path, flags)
        except OSError:
            raise AuthorizationError("journal_genesis_marker") from None
        try:
            self._validate_owner_file_details(os.fstat(descriptor), "journal_genesis_marker")
            payload = bytearray()
            while len(payload) <= 4096:
                chunk = os.read(descriptor, 4097 - len(payload))
                if not chunk:
                    break
                payload.extend(chunk)
            if len(payload) > 4096:
                raise AuthorizationError("journal_genesis_marker")
        except AuthorizationError:
            raise
        except OSError:
            raise AuthorizationError("journal_genesis_marker") from None
        finally:
            with suppress(OSError):
                os.close(descriptor)
        try:
            raw = json.loads(bytes(payload).decode("ascii"))
        except (UnicodeDecodeError, json.JSONDecodeError):
            raise AuthorizationError("journal_genesis_marker") from None
        keys = {
            "approver_identity",
            "contract_sha256",
            "created_at",
            "disposal_owner",
            "genesis_sha256",
            "journal_path_sha256",
            "journal_schema_sha256",
            "journal_uuid",
            "marker_schema_version",
            "operation_id",
            "proposal_sha256",
            "state",
        }
        if not isinstance(raw, dict) or set(raw) != keys:
            raise AuthorizationError("journal_genesis_marker")
        string_fields = keys - {"state"}
        if any(type(raw[field]) is not str for field in string_fields):
            raise AuthorizationError("journal_genesis_marker")
        if raw["marker_schema_version"] != _JOURNAL_GENESIS_MARKER_SCHEMA_VERSION:
            raise AuthorizationError("journal_genesis_marker")
        if type(raw["state"]) is not str or raw["state"] not in {
            "pending",
            "current",
            "abandon",
        }:
            raise AuthorizationError("journal_genesis_marker")
        if (
            raw["journal_path_sha256"] != self._path_sha256()
            or raw["journal_schema_sha256"] != self.journal_schema_sha256()
            or any(
                re.fullmatch(_SHA256, raw[field]) is None
                for field in (
                    "contract_sha256",
                    "genesis_sha256",
                    "journal_path_sha256",
                    "journal_schema_sha256",
                    "proposal_sha256",
                )
            )
        ):
            raise AuthorizationError("journal_genesis_marker")
        try:
            parsed_uuid = uuid.UUID(raw["journal_uuid"])
            created = datetime.fromisoformat(raw["created_at"].removesuffix("Z") + "+00:00")
        except (AttributeError, ValueError):
            raise AuthorizationError("journal_genesis_marker") from None
        if (
            str(parsed_uuid) != raw["journal_uuid"]
            or created.tzinfo is None
            or created.utcoffset() is None
            or not raw["operation_id"]
            or re.fullmatch(_IDENTIFIER, raw["disposal_owner"]) is None
            or re.fullmatch(_IDENTIFIER, raw["approver_identity"]) is None
        ):
            raise AuthorizationError("journal_genesis_marker")
        return _JournalGenesisMarker(
            state=cast(Literal["pending", "current", "abandon"], raw["state"]),
            journal_uuid=raw["journal_uuid"],
            journal_path_sha256=raw["journal_path_sha256"],
            journal_schema_sha256=raw["journal_schema_sha256"],
            genesis_sha256=raw["genesis_sha256"],
            proposal_sha256=raw["proposal_sha256"],
            contract_sha256=raw["contract_sha256"],
            operation_id=raw["operation_id"],
            disposal_owner=raw["disposal_owner"],
            approver_identity=raw["approver_identity"],
            created_at=raw["created_at"],
        )

    def _set_genesis_marker_state(
        self,
        marker: _JournalGenesisMarker,
        state: Literal["current", "abandon"],
    ) -> _JournalGenesisMarker:
        if marker.state != "pending":
            raise AuthorizationError("provisioning_incomplete")
        replacement = _JournalGenesisMarker(
            state=state,
            journal_uuid=marker.journal_uuid,
            journal_path_sha256=marker.journal_path_sha256,
            journal_schema_sha256=marker.journal_schema_sha256,
            genesis_sha256=marker.genesis_sha256,
            proposal_sha256=marker.proposal_sha256,
            contract_sha256=marker.contract_sha256,
            operation_id=marker.operation_id,
            disposal_owner=marker.disposal_owner,
            approver_identity=marker.approver_identity,
            created_at=marker.created_at,
        )
        path = self._genesis_marker_path()
        before = self._owner_file_details(path, "journal_genesis_marker")
        flags = os.O_WRONLY | getattr(os, "O_CLOEXEC", 0) | getattr(os, "O_NOFOLLOW", 0)
        try:
            descriptor = os.open(path, flags)
        except OSError:
            raise AuthorizationError("journal_genesis_marker") from None
        try:
            if (
                self._validate_owner_file_details(os.fstat(descriptor), "journal_genesis_marker")
                != before
                or self._read_genesis_marker() != marker
            ):
                raise AuthorizationError("journal_genesis_marker")
            os.ftruncate(descriptor, 0)
            remaining = memoryview(self._marker_bytes(replacement))
            while remaining:
                written = os.write(descriptor, remaining)
                if written <= 0:
                    raise AuthorizationError("journal_genesis_marker")
                remaining = remaining[written:]
            os.fsync(descriptor)
            if (
                self._validate_owner_file_details(os.fstat(descriptor), "journal_genesis_marker")
                != before
                or self._owner_file_details(path, "journal_genesis_marker") != before
            ):
                raise AuthorizationError("journal_genesis_marker")
            return replacement
        except AuthorizationError:
            raise
        except OSError:
            raise AuthorizationError("journal_genesis_marker") from None
        finally:
            with suppress(OSError):
                os.close(descriptor)

    @staticmethod
    def _marker_matches_verified(marker: _JournalGenesisMarker, verified: _VerifiedGenesis) -> bool:
        return marker == SQLiteAuthorizationJournal._marker_from_verified(
            verified, state=marker.state
        ) and marker.state in {"pending", "current", "abandon"}

    @staticmethod
    def _marker_matches_identity(marker: _JournalGenesisMarker, identity: _JournalIdentity) -> bool:
        return (
            marker.state == "current"
            and marker.journal_uuid == identity.journal_uuid
            and marker.genesis_sha256 == identity.genesis_sha256
            and marker.journal_path_sha256 == identity.journal_path_sha256
        )

    @staticmethod
    def _anchor_bytes(identity: _JournalIdentity) -> bytes:
        payload = {
            "anchor_schema_version": _JOURNAL_ANCHOR_SCHEMA_VERSION,
            "database_dev": identity.database_dev,
            "database_ino": identity.database_ino,
            "database_nlink": identity.database_nlink,
            "genesis_sha256": identity.genesis_sha256,
            "journal_path_sha256": identity.journal_path_sha256,
            "journal_uuid": identity.journal_uuid,
            "metadata_schema_sha256": identity.metadata_schema_sha256,
            "operation_schema_sha256": identity.operation_schema_sha256,
        }
        return json.dumps(payload, sort_keys=True, separators=(",", ":")).encode("ascii") + b"\n"

    def _write_anchor(self, identity: _JournalIdentity) -> tuple[int, int, int]:
        anchor_path = self._anchor_path()
        flags = os.O_WRONLY | os.O_CREAT | os.O_EXCL | getattr(os, "O_CLOEXEC", 0)
        flags |= getattr(os, "O_NOFOLLOW", 0)
        try:
            descriptor = os.open(anchor_path, flags, 0o600)
        except FileExistsError:
            raise AuthorizationError("journal_identity_mismatch") from None
        except OSError:
            raise AuthorizationError("journal_anchor") from None
        try:
            anchor_details = self._validate_owner_file_details(
                os.fstat(descriptor), "journal_anchor"
            )
            remaining = memoryview(self._anchor_bytes(identity))
            while remaining:
                written = os.write(descriptor, remaining)
                if written <= 0:
                    raise AuthorizationError("journal_anchor")
                remaining = remaining[written:]
            os.fsync(descriptor)
            return anchor_details
        except AuthorizationError:
            raise
        except OSError:
            raise AuthorizationError("journal_anchor") from None
        finally:
            with suppress(OSError):
                os.close(descriptor)

    def _read_anchor(self) -> _JournalIdentity:
        anchor_path = self._anchor_path()
        self._owner_file_details(anchor_path, "journal_anchor")
        flags = os.O_RDONLY | getattr(os, "O_CLOEXEC", 0) | getattr(os, "O_NOFOLLOW", 0)
        try:
            descriptor = os.open(anchor_path, flags)
        except OSError:
            raise AuthorizationError("journal_anchor") from None
        try:
            anchor_details = self._validate_owner_file_details(
                os.fstat(descriptor), "journal_anchor"
            )
            payload = bytearray()
            while len(payload) <= 4096:
                chunk = os.read(descriptor, 4097 - len(payload))
                if not chunk:
                    break
                payload.extend(chunk)
            if len(payload) > 4096:
                raise AuthorizationError("journal_anchor")
        except AuthorizationError:
            raise
        except OSError:
            raise AuthorizationError("journal_anchor") from None
        finally:
            with suppress(OSError):
                os.close(descriptor)
        try:
            raw = json.loads(bytes(payload).decode("ascii"))
        except (UnicodeDecodeError, json.JSONDecodeError):
            raise AuthorizationError("journal_anchor") from None
        expected_keys = {
            "anchor_schema_version",
            "database_dev",
            "database_ino",
            "database_nlink",
            "genesis_sha256",
            "journal_path_sha256",
            "journal_uuid",
            "metadata_schema_sha256",
            "operation_schema_sha256",
        }
        if not isinstance(raw, dict) or set(raw) != expected_keys:
            raise AuthorizationError("journal_anchor")
        strings = (
            "anchor_schema_version",
            "genesis_sha256",
            "journal_path_sha256",
            "journal_uuid",
            "metadata_schema_sha256",
            "operation_schema_sha256",
        )
        if any(type(raw[key]) is not str for key in strings):
            raise AuthorizationError("journal_anchor")
        integers = ("database_dev", "database_ino", "database_nlink")
        if any(type(raw[key]) is not int or raw[key] < 1 for key in integers):
            raise AuthorizationError("journal_anchor")
        if (
            raw["anchor_schema_version"] != _JOURNAL_ANCHOR_SCHEMA_VERSION
            or raw["journal_path_sha256"] != self._path_sha256()
            or re.fullmatch(_SHA256, raw["genesis_sha256"]) is None
            or raw["operation_schema_sha256"] != self._expected_operation_schema_sha256()
            or raw["metadata_schema_sha256"] != self._expected_metadata_schema_sha256()
            or re.fullmatch(_SHA256, raw["journal_path_sha256"]) is None
            or re.fullmatch(_SHA256, raw["operation_schema_sha256"]) is None
            or re.fullmatch(_SHA256, raw["metadata_schema_sha256"]) is None
            or raw["database_nlink"] != 1
        ):
            raise AuthorizationError("journal_anchor")
        try:
            parsed_uuid = uuid.UUID(raw["journal_uuid"])
        except (AttributeError, ValueError):
            raise AuthorizationError("journal_anchor") from None
        if str(parsed_uuid) != raw["journal_uuid"]:
            raise AuthorizationError("journal_anchor")
        return _JournalIdentity(
            journal_uuid=raw["journal_uuid"],
            journal_path_sha256=raw["journal_path_sha256"],
            operation_schema_sha256=raw["operation_schema_sha256"],
            metadata_schema_sha256=raw["metadata_schema_sha256"],
            genesis_sha256=raw["genesis_sha256"],
            anchor_dev=anchor_details[0],
            anchor_ino=anchor_details[1],
            anchor_nlink=anchor_details[2],
            database_dev=raw["database_dev"],
            database_ino=raw["database_ino"],
            database_nlink=raw["database_nlink"],
        )

    def _metadata_identity(
        self, connection: sqlite3.Connection, database_details: tuple[int, int, int]
    ) -> _JournalIdentity:
        rows = connection.execute(
            f"""
            SELECT journal_uuid, journal_path_sha256, operation_schema_sha256,
                   metadata_schema_sha256, genesis_sha256, anchor_dev, anchor_ino,
                   anchor_nlink, schema_version
            FROM {_JOURNAL_METADATA_TABLE}
            WHERE singleton = 1
            """
        ).fetchall()
        if len(rows) != 1 or len(rows[0]) != 9:
            raise AuthorizationError("journal_schema")
        (
            journal_uuid,
            path_sha256,
            operation_schema_sha256,
            metadata_schema_sha256,
            genesis_sha256,
            anchor_dev,
            anchor_ino,
            anchor_nlink,
            version,
        ) = rows[0]
        if (
            type(journal_uuid) is not str
            or type(path_sha256) is not str
            or type(operation_schema_sha256) is not str
            or type(metadata_schema_sha256) is not str
            or type(genesis_sha256) is not str
            or type(anchor_dev) is not int
            or type(anchor_ino) is not int
            or type(anchor_nlink) is not int
            or version != _JOURNAL_SCHEMA_VERSION
            or path_sha256 != self._path_sha256()
            or operation_schema_sha256 != self._expected_operation_schema_sha256()
            or metadata_schema_sha256 != self._expected_metadata_schema_sha256()
            or re.fullmatch(_SHA256, genesis_sha256) is None
            or anchor_dev < 1
            or anchor_ino < 1
            or anchor_nlink != 1
        ):
            raise AuthorizationError("journal_schema")
        try:
            parsed_uuid = uuid.UUID(journal_uuid)
        except ValueError:
            raise AuthorizationError("journal_schema") from None
        if str(parsed_uuid) != journal_uuid:
            raise AuthorizationError("journal_schema")
        return _JournalIdentity(
            journal_uuid=journal_uuid,
            journal_path_sha256=path_sha256,
            operation_schema_sha256=operation_schema_sha256,
            metadata_schema_sha256=metadata_schema_sha256,
            genesis_sha256=genesis_sha256,
            anchor_dev=anchor_dev,
            anchor_ino=anchor_ino,
            anchor_nlink=anchor_nlink,
            database_dev=database_details[0],
            database_ino=database_details[1],
            database_nlink=database_details[2],
        )

    def _validate_identity(
        self,
        connection: sqlite3.Connection,
        expected: _JournalIdentity,
        *,
        allow_pending_marker: bool = False,
    ) -> None:
        self._validate_path()
        self._validate_companions()
        database_details = self._owner_file_details(self._path, "journal_identity_mismatch")
        if database_details != (
            expected.database_dev,
            expected.database_ino,
            expected.database_nlink,
        ):
            raise AuthorizationError("journal_identity_mismatch")
        if self._read_anchor() != expected:
            raise AuthorizationError("journal_identity_mismatch")
        self._reject_incompatible_tables(connection)
        self._validate_schema(connection)
        if self._metadata_identity(connection, database_details) != expected:
            raise AuthorizationError("journal_identity_mismatch")
        marker = self._read_genesis_marker()
        if not self._marker_matches_identity(marker, expected) and not (
            allow_pending_marker
            and marker.state == "pending"
            and marker.journal_uuid == expected.journal_uuid
            and marker.genesis_sha256 == expected.genesis_sha256
            and marker.journal_path_sha256 == expected.journal_path_sha256
        ):
            raise AuthorizationError("journal_identity_mismatch")

    @staticmethod
    def _require_verified_genesis(verified: _VerifiedGenesis) -> None:
        if type(verified) is not _VerifiedGenesis or verified.capability is not _GENESIS_CAPABILITY:
            raise AuthorizationError("journal_genesis")

    def _begin_verified_genesis(self, verified: _VerifiedGenesis) -> None:
        """Persist the one-time pending marker before any database creation."""

        self._require_verified_genesis(verified)
        with self._identity_lease() as lease:
            lease.assert_stable()
            marker_details = self._owner_file_details_or_none(
                self._genesis_marker_path(), "journal_genesis_marker"
            )
            database_details = self._owner_file_details_or_none(self._path, "journal_path")
            anchor_details = self._owner_file_details_or_none(self._anchor_path(), "journal_anchor")
            if marker_details is not None:
                marker = self._read_genesis_marker()
                if marker.state == "pending" and self._marker_matches_verified(marker, verified):
                    raise AuthorizationError("provisioning_incomplete")
                raise AuthorizationError("journal_genesis_replayed")
            if database_details is not None or anchor_details is not None:
                raise AuthorizationError("journal_genesis_missing")
            self._write_genesis_marker(self._marker_from_verified(verified, state="pending"))
            lease.assert_stable()

    def _complete_verified_genesis(self, verified: _VerifiedGenesis) -> _JournalIdentity:
        """Create the database/anchor only after a pending signed marker exists."""

        self._require_verified_genesis(verified)
        with self._identity_lease() as lease:
            lease.assert_stable()
            marker = self._read_genesis_marker()
            if marker.state != "pending" or not self._marker_matches_verified(marker, verified):
                raise AuthorizationError("provisioning_incomplete")
            if (
                self._owner_file_details_or_none(self._path, "journal_path") is not None
                or self._owner_file_details_or_none(self._anchor_path(), "journal_anchor")
                is not None
            ):
                raise AuthorizationError("provisioning_incomplete")
            identity = self._initialize_identity(verified, marker)
            lease.assert_stable()
            return identity

    def _initialize_identity(
        self, verified: _VerifiedGenesis, marker: _JournalGenesisMarker
    ) -> _JournalIdentity:
        database_details = self._create_database_file()
        identity = _JournalIdentity(
            journal_uuid=verified.receipt.journal_uuid,
            journal_path_sha256=self._path_sha256(),
            operation_schema_sha256=self._expected_operation_schema_sha256(),
            metadata_schema_sha256=self._expected_metadata_schema_sha256(),
            genesis_sha256=verified.artifact_sha256,
            anchor_dev=0,
            anchor_ino=0,
            anchor_nlink=0,
            database_dev=database_details[0],
            database_ino=database_details[1],
            database_nlink=database_details[2],
        )
        try:
            connection = sqlite3.connect(
                f"{self._path.as_uri()}?mode=rw", uri=True, isolation_level=None, timeout=5.0
            )
        except sqlite3.Error:
            raise AuthorizationError("journal_open") from None
        try:
            connection.execute("PRAGMA trusted_schema = OFF")
            row = connection.execute("PRAGMA journal_mode = DELETE").fetchone()
            if row != ("delete",):
                raise AuthorizationError("journal_durability")
            connection.execute("PRAGMA synchronous = FULL")
            connection.execute("BEGIN IMMEDIATE")
            connection.execute(_OPERATION_SCHEMA)
            connection.execute(_JOURNAL_METADATA_SCHEMA)
            connection.execute("COMMIT")
            self._validate_companions()
            if (
                self._owner_file_details(self._path, "journal_identity_mismatch")
                != database_details
            ):
                raise AuthorizationError("journal_identity_mismatch")
            anchor_details = self._write_anchor(identity)
            identity = _JournalIdentity(
                journal_uuid=identity.journal_uuid,
                journal_path_sha256=identity.journal_path_sha256,
                operation_schema_sha256=identity.operation_schema_sha256,
                metadata_schema_sha256=identity.metadata_schema_sha256,
                genesis_sha256=identity.genesis_sha256,
                anchor_dev=anchor_details[0],
                anchor_ino=anchor_details[1],
                anchor_nlink=anchor_details[2],
                database_dev=identity.database_dev,
                database_ino=identity.database_ino,
                database_nlink=identity.database_nlink,
            )
            connection.execute("BEGIN IMMEDIATE")
            connection.execute(
                f"""
                INSERT INTO {_JOURNAL_METADATA_TABLE} (
                    singleton, journal_uuid, journal_path_sha256,
                    operation_schema_sha256, metadata_schema_sha256, genesis_sha256,
                    anchor_dev, anchor_ino, anchor_nlink, schema_version
                ) VALUES (1, ?, ?, ?, ?, ?, ?, ?, ?, ?)
                """,
                (
                    identity.journal_uuid,
                    identity.journal_path_sha256,
                    identity.operation_schema_sha256,
                    identity.metadata_schema_sha256,
                    identity.genesis_sha256,
                    identity.anchor_dev,
                    identity.anchor_ino,
                    identity.anchor_nlink,
                    _JOURNAL_SCHEMA_VERSION,
                ),
            )
            self._validate_schema(connection)
            connection.execute("COMMIT")
            self._validate_companions()
            if (
                self._owner_file_details(self._path, "journal_identity_mismatch")
                != database_details
            ):
                raise AuthorizationError("journal_identity_mismatch")
            self._validate_identity(connection, identity, allow_pending_marker=True)
            self._set_genesis_marker_state(marker, "current")
            self._validate_identity(connection, identity)
            return identity
        except AuthorizationError:
            with suppress(sqlite3.Error):
                connection.execute("ROLLBACK")
            raise
        except sqlite3.Error:
            with suppress(sqlite3.Error):
                connection.execute("ROLLBACK")
            raise AuthorizationError("journal_transaction") from None
        finally:
            connection.close()

    def _established_identity(self) -> _JournalIdentity:
        self._validate_path()
        with self._identity_lease() as lease:
            lease.assert_stable()
            database_details = self._owner_file_details_or_none(self._path, "journal_path")
            anchor_details = self._owner_file_details_or_none(self._anchor_path(), "journal_anchor")
            marker_details = self._owner_file_details_or_none(
                self._genesis_marker_path(), "journal_genesis_marker"
            )
            if marker_details is None:
                if database_details is None and anchor_details is None:
                    raise AuthorizationError("journal_absent")
                raise AuthorizationError("journal_genesis_missing")
            marker = self._read_genesis_marker()
            if marker.state != "current":
                raise AuthorizationError("provisioning_incomplete")
            if database_details is None:
                raise AuthorizationError("journal_missing")
            if anchor_details is None:
                raise AuthorizationError("journal_anchor_missing")
            self._validate_companions()
            try:
                connection = sqlite3.connect(
                    f"{self._path.as_uri()}?mode=ro", uri=True, isolation_level=None, timeout=5.0
                )
            except sqlite3.Error:
                raise AuthorizationError("journal_open") from None
            try:
                connection.execute("PRAGMA trusted_schema = OFF")
                identity = self._read_anchor()
                self._validate_identity(connection, identity)
                lease.assert_stable()
                return identity
            finally:
                connection.close()

    def assert_identity(self) -> None:
        """Recheck the anchored database identity without creating any journal."""

        self._established_identity()

    def _pin_execution_identity(self) -> _JournalExecutionPin:
        """Capture exact local identities before provider inspection/effect work."""

        identity = self._established_identity()
        database_details = self._owner_file_details(self._path, "journal_identity_pinned")
        anchor_details = self._owner_file_details(self._anchor_path(), "journal_identity_pinned")
        marker_details = self._owner_file_details(
            self._genesis_marker_path(), "journal_identity_pinned"
        )
        if database_details != (
            identity.database_dev,
            identity.database_ino,
            identity.database_nlink,
        ) or anchor_details != (identity.anchor_dev, identity.anchor_ino, identity.anchor_nlink):
            raise AuthorizationError("journal_identity_pinned")
        # A replacement can race the first reads.  A second complete identity
        # check makes a changing path fail closed before provider acquisition.
        if self._established_identity() != identity:
            raise AuthorizationError("journal_identity_pinned")
        if (
            self._owner_file_details(self._path, "journal_identity_pinned") != database_details
            or self._owner_file_details(self._anchor_path(), "journal_identity_pinned")
            != anchor_details
            or self._owner_file_details(self._genesis_marker_path(), "journal_identity_pinned")
            != marker_details
        ):
            raise AuthorizationError("journal_identity_pinned")
        return _JournalExecutionPin(
            identity=identity,
            database_details=database_details,
            anchor_details=anchor_details,
            marker_details=marker_details,
            capability=_JOURNAL_PIN_CAPABILITY,
        )

    def _assert_pinned_execution_identity(self, pin: _JournalExecutionPin) -> None:
        """Fail closed if any pre-effect local object was replaced or removed."""

        if type(pin) is not _JournalExecutionPin or pin.capability is not _JOURNAL_PIN_CAPABILITY:
            raise AuthorizationError("journal_identity_pinned")
        try:
            current = self._established_identity()
            database_details = self._owner_file_details(self._path, "journal_identity_pinned")
            anchor_details = self._owner_file_details(
                self._anchor_path(), "journal_identity_pinned"
            )
            marker_details = self._owner_file_details(
                self._genesis_marker_path(), "journal_identity_pinned"
            )
        except AuthorizationError:
            raise AuthorizationError("journal_identity_pinned") from None
        if (
            current != pin.identity
            or database_details != pin.database_details
            or anchor_details != pin.anchor_details
            or marker_details != pin.marker_details
        ):
            raise AuthorizationError("journal_identity_pinned")

    def assert_genesis(self, verified: _VerifiedGenesis) -> None:
        """Require the signed root artifact to match the durable current identity."""

        self._require_verified_genesis(verified)
        identity = self._established_identity()
        marker = self._read_genesis_marker()
        if (
            not self._marker_matches_verified(marker, verified)
            or marker.state != "current"
            or identity.journal_uuid != verified.receipt.journal_uuid
            or identity.genesis_sha256 != verified.artifact_sha256
        ):
            raise AuthorizationError("journal_genesis_mismatch")

    def reconcile_genesis(
        self,
        receipt: JournalGenesisReconciliationReceiptV1,
        *,
        signer: TrustedEd25519SignerV1,
    ) -> JournalMigrationStatus:
        """Resolve a pending genesis only with typed signed operator evidence."""

        _verify_journal_genesis_reconciliation_receipt(receipt, signer=signer)
        with self._identity_lease() as lease:
            lease.assert_stable()
            marker = self._read_genesis_marker()
            if (
                marker.state != "pending"
                or receipt.journal_uuid != marker.journal_uuid
                or receipt.journal_path_sha256 != marker.journal_path_sha256
                or receipt.genesis_sha256 != marker.genesis_sha256
            ):
                raise AuthorizationError("provisioning_incomplete")
            if receipt.outcome == "provisioning_abandoned":
                self._set_genesis_marker_state(marker, "abandon")
                lease.assert_stable()
                return JournalMigrationStatus.PROVISIONING_INCOMPLETE
            database_details = self._owner_file_details_or_none(self._path, "journal_path")
            anchor_details = self._owner_file_details_or_none(self._anchor_path(), "journal_anchor")
            if database_details is None or anchor_details is None:
                raise AuthorizationError("provisioning_incomplete")
            try:
                connection = sqlite3.connect(
                    f"{self._path.as_uri()}?mode=ro", uri=True, isolation_level=None, timeout=5.0
                )
            except sqlite3.Error:
                raise AuthorizationError("journal_open") from None
            try:
                connection.execute("PRAGMA trusted_schema = OFF")
                identity = self._read_anchor()
                self._validate_identity(connection, identity, allow_pending_marker=True)
                self._set_genesis_marker_state(marker, "current")
                self._validate_identity(connection, identity)
            finally:
                connection.close()
            lease.assert_stable()
            return JournalMigrationStatus.CURRENT

    def _connect(self) -> tuple[sqlite3.Connection, _JournalIdentity]:
        identity = self._established_identity()
        self._validate_companions()
        try:
            connection = sqlite3.connect(
                f"{self._path.as_uri()}?mode=rw", uri=True, isolation_level=None, timeout=5.0
            )
        except sqlite3.Error:
            raise AuthorizationError("journal_open") from None
        try:
            connection.execute("PRAGMA trusted_schema = OFF")
            self._validate_identity(connection, identity)
            row = connection.execute("PRAGMA journal_mode = DELETE").fetchone()
            if row != ("delete",):
                raise AuthorizationError("journal_durability")
            connection.execute("PRAGMA synchronous = FULL")
            self._validate_identity(connection, identity)
            return connection, identity
        except AuthorizationError:
            connection.close()
            raise
        except sqlite3.Error:
            connection.close()
            raise AuthorizationError("journal_open") from None

    @staticmethod
    def _validate_schema(connection: sqlite3.Connection) -> None:
        SQLiteAuthorizationJournal._reject_executable_schema_objects(connection)
        rows = connection.execute(f"PRAGMA table_info({_OPERATION_TABLE})").fetchall()
        expected = [
            (0, "operation_id", "TEXT", 1, None, 1),
            (1, "operation_kind", "TEXT", 1, None, 0),
            (2, "nonce", "TEXT", 1, None, 0),
            (3, "proposal_sha256", "TEXT", 1, None, 0),
            (4, "contract_sha256", "TEXT", 1, None, 0),
            (5, "provider_provenance_sha256", "TEXT", 1, None, 0),
            (6, "idempotency_key", "TEXT", 1, None, 0),
            (7, "state", "TEXT", 1, None, 0),
            (8, "effect_receipt_sha256", "TEXT", 0, None, 0),
            (9, "failure_phase", "TEXT", 0, None, 0),
            (10, "created_at", "TEXT", 1, None, 0),
            (11, "updated_at", "TEXT", 1, None, 0),
        ]
        if rows != expected:
            raise AuthorizationError("journal_schema")
        index_rows = connection.execute(f"PRAGMA index_list({_OPERATION_TABLE})").fetchall()
        indexes = {
            (
                bool(index[2]),
                index[3],
                tuple(
                    column[2]
                    for column in connection.execute(f"PRAGMA index_info({index[1]})").fetchall()
                ),
            )
            for index in index_rows
        }
        if indexes != {(True, "pk", ("operation_id",)), (True, "u", ("nonce",))}:
            raise AuthorizationError("journal_schema")
        schema = connection.execute(
            "SELECT sql FROM sqlite_master WHERE type = 'table' AND name = ?", (_OPERATION_TABLE,)
        ).fetchone()
        expected_sql = re.sub(r"\s+", "", _OPERATION_SCHEMA.replace("IF NOT EXISTS ", "").lower())
        if (
            schema is None
            or type(schema[0]) is not str
            or re.sub(r"\s+", "", schema[0].lower()) != expected_sql
        ):
            raise AuthorizationError("journal_schema")

        metadata_rows = connection.execute(
            f"PRAGMA table_info({_JOURNAL_METADATA_TABLE})"
        ).fetchall()
        expected_metadata_rows = [
            (0, "singleton", "INTEGER", 1, None, 1),
            (1, "journal_uuid", "TEXT", 1, None, 0),
            (2, "journal_path_sha256", "TEXT", 1, None, 0),
            (3, "operation_schema_sha256", "TEXT", 1, None, 0),
            (4, "metadata_schema_sha256", "TEXT", 1, None, 0),
            (5, "genesis_sha256", "TEXT", 1, None, 0),
            (6, "anchor_dev", "INTEGER", 1, None, 0),
            (7, "anchor_ino", "INTEGER", 1, None, 0),
            (8, "anchor_nlink", "INTEGER", 1, None, 0),
            (9, "schema_version", "TEXT", 1, None, 0),
        ]
        if metadata_rows != expected_metadata_rows:
            raise AuthorizationError("journal_schema")
        metadata_schema = connection.execute(
            "SELECT sql FROM sqlite_master WHERE type = 'table' AND name = ?",
            (_JOURNAL_METADATA_TABLE,),
        ).fetchone()
        expected_metadata_sql = re.sub(
            r"\s+", "", _JOURNAL_METADATA_SCHEMA.replace("IF NOT EXISTS ", "").lower()
        )
        if (
            metadata_schema is None
            or type(metadata_schema[0]) is not str
            or re.sub(r"\s+", "", metadata_schema[0].lower()) != expected_metadata_sql
        ):
            raise AuthorizationError("journal_schema")

    def _transaction(self, action: Callable[[sqlite3.Connection], str | None]) -> str | None:
        connection, identity = self._connect()
        try:
            connection.execute("BEGIN IMMEDIATE")
            self._validate_identity(connection, identity)
            result = action(connection)
            connection.execute("COMMIT")
            self._validate_identity(connection, identity)
            return result
        except AuthorizationError:
            with suppress(sqlite3.Error):
                connection.execute("ROLLBACK")
            raise
        except sqlite3.Error:
            with suppress(sqlite3.Error):
                connection.execute("ROLLBACK")
            raise AuthorizationError("journal_transaction") from None
        finally:
            connection.close()

    @staticmethod
    def _require_verified(verified: _VerifiedExecution) -> None:
        if (
            type(verified) is not _VerifiedExecution
            or verified.capability is not _VERIFIED_CAPABILITY
        ):
            raise AuthorizationError("journal")

    @staticmethod
    def _bindings(verified: _VerifiedExecution) -> tuple[str, str, str, str]:
        context = verified.context
        return (
            context.proposal_sha256,
            context.contract_sha256,
            context.provider_provenance_sha256,
            context.idempotency_key,
        )

    def _operation_lease(self, operation_id: str, *, nonblocking: bool = False) -> _OperationLease:
        if type(operation_id) is not str or not operation_id:
            raise AuthorizationError("operation_id")
        return _OperationLease(self, operation_id, nonblocking=nonblocking)

    def _claim_verified(self, verified: _VerifiedExecution) -> None:
        self._require_verified(verified)
        proposal_sha256, contract_sha256, provider_sha256, idempotency_key = self._bindings(
            verified
        )

        def claim(connection: sqlite3.Connection) -> None:
            existing = connection.execute(
                f"SELECT state FROM {_OPERATION_TABLE} WHERE operation_id = ?",
                (verified.context.operation_id,),
            ).fetchone()
            if existing is not None:
                raise AuthorizationError("operation_replayed")
            nonce = connection.execute(
                f"SELECT operation_id FROM {_OPERATION_TABLE} WHERE nonce = ?", (verified.nonce,)
            ).fetchone()
            if nonce is not None:
                raise AuthorizationError("nonce_replayed")
            connection.execute(
                f"""
                INSERT INTO {_OPERATION_TABLE} (
                    operation_id, operation_kind, nonce, proposal_sha256, contract_sha256,
                    provider_provenance_sha256, idempotency_key, state,
                    effect_receipt_sha256, failure_phase, created_at, updated_at
                ) VALUES (?, ?, ?, ?, ?, ?, ?, ?, NULL, NULL, ?, ?)
                """,
                (
                    verified.context.operation_id,
                    verified.context.operation_kind,
                    verified.nonce,
                    proposal_sha256,
                    contract_sha256,
                    provider_sha256,
                    idempotency_key,
                    AuthorizationOperationState.CLAIMED.value,
                    verified.authorized_at,
                    verified.authorized_at,
                ),
            )
            return None

        self._transaction(claim)

    def _begin_effect(self, verified: _VerifiedExecution) -> None:
        self._require_verified(verified)
        proposal_sha256, contract_sha256, provider_sha256, idempotency_key = self._bindings(
            verified
        )

        def begin(connection: sqlite3.Connection) -> None:
            result = connection.execute(
                f"""
                UPDATE {_OPERATION_TABLE}
                SET state = ?, updated_at = ?
                WHERE operation_id = ? AND nonce = ? AND proposal_sha256 = ?
                  AND contract_sha256 = ? AND provider_provenance_sha256 = ?
                  AND idempotency_key = ? AND state = ?
                """,
                (
                    AuthorizationOperationState.IN_PROGRESS.value,
                    verified.authorized_at,
                    verified.context.operation_id,
                    verified.nonce,
                    proposal_sha256,
                    contract_sha256,
                    provider_sha256,
                    idempotency_key,
                    AuthorizationOperationState.CLAIMED.value,
                ),
            )
            if result.rowcount != 1:
                raise AuthorizationError("operation_state")
            return None

        self._transaction(begin)

    def _commit_effect(self, verified: _VerifiedExecution, effect_receipt: EffectReceiptV1) -> None:
        self._require_verified(verified)
        proposal_sha256, contract_sha256, provider_sha256, idempotency_key = self._bindings(
            verified
        )

        def commit(connection: sqlite3.Connection) -> None:
            result = connection.execute(
                f"""
                UPDATE {_OPERATION_TABLE}
                SET state = ?, effect_receipt_sha256 = ?, failure_phase = NULL, updated_at = ?
                WHERE operation_id = ? AND nonce = ? AND proposal_sha256 = ?
                  AND contract_sha256 = ? AND provider_provenance_sha256 = ?
                  AND idempotency_key = ? AND state = ?
                """,
                (
                    AuthorizationOperationState.COMMITTED.value,
                    effect_receipt.effect_receipt_sha256,
                    verified.authorized_at,
                    verified.context.operation_id,
                    verified.nonce,
                    proposal_sha256,
                    contract_sha256,
                    provider_sha256,
                    idempotency_key,
                    AuthorizationOperationState.IN_PROGRESS.value,
                ),
            )
            if result.rowcount != 1:
                raise AuthorizationError("operation_state")
            return None

        self._transaction(commit)

    def _fail_effect(self, verified: _VerifiedExecution) -> None:
        self._require_verified(verified)

        def fail(connection: sqlite3.Connection) -> None:
            result = connection.execute(
                f"""
                UPDATE {_OPERATION_TABLE}
                SET state = ?, failure_phase = ?, updated_at = ?
                WHERE operation_id = ? AND nonce = ? AND state = ?
                """,
                (
                    AuthorizationOperationState.FAILED_RECOVERY_REQUIRED.value,
                    "effect",
                    verified.authorized_at,
                    verified.context.operation_id,
                    verified.nonce,
                    AuthorizationOperationState.IN_PROGRESS.value,
                ),
            )
            if result.rowcount != 1:
                raise AuthorizationError("operation_state")
            return None

        self._transaction(fail)

    def operation_state(self, operation_id: str) -> AuthorizationOperationState | None:
        if type(operation_id) is not str or not operation_id:
            raise AuthorizationError("operation_id")
        connection, identity = self._connect()
        try:
            connection.execute("BEGIN IMMEDIATE")
            self._validate_identity(connection, identity)
            row = connection.execute(
                f"SELECT state FROM {_OPERATION_TABLE} WHERE operation_id = ?", (operation_id,)
            ).fetchone()
            connection.execute("COMMIT")
            self._validate_identity(connection, identity)
        except AuthorizationError:
            with suppress(sqlite3.Error):
                connection.execute("ROLLBACK")
            raise
        except sqlite3.Error:
            with suppress(sqlite3.Error):
                connection.execute("ROLLBACK")
            raise AuthorizationError("journal_transaction") from None
        finally:
            connection.close()
        if row is None:
            return None
        try:
            return AuthorizationOperationState(row[0])
        except (TypeError, ValueError):
            raise AuthorizationError("journal_schema") from None

    def require_recovery(self, operation_id: str) -> AuthorizationOperationState:
        """Mark a released, ambiguous operation unretryable without retrying it."""

        if type(operation_id) is not str or not operation_id:
            raise AuthorizationError("operation_id")

        def recover(connection: sqlite3.Connection) -> str:
            result = connection.execute(
                f"""
                UPDATE {_OPERATION_TABLE}
                SET state = ?, failure_phase = ?, updated_at = ?
                WHERE operation_id = ? AND state IN (?, ?)
                """,
                (
                    AuthorizationOperationState.FAILED_RECOVERY_REQUIRED.value,
                    "explicit_recovery",
                    datetime.now(UTC).isoformat(timespec="seconds").replace("+00:00", "Z"),
                    operation_id,
                    AuthorizationOperationState.CLAIMED.value,
                    AuthorizationOperationState.IN_PROGRESS.value,
                ),
            )
            if result.rowcount != 1:
                raise AuthorizationError("operation_state")
            return AuthorizationOperationState.FAILED_RECOVERY_REQUIRED.value

        with self._operation_lease(operation_id, nonblocking=True) as lease:
            lease.assert_stable()
            result = self._transaction(recover)
            lease.assert_stable()
        assert result is not None
        return AuthorizationOperationState(result)

    def reconcile_ambiguous_effect(
        self,
        receipt: ReconciliationReceiptV1,
        *,
        signer: TrustedEd25519SignerV1,
    ) -> AuthorizationOperationState:
        """Commit only a released ambiguous operation with signed outcome evidence.

        This operation never invokes an effect.  Without a verified typed
        receipt, callers must leave the journal in ``failed_recovery_required``
        and perform no automatic retry.
        """

        _verify_reconciliation_receipt(receipt, signer=signer)

        def reconcile(connection: sqlite3.Connection) -> str:
            row = connection.execute(
                f"""
                SELECT idempotency_key, state FROM {_OPERATION_TABLE}
                WHERE operation_id = ?
                """,
                (receipt.operation_id,),
            ).fetchone()
            if row is None or type(row[0]) is not str or type(row[1]) is not str:
                raise AuthorizationError("operation_state")
            if row[0] != receipt.idempotency_key or row[1] not in {
                AuthorizationOperationState.IN_PROGRESS.value,
                AuthorizationOperationState.FAILED_RECOVERY_REQUIRED.value,
            }:
                raise AuthorizationError("operation_state")
            result = connection.execute(
                f"""
                UPDATE {_OPERATION_TABLE}
                SET state = ?, effect_receipt_sha256 = ?, failure_phase = ?, updated_at = ?
                WHERE operation_id = ? AND idempotency_key = ?
                  AND state IN (?, ?)
                """,
                (
                    AuthorizationOperationState.COMMITTED.value,
                    receipt.effect_receipt_sha256,
                    "reconciled",
                    datetime.now(UTC).isoformat(timespec="seconds").replace("+00:00", "Z"),
                    receipt.operation_id,
                    receipt.idempotency_key,
                    AuthorizationOperationState.IN_PROGRESS.value,
                    AuthorizationOperationState.FAILED_RECOVERY_REQUIRED.value,
                ),
            )
            if result.rowcount != 1:
                raise AuthorizationError("operation_state")
            return AuthorizationOperationState.COMMITTED.value

        with self._operation_lease(receipt.operation_id, nonblocking=True) as lease:
            lease.assert_stable()
            result = self._transaction(reconcile)
            lease.assert_stable()
        assert result is not None
        return AuthorizationOperationState(result)


class InitialProvisioningJournalStatus(StrEnum):
    """Read-only state for the separate pre-creation durable journal."""

    ABSENT = "absent"
    CURRENT = "current"
    PROVISIONING_INCOMPLETE = "provisioning_incomplete"
    ABANDONED = "abandoned"
    JOURNAL_MISSING = "journal_missing"
    IDENTITY_MISMATCH = "identity_mismatch"
    UNKNOWN = "unknown"


class _InitialJournalAnchorV1(_Model):
    schema_version: Literal["rsd.initial-provisioning-journal-anchor.v1"]
    journal_uuid: str = Field(pattern=_UUID)
    journal_path_sha256: str = Field(pattern=_SHA256)
    journal_schema_sha256: str = Field(pattern=_SHA256)
    intent_sha256: str = Field(pattern=_SHA256)
    database_dev: int = Field(ge=0)
    database_ino: int = Field(ge=1)
    database_nlink: Literal[1]


class _InitialJournalMarkerV1(_Model):
    schema_version: Literal["rsd.initial-provisioning-journal-marker.v1"]
    state: Literal["pending", "current", "abandoned"]
    journal_uuid: str = Field(pattern=_UUID)
    journal_path_sha256: str = Field(pattern=_SHA256)
    journal_schema_sha256: str = Field(pattern=_SHA256)
    intent_sha256: str = Field(pattern=_SHA256)


@dataclass(frozen=True, slots=True)
class _InitialJournalIdentity:
    journal_uuid: str
    journal_path_sha256: str
    journal_schema_sha256: str
    intent_sha256: str
    database_details: tuple[int, int, int]
    anchor_details: tuple[int, int, int]


@dataclass(frozen=True, slots=True)
class _InitialJournalExecutionPin:
    """Exact initial-journal objects observed before a live creation effect."""

    identity: _InitialJournalIdentity
    database_details: tuple[int, int, int]
    anchor_details: tuple[int, int, int]
    marker_details: tuple[int, int, int]
    capability: object = field(repr=False, compare=False)


class SQLiteInitialProvisioningJournal:
    """Durable owner-only state for the one bounded pre-observation operation.

    It has a deliberately separate schema and identity from the observed
    lifecycle journal.  Neither its constructor nor its authorization methods
    create files; only the explicit signed intent provisioning boundary does.
    """

    def __init__(self, path: Path) -> None:
        self._requested_path = path
        self._path = Path(os.path.realpath(path))

    def _validate_path(self) -> None:
        requested = self._requested_path
        if not requested.is_absolute() or not requested.name or requested.name in {".", ".."}:
            raise AuthorizationError("initial_journal_path")
        SQLiteAuthorizationJournal._validate_owner_directory(requested.parent)
        try:
            details = os.lstat(requested)
        except FileNotFoundError:
            return
        except OSError:
            raise AuthorizationError("initial_journal_path") from None
        if stat.S_ISLNK(details.st_mode):
            raise AuthorizationError("initial_journal_path")

    def _path_sha256(self) -> str:
        return _digest(os.fsencode(str(self._path)))

    def _anchor_path(self) -> Path:
        self._validate_path()
        return self._path.parent / f"{_INITIAL_JOURNAL_ANCHOR_PREFIX}{self._path_sha256()}.json"

    def _marker_path(self) -> Path:
        self._validate_path()
        return self._path.parent / f"{_INITIAL_JOURNAL_MARKER_PREFIX}{self._path_sha256()}.json"

    @classmethod
    def _operation_schema_sha256(cls) -> str:
        return SQLiteAuthorizationJournal._schema_sha256(_INITIAL_OPERATION_SCHEMA)

    @classmethod
    def _metadata_schema_sha256(cls) -> str:
        return SQLiteAuthorizationJournal._schema_sha256(_INITIAL_JOURNAL_METADATA_SCHEMA)

    @classmethod
    def journal_schema_sha256(cls) -> str:
        material = {
            "metadata_schema_sha256": cls._metadata_schema_sha256(),
            "operation_schema_sha256": cls._operation_schema_sha256(),
            "schema_version": _INITIAL_JOURNAL_SCHEMA_VERSION,
        }
        return _digest(json.dumps(material, sort_keys=True, separators=(",", ":")).encode())

    def _identity_lease(self) -> _OperationLease:
        self._validate_path()
        return _OperationLease(
            cast(SQLiteAuthorizationJournal, self),
            self._path_sha256(),
            nonblocking=False,
            prefix=f"{_INITIAL_JOURNAL_MARKER_PREFIX}lease-",
        )

    def _operation_lease(self, operation_id: str, *, nonblocking: bool = False) -> _OperationLease:
        if type(operation_id) is not str or not operation_id:
            raise AuthorizationError("initial_operation_id")
        return _OperationLease(
            cast(SQLiteAuthorizationJournal, self),
            operation_id,
            nonblocking=nonblocking,
            prefix=f"{_INITIAL_JOURNAL_MARKER_PREFIX}operation-",
        )

    @staticmethod
    def _file_details(path: Path, phase: str) -> tuple[int, int, int]:
        return SQLiteAuthorizationJournal._owner_file_details(path, phase)

    @staticmethod
    def _file_details_or_none(path: Path, phase: str) -> tuple[int, int, int] | None:
        return SQLiteAuthorizationJournal._owner_file_details_or_none(path, phase)

    @staticmethod
    def _fsync_parent(path: Path) -> None:
        descriptor: int | None = None
        try:
            descriptor = os.open(path.parent, os.O_RDONLY | getattr(os, "O_CLOEXEC", 0))
            os.fsync(descriptor)
        except OSError:
            raise AuthorizationError("initial_journal_durability") from None
        finally:
            if descriptor is not None:
                with suppress(OSError):
                    os.close(descriptor)

    @staticmethod
    def _write_exclusive(path: Path, payload: bytes, *, phase: str) -> tuple[int, int, int]:
        descriptor: int | None = None
        try:
            descriptor = os.open(
                path,
                os.O_WRONLY
                | os.O_CREAT
                | os.O_EXCL
                | getattr(os, "O_CLOEXEC", 0)
                | getattr(os, "O_NOFOLLOW", 0),
                0o600,
            )
            details = SQLiteAuthorizationJournal._validate_owner_file_details(
                os.fstat(descriptor), phase
            )
            view = memoryview(payload)
            while view:
                written = os.write(descriptor, view)
                if written <= 0:
                    raise AuthorizationError(phase)
                view = view[written:]
            os.fsync(descriptor)
            return details
        except AuthorizationError:
            raise
        except FileExistsError:
            raise AuthorizationError(phase) from None
        except OSError:
            raise AuthorizationError(phase) from None
        finally:
            if descriptor is not None:
                with suppress(OSError):
                    os.close(descriptor)

    @staticmethod
    def _rewrite_current(path: Path, payload: bytes, *, phase: str) -> None:
        descriptor: int | None = None
        try:
            descriptor = os.open(
                path,
                os.O_WRONLY
                | os.O_TRUNC
                | getattr(os, "O_CLOEXEC", 0)
                | getattr(os, "O_NOFOLLOW", 0),
            )
            SQLiteAuthorizationJournal._validate_owner_file_details(os.fstat(descriptor), phase)
            view = memoryview(payload)
            while view:
                written = os.write(descriptor, view)
                if written <= 0:
                    raise AuthorizationError(phase)
                view = view[written:]
            os.fsync(descriptor)
        except AuthorizationError:
            raise
        except OSError:
            raise AuthorizationError(phase) from None
        finally:
            if descriptor is not None:
                with suppress(OSError):
                    os.close(descriptor)

    @staticmethod
    def _model_bytes(model: BaseModel, *, phase: str) -> bytes:
        try:
            return json.dumps(
                model.model_dump(mode="json"), sort_keys=True, separators=(",", ":")
            ).encode("utf-8")
        except (TypeError, ValueError):
            raise AuthorizationError(phase) from None

    @staticmethod
    def _read_model(path: Path, model: type[_Model], *, phase: str) -> _Model:
        SQLiteInitialProvisioningJournal._file_details(path, phase)
        try:
            raw = path.read_bytes()
            return model.model_validate(_parse_document(raw, phase=phase))
        except (AuthorizationError, OSError, ValidationError, ValueError):
            raise AuthorizationError(phase) from None

    def _read_marker(self) -> _InitialJournalMarkerV1:
        model = self._read_model(
            self._marker_path(), _InitialJournalMarkerV1, phase="initial_journal_marker"
        )
        if type(model) is not _InitialJournalMarkerV1:
            raise AuthorizationError("initial_journal_marker")
        return model

    def _read_anchor(self) -> _InitialJournalAnchorV1:
        model = self._read_model(
            self._anchor_path(), _InitialJournalAnchorV1, phase="initial_journal_anchor"
        )
        if type(model) is not _InitialJournalAnchorV1:
            raise AuthorizationError("initial_journal_anchor")
        return model

    def _write_marker(self, marker: _InitialJournalMarkerV1) -> tuple[int, int, int]:
        details = self._write_exclusive(
            self._marker_path(),
            self._model_bytes(marker, phase="initial_journal_marker"),
            phase="initial_journal_marker",
        )
        self._fsync_parent(self._marker_path())
        return details

    def _write_anchor(self, anchor: _InitialJournalAnchorV1) -> tuple[int, int, int]:
        details = self._write_exclusive(
            self._anchor_path(),
            self._model_bytes(anchor, phase="initial_journal_anchor"),
            phase="initial_journal_anchor",
        )
        self._fsync_parent(self._anchor_path())
        return details

    def _set_marker_state(
        self, marker: _InitialJournalMarkerV1, state: Literal["current", "abandoned"]
    ) -> None:
        current = marker.model_copy(update={"state": state})
        self._rewrite_current(
            self._marker_path(),
            self._model_bytes(current, phase="initial_journal_marker"),
            phase="initial_journal_marker",
        )
        self._fsync_parent(self._marker_path())

    def _set_marker_current(self, marker: _InitialJournalMarkerV1) -> None:
        self._set_marker_state(marker, "current")

    def _create_database(self) -> tuple[int, int, int]:
        descriptor: int | None = None
        try:
            descriptor = os.open(
                self._path,
                os.O_RDWR
                | os.O_CREAT
                | os.O_EXCL
                | getattr(os, "O_CLOEXEC", 0)
                | getattr(os, "O_NOFOLLOW", 0),
                0o600,
            )
            details = SQLiteAuthorizationJournal._validate_owner_file_details(
                os.fstat(descriptor), "initial_journal_path"
            )
            os.fsync(descriptor)
            self._fsync_parent(self._path)
            return details
        except AuthorizationError:
            raise
        except FileExistsError:
            raise AuthorizationError("initial_journal_replayed") from None
        except OSError:
            raise AuthorizationError("initial_journal_path") from None
        finally:
            if descriptor is not None:
                with suppress(OSError):
                    os.close(descriptor)

    def _validate_companions(self) -> None:
        for suffix in ("-journal", "-wal", "-shm"):
            if self._file_details_or_none(
                Path(f"{self._path}{suffix}"), "initial_journal_companion"
            ):
                raise AuthorizationError("initial_journal_companion")

    @staticmethod
    def _normalized_schema(schema: str) -> str:
        return re.sub(r"\s+", "", schema.replace("IF NOT EXISTS ", "").lower())

    @classmethod
    def _validate_schema(cls, connection: sqlite3.Connection) -> None:
        SQLiteAuthorizationJournal._reject_executable_schema_objects(connection)
        names = SQLiteAuthorizationJournal._table_names(connection)
        if names != {_INITIAL_OPERATION_TABLE, _INITIAL_JOURNAL_METADATA_TABLE}:
            raise AuthorizationError("initial_journal_schema")
        expected_tables = (
            (_INITIAL_OPERATION_TABLE, _INITIAL_OPERATION_SCHEMA),
            (_INITIAL_JOURNAL_METADATA_TABLE, _INITIAL_JOURNAL_METADATA_SCHEMA),
        )
        for name, expected in expected_tables:
            row = connection.execute(
                "SELECT sql FROM sqlite_master WHERE type = 'table' AND name = ?", (name,)
            ).fetchone()
            if (
                row is None
                or type(row[0]) is not str
                or cls._normalized_schema(row[0]) != cls._normalized_schema(expected)
            ):
                raise AuthorizationError("initial_journal_schema")

    def _metadata_identity(
        self,
        connection: sqlite3.Connection,
        *,
        database_details: tuple[int, int, int],
        anchor_details: tuple[int, int, int],
    ) -> _InitialJournalIdentity:
        self._validate_schema(connection)
        rows = connection.execute(
            f"""
            SELECT journal_uuid, journal_path_sha256, journal_schema_sha256, intent_sha256,
                   anchor_dev, anchor_ino, anchor_nlink, schema_version
            FROM {_INITIAL_JOURNAL_METADATA_TABLE}
            """
        ).fetchall()
        if len(rows) != 1:
            raise AuthorizationError("initial_journal_identity")
        row = rows[0]
        if (
            len(row) != 8
            or any(type(value) is not str for value in row[:4])
            or any(type(value) is not int for value in row[4:7])
            or row[7] != _INITIAL_JOURNAL_SCHEMA_VERSION
            or row[4:7] != anchor_details
        ):
            raise AuthorizationError("initial_journal_identity")
        return _InitialJournalIdentity(
            journal_uuid=cast(str, row[0]),
            journal_path_sha256=cast(str, row[1]),
            journal_schema_sha256=cast(str, row[2]),
            intent_sha256=cast(str, row[3]),
            database_details=database_details,
            anchor_details=anchor_details,
        )

    def _established_identity(self) -> _InitialJournalIdentity:
        self._validate_path()
        with self._identity_lease() as lease:
            lease.assert_stable()
            database_details = self._file_details_or_none(self._path, "initial_journal_path")
            anchor_details = self._file_details_or_none(
                self._anchor_path(), "initial_journal_anchor"
            )
            marker_details = self._file_details_or_none(
                self._marker_path(), "initial_journal_marker"
            )
            if marker_details is None:
                if database_details is None and anchor_details is None:
                    raise AuthorizationError("initial_journal_absent")
                raise AuthorizationError("initial_journal_marker")
            marker = self._read_marker()
            if marker.state != "current":
                raise AuthorizationError("initial_provisioning_incomplete")
            if database_details is None or anchor_details is None:
                raise AuthorizationError("initial_journal_missing")
            self._validate_companions()
            try:
                connection = sqlite3.connect(
                    f"{self._path.as_uri()}?mode=ro", uri=True, isolation_level=None, timeout=5.0
                )
            except sqlite3.Error:
                raise AuthorizationError("initial_journal_open") from None
            try:
                connection.execute("PRAGMA trusted_schema = OFF")
                anchor = self._read_anchor()
                identity = self._metadata_identity(
                    connection,
                    database_details=database_details,
                    anchor_details=anchor_details,
                )
                if (
                    anchor.journal_uuid != identity.journal_uuid
                    or anchor.journal_path_sha256 != identity.journal_path_sha256
                    or anchor.journal_schema_sha256 != identity.journal_schema_sha256
                    or anchor.intent_sha256 != identity.intent_sha256
                    or (anchor.database_dev, anchor.database_ino, anchor.database_nlink)
                    != database_details
                    or marker.journal_uuid != identity.journal_uuid
                    or marker.journal_path_sha256 != identity.journal_path_sha256
                    or marker.journal_schema_sha256 != identity.journal_schema_sha256
                    or marker.intent_sha256 != identity.intent_sha256
                ):
                    raise AuthorizationError("initial_journal_identity")
                lease.assert_stable()
                return identity
            finally:
                connection.close()

    def _pin_execution_identity(self) -> _InitialJournalExecutionPin:
        """Capture the local identity that must survive one initial effect."""

        identity = self._established_identity()
        database_details = self._file_details(self._path, "initial_journal_identity_pinned")
        anchor_details = self._file_details(self._anchor_path(), "initial_journal_identity_pinned")
        marker_details = self._file_details(self._marker_path(), "initial_journal_identity_pinned")
        if (
            database_details != identity.database_details
            or anchor_details != identity.anchor_details
            or self._established_identity() != identity
            or self._file_details(self._path, "initial_journal_identity_pinned") != database_details
            or self._file_details(self._anchor_path(), "initial_journal_identity_pinned")
            != anchor_details
            or self._file_details(self._marker_path(), "initial_journal_identity_pinned")
            != marker_details
        ):
            raise AuthorizationError("initial_journal_identity_pinned")
        return _InitialJournalExecutionPin(
            identity=identity,
            database_details=database_details,
            anchor_details=anchor_details,
            marker_details=marker_details,
            capability=_INITIAL_JOURNAL_PIN_CAPABILITY,
        )

    def _assert_pinned_execution_identity(self, pin: _InitialJournalExecutionPin) -> None:
        """Reject database, anchor, or marker replacement after first snapshot."""

        if (
            type(pin) is not _InitialJournalExecutionPin
            or pin.capability is not _INITIAL_JOURNAL_PIN_CAPABILITY
        ):
            raise AuthorizationError("initial_journal_identity_pinned")
        try:
            identity = self._established_identity()
            database_details = self._file_details(self._path, "initial_journal_identity_pinned")
            anchor_details = self._file_details(
                self._anchor_path(), "initial_journal_identity_pinned"
            )
            marker_details = self._file_details(
                self._marker_path(), "initial_journal_identity_pinned"
            )
        except AuthorizationError:
            raise AuthorizationError("initial_journal_identity_pinned") from None
        if (
            identity != pin.identity
            or database_details != pin.database_details
            or anchor_details != pin.anchor_details
            or marker_details != pin.marker_details
        ):
            raise AuthorizationError("initial_journal_identity_pinned")

    def migration_status(self) -> InitialProvisioningJournalStatus:
        """Classify local state without creating, rotating, or repairing it."""

        self._validate_path()
        database_details = self._file_details_or_none(self._path, "initial_journal_path")
        anchor_details = self._file_details_or_none(self._anchor_path(), "initial_journal_anchor")
        marker_details = self._file_details_or_none(self._marker_path(), "initial_journal_marker")
        if database_details is None and anchor_details is None and marker_details is None:
            return InitialProvisioningJournalStatus.ABSENT
        if marker_details is not None:
            try:
                marker = self._read_marker()
            except AuthorizationError:
                return InitialProvisioningJournalStatus.IDENTITY_MISMATCH
            if marker.state != "current":
                if marker.state == "abandoned":
                    return InitialProvisioningJournalStatus.ABANDONED
                return InitialProvisioningJournalStatus.PROVISIONING_INCOMPLETE
        if database_details is None or anchor_details is None or marker_details is None:
            return InitialProvisioningJournalStatus.JOURNAL_MISSING
        try:
            self._established_identity()
        except AuthorizationError:
            return InitialProvisioningJournalStatus.IDENTITY_MISMATCH
        return InitialProvisioningJournalStatus.CURRENT

    @staticmethod
    def _require_verified_intent(verified: _VerifiedInitialIntent) -> None:
        if (
            type(verified) is not _VerifiedInitialIntent
            or verified.capability is not _INITIAL_INTENT_CAPABILITY
        ):
            raise AuthorizationError("initial_journal")

    def _begin_verified_intent(self, verified: _VerifiedInitialIntent) -> None:
        """Persist a pending local marker before the external genesis claim."""

        self._require_verified_intent(verified)
        intent = verified.intent
        with self._identity_lease() as lease:
            lease.assert_stable()
            if self.migration_status() is not InitialProvisioningJournalStatus.ABSENT:
                raise AuthorizationError("initial_journal_replayed")
            marker = _InitialJournalMarkerV1(
                schema_version="rsd.initial-provisioning-journal-marker.v1",
                state="pending",
                journal_uuid=intent.journal_uuid,
                journal_path_sha256=intent.journal_path_sha256,
                journal_schema_sha256=intent.journal_schema_sha256,
                intent_sha256=verified.intent_sha256,
            )
            self._write_marker(marker)
            lease.assert_stable()

    def _complete_verified_intent(self, verified: _VerifiedInitialIntent) -> None:
        """Create exactly one journal/anchor pair after a pending marker exists."""

        self._require_verified_intent(verified)
        intent = verified.intent
        with self._identity_lease() as lease:
            lease.assert_stable()
            marker = self._read_marker()
            if (
                marker.state != "pending"
                or marker.journal_uuid != intent.journal_uuid
                or marker.intent_sha256 != verified.intent_sha256
                or marker.journal_path_sha256 != self._path_sha256()
                or marker.journal_schema_sha256 != self.journal_schema_sha256()
            ):
                raise AuthorizationError("initial_provisioning_incomplete")
            if (
                self._file_details_or_none(self._path, "initial_journal_path") is not None
                or self._file_details_or_none(self._anchor_path(), "initial_journal_anchor")
                is not None
            ):
                raise AuthorizationError("initial_provisioning_incomplete")
            database_details = self._create_database()
            try:
                connection = sqlite3.connect(
                    f"{self._path.as_uri()}?mode=rw", uri=True, isolation_level=None, timeout=5.0
                )
            except sqlite3.Error:
                raise AuthorizationError("initial_journal_open") from None
            try:
                connection.execute("PRAGMA trusted_schema = OFF")
                if connection.execute("PRAGMA journal_mode = DELETE").fetchone() != ("delete",):
                    raise AuthorizationError("initial_journal_durability")
                connection.execute("PRAGMA synchronous = FULL")
                connection.execute("BEGIN IMMEDIATE")
                connection.execute(_INITIAL_OPERATION_SCHEMA)
                connection.execute(_INITIAL_JOURNAL_METADATA_SCHEMA)
                connection.execute("COMMIT")
                anchor = _InitialJournalAnchorV1(
                    schema_version="rsd.initial-provisioning-journal-anchor.v1",
                    journal_uuid=intent.journal_uuid,
                    journal_path_sha256=intent.journal_path_sha256,
                    journal_schema_sha256=intent.journal_schema_sha256,
                    intent_sha256=verified.intent_sha256,
                    database_dev=database_details[0],
                    database_ino=database_details[1],
                    database_nlink=1,
                )
                anchor_details = self._write_anchor(anchor)
                connection.execute("BEGIN IMMEDIATE")
                connection.execute(
                    f"""
                    INSERT INTO {_INITIAL_JOURNAL_METADATA_TABLE} (
                        singleton, journal_uuid, journal_path_sha256, journal_schema_sha256,
                        intent_sha256, anchor_dev, anchor_ino, anchor_nlink, schema_version
                    ) VALUES (1, ?, ?, ?, ?, ?, ?, ?, ?)
                    """,
                    (
                        intent.journal_uuid,
                        intent.journal_path_sha256,
                        intent.journal_schema_sha256,
                        verified.intent_sha256,
                        anchor_details[0],
                        anchor_details[1],
                        anchor_details[2],
                        _INITIAL_JOURNAL_SCHEMA_VERSION,
                    ),
                )
                connection.execute("COMMIT")
                self._set_marker_current(marker)
                lease.assert_stable()
            except AuthorizationError:
                with suppress(sqlite3.Error):
                    connection.execute("ROLLBACK")
                raise
            except sqlite3.Error:
                with suppress(sqlite3.Error):
                    connection.execute("ROLLBACK")
                raise AuthorizationError("initial_journal_transaction") from None
            finally:
                connection.close()

    def reconcile_genesis(
        self, receipt: InitialJournalGenesisReconciliationReceiptV1
    ) -> InitialProvisioningJournalStatus:
        """Resolve a pending genesis without recreating any local object.

        Completion is permitted only after the database and anchor already
        exist and validate against the pending marker.  Earlier crash windows
        can only be explicitly abandoned, preserving the external tombstone.
        """

        if type(receipt) is not InitialJournalGenesisReconciliationReceiptV1:
            raise AuthorizationError("initial_journal_reconciliation")
        with self._identity_lease() as lease:
            lease.assert_stable()
            marker = self._read_marker()
            if (
                marker.state != "pending"
                or marker.journal_uuid != receipt.journal_uuid
                or marker.journal_path_sha256 != receipt.journal_path_sha256
                or marker.intent_sha256 != receipt.intent_sha256
            ):
                raise AuthorizationError("initial_journal_reconciliation")
            if receipt.outcome == "provisioning_abandoned":
                self._set_marker_state(marker, "abandoned")
                lease.assert_stable()
                return InitialProvisioningJournalStatus.ABANDONED

            database_details = self._file_details_or_none(
                self._path, "initial_journal_reconciliation"
            )
            anchor_details = self._file_details_or_none(
                self._anchor_path(), "initial_journal_reconciliation"
            )
            if database_details is None or anchor_details is None:
                raise AuthorizationError("initial_journal_reconciliation")
            self._validate_companions()
            try:
                connection = sqlite3.connect(
                    f"{self._path.as_uri()}?mode=ro", uri=True, isolation_level=None, timeout=5.0
                )
            except sqlite3.Error:
                raise AuthorizationError("initial_journal_reconciliation") from None
            try:
                connection.execute("PRAGMA trusted_schema = OFF")
                anchor = self._read_anchor()
                identity = self._metadata_identity(
                    connection,
                    database_details=database_details,
                    anchor_details=anchor_details,
                )
                if (
                    anchor.journal_uuid != marker.journal_uuid
                    or anchor.journal_path_sha256 != marker.journal_path_sha256
                    or anchor.journal_schema_sha256 != marker.journal_schema_sha256
                    or anchor.intent_sha256 != marker.intent_sha256
                    or (anchor.database_dev, anchor.database_ino, anchor.database_nlink)
                    != database_details
                    or identity.journal_uuid != marker.journal_uuid
                    or identity.journal_path_sha256 != marker.journal_path_sha256
                    or identity.journal_schema_sha256 != marker.journal_schema_sha256
                    or identity.intent_sha256 != marker.intent_sha256
                ):
                    raise AuthorizationError("initial_journal_reconciliation")
            except AuthorizationError:
                raise
            except sqlite3.Error:
                raise AuthorizationError("initial_journal_reconciliation") from None
            finally:
                connection.close()
            self._set_marker_current(marker)
            lease.assert_stable()
        return InitialProvisioningJournalStatus.CURRENT

    def assert_intent(self, verified: _VerifiedInitialIntent) -> None:
        self._require_verified_intent(verified)
        identity = self._established_identity()
        intent = verified.intent
        if (
            identity.journal_uuid != intent.journal_uuid
            or identity.journal_path_sha256 != intent.journal_path_sha256
            or identity.journal_schema_sha256 != intent.journal_schema_sha256
            or identity.intent_sha256 != verified.intent_sha256
        ):
            raise AuthorizationError("initial_journal_intent_mismatch")

    def _connect(self) -> tuple[sqlite3.Connection, _InitialJournalIdentity]:
        identity = self._established_identity()
        self._validate_companions()
        try:
            connection = sqlite3.connect(
                f"{self._path.as_uri()}?mode=rw", uri=True, isolation_level=None, timeout=5.0
            )
        except sqlite3.Error:
            raise AuthorizationError("initial_journal_open") from None
        try:
            connection.execute("PRAGMA trusted_schema = OFF")
            if connection.execute("PRAGMA journal_mode = DELETE").fetchone() != ("delete",):
                raise AuthorizationError("initial_journal_durability")
            connection.execute("PRAGMA synchronous = FULL")
            return connection, identity
        except AuthorizationError:
            connection.close()
            raise
        except sqlite3.Error:
            connection.close()
            raise AuthorizationError("initial_journal_open") from None

    def _transaction(self, action: Callable[[sqlite3.Connection], None]) -> None:
        connection, identity = self._connect()
        try:
            connection.execute("BEGIN IMMEDIATE")
            if self._established_identity() != identity:
                raise AuthorizationError("initial_journal_identity")
            action(connection)
            connection.execute("COMMIT")
            if self._established_identity() != identity:
                raise AuthorizationError("initial_journal_identity")
        except AuthorizationError:
            with suppress(sqlite3.Error):
                connection.execute("ROLLBACK")
            raise
        except sqlite3.Error:
            with suppress(sqlite3.Error):
                connection.execute("ROLLBACK")
            raise AuthorizationError("initial_journal_transaction") from None
        finally:
            connection.close()

    @staticmethod
    def _require_verified_operation(verified: _VerifiedInitialProvisioning) -> None:
        if (
            type(verified) is not _VerifiedInitialProvisioning
            or verified.capability is not _INITIAL_VERIFIED_CAPABILITY
        ):
            raise AuthorizationError("initial_journal")

    def _claim_verified(self, verified: _VerifiedInitialProvisioning) -> None:
        self._require_verified_operation(verified)
        context = verified.context

        def claim(connection: sqlite3.Connection) -> None:
            existing = connection.execute(
                f"SELECT 1 FROM {_INITIAL_OPERATION_TABLE} WHERE provisioning_operation_id = ?",
                (context.provisioning_operation_id,),
            ).fetchone()
            nonce = connection.execute(
                f"SELECT 1 FROM {_INITIAL_OPERATION_TABLE} WHERE nonce = ?", (verified.nonce,)
            ).fetchone()
            if existing is not None:
                raise AuthorizationError("initial_operation_replayed")
            if nonce is not None:
                raise AuthorizationError("initial_nonce_replayed")
            connection.execute(
                f"""
                INSERT INTO {_INITIAL_OPERATION_TABLE} (
                    provisioning_operation_id, operation_kind, operation_scope, intent_sha256,
                    nonce,
                    provider_provenance_sha256, idempotency_key, state, effect_receipt_sha256,
                    observed_resources_sha256, failure_phase, created_at, updated_at
                ) VALUES (?, ?, ?, ?, ?, ?, ?, ?, NULL, NULL, NULL, ?, ?)
                """,
                (
                    context.provisioning_operation_id,
                    context.operation_kind,
                    context.operation_scope,
                    context.intent_sha256,
                    verified.nonce,
                    context.provider_provenance_sha256,
                    context.idempotency_key,
                    InitialProvisioningOperationState.CLAIMED.value,
                    verified.authorized_at,
                    verified.authorized_at,
                ),
            )

        self._transaction(claim)

    def _begin_effect(self, verified: _VerifiedInitialProvisioning) -> None:
        self._require_verified_operation(verified)
        context = verified.context

        def begin(connection: sqlite3.Connection) -> None:
            result = connection.execute(
                f"""
                UPDATE {_INITIAL_OPERATION_TABLE}
                SET state = ?, updated_at = ?
                WHERE provisioning_operation_id = ? AND intent_sha256 = ? AND nonce = ?
                  AND idempotency_key = ? AND state = ?
                """,
                (
                    InitialProvisioningOperationState.IN_PROGRESS.value,
                    verified.authorized_at,
                    context.provisioning_operation_id,
                    context.intent_sha256,
                    verified.nonce,
                    context.idempotency_key,
                    InitialProvisioningOperationState.CLAIMED.value,
                ),
            )
            if result.rowcount != 1:
                raise AuthorizationError("initial_operation_state")

        self._transaction(begin)

    def _commit_effect(
        self, verified: _VerifiedInitialProvisioning, receipt: InitialProvisioningEffectReceiptV1
    ) -> None:
        self._require_verified_operation(verified)
        context = verified.context
        resources_sha256 = _digest(
            _INITIAL_EFFECT_RECEIPT_DOMAIN
            + json.dumps(
                receipt.observed_resources.model_dump(mode="json"),
                sort_keys=True,
                separators=(",", ":"),
            ).encode()
        )

        def commit(connection: sqlite3.Connection) -> None:
            result = connection.execute(
                f"""
                UPDATE {_INITIAL_OPERATION_TABLE}
                SET state = ?, effect_receipt_sha256 = ?, observed_resources_sha256 = ?,
                    failure_phase = NULL, updated_at = ?
                WHERE provisioning_operation_id = ? AND intent_sha256 = ? AND nonce = ?
                  AND idempotency_key = ? AND state = ?
                """,
                (
                    InitialProvisioningOperationState.PROVISIONED_EMPTY.value,
                    receipt.effect_receipt_sha256,
                    resources_sha256,
                    verified.authorized_at,
                    context.provisioning_operation_id,
                    context.intent_sha256,
                    verified.nonce,
                    context.idempotency_key,
                    InitialProvisioningOperationState.IN_PROGRESS.value,
                ),
            )
            if result.rowcount != 1:
                raise AuthorizationError("initial_operation_state")

        self._transaction(commit)

    def _fail_effect(self, verified: _VerifiedInitialProvisioning) -> None:
        self._require_verified_operation(verified)
        context = verified.context

        def fail(connection: sqlite3.Connection) -> None:
            result = connection.execute(
                f"""
                UPDATE {_INITIAL_OPERATION_TABLE}
                SET state = ?, failure_phase = ?, updated_at = ?
                WHERE provisioning_operation_id = ? AND nonce = ? AND state IN (?, ?)
                """,
                (
                    InitialProvisioningOperationState.FAILED_RECOVERY_REQUIRED.value,
                    "effect_failed_recovery_required",
                    verified.authorized_at,
                    context.provisioning_operation_id,
                    verified.nonce,
                    InitialProvisioningOperationState.CLAIMED.value,
                    InitialProvisioningOperationState.IN_PROGRESS.value,
                ),
            )
            if result.rowcount != 1:
                raise AuthorizationError("initial_operation_state")

        self._transaction(fail)

    def operation_state(
        self, provisioning_operation_id: str
    ) -> InitialProvisioningOperationState | None:
        if type(provisioning_operation_id) is not str or not provisioning_operation_id:
            raise AuthorizationError("initial_operation_id")
        connection, _ = self._connect()
        try:
            row = connection.execute(
                f"SELECT state FROM {_INITIAL_OPERATION_TABLE} WHERE provisioning_operation_id = ?",
                (provisioning_operation_id,),
            ).fetchone()
        except sqlite3.Error:
            raise AuthorizationError("initial_journal_transaction") from None
        finally:
            connection.close()
        if row is None:
            return None
        try:
            return InitialProvisioningOperationState(row[0])
        except (TypeError, ValueError):
            raise AuthorizationError("initial_journal_schema") from None

    def require_recovery(self, provisioning_operation_id: str) -> InitialProvisioningOperationState:
        """Mark an ambiguous initial effect terminal without retrying it."""

        if type(provisioning_operation_id) is not str or not provisioning_operation_id:
            raise AuthorizationError("initial_operation_id")

        def recover(connection: sqlite3.Connection) -> None:
            result = connection.execute(
                f"""
                UPDATE {_INITIAL_OPERATION_TABLE}
                SET state = ?, failure_phase = ?, updated_at = ?
                WHERE provisioning_operation_id = ? AND state IN (?, ?)
                """,
                (
                    InitialProvisioningOperationState.FAILED_RECOVERY_REQUIRED.value,
                    "explicit_recovery",
                    datetime.now(UTC).isoformat(timespec="seconds").replace("+00:00", "Z"),
                    provisioning_operation_id,
                    InitialProvisioningOperationState.CLAIMED.value,
                    InitialProvisioningOperationState.IN_PROGRESS.value,
                ),
            )
            if result.rowcount != 1:
                raise AuthorizationError("initial_operation_state")

        with self._operation_lease(provisioning_operation_id, nonblocking=True) as lease:
            lease.assert_stable()
            self._transaction(recover)
            lease.assert_stable()
        return InitialProvisioningOperationState.FAILED_RECOVERY_REQUIRED


def _validate_effect_receipt(context: VerifiedExecutionContext, value: object) -> EffectReceiptV1:
    if type(value) is not EffectReceiptV1:
        raise AuthorizationError("effect_receipt")
    receipt = value
    if (
        receipt.operation_kind != context.operation_kind
        or receipt.operation_id != context.operation_id
        or receipt.idempotency_key != context.idempotency_key
    ):
        raise AuthorizationError("effect_receipt")
    return receipt


def _validate_initial_effect_receipt(
    context: InitialProvisioningExecutionContext, value: object
) -> InitialProvisioningEffectReceiptV1:
    """Reject every effect output outside the one empty-resource scope."""

    if type(value) is not InitialProvisioningEffectReceiptV1:
        raise AuthorizationError("initial_effect_receipt")
    receipt = value
    if (
        receipt.operation_kind != context.operation_kind
        or receipt.operation_scope != context.operation_scope
        or receipt.provisioning_operation_id != context.provisioning_operation_id
        or receipt.intent_sha256 != context.intent_sha256
        or receipt.journal_uuid != context.intent.journal_uuid
        or receipt.idempotency_key != context.idempotency_key
    ):
        raise AuthorizationError("initial_effect_receipt")
    return receipt


def _reconciliation_message(receipt: ReconciliationReceiptV1) -> bytes:
    material = {
        "effect_receipt_sha256": receipt.effect_receipt_sha256,
        "idempotency_key": receipt.idempotency_key,
        "operation_id": receipt.operation_id,
        "outcome": receipt.outcome,
        "schema_version": receipt.schema_version,
        "signer_key_id": receipt.signer_key_id,
    }
    return _RECONCILIATION_DOMAIN + json.dumps(
        material, sort_keys=True, separators=(",", ":")
    ).encode("ascii")


def _journal_genesis_reconciliation_message(
    receipt: JournalGenesisReconciliationReceiptV1,
) -> bytes:
    material = receipt.model_dump(mode="json", exclude={"signature_base64"})
    return _JOURNAL_GENESIS_RECONCILIATION_DOMAIN + json.dumps(
        material, sort_keys=True, separators=(",", ":")
    ).encode("utf-8")


def _verify_journal_genesis_reconciliation_receipt(
    receipt: JournalGenesisReconciliationReceiptV1,
    *,
    signer: TrustedEd25519SignerV1,
) -> None:
    if (
        type(receipt) is not JournalGenesisReconciliationReceiptV1
        or type(signer) is not TrustedEd25519SignerV1
        or receipt.signer_key_id != signer.key_id
    ):
        raise AuthorizationError("journal_genesis_reconciliation_signature")
    try:
        signature = _canonical_base64(receipt.signature_base64)
        signer.key().verify(signature, _journal_genesis_reconciliation_message(receipt))
    except (InvalidSignature, ValueError, binascii.Error):
        raise AuthorizationError("journal_genesis_reconciliation_signature") from None


def _initial_journal_genesis_reconciliation_message(
    receipt: InitialJournalGenesisReconciliationReceiptV1,
) -> bytes:
    material = receipt.model_dump(mode="json", exclude={"signature_base64"})
    return _INITIAL_JOURNAL_GENESIS_RECONCILIATION_DOMAIN + json.dumps(
        material, sort_keys=True, separators=(",", ":")
    ).encode("utf-8")


def _verify_initial_journal_genesis_reconciliation_receipt(
    receipt: InitialJournalGenesisReconciliationReceiptV1,
    *,
    signer: TrustedEd25519SignerV1,
) -> None:
    if (
        type(receipt) is not InitialJournalGenesisReconciliationReceiptV1
        or type(signer) is not TrustedEd25519SignerV1
        or receipt.signer_key_id != signer.key_id
    ):
        raise AuthorizationError("initial_journal_reconciliation_signature")
    try:
        signature = _canonical_base64(receipt.signature_base64)
        signer.key().verify(signature, _initial_journal_genesis_reconciliation_message(receipt))
    except (InvalidSignature, ValueError, binascii.Error):
        raise AuthorizationError("initial_journal_reconciliation_signature") from None


def _verify_reconciliation_receipt(
    receipt: ReconciliationReceiptV1, *, signer: TrustedEd25519SignerV1
) -> None:
    if (
        type(receipt) is not ReconciliationReceiptV1
        or type(signer) is not TrustedEd25519SignerV1
        or receipt.signer_key_id != signer.key_id
    ):
        raise AuthorizationError("reconciliation_signature")
    signature = _safe_call(lambda: _canonical_base64(receipt.signature_base64))
    if signature is _SAFE_CALL_FAILURE or type(signature) is not bytes:
        raise AuthorizationError("reconciliation_signature")
    verified = _safe_call(lambda: signer.key().verify(signature, _reconciliation_message(receipt)))
    if verified is _SAFE_CALL_FAILURE:
        raise AuthorizationError("reconciliation_signature")


def _read_clock(clock: Callable[[], datetime]) -> datetime:
    observed = _safe_call(clock)
    if type(observed) is not datetime or observed.tzinfo is None or observed.utcoffset() is None:
        raise AuthorizationError("clock")
    return observed.astimezone(UTC)


def _system_utc_clock() -> datetime:
    return datetime.now(UTC)


def _acquire_provider_lease(
    provider: ProviderProvenanceAdapter, references: tuple[ProviderReferenceV1, ...]
) -> tuple[object, ProviderSnapshotLease]:
    manager = _safe_call(lambda: provider.acquire(references))
    if manager is _SAFE_CALL_FAILURE:
        raise AuthorizationError("provider_failure")
    context_manager = cast(AbstractContextManager[ProviderSnapshotLease], manager)
    enter = _safe_call(lambda: context_manager.__enter__)
    exit_method = _safe_call(lambda: context_manager.__exit__)
    if (
        enter is _SAFE_CALL_FAILURE
        or exit_method is _SAFE_CALL_FAILURE
        or not callable(enter)
        or not callable(exit_method)
    ):
        raise AuthorizationError("provider_failure")
    lease = _safe_call(enter)
    if lease is _SAFE_CALL_FAILURE:
        raise AuthorizationError("provider_failure")
    return manager, cast(ProviderSnapshotLease, lease)


def _release_provider_lease(manager: object) -> bool:
    context_manager = cast(AbstractContextManager[ProviderSnapshotLease], manager)
    exit_method = _safe_call(lambda: context_manager.__exit__)
    if exit_method is _SAFE_CALL_FAILURE or not callable(exit_method):
        return False
    return _safe_call(lambda: exit_method(None, None, None)) is not _SAFE_CALL_FAILURE


def _mark_effect_ambiguous(
    journal: SQLiteAuthorizationJournal, verified: _VerifiedExecution
) -> None:
    result = _safe_call(lambda: journal._fail_effect(verified))
    if result is _SAFE_CALL_FAILURE:
        raise AuthorizationError("effect_failed_recovery_required")


def _check_execution_stability(
    journal: SQLiteAuthorizationJournal,
    journal_pin: _JournalExecutionPin,
    artifact_lease: ArtifactRootLease,
    operation_lease: _OperationLease,
) -> None:
    artifact_lease.assert_stable()
    operation_lease.assert_stable()
    journal._assert_pinned_execution_identity(journal_pin)


def _check_initial_execution_stability(
    journal: SQLiteInitialProvisioningJournal,
    journal_pin: _InitialJournalExecutionPin,
    intent: _VerifiedInitialIntent,
    artifact_lease: ArtifactRootLease,
    operation_lease: _OperationLease,
) -> None:
    artifact_lease.assert_stable()
    operation_lease.assert_stable()
    journal._assert_pinned_execution_identity(journal_pin)
    journal.assert_intent(intent)


def _check_observed_stage_stability(
    journal: SQLiteInitialProvisioningJournal,
    journal_pin: _InitialJournalExecutionPin,
    intent: _VerifiedInitialIntent,
) -> None:
    """Keep the completed initial stage pinned through an observed effect."""

    journal._assert_pinned_execution_identity(journal_pin)
    journal.assert_intent(intent)
    if (
        journal.operation_state(intent.intent.provisioning_operation_id)
        is not InitialProvisioningOperationState.PROVISIONED_EMPTY
    ):
        raise AuthorizationError("initial_operation_state")


def _require_current_initial_journal(status: InitialProvisioningJournalStatus) -> None:
    if status is InitialProvisioningJournalStatus.CURRENT:
        return
    phases = {
        InitialProvisioningJournalStatus.ABSENT: "initial_journal_absent",
        InitialProvisioningJournalStatus.PROVISIONING_INCOMPLETE: "initial_provisioning_incomplete",
        InitialProvisioningJournalStatus.ABANDONED: "initial_journal_abandoned",
        InitialProvisioningJournalStatus.JOURNAL_MISSING: "initial_journal_missing",
        InitialProvisioningJournalStatus.IDENTITY_MISMATCH: "initial_journal_identity_mismatch",
        InitialProvisioningJournalStatus.UNKNOWN: "initial_journal_schema",
    }
    raise AuthorizationError(phases[status])


def _verify_initial_intent_binding(
    verified: _VerifiedInitialIntent,
    *,
    journal: SQLiteInitialProvisioningJournal,
    replay_policy: ReplayAuthorityPolicyV1,
) -> None:
    if (
        type(verified) is not _VerifiedInitialIntent
        or verified.capability is not _INITIAL_INTENT_CAPABILITY
        or type(journal) is not SQLiteInitialProvisioningJournal
        or type(replay_policy) is not ReplayAuthorityPolicyV1
    ):
        raise AuthorizationError("initial_intent_binding")
    intent = verified.intent
    if (
        intent.journal_path != str(journal._path)
        or intent.journal_path_sha256 != journal._path_sha256()
        or intent.journal_schema_sha256 != journal.journal_schema_sha256()
        or intent.replay_policy_sha256 != replay_policy.sha256()
    ):
        raise AuthorizationError("initial_intent_binding")


def _require_tls_termination_profile(profile: object) -> None:
    """Keep TLS profiles outside every current create and effect boundary."""

    if profile is DisposableTransportProfile.TLS_VERIFIED:
        raise AuthorizationError("tls_termination_amendment_required")


def _require_tls_termination_amendment(intent: InitialProvisioningIntentV1) -> None:
    """Reject malformed and TLS initial intents at the effect boundary."""

    if type(intent) is not InitialProvisioningIntentV1:
        raise AuthorizationError("tls_termination_amendment_required")
    _require_tls_termination_profile(intent.plan.transport.profile)


def _provision_initial_journal_with_clock(
    paths: AuthorizationPaths,
    *,
    signer: TrustedEd25519SignerV1,
    expected_disposal_owner: str,
    expected_approver_identity: str,
    journal: SQLiteInitialProvisioningJournal,
    intent: InitialProvisioningIntentV1,
    replay_authority: ProtocolReplayAuthority,
    replay_policy: ReplayAuthorityPolicyV1,
    replay_policy_artifact: ReplayAuthorityPolicyArtifactV1,
    clock: Callable[[], datetime],
    _capability: object,
) -> InitialJournalProvisioningReceiptV1:
    """Explicit create-once initial journal provisioning from a signed intent."""

    if _capability not in {_TEST_CLOCK_CAPABILITY, _SYSTEM_CLOCK_CAPABILITY}:
        raise AuthorizationError("test_clock")
    if (
        type(paths) is not AuthorizationPaths
        or type(signer) is not TrustedEd25519SignerV1
        or type(journal) is not SQLiteInitialProvisioningJournal
        or type(intent) is not InitialProvisioningIntentV1
        or type(replay_policy) is not ReplayAuthorityPolicyV1
        or type(replay_policy_artifact) is not ReplayAuthorityPolicyArtifactV1
    ):
        raise AuthorizationError("initial_journal_genesis")
    _replay_claim_method(replay_authority)
    now = _read_clock(clock)
    _verify_initial_intent_signature(intent, signer=signer)
    replay_policy_verified = _safe_call(
        lambda: verify_replay_authority_policy_artifact(
            replay_policy_artifact,
            signer=signer,
            initial_intent=intent,
            expected_policy_sha256=replay_policy.sha256(),
        )
    )
    if replay_policy_verified is _SAFE_CALL_FAILURE:
        raise AuthorizationError("replay_policy_artifact")
    try:
        created = datetime.fromisoformat(intent.created_at.removesuffix("Z") + "+00:00")
        retained = datetime.fromisoformat(intent.retention_expires_at.removesuffix("Z") + "+00:00")
    except ValueError:
        raise AuthorizationError("initial_intent_freshness") from None
    if (
        created.tzinfo is None
        or retained.tzinfo is None
        or created.astimezone(UTC) > now
        or now - created.astimezone(UTC) > _STAGE_ATTESTATION_FRESHNESS
        or retained.astimezone(UTC) <= now
        or intent.disposal_owner != expected_disposal_owner
        or intent.approver_identity != expected_approver_identity
    ):
        raise AuthorizationError("initial_intent_freshness")
    verified = _VerifiedInitialIntent(
        intent=intent,
        intent_sha256=initial_provisioning_intent_sha256(intent),
        capability=_INITIAL_INTENT_CAPABILITY,
    )
    _verify_initial_intent_binding(verified, journal=journal, replay_policy=replay_policy)
    _require_tls_termination_amendment(intent)
    with ArtifactRootLease(paths.root) as artifact_lease:
        artifact_lease.assert_stable()
        if journal.migration_status() is not InitialProvisioningJournalStatus.ABSENT:
            raise AuthorizationError("initial_journal_replayed")
        artifact_lease.assert_absent(paths.initial_intent_name(), phase="initial_journal_replayed")
        artifact_lease.assert_absent(paths.initial_receipt_name(), phase="initial_journal_replayed")
        # The signed replay namespace is the durable preimage for the
        # irreversible external tombstone.  It must exist (and be durable)
        # first.  A crash at this point is safely resumable only when the
        # exact same verified bytes are already present; any substitution is
        # blocked rather than silently rotated.
        artifact_lease.write_once_or_require_exact(
            paths.replay_policy_name(),
            _replay_policy_artifact_bytes(replay_policy_artifact),
            phase="replay_policy_artifact",
        )
        # Reopen descriptor-relatively and verify the bytes which are now
        # durable.  Verifying only the caller-provided object before the
        # create would leave a narrow pre-claim substitution surface.
        persisted_replay_policy, persisted_replay_raw = _read_replay_policy_artifact(
            paths,
            signer=signer,
            initial_intent=intent,
            replay_policy=replay_policy,
            reader=artifact_lease.reader(),
        )
        if persisted_replay_policy != replay_policy_artifact or not hmac.compare_digest(
            persisted_replay_raw,
            _replay_policy_artifact_bytes(replay_policy_artifact),
        ):
            raise AuthorizationError("replay_policy_artifact")
        artifact_lease.assert_stable()
        journal._begin_verified_intent(verified)
        _claim_replay_tombstone(
            replay_authority,
            _initial_genesis_tombstone(replay_policy, verified),
            phase="initial_journal_replayed",
        )
        artifact_lease.assert_stable()
        artifact_lease.write_once(
            paths.initial_intent_name(),
            _initial_intent_artifact_bytes(intent),
            phase="initial_journal_replayed",
        )
        journal._complete_verified_intent(verified)
        journal.assert_intent(verified)
        artifact_lease.assert_stable()
    return InitialJournalProvisioningReceiptV1(
        schema_version="rsd.initial-provisioning-journal-provisioning-receipt.v1",
        status="provisioned",
        operation_kind=_INITIAL_OPERATION_KIND,
        provisioning_operation_id=intent.provisioning_operation_id,
        journal_uuid=intent.journal_uuid,
        intent_sha256=verified.intent_sha256,
        provisioned_at=now.isoformat(timespec="seconds").replace("+00:00", "Z"),
    )


def provision_initial_journal(
    paths: AuthorizationPaths,
    *,
    signer: TrustedEd25519SignerV1,
    expected_disposal_owner: str,
    expected_approver_identity: str,
    journal: SQLiteInitialProvisioningJournal,
    intent: InitialProvisioningIntentV1,
    replay_authority: ProtocolReplayAuthority,
    replay_policy: ReplayAuthorityPolicyV1,
    replay_policy_artifact: ReplayAuthorityPolicyArtifactV1,
) -> InitialJournalProvisioningReceiptV1:
    """Provision the separate pre-creation journal exactly once."""

    return _provision_initial_journal_with_clock(
        paths,
        signer=signer,
        expected_disposal_owner=expected_disposal_owner,
        expected_approver_identity=expected_approver_identity,
        journal=journal,
        intent=intent,
        replay_authority=replay_authority,
        replay_policy=replay_policy,
        replay_policy_artifact=replay_policy_artifact,
        clock=_system_utc_clock,
        _capability=_SYSTEM_CLOCK_CAPABILITY,
    )


def _provision_initial_journal_for_test(
    paths: AuthorizationPaths,
    *,
    signer: TrustedEd25519SignerV1,
    expected_disposal_owner: str,
    expected_approver_identity: str,
    journal: SQLiteInitialProvisioningJournal,
    intent: InitialProvisioningIntentV1,
    replay_authority: ProtocolReplayAuthority,
    replay_policy: ReplayAuthorityPolicyV1,
    replay_policy_artifact: ReplayAuthorityPolicyArtifactV1,
    _clock: Callable[[], datetime],
    _capability: object,
) -> InitialJournalProvisioningReceiptV1:
    """Module-restricted test clock seam for initial journal provisioning."""

    if _capability is not _TEST_CLOCK_CAPABILITY:
        raise AuthorizationError("test_clock")
    return _provision_initial_journal_with_clock(
        paths,
        signer=signer,
        expected_disposal_owner=expected_disposal_owner,
        expected_approver_identity=expected_approver_identity,
        journal=journal,
        intent=intent,
        replay_authority=replay_authority,
        replay_policy=replay_policy,
        replay_policy_artifact=replay_policy_artifact,
        clock=_clock,
        _capability=_TEST_CLOCK_CAPABILITY,
    )


def _mark_initial_effect_ambiguous(
    journal: SQLiteInitialProvisioningJournal, verified: _VerifiedInitialProvisioning
) -> None:
    if _safe_call(lambda: journal._fail_effect(verified)) is _SAFE_CALL_FAILURE:
        raise AuthorizationError("initial_effect_failed_recovery_required")


def _authorize_initial_provisioning_and_execute_with_clock(
    paths: AuthorizationPaths,
    *,
    signer: TrustedEd25519SignerV1,
    provider: ProviderProvenanceAdapter,
    expected_disposal_owner: str,
    expected_approver_identity: str,
    journal: SQLiteInitialProvisioningJournal,
    effect: Callable[[InitialProvisioningExecutionContext], InitialProvisioningEffectReceiptV1],
    replay_authority: ProtocolReplayAuthority,
    replay_policy: ReplayAuthorityPolicyV1,
    clock: Callable[[], datetime],
) -> InitialProvisioningExecutionReceiptV1:
    """Authorize only the typed isolated-empty pre-observation effect scope."""

    if (
        type(paths) is not AuthorizationPaths
        or type(signer) is not TrustedEd25519SignerV1
        or type(journal) is not SQLiteInitialProvisioningJournal
        or type(replay_policy) is not ReplayAuthorityPolicyV1
        or not callable(effect)
    ):
        raise AuthorizationError("initial_journal_effect")
    _replay_claim_method(replay_authority)
    with ArtifactRootLease(paths.root) as artifact_lease:
        artifact_lease.assert_stable()
        _require_current_initial_journal(journal.migration_status())
        verified_intent, initial_raw = _read_verified_initial_intent(
            paths,
            signer=signer,
            expected_disposal_owner=expected_disposal_owner,
            expected_approver_identity=expected_approver_identity,
            now=_read_clock(clock),
            reader=artifact_lease.reader(),
        )
        _verify_initial_intent_binding(
            verified_intent, journal=journal, replay_policy=replay_policy
        )
        _require_tls_termination_amendment(verified_intent.intent)
        replay_artifact, replay_raw = _read_replay_policy_artifact(
            paths,
            signer=signer,
            initial_intent=verified_intent.intent,
            replay_policy=replay_policy,
            reader=artifact_lease.reader(),
        )
        fingerprints, material_snapshot = _trusted_provider_fingerprints(
            signer=signer,
            initial_intent=verified_intent.intent,
            expected_disposal_owner=expected_disposal_owner,
            expected_approver_identity=expected_approver_identity,
            now=_read_clock(clock),
            reader=artifact_lease.reader(),
        )
        journal.assert_intent(verified_intent)
        journal_pin = journal._pin_execution_identity()
        artifact_lease.assert_absent(
            paths.initial_receipt_name(), phase="initial_operation_replayed"
        )
        references = verified_intent.intent.provider_references.all()
        manager, provider_lease = _acquire_provider_lease(provider, references)
        released = True
        execution_receipt: InitialProvisioningExecutionReceiptV1 | None = None
        try:
            initial_provider_sha256, expectations = _provider_commitment(
                references=references,
                lease=provider_lease,
                fingerprints=fingerprints,
                recheck=False,
            )
            artifact_lease.assert_stable()
            journal._assert_pinned_execution_identity(journal_pin)
            repeated_intent, repeated_raw = _read_verified_initial_intent(
                paths,
                signer=signer,
                expected_disposal_owner=expected_disposal_owner,
                expected_approver_identity=expected_approver_identity,
                now=_read_clock(clock),
                reader=artifact_lease.reader(),
            )
            if repeated_intent != verified_intent or repeated_raw != initial_raw:
                raise AuthorizationError("initial_artifact_race")
            repeated_replay_artifact, repeated_replay_raw = _read_replay_policy_artifact(
                paths,
                signer=signer,
                initial_intent=repeated_intent.intent,
                replay_policy=replay_policy,
                reader=artifact_lease.reader(),
            )
            if repeated_replay_artifact != replay_artifact or repeated_replay_raw != replay_raw:
                raise AuthorizationError("initial_artifact_race")
            repeated_fingerprints, repeated_material_snapshot = _trusted_provider_fingerprints(
                signer=signer,
                initial_intent=repeated_intent.intent,
                expected_disposal_owner=expected_disposal_owner,
                expected_approver_identity=expected_approver_identity,
                now=_read_clock(clock),
                reader=artifact_lease.reader(),
            )
            if (
                repeated_fingerprints != fingerprints
                or repeated_material_snapshot != material_snapshot
            ):
                raise AuthorizationError("initial_artifact_race")
            final_provider_sha256, final_expectations = _provider_commitment(
                references=references,
                lease=provider_lease,
                fingerprints=fingerprints,
                recheck=True,
            )
            artifact_lease.assert_stable()
            journal._assert_pinned_execution_identity(journal_pin)
            if (
                initial_provider_sha256 != final_provider_sha256
                or expectations != final_expectations
            ):
                raise AuthorizationError("initial_provider_race")
            terminal_fingerprints, terminal_material_snapshot = _trusted_provider_fingerprints(
                signer=signer,
                initial_intent=verified_intent.intent,
                expected_disposal_owner=expected_disposal_owner,
                expected_approver_identity=expected_approver_identity,
                now=_read_clock(clock),
                reader=artifact_lease.reader(),
            )
            if (
                terminal_fingerprints != fingerprints
                or terminal_material_snapshot != material_snapshot
            ):
                raise AuthorizationError("initial_artifact_race")
            authorized_at = _read_clock(clock).isoformat(timespec="seconds").replace("+00:00", "Z")
            context = InitialProvisioningExecutionContext(
                operation_kind=_INITIAL_OPERATION_KIND,
                operation_scope="create_isolated_empty_resources_v1",
                provisioning_operation_id=verified_intent.intent.provisioning_operation_id,
                intent=verified_intent.intent,
                provider_expectations=final_expectations,
                intent_sha256=verified_intent.intent_sha256,
                idempotency_key=_initial_idempotency_key(
                    provisioning_operation_id=verified_intent.intent.provisioning_operation_id,
                    intent_sha256=verified_intent.intent_sha256,
                    provider_sha256=final_provider_sha256,
                ),
                provider_provenance_sha256=final_provider_sha256,
            )
            verified = _VerifiedInitialProvisioning(
                context=context,
                nonce=secrets.token_hex(16),
                authorized_at=authorized_at,
                capability=_INITIAL_VERIFIED_CAPABILITY,
            )
            with journal._operation_lease(context.provisioning_operation_id) as operation_lease:
                _check_initial_execution_stability(
                    journal, journal_pin, verified_intent, artifact_lease, operation_lease
                )
                _claim_replay_tombstone(
                    replay_authority,
                    _initial_operation_tombstone(replay_policy, verified),
                    phase="initial_replay_authority_replayed",
                )
                _check_initial_execution_stability(
                    journal, journal_pin, verified_intent, artifact_lease, operation_lease
                )
                journal._claim_verified(verified)
                journal._begin_effect(verified)
                _check_initial_execution_stability(
                    journal, journal_pin, verified_intent, artifact_lease, operation_lease
                )
                outcome = _safe_call(lambda: effect(context))
                if outcome is _SAFE_CALL_FAILURE:
                    _mark_initial_effect_ambiguous(journal, verified)
                    raise AuthorizationError("initial_effect_failed_recovery_required")
                effect_receipt = _safe_call(
                    lambda: _validate_initial_effect_receipt(context, outcome)
                )
                if type(effect_receipt) is not InitialProvisioningEffectReceiptV1:
                    _mark_initial_effect_ambiguous(journal, verified)
                    raise AuthorizationError("initial_effect_failed_recovery_required")
                post_effect_fingerprints = _safe_call(
                    lambda: _trusted_provider_fingerprints(
                        signer=signer,
                        initial_intent=verified_intent.intent,
                        expected_disposal_owner=expected_disposal_owner,
                        expected_approver_identity=expected_approver_identity,
                        now=_read_clock(clock),
                        reader=artifact_lease.reader(),
                    )
                )
                if post_effect_fingerprints is _SAFE_CALL_FAILURE or post_effect_fingerprints != (
                    fingerprints,
                    material_snapshot,
                ):
                    _mark_initial_effect_ambiguous(journal, verified)
                    raise AuthorizationError("initial_effect_failed_recovery_required")
                stable = _safe_call(
                    lambda: _check_initial_execution_stability(
                        journal, journal_pin, verified_intent, artifact_lease, operation_lease
                    )
                )
                if stable is _SAFE_CALL_FAILURE:
                    _mark_initial_effect_ambiguous(journal, verified)
                    raise AuthorizationError("initial_effect_failed_recovery_required")
                receipt_written = _safe_call(
                    lambda: artifact_lease.write_once(
                        paths.initial_receipt_name(),
                        _initial_receipt_artifact_bytes(effect_receipt),
                        phase="initial_effect_failed_recovery_required",
                    )
                )
                if receipt_written is _SAFE_CALL_FAILURE:
                    _mark_initial_effect_ambiguous(journal, verified)
                    raise AuthorizationError("initial_effect_failed_recovery_required")
                stable_before_commit = _safe_call(
                    lambda: _check_initial_execution_stability(
                        journal, journal_pin, verified_intent, artifact_lease, operation_lease
                    )
                )
                if stable_before_commit is _SAFE_CALL_FAILURE:
                    _mark_initial_effect_ambiguous(journal, verified)
                    raise AuthorizationError("initial_effect_failed_recovery_required")
                committed = _safe_call(lambda: journal._commit_effect(verified, effect_receipt))
                if committed is _SAFE_CALL_FAILURE:
                    _mark_initial_effect_ambiguous(journal, verified)
                    raise AuthorizationError("initial_effect_failed_recovery_required")
                terminal_stable = _safe_call(
                    lambda: _check_initial_execution_stability(
                        journal, journal_pin, verified_intent, artifact_lease, operation_lease
                    )
                )
                if terminal_stable is _SAFE_CALL_FAILURE:
                    raise AuthorizationError("initial_terminal_stability")
                execution_receipt = InitialProvisioningExecutionReceiptV1(
                    schema_version="rsd.initial-provisioning-execution-receipt.v1",
                    status="provisioned_empty",
                    operation_kind=_INITIAL_OPERATION_KIND,
                    operation_scope="create_isolated_empty_resources_v1",
                    provisioning_operation_id=context.provisioning_operation_id,
                    intent_sha256=context.intent_sha256,
                    idempotency_key=context.idempotency_key,
                    effect_receipt_sha256=effect_receipt.effect_receipt_sha256,
                    observed_resources_sha256=_digest(
                        _INITIAL_EFFECT_RECEIPT_DOMAIN
                        + json.dumps(
                            effect_receipt.observed_resources.model_dump(mode="json"),
                            sort_keys=True,
                            separators=(",", ":"),
                        ).encode()
                    ),
                    committed_at=authorized_at,
                )
        finally:
            released = _release_provider_lease(manager)
        if not released:
            raise AuthorizationError("provider_release")
        assert execution_receipt is not None
        return execution_receipt


def authorize_initial_provisioning_and_execute(
    paths: AuthorizationPaths,
    *,
    signer: TrustedEd25519SignerV1,
    provider: ProviderProvenanceAdapter,
    expected_disposal_owner: str,
    expected_approver_identity: str,
    journal: SQLiteInitialProvisioningJournal,
    effect: Callable[[InitialProvisioningExecutionContext], InitialProvisioningEffectReceiptV1],
    replay_authority: ProtocolReplayAuthority,
    replay_policy: ReplayAuthorityPolicyV1,
) -> InitialProvisioningExecutionReceiptV1:
    """Use the trusted system clock for the sole initial creation boundary."""

    return _authorize_initial_provisioning_and_execute_with_clock(
        paths,
        signer=signer,
        provider=provider,
        expected_disposal_owner=expected_disposal_owner,
        expected_approver_identity=expected_approver_identity,
        journal=journal,
        effect=effect,
        replay_authority=replay_authority,
        replay_policy=replay_policy,
        clock=_system_utc_clock,
    )


def _authorize_initial_provisioning_and_execute_for_test(
    paths: AuthorizationPaths,
    *,
    signer: TrustedEd25519SignerV1,
    provider: ProviderProvenanceAdapter,
    expected_disposal_owner: str,
    expected_approver_identity: str,
    journal: SQLiteInitialProvisioningJournal,
    effect: Callable[[InitialProvisioningExecutionContext], InitialProvisioningEffectReceiptV1],
    replay_authority: ProtocolReplayAuthority,
    replay_policy: ReplayAuthorityPolicyV1,
    _clock: Callable[[], datetime],
    _capability: object,
) -> InitialProvisioningExecutionReceiptV1:
    """Module-restricted clock seam for adversarial initial-stage tests."""

    if _capability is not _TEST_CLOCK_CAPABILITY:
        raise AuthorizationError("test_clock")
    return _authorize_initial_provisioning_and_execute_with_clock(
        paths,
        signer=signer,
        provider=provider,
        expected_disposal_owner=expected_disposal_owner,
        expected_approver_identity=expected_approver_identity,
        journal=journal,
        effect=effect,
        replay_authority=replay_authority,
        replay_policy=replay_policy,
        clock=_clock,
    )


def _provision_journal_with_clock(
    paths: AuthorizationPaths,
    *,
    signer: TrustedEd25519SignerV1,
    expected_disposal_owner: str,
    expected_approver_identity: str,
    journal: SQLiteAuthorizationJournal,
    receipt: JournalGenesisReceiptV1,
    replay_authority: ProtocolReplayAuthority,
    replay_policy: ReplayAuthorityPolicyV1,
    clock: Callable[[], datetime],
    _capability: object,
) -> JournalProvisioningReceiptV1:
    """Explicit one-time journal genesis; never called by authorization/effect paths."""

    if _capability is not _TEST_CLOCK_CAPABILITY and _capability is not _SYSTEM_CLOCK_CAPABILITY:
        raise AuthorizationError("test_clock")
    if (
        type(paths) is not AuthorizationPaths
        or type(signer) is not TrustedEd25519SignerV1
        or type(journal) is not SQLiteAuthorizationJournal
        or type(receipt) is not JournalGenesisReceiptV1
        or type(replay_policy) is not ReplayAuthorityPolicyV1
    ):
        raise AuthorizationError("journal_genesis")
    _replay_claim_method(replay_authority)
    now = _read_clock(clock)
    with ArtifactRootLease(paths.root) as artifact_lease:
        artifacts, _ = _verify_artifact_snapshot(
            paths,
            signer=signer,
            expected_disposal_owner=expected_disposal_owner,
            expected_approver_identity=expected_approver_identity,
            now=now,
            reader=artifact_lease.reader(),
        )
        _require_tls_termination_profile(artifacts.proposal.transport.profile)
        _verify_journal_genesis_binding(
            receipt,
            artifacts=artifacts,
            signer=signer,
            expected_disposal_owner=expected_disposal_owner,
            expected_approver_identity=expected_approver_identity,
            journal=journal,
            replay_policy=replay_policy,
            now=now,
        )
        raw = _journal_genesis_artifact_bytes(receipt)
        verified = _VerifiedGenesis(
            receipt=receipt,
            artifact_sha256=_digest(raw),
            capability=_GENESIS_CAPABILITY,
        )
        status = journal.migration_status()
        if status is JournalMigrationStatus.PROVISIONING_INCOMPLETE:
            raise AuthorizationError("provisioning_incomplete")
        if status is not JournalMigrationStatus.ABSENT:
            raise AuthorizationError("journal_genesis_replayed")
        artifact_lease.assert_absent(paths.journal_genesis_name(), phase="journal_genesis_replayed")
        journal._begin_verified_genesis(verified)
        _claim_replay_tombstone(
            replay_authority,
            _genesis_tombstone(replay_policy, verified),
            phase="journal_genesis_replayed",
        )
        artifact_lease.assert_stable()
        artifact_lease.write_once(
            paths.journal_genesis_name(), raw, phase="journal_genesis_replayed"
        )
        journal._complete_verified_genesis(verified)
        artifact_lease.assert_stable()
    return JournalProvisioningReceiptV1(
        schema_version="rsd.authorization-journal-provisioning-receipt.v1",
        status="provisioned",
        journal_uuid=receipt.journal_uuid,
        genesis_sha256=verified.artifact_sha256,
        provisioned_at=now.isoformat(timespec="seconds").replace("+00:00", "Z"),
    )


def provision_journal(
    paths: AuthorizationPaths,
    *,
    signer: TrustedEd25519SignerV1,
    expected_disposal_owner: str,
    expected_approver_identity: str,
    journal: SQLiteAuthorizationJournal,
    receipt: JournalGenesisReceiptV1,
    replay_authority: ProtocolReplayAuthority,
    replay_policy: ReplayAuthorityPolicyV1,
) -> JournalProvisioningReceiptV1:
    """Provision exactly one signed journal identity for the supplied artifacts."""

    return _provision_journal_with_clock(
        paths,
        signer=signer,
        expected_disposal_owner=expected_disposal_owner,
        expected_approver_identity=expected_approver_identity,
        journal=journal,
        receipt=receipt,
        replay_authority=replay_authority,
        replay_policy=replay_policy,
        clock=_system_utc_clock,
        _capability=_SYSTEM_CLOCK_CAPABILITY,
    )


def _provision_journal_for_test(
    paths: AuthorizationPaths,
    *,
    signer: TrustedEd25519SignerV1,
    expected_disposal_owner: str,
    expected_approver_identity: str,
    journal: SQLiteAuthorizationJournal,
    receipt: JournalGenesisReceiptV1,
    replay_authority: ProtocolReplayAuthority,
    replay_policy: ReplayAuthorityPolicyV1,
    _clock: Callable[[], datetime],
    _capability: object,
) -> JournalProvisioningReceiptV1:
    """Test-only clock seam, unavailable from the public provisioning entry point."""

    if _capability is not _TEST_CLOCK_CAPABILITY:
        raise AuthorizationError("test_clock")
    return _provision_journal_with_clock(
        paths,
        signer=signer,
        expected_disposal_owner=expected_disposal_owner,
        expected_approver_identity=expected_approver_identity,
        journal=journal,
        receipt=receipt,
        replay_authority=replay_authority,
        replay_policy=replay_policy,
        clock=_clock,
        _capability=_TEST_CLOCK_CAPABILITY,
    )


def reconcile_journal_genesis(
    journal: SQLiteAuthorizationJournal,
    receipt: JournalGenesisReconciliationReceiptV1,
    *,
    signer: TrustedEd25519SignerV1,
) -> JournalMigrationStatus:
    """Apply signed recovery evidence to an interrupted journal genesis only."""

    if (
        type(journal) is not SQLiteAuthorizationJournal
        or type(receipt) is not JournalGenesisReconciliationReceiptV1
        or type(signer) is not TrustedEd25519SignerV1
    ):
        raise AuthorizationError("journal_genesis_reconciliation")
    return journal.reconcile_genesis(receipt, signer=signer)


def reconcile_initial_journal_genesis(
    journal: SQLiteInitialProvisioningJournal,
    receipt: InitialJournalGenesisReconciliationReceiptV1,
    *,
    signer: TrustedEd25519SignerV1,
) -> InitialProvisioningJournalStatus:
    """Apply signed, non-retrying recovery evidence to initial genesis only."""

    if (
        type(journal) is not SQLiteInitialProvisioningJournal
        or type(receipt) is not InitialJournalGenesisReconciliationReceiptV1
        or type(signer) is not TrustedEd25519SignerV1
    ):
        raise AuthorizationError("initial_journal_reconciliation")
    _verify_initial_journal_genesis_reconciliation_receipt(receipt, signer=signer)
    return journal.reconcile_genesis(receipt)


def _require_current_journal(status: JournalMigrationStatus) -> None:
    if status is JournalMigrationStatus.CURRENT:
        return
    phases = {
        JournalMigrationStatus.ABSENT: "journal_absent",
        JournalMigrationStatus.ANCHOR_MISSING: "journal_anchor_missing",
        JournalMigrationStatus.GENESIS_MISSING: "journal_genesis_missing",
        JournalMigrationStatus.JOURNAL_MISSING: "journal_missing",
        JournalMigrationStatus.PROVISIONING_INCOMPLETE: "provisioning_incomplete",
        JournalMigrationStatus.IDENTITY_MISMATCH: "journal_identity_mismatch",
        JournalMigrationStatus.LEGACY_DETECTED: "journal_legacy_detected",
        JournalMigrationStatus.EMPTY: "journal_schema",
        JournalMigrationStatus.UNKNOWN: "journal_schema",
    }
    raise AuthorizationError(phases[status])


def _authorize_and_execute_with_clock(
    paths: AuthorizationPaths,
    *,
    signer: TrustedEd25519SignerV1,
    provider: ProviderProvenanceAdapter,
    expected_disposal_owner: str,
    expected_approver_identity: str,
    journal: SQLiteAuthorizationJournal,
    initial_journal: SQLiteInitialProvisioningJournal,
    effect: Callable[[VerifiedExecutionContext], EffectReceiptV1],
    replay_authority: ProtocolReplayAuthority,
    replay_policy: ReplayAuthorityPolicyV1,
    clock: Callable[[], datetime],
) -> ExecutionReceiptV1:
    """Internal implementation with a capability-hidden test clock.

    The public entry point always supplies the system UTC clock.  A failed
    callback and any process interruption after ``_begin_effect`` leave an
    ambiguous operation that cannot be retried automatically.
    """

    if (
        type(paths) is not AuthorizationPaths
        or type(signer) is not TrustedEd25519SignerV1
        or type(journal) is not SQLiteAuthorizationJournal
        or type(initial_journal) is not SQLiteInitialProvisioningJournal
        or type(replay_policy) is not ReplayAuthorityPolicyV1
        or not callable(effect)
    ):
        raise AuthorizationError("journal_effect")
    _replay_claim_method(replay_authority)
    with ArtifactRootLease(paths.root) as artifact_lease:
        artifact_lease.assert_stable()
        _require_current_journal(journal.migration_status())
        _require_current_initial_journal(initial_journal.migration_status())
        journal_pin = journal._pin_execution_identity()
        artifacts, genesis, snapshot = _verify_authorization_artifact_snapshot(
            paths,
            signer=signer,
            expected_disposal_owner=expected_disposal_owner,
            expected_approver_identity=expected_approver_identity,
            journal=journal,
            replay_policy=replay_policy,
            now=_read_clock(clock),
            reader=artifact_lease.reader(),
        )
        initial_stage, initial_stage_snapshot = _read_initial_stage_artifacts(
            paths,
            signer=signer,
            expected_disposal_owner=expected_disposal_owner,
            expected_approver_identity=expected_approver_identity,
            now=_read_clock(clock),
            reader=artifact_lease.reader(),
        )
        verified_initial_intent = _VerifiedInitialIntent(
            intent=initial_stage.intent,
            intent_sha256=initial_provisioning_intent_sha256(initial_stage.intent),
            capability=_INITIAL_INTENT_CAPABILITY,
        )
        _verify_initial_intent_binding(
            verified_initial_intent, journal=initial_journal, replay_policy=replay_policy
        )
        _require_tls_termination_amendment(verified_initial_intent.intent)
        replay_artifact, replay_raw = _read_replay_policy_artifact(
            paths,
            signer=signer,
            initial_intent=initial_stage.intent,
            replay_policy=replay_policy,
            reader=artifact_lease.reader(),
        )
        fingerprints, material_snapshot = _trusted_provider_fingerprints(
            signer=signer,
            initial_intent=initial_stage.intent,
            expected_disposal_owner=expected_disposal_owner,
            expected_approver_identity=expected_approver_identity,
            now=_read_clock(clock),
            reader=artifact_lease.reader(),
        )
        initial_journal.assert_intent(verified_initial_intent)
        if (
            initial_journal.operation_state(initial_stage.intent.provisioning_operation_id)
            is not InitialProvisioningOperationState.PROVISIONED_EMPTY
        ):
            raise AuthorizationError("initial_operation_state")
        initial_journal_pin = initial_journal._pin_execution_identity()
        try:
            validate_observed_candidate_transition(
                initial_stage.intent,
                initial_stage.receipt,
                initial_stage.attestation,
                artifacts.proposal,
                artifacts.final_contract,
            )
        except ValueError:
            raise AuthorizationError("initial_stage_transition") from None
        artifact_lease.assert_stable()
        journal.assert_genesis(genesis)
        journal._assert_pinned_execution_identity(journal_pin)
        _check_observed_stage_stability(
            initial_journal, initial_journal_pin, verified_initial_intent
        )
        artifact_lease.assert_stable()
        references = artifacts.proposal.provider_references.all()
        manager, provider_lease = _acquire_provider_lease(provider, references)
        execution_receipt: ExecutionReceiptV1 | None = None
        provider_released = True
        try:
            initial_provider_sha256, expectations = _provider_commitment(
                references=references,
                lease=provider_lease,
                fingerprints=fingerprints,
                recheck=False,
            )
            artifact_lease.assert_stable()
            journal._assert_pinned_execution_identity(journal_pin)
            _check_observed_stage_stability(
                initial_journal, initial_journal_pin, verified_initial_intent
            )
            repeated_artifacts, repeated_genesis, repeated_snapshot = (
                _verify_authorization_artifact_snapshot(
                    paths,
                    signer=signer,
                    expected_disposal_owner=expected_disposal_owner,
                    expected_approver_identity=expected_approver_identity,
                    journal=journal,
                    replay_policy=replay_policy,
                    now=_read_clock(clock),
                    reader=artifact_lease.reader(),
                )
            )
            repeated_stage, repeated_stage_snapshot = _read_initial_stage_artifacts(
                paths,
                signer=signer,
                expected_disposal_owner=expected_disposal_owner,
                expected_approver_identity=expected_approver_identity,
                now=_read_clock(clock),
                reader=artifact_lease.reader(),
            )
            repeated_replay_artifact, repeated_replay_raw = _read_replay_policy_artifact(
                paths,
                signer=signer,
                initial_intent=repeated_stage.intent,
                replay_policy=replay_policy,
                reader=artifact_lease.reader(),
            )
            repeated_fingerprints, repeated_material_snapshot = _trusted_provider_fingerprints(
                signer=signer,
                initial_intent=repeated_stage.intent,
                expected_disposal_owner=expected_disposal_owner,
                expected_approver_identity=expected_approver_identity,
                now=_read_clock(clock),
                reader=artifact_lease.reader(),
            )
            try:
                validate_observed_candidate_transition(
                    repeated_stage.intent,
                    repeated_stage.receipt,
                    repeated_stage.attestation,
                    repeated_artifacts.proposal,
                    repeated_artifacts.final_contract,
                )
            except ValueError:
                raise AuthorizationError("initial_stage_transition") from None
            _check_observed_stage_stability(
                initial_journal, initial_journal_pin, verified_initial_intent
            )
            artifact_lease.assert_stable()
            if (
                not _same_artifact_receipt(artifacts.receipt, repeated_artifacts.receipt)
                or genesis != repeated_genesis
                or snapshot != repeated_snapshot
                or initial_stage_snapshot != repeated_stage_snapshot
                or replay_artifact != repeated_replay_artifact
                or replay_raw != repeated_replay_raw
                or fingerprints != repeated_fingerprints
                or material_snapshot != repeated_material_snapshot
            ):
                raise AuthorizationError("artifact_race")
            final_provider_sha256, final_expectations = _provider_commitment(
                references=references,
                lease=provider_lease,
                fingerprints=fingerprints,
                recheck=True,
            )
            artifact_lease.assert_stable()
            journal._assert_pinned_execution_identity(journal_pin)
            _check_observed_stage_stability(
                initial_journal, initial_journal_pin, verified_initial_intent
            )
            if (
                initial_provider_sha256 != final_provider_sha256
                or expectations != final_expectations
            ):
                raise AuthorizationError("provider_race")
            authorization_clock = _read_clock(clock)
            terminal_artifacts, terminal_genesis, terminal_snapshot = (
                _verify_authorization_artifact_snapshot(
                    paths,
                    signer=signer,
                    expected_disposal_owner=expected_disposal_owner,
                    expected_approver_identity=expected_approver_identity,
                    journal=journal,
                    replay_policy=replay_policy,
                    now=authorization_clock,
                    reader=artifact_lease.reader(),
                )
            )
            terminal_stage, terminal_stage_snapshot = _read_initial_stage_artifacts(
                paths,
                signer=signer,
                expected_disposal_owner=expected_disposal_owner,
                expected_approver_identity=expected_approver_identity,
                now=authorization_clock,
                reader=artifact_lease.reader(),
            )
            terminal_replay_artifact, terminal_replay_raw = _read_replay_policy_artifact(
                paths,
                signer=signer,
                initial_intent=terminal_stage.intent,
                replay_policy=replay_policy,
                reader=artifact_lease.reader(),
            )
            terminal_fingerprints, terminal_material_snapshot = _trusted_provider_fingerprints(
                signer=signer,
                initial_intent=terminal_stage.intent,
                expected_disposal_owner=expected_disposal_owner,
                expected_approver_identity=expected_approver_identity,
                now=authorization_clock,
                reader=artifact_lease.reader(),
            )
            try:
                validate_observed_candidate_transition(
                    terminal_stage.intent,
                    terminal_stage.receipt,
                    terminal_stage.attestation,
                    terminal_artifacts.proposal,
                    terminal_artifacts.final_contract,
                )
            except ValueError:
                raise AuthorizationError("initial_stage_transition") from None
            _check_observed_stage_stability(
                initial_journal, initial_journal_pin, verified_initial_intent
            )
            artifact_lease.assert_stable()
            if (
                not _same_artifact_receipt(artifacts.receipt, repeated_artifacts.receipt)
                or not _same_artifact_receipt(artifacts.receipt, terminal_artifacts.receipt)
                or genesis != repeated_genesis
                or genesis != terminal_genesis
                or snapshot != repeated_snapshot
                or snapshot != terminal_snapshot
                or initial_stage_snapshot != terminal_stage_snapshot
                or replay_artifact != terminal_replay_artifact
                or replay_raw != terminal_replay_raw
                or fingerprints != terminal_fingerprints
                or material_snapshot != terminal_material_snapshot
            ):
                raise AuthorizationError("artifact_race")
            idempotency_key = _idempotency_key(
                operation_id=artifacts.receipt.operation_id,
                proposal_sha256=artifacts.receipt.proposal_sha256,
                contract_sha256=artifacts.receipt.contract_sha256,
                provider_sha256=final_provider_sha256,
            )
            context = VerifiedExecutionContext(
                operation_kind=_OBSERVED_OPERATION_KIND,
                operation_id=artifacts.receipt.operation_id,
                idempotency_key=idempotency_key,
                proposal=artifacts.proposal,
                final_contract=artifacts.final_contract,
                provider_expectations=final_expectations,
                proposal_sha256=artifacts.receipt.proposal_sha256,
                contract_sha256=artifacts.receipt.contract_sha256,
                provider_provenance_sha256=final_provider_sha256,
            )
            authorized_at = authorization_clock.isoformat(timespec="seconds").replace("+00:00", "Z")
            verified = _VerifiedExecution(
                context=context,
                nonce=secrets.token_hex(16),
                authorized_at=authorized_at,
                capability=_VERIFIED_CAPABILITY,
            )
            with journal._operation_lease(context.operation_id) as operation_lease:
                _check_execution_stability(journal, journal_pin, artifact_lease, operation_lease)
                _check_observed_stage_stability(
                    initial_journal, initial_journal_pin, verified_initial_intent
                )
                _claim_replay_tombstone(
                    replay_authority,
                    _operation_tombstone(replay_policy, genesis, context),
                    phase="replay_authority_replayed",
                )
                _check_execution_stability(journal, journal_pin, artifact_lease, operation_lease)
                _check_observed_stage_stability(
                    initial_journal, initial_journal_pin, verified_initial_intent
                )
                journal._claim_verified(verified)
                journal._begin_effect(verified)
                _check_execution_stability(journal, journal_pin, artifact_lease, operation_lease)
                _check_observed_stage_stability(
                    initial_journal, initial_journal_pin, verified_initial_intent
                )
                outcome = _safe_call(lambda: effect(context))
                if outcome is _SAFE_CALL_FAILURE:
                    _mark_effect_ambiguous(journal, verified)
                    raise AuthorizationError("effect_failed_recovery_required")
                effect_receipt = _safe_call(lambda: _validate_effect_receipt(context, outcome))
                if type(effect_receipt) is not EffectReceiptV1:
                    _mark_effect_ambiguous(journal, verified)
                    raise AuthorizationError("effect_failed_recovery_required")
                post_effect_stable = _safe_call(
                    lambda: _check_execution_stability(
                        journal, journal_pin, artifact_lease, operation_lease
                    )
                )
                initial_post_effect_stable = _safe_call(
                    lambda: _check_observed_stage_stability(
                        initial_journal, initial_journal_pin, verified_initial_intent
                    )
                )
                post_effect_materials = _safe_call(
                    lambda: _trusted_provider_fingerprints(
                        signer=signer,
                        initial_intent=verified_initial_intent.intent,
                        expected_disposal_owner=expected_disposal_owner,
                        expected_approver_identity=expected_approver_identity,
                        now=_read_clock(clock),
                        reader=artifact_lease.reader(),
                    )
                )
                if (
                    post_effect_stable is _SAFE_CALL_FAILURE
                    or initial_post_effect_stable is _SAFE_CALL_FAILURE
                    or post_effect_materials is _SAFE_CALL_FAILURE
                    or post_effect_materials != (fingerprints, material_snapshot)
                ):
                    _mark_effect_ambiguous(journal, verified)
                    raise AuthorizationError("effect_failed_recovery_required")
                committed = _safe_call(lambda: journal._commit_effect(verified, effect_receipt))
                if committed is _SAFE_CALL_FAILURE:
                    _mark_effect_ambiguous(journal, verified)
                    raise AuthorizationError("effect_failed_recovery_required")
                terminal_stable = _safe_call(
                    lambda: _check_execution_stability(
                        journal, journal_pin, artifact_lease, operation_lease
                    )
                )
                initial_terminal_stable = _safe_call(
                    lambda: _check_observed_stage_stability(
                        initial_journal, initial_journal_pin, verified_initial_intent
                    )
                )
                if (
                    terminal_stable is _SAFE_CALL_FAILURE
                    or initial_terminal_stable is _SAFE_CALL_FAILURE
                ):
                    raise AuthorizationError("terminal_stability")
                execution_receipt = ExecutionReceiptV1(
                    schema_version="rsd.lifecycle-execution-receipt.v1",
                    status="committed",
                    operation_kind=_OBSERVED_OPERATION_KIND,
                    operation_id=context.operation_id,
                    idempotency_key=context.idempotency_key,
                    effect_receipt_sha256=effect_receipt.effect_receipt_sha256,
                    proposal_sha256=context.proposal_sha256,
                    contract_sha256=context.contract_sha256,
                    provider_provenance_sha256=context.provider_provenance_sha256,
                    committed_at=authorized_at,
                )
        finally:
            provider_released = _release_provider_lease(manager)
        assert execution_receipt is not None
        if not provider_released:
            raise AuthorizationError("provider_release")
        return execution_receipt


def _authorize_and_execute_for_test(
    paths: AuthorizationPaths,
    *,
    signer: TrustedEd25519SignerV1,
    provider: ProviderProvenanceAdapter,
    expected_disposal_owner: str,
    expected_approver_identity: str,
    journal: SQLiteAuthorizationJournal,
    initial_journal: SQLiteInitialProvisioningJournal,
    effect: Callable[[VerifiedExecutionContext], EffectReceiptV1],
    replay_authority: ProtocolReplayAuthority,
    replay_policy: ReplayAuthorityPolicyV1,
    _clock: Callable[[], datetime],
    _capability: object,
) -> ExecutionReceiptV1:
    """Test-only clock seam, inaccessible from the exported entry point."""

    if _capability is not _TEST_CLOCK_CAPABILITY:
        raise AuthorizationError("test_clock")
    return _authorize_and_execute_with_clock(
        paths,
        signer=signer,
        provider=provider,
        expected_disposal_owner=expected_disposal_owner,
        expected_approver_identity=expected_approver_identity,
        journal=journal,
        initial_journal=initial_journal,
        effect=effect,
        replay_authority=replay_authority,
        replay_policy=replay_policy,
        clock=_clock,
    )


def authorize_and_execute(
    paths: AuthorizationPaths,
    *,
    signer: TrustedEd25519SignerV1,
    provider: ProviderProvenanceAdapter,
    expected_disposal_owner: str,
    expected_approver_identity: str,
    journal: SQLiteAuthorizationJournal,
    initial_journal: SQLiteInitialProvisioningJournal,
    effect: Callable[[VerifiedExecutionContext], EffectReceiptV1],
    replay_authority: ProtocolReplayAuthority,
    replay_policy: ReplayAuthorityPolicyV1,
) -> ExecutionReceiptV1:
    """Verify, lease, execute once, and commit using the trusted UTC clock."""

    return _authorize_and_execute_with_clock(
        paths,
        signer=signer,
        provider=provider,
        expected_disposal_owner=expected_disposal_owner,
        expected_approver_identity=expected_approver_identity,
        journal=journal,
        initial_journal=initial_journal,
        effect=effect,
        replay_authority=replay_authority,
        replay_policy=replay_policy,
        clock=_system_utc_clock,
    )


def main(argv: Sequence[str] | None = None) -> int:
    """Read-only command; embedding code must inject all trusted boundaries."""

    parser = argparse.ArgumentParser(prog="rsd-lifecycle-authorize")
    commands = parser.add_subparsers(dest="command", required=True)
    command = commands.add_parser(
        "authorize", help="verify authorization through injected boundaries"
    )
    command.add_argument("--root", type=Path, required=True)
    arguments = parser.parse_args(argv)
    del arguments
    print(
        json.dumps({"status": "blocked", "phase": "injected_trust_required"}, separators=(",", ":"))
    )
    return 2


if __name__ == "__main__":  # pragma: no cover
    raise SystemExit(main())
