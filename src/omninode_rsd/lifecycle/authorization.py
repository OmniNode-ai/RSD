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
    AllocationEffectReceiptV2,
    AllocationIntentV2,
    ApprovalEvidenceV1,
    ContainerBootstrapInspectionV1,
    ContainerBootstrapTemplateV1,
    DisposablePreflightError,
    DisposableTransportProfile,
    EphemeralPostgreSQLConnectionPolicyV1,
    ExecutorControlPolicyV1,
    ExecutorInstallationIntentV1,
    ExecutorInstallationPolicyV1,
    ExecutorInstallationReceiptV1,
    ExecutorOperationReceiptV1,
    GovernedBaselineV1,
    MaterializationEffectReceiptV1,
    MaterializationIntentV1,
    ObservedAllocationAttestationV1,
    ObservedRuntimeAttestationV1,
    PostgreSQLControlPolicyV1,
    PostgreSQLLoginTransitionIntentV1,
    PreflightPaths,
    PreflightReceiptV1,
    ProposalV1,
    ProviderDeclarationV1,
    ProviderReferenceV1,
    RegistryVerificationV1,
    RuntimeContractV1,
    SecretCapabilityPolicyV1,
    SecretDeliveryReceiptV1,
    SecretDeliveryRequestV1,
    SecretHandlingPolicyV1,
    StartRuntimeEffectReceiptV2,
    StartRuntimeExecutorReceiptV2,
    StartRuntimeIntentV2,
    TargetAttestationV1,
    _OwnerOnlyReader,
    _strict_canonical_model,
    _UniqueLoader,
    allocation_effect_receipt_sha256,
    allocation_intent_sha256,
    canonical_sha256,
    compile_preflight,
    materialization_effect_receipt_sha256,
    materialization_intent_sha256,
    observed_allocation_attestation_sha256,
    observed_runtime_attestation_sha256,
    start_runtime_effect_receipt_sha256,
    start_runtime_intent_sha256,
    strict_canonical_allocation_intent,
    strict_canonical_materialization_intent,
    strict_canonical_start_runtime_intent,
    validate_observed_allocation_transition,
    validate_observed_runtime_transition,
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
_ALLOCATION_INTENT_ARTIFACT_NAME: Final = "allocation-intent.yaml"
_ALLOCATION_RECEIPT_ARTIFACT_NAME: Final = "allocation-receipt.yaml"
_OBSERVED_ALLOCATION_ATTESTATION_ARTIFACT_NAME: Final = "observed-allocation-attestation.yaml"
_MATERIALIZATION_INTENT_ARTIFACT_NAME: Final = "materialization-intent.yaml"
_MATERIALIZATION_RECEIPT_ARTIFACT_NAME: Final = "materialization-receipt.yaml"
_OBSERVED_RUNTIME_ATTESTATION_ARTIFACT_NAME: Final = "observed-runtime-attestation.yaml"
_EXECUTOR_CONTROL_POLICY_ARTIFACT_NAME: Final = "executor-control-policy.yaml"
_POSTGRES_CONTROL_POLICY_ARTIFACT_NAME: Final = "postgres-control-policy.yaml"
_SECRET_CAPABILITY_POLICY_ARTIFACT_NAME: Final = "secret-capability-policy.yaml"
_SECRET_HANDLING_POLICY_ARTIFACT_NAME: Final = "secret-handling-policy.yaml"
_EXECUTOR_INSTALLATION_POLICY_ARTIFACT_NAME: Final = "executor-installation-policy.yaml"
_EXECUTOR_INSTALLATION_INTENT_ARTIFACT_NAME: Final = "executor-installation-intent.yaml"
_EXECUTOR_INSTALLATION_RECEIPT_ARTIFACT_NAME: Final = "executor-installation-receipt.yaml"
_START_RUNTIME_INTENT_PREFIX: Final = "start-runtime-intent-"
_START_RUNTIME_RECEIPT_PREFIX: Final = "start-runtime-receipt-"
_REPLAY_POLICY_ARTIFACT_NAME: Final = "replay-authority-policy.yaml"
_MARKED_EVIDENCE_NAMES: Final[frozenset[str]] = frozenset(_ARTIFACT_NAMES[2:-1])
_SIGNATURE_DOMAIN: Final = b"omninode-rsd.authorization.ed25519.v3\x00"
_ALLOCATION_INTENT_SIGNATURE_DOMAIN: Final = b"omninode-rsd.allocation-intent.ed25519.v2\x00"
_OBSERVED_ALLOCATION_ATTESTATION_SIGNATURE_DOMAIN: Final = (
    b"omninode-rsd.observed-allocation-attestation.ed25519.v1\x00"
)
_MATERIALIZATION_INTENT_SIGNATURE_DOMAIN: Final = (
    b"omninode-rsd.materialization-intent.ed25519.v1\x00"
)
_OBSERVED_RUNTIME_ATTESTATION_SIGNATURE_DOMAIN: Final = (
    b"omninode-rsd.observed-runtime-attestation.ed25519.v1\x00"
)
_EXECUTOR_CONTROL_POLICY_SIGNATURE_DOMAIN: Final = (
    b"omninode-rsd.executor-control-policy.ed25519.v1\x00"
)
_POSTGRES_CONTROL_POLICY_SIGNATURE_DOMAIN: Final = (
    b"omninode-rsd.postgresql-control-policy.ed25519.v1\x00"
)
_SECRET_CAPABILITY_POLICY_SIGNATURE_DOMAIN: Final = (
    b"omninode-rsd.secret-capability-policy.ed25519.v1\x00"
)
_SECRET_HANDLING_POLICY_SIGNATURE_DOMAIN: Final = (
    b"omninode-rsd.secret-handling-policy.ed25519.v1\x00"
)
_EXECUTOR_INSTALLATION_POLICY_SIGNATURE_DOMAIN: Final = (
    b"omninode-rsd.executor-installation-policy.ed25519.v1\x00"
)
_EXECUTOR_INSTALLATION_INTENT_SIGNATURE_DOMAIN: Final = (
    b"omninode-rsd.executor-installation-intent.ed25519.v1\x00"
)
_EXECUTOR_INSTALLATION_RECEIPT_SIGNATURE_DOMAIN: Final = (
    b"omninode-rsd.executor-installation-receipt.ed25519.v1\x00"
)
_EXECUTOR_OPERATION_RECEIPT_SIGNATURE_DOMAIN: Final = (
    b"omninode-rsd.executor-operation-receipt.ed25519.v1\x00"
)
_START_RUNTIME_INTENT_SIGNATURE_DOMAIN: Final = b"omninode-rsd.start-runtime-intent.ed25519.v2\x00"
_START_RUNTIME_EXECUTOR_RECEIPT_SIGNATURE_DOMAIN: Final = (
    b"omninode-rsd.start-runtime-executor-receipt.ed25519.v2\x00"
)
_ALLOCATION_EFFECT_RECEIPT_DOMAIN: Final = b"omninode-rsd.allocation-effect-receipt.v2\x00"
_MATERIALIZATION_EFFECT_RECEIPT_DOMAIN: Final = (
    b"omninode-rsd.materialization-effect-receipt.v1\x00"
)
_IDEMPOTENCY_DOMAIN: Final = b"omninode-rsd.authorization.effect.v1\x00"
_ALLOCATION_IDEMPOTENCY_DOMAIN: Final = b"omninode-rsd.allocation-effect.v2\x00"
_MATERIALIZATION_IDEMPOTENCY_DOMAIN: Final = b"omninode-rsd.materialization-effect.v1\x00"
_START_RUNTIME_IDEMPOTENCY_DOMAIN: Final = b"omninode-rsd.start-runtime-effect.v2\x00"
_RECONCILIATION_DOMAIN: Final = b"omninode-rsd.authorization.reconciliation.v1\x00"
_JOURNAL_GENESIS_DOMAIN: Final = b"omninode-rsd.authorization.journal-genesis.v1\x00"
_JOURNAL_GENESIS_RECONCILIATION_DOMAIN: Final = (
    b"omninode-rsd.authorization.journal-genesis-reconciliation.v1\x00"
)
_ALLOCATION_JOURNAL_GENESIS_RECONCILIATION_DOMAIN: Final = (
    b"omninode-rsd.allocation-journal-genesis-reconciliation.v1\x00"
)
_REPLAY_TOMBSTONE_DOMAIN: Final = b"omninode-rsd.authorization.replay-tombstone.v1\x00"
_REPLAY_ACCOUNT_DOMAIN: Final = b"omninode-rsd.authorization.replay-account.v1\x00"
_ARTIFACT_LOCK_PREFIX: Final = ".rsd-authorization-root-"
_OPERATION_LEASE_PREFIX: Final = ".rsd-authorization-operation-"
_JOURNAL_IDENTITY_LEASE_PREFIX: Final = ".rsd-authorization-journal-identity-"
_JOURNAL_ANCHOR_PREFIX: Final = ".rsd-authorization-journal-anchor-"
_JOURNAL_GENESIS_MARKER_PREFIX: Final = ".rsd-authorization-journal-genesis-"
_ALLOCATION_JOURNAL_ANCHOR_PREFIX: Final = ".rsd-allocation-journal-anchor-"
_ALLOCATION_JOURNAL_MARKER_PREFIX: Final = ".rsd-allocation-journal-marker-"
_VERIFIED_CAPABILITY: Final = object()
_GENESIS_CAPABILITY: Final = object()
_ALLOCATION_VERIFIED_CAPABILITY: Final = object()
_ALLOCATION_INTENT_CAPABILITY: Final = object()
_MATERIALIZATION_VERIFIED_CAPABILITY: Final = object()
_MATERIALIZATION_INTENT_CAPABILITY: Final = object()
_START_RUNTIME_VERIFIED_CAPABILITY: Final = object()
_JOURNAL_PIN_CAPABILITY: Final = object()
_ALLOCATION_JOURNAL_PIN_CAPABILITY: Final = object()
_SAFE_CALL_FAILURE: Final = object()
_OPERATION_TABLE: Final = "authorization_operation_journal"
_JOURNAL_METADATA_TABLE: Final = "authorization_journal_metadata"
_ALLOCATION_OPERATION_TABLE: Final = "allocation_operation_journal"
_MATERIALIZATION_OPERATION_TABLE: Final = "materialization_operation_journal"
_START_RUNTIME_OPERATION_TABLE: Final = "start_runtime_operation_journal"
_ALLOCATION_JOURNAL_METADATA_TABLE: Final = "allocation_journal_metadata"
_LEGACY_OPERATION_TABLE: Final = "authorization_nonce_journal"
_JOURNAL_SCHEMA_VERSION: Final = "rsd.authorization-journal.v1"
_ALLOCATION_JOURNAL_SCHEMA_VERSION: Final = "rsd.allocation-materialization-start-journal.v4"
_JOURNAL_ANCHOR_SCHEMA_VERSION: Final = "rsd.authorization-journal-anchor.v1"
_JOURNAL_GENESIS_MARKER_SCHEMA_VERSION: Final = "rsd.authorization-journal-genesis-marker.v1"
_JOURNAL_OPERATION_DOMAIN: Final = "rsd.observed-lifecycle-operation.v1"
_OBSERVED_OPERATION_KIND: Final = "observed_lifecycle_v1"
_ALLOCATION_OPERATION_KIND: Final = "allocation_v2"
_MATERIALIZATION_OPERATION_KIND: Final = "materialization_v1"
_START_RUNTIME_OPERATION_KIND: Final = "start_runtime_v2"
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
_ALLOCATION_OPERATION_SCHEMA: Final = f"""
CREATE TABLE IF NOT EXISTS {_ALLOCATION_OPERATION_TABLE} (
    allocation_operation_id TEXT PRIMARY KEY NOT NULL,
    operation_kind TEXT NOT NULL CHECK (operation_kind = '{_ALLOCATION_OPERATION_KIND}'),
    operation_scope TEXT NOT NULL CHECK (operation_scope = 'allocate_isolated_empty_resources_v2'),
    allocation_intent_sha256 TEXT NOT NULL,
    nonce TEXT NOT NULL UNIQUE,
    provider_provenance_sha256 TEXT NOT NULL,
    executor_provenance_sha256 TEXT NOT NULL,
    postgres_control_provenance_sha256 TEXT NOT NULL,
    idempotency_key TEXT NOT NULL,
    state TEXT NOT NULL,
    effect_receipt_sha256 TEXT,
    allocated_resources_sha256 TEXT,
    failure_phase TEXT,
    created_at TEXT NOT NULL,
    updated_at TEXT NOT NULL,
    CHECK (state IN ('claimed', 'in_progress', 'allocated', 'failed_recovery_required'))
) WITHOUT ROWID
"""
_MATERIALIZATION_OPERATION_SCHEMA: Final = f"""
CREATE TABLE IF NOT EXISTS {_MATERIALIZATION_OPERATION_TABLE} (
    materialization_operation_id TEXT PRIMARY KEY NOT NULL,
    operation_kind TEXT NOT NULL CHECK (operation_kind = '{_MATERIALIZATION_OPERATION_KIND}'),
    operation_scope TEXT NOT NULL CHECK (operation_scope = 'materialize_and_start_runtime_v1'),
    allocation_operation_id TEXT NOT NULL UNIQUE,
    materialization_intent_sha256 TEXT NOT NULL,
    allocation_effect_receipt_sha256 TEXT NOT NULL,
    observed_allocation_attestation_sha256 TEXT NOT NULL,
    request_nonce_sha256 TEXT NOT NULL UNIQUE,
    nonce TEXT NOT NULL UNIQUE,
    provider_provenance_sha256 TEXT NOT NULL,
    executor_provenance_sha256 TEXT NOT NULL,
    postgres_login_provenance_sha256 TEXT NOT NULL,
    secret_capability_provenance_sha256 TEXT NOT NULL,
    secret_delivery_provenance_sha256 TEXT NOT NULL,
    idempotency_key TEXT NOT NULL,
    state TEXT NOT NULL,
    effect_receipt_sha256 TEXT,
    failure_phase TEXT,
    created_at TEXT NOT NULL,
    updated_at TEXT NOT NULL,
    CHECK (state IN ('claimed', 'in_progress', 'materialized', 'failed_recovery_required'))
) WITHOUT ROWID
"""
_START_RUNTIME_OPERATION_SCHEMA: Final = f"""
CREATE TABLE IF NOT EXISTS {_START_RUNTIME_OPERATION_TABLE} (
    start_operation_id TEXT PRIMARY KEY NOT NULL,
    operation_kind TEXT NOT NULL CHECK (operation_kind = '{_START_RUNTIME_OPERATION_KIND}'),
    operation_scope TEXT NOT NULL CHECK (operation_scope = 'start_runtime_v2'),
    materialization_operation_id TEXT NOT NULL,
    materialization_intent_sha256 TEXT NOT NULL,
    materialization_effect_receipt_sha256 TEXT NOT NULL,
    observed_runtime_attestation_sha256 TEXT NOT NULL,
    start_runtime_intent_sha256 TEXT NOT NULL,
    request_nonce_sha256 TEXT NOT NULL UNIQUE,
    channel_binding_sha256 TEXT NOT NULL,
    session_binding_sha256 TEXT NOT NULL,
    nonce TEXT NOT NULL UNIQUE,
    provider_provenance_sha256 TEXT NOT NULL,
    executor_provenance_sha256 TEXT NOT NULL,
    secret_capability_provenance_sha256 TEXT NOT NULL,
    remote_session_provenance_sha256 TEXT NOT NULL,
    idempotency_key TEXT NOT NULL,
    state TEXT NOT NULL,
    effect_receipt_sha256 TEXT,
    failure_phase TEXT,
    created_at TEXT NOT NULL,
    updated_at TEXT NOT NULL,
    CHECK (state IN ('claimed', 'in_progress', 'started', 'failed_recovery_required'))
) WITHOUT ROWID
"""
_ALLOCATION_JOURNAL_METADATA_SCHEMA: Final = f"""
CREATE TABLE IF NOT EXISTS {_ALLOCATION_JOURNAL_METADATA_TABLE} (
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

    ALLOCATION = _ALLOCATION_OPERATION_KIND
    MATERIALIZATION = _MATERIALIZATION_OPERATION_KIND
    START_RUNTIME = _START_RUNTIME_OPERATION_KIND
    OBSERVED_LIFECYCLE = _OBSERVED_OPERATION_KIND


class AllocationOperationState(StrEnum):
    """Durable states for a one-time empty-resource creation operation."""

    CLAIMED = "claimed"
    IN_PROGRESS = "in_progress"
    ALLOCATED = "allocated"
    FAILED_RECOVERY_REQUIRED = "failed_recovery_required"


class MaterializationOperationState(StrEnum):
    """Durable states for the one post-allocation runtime materialization."""

    CLAIMED = "claimed"
    IN_PROGRESS = "in_progress"
    MATERIALIZED = "materialized"
    FAILED_RECOVERY_REQUIRED = "failed_recovery_required"


class StartRuntimeOperationState(StrEnum):
    """Durable states for one fresh post-materialization runtime start."""

    CLAIMED = "claimed"
    IN_PROGRESS = "in_progress"
    STARTED = "started"
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
        "allocation_genesis",
        "allocation_operation",
        "materialization_operation",
        "start_runtime_operation",
        "observed_genesis",
        "observed_operation",
    ]
    operation_kind: Literal[
        "allocation_v2", "materialization_v1", "start_runtime_v2", "observed_lifecycle_v1"
    ]
    service: str = Field(pattern=_IDENTIFIER, min_length=1, max_length=128)
    account: str = Field(pattern=_IDENTIFIER, min_length=1, max_length=128)
    journal_genesis_id: str = Field(pattern=_UUID)
    operation_id: str = Field(min_length=1, max_length=256)
    proposal_sha256: str | None = Field(default=None, pattern=_SHA256)
    contract_sha256: str | None = Field(default=None, pattern=_SHA256)
    allocation_intent_sha256: str | None = Field(default=None, pattern=_SHA256)
    materialization_intent_sha256: str | None = Field(default=None, pattern=_SHA256)
    allocation_effect_receipt_sha256: str | None = Field(default=None, pattern=_SHA256)
    materialization_effect_receipt_sha256: str | None = Field(default=None, pattern=_SHA256)
    observed_allocation_attestation_sha256: str | None = Field(default=None, pattern=_SHA256)
    observed_runtime_attestation_sha256: str | None = Field(default=None, pattern=_SHA256)
    start_runtime_intent_sha256: str | None = Field(default=None, pattern=_SHA256)
    request_nonce_sha256: str | None = Field(default=None, pattern=_SHA256)
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
        allocation = self.kind in {"allocation_genesis", "allocation_operation"}
        materialization = self.kind == "materialization_operation"
        start = self.kind == "start_runtime_operation"
        operation = self.kind in {
            "allocation_operation",
            "materialization_operation",
            "start_runtime_operation",
            "observed_operation",
        }
        if (
            observed != (self.operation_kind == _OBSERVED_OPERATION_KIND)
            or allocation != (self.operation_kind == _ALLOCATION_OPERATION_KIND)
            or materialization != (self.operation_kind == _MATERIALIZATION_OPERATION_KIND)
            or start != (self.operation_kind == _START_RUNTIME_OPERATION_KIND)
        ):
            raise ValueError("replay tombstone binding is invalid")
        if observed:
            if (
                type(self.proposal_sha256) is not str
                or type(self.contract_sha256) is not str
                or self.allocation_intent_sha256 is not None
                or self.materialization_intent_sha256 is not None
                or self.allocation_effect_receipt_sha256 is not None
                or self.materialization_effect_receipt_sha256 is not None
                or self.observed_allocation_attestation_sha256 is not None
                or self.observed_runtime_attestation_sha256 is not None
                or self.start_runtime_intent_sha256 is not None
                or self.request_nonce_sha256 is not None
            ):
                raise ValueError("replay tombstone binding is invalid")
        elif (
            (
                allocation
                and (
                    type(self.allocation_intent_sha256) is not str
                    or self.proposal_sha256 is not None
                    or self.contract_sha256 is not None
                    or self.materialization_intent_sha256 is not None
                    or self.allocation_effect_receipt_sha256 is not None
                    or self.materialization_effect_receipt_sha256 is not None
                    or self.observed_allocation_attestation_sha256 is not None
                    or self.observed_runtime_attestation_sha256 is not None
                    or self.start_runtime_intent_sha256 is not None
                    or self.request_nonce_sha256 is not None
                )
            )
            or (
                materialization
                and (
                    type(self.allocation_intent_sha256) is not str
                    or type(self.materialization_intent_sha256) is not str
                    or type(self.allocation_effect_receipt_sha256) is not str
                    or self.materialization_effect_receipt_sha256 is not None
                    or type(self.observed_allocation_attestation_sha256) is not str
                    or self.proposal_sha256 is not None
                    or self.contract_sha256 is not None
                    or self.observed_runtime_attestation_sha256 is not None
                    or self.start_runtime_intent_sha256 is not None
                    or type(self.request_nonce_sha256) is not str
                )
            )
            or (
                start
                and (
                    type(self.proposal_sha256) is not str
                    or type(self.contract_sha256) is not str
                    or type(self.materialization_intent_sha256) is not str
                    or type(self.allocation_effect_receipt_sha256) is not str
                    or type(self.materialization_effect_receipt_sha256) is not str
                    or type(self.observed_allocation_attestation_sha256) is not str
                    or type(self.observed_runtime_attestation_sha256) is not str
                    or type(self.start_runtime_intent_sha256) is not str
                    or type(self.request_nonce_sha256) is not str
                    or self.allocation_intent_sha256 is not None
                )
            )
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
class ExecutorControlProvenance:
    """Value-free identity observed through a future local executor lease."""

    executor_id: str
    endpoint_sha256: str
    host_fingerprint_sha256: str
    control_capability_fingerprint_sha256: str
    engine_fingerprint_sha256: str


class ExecutorControlLease(Protocol):
    """A lease that pins the future local executor through one effect."""

    def inspect(self, policy: ExecutorControlPolicyV1) -> ExecutorControlProvenance | None: ...

    def recheck(self, policy: ExecutorControlPolicyV1) -> ExecutorControlProvenance | None: ...


class ExecutorControlAdapter(Protocol):
    """Injected local-only executor provenance boundary; no Docker client is provided here."""

    def acquire(
        self, policy: ExecutorControlPolicyV1
    ) -> AbstractContextManager[ExecutorControlLease]: ...


class ExecutorControlExpectationV1(_Model):
    """Exact non-secret executor binding exposed to an effect context."""

    executor_id: str = Field(pattern=_IDENTIFIER)
    endpoint_sha256: str = Field(pattern=_SHA256)
    host_fingerprint_sha256: str = Field(pattern=_SHA256)
    control_capability_fingerprint_sha256: str = Field(pattern=_SHA256)
    engine_fingerprint_sha256: str = Field(pattern=_SHA256)


@dataclass(frozen=True, slots=True)
class PostgreSQLControlProvenance:
    """Value-free status of the future PostgreSQL control capability."""

    authority: str
    maintenance_reference_sha256: str
    capability_fingerprint_sha256: str


class PostgreSQLControlLease(Protocol):
    """Future typed capability for empty schema/role/ACL work only."""

    def inspect(self, policy: PostgreSQLControlPolicyV1) -> PostgreSQLControlProvenance | None: ...

    def recheck(self, policy: PostgreSQLControlPolicyV1) -> PostgreSQLControlProvenance | None: ...


class PostgreSQLControlCapability(Protocol):
    """Inject a value-free lease; this package does not open PostgreSQL connections."""

    def acquire(
        self, policy: PostgreSQLControlPolicyV1
    ) -> AbstractContextManager[PostgreSQLControlLease]: ...


@dataclass(frozen=True, slots=True)
class PostgreSQLLoginTransitionProvenance:
    """Value-free identity of one prepared observed-OID login transition."""

    authority: str
    system_identifier: str
    database_oid: int
    owner_role_oid: int
    application_role_oid: int
    prepared_operation_id: str
    application_password_reference_sha256: str
    capability_fingerprint_sha256: str


class PostgreSQLLoginTransitionLease(Protocol):
    """One-shot OID-bound PostgreSQL transition lease with no SQL/DSN surface."""

    def inspect(
        self,
        policy: PostgreSQLControlPolicyV1,
        transition: PostgreSQLLoginTransitionIntentV1,
        connection: EphemeralPostgreSQLConnectionPolicyV1,
    ) -> PostgreSQLLoginTransitionProvenance | None: ...

    def recheck(
        self,
        policy: PostgreSQLControlPolicyV1,
        transition: PostgreSQLLoginTransitionIntentV1,
        connection: EphemeralPostgreSQLConnectionPolicyV1,
    ) -> PostgreSQLLoginTransitionProvenance | None: ...


class PostgreSQLLoginTransitionCapability(Protocol):
    """Acquire only a prepared transition lease; no raw query or URI is accepted."""

    def acquire(
        self,
        policy: PostgreSQLControlPolicyV1,
        transition: PostgreSQLLoginTransitionIntentV1,
        connection: EphemeralPostgreSQLConnectionPolicyV1,
    ) -> AbstractContextManager[PostgreSQLLoginTransitionLease]: ...


class PostgreSQLControlExpectationV1(_Model):
    """Exact bounded PostgreSQL-control provenance visible to allocation effects."""

    authority: str
    maintenance_reference_sha256: str = Field(pattern=_SHA256)
    capability_fingerprint_sha256: str = Field(pattern=_SHA256)


class PostgreSQLLoginTransitionExpectationV1(_Model):
    """Non-secret, exact transition binding exposed to the materialization effect."""

    authority: str
    system_identifier: str = Field(pattern=r"^[0-9]{8,32}$")
    database_oid: int = Field(ge=1)
    owner_role_oid: int = Field(ge=1)
    application_role_oid: int = Field(ge=1)
    prepared_operation_id: str = Field(pattern=_UUID)
    application_password_reference_sha256: str = Field(pattern=_SHA256)
    capability_fingerprint_sha256: str = Field(pattern=_SHA256)


@dataclass(frozen=True, slots=True)
class SecretMaterialProvenance:
    """Value-free identity of an opaque local secret-use capability."""

    provider_identity_sha256: str
    capability_fingerprint_sha256: str


@dataclass(frozen=True, slots=True)
class SecretDeliveryProvenance:
    """Value-free delivery-channel proof; it contains no value or URI."""

    request_nonce_sha256: str
    channel_binding_sha256: str
    session_binding_sha256: str
    capability_fingerprint_sha256: str


class SecretMaterialLease(Protocol):
    """Opaque bounded material-use lease; it never exposes raw secret values or mappings."""

    def inspect(
        self,
        policy: SecretCapabilityPolicyV1,
        handling_policy: SecretHandlingPolicyV1,
    ) -> SecretMaterialProvenance | None: ...

    def recheck(
        self,
        policy: SecretCapabilityPolicyV1,
        handling_policy: SecretHandlingPolicyV1,
    ) -> SecretMaterialProvenance | None: ...

    def inspect_delivery(
        self, request: SecretDeliveryRequestV1
    ) -> SecretDeliveryProvenance | None: ...

    def recheck_delivery(
        self, request: SecretDeliveryRequestV1
    ) -> SecretDeliveryProvenance | None: ...

    def deliver(self, request: SecretDeliveryRequestV1) -> SecretDeliveryReceiptV1 | None: ...


class SecretMaterialCapability(Protocol):
    """Acquire only an operation-scoped secret lease for materialization."""

    def acquire(
        self,
        policy: SecretCapabilityPolicyV1,
        handling_policy: SecretHandlingPolicyV1,
    ) -> AbstractContextManager[SecretMaterialLease]: ...


@dataclass(frozen=True, slots=True)
class RemoteExecutorSessionProvenance:
    """Pinned value-free remote session metadata for a future forced command."""

    executor_id: str
    host_fingerprint_sha256: str
    channel_binding_sha256: str
    session_binding_sha256: str
    attestation_key_fingerprint_sha256: str


class RemoteExecutorSessionLease(Protocol):
    """Opaque forced-command session lease; no Secure Shell client or stream is exposed."""

    def inspect(self, intent: StartRuntimeIntentV2) -> RemoteExecutorSessionProvenance | None: ...

    def recheck(self, intent: StartRuntimeIntentV2) -> RemoteExecutorSessionProvenance | None: ...


class RemoteExecutorSessionCapability(Protocol):
    """Acquire a bounded remote execution session for a single signed start."""

    def acquire(
        self, intent: StartRuntimeIntentV2
    ) -> AbstractContextManager[RemoteExecutorSessionLease]: ...


class _DirectlySignedArtifact(Protocol):
    """Shared signed fields after the caller has canonicalized a concrete model."""

    signer_key_id: str
    signature_base64: str


class _ControlLeaseAcquirer(Protocol):
    """Internal structural type for safely inspected injected control adapters."""

    def acquire(self, *policies: BaseModel) -> object: ...


class SecretMaterialExpectationV1(_Model):
    """Non-secret capability provenance bound to one materialization context."""

    provider_identity_sha256: str = Field(pattern=_SHA256)
    capability_fingerprint_sha256: str = Field(pattern=_SHA256)
    secret_handling_policy_sha256: str = Field(pattern=_SHA256)


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


class AllocationJournalGenesisReconciliationReceiptV1(_Model):
    """Signed resolution of an interrupted allocation-journal genesis.

    A completed reconciliation may only expose a database and anchor that were
    already durably created before the interruption.  It never retries or
    recreates those objects after an external genesis tombstone exists.
    """

    schema_version: Literal["rsd.allocation-journal-genesis-reconciliation.v1"]
    outcome: Literal["provisioning_completed", "provisioning_abandoned"]
    journal_uuid: str = Field(pattern=_UUID)
    journal_path_sha256: str = Field(pattern=_SHA256)
    intent_sha256: str = Field(pattern=_SHA256)
    created_at: str = Field(min_length=20, max_length=40)
    signer_key_id: str = Field(pattern=_IDENTIFIER)
    signature_base64: str = Field(min_length=4, max_length=256)

    @model_validator(mode="after")
    def canonical_fields(self) -> AllocationJournalGenesisReconciliationReceiptV1:
        try:
            created = datetime.fromisoformat(self.created_at.removesuffix("Z") + "+00:00")
        except ValueError:
            raise ValueError("allocation journal reconciliation fields are invalid") from None
        if (
            not self.created_at.endswith("Z")
            or created.tzinfo is None
            or created.utcoffset() is None
            or len(_canonical_base64(self.signature_base64)) != 64
        ):
            raise ValueError("allocation journal reconciliation fields are invalid")
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
class AllocationExecutionContext:
    """Opaque, value-free input for allocation-only creation."""

    operation_kind: Literal["allocation_v2"]
    operation_scope: Literal["allocate_isolated_empty_resources_v2"]
    allocation_operation_id: str
    intent: AllocationIntentV2
    provider_expectations: tuple[ProviderExpectationV1, ...]
    executor_expectation: ExecutorControlExpectationV1
    postgres_control_expectation: PostgreSQLControlExpectationV1
    allocation_intent_sha256: str
    idempotency_key: str
    provider_provenance_sha256: str
    executor_provenance_sha256: str
    postgres_control_provenance_sha256: str


class AllocationExecutor(Protocol):
    """Future typed effect boundary; no Docker or PostgreSQL implementation exists here."""

    def allocate_empty_resources(
        self,
        context: AllocationExecutionContext,
        executor_control: ExecutorControlLease,
        postgres_control: PostgreSQLControlLease,
    ) -> AllocationEffectReceiptV2: ...


@dataclass(frozen=True, slots=True)
class MaterializationExecutionContext:
    """Opaque non-secret input for the post-allocation container creation boundary."""

    operation_kind: Literal["materialization_v1"]
    operation_scope: Literal["materialize_and_start_runtime_v1"]
    materialization_operation_id: str
    intent: MaterializationIntentV1
    allocation_attestation: ObservedAllocationAttestationV1
    allocation_attestation_sha256: str
    provider_expectations: tuple[ProviderExpectationV1, ...]
    executor_expectation: ExecutorControlExpectationV1
    executor_attestation_key_id: str
    executor_attestation_public_key_base64: str
    executor_attestation_public_key_fingerprint_sha256: str
    postgres_login_expectation: PostgreSQLLoginTransitionExpectationV1
    secret_material_expectation: SecretMaterialExpectationV1
    secret_handling_policy_sha256: str
    secret_delivery_request: SecretDeliveryRequestV1
    materialization_intent_sha256: str
    idempotency_key: str
    provider_provenance_sha256: str
    executor_provenance_sha256: str
    postgres_login_provenance_sha256: str
    secret_capability_provenance_sha256: str
    secret_delivery_provenance_sha256: str


class MaterializationExecutor(Protocol):
    """Future local executor that receives an opaque secret lease, never raw values."""

    def materialize_and_start(
        self,
        context: MaterializationExecutionContext,
        executor_control: ExecutorControlLease,
        postgres_login: PostgreSQLLoginTransitionLease,
        secret_material: SecretMaterialLease,
    ) -> MaterializationEffectReceiptV1: ...


@dataclass(frozen=True, slots=True)
class StartRuntimeExecutionContext:
    """Opaque, value-free input for one fresh runtime start or restart.

    The context deliberately exposes only authenticated predecessor evidence,
    requested secret-delivery metadata, and a pinned remote-session identity.
    It has no URI, provider value, stream, artifact path, or journal handle.
    """

    operation_kind: Literal["start_runtime_v2"]
    operation_scope: Literal["start_runtime_v2"]
    start_operation_id: str
    intent: StartRuntimeIntentV2
    materialization_intent: MaterializationIntentV1
    materialization_receipt: MaterializationEffectReceiptV1
    observed_runtime_attestation: ObservedRuntimeAttestationV1
    provider_expectations: tuple[ProviderExpectationV1, ...]
    executor_expectation: ExecutorControlExpectationV1
    executor_attestation_key_id: str
    executor_attestation_public_key_base64: str
    executor_attestation_public_key_fingerprint_sha256: str
    secret_material_expectation: SecretMaterialExpectationV1
    secret_handling_policy_sha256: str
    secret_delivery_request: SecretDeliveryRequestV1
    start_runtime_intent_sha256: str
    idempotency_key: str
    proposal_sha256: str
    contract_sha256: str
    provider_provenance_sha256: str
    executor_provenance_sha256: str
    secret_capability_provenance_sha256: str
    secret_delivery_provenance_sha256: str
    remote_session_provenance_sha256: str


class StartRuntimeExecutor(Protocol):
    """Future forced-command effect boundary for a fresh opaque delivery/start.

    No Secure Shell client, Docker client, provider value, URI, command line, or raw
    process environment is made public through this protocol.
    """

    def start_runtime(
        self,
        context: StartRuntimeExecutionContext,
        remote_session: RemoteExecutorSessionLease,
        secret_material: SecretMaterialLease,
    ) -> StartRuntimeEffectReceiptV2: ...


class AllocationJournalProvisioningReceiptV1(_Model):
    """Audit output for explicit pre-creation journal provisioning."""

    schema_version: Literal["rsd.allocation-journal-provisioning-receipt.v1"]
    status: Literal["provisioned"]
    operation_kind: Literal["allocation_v2"]
    allocation_operation_id: str = Field(pattern=_UUID)
    journal_uuid: str = Field(pattern=_UUID)
    allocation_intent_sha256: str = Field(pattern=_SHA256)
    provisioned_at: str


class AllocationExecutionReceiptV1(_Model):
    """Non-bearer audit result after the bounded allocation effect commits."""

    schema_version: Literal["rsd.allocation-execution-receipt.v2"]
    status: Literal["allocated_isolated_empty_resources"]
    operation_kind: Literal["allocation_v2"]
    operation_scope: Literal["allocate_isolated_empty_resources_v2"]
    allocation_operation_id: str = Field(pattern=_UUID)
    allocation_intent_sha256: str = Field(pattern=_SHA256)
    idempotency_key: str = Field(pattern=_SHA256)
    effect_receipt_sha256: str = Field(pattern=_SHA256)
    allocated_resources_sha256: str = Field(pattern=_SHA256)
    committed_at: str


class MaterializationExecutionReceiptV1(_Model):
    """Non-bearer audit result after final runtime materialization commits once."""

    schema_version: Literal["rsd.materialization-execution-receipt.v1"]
    status: Literal["materialized_and_started_runtime"]
    operation_kind: Literal["materialization_v1"]
    operation_scope: Literal["materialize_and_start_runtime_v1"]
    materialization_operation_id: str = Field(pattern=_UUID)
    materialization_intent_sha256: str = Field(pattern=_SHA256)
    allocation_operation_id: str = Field(pattern=_UUID)
    allocation_effect_receipt_sha256: str = Field(pattern=_SHA256)
    observed_allocation_attestation_sha256: str = Field(pattern=_SHA256)
    idempotency_key: str = Field(pattern=_SHA256)
    effect_receipt_sha256: str = Field(pattern=_SHA256)
    committed_at: str


class StartRuntimeExecutionReceiptV2(_Model):
    """Non-bearer audit result after a fresh start commits exactly once."""

    schema_version: Literal["rsd.start-runtime-execution-receipt.v2"]
    status: Literal["started_runtime"]
    operation_kind: Literal["start_runtime_v2"]
    operation_scope: Literal["start_runtime_v2"]
    start_operation_id: str = Field(pattern=_UUID)
    start_runtime_intent_sha256: str = Field(pattern=_SHA256)
    materialization_operation_id: str = Field(pattern=_UUID)
    materialization_effect_receipt_sha256: str = Field(pattern=_SHA256)
    observed_runtime_attestation_sha256: str = Field(pattern=_SHA256)
    idempotency_key: str = Field(pattern=_SHA256)
    effect_receipt_sha256: str = Field(pattern=_SHA256)
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
    def allocation_intent_name() -> str:
        """Fixed artifact name for the signed pre-creation intent."""

        return _ALLOCATION_INTENT_ARTIFACT_NAME

    @staticmethod
    def allocation_receipt_name() -> str:
        """Fixed artifact name for the resource-only allocation receipt."""

        return _ALLOCATION_RECEIPT_ARTIFACT_NAME

    @staticmethod
    def observed_allocation_attestation_name() -> str:
        """Fixed artifact name for the signed allocation observation."""

        return _OBSERVED_ALLOCATION_ATTESTATION_ARTIFACT_NAME

    @staticmethod
    def materialization_intent_name() -> str:
        return _MATERIALIZATION_INTENT_ARTIFACT_NAME

    @staticmethod
    def materialization_receipt_name() -> str:
        return _MATERIALIZATION_RECEIPT_ARTIFACT_NAME

    @staticmethod
    def observed_runtime_attestation_name() -> str:
        return _OBSERVED_RUNTIME_ATTESTATION_ARTIFACT_NAME

    @staticmethod
    def executor_control_policy_name() -> str:
        return _EXECUTOR_CONTROL_POLICY_ARTIFACT_NAME

    @staticmethod
    def postgres_control_policy_name() -> str:
        return _POSTGRES_CONTROL_POLICY_ARTIFACT_NAME

    @staticmethod
    def secret_capability_policy_name() -> str:
        return _SECRET_CAPABILITY_POLICY_ARTIFACT_NAME

    @staticmethod
    def secret_handling_policy_name() -> str:
        return _SECRET_HANDLING_POLICY_ARTIFACT_NAME

    @staticmethod
    def executor_installation_policy_name() -> str:
        return _EXECUTOR_INSTALLATION_POLICY_ARTIFACT_NAME

    @staticmethod
    def executor_installation_intent_name() -> str:
        return _EXECUTOR_INSTALLATION_INTENT_ARTIFACT_NAME

    @staticmethod
    def executor_installation_receipt_name() -> str:
        return _EXECUTOR_INSTALLATION_RECEIPT_ARTIFACT_NAME

    @staticmethod
    def start_runtime_intent_name(start_operation_id: str) -> str:
        if type(start_operation_id) is not str or re.fullmatch(_UUID, start_operation_id) is None:
            raise AuthorizationError("start_runtime_operation_id")
        return f"{_START_RUNTIME_INTENT_PREFIX}{start_operation_id}.yaml"

    @staticmethod
    def start_runtime_receipt_name(start_operation_id: str) -> str:
        if type(start_operation_id) is not str or re.fullmatch(_UUID, start_operation_id) is None:
            raise AuthorizationError("start_runtime_operation_id")
        return f"{_START_RUNTIME_RECEIPT_PREFIX}{start_operation_id}.yaml"

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
class _AllocationStageArtifacts:
    """Root-bound planned-to-observed material, never returned to callers."""

    intent: AllocationIntentV2
    receipt: AllocationEffectReceiptV2
    attestation: ObservedAllocationAttestationV1


@dataclass(frozen=True, slots=True)
class _MaterializationStageArtifacts:
    """The signed post-allocation chain consumed by materialization only."""

    intent: MaterializationIntentV1
    receipt: MaterializationEffectReceiptV1
    attestation: ObservedRuntimeAttestationV1


@dataclass(frozen=True, slots=True)
class _AllocationControlPolicies:
    """Signed control policy preimages re-opened from the artifact root."""

    executor: ExecutorControlPolicyV1
    postgres: PostgreSQLControlPolicyV1


@dataclass(frozen=True, slots=True)
class _MaterializationControlPolicies:
    """Signed secret-use constraints re-opened before a runtime effect."""

    executor: ExecutorControlPolicyV1
    postgres: PostgreSQLControlPolicyV1
    installation_policy: ExecutorInstallationPolicyV1
    installation_intent: ExecutorInstallationIntentV1
    installation_receipt: ExecutorInstallationReceiptV1
    secret_capability: SecretCapabilityPolicyV1
    handling: SecretHandlingPolicyV1


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
class _VerifiedAllocationIntent:
    """Signature-verified intent admitted only to allocation journal provisioning."""

    intent: AllocationIntentV2
    intent_sha256: str
    capability: object = field(repr=False, compare=False)


@dataclass(frozen=True, slots=True)
class _VerifiedAllocation:
    """Capability-bound local claim for the bounded pre-observation effect."""

    context: AllocationExecutionContext
    nonce: str
    authorized_at: str
    capability: object = field(repr=False, compare=False)


@dataclass(frozen=True, slots=True)
class _VerifiedMaterialization:
    """Capability-bound local claim for one post-allocation runtime effect."""

    context: MaterializationExecutionContext
    nonce: str
    authorized_at: str
    capability: object = field(repr=False, compare=False)


@dataclass(frozen=True, slots=True)
class _VerifiedStartRuntime:
    """Capability-bound local claim for one fresh remote runtime start."""

    context: StartRuntimeExecutionContext
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
        "allocation_genesis",
        "allocation_operation",
        "materialization_operation",
        "start_runtime_operation",
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
    stage = {
        "allocation_genesis": "a",
        "allocation_operation": "a",
        "materialization_operation": "m",
        "start_runtime_operation": "s",
        "observed_genesis": "o",
        "observed_operation": "o",
    }[kind]
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


def _allocation_genesis_tombstone(
    policy: ReplayAuthorityPolicyV1,
    verified: _VerifiedAllocationIntent,
) -> ReplayTombstoneV1:
    if (
        type(verified) is not _VerifiedAllocationIntent
        or verified.capability is not _ALLOCATION_INTENT_CAPABILITY
    ):
        raise AuthorizationError("replay_authority_binding")
    intent = verified.intent
    return ReplayTombstoneV1(
        schema_version="rsd.replay-tombstone.v1",
        kind="allocation_genesis",
        operation_kind=_ALLOCATION_OPERATION_KIND,
        service=policy.service,
        account=_replay_account(
            policy,
            kind="allocation_genesis",
            operation_id=intent.allocation_operation_id,
        ),
        journal_genesis_id=intent.journal_uuid,
        operation_id=intent.allocation_operation_id,
        allocation_intent_sha256=verified.intent_sha256,
    )


def _allocation_operation_tombstone(
    policy: ReplayAuthorityPolicyV1,
    verified: _VerifiedAllocation,
) -> ReplayTombstoneV1:
    if (
        type(verified) is not _VerifiedAllocation
        or verified.capability is not _ALLOCATION_VERIFIED_CAPABILITY
    ):
        raise AuthorizationError("replay_authority_binding")
    context = verified.context
    return ReplayTombstoneV1(
        schema_version="rsd.replay-tombstone.v1",
        kind="allocation_operation",
        operation_kind=_ALLOCATION_OPERATION_KIND,
        service=policy.service,
        account=_replay_account(
            policy,
            kind="allocation_operation",
            operation_id=context.allocation_operation_id,
        ),
        journal_genesis_id=context.intent.journal_uuid,
        operation_id=context.allocation_operation_id,
        allocation_intent_sha256=context.allocation_intent_sha256,
        provider_provenance_sha256=context.provider_provenance_sha256,
        idempotency_key=context.idempotency_key,
    )


def _materialization_operation_tombstone(
    policy: ReplayAuthorityPolicyV1,
    verified: _VerifiedMaterialization,
) -> ReplayTombstoneV1:
    if (
        type(verified) is not _VerifiedMaterialization
        or verified.capability is not _MATERIALIZATION_VERIFIED_CAPABILITY
    ):
        raise AuthorizationError("replay_authority_binding")
    context = verified.context
    return ReplayTombstoneV1(
        schema_version="rsd.replay-tombstone.v1",
        kind="materialization_operation",
        operation_kind=_MATERIALIZATION_OPERATION_KIND,
        service=policy.service,
        account=_replay_account(
            policy,
            kind="materialization_operation",
            operation_id=context.materialization_operation_id,
        ),
        journal_genesis_id=context.intent.journal_uuid,
        operation_id=context.materialization_operation_id,
        allocation_intent_sha256=context.intent.allocation_intent_sha256,
        materialization_intent_sha256=context.materialization_intent_sha256,
        allocation_effect_receipt_sha256=context.intent.allocation_effect_receipt_sha256,
        observed_allocation_attestation_sha256=context.allocation_attestation_sha256,
        request_nonce_sha256=context.secret_delivery_request.request_nonce_sha256,
        provider_provenance_sha256=context.provider_provenance_sha256,
        idempotency_key=context.idempotency_key,
    )


def _start_runtime_operation_tombstone(
    policy: ReplayAuthorityPolicyV1,
    verified: _VerifiedStartRuntime,
) -> ReplayTombstoneV1:
    """Bind an external create-once claim to one fresh signed start request."""

    if (
        type(verified) is not _VerifiedStartRuntime
        or verified.capability is not _START_RUNTIME_VERIFIED_CAPABILITY
    ):
        raise AuthorizationError("replay_authority_binding")
    context = verified.context
    return ReplayTombstoneV1(
        schema_version="rsd.replay-tombstone.v1",
        kind="start_runtime_operation",
        operation_kind=_START_RUNTIME_OPERATION_KIND,
        service=policy.service,
        account=_replay_account(
            policy,
            kind="start_runtime_operation",
            operation_id=context.start_operation_id,
        ),
        journal_genesis_id=context.intent.journal_uuid,
        operation_id=context.start_operation_id,
        proposal_sha256=context.proposal_sha256,
        contract_sha256=context.contract_sha256,
        materialization_intent_sha256=materialization_intent_sha256(context.materialization_intent),
        allocation_effect_receipt_sha256=(
            context.materialization_intent.allocation_effect_receipt_sha256
        ),
        materialization_effect_receipt_sha256=materialization_effect_receipt_sha256(
            context.materialization_receipt
        ),
        observed_allocation_attestation_sha256=(
            context.materialization_intent.observed_allocation_attestation_sha256
        ),
        observed_runtime_attestation_sha256=(context.intent.observed_runtime_attestation_sha256),
        start_runtime_intent_sha256=context.start_runtime_intent_sha256,
        request_nonce_sha256=context.secret_delivery_request.request_nonce_sha256,
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
    if (
        type(result) is ReplayAuthorityClaimResult
        and result.value == ReplayAuthorityClaimResult.CREATED.value
    ):
        return
    if type(result) is ReplayAuthorityClaimResult and result.value in {
        ReplayAuthorityClaimResult.DUPLICATE_SAME.value,
        ReplayAuthorityClaimResult.DUPLICATE_CONFLICT.value,
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
        parsed = DetachedAuthorizationSignatureV1.model_validate(
            _parse_document(raw, phase="signature_artifact")
        )
        return _strict_canonical_model(parsed, DetachedAuthorizationSignatureV1)
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
    receipt = cast(
        JournalGenesisReceiptV1,
        _canonical_artifact_model(
            receipt, JournalGenesisReceiptV1, phase="journal_genesis_signature"
        ),
    )
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
        raise AuthorizationError("allocation_stage_signature") from None


def _allocation_intent_message(intent: AllocationIntentV2) -> bytes:
    if type(intent) is not AllocationIntentV2:
        raise AuthorizationError("allocation_intent_signature")
    return _direct_signature_message(_ALLOCATION_INTENT_SIGNATURE_DOMAIN, intent)


def _observed_allocation_attestation_message(
    attestation: ObservedAllocationAttestationV1,
) -> bytes:
    if type(attestation) is not ObservedAllocationAttestationV1:
        raise AuthorizationError("observed_allocation_signature")
    return _direct_signature_message(_OBSERVED_ALLOCATION_ATTESTATION_SIGNATURE_DOMAIN, attestation)


def _materialization_intent_message(intent: MaterializationIntentV1) -> bytes:
    if type(intent) is not MaterializationIntentV1:
        raise AuthorizationError("materialization_intent_signature")
    return _direct_signature_message(_MATERIALIZATION_INTENT_SIGNATURE_DOMAIN, intent)


def _observed_runtime_attestation_message(attestation: ObservedRuntimeAttestationV1) -> bytes:
    if type(attestation) is not ObservedRuntimeAttestationV1:
        raise AuthorizationError("observed_runtime_signature")
    return _direct_signature_message(_OBSERVED_RUNTIME_ATTESTATION_SIGNATURE_DOMAIN, attestation)


def _executor_control_policy_message(policy: ExecutorControlPolicyV1) -> bytes:
    if type(policy) is not ExecutorControlPolicyV1:
        raise AuthorizationError("executor_control_policy_signature")
    return _direct_signature_message(_EXECUTOR_CONTROL_POLICY_SIGNATURE_DOMAIN, policy)


def _postgres_control_policy_message(policy: PostgreSQLControlPolicyV1) -> bytes:
    if type(policy) is not PostgreSQLControlPolicyV1:
        raise AuthorizationError("postgres_control_policy_signature")
    return _direct_signature_message(_POSTGRES_CONTROL_POLICY_SIGNATURE_DOMAIN, policy)


def _secret_capability_policy_message(policy: SecretCapabilityPolicyV1) -> bytes:
    if type(policy) is not SecretCapabilityPolicyV1:
        raise AuthorizationError("secret_capability_policy_signature")
    return _direct_signature_message(_SECRET_CAPABILITY_POLICY_SIGNATURE_DOMAIN, policy)


def _secret_handling_policy_message(policy: SecretHandlingPolicyV1) -> bytes:
    if type(policy) is not SecretHandlingPolicyV1:
        raise AuthorizationError("secret_handling_policy_signature")
    return _direct_signature_message(_SECRET_HANDLING_POLICY_SIGNATURE_DOMAIN, policy)


def _executor_installation_policy_message(policy: ExecutorInstallationPolicyV1) -> bytes:
    if type(policy) is not ExecutorInstallationPolicyV1:
        raise AuthorizationError("executor_installation_policy_signature")
    return _direct_signature_message(_EXECUTOR_INSTALLATION_POLICY_SIGNATURE_DOMAIN, policy)


def _executor_installation_intent_message(intent: ExecutorInstallationIntentV1) -> bytes:
    if type(intent) is not ExecutorInstallationIntentV1:
        raise AuthorizationError("executor_installation_intent_signature")
    return _direct_signature_message(_EXECUTOR_INSTALLATION_INTENT_SIGNATURE_DOMAIN, intent)


def _executor_installation_receipt_message(receipt: ExecutorInstallationReceiptV1) -> bytes:
    if type(receipt) is not ExecutorInstallationReceiptV1:
        raise AuthorizationError("executor_installation_receipt_signature")
    return _direct_signature_message(_EXECUTOR_INSTALLATION_RECEIPT_SIGNATURE_DOMAIN, receipt)


def _executor_operation_receipt_message(receipt: ExecutorOperationReceiptV1) -> bytes:
    if type(receipt) is not ExecutorOperationReceiptV1:
        raise AuthorizationError("executor_operation_receipt_signature")
    return _direct_signature_message(_EXECUTOR_OPERATION_RECEIPT_SIGNATURE_DOMAIN, receipt)


def _start_runtime_intent_message(intent: StartRuntimeIntentV2) -> bytes:
    if type(intent) is not StartRuntimeIntentV2:
        raise AuthorizationError("start_runtime_intent_signature")
    return _direct_signature_message(_START_RUNTIME_INTENT_SIGNATURE_DOMAIN, intent)


def _start_runtime_executor_receipt_message(receipt: StartRuntimeExecutorReceiptV2) -> bytes:
    if type(receipt) is not StartRuntimeExecutorReceiptV2:
        raise AuthorizationError("start_runtime_executor_receipt_signature")
    return _direct_signature_message(_START_RUNTIME_EXECUTOR_RECEIPT_SIGNATURE_DOMAIN, receipt)


def _verify_direct_signature(
    model: BaseModel,
    *,
    signer: TrustedEd25519SignerV1,
    message: Callable[[BaseModel], bytes],
    phase: str,
) -> None:
    signed = cast(_DirectlySignedArtifact, model)
    if type(signer) is not TrustedEd25519SignerV1 or signed.signer_key_id != signer.key_id:
        raise AuthorizationError(phase)
    try:
        signature = signed.signature_base64
        if type(signature) is not str:
            raise ValueError
        signer.key().verify(_canonical_base64(signature), message(model))
    except (InvalidSignature, ValueError, TypeError, binascii.Error):
        raise AuthorizationError(phase) from None


def _verify_allocation_intent_signature(
    intent: AllocationIntentV2, *, signer: TrustedEd25519SignerV1
) -> None:
    intent = _canonical_allocation_intent(intent)
    if (
        type(intent) is not AllocationIntentV2
        or type(signer) is not TrustedEd25519SignerV1
        or intent.signer_key_id != signer.key_id
    ):
        raise AuthorizationError("allocation_intent_signature")
    try:
        signer.key().verify(
            _canonical_base64(intent.signature_base64), _allocation_intent_message(intent)
        )
    except (InvalidSignature, ValueError, binascii.Error):
        raise AuthorizationError("allocation_intent_signature") from None


def _verify_observed_allocation_attestation_signature(
    attestation: ObservedAllocationAttestationV1,
    *,
    signer: TrustedEd25519SignerV1,
) -> None:
    attestation = cast(
        ObservedAllocationAttestationV1,
        _canonical_artifact_model(
            attestation,
            ObservedAllocationAttestationV1,
            phase="observed_allocation_signature",
        ),
    )
    _verify_direct_signature(
        attestation,
        signer=signer,
        message=lambda model: _observed_allocation_attestation_message(
            cast(ObservedAllocationAttestationV1, model)
        ),
        phase="observed_allocation_signature",
    )


def _verify_materialization_intent_signature(
    intent: MaterializationIntentV1, *, signer: TrustedEd25519SignerV1
) -> None:
    intent = cast(
        MaterializationIntentV1,
        _canonical_artifact_model(
            intent, MaterializationIntentV1, phase="materialization_intent_signature"
        ),
    )
    _verify_direct_signature(
        intent,
        signer=signer,
        message=lambda model: _materialization_intent_message(cast(MaterializationIntentV1, model)),
        phase="materialization_intent_signature",
    )


def _verify_executor_control_policy_signature(
    policy: ExecutorControlPolicyV1, *, signer: TrustedEd25519SignerV1
) -> None:
    policy = cast(
        ExecutorControlPolicyV1,
        _canonical_artifact_model(
            policy, ExecutorControlPolicyV1, phase="executor_control_policy_signature"
        ),
    )
    _verify_direct_signature(
        policy,
        signer=signer,
        message=lambda model: _executor_control_policy_message(
            cast(ExecutorControlPolicyV1, model)
        ),
        phase="executor_control_policy_signature",
    )


def _verify_postgres_control_policy_signature(
    policy: PostgreSQLControlPolicyV1, *, signer: TrustedEd25519SignerV1
) -> None:
    policy = cast(
        PostgreSQLControlPolicyV1,
        _canonical_artifact_model(
            policy, PostgreSQLControlPolicyV1, phase="postgres_control_policy_signature"
        ),
    )
    _verify_direct_signature(
        policy,
        signer=signer,
        message=lambda model: _postgres_control_policy_message(
            cast(PostgreSQLControlPolicyV1, model)
        ),
        phase="postgres_control_policy_signature",
    )


def _verify_secret_capability_policy_signature(
    policy: SecretCapabilityPolicyV1, *, signer: TrustedEd25519SignerV1
) -> None:
    policy = cast(
        SecretCapabilityPolicyV1,
        _canonical_artifact_model(
            policy, SecretCapabilityPolicyV1, phase="secret_capability_policy_signature"
        ),
    )
    _verify_direct_signature(
        policy,
        signer=signer,
        message=lambda model: _secret_capability_policy_message(
            cast(SecretCapabilityPolicyV1, model)
        ),
        phase="secret_capability_policy_signature",
    )


def _verify_secret_handling_policy_signature(
    policy: SecretHandlingPolicyV1, *, signer: TrustedEd25519SignerV1
) -> None:
    policy = cast(
        SecretHandlingPolicyV1,
        _canonical_artifact_model(
            policy, SecretHandlingPolicyV1, phase="secret_handling_policy_signature"
        ),
    )
    _verify_direct_signature(
        policy,
        signer=signer,
        message=lambda model: _secret_handling_policy_message(cast(SecretHandlingPolicyV1, model)),
        phase="secret_handling_policy_signature",
    )


def _verify_executor_installation_policy_signature(
    policy: ExecutorInstallationPolicyV1, *, signer: TrustedEd25519SignerV1
) -> None:
    policy = cast(
        ExecutorInstallationPolicyV1,
        _canonical_artifact_model(
            policy, ExecutorInstallationPolicyV1, phase="executor_installation_policy_signature"
        ),
    )
    _verify_direct_signature(
        policy,
        signer=signer,
        message=lambda model: _executor_installation_policy_message(
            cast(ExecutorInstallationPolicyV1, model)
        ),
        phase="executor_installation_policy_signature",
    )


def _verify_executor_installation_intent_signature(
    intent: ExecutorInstallationIntentV1, *, signer: TrustedEd25519SignerV1
) -> None:
    intent = cast(
        ExecutorInstallationIntentV1,
        _canonical_artifact_model(
            intent, ExecutorInstallationIntentV1, phase="executor_installation_intent_signature"
        ),
    )
    _verify_direct_signature(
        intent,
        signer=signer,
        message=lambda model: _executor_installation_intent_message(
            cast(ExecutorInstallationIntentV1, model)
        ),
        phase="executor_installation_intent_signature",
    )


def _verify_executor_attestation_signature(
    receipt: ExecutorInstallationReceiptV1
    | ExecutorOperationReceiptV1
    | StartRuntimeExecutorReceiptV2,
    *,
    executor: ExecutorControlPolicyV1,
    message: Callable[
        [
            ExecutorInstallationReceiptV1
            | ExecutorOperationReceiptV1
            | StartRuntimeExecutorReceiptV2
        ],
        bytes,
    ],
    phase: str,
) -> None:
    """Verify a receipt against the exact pinned executor attestation key."""

    valid = False
    try:
        if (
            type(executor) is not ExecutorControlPolicyV1
            or type(receipt)
            not in {
                ExecutorInstallationReceiptV1,
                ExecutorOperationReceiptV1,
                StartRuntimeExecutorReceiptV2,
            }
            or receipt.signer_key_id != executor.executor.attestation_key_id
        ):
            raise ValueError
        public_key = _canonical_base64(executor.executor.attestation_public_key_base64)
        if (
            len(public_key) != 32
            or _digest(public_key) != executor.executor.attestation_public_key_fingerprint_sha256
        ):
            raise ValueError
        Ed25519PublicKey.from_public_bytes(public_key).verify(
            _canonical_base64(receipt.signature_base64), message(receipt)
        )
        valid = True
    except (InvalidSignature, ValueError, TypeError, binascii.Error):
        valid = False
    if not valid:
        raise AuthorizationError(phase)


def _verify_start_runtime_intent_signature(
    intent: StartRuntimeIntentV2, *, signer: TrustedEd25519SignerV1
) -> None:
    intent = cast(
        StartRuntimeIntentV2,
        _canonical_artifact_model(
            intent, StartRuntimeIntentV2, phase="start_runtime_intent_signature"
        ),
    )
    _verify_direct_signature(
        intent,
        signer=signer,
        message=lambda model: _start_runtime_intent_message(cast(StartRuntimeIntentV2, model)),
        phase="start_runtime_intent_signature",
    )


def _verify_observed_runtime_attestation_signature(
    attestation: ObservedRuntimeAttestationV1,
    *,
    signer: TrustedEd25519SignerV1,
) -> None:
    attestation = cast(
        ObservedRuntimeAttestationV1,
        _canonical_artifact_model(
            attestation,
            ObservedRuntimeAttestationV1,
            phase="observed_attestation_signature",
        ),
    )
    if (
        type(attestation) is not ObservedRuntimeAttestationV1
        or type(signer) is not TrustedEd25519SignerV1
        or attestation.signer_key_id != signer.key_id
    ):
        raise AuthorizationError("observed_attestation_signature")
    try:
        signer.key().verify(
            _canonical_base64(attestation.signature_base64),
            _observed_runtime_attestation_message(attestation),
        )
    except (InvalidSignature, ValueError, binascii.Error):
        raise AuthorizationError("observed_attestation_signature") from None


def _allocation_intent_artifact_bytes(intent: AllocationIntentV2) -> bytes:
    try:
        return yaml.safe_dump(intent.model_dump(mode="json"), sort_keys=True).encode("utf-8")
    except (TypeError, ValueError, yaml.YAMLError):
        raise AuthorizationError("allocation_intent_artifact") from None


def _allocation_receipt_artifact_bytes(receipt: AllocationEffectReceiptV2) -> bytes:
    try:
        return yaml.safe_dump(receipt.model_dump(mode="json"), sort_keys=True).encode("utf-8")
    except (TypeError, ValueError, yaml.YAMLError):
        raise AuthorizationError("allocation_receipt_artifact") from None


def _signed_model_artifact_bytes(model: BaseModel, *, phase: str) -> bytes:
    """Serialize only a canonical typed, value-free signed artifact."""

    try:
        return yaml.safe_dump(model.model_dump(mode="json"), sort_keys=True).encode("utf-8")
    except (TypeError, ValueError, yaml.YAMLError):
        raise AuthorizationError(phase) from None


def _materialization_intent_artifact_bytes(intent: MaterializationIntentV1) -> bytes:
    return _signed_model_artifact_bytes(intent, phase="materialization_intent_artifact")


def _materialization_receipt_artifact_bytes(receipt: MaterializationEffectReceiptV1) -> bytes:
    return _signed_model_artifact_bytes(receipt, phase="materialization_receipt_artifact")


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
                parsed = _strict_canonical_model(parsed, model_type)
            except (AuthorizationError, ValidationError, ValueError):
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
        proposal = _strict_canonical_model(proposal, ProposalV1)
        final_contract = _strict_canonical_model(final_contract, RuntimeContractV1)
    except (AuthorizationError, ValidationError, ValueError):
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
        receipt = _strict_canonical_model(receipt, JournalGenesisReceiptV1)
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


def _read_allocation_stage_artifacts(
    paths: AuthorizationPaths,
    *,
    signer: TrustedEd25519SignerV1,
    expected_disposal_owner: str,
    expected_approver_identity: str,
    now: datetime,
    reader: _OwnerOnlyReader,
) -> tuple[_AllocationStageArtifacts, dict[str, bytes]]:
    """Read the resource-only allocation hand-off through the locked root fd."""

    names = (
        paths.allocation_intent_name(),
        paths.allocation_receipt_name(),
        paths.observed_allocation_attestation_name(),
    )
    try:
        raw = {name: reader.read(name) for name in names}
        intent = AllocationIntentV2.model_validate(
            _parse_document(raw[paths.allocation_intent_name()], phase="allocation_intent_artifact")
        )
        intent = _canonical_allocation_intent(intent)
        receipt = AllocationEffectReceiptV2.model_validate(
            _parse_document(
                raw[paths.allocation_receipt_name()], phase="allocation_receipt_artifact"
            )
        )
        attestation = ObservedAllocationAttestationV1.model_validate(
            _parse_document(
                raw[paths.observed_allocation_attestation_name()],
                phase="observed_allocation_attestation_artifact",
            )
        )
        receipt = _strict_canonical_model(receipt, AllocationEffectReceiptV2)
        attestation = _strict_canonical_model(attestation, ObservedAllocationAttestationV1)
    except (AuthorizationError, DisposablePreflightError, ValidationError, ValueError):
        raise AuthorizationError("allocation_stage_artifact") from None
    _verify_allocation_intent_signature(intent, signer=signer)
    _verify_observed_allocation_attestation_signature(attestation, signer=signer)
    try:
        created = datetime.fromisoformat(intent.created_at.removesuffix("Z") + "+00:00")
        completed = datetime.fromisoformat(receipt.completed_at.removesuffix("Z") + "+00:00")
        observed = datetime.fromisoformat(attestation.observed_at.removesuffix("Z") + "+00:00")
        retained = datetime.fromisoformat(intent.retention_expires_at.removesuffix("Z") + "+00:00")
    except ValueError:
        raise AuthorizationError("allocation_stage_freshness") from None
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
        raise AuthorizationError("allocation_stage_freshness")
    try:
        validate_observed_allocation_transition(intent, receipt, attestation)
    except ValueError:
        raise AuthorizationError("allocation_stage_transition") from None
    return _AllocationStageArtifacts(intent, receipt, attestation), raw


def _read_materialization_stage_artifacts(
    paths: AuthorizationPaths,
    *,
    signer: TrustedEd25519SignerV1,
    expected_disposal_owner: str,
    expected_approver_identity: str,
    now: datetime,
    reader: _OwnerOnlyReader,
    allocation: _AllocationStageArtifacts,
    proposal: ProposalV1,
    contract: RuntimeContractV1,
) -> tuple[_MaterializationStageArtifacts, dict[str, bytes]]:
    """Read the post-allocation runtime chain only after allocation is verified."""

    names = (
        paths.materialization_intent_name(),
        paths.materialization_receipt_name(),
        paths.observed_runtime_attestation_name(),
    )
    try:
        raw = {name: reader.read(name) for name in names}
        intent = MaterializationIntentV1.model_validate(
            _parse_document(
                raw[paths.materialization_intent_name()], phase="materialization_intent_artifact"
            )
        )
        intent = strict_canonical_materialization_intent(intent)
        receipt = MaterializationEffectReceiptV1.model_validate(
            _parse_document(
                raw[paths.materialization_receipt_name()], phase="materialization_receipt_artifact"
            )
        )
        receipt = _strict_canonical_model(receipt, MaterializationEffectReceiptV1)
        attestation = ObservedRuntimeAttestationV1.model_validate(
            _parse_document(
                raw[paths.observed_runtime_attestation_name()],
                phase="observed_runtime_attestation_artifact",
            )
        )
        attestation = _strict_canonical_model(attestation, ObservedRuntimeAttestationV1)
    except (AuthorizationError, DisposablePreflightError, ValidationError, ValueError):
        raise AuthorizationError("materialization_stage_artifact") from None
    _verify_materialization_intent_signature(intent, signer=signer)
    _verify_observed_runtime_attestation_signature(attestation, signer=signer)
    try:
        created = datetime.fromisoformat(intent.created_at.removesuffix("Z") + "+00:00")
        completed = datetime.fromisoformat(receipt.completed_at.removesuffix("Z") + "+00:00")
        observed = datetime.fromisoformat(attestation.observed_at.removesuffix("Z") + "+00:00")
        retained = datetime.fromisoformat(intent.retention_expires_at.removesuffix("Z") + "+00:00")
    except ValueError:
        raise AuthorizationError("materialization_stage_freshness") from None
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
        raise AuthorizationError("materialization_stage_freshness")
    try:
        validate_observed_runtime_transition(
            allocation.attestation,
            intent,
            receipt,
            attestation,
            proposal,
            contract,
        )
    except ValueError:
        raise AuthorizationError("materialization_stage_transition") from None
    return _MaterializationStageArtifacts(intent, receipt, attestation), raw


def _read_verified_allocation_intent(
    paths: AuthorizationPaths,
    *,
    signer: TrustedEd25519SignerV1,
    expected_disposal_owner: str,
    expected_approver_identity: str,
    now: datetime,
    reader: _OwnerOnlyReader,
) -> tuple[_VerifiedAllocationIntent, bytes]:
    """Read the root-bound signed intent without constructing any journal."""

    try:
        raw = reader.read(paths.allocation_intent_name())
        intent = AllocationIntentV2.model_validate(
            _parse_document(raw, phase="allocation_intent_artifact")
        )
        intent = _canonical_allocation_intent(intent)
    except (AuthorizationError, DisposablePreflightError, ValidationError, ValueError):
        raise AuthorizationError("allocation_intent_artifact") from None
    _verify_allocation_intent_signature(intent, signer=signer)
    try:
        created = datetime.fromisoformat(intent.created_at.removesuffix("Z") + "+00:00")
        retention = datetime.fromisoformat(intent.retention_expires_at.removesuffix("Z") + "+00:00")
    except ValueError:
        raise AuthorizationError("allocation_intent_freshness") from None
    if (
        created.tzinfo is None
        or retention.tzinfo is None
        or created.astimezone(UTC) > now
        or now - created.astimezone(UTC) > _STAGE_ATTESTATION_FRESHNESS
        or retention.astimezone(UTC) <= now
        or intent.disposal_owner != expected_disposal_owner
        or intent.approver_identity != expected_approver_identity
    ):
        raise AuthorizationError("allocation_intent_freshness")
    return (
        _VerifiedAllocationIntent(
            intent=intent,
            intent_sha256=allocation_intent_sha256(intent),
            capability=_ALLOCATION_INTENT_CAPABILITY,
        ),
        raw,
    )


def _read_replay_policy_artifact(
    paths: AuthorizationPaths,
    *,
    signer: TrustedEd25519SignerV1,
    allocation_intent: AllocationIntentV2,
    replay_policy: ReplayAuthorityPolicyV1,
    reader: _OwnerOnlyReader,
) -> tuple[ReplayAuthorityPolicyArtifactV1, bytes]:
    """Verify the root-persisted replay policy before a tombstone is claimed."""

    def read_and_verify() -> tuple[ReplayAuthorityPolicyArtifactV1, bytes]:
        raw = reader.read(paths.replay_policy_name())
        artifact = ReplayAuthorityPolicyArtifactV1.model_validate(
            _parse_document(raw, phase="replay_policy_artifact")
        )
        artifact = _strict_canonical_model(artifact, ReplayAuthorityPolicyArtifactV1)
        verify_replay_authority_policy_artifact(
            artifact,
            signer=signer,
            allocation_intent=allocation_intent,
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


def _read_canonical_signed_model(
    reader: _OwnerOnlyReader,
    *,
    name: str,
    model_type: type[BaseModel],
    phase: str,
) -> tuple[BaseModel, bytes]:
    """Descriptor-relative, no-follow reload for a value-free signed model."""

    try:
        raw = reader.read(name)
        parsed = model_type.model_validate(_parse_document(raw, phase=phase))
        canonical = _strict_canonical_model(parsed, model_type)
    except (AuthorizationError, DisposablePreflightError, ValidationError, ValueError):
        raise AuthorizationError(phase) from None
    return canonical, raw


def _verify_allocation_control_policy_bindings(
    *,
    intent: AllocationIntentV2,
    executor: ExecutorControlPolicyV1,
    postgres: PostgreSQLControlPolicyV1,
    signer: TrustedEd25519SignerV1,
) -> None:
    """Bind allocation-only capabilities to the exact signed resource plan."""

    _verify_executor_control_policy_signature(executor, signer=signer)
    _verify_postgres_control_policy_signature(postgres, signer=signer)
    topology = intent.plan.topology
    database = intent.plan.postgres
    if (
        executor.source_commit != intent.source_commit
        or executor.executor.executor_id != topology.executor.executor_id
        or postgres.source_commit != intent.source_commit
        or postgres.executor_identity_sha256 != canonical_sha256(executor.executor)
        or postgres.authority != database.authority
        or postgres.database_name != database.database_name
        or postgres.schema_name != database.schema_name
        or postgres.owner_role != database.owner_role
        or postgres.application_role != database.application_role
        or postgres.role_names != database.role_names
        or postgres.allocation_role_states != database.allocation_role_states
        or postgres.grants != database.grants
        or database.control_policy_sha256 != canonical_sha256(postgres)
        or intent.evidence.executor_control_policy_sha256 != canonical_sha256(executor)
        or intent.evidence.postgres_control_policy_sha256 != canonical_sha256(postgres)
    ):
        raise AuthorizationError("allocation_control_policy_binding")


def _read_allocation_control_policies(
    paths: AuthorizationPaths,
    *,
    intent: AllocationIntentV2,
    signer: TrustedEd25519SignerV1,
    reader: _OwnerOnlyReader,
) -> tuple[_AllocationControlPolicies, dict[str, bytes]]:
    executor_model, executor_raw = _read_canonical_signed_model(
        reader,
        name=paths.executor_control_policy_name(),
        model_type=ExecutorControlPolicyV1,
        phase="executor_control_policy_artifact",
    )
    postgres_model, postgres_raw = _read_canonical_signed_model(
        reader,
        name=paths.postgres_control_policy_name(),
        model_type=PostgreSQLControlPolicyV1,
        phase="postgres_control_policy_artifact",
    )
    if (
        type(executor_model) is not ExecutorControlPolicyV1
        or type(postgres_model) is not PostgreSQLControlPolicyV1
    ):
        raise AuthorizationError("allocation_control_policy_artifact")
    _verify_allocation_control_policy_bindings(
        intent=intent,
        executor=executor_model,
        postgres=postgres_model,
        signer=signer,
    )
    return (
        _AllocationControlPolicies(executor=executor_model, postgres=postgres_model),
        {
            paths.executor_control_policy_name(): executor_raw,
            paths.postgres_control_policy_name(): postgres_raw,
        },
    )


def _verify_materialization_control_policy_bindings(
    *,
    allocation_intent: AllocationIntentV2,
    intent: MaterializationIntentV1,
    executor: ExecutorControlPolicyV1,
    secret_capability: SecretCapabilityPolicyV1,
    secret_handling: SecretHandlingPolicyV1,
    provider_material_attestation_sha256: str,
    signer: TrustedEd25519SignerV1,
) -> None:
    """Bind the only secret delivery sinks to one observed allocation chain."""

    _verify_executor_control_policy_signature(executor, signer=signer)
    _verify_secret_capability_policy_signature(secret_capability, signer=signer)
    _verify_secret_handling_policy_signature(secret_handling, signer=signer)
    executor_hash = canonical_sha256(executor)
    secret_capability_hash = canonical_sha256(secret_capability)
    secret_handling_hash = canonical_sha256(secret_handling)
    component_image_bindings = (
        (intent.plan.primary_infisical, executor.image_configs[0]),
        (intent.plan.primary_valkey, executor.image_configs[1]),
        (intent.plan.restore_infisical, executor.image_configs[2]),
        (intent.plan.restore_valkey, executor.image_configs[3]),
    )
    if (
        executor.source_commit != allocation_intent.source_commit
        or executor.executor.executor_id != intent.topology.executor.executor_id
        or intent.evidence.executor_control_policy_sha256 != executor_hash
        or intent.evidence.secret_capability_policy_sha256 != secret_capability_hash
        or intent.evidence.secret_handling_policy_sha256 != secret_handling_hash
        or intent.evidence.provider_material_attestation_sha256
        != provider_material_attestation_sha256
        or secret_capability.source_commit != allocation_intent.source_commit
        or secret_capability.executor_identity_sha256 != canonical_sha256(executor.executor)
        or secret_capability.provider_identity_sha256 != provider_material_attestation_sha256
        or secret_capability.secret_handling_policy_sha256 != secret_handling_hash
        or secret_handling.source_commit != allocation_intent.source_commit
        or secret_handling.allocation_intent_sha256 != allocation_intent_sha256(allocation_intent)
        or secret_handling.executor_identity_sha256 != canonical_sha256(executor.executor)
        or secret_handling.provider_identity_sha256 != secret_capability.provider_identity_sha256
        or secret_handling.capability_fingerprint_sha256
        != secret_capability.capability_fingerprint_sha256
        or any(
            component.image != binding.image or component.config_sha256 != binding.config_sha256
            for component, binding in component_image_bindings
        )
    ):
        raise AuthorizationError("materialization_control_policy_binding")


def _verify_executor_installation_chain(
    *,
    allocation_intent: AllocationIntentV2,
    materialization_intent: MaterializationIntentV1,
    executor: ExecutorControlPolicyV1,
    policy: ExecutorInstallationPolicyV1,
    intent: ExecutorInstallationIntentV1,
    receipt: ExecutorInstallationReceiptV1,
    signer: TrustedEd25519SignerV1,
    now: datetime,
) -> None:
    """Require the signed, attested remote-installation predecessor exactly once."""

    _verify_executor_installation_policy_signature(policy, signer=signer)
    _verify_executor_installation_intent_signature(intent, signer=signer)
    _verify_executor_attestation_signature(
        receipt,
        executor=executor,
        message=lambda item: _executor_installation_receipt_message(
            cast(ExecutorInstallationReceiptV1, item)
        ),
        phase="executor_installation_receipt_signature",
    )
    try:
        created = datetime.fromisoformat(policy.created_at.removesuffix("Z") + "+00:00")
        expires = datetime.fromisoformat(policy.expires_at.removesuffix("Z") + "+00:00")
        intent_created = datetime.fromisoformat(intent.created_at.removesuffix("Z") + "+00:00")
        intent_retention = datetime.fromisoformat(
            intent.retention_expires_at.removesuffix("Z") + "+00:00"
        )
        completed = datetime.fromisoformat(receipt.completed_at.removesuffix("Z") + "+00:00")
    except ValueError:
        raise AuthorizationError("executor_installation_freshness") from None
    policy_hash = canonical_sha256(policy)
    installation_intent_hash = canonical_sha256(intent)
    if (
        any(
            value.tzinfo is None
            for value in (created, expires, intent_created, intent_retention, completed)
        )
        or created.astimezone(UTC) > now
        or expires.astimezone(UTC) <= now
        or intent_created.astimezone(UTC) > now
        or intent_retention.astimezone(UTC) <= now
        or completed.astimezone(UTC) > now
        or policy.source_commit != allocation_intent.source_commit
        or policy.allocation_intent_sha256 != allocation_intent_sha256(allocation_intent)
        or policy.disposal_owner != allocation_intent.disposal_owner
        or policy.approver_identity != allocation_intent.approver_identity
        or policy.executor != executor.executor
        or policy.allowed_engine_fingerprint_sha256 != executor.engine_fingerprint_sha256
        or policy.template_bundle_sha256
        != canonical_sha256(materialization_intent.bootstrap_templates)
        or policy.allowed_postgres_identity_sha256
        != canonical_sha256(materialization_intent.postgres_login_transition)
        or executor.installation_policy_sha256 != policy_hash
        or materialization_intent.evidence.executor_installation_policy_sha256 != policy_hash
        or intent.source_commit != allocation_intent.source_commit
        or intent.allocation_intent_sha256 != allocation_intent_sha256(allocation_intent)
        or intent.executor_installation_policy_sha256 != policy_hash
        or intent.disposal_owner != allocation_intent.disposal_owner
        or intent.approver_identity != allocation_intent.approver_identity
        or materialization_intent.executor_installation_intent_sha256 != installation_intent_hash
        or materialization_intent.evidence.executor_installation_intent_sha256
        != installation_intent_hash
        or receipt.installation_operation_id != intent.installation_operation_id
        or receipt.allocation_intent_sha256 != allocation_intent_sha256(allocation_intent)
        or receipt.installation_intent_sha256 != installation_intent_hash
        or receipt.executor_installation_policy_sha256 != policy_hash
        or receipt.executor_id != executor.executor.executor_id
        or receipt.host_fingerprint_sha256 != executor.executor.host_fingerprint_sha256
        or receipt.engine_fingerprint_sha256 != executor.engine_fingerprint_sha256
        or receipt.package_sha256 != policy.package_sha256
        or receipt.executable_sha256 != policy.executable_sha256
        or receipt.template_bundle_sha256 != policy.template_bundle_sha256
        or receipt.systemd_unit_sha256 != policy.systemd_unit_sha256
        or receipt.unix_socket_policy_sha256 != policy.unix_socket_policy_sha256
        or receipt.ssh_policy_sha256 != canonical_sha256(policy.ssh)
        or receipt.attestation_public_key_fingerprint_sha256
        != executor.executor.attestation_public_key_fingerprint_sha256
        or receipt.monotonic_revision != executor.executor.monotonic_revision
        or materialization_intent.executor_installation_receipt_sha256 != canonical_sha256(receipt)
        or materialization_intent.evidence.executor_installation_receipt_sha256
        != canonical_sha256(receipt)
    ):
        raise AuthorizationError("executor_installation_binding")


def _verify_materialization_intent_chain(
    *,
    allocation: _AllocationStageArtifacts,
    intent: MaterializationIntentV1,
    replay_policy: ReplayAuthorityPolicyV1,
    expected_disposal_owner: str,
    expected_approver_identity: str,
    now: datetime,
) -> None:
    """Bind post-allocation authority to one immutable observed resource set."""

    try:
        created = datetime.fromisoformat(intent.created_at.removesuffix("Z") + "+00:00")
        retained = datetime.fromisoformat(intent.retention_expires_at.removesuffix("Z") + "+00:00")
    except ValueError:
        raise AuthorizationError("materialization_intent_freshness") from None
    if (
        created.tzinfo is None
        or retained.tzinfo is None
        or created.astimezone(UTC) > now
        or now - created.astimezone(UTC) > _STAGE_ATTESTATION_FRESHNESS
        or retained.astimezone(UTC) <= now
        or intent.source_commit != allocation.intent.source_commit
        or intent.allocation_operation_id != allocation.intent.allocation_operation_id
        or intent.allocation_intent_sha256 != allocation_intent_sha256(allocation.intent)
        or intent.allocation_effect_receipt_sha256
        != allocation_effect_receipt_sha256(allocation.receipt)
        or intent.observed_allocation_attestation_sha256
        != observed_allocation_attestation_sha256(allocation.attestation)
        or intent.journal_uuid != allocation.intent.journal_uuid
        or intent.replay_policy_sha256 != replay_policy.sha256()
        or intent.topology != allocation.intent.plan.topology
        or intent.provider_references != allocation.intent.provider_references
        or intent.plan.primary_valkey.volume_name
        != allocation.intent.plan.primary_valkey_volume.name
        or intent.plan.restore_valkey.volume_name
        != allocation.intent.plan.restore_valkey_volume.name
        or intent.disposal_owner != expected_disposal_owner
        or intent.approver_identity != expected_approver_identity
    ):
        raise AuthorizationError("materialization_intent_binding")
    postgres = allocation.attestation.allocated_resources.postgres
    transition = intent.postgres_login_transition
    connection = intent.ephemeral_postgres_connection
    if (
        transition.system_identifier != postgres.system_identifier
        or transition.database_name != postgres.database_name
        or transition.database_oid != postgres.database_oid
        or transition.owner_role != postgres.owner_role
        or transition.owner_role_oid != postgres.owner_role_oid
        or transition.application_role != postgres.application_role
        or transition.application_role_oid != postgres.application_role_oid
        or transition.application_password_reference_sha256
        != allocation.intent.provider_references.postgres_application_password.reference_sha256
        or connection.authority != allocation.intent.plan.postgres.authority
        or connection.database_name != postgres.database_name
        or connection.application_role != postgres.application_role
        or connection.application_password_reference_sha256
        != transition.application_password_reference_sha256
        or connection.prepared_operation_id != transition.prepared_operation_id
    ):
        raise AuthorizationError("materialization_postgres_transition_binding")


def _verify_start_runtime_intent_chain(
    *,
    allocation: _AllocationStageArtifacts,
    materialization: _MaterializationStageArtifacts,
    intent: StartRuntimeIntentV2,
    controls: _MaterializationControlPolicies,
    provider_material_attestation_sha256: str,
    replay_policy: ReplayAuthorityPolicyV1,
    expected_disposal_owner: str,
    expected_approver_identity: str,
    now: datetime,
) -> None:
    """Bind a fresh start to every signed, observed predecessor exactly.

    This does not treat a materialization receipt as a bearer grant.  The
    caller's StartRuntime intent must name the committed observed chain, the
    executor installation chain, the opaque delivery policy, and a new nonce.
    """

    try:
        created = datetime.fromisoformat(intent.created_at.removesuffix("Z") + "+00:00")
        retained = datetime.fromisoformat(intent.retention_expires_at.removesuffix("Z") + "+00:00")
    except ValueError:
        raise AuthorizationError("start_runtime_intent_freshness") from None
    materialization_intent = materialization.intent
    materialization_receipt = materialization.receipt
    evidence = intent.evidence
    executor_receipt = materialization_receipt.executor_receipt
    _verify_executor_attestation_signature(
        executor_receipt,
        executor=controls.executor,
        message=lambda item: _executor_operation_receipt_message(
            cast(ExecutorOperationReceiptV1, item)
        ),
        phase="materialization_executor_receipt_signature",
    )
    if (
        created.tzinfo is None
        or retained.tzinfo is None
        or created.astimezone(UTC) > now
        or now - created.astimezone(UTC) > _STAGE_ATTESTATION_FRESHNESS
        or retained.astimezone(UTC) <= now
        or intent.source_commit != allocation.intent.source_commit
        or intent.materialization_operation_id
        != materialization_intent.materialization_operation_id
        or intent.materialization_intent_sha256
        != materialization_intent_sha256(materialization_intent)
        or intent.materialization_effect_receipt_sha256
        != materialization_effect_receipt_sha256(materialization_receipt)
        or intent.observed_runtime_attestation_sha256
        != observed_runtime_attestation_sha256(materialization.attestation)
        or intent.provider_references != allocation.intent.provider_references
        or intent.provider_references != materialization_intent.provider_references
        or intent.journal_uuid != allocation.intent.journal_uuid
        or intent.journal_uuid != materialization_intent.journal_uuid
        or intent.replay_policy_sha256 != replay_policy.sha256()
        or intent.disposal_owner != expected_disposal_owner
        or intent.approver_identity != expected_approver_identity
        or evidence.materialization_intent_sha256
        != materialization_intent_sha256(materialization_intent)
        or evidence.materialization_effect_receipt_sha256
        != materialization_effect_receipt_sha256(materialization_receipt)
        or evidence.observed_runtime_attestation_sha256
        != observed_runtime_attestation_sha256(materialization.attestation)
        or evidence.executor_control_policy_sha256 != canonical_sha256(controls.executor)
        or evidence.executor_installation_policy_sha256
        != canonical_sha256(controls.installation_policy)
        or evidence.executor_installation_intent_sha256
        != canonical_sha256(controls.installation_intent)
        or evidence.executor_installation_receipt_sha256
        != canonical_sha256(controls.installation_receipt)
        or evidence.secret_capability_policy_sha256 != canonical_sha256(controls.secret_capability)
        or evidence.secret_handling_policy_sha256 != canonical_sha256(controls.handling)
        or evidence.provider_material_attestation_sha256 != provider_material_attestation_sha256
        or executor_receipt.operation_scope != materialization_intent.operation_scope
        or executor_receipt.operation_id != materialization_intent.materialization_operation_id
        or executor_receipt.installation_receipt_sha256
        != canonical_sha256(controls.installation_receipt)
        or executor_receipt.executor_id != controls.executor.executor.executor_id
        or executor_receipt.host_fingerprint_sha256
        != controls.executor.executor.host_fingerprint_sha256
        or executor_receipt.engine_fingerprint_sha256 != controls.executor.engine_fingerprint_sha256
        or intent.delivery_request.operation_scope != "start_runtime_v2"
        or intent.delivery_request.operation_id != intent.start_operation_id
        or intent.delivery_request.journal_uuid != intent.journal_uuid
        or intent.delivery_request.provider_material_attestation_sha256
        != provider_material_attestation_sha256
    ):
        raise AuthorizationError("start_runtime_intent_binding")


def _read_materialization_control_policies(
    paths: AuthorizationPaths,
    *,
    allocation_intent: AllocationIntentV2,
    intent: MaterializationIntentV1,
    provider_material_attestation_sha256: str,
    signer: TrustedEd25519SignerV1,
    now: datetime,
    reader: _OwnerOnlyReader,
) -> tuple[_MaterializationControlPolicies, dict[str, bytes]]:
    executor_model, executor_raw = _read_canonical_signed_model(
        reader,
        name=paths.executor_control_policy_name(),
        model_type=ExecutorControlPolicyV1,
        phase="executor_control_policy_artifact",
    )
    capability_model, capability_raw = _read_canonical_signed_model(
        reader,
        name=paths.secret_capability_policy_name(),
        model_type=SecretCapabilityPolicyV1,
        phase="secret_capability_policy_artifact",
    )
    handling_model, handling_raw = _read_canonical_signed_model(
        reader,
        name=paths.secret_handling_policy_name(),
        model_type=SecretHandlingPolicyV1,
        phase="secret_handling_policy_artifact",
    )
    postgres_model, postgres_raw = _read_canonical_signed_model(
        reader,
        name=paths.postgres_control_policy_name(),
        model_type=PostgreSQLControlPolicyV1,
        phase="postgres_control_policy_artifact",
    )
    installation_policy_model, installation_policy_raw = _read_canonical_signed_model(
        reader,
        name=paths.executor_installation_policy_name(),
        model_type=ExecutorInstallationPolicyV1,
        phase="executor_installation_policy_artifact",
    )
    installation_intent_model, installation_intent_raw = _read_canonical_signed_model(
        reader,
        name=paths.executor_installation_intent_name(),
        model_type=ExecutorInstallationIntentV1,
        phase="executor_installation_intent_artifact",
    )
    installation_receipt_model, installation_receipt_raw = _read_canonical_signed_model(
        reader,
        name=paths.executor_installation_receipt_name(),
        model_type=ExecutorInstallationReceiptV1,
        phase="executor_installation_receipt_artifact",
    )
    if (
        type(executor_model) is not ExecutorControlPolicyV1
        or type(postgres_model) is not PostgreSQLControlPolicyV1
        or type(installation_policy_model) is not ExecutorInstallationPolicyV1
        or type(installation_intent_model) is not ExecutorInstallationIntentV1
        or type(installation_receipt_model) is not ExecutorInstallationReceiptV1
        or type(capability_model) is not SecretCapabilityPolicyV1
        or type(handling_model) is not SecretHandlingPolicyV1
    ):
        raise AuthorizationError("materialization_control_policy_artifact")
    _verify_materialization_control_policy_bindings(
        allocation_intent=allocation_intent,
        intent=intent,
        executor=executor_model,
        secret_capability=capability_model,
        secret_handling=handling_model,
        provider_material_attestation_sha256=provider_material_attestation_sha256,
        signer=signer,
    )
    _verify_allocation_control_policy_bindings(
        intent=allocation_intent,
        executor=executor_model,
        postgres=postgres_model,
        signer=signer,
    )
    _verify_executor_installation_chain(
        allocation_intent=allocation_intent,
        materialization_intent=intent,
        executor=executor_model,
        policy=installation_policy_model,
        intent=installation_intent_model,
        receipt=installation_receipt_model,
        signer=signer,
        now=now,
    )
    return (
        _MaterializationControlPolicies(
            executor=executor_model,
            postgres=postgres_model,
            installation_policy=installation_policy_model,
            installation_intent=installation_intent_model,
            installation_receipt=installation_receipt_model,
            secret_capability=capability_model,
            handling=handling_model,
        ),
        {
            paths.executor_control_policy_name(): executor_raw,
            paths.postgres_control_policy_name(): postgres_raw,
            paths.executor_installation_policy_name(): installation_policy_raw,
            paths.executor_installation_intent_name(): installation_intent_raw,
            paths.executor_installation_receipt_name(): installation_receipt_raw,
            paths.secret_capability_policy_name(): capability_raw,
            paths.secret_handling_policy_name(): handling_raw,
        },
    )


def _trusted_provider_fingerprints(
    *,
    signer: TrustedEd25519SignerV1,
    allocation_intent: AllocationIntentV2,
    expected_disposal_owner: str,
    expected_approver_identity: str,
    now: datetime,
    reader: _OwnerOnlyReader,
) -> tuple[dict[str, str], tuple[str, str, str, str, str]]:
    """Load the completed material state from the locked artifact root only.

    Caller models are deliberately not accepted here.  The signer genesis,
    policy, pending manifest, and terminal attestation are all descriptor-
    relative, owner-only files. Their raw hashes become part of the repeated
    authorization snapshot so a replacement cannot survive to an effect.
    """

    def verify() -> tuple[dict[str, str], tuple[str, str, str, str, str]]:
        signer_genesis, signer_hash = _load_verified_signer_genesis_from_reader(
            reader,
            issuer=signer,
            allocation_intent=allocation_intent,
        )
        provider_signer = _ProviderArtifactSigner.from_genesis(signer_genesis)
        _policy, _genesis, attestation, material_hashes = (
            _load_verified_provider_material_bundle_from_reader_at(
                reader,
                signer=provider_signer,
                signer_genesis=signer_genesis,
                issuer=signer,
                allocation_intent=allocation_intent,
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
        or len(result[1]) != 5
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


def _allocation_idempotency_key(
    *,
    allocation_operation_id: str,
    intent_sha256: str,
    provider_sha256: str,
    executor_sha256: str,
    postgres_control_sha256: str,
) -> str:
    material = "\x00".join(
        (
            allocation_operation_id,
            intent_sha256,
            provider_sha256,
            executor_sha256,
            postgres_control_sha256,
        )
    ).encode("ascii")
    return _digest(_ALLOCATION_IDEMPOTENCY_DOMAIN + material)


def _materialization_idempotency_key(
    *,
    materialization_operation_id: str,
    materialization_intent_sha256: str,
    allocation_effect_receipt_sha256: str,
    observed_allocation_attestation_sha256: str,
    provider_sha256: str,
    executor_sha256: str,
    postgres_login_sha256: str,
    secret_capability_sha256: str,
    secret_delivery_sha256: str,
) -> str:
    material = "\x00".join(
        (
            materialization_operation_id,
            materialization_intent_sha256,
            allocation_effect_receipt_sha256,
            observed_allocation_attestation_sha256,
            provider_sha256,
            executor_sha256,
            postgres_login_sha256,
            secret_capability_sha256,
            secret_delivery_sha256,
        )
    ).encode("ascii")
    return _digest(_MATERIALIZATION_IDEMPOTENCY_DOMAIN + material)


def _start_runtime_idempotency_key(
    *,
    start_operation_id: str,
    start_runtime_intent_sha256: str,
    materialization_effect_receipt_sha256: str,
    observed_runtime_attestation_sha256: str,
    provider_sha256: str,
    executor_sha256: str,
    secret_capability_sha256: str,
    secret_delivery_sha256: str,
    remote_session_sha256: str,
) -> str:
    """Derive a non-bearer idempotency key for one signed fresh start."""

    material = "\x00".join(
        (
            start_operation_id,
            start_runtime_intent_sha256,
            materialization_effect_receipt_sha256,
            observed_runtime_attestation_sha256,
            provider_sha256,
            executor_sha256,
            secret_capability_sha256,
            secret_delivery_sha256,
            remote_session_sha256,
        )
    ).encode("ascii")
    return _digest(_START_RUNTIME_IDEMPOTENCY_DOMAIN + material)


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

        receipt = cast(
            JournalGenesisReconciliationReceiptV1,
            _canonical_artifact_model(
                receipt,
                JournalGenesisReconciliationReceiptV1,
                phase="journal_genesis_reconciliation",
            ),
        )
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
                    _system_utc_clock().isoformat(timespec="seconds").replace("+00:00", "Z"),
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

        receipt = cast(
            ReconciliationReceiptV1,
            _canonical_artifact_model(
                receipt,
                ReconciliationReceiptV1,
                phase="reconciliation_signature",
            ),
        )
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
                    _system_utc_clock().isoformat(timespec="seconds").replace("+00:00", "Z"),
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


class AllocationJournalStatus(StrEnum):
    """Read-only state for the separate pre-creation durable journal."""

    ABSENT = "absent"
    CURRENT = "current"
    PROVISIONING_INCOMPLETE = "provisioning_incomplete"
    ABANDONED = "abandoned"
    JOURNAL_MISSING = "journal_missing"
    IDENTITY_MISMATCH = "identity_mismatch"
    UNKNOWN = "unknown"


class _AllocationJournalAnchorV1(_Model):
    schema_version: Literal["rsd.allocation-journal-anchor.v1"]
    journal_uuid: str = Field(pattern=_UUID)
    journal_path_sha256: str = Field(pattern=_SHA256)
    journal_schema_sha256: str = Field(pattern=_SHA256)
    intent_sha256: str = Field(pattern=_SHA256)
    database_dev: int = Field(ge=0)
    database_ino: int = Field(ge=1)
    database_nlink: Literal[1]


class _AllocationJournalMarkerV1(_Model):
    schema_version: Literal["rsd.allocation-journal-marker.v1"]
    state: Literal["pending", "current", "abandoned"]
    journal_uuid: str = Field(pattern=_UUID)
    journal_path_sha256: str = Field(pattern=_SHA256)
    journal_schema_sha256: str = Field(pattern=_SHA256)
    intent_sha256: str = Field(pattern=_SHA256)


@dataclass(frozen=True, slots=True)
class _AllocationJournalIdentity:
    journal_uuid: str
    journal_path_sha256: str
    journal_schema_sha256: str
    intent_sha256: str
    database_details: tuple[int, int, int]
    anchor_details: tuple[int, int, int]


@dataclass(frozen=True, slots=True)
class _AllocationJournalExecutionPin:
    """Exact allocation-journal objects observed before a live creation effect."""

    identity: _AllocationJournalIdentity
    database_details: tuple[int, int, int]
    anchor_details: tuple[int, int, int]
    marker_details: tuple[int, int, int]
    capability: object = field(repr=False, compare=False)


class SQLiteAllocationJournal:
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
            raise AuthorizationError("allocation_journal_path")
        SQLiteAuthorizationJournal._validate_owner_directory(requested.parent)
        try:
            details = os.lstat(requested)
        except FileNotFoundError:
            return
        except OSError:
            raise AuthorizationError("allocation_journal_path") from None
        if stat.S_ISLNK(details.st_mode):
            raise AuthorizationError("allocation_journal_path")

    def _path_sha256(self) -> str:
        return _digest(os.fsencode(str(self._path)))

    def _anchor_path(self) -> Path:
        self._validate_path()
        return self._path.parent / f"{_ALLOCATION_JOURNAL_ANCHOR_PREFIX}{self._path_sha256()}.json"

    def _marker_path(self) -> Path:
        self._validate_path()
        return self._path.parent / f"{_ALLOCATION_JOURNAL_MARKER_PREFIX}{self._path_sha256()}.json"

    @classmethod
    def _operation_schema_sha256(cls) -> str:
        return SQLiteAuthorizationJournal._schema_sha256(_ALLOCATION_OPERATION_SCHEMA)

    @classmethod
    def _materialization_operation_schema_sha256(cls) -> str:
        return SQLiteAuthorizationJournal._schema_sha256(_MATERIALIZATION_OPERATION_SCHEMA)

    @classmethod
    def _start_runtime_operation_schema_sha256(cls) -> str:
        return SQLiteAuthorizationJournal._schema_sha256(_START_RUNTIME_OPERATION_SCHEMA)

    @classmethod
    def _metadata_schema_sha256(cls) -> str:
        return SQLiteAuthorizationJournal._schema_sha256(_ALLOCATION_JOURNAL_METADATA_SCHEMA)

    @classmethod
    def journal_schema_sha256(cls) -> str:
        material = {
            "metadata_schema_sha256": cls._metadata_schema_sha256(),
            "operation_schema_sha256": cls._operation_schema_sha256(),
            "materialization_operation_schema_sha256": (
                cls._materialization_operation_schema_sha256()
            ),
            "start_runtime_operation_schema_sha256": (cls._start_runtime_operation_schema_sha256()),
            "schema_version": _ALLOCATION_JOURNAL_SCHEMA_VERSION,
        }
        return _digest(json.dumps(material, sort_keys=True, separators=(",", ":")).encode())

    def _identity_lease(self) -> _OperationLease:
        self._validate_path()
        return _OperationLease(
            cast(SQLiteAuthorizationJournal, self),
            self._path_sha256(),
            nonblocking=False,
            prefix=f"{_ALLOCATION_JOURNAL_MARKER_PREFIX}lease-",
        )

    def _operation_lease(self, operation_id: str, *, nonblocking: bool = False) -> _OperationLease:
        if type(operation_id) is not str or not operation_id:
            raise AuthorizationError("allocation_operation_id")
        return _OperationLease(
            cast(SQLiteAuthorizationJournal, self),
            operation_id,
            nonblocking=nonblocking,
            prefix=f"{_ALLOCATION_JOURNAL_MARKER_PREFIX}operation-",
        )

    def _materialization_operation_lease(
        self, operation_id: str, *, nonblocking: bool = False
    ) -> _OperationLease:
        if type(operation_id) is not str or not operation_id:
            raise AuthorizationError("materialization_operation_id")
        return _OperationLease(
            cast(SQLiteAuthorizationJournal, self),
            operation_id,
            nonblocking=nonblocking,
            prefix=f"{_ALLOCATION_JOURNAL_MARKER_PREFIX}materialization-",
        )

    def _start_runtime_operation_lease(
        self, operation_id: str, *, nonblocking: bool = False
    ) -> _OperationLease:
        if type(operation_id) is not str or not operation_id:
            raise AuthorizationError("start_runtime_operation_id")
        return _OperationLease(
            cast(SQLiteAuthorizationJournal, self),
            operation_id,
            nonblocking=nonblocking,
            prefix=f"{_ALLOCATION_JOURNAL_MARKER_PREFIX}start-runtime-",
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
            raise AuthorizationError("allocation_journal_durability") from None
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
        SQLiteAllocationJournal._file_details(path, phase)
        try:
            raw = path.read_bytes()
            return model.model_validate(_parse_document(raw, phase=phase))
        except (AuthorizationError, OSError, ValidationError, ValueError):
            raise AuthorizationError(phase) from None

    def _read_marker(self) -> _AllocationJournalMarkerV1:
        model = self._read_model(
            self._marker_path(), _AllocationJournalMarkerV1, phase="allocation_journal_marker"
        )
        if type(model) is not _AllocationJournalMarkerV1:
            raise AuthorizationError("allocation_journal_marker")
        return model

    def _read_anchor(self) -> _AllocationJournalAnchorV1:
        model = self._read_model(
            self._anchor_path(), _AllocationJournalAnchorV1, phase="allocation_journal_anchor"
        )
        if type(model) is not _AllocationJournalAnchorV1:
            raise AuthorizationError("allocation_journal_anchor")
        return model

    def _write_marker(self, marker: _AllocationJournalMarkerV1) -> tuple[int, int, int]:
        details = self._write_exclusive(
            self._marker_path(),
            self._model_bytes(marker, phase="allocation_journal_marker"),
            phase="allocation_journal_marker",
        )
        self._fsync_parent(self._marker_path())
        return details

    def _write_anchor(self, anchor: _AllocationJournalAnchorV1) -> tuple[int, int, int]:
        details = self._write_exclusive(
            self._anchor_path(),
            self._model_bytes(anchor, phase="allocation_journal_anchor"),
            phase="allocation_journal_anchor",
        )
        self._fsync_parent(self._anchor_path())
        return details

    def _set_marker_state(
        self, marker: _AllocationJournalMarkerV1, state: Literal["current", "abandoned"]
    ) -> None:
        current = marker.model_copy(update={"state": state})
        self._rewrite_current(
            self._marker_path(),
            self._model_bytes(current, phase="allocation_journal_marker"),
            phase="allocation_journal_marker",
        )
        self._fsync_parent(self._marker_path())

    def _set_marker_current(self, marker: _AllocationJournalMarkerV1) -> None:
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
                os.fstat(descriptor), "allocation_journal_path"
            )
            os.fsync(descriptor)
            self._fsync_parent(self._path)
            return details
        except AuthorizationError:
            raise
        except FileExistsError:
            raise AuthorizationError("allocation_journal_replayed") from None
        except OSError:
            raise AuthorizationError("allocation_journal_path") from None
        finally:
            if descriptor is not None:
                with suppress(OSError):
                    os.close(descriptor)

    def _validate_companions(self) -> None:
        for suffix in ("-journal", "-wal", "-shm"):
            if self._file_details_or_none(
                Path(f"{self._path}{suffix}"), "allocation_journal_companion"
            ):
                raise AuthorizationError("allocation_journal_companion")

    @staticmethod
    def _normalized_schema(schema: str) -> str:
        return re.sub(r"\s+", "", schema.replace("IF NOT EXISTS ", "").lower())

    @classmethod
    def _validate_schema(cls, connection: sqlite3.Connection) -> None:
        SQLiteAuthorizationJournal._reject_executable_schema_objects(connection)
        names = SQLiteAuthorizationJournal._table_names(connection)
        if names != {
            _ALLOCATION_OPERATION_TABLE,
            _MATERIALIZATION_OPERATION_TABLE,
            _START_RUNTIME_OPERATION_TABLE,
            _ALLOCATION_JOURNAL_METADATA_TABLE,
        }:
            raise AuthorizationError("allocation_journal_schema")
        expected_tables = (
            (_ALLOCATION_OPERATION_TABLE, _ALLOCATION_OPERATION_SCHEMA),
            (_MATERIALIZATION_OPERATION_TABLE, _MATERIALIZATION_OPERATION_SCHEMA),
            (_START_RUNTIME_OPERATION_TABLE, _START_RUNTIME_OPERATION_SCHEMA),
            (_ALLOCATION_JOURNAL_METADATA_TABLE, _ALLOCATION_JOURNAL_METADATA_SCHEMA),
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
                raise AuthorizationError("allocation_journal_schema")

    def _metadata_identity(
        self,
        connection: sqlite3.Connection,
        *,
        database_details: tuple[int, int, int],
        anchor_details: tuple[int, int, int],
    ) -> _AllocationJournalIdentity:
        self._validate_schema(connection)
        rows = connection.execute(
            f"""
            SELECT journal_uuid, journal_path_sha256, journal_schema_sha256, intent_sha256,
                   anchor_dev, anchor_ino, anchor_nlink, schema_version
            FROM {_ALLOCATION_JOURNAL_METADATA_TABLE}
            """
        ).fetchall()
        if len(rows) != 1:
            raise AuthorizationError("allocation_journal_identity")
        row = rows[0]
        if (
            len(row) != 8
            or any(type(value) is not str for value in row[:4])
            or any(type(value) is not int for value in row[4:7])
            or row[7] != _ALLOCATION_JOURNAL_SCHEMA_VERSION
            or row[4:7] != anchor_details
        ):
            raise AuthorizationError("allocation_journal_identity")
        return _AllocationJournalIdentity(
            journal_uuid=cast(str, row[0]),
            journal_path_sha256=cast(str, row[1]),
            journal_schema_sha256=cast(str, row[2]),
            intent_sha256=cast(str, row[3]),
            database_details=database_details,
            anchor_details=anchor_details,
        )

    def _established_identity(self) -> _AllocationJournalIdentity:
        self._validate_path()
        with self._identity_lease() as lease:
            lease.assert_stable()
            database_details = self._file_details_or_none(self._path, "allocation_journal_path")
            anchor_details = self._file_details_or_none(
                self._anchor_path(), "allocation_journal_anchor"
            )
            marker_details = self._file_details_or_none(
                self._marker_path(), "allocation_journal_marker"
            )
            if marker_details is None:
                if database_details is None and anchor_details is None:
                    raise AuthorizationError("allocation_journal_absent")
                raise AuthorizationError("allocation_journal_marker")
            marker = self._read_marker()
            if marker.state != "current":
                raise AuthorizationError("allocation_incomplete")
            if database_details is None or anchor_details is None:
                raise AuthorizationError("allocation_journal_missing")
            self._validate_companions()
            try:
                connection = sqlite3.connect(
                    f"{self._path.as_uri()}?mode=ro", uri=True, isolation_level=None, timeout=5.0
                )
            except sqlite3.Error:
                raise AuthorizationError("allocation_journal_open") from None
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
                    raise AuthorizationError("allocation_journal_identity")
                lease.assert_stable()
                return identity
            finally:
                connection.close()

    def _pin_execution_identity(self) -> _AllocationJournalExecutionPin:
        """Capture the local identity that must survive one allocation effect."""

        identity = self._established_identity()
        database_details = self._file_details(self._path, "allocation_journal_identity_pinned")
        anchor_details = self._file_details(
            self._anchor_path(), "allocation_journal_identity_pinned"
        )
        marker_details = self._file_details(
            self._marker_path(), "allocation_journal_identity_pinned"
        )
        if (
            database_details != identity.database_details
            or anchor_details != identity.anchor_details
            or self._established_identity() != identity
            or self._file_details(self._path, "allocation_journal_identity_pinned")
            != database_details
            or self._file_details(self._anchor_path(), "allocation_journal_identity_pinned")
            != anchor_details
            or self._file_details(self._marker_path(), "allocation_journal_identity_pinned")
            != marker_details
        ):
            raise AuthorizationError("allocation_journal_identity_pinned")
        return _AllocationJournalExecutionPin(
            identity=identity,
            database_details=database_details,
            anchor_details=anchor_details,
            marker_details=marker_details,
            capability=_ALLOCATION_JOURNAL_PIN_CAPABILITY,
        )

    def _assert_pinned_execution_identity(self, pin: _AllocationJournalExecutionPin) -> None:
        """Reject database, anchor, or marker replacement after first snapshot."""

        if (
            type(pin) is not _AllocationJournalExecutionPin
            or pin.capability is not _ALLOCATION_JOURNAL_PIN_CAPABILITY
        ):
            raise AuthorizationError("allocation_journal_identity_pinned")
        try:
            identity = self._established_identity()
            database_details = self._file_details(self._path, "allocation_journal_identity_pinned")
            anchor_details = self._file_details(
                self._anchor_path(), "allocation_journal_identity_pinned"
            )
            marker_details = self._file_details(
                self._marker_path(), "allocation_journal_identity_pinned"
            )
        except AuthorizationError:
            raise AuthorizationError("allocation_journal_identity_pinned") from None
        if (
            identity != pin.identity
            or database_details != pin.database_details
            or anchor_details != pin.anchor_details
            or marker_details != pin.marker_details
        ):
            raise AuthorizationError("allocation_journal_identity_pinned")

    def migration_status(self) -> AllocationJournalStatus:
        """Classify local state without creating, rotating, or repairing it."""

        self._validate_path()
        database_details = self._file_details_or_none(self._path, "allocation_journal_path")
        anchor_details = self._file_details_or_none(
            self._anchor_path(), "allocation_journal_anchor"
        )
        marker_details = self._file_details_or_none(
            self._marker_path(), "allocation_journal_marker"
        )
        if database_details is None and anchor_details is None and marker_details is None:
            return AllocationJournalStatus.ABSENT
        if marker_details is not None:
            try:
                marker = self._read_marker()
            except AuthorizationError:
                return AllocationJournalStatus.IDENTITY_MISMATCH
            if marker.state != "current":
                if marker.state == "abandoned":
                    return AllocationJournalStatus.ABANDONED
                return AllocationJournalStatus.PROVISIONING_INCOMPLETE
        if database_details is None or anchor_details is None or marker_details is None:
            return AllocationJournalStatus.JOURNAL_MISSING
        try:
            self._established_identity()
        except AuthorizationError:
            return AllocationJournalStatus.IDENTITY_MISMATCH
        return AllocationJournalStatus.CURRENT

    @staticmethod
    def _require_verified_intent(verified: _VerifiedAllocationIntent) -> None:
        if (
            type(verified) is not _VerifiedAllocationIntent
            or verified.capability is not _ALLOCATION_INTENT_CAPABILITY
        ):
            raise AuthorizationError("allocation_journal")

    def _begin_verified_intent(self, verified: _VerifiedAllocationIntent) -> None:
        """Persist a pending local marker before the external genesis claim."""

        self._require_verified_intent(verified)
        intent = verified.intent
        with self._identity_lease() as lease:
            lease.assert_stable()
            status = self.migration_status()
            if (
                type(status) is not AllocationJournalStatus
                or status.value != AllocationJournalStatus.ABSENT.value
            ):
                raise AuthorizationError("allocation_journal_replayed")
            marker = _AllocationJournalMarkerV1(
                schema_version="rsd.allocation-journal-marker.v1",
                state="pending",
                journal_uuid=intent.journal_uuid,
                journal_path_sha256=intent.journal_path_sha256,
                journal_schema_sha256=intent.journal_schema_sha256,
                intent_sha256=verified.intent_sha256,
            )
            self._write_marker(marker)
            lease.assert_stable()

    def _complete_verified_intent(self, verified: _VerifiedAllocationIntent) -> None:
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
                raise AuthorizationError("allocation_incomplete")
            if (
                self._file_details_or_none(self._path, "allocation_journal_path") is not None
                or self._file_details_or_none(self._anchor_path(), "allocation_journal_anchor")
                is not None
            ):
                raise AuthorizationError("allocation_incomplete")
            database_details = self._create_database()
            try:
                connection = sqlite3.connect(
                    f"{self._path.as_uri()}?mode=rw", uri=True, isolation_level=None, timeout=5.0
                )
            except sqlite3.Error:
                raise AuthorizationError("allocation_journal_open") from None
            try:
                connection.execute("PRAGMA trusted_schema = OFF")
                if connection.execute("PRAGMA journal_mode = DELETE").fetchone() != ("delete",):
                    raise AuthorizationError("allocation_journal_durability")
                connection.execute("PRAGMA synchronous = FULL")
                connection.execute("BEGIN IMMEDIATE")
                connection.execute(_ALLOCATION_OPERATION_SCHEMA)
                connection.execute(_MATERIALIZATION_OPERATION_SCHEMA)
                connection.execute(_START_RUNTIME_OPERATION_SCHEMA)
                connection.execute(_ALLOCATION_JOURNAL_METADATA_SCHEMA)
                connection.execute("COMMIT")
                anchor = _AllocationJournalAnchorV1(
                    schema_version="rsd.allocation-journal-anchor.v1",
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
                    INSERT INTO {_ALLOCATION_JOURNAL_METADATA_TABLE} (
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
                        _ALLOCATION_JOURNAL_SCHEMA_VERSION,
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
                raise AuthorizationError("allocation_journal_transaction") from None
            finally:
                connection.close()

    def reconcile_genesis(
        self, receipt: AllocationJournalGenesisReconciliationReceiptV1
    ) -> AllocationJournalStatus:
        """Resolve a pending genesis without recreating any local object.

        Completion is permitted only after the database and anchor already
        exist and validate against the pending marker.  Earlier crash windows
        can only be explicitly abandoned, preserving the external tombstone.
        """

        receipt = cast(
            AllocationJournalGenesisReconciliationReceiptV1,
            _canonical_artifact_model(
                receipt,
                AllocationJournalGenesisReconciliationReceiptV1,
                phase="allocation_journal_reconciliation",
            ),
        )
        with self._identity_lease() as lease:
            lease.assert_stable()
            marker = self._read_marker()
            if (
                marker.state != "pending"
                or marker.journal_uuid != receipt.journal_uuid
                or marker.journal_path_sha256 != receipt.journal_path_sha256
                or marker.intent_sha256 != receipt.intent_sha256
            ):
                raise AuthorizationError("allocation_journal_reconciliation")
            if receipt.outcome == "provisioning_abandoned":
                self._set_marker_state(marker, "abandoned")
                lease.assert_stable()
                return AllocationJournalStatus.ABANDONED

            database_details = self._file_details_or_none(
                self._path, "allocation_journal_reconciliation"
            )
            anchor_details = self._file_details_or_none(
                self._anchor_path(), "allocation_journal_reconciliation"
            )
            if database_details is None or anchor_details is None:
                raise AuthorizationError("allocation_journal_reconciliation")
            self._validate_companions()
            try:
                connection = sqlite3.connect(
                    f"{self._path.as_uri()}?mode=ro", uri=True, isolation_level=None, timeout=5.0
                )
            except sqlite3.Error:
                raise AuthorizationError("allocation_journal_reconciliation") from None
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
                    raise AuthorizationError("allocation_journal_reconciliation")
            except AuthorizationError:
                raise
            except sqlite3.Error:
                raise AuthorizationError("allocation_journal_reconciliation") from None
            finally:
                connection.close()
            self._set_marker_current(marker)
            lease.assert_stable()
        return AllocationJournalStatus.CURRENT

    def assert_intent(self, verified: _VerifiedAllocationIntent) -> None:
        self._require_verified_intent(verified)
        identity = self._established_identity()
        intent = verified.intent
        if (
            identity.journal_uuid != intent.journal_uuid
            or identity.journal_path_sha256 != intent.journal_path_sha256
            or identity.journal_schema_sha256 != intent.journal_schema_sha256
            or identity.intent_sha256 != verified.intent_sha256
        ):
            raise AuthorizationError("allocation_journal_intent_mismatch")

    def _connect(self) -> tuple[sqlite3.Connection, _AllocationJournalIdentity]:
        identity = self._established_identity()
        self._validate_companions()
        try:
            connection = sqlite3.connect(
                f"{self._path.as_uri()}?mode=rw", uri=True, isolation_level=None, timeout=5.0
            )
        except sqlite3.Error:
            raise AuthorizationError("allocation_journal_open") from None
        try:
            connection.execute("PRAGMA trusted_schema = OFF")
            if connection.execute("PRAGMA journal_mode = DELETE").fetchone() != ("delete",):
                raise AuthorizationError("allocation_journal_durability")
            connection.execute("PRAGMA synchronous = FULL")
            return connection, identity
        except AuthorizationError:
            connection.close()
            raise
        except sqlite3.Error:
            connection.close()
            raise AuthorizationError("allocation_journal_open") from None

    def _transaction(self, action: Callable[[sqlite3.Connection], None]) -> None:
        connection, identity = self._connect()
        try:
            connection.execute("BEGIN IMMEDIATE")
            if self._established_identity() != identity:
                raise AuthorizationError("allocation_journal_identity")
            action(connection)
            connection.execute("COMMIT")
            if self._established_identity() != identity:
                raise AuthorizationError("allocation_journal_identity")
        except AuthorizationError:
            with suppress(sqlite3.Error):
                connection.execute("ROLLBACK")
            raise
        except sqlite3.Error:
            with suppress(sqlite3.Error):
                connection.execute("ROLLBACK")
            raise AuthorizationError("allocation_journal_transaction") from None
        finally:
            connection.close()

    @staticmethod
    def _require_verified_operation(verified: _VerifiedAllocation) -> None:
        if (
            type(verified) is not _VerifiedAllocation
            or verified.capability is not _ALLOCATION_VERIFIED_CAPABILITY
        ):
            raise AuthorizationError("allocation_journal")

    def _claim_verified(self, verified: _VerifiedAllocation) -> None:
        self._require_verified_operation(verified)
        context = verified.context

        def claim(connection: sqlite3.Connection) -> None:
            existing = connection.execute(
                f"SELECT 1 FROM {_ALLOCATION_OPERATION_TABLE} WHERE allocation_operation_id = ?",
                (context.allocation_operation_id,),
            ).fetchone()
            nonce = connection.execute(
                f"SELECT 1 FROM {_ALLOCATION_OPERATION_TABLE} WHERE nonce = ?", (verified.nonce,)
            ).fetchone()
            if existing is not None:
                raise AuthorizationError("allocation_operation_replayed")
            if nonce is not None:
                raise AuthorizationError("initial_nonce_replayed")
            connection.execute(
                f"""
                INSERT INTO {_ALLOCATION_OPERATION_TABLE} (
                    allocation_operation_id, operation_kind, operation_scope,
                    allocation_intent_sha256,
                    nonce,
                    provider_provenance_sha256, executor_provenance_sha256,
                    postgres_control_provenance_sha256, idempotency_key, state,
                    effect_receipt_sha256,
                    allocated_resources_sha256, failure_phase, created_at, updated_at
                ) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, NULL, NULL, NULL, ?, ?)
                """,
                (
                    context.allocation_operation_id,
                    context.operation_kind,
                    context.operation_scope,
                    context.allocation_intent_sha256,
                    verified.nonce,
                    context.provider_provenance_sha256,
                    context.executor_provenance_sha256,
                    context.postgres_control_provenance_sha256,
                    context.idempotency_key,
                    AllocationOperationState.CLAIMED.value,
                    verified.authorized_at,
                    verified.authorized_at,
                ),
            )

        self._transaction(claim)

    def _begin_effect(self, verified: _VerifiedAllocation) -> None:
        self._require_verified_operation(verified)
        context = verified.context

        def begin(connection: sqlite3.Connection) -> None:
            result = connection.execute(
                f"""
                UPDATE {_ALLOCATION_OPERATION_TABLE}
                SET state = ?, updated_at = ?
                WHERE allocation_operation_id = ? AND allocation_intent_sha256 = ? AND nonce = ?
                  AND idempotency_key = ? AND state = ?
                """,
                (
                    AllocationOperationState.IN_PROGRESS.value,
                    verified.authorized_at,
                    context.allocation_operation_id,
                    context.allocation_intent_sha256,
                    verified.nonce,
                    context.idempotency_key,
                    AllocationOperationState.CLAIMED.value,
                ),
            )
            if result.rowcount != 1:
                raise AuthorizationError("allocation_operation_state")

        self._transaction(begin)

    def _commit_effect(
        self, verified: _VerifiedAllocation, receipt: AllocationEffectReceiptV2
    ) -> None:
        self._require_verified_operation(verified)
        context = verified.context
        resources_sha256 = _digest(
            _ALLOCATION_EFFECT_RECEIPT_DOMAIN
            + json.dumps(
                receipt.allocated_resources.model_dump(mode="json"),
                sort_keys=True,
                separators=(",", ":"),
            ).encode()
        )

        def commit(connection: sqlite3.Connection) -> None:
            result = connection.execute(
                f"""
                UPDATE {_ALLOCATION_OPERATION_TABLE}
                SET state = ?, effect_receipt_sha256 = ?, allocated_resources_sha256 = ?,
                    failure_phase = NULL, updated_at = ?
                WHERE allocation_operation_id = ? AND allocation_intent_sha256 = ? AND nonce = ?
                  AND idempotency_key = ? AND state = ?
                """,
                (
                    AllocationOperationState.ALLOCATED.value,
                    allocation_effect_receipt_sha256(receipt),
                    resources_sha256,
                    verified.authorized_at,
                    context.allocation_operation_id,
                    context.allocation_intent_sha256,
                    verified.nonce,
                    context.idempotency_key,
                    AllocationOperationState.IN_PROGRESS.value,
                ),
            )
            if result.rowcount != 1:
                raise AuthorizationError("allocation_operation_state")

        self._transaction(commit)

    def _fail_effect(self, verified: _VerifiedAllocation) -> None:
        self._require_verified_operation(verified)
        context = verified.context

        def fail(connection: sqlite3.Connection) -> None:
            result = connection.execute(
                f"""
                UPDATE {_ALLOCATION_OPERATION_TABLE}
                SET state = ?, failure_phase = ?, updated_at = ?
                WHERE allocation_operation_id = ? AND nonce = ? AND state IN (?, ?)
                """,
                (
                    AllocationOperationState.FAILED_RECOVERY_REQUIRED.value,
                    "effect_failed_recovery_required",
                    verified.authorized_at,
                    context.allocation_operation_id,
                    verified.nonce,
                    AllocationOperationState.CLAIMED.value,
                    AllocationOperationState.IN_PROGRESS.value,
                ),
            )
            if result.rowcount != 1:
                raise AuthorizationError("allocation_operation_state")

        self._transaction(fail)

    def operation_state(self, allocation_operation_id: str) -> AllocationOperationState | None:
        if type(allocation_operation_id) is not str or not allocation_operation_id:
            raise AuthorizationError("allocation_operation_id")
        connection, _ = self._connect()
        try:
            row = connection.execute(
                f"SELECT state FROM {_ALLOCATION_OPERATION_TABLE} "
                "WHERE allocation_operation_id = ?",
                (allocation_operation_id,),
            ).fetchone()
        except sqlite3.Error:
            raise AuthorizationError("allocation_journal_transaction") from None
        finally:
            connection.close()
        if row is None:
            return None
        try:
            return AllocationOperationState(row[0])
        except (TypeError, ValueError):
            raise AuthorizationError("allocation_journal_schema") from None

    def assert_committed_allocation_stage(
        self,
        verified: _VerifiedAllocationIntent,
        receipt: AllocationEffectReceiptV2,
        attestation: ObservedAllocationAttestationV1,
    ) -> None:
        """Require the persisted receipt and signed observation to match the committed row."""

        self._require_verified_intent(verified)
        try:
            validate_observed_allocation_transition(verified.intent, receipt, attestation)
        except ValueError:
            raise AuthorizationError("allocation_stage_transition") from None
        connection, _ = self._connect()
        try:
            row = connection.execute(
                f"""
                SELECT state, allocation_intent_sha256, effect_receipt_sha256
                FROM {_ALLOCATION_OPERATION_TABLE}
                WHERE allocation_operation_id = ?
                """,
                (verified.intent.allocation_operation_id,),
            ).fetchone()
        except sqlite3.Error:
            raise AuthorizationError("allocation_journal_transaction") from None
        finally:
            connection.close()
        if (
            row is None
            or len(row) != 3
            or row[0] != AllocationOperationState.ALLOCATED.value
            or row[1] != verified.intent_sha256
            or row[2] != allocation_effect_receipt_sha256(receipt)
        ):
            raise AuthorizationError("allocation_operation_state")

    def require_recovery(self, allocation_operation_id: str) -> AllocationOperationState:
        """Mark an ambiguous allocation effect terminal without retrying it."""

        if type(allocation_operation_id) is not str or not allocation_operation_id:
            raise AuthorizationError("allocation_operation_id")

        def recover(connection: sqlite3.Connection) -> None:
            result = connection.execute(
                f"""
                UPDATE {_ALLOCATION_OPERATION_TABLE}
                SET state = ?, failure_phase = ?, updated_at = ?
                WHERE allocation_operation_id = ? AND state IN (?, ?)
                """,
                (
                    AllocationOperationState.FAILED_RECOVERY_REQUIRED.value,
                    "explicit_recovery",
                    _system_utc_clock().isoformat(timespec="seconds").replace("+00:00", "Z"),
                    allocation_operation_id,
                    AllocationOperationState.CLAIMED.value,
                    AllocationOperationState.IN_PROGRESS.value,
                ),
            )
            if result.rowcount != 1:
                raise AuthorizationError("allocation_operation_state")

        with self._operation_lease(allocation_operation_id, nonblocking=True) as lease:
            lease.assert_stable()
            self._transaction(recover)
            lease.assert_stable()
        return AllocationOperationState.FAILED_RECOVERY_REQUIRED

    @staticmethod
    def _require_verified_materialization(verified: _VerifiedMaterialization) -> None:
        if (
            type(verified) is not _VerifiedMaterialization
            or verified.capability is not _MATERIALIZATION_VERIFIED_CAPABILITY
        ):
            raise AuthorizationError("materialization_journal")

    def _claim_materialization_verified(self, verified: _VerifiedMaterialization) -> None:
        """Atomically bind one post-allocation operation to this journal identity."""

        self._require_verified_materialization(verified)
        context = verified.context

        def claim(connection: sqlite3.Connection) -> None:
            allocation = connection.execute(
                f"""
                SELECT state, allocation_intent_sha256, effect_receipt_sha256
                FROM {_ALLOCATION_OPERATION_TABLE}
                WHERE allocation_operation_id = ?
                """,
                (context.intent.allocation_operation_id,),
            ).fetchone()
            if allocation != (
                AllocationOperationState.ALLOCATED.value,
                context.intent.allocation_intent_sha256,
                context.intent.allocation_effect_receipt_sha256,
            ):
                raise AuthorizationError("materialization_allocation_predecessor")
            existing = connection.execute(
                f"SELECT 1 FROM {_MATERIALIZATION_OPERATION_TABLE} "
                "WHERE materialization_operation_id = ? OR allocation_operation_id = ? "
                "OR request_nonce_sha256 = ?",
                (
                    context.materialization_operation_id,
                    context.intent.allocation_operation_id,
                    context.secret_delivery_request.request_nonce_sha256,
                ),
            ).fetchone()
            start_request_nonce = connection.execute(
                f"SELECT 1 FROM {_START_RUNTIME_OPERATION_TABLE} WHERE request_nonce_sha256 = ?",
                (context.secret_delivery_request.request_nonce_sha256,),
            ).fetchone()
            nonce = connection.execute(
                f"SELECT 1 FROM {_MATERIALIZATION_OPERATION_TABLE} WHERE nonce = ?",
                (verified.nonce,),
            ).fetchone()
            if existing is not None or start_request_nonce is not None:
                raise AuthorizationError("materialization_operation_replayed")
            if nonce is not None:
                raise AuthorizationError("materialization_nonce_replayed")
            connection.execute(
                f"""
                INSERT INTO {_MATERIALIZATION_OPERATION_TABLE} (
                    materialization_operation_id, operation_kind, operation_scope,
                    allocation_operation_id, materialization_intent_sha256,
                    allocation_effect_receipt_sha256, observed_allocation_attestation_sha256,
                    request_nonce_sha256, nonce, provider_provenance_sha256,
                    executor_provenance_sha256,
                    postgres_login_provenance_sha256, secret_capability_provenance_sha256,
                    secret_delivery_provenance_sha256, idempotency_key, state,
                    effect_receipt_sha256, failure_phase, created_at, updated_at
                ) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, NULL, NULL, ?, ?)
                """,
                (
                    context.materialization_operation_id,
                    context.operation_kind,
                    context.operation_scope,
                    context.intent.allocation_operation_id,
                    context.materialization_intent_sha256,
                    context.intent.allocation_effect_receipt_sha256,
                    context.allocation_attestation_sha256,
                    context.secret_delivery_request.request_nonce_sha256,
                    verified.nonce,
                    context.provider_provenance_sha256,
                    context.executor_provenance_sha256,
                    context.postgres_login_provenance_sha256,
                    context.secret_capability_provenance_sha256,
                    context.secret_delivery_provenance_sha256,
                    context.idempotency_key,
                    MaterializationOperationState.CLAIMED.value,
                    verified.authorized_at,
                    verified.authorized_at,
                ),
            )

        self._transaction(claim)

    def _begin_materialization_effect(self, verified: _VerifiedMaterialization) -> None:
        self._require_verified_materialization(verified)
        context = verified.context

        def begin(connection: sqlite3.Connection) -> None:
            result = connection.execute(
                f"""
                UPDATE {_MATERIALIZATION_OPERATION_TABLE}
                SET state = ?, updated_at = ?
                WHERE materialization_operation_id = ? AND materialization_intent_sha256 = ?
                  AND nonce = ? AND idempotency_key = ? AND state = ?
                """,
                (
                    MaterializationOperationState.IN_PROGRESS.value,
                    verified.authorized_at,
                    context.materialization_operation_id,
                    context.materialization_intent_sha256,
                    verified.nonce,
                    context.idempotency_key,
                    MaterializationOperationState.CLAIMED.value,
                ),
            )
            if result.rowcount != 1:
                raise AuthorizationError("materialization_operation_state")

        self._transaction(begin)

    def _commit_materialization_effect(
        self,
        verified: _VerifiedMaterialization,
        receipt: MaterializationEffectReceiptV1,
    ) -> None:
        self._require_verified_materialization(verified)
        context = verified.context

        def commit(connection: sqlite3.Connection) -> None:
            result = connection.execute(
                f"""
                UPDATE {_MATERIALIZATION_OPERATION_TABLE}
                SET state = ?, effect_receipt_sha256 = ?, failure_phase = NULL, updated_at = ?
                WHERE materialization_operation_id = ? AND materialization_intent_sha256 = ?
                  AND nonce = ? AND idempotency_key = ? AND state = ?
                """,
                (
                    MaterializationOperationState.MATERIALIZED.value,
                    materialization_effect_receipt_sha256(receipt),
                    verified.authorized_at,
                    context.materialization_operation_id,
                    context.materialization_intent_sha256,
                    verified.nonce,
                    context.idempotency_key,
                    MaterializationOperationState.IN_PROGRESS.value,
                ),
            )
            if result.rowcount != 1:
                raise AuthorizationError("materialization_operation_state")

        self._transaction(commit)

    def _fail_materialization_effect(self, verified: _VerifiedMaterialization) -> None:
        self._require_verified_materialization(verified)
        context = verified.context

        def fail(connection: sqlite3.Connection) -> None:
            result = connection.execute(
                f"""
                UPDATE {_MATERIALIZATION_OPERATION_TABLE}
                SET state = ?, failure_phase = ?, updated_at = ?
                WHERE materialization_operation_id = ? AND nonce = ? AND state IN (?, ?)
                """,
                (
                    MaterializationOperationState.FAILED_RECOVERY_REQUIRED.value,
                    "effect_failed_recovery_required",
                    verified.authorized_at,
                    context.materialization_operation_id,
                    verified.nonce,
                    MaterializationOperationState.CLAIMED.value,
                    MaterializationOperationState.IN_PROGRESS.value,
                ),
            )
            if result.rowcount != 1:
                raise AuthorizationError("materialization_operation_state")

        self._transaction(fail)

    def materialization_operation_state(
        self, materialization_operation_id: str
    ) -> MaterializationOperationState | None:
        if type(materialization_operation_id) is not str or not materialization_operation_id:
            raise AuthorizationError("materialization_operation_id")
        connection, _ = self._connect()
        try:
            row = connection.execute(
                f"SELECT state FROM {_MATERIALIZATION_OPERATION_TABLE} "
                "WHERE materialization_operation_id = ?",
                (materialization_operation_id,),
            ).fetchone()
        except sqlite3.Error:
            raise AuthorizationError("materialization_journal_transaction") from None
        finally:
            connection.close()
        if row is None:
            return None
        try:
            return MaterializationOperationState(row[0])
        except (TypeError, ValueError):
            raise AuthorizationError("materialization_journal_schema") from None

    def assert_committed_materialization_stage(
        self,
        intent: MaterializationIntentV1,
        receipt: MaterializationEffectReceiptV1,
    ) -> None:
        """Require a persisted post-allocation terminal record before later effects."""

        intent = _canonical_materialization_intent(intent)
        connection, _ = self._connect()
        try:
            row = connection.execute(
                f"""
                SELECT state, materialization_intent_sha256, effect_receipt_sha256,
                       allocation_operation_id, allocation_effect_receipt_sha256,
                       observed_allocation_attestation_sha256
                FROM {_MATERIALIZATION_OPERATION_TABLE}
                WHERE materialization_operation_id = ?
                """,
                (intent.materialization_operation_id,),
            ).fetchone()
        except sqlite3.Error:
            raise AuthorizationError("materialization_journal_transaction") from None
        finally:
            connection.close()
        if row is None or row != (
            MaterializationOperationState.MATERIALIZED.value,
            materialization_intent_sha256(intent),
            materialization_effect_receipt_sha256(receipt),
            intent.allocation_operation_id,
            intent.allocation_effect_receipt_sha256,
            intent.observed_allocation_attestation_sha256,
        ):
            raise AuthorizationError("materialization_operation_state")

    def require_materialization_recovery(
        self, materialization_operation_id: str
    ) -> MaterializationOperationState:
        """Terminally mark an ambiguous materialization; it never retries an effect."""

        if type(materialization_operation_id) is not str or not materialization_operation_id:
            raise AuthorizationError("materialization_operation_id")

        def recover(connection: sqlite3.Connection) -> None:
            result = connection.execute(
                f"""
                UPDATE {_MATERIALIZATION_OPERATION_TABLE}
                SET state = ?, failure_phase = ?, updated_at = ?
                WHERE materialization_operation_id = ? AND state IN (?, ?)
                """,
                (
                    MaterializationOperationState.FAILED_RECOVERY_REQUIRED.value,
                    "explicit_recovery",
                    _system_utc_clock().isoformat(timespec="seconds").replace("+00:00", "Z"),
                    materialization_operation_id,
                    MaterializationOperationState.CLAIMED.value,
                    MaterializationOperationState.IN_PROGRESS.value,
                ),
            )
            if result.rowcount != 1:
                raise AuthorizationError("materialization_operation_state")

        with self._materialization_operation_lease(
            materialization_operation_id, nonblocking=True
        ) as lease:
            lease.assert_stable()
            self._transaction(recover)
            lease.assert_stable()
        return MaterializationOperationState.FAILED_RECOVERY_REQUIRED

    @staticmethod
    def _require_verified_start_runtime(verified: _VerifiedStartRuntime) -> None:
        if (
            type(verified) is not _VerifiedStartRuntime
            or verified.capability is not _START_RUNTIME_VERIFIED_CAPABILITY
        ):
            raise AuthorizationError("start_runtime_journal")

    def _claim_start_runtime_verified(self, verified: _VerifiedStartRuntime) -> None:
        """Atomically claim one fresh delivery/start after materialization committed.

        A restart is deliberately not a mutation of the materialization row.
        Each fresh signed StartRuntime intent has its own operation ID and
        request nonce, while the materialization predecessor remains immutable.
        """

        self._require_verified_start_runtime(verified)
        context = verified.context

        def claim(connection: sqlite3.Connection) -> None:
            predecessor = connection.execute(
                f"""
                SELECT state, materialization_intent_sha256, effect_receipt_sha256
                FROM {_MATERIALIZATION_OPERATION_TABLE}
                WHERE materialization_operation_id = ?
                """,
                (context.materialization_intent.materialization_operation_id,),
            ).fetchone()
            if predecessor != (
                MaterializationOperationState.MATERIALIZED.value,
                materialization_intent_sha256(context.materialization_intent),
                materialization_effect_receipt_sha256(context.materialization_receipt),
            ):
                raise AuthorizationError("start_runtime_materialization_predecessor")
            existing = connection.execute(
                f"SELECT 1 FROM {_START_RUNTIME_OPERATION_TABLE} "
                "WHERE start_operation_id = ? OR request_nonce_sha256 = ?",
                (
                    context.start_operation_id,
                    context.secret_delivery_request.request_nonce_sha256,
                ),
            ).fetchone()
            nonce = connection.execute(
                f"SELECT 1 FROM {_START_RUNTIME_OPERATION_TABLE} WHERE nonce = ?",
                (verified.nonce,),
            ).fetchone()
            materialization_request_nonce = connection.execute(
                f"SELECT 1 FROM {_MATERIALIZATION_OPERATION_TABLE} WHERE request_nonce_sha256 = ?",
                (context.secret_delivery_request.request_nonce_sha256,),
            ).fetchone()
            if existing is not None or materialization_request_nonce is not None:
                raise AuthorizationError("start_runtime_operation_replayed")
            if nonce is not None:
                raise AuthorizationError("start_runtime_nonce_replayed")
            connection.execute(
                f"""
                INSERT INTO {_START_RUNTIME_OPERATION_TABLE} (
                    start_operation_id, operation_kind, operation_scope,
                    materialization_operation_id, materialization_intent_sha256,
                    materialization_effect_receipt_sha256,
                    observed_runtime_attestation_sha256, start_runtime_intent_sha256,
                    request_nonce_sha256, channel_binding_sha256, session_binding_sha256,
                    nonce, provider_provenance_sha256, executor_provenance_sha256,
                    secret_capability_provenance_sha256,
                    remote_session_provenance_sha256, idempotency_key, state,
                    effect_receipt_sha256, failure_phase, created_at, updated_at
                ) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, NULL, NULL, ?, ?)
                """,
                (
                    context.start_operation_id,
                    context.operation_kind,
                    context.operation_scope,
                    context.materialization_intent.materialization_operation_id,
                    materialization_intent_sha256(context.materialization_intent),
                    materialization_effect_receipt_sha256(context.materialization_receipt),
                    context.intent.observed_runtime_attestation_sha256,
                    context.start_runtime_intent_sha256,
                    context.secret_delivery_request.request_nonce_sha256,
                    context.secret_delivery_request.channel_binding_sha256,
                    context.secret_delivery_request.session_binding_sha256,
                    verified.nonce,
                    context.provider_provenance_sha256,
                    context.executor_provenance_sha256,
                    context.secret_capability_provenance_sha256,
                    context.remote_session_provenance_sha256,
                    context.idempotency_key,
                    StartRuntimeOperationState.CLAIMED.value,
                    verified.authorized_at,
                    verified.authorized_at,
                ),
            )

        self._transaction(claim)

    def _begin_start_runtime_effect(self, verified: _VerifiedStartRuntime) -> None:
        self._require_verified_start_runtime(verified)
        context = verified.context

        def begin(connection: sqlite3.Connection) -> None:
            result = connection.execute(
                f"""
                UPDATE {_START_RUNTIME_OPERATION_TABLE}
                SET state = ?, updated_at = ?
                WHERE start_operation_id = ? AND start_runtime_intent_sha256 = ?
                  AND nonce = ? AND idempotency_key = ? AND state = ?
                """,
                (
                    StartRuntimeOperationState.IN_PROGRESS.value,
                    verified.authorized_at,
                    context.start_operation_id,
                    context.start_runtime_intent_sha256,
                    verified.nonce,
                    context.idempotency_key,
                    StartRuntimeOperationState.CLAIMED.value,
                ),
            )
            if result.rowcount != 1:
                raise AuthorizationError("start_runtime_operation_state")

        self._transaction(begin)

    def _commit_start_runtime_effect(
        self,
        verified: _VerifiedStartRuntime,
        receipt: StartRuntimeEffectReceiptV2,
    ) -> None:
        self._require_verified_start_runtime(verified)
        context = verified.context

        def commit(connection: sqlite3.Connection) -> None:
            result = connection.execute(
                f"""
                UPDATE {_START_RUNTIME_OPERATION_TABLE}
                SET state = ?, effect_receipt_sha256 = ?, failure_phase = NULL, updated_at = ?
                WHERE start_operation_id = ? AND start_runtime_intent_sha256 = ?
                  AND nonce = ? AND idempotency_key = ? AND state = ?
                """,
                (
                    StartRuntimeOperationState.STARTED.value,
                    start_runtime_effect_receipt_sha256(receipt),
                    verified.authorized_at,
                    context.start_operation_id,
                    context.start_runtime_intent_sha256,
                    verified.nonce,
                    context.idempotency_key,
                    StartRuntimeOperationState.IN_PROGRESS.value,
                ),
            )
            if result.rowcount != 1:
                raise AuthorizationError("start_runtime_operation_state")

        self._transaction(commit)

    def _fail_start_runtime_effect(self, verified: _VerifiedStartRuntime) -> None:
        self._require_verified_start_runtime(verified)
        context = verified.context

        def fail(connection: sqlite3.Connection) -> None:
            result = connection.execute(
                f"""
                UPDATE {_START_RUNTIME_OPERATION_TABLE}
                SET state = ?, failure_phase = ?, updated_at = ?
                WHERE start_operation_id = ? AND nonce = ? AND state IN (?, ?)
                """,
                (
                    StartRuntimeOperationState.FAILED_RECOVERY_REQUIRED.value,
                    "effect_failed_recovery_required",
                    verified.authorized_at,
                    context.start_operation_id,
                    verified.nonce,
                    StartRuntimeOperationState.CLAIMED.value,
                    StartRuntimeOperationState.IN_PROGRESS.value,
                ),
            )
            if result.rowcount != 1:
                raise AuthorizationError("start_runtime_operation_state")

        self._transaction(fail)

    def start_runtime_operation_state(
        self, start_operation_id: str
    ) -> StartRuntimeOperationState | None:
        if type(start_operation_id) is not str or not start_operation_id:
            raise AuthorizationError("start_runtime_operation_id")
        connection, _ = self._connect()
        try:
            row = connection.execute(
                f"SELECT state FROM {_START_RUNTIME_OPERATION_TABLE} WHERE start_operation_id = ?",
                (start_operation_id,),
            ).fetchone()
        except sqlite3.Error:
            raise AuthorizationError("start_runtime_journal_transaction") from None
        finally:
            connection.close()
        if row is None:
            return None
        try:
            return StartRuntimeOperationState(row[0])
        except (TypeError, ValueError):
            raise AuthorizationError("start_runtime_journal_schema") from None

    def require_start_runtime_recovery(self, start_operation_id: str) -> StartRuntimeOperationState:
        """Mark an ambiguous start terminally; never automatically redeliver secrets."""

        if type(start_operation_id) is not str or not start_operation_id:
            raise AuthorizationError("start_runtime_operation_id")

        def recover(connection: sqlite3.Connection) -> None:
            result = connection.execute(
                f"""
                UPDATE {_START_RUNTIME_OPERATION_TABLE}
                SET state = ?, failure_phase = ?, updated_at = ?
                WHERE start_operation_id = ? AND state IN (?, ?)
                """,
                (
                    StartRuntimeOperationState.FAILED_RECOVERY_REQUIRED.value,
                    "explicit_recovery",
                    _system_utc_clock().isoformat(timespec="seconds").replace("+00:00", "Z"),
                    start_operation_id,
                    StartRuntimeOperationState.CLAIMED.value,
                    StartRuntimeOperationState.IN_PROGRESS.value,
                ),
            )
            if result.rowcount != 1:
                raise AuthorizationError("start_runtime_operation_state")

        with self._start_runtime_operation_lease(start_operation_id, nonblocking=True) as lease:
            lease.assert_stable()
            self._transaction(recover)
            lease.assert_stable()
        return StartRuntimeOperationState.FAILED_RECOVERY_REQUIRED


def _validate_effect_receipt(context: VerifiedExecutionContext, value: object) -> EffectReceiptV1:
    receipt = cast(
        EffectReceiptV1,
        _canonical_artifact_model(value, EffectReceiptV1, phase="effect_receipt"),
    )
    if (
        receipt.operation_kind != context.operation_kind
        or receipt.operation_id != context.operation_id
        or receipt.idempotency_key != context.idempotency_key
    ):
        raise AuthorizationError("effect_receipt")
    return receipt


def _validate_allocation_effect_receipt(
    context: AllocationExecutionContext, value: object
) -> AllocationEffectReceiptV2:
    """Reject every effect output outside the one empty-resource scope."""

    receipt = cast(
        AllocationEffectReceiptV2,
        _canonical_artifact_model(
            value,
            AllocationEffectReceiptV2,
            phase="allocation_effect_receipt",
        ),
    )
    if (
        receipt.operation_kind != context.operation_kind
        or receipt.operation_scope != context.operation_scope
        or receipt.allocation_operation_id != context.allocation_operation_id
        or receipt.allocation_intent_sha256 != context.allocation_intent_sha256
        or receipt.journal_uuid != context.intent.journal_uuid
        or receipt.idempotency_key != context.idempotency_key
    ):
        raise AuthorizationError("allocation_effect_receipt")
    plan = context.intent.plan
    resources = receipt.allocated_resources
    expected_networks = (
        (resources.primary_network, plan.topology.primary_network),
        (resources.restore_network, plan.topology.restore_network),
    )
    expected_volumes = (
        (resources.primary_cache_volume, plan.primary_valkey_volume),
        (resources.restore_cache_volume, plan.restore_valkey_volume),
    )
    if (
        resources.engine.engine_fingerprint_sha256
        != context.executor_expectation.engine_fingerprint_sha256
        or resources.no_host_publication.container_ids != ()
        or resources.no_host_publication.host_network is not False
        or resources.no_host_publication.publish_all_ports is not False
        or resources.no_host_publication.published_port_bindings != ()
        or resources.no_host_publication.allowed_attachment_set_sha256
        != canonical_sha256(plan.topology)
        or any(
            observed.name != expected.name
            or observed.driver != expected.driver
            or observed.model_dump(mode="python")["internal"]
            != expected.model_dump(mode="python")["internal"]
            or observed.subnet != expected.subnet
            or observed.gateway != expected.gateway
            or observed.options != expected.options
            for observed, expected in expected_networks
        )
        or any(
            observed.name != expected.name
            or observed.driver != expected.driver
            or observed.options != expected.options
            for observed, expected in expected_volumes
        )
        or resources.postgres.database_name != plan.postgres.database_name
        or resources.postgres.schema_name != plan.postgres.schema_name
        or resources.postgres.owner_role != plan.postgres.owner_role
        or resources.postgres.application_role != plan.postgres.application_role
        or tuple(role.role for role in resources.postgres.role_oids) != plan.postgres.role_names
        or tuple((role.can_login, role.password_absent) for role in resources.postgres.role_oids)
        != ((False, True), (False, True))
        or tuple(
            (grant.role, grant.grantee, grant.privilege, grant.schema_name)
            for grant in resources.postgres.grants
        )
        != tuple(
            (grant.role, grant.grantee, grant.privilege, grant.schema_name)
            for grant in plan.postgres.grants
        )
    ):
        raise AuthorizationError("allocation_effect_receipt")
    return receipt


def _bootstrap_inspection_matches(
    inspection: ContainerBootstrapInspectionV1, template: ContainerBootstrapTemplateV1
) -> bool:
    """Compare explicit engine inspection fields; a template digest alone never suffices."""

    return (
        inspection.entrypoint_sha256 == template.entrypoint_sha256
        and inspection.template_sha256 == template.template_sha256
        and inspection.run_as_non_root is True
        and inspection.read_only_root_filesystem is True
        and inspection.cap_drop_all is True
        and inspection.no_new_privileges is True
        and inspection.private_pid is True
        and inspection.log_driver == template.log_driver
        and inspection.restart_policy == "no"
        and inspection.mounts == ()
        and inspection.docker_socket_mounted is False
        and inspection.host_network is False
        and inspection.publish_all_ports is False
        and inspection.port_bindings == ()
        and inspection.network_name == template.network_name
        and inspection.network_alias == template.network_alias
        and inspection.static_ipv4 == template.static_ipv4
        and inspection.accepted_secret_sink == template.accepted_secret_sink
        and inspection.running is True
    )


def _verify_context_executor_operation_receipt(
    context: MaterializationExecutionContext,
    receipt: ExecutorOperationReceiptV1,
) -> None:
    """Verify executor attestation without handing an effect a mutable verifier."""

    valid = False
    try:
        if receipt.signer_key_id != context.executor_attestation_key_id:
            raise ValueError
        public_key = _canonical_base64(context.executor_attestation_public_key_base64)
        if (
            len(public_key) != 32
            or _digest(public_key) != context.executor_attestation_public_key_fingerprint_sha256
        ):
            raise ValueError
        Ed25519PublicKey.from_public_bytes(public_key).verify(
            _canonical_base64(receipt.signature_base64),
            _executor_operation_receipt_message(receipt),
        )
        valid = True
    except (InvalidSignature, ValueError, binascii.Error):
        valid = False
    if not valid:
        raise AuthorizationError("materialization_executor_receipt_signature")


def _validate_materialization_effect_receipt(
    context: MaterializationExecutionContext, value: object
) -> MaterializationEffectReceiptV1:
    """Require exactly the signed final attachment graph and no host publication."""

    receipt = cast(
        MaterializationEffectReceiptV1,
        _canonical_artifact_model(
            value,
            MaterializationEffectReceiptV1,
            phase="materialization_effect_receipt",
        ),
    )
    intent = context.intent
    if (
        receipt.operation_kind != context.operation_kind
        or receipt.operation_scope != context.operation_scope
        or receipt.materialization_operation_id != context.materialization_operation_id
        or receipt.materialization_intent_sha256 != context.materialization_intent_sha256
        or receipt.allocation_operation_id != intent.allocation_operation_id
        or receipt.allocation_effect_receipt_sha256 != intent.allocation_effect_receipt_sha256
        or receipt.observed_allocation_attestation_sha256 != context.allocation_attestation_sha256
        or receipt.journal_uuid != intent.journal_uuid
        or receipt.idempotency_key != context.idempotency_key
    ):
        raise AuthorizationError("materialization_effect_receipt")
    plans = (
        (
            receipt.primary_infisical,
            intent.plan.primary_infisical,
            intent.topology.primary_infisical,
            intent.bootstrap_templates.primary_infisical,
        ),
        (
            receipt.primary_valkey,
            intent.plan.primary_valkey,
            intent.topology.primary_valkey,
            intent.bootstrap_templates.primary_valkey,
        ),
        (
            receipt.restore_infisical,
            intent.plan.restore_infisical,
            intent.topology.restore_infisical,
            intent.bootstrap_templates.restore_infisical,
        ),
        (
            receipt.restore_valkey,
            intent.plan.restore_valkey,
            intent.topology.restore_valkey,
            intent.bootstrap_templates.restore_valkey,
        ),
    )
    allocated = context.allocation_attestation.allocated_resources
    network_ids = {
        allocated.primary_network.name: allocated.primary_network.network_id,
        allocated.restore_network.name: allocated.restore_network.network_id,
    }
    for observed, plan, placement, template in plans:
        if (
            observed.component != plan.component
            or observed.image != plan.image
            or observed.config_sha256 != plan.config_sha256
            or len(observed.attachments) != 1
            or observed.attachments[0].network_name != placement.network_name
            or observed.attachments[0].network_id != network_ids.get(placement.network_name)
            or observed.attachments[0].alias != placement.alias
            or observed.attachments[0].static_ipv4 != placement.static_ipv4
            or observed.no_host_publication.network_mode != "isolated_user_network_v1"
            or observed.no_host_publication.host_network is not False
            or observed.no_host_publication.publish_all_ports is not False
            or observed.no_host_publication.port_bindings != ()
            or not _bootstrap_inspection_matches(observed.inspection, template)
        ):
            raise AuthorizationError("materialization_effect_receipt")
    executor_receipt = receipt.executor_receipt
    request = context.secret_delivery_request
    if (
        receipt.executor_receipt_sha256 != canonical_sha256(executor_receipt)
        or executor_receipt.operation_scope != context.operation_scope
        or executor_receipt.operation_id != context.materialization_operation_id
        or executor_receipt.idempotency_key != context.idempotency_key
        or executor_receipt.executor_id != context.executor_expectation.executor_id
        or executor_receipt.host_fingerprint_sha256
        != context.executor_expectation.host_fingerprint_sha256
        or executor_receipt.engine_fingerprint_sha256
        != context.executor_expectation.engine_fingerprint_sha256
        or executor_receipt.channel_binding_sha256 != request.channel_binding_sha256
        or executor_receipt.session_binding_sha256 != request.session_binding_sha256
        or tuple(item.container_id for item in executor_receipt.containers)
        != tuple(item.container_id for item, *_rest in plans)
        or any(
            executor_item.inspection != observed.inspection
            for executor_item, (observed, *_rest) in zip(
                executor_receipt.containers, plans, strict=True
            )
        )
    ):
        raise AuthorizationError("materialization_executor_receipt")
    _verify_context_executor_operation_receipt(context, executor_receipt)
    transition = intent.postgres_login_transition
    transition_receipt = receipt.postgres_login_transition
    if (
        transition_receipt.prepared_operation_id != transition.prepared_operation_id
        or transition_receipt.system_identifier != transition.system_identifier
        or transition_receipt.database_name != transition.database_name
        or transition_receipt.database_oid != transition.database_oid
        or transition_receipt.owner_role != transition.owner_role
        or transition_receipt.owner_role_oid != transition.owner_role_oid
        or transition_receipt.application_role != transition.application_role
        or transition_receipt.application_role_oid != transition.application_role_oid
        or transition_receipt.application_password_reference_sha256
        != transition.application_password_reference_sha256
        or transition_receipt.owner_can_login is not False
        or transition_receipt.owner_password_absent is not True
        or transition_receipt.application_can_login is not True
        or transition_receipt.application_password_verifier_installed is not True
        or context.postgres_login_expectation.prepared_operation_id
        != transition.prepared_operation_id
        or context.postgres_login_expectation.database_oid != transition.database_oid
        or context.postgres_login_expectation.owner_role_oid != transition.owner_role_oid
        or context.postgres_login_expectation.application_role_oid
        != transition.application_role_oid
        or context.postgres_login_expectation.application_password_reference_sha256
        != transition.application_password_reference_sha256
    ):
        raise AuthorizationError("materialization_postgres_transition_receipt")
    delivery = receipt.delivery_receipt
    if (
        delivery.operation_scope != request.operation_scope
        or delivery.operation_id != request.operation_id
        or delivery.journal_uuid != request.journal_uuid
        or delivery.request_nonce_sha256 != request.request_nonce_sha256
        or delivery.channel_binding_sha256 != request.channel_binding_sha256
        or delivery.session_binding_sha256 != request.session_binding_sha256
        or any(
            (
                delivered.purpose,
                delivered.reference_sha256,
                delivered.sink,
                delivered.target_processes,
                delivered.delivered,
            )
            != (
                slot.purpose,
                slot.reference_sha256,
                slot.sink,
                slot.target_processes,
                True,
            )
            for delivered, slot in zip(delivery.slots, request.slots, strict=True)
        )
    ):
        raise AuthorizationError("materialization_secret_delivery_receipt")
    if executor_receipt.secret_delivery_receipt_sha256 != canonical_sha256(delivery):
        raise AuthorizationError("materialization_executor_receipt")
    return receipt


def _verify_context_start_runtime_executor_receipt(
    context: StartRuntimeExecutionContext,
    receipt: StartRuntimeExecutorReceiptV2,
) -> None:
    """Verify a redacted start receipt against the pinned executor key."""

    valid = False
    try:
        if receipt.signer_key_id != context.executor_attestation_key_id:
            raise ValueError
        public_key = _canonical_base64(context.executor_attestation_public_key_base64)
        if (
            len(public_key) != 32
            or _digest(public_key) != context.executor_attestation_public_key_fingerprint_sha256
        ):
            raise ValueError
        Ed25519PublicKey.from_public_bytes(public_key).verify(
            _canonical_base64(receipt.signature_base64),
            _start_runtime_executor_receipt_message(receipt),
        )
        valid = True
    except (InvalidSignature, ValueError, binascii.Error):
        valid = False
    if not valid:
        raise AuthorizationError("start_runtime_executor_receipt_signature")


def _validate_start_runtime_effect_receipt(
    context: StartRuntimeExecutionContext, value: object
) -> StartRuntimeEffectReceiptV2:
    """Accept only a signed restart of the exact previously observed runtime.

    A fresh StartRuntime authorization may redeliver the five bounded slots,
    but cannot use that fact to swap images, container identities, attachment
    graphs, hardening fields, or the executor installation chain.
    """

    receipt = cast(
        StartRuntimeEffectReceiptV2,
        _canonical_artifact_model(
            value,
            StartRuntimeEffectReceiptV2,
            phase="start_runtime_effect_receipt",
        ),
    )
    request = context.secret_delivery_request
    if (
        receipt.operation_kind != context.operation_kind
        or receipt.operation_scope != context.operation_scope
        or receipt.start_operation_id != context.start_operation_id
        or receipt.start_runtime_intent_sha256 != context.start_runtime_intent_sha256
        or receipt.materialization_operation_id
        != context.materialization_intent.materialization_operation_id
        or receipt.materialization_effect_receipt_sha256
        != materialization_effect_receipt_sha256(context.materialization_receipt)
        or receipt.journal_uuid != context.intent.journal_uuid
        or receipt.idempotency_key != context.idempotency_key
    ):
        raise AuthorizationError("start_runtime_effect_receipt")
    executor_receipt = receipt.executor_receipt
    expected_observations = (
        context.materialization_receipt.primary_infisical,
        context.materialization_receipt.primary_valkey,
        context.materialization_receipt.restore_infisical,
        context.materialization_receipt.restore_valkey,
    )
    if (
        executor_receipt.operation_kind != context.operation_kind
        or executor_receipt.operation_scope != context.operation_scope
        or executor_receipt.start_operation_id != context.start_operation_id
        or executor_receipt.start_runtime_intent_sha256 != context.start_runtime_intent_sha256
        or executor_receipt.idempotency_key != context.idempotency_key
        or executor_receipt.request_nonce_sha256 != request.request_nonce_sha256
        or executor_receipt.channel_binding_sha256 != request.channel_binding_sha256
        or executor_receipt.session_binding_sha256 != request.session_binding_sha256
        or executor_receipt.installation_receipt_sha256
        != context.intent.evidence.executor_installation_receipt_sha256
        or executor_receipt.executor_id != context.executor_expectation.executor_id
        or executor_receipt.host_fingerprint_sha256
        != context.executor_expectation.host_fingerprint_sha256
        or executor_receipt.engine_fingerprint_sha256
        != context.executor_expectation.engine_fingerprint_sha256
        or tuple(item.component for item in executor_receipt.containers)
        != tuple(item.component for item in expected_observations)
        or tuple(item.container_id for item in executor_receipt.containers)
        != tuple(item.container_id for item in expected_observations)
        or any(
            item.inspection != observed.inspection
            for item, observed in zip(
                executor_receipt.containers, expected_observations, strict=True
            )
        )
    ):
        raise AuthorizationError("start_runtime_executor_receipt")
    _verify_context_start_runtime_executor_receipt(context, executor_receipt)
    delivery = receipt.delivery_receipt
    if (
        delivery.operation_scope != request.operation_scope
        or delivery.operation_id != request.operation_id
        or delivery.journal_uuid != request.journal_uuid
        or delivery.request_nonce_sha256 != request.request_nonce_sha256
        or delivery.channel_binding_sha256 != request.channel_binding_sha256
        or delivery.session_binding_sha256 != request.session_binding_sha256
        or any(
            (
                delivered.purpose,
                delivered.reference_sha256,
                delivered.sink,
                delivered.target_processes,
                delivered.delivered,
            )
            != (
                slot.purpose,
                slot.reference_sha256,
                slot.sink,
                slot.target_processes,
                True,
            )
            for delivered, slot in zip(delivery.slots, request.slots, strict=True)
        )
    ):
        raise AuthorizationError("start_runtime_secret_delivery_receipt")
    if executor_receipt.secret_delivery_receipt_sha256 != canonical_sha256(delivery):
        raise AuthorizationError("start_runtime_executor_receipt")
    try:
        completed_at = tuple(
            datetime.fromisoformat(value.removesuffix("Z") + "+00:00")
            for value in (
                receipt.completed_at,
                executor_receipt.completed_at,
                delivery.completed_at,
            )
        )
    except ValueError:
        raise AuthorizationError("start_runtime_effect_receipt") from None
    now = _system_utc_clock()
    if (
        type(now) is not datetime
        or now.tzinfo is None
        or now.utcoffset() is None
        or any(value.tzinfo is None or value.utcoffset() is None for value in completed_at)
        or any(value.astimezone(UTC) > now.astimezone(UTC) for value in completed_at)
        or any(
            now.astimezone(UTC) - value.astimezone(UTC) > _STAGE_ATTESTATION_FRESHNESS
            for value in completed_at
        )
    ):
        raise AuthorizationError("start_runtime_effect_receipt")
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
    receipt = cast(
        JournalGenesisReconciliationReceiptV1,
        _canonical_artifact_model(
            receipt,
            JournalGenesisReconciliationReceiptV1,
            phase="journal_genesis_reconciliation_signature",
        ),
    )
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


def _allocation_journal_genesis_reconciliation_message(
    receipt: AllocationJournalGenesisReconciliationReceiptV1,
) -> bytes:
    material = receipt.model_dump(mode="json", exclude={"signature_base64"})
    return _ALLOCATION_JOURNAL_GENESIS_RECONCILIATION_DOMAIN + json.dumps(
        material, sort_keys=True, separators=(",", ":")
    ).encode("utf-8")


def _verify_allocation_journal_genesis_reconciliation_receipt(
    receipt: AllocationJournalGenesisReconciliationReceiptV1,
    *,
    signer: TrustedEd25519SignerV1,
) -> None:
    receipt = cast(
        AllocationJournalGenesisReconciliationReceiptV1,
        _canonical_artifact_model(
            receipt,
            AllocationJournalGenesisReconciliationReceiptV1,
            phase="allocation_journal_reconciliation_signature",
        ),
    )
    if (
        type(receipt) is not AllocationJournalGenesisReconciliationReceiptV1
        or type(signer) is not TrustedEd25519SignerV1
        or receipt.signer_key_id != signer.key_id
    ):
        raise AuthorizationError("allocation_journal_reconciliation_signature")
    try:
        signature = _canonical_base64(receipt.signature_base64)
        signer.key().verify(signature, _allocation_journal_genesis_reconciliation_message(receipt))
    except (InvalidSignature, ValueError, binascii.Error):
        raise AuthorizationError("allocation_journal_reconciliation_signature") from None


def _verify_reconciliation_receipt(
    receipt: ReconciliationReceiptV1, *, signer: TrustedEd25519SignerV1
) -> None:
    receipt = cast(
        ReconciliationReceiptV1,
        _canonical_artifact_model(
            receipt,
            ReconciliationReceiptV1,
            phase="reconciliation_signature",
        ),
    )
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


def _system_utc_clock() -> datetime:
    return datetime.now(UTC)


def _canonical_allocation_intent(intent: AllocationIntentV2) -> AllocationIntentV2:
    """Reject Pydantic construction/copy drift before an authorization decision."""

    try:
        return strict_canonical_allocation_intent(intent)
    except ValueError:
        raise AuthorizationError("allocation_intent_artifact") from None


def _canonical_materialization_intent(intent: MaterializationIntentV1) -> MaterializationIntentV1:
    """Reject raw enum/string/model-copy drift before a runtime effect boundary."""

    try:
        return strict_canonical_materialization_intent(intent)
    except ValueError:
        raise AuthorizationError("materialization_intent_artifact") from None


def _canonical_artifact_model(
    model: object, model_type: type[BaseModel], *, phase: str
) -> BaseModel:
    """Revalidate caller-supplied signed models before a journal or effect path."""

    try:
        return _strict_canonical_model(model, model_type)
    except ValueError:
        raise AuthorizationError(phase) from None


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


def _acquire_control_lease(
    adapter: object,
    policy: BaseModel,
    *,
    phase: str,
    secondary_policy: BaseModel | None = None,
    tertiary_policy: BaseModel | None = None,
) -> tuple[object, object]:
    """Open one injected capability lease without exposing adapter exceptions."""

    acquire = _safe_call(lambda: cast(_ControlLeaseAcquirer, adapter).acquire)
    if acquire is _SAFE_CALL_FAILURE or not callable(acquire):
        raise AuthorizationError(phase)
    # The secret-material capability is deliberately a two-policy boundary,
    # and the PostgreSQL login capability is deliberately a three-policy
    # boundary. Do not collapse either into a caller-created composite object:
    # an adapter could otherwise silently ignore a destination or observed-OID
    # restriction.
    if tertiary_policy is not None and secondary_policy is None:
        raise AuthorizationError(phase)
    manager = _safe_call(
        lambda: (
            acquire(policy)
            if secondary_policy is None
            else (
                acquire(policy, secondary_policy)
                if tertiary_policy is None
                else acquire(policy, secondary_policy, tertiary_policy)
            )
        )
    )
    if manager is _SAFE_CALL_FAILURE:
        raise AuthorizationError(phase)
    context_manager = cast(AbstractContextManager[object], manager)
    enter = _safe_call(lambda: context_manager.__enter__)
    exit_method = _safe_call(lambda: context_manager.__exit__)
    if (
        enter is _SAFE_CALL_FAILURE
        or exit_method is _SAFE_CALL_FAILURE
        or not callable(enter)
        or not callable(exit_method)
    ):
        raise AuthorizationError(phase)
    lease = _safe_call(enter)
    if lease is _SAFE_CALL_FAILURE:
        raise AuthorizationError(phase)
    return manager, lease


def _release_control_lease(manager: object) -> bool:
    context_manager = cast(AbstractContextManager[object], manager)
    exit_method = _safe_call(lambda: context_manager.__exit__)
    return (
        exit_method is not _SAFE_CALL_FAILURE
        and callable(exit_method)
        and _safe_call(lambda: exit_method(None, None, None)) is not _SAFE_CALL_FAILURE
    )


def _lease_method_value(
    lease: object, method_name: Literal["inspect", "recheck"], policy: BaseModel, *, phase: str
) -> object:
    method = _safe_call(lambda: getattr(lease, method_name))
    if method is _SAFE_CALL_FAILURE or not callable(method):
        raise AuthorizationError(phase)
    value = _safe_call(lambda: method(policy))
    if value is _SAFE_CALL_FAILURE or value is None:
        raise AuthorizationError(phase)
    return value


def _executor_control_commitment(
    lease: ExecutorControlLease,
    policy: ExecutorControlPolicyV1,
    *,
    recheck: bool,
) -> tuple[str, ExecutorControlExpectationV1]:
    value = _lease_method_value(
        lease, "recheck" if recheck else "inspect", policy, phase="executor_control_provenance"
    )
    if type(value) is not ExecutorControlProvenance:
        raise AuthorizationError("executor_control_provenance")
    provenance = value
    if (
        type(provenance.executor_id) is not str
        or type(provenance.endpoint_sha256) is not str
        or type(provenance.host_fingerprint_sha256) is not str
        or type(provenance.control_capability_fingerprint_sha256) is not str
        or type(provenance.engine_fingerprint_sha256) is not str
        or provenance.executor_id != policy.executor.executor_id
        or provenance.endpoint_sha256 != policy.executor.endpoint_sha256
        or provenance.host_fingerprint_sha256 != policy.executor.host_fingerprint_sha256
        or provenance.control_capability_fingerprint_sha256
        != policy.executor.control_capability_fingerprint_sha256
        or provenance.engine_fingerprint_sha256 != policy.engine_fingerprint_sha256
    ):
        raise AuthorizationError("executor_control_provenance")
    expectation = ExecutorControlExpectationV1(
        executor_id=provenance.executor_id,
        endpoint_sha256=provenance.endpoint_sha256,
        host_fingerprint_sha256=provenance.host_fingerprint_sha256,
        control_capability_fingerprint_sha256=provenance.control_capability_fingerprint_sha256,
        engine_fingerprint_sha256=provenance.engine_fingerprint_sha256,
    )
    return _digest(_canonical_json_bytes(expectation.model_dump(mode="json"))), expectation


def _postgres_control_commitment(
    lease: PostgreSQLControlLease,
    policy: PostgreSQLControlPolicyV1,
    *,
    recheck: bool,
) -> tuple[str, PostgreSQLControlExpectationV1]:
    value = _lease_method_value(
        lease, "recheck" if recheck else "inspect", policy, phase="postgres_control_provenance"
    )
    if type(value) is not PostgreSQLControlProvenance:
        raise AuthorizationError("postgres_control_provenance")
    provenance = value
    if (
        type(provenance.authority) is not str
        or type(provenance.maintenance_reference_sha256) is not str
        or type(provenance.capability_fingerprint_sha256) is not str
        or provenance.authority != policy.authority
        or provenance.maintenance_reference_sha256 != policy.maintenance_reference_sha256
    ):
        raise AuthorizationError("postgres_control_provenance")
    expectation = PostgreSQLControlExpectationV1(
        authority=provenance.authority,
        maintenance_reference_sha256=provenance.maintenance_reference_sha256,
        capability_fingerprint_sha256=provenance.capability_fingerprint_sha256,
    )
    return _digest(_canonical_json_bytes(expectation.model_dump(mode="json"))), expectation


def _postgres_login_transition_commitment(
    lease: PostgreSQLLoginTransitionLease,
    policy: PostgreSQLControlPolicyV1,
    transition: PostgreSQLLoginTransitionIntentV1,
    connection: EphemeralPostgreSQLConnectionPolicyV1,
    *,
    recheck: bool,
) -> tuple[str, PostgreSQLLoginTransitionExpectationV1]:
    """Commit one lease to the exact observed-OID, prepared login transition."""

    method = _safe_call(lambda: getattr(lease, "recheck" if recheck else "inspect"))
    if method is _SAFE_CALL_FAILURE or not callable(method):
        raise AuthorizationError("postgres_login_transition_provenance")
    value = _safe_call(lambda: method(policy, transition, connection))
    if value is _SAFE_CALL_FAILURE or type(value) is not PostgreSQLLoginTransitionProvenance:
        raise AuthorizationError("postgres_login_transition_provenance")
    provenance = value
    if (
        type(provenance.authority) is not str
        or type(provenance.system_identifier) is not str
        or type(provenance.database_oid) is not int
        or type(provenance.owner_role_oid) is not int
        or type(provenance.application_role_oid) is not int
        or type(provenance.prepared_operation_id) is not str
        or type(provenance.application_password_reference_sha256) is not str
        or type(provenance.capability_fingerprint_sha256) is not str
        or provenance.authority != policy.authority
        or provenance.authority != connection.authority
        or provenance.system_identifier != transition.system_identifier
        or provenance.database_oid != transition.database_oid
        or provenance.owner_role_oid != transition.owner_role_oid
        or provenance.application_role_oid != transition.application_role_oid
        or provenance.prepared_operation_id != transition.prepared_operation_id
        or provenance.application_password_reference_sha256
        != transition.application_password_reference_sha256
        or provenance.application_password_reference_sha256
        != connection.application_password_reference_sha256
        or re.fullmatch(_SHA256, provenance.capability_fingerprint_sha256) is None
    ):
        raise AuthorizationError("postgres_login_transition_provenance")
    expectation = PostgreSQLLoginTransitionExpectationV1(
        authority=provenance.authority,
        system_identifier=provenance.system_identifier,
        database_oid=provenance.database_oid,
        owner_role_oid=provenance.owner_role_oid,
        application_role_oid=provenance.application_role_oid,
        prepared_operation_id=provenance.prepared_operation_id,
        application_password_reference_sha256=(provenance.application_password_reference_sha256),
        capability_fingerprint_sha256=provenance.capability_fingerprint_sha256,
    )
    return _digest(_canonical_json_bytes(expectation.model_dump(mode="json"))), expectation


def _secret_material_commitment(
    lease: SecretMaterialLease,
    capability_policy: SecretCapabilityPolicyV1,
    handling_policy: SecretHandlingPolicyV1,
    *,
    recheck: bool,
) -> tuple[str, SecretMaterialExpectationV1]:
    method = _safe_call(lambda: getattr(lease, "recheck" if recheck else "inspect"))
    if method is _SAFE_CALL_FAILURE or not callable(method):
        raise AuthorizationError("secret_material_provenance")
    value = _safe_call(lambda: method(capability_policy, handling_policy))
    if value is _SAFE_CALL_FAILURE or type(value) is not SecretMaterialProvenance:
        raise AuthorizationError("secret_material_provenance")
    provenance = value
    if (
        type(provenance.provider_identity_sha256) is not str
        or type(provenance.capability_fingerprint_sha256) is not str
        or provenance.provider_identity_sha256 != capability_policy.provider_identity_sha256
        or provenance.capability_fingerprint_sha256
        != capability_policy.capability_fingerprint_sha256
    ):
        raise AuthorizationError("secret_material_provenance")
    expectation = SecretMaterialExpectationV1(
        provider_identity_sha256=provenance.provider_identity_sha256,
        capability_fingerprint_sha256=provenance.capability_fingerprint_sha256,
        secret_handling_policy_sha256=canonical_sha256(handling_policy),
    )
    return _digest(_canonical_json_bytes(expectation.model_dump(mode="json"))), expectation


def _secret_delivery_commitment(
    lease: SecretMaterialLease,
    request: SecretDeliveryRequestV1,
    capability_policy: SecretCapabilityPolicyV1,
    *,
    recheck: bool,
) -> str:
    """Require the opaque lease to bind the exact signed slots and session."""

    method = _safe_call(
        lambda: getattr(lease, "recheck_delivery" if recheck else "inspect_delivery")
    )
    if method is _SAFE_CALL_FAILURE or not callable(method):
        raise AuthorizationError("secret_delivery_provenance")
    value = _safe_call(lambda: method(request))
    if value is _SAFE_CALL_FAILURE or type(value) is not SecretDeliveryProvenance:
        raise AuthorizationError("secret_delivery_provenance")
    provenance = value
    if (
        type(provenance.request_nonce_sha256) is not str
        or type(provenance.channel_binding_sha256) is not str
        or type(provenance.session_binding_sha256) is not str
        or type(provenance.capability_fingerprint_sha256) is not str
        or provenance.request_nonce_sha256 != request.request_nonce_sha256
        or provenance.channel_binding_sha256 != request.channel_binding_sha256
        or provenance.session_binding_sha256 != request.session_binding_sha256
        or provenance.capability_fingerprint_sha256
        != capability_policy.capability_fingerprint_sha256
    ):
        raise AuthorizationError("secret_delivery_provenance")
    return _digest(
        _canonical_json_bytes(
            {
                "capability_fingerprint_sha256": provenance.capability_fingerprint_sha256,
                "channel_binding_sha256": provenance.channel_binding_sha256,
                "request_nonce_sha256": provenance.request_nonce_sha256,
                "session_binding_sha256": provenance.session_binding_sha256,
            }
        )
    )


def _remote_executor_session_commitment(
    lease: RemoteExecutorSessionLease,
    intent: StartRuntimeIntentV2,
    executor: ExecutorControlPolicyV1,
    *,
    recheck: bool,
) -> str:
    """Pin a forced-command remote session to one signed start request."""

    method = _safe_call(lambda: getattr(lease, "recheck" if recheck else "inspect"))
    if method is _SAFE_CALL_FAILURE or not callable(method):
        raise AuthorizationError("remote_executor_session_provenance")
    value = _safe_call(lambda: method(intent))
    if value is _SAFE_CALL_FAILURE or type(value) is not RemoteExecutorSessionProvenance:
        raise AuthorizationError("remote_executor_session_provenance")
    provenance = value
    request = intent.delivery_request
    if (
        type(provenance.executor_id) is not str
        or type(provenance.host_fingerprint_sha256) is not str
        or type(provenance.channel_binding_sha256) is not str
        or type(provenance.session_binding_sha256) is not str
        or type(provenance.attestation_key_fingerprint_sha256) is not str
        or provenance.executor_id != executor.executor.executor_id
        or provenance.host_fingerprint_sha256 != executor.executor.host_fingerprint_sha256
        or provenance.channel_binding_sha256 != request.channel_binding_sha256
        or provenance.session_binding_sha256 != request.session_binding_sha256
        or provenance.attestation_key_fingerprint_sha256
        != executor.executor.attestation_public_key_fingerprint_sha256
    ):
        raise AuthorizationError("remote_executor_session_provenance")
    return _digest(
        _canonical_json_bytes(
            {
                "attestation_key_fingerprint_sha256": provenance.attestation_key_fingerprint_sha256,
                "channel_binding_sha256": provenance.channel_binding_sha256,
                "executor_id": provenance.executor_id,
                "host_fingerprint_sha256": provenance.host_fingerprint_sha256,
                "session_binding_sha256": provenance.session_binding_sha256,
            }
        )
    )


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


def _check_allocation_execution_stability(
    journal: SQLiteAllocationJournal,
    journal_pin: _AllocationJournalExecutionPin,
    intent: _VerifiedAllocationIntent,
    artifact_lease: ArtifactRootLease,
    operation_lease: _OperationLease,
) -> None:
    artifact_lease.assert_stable()
    operation_lease.assert_stable()
    journal._assert_pinned_execution_identity(journal_pin)
    journal.assert_intent(intent)


def _check_observed_stage_stability(
    journal: SQLiteAllocationJournal,
    journal_pin: _AllocationJournalExecutionPin,
    intent: _VerifiedAllocationIntent,
) -> None:
    """Keep the completed allocation stage pinned through an observed effect."""

    journal._assert_pinned_execution_identity(journal_pin)
    journal.assert_intent(intent)
    state = journal.operation_state(intent.intent.allocation_operation_id)
    if (
        type(state) is not AllocationOperationState
        or state.value != AllocationOperationState.ALLOCATED.value
    ):
        raise AuthorizationError("allocation_operation_state")


def _require_current_allocation_journal(status: AllocationJournalStatus) -> None:
    if (
        type(status) is AllocationJournalStatus
        and status.value == AllocationJournalStatus.CURRENT.value
    ):
        return
    phases = {
        AllocationJournalStatus.ABSENT: "allocation_journal_absent",
        AllocationJournalStatus.PROVISIONING_INCOMPLETE: "allocation_incomplete",
        AllocationJournalStatus.ABANDONED: "allocation_journal_abandoned",
        AllocationJournalStatus.JOURNAL_MISSING: "allocation_journal_missing",
        AllocationJournalStatus.IDENTITY_MISMATCH: "allocation_journal_identity_mismatch",
        AllocationJournalStatus.UNKNOWN: "allocation_journal_schema",
    }
    raise AuthorizationError(phases[status])


def _verify_allocation_intent_binding(
    verified: _VerifiedAllocationIntent,
    *,
    journal: SQLiteAllocationJournal,
    replay_policy: ReplayAuthorityPolicyV1,
) -> None:
    if (
        type(verified) is not _VerifiedAllocationIntent
        or verified.capability is not _ALLOCATION_INTENT_CAPABILITY
        or type(journal) is not SQLiteAllocationJournal
        or type(replay_policy) is not ReplayAuthorityPolicyV1
    ):
        raise AuthorizationError("allocation_intent_binding")
    intent = verified.intent
    if (
        intent.journal_path != str(journal._path)
        or intent.journal_path_sha256 != journal._path_sha256()
        or intent.journal_schema_sha256 != journal.journal_schema_sha256()
        or intent.replay_policy_sha256 != replay_policy.sha256()
    ):
        raise AuthorizationError("allocation_intent_binding")


def _require_tls_termination_profile(profile: object) -> None:
    """Keep TLS profiles outside every current create and effect boundary."""

    if (
        type(profile) is not DisposableTransportProfile
        or profile.value == DisposableTransportProfile.TLS_VERIFIED.value
    ):
        raise AuthorizationError("tls_termination_amendment_required")


def _require_tls_termination_amendment(
    intent: AllocationIntentV2,
) -> AllocationIntentV2:
    """Return canonical non-TLS intent at an effect boundary."""

    canonical = _canonical_allocation_intent(intent)
    _require_tls_termination_profile(canonical.plan.transport.profile)
    return canonical


def _require_signed_non_tls_allocation_intent(
    intent: AllocationIntentV2,
    *,
    signer: TrustedEd25519SignerV1,
) -> AllocationIntentV2:
    """Validate a supplied stage intent before a mutating boundary opens files.

    The public journal/effect APIs intentionally require the signed initial
    intent again even though a matching immutable copy is later read under the
    artifact lease.  This gives unsupported TLS a true zero-side-effect path:
    no root lock, journal file, replay claim, provider lease, or callback can
    be reached before the canonical type, signature, and transport profile are
    rejected.
    """

    canonical = _canonical_allocation_intent(intent)
    _verify_allocation_intent_signature(canonical, signer=signer)
    _require_tls_termination_profile(canonical.plan.transport.profile)
    return canonical


def _require_signed_non_tls_materialization_intent(
    intent: MaterializationIntentV1,
    *,
    allocation_intent: AllocationIntentV2,
    signer: TrustedEd25519SignerV1,
) -> MaterializationIntentV1:
    """Validate the post-allocation authority before it can touch the root."""

    _require_signed_non_tls_allocation_intent(allocation_intent, signer=signer)
    canonical = _canonical_materialization_intent(intent)
    _verify_materialization_intent_signature(canonical, signer=signer)
    if canonical.allocation_intent_sha256 != allocation_intent_sha256(allocation_intent):
        raise AuthorizationError("materialization_intent_binding")
    return canonical


def _require_signed_non_tls_start_runtime_intent(
    intent: StartRuntimeIntentV2,
    *,
    allocation_intent: AllocationIntentV2,
    signer: TrustedEd25519SignerV1,
) -> StartRuntimeIntentV2:
    """Validate a fresh start authority before it can create a lock or claim.

    The allocation intent is deliberately reverified first, so a raw string,
    subclass, or model-constructed TLS profile can never reach a provider,
    replay authority, artifact root, or remote-session adapter through this
    later mutation path.
    """

    _require_signed_non_tls_allocation_intent(allocation_intent, signer=signer)
    try:
        canonical = strict_canonical_start_runtime_intent(intent)
    except (TypeError, ValueError, ValidationError):
        raise AuthorizationError("start_runtime_intent_signature") from None
    _verify_start_runtime_intent_signature(canonical, signer=signer)
    if canonical.provider_references != allocation_intent.provider_references:
        raise AuthorizationError("start_runtime_intent_binding")
    return canonical


def _provision_allocation_journal(
    paths: AuthorizationPaths,
    *,
    signer: TrustedEd25519SignerV1,
    expected_disposal_owner: str,
    expected_approver_identity: str,
    journal: SQLiteAllocationJournal,
    intent: AllocationIntentV2,
    executor_control_policy: ExecutorControlPolicyV1,
    postgres_control_policy: PostgreSQLControlPolicyV1,
    replay_authority: ProtocolReplayAuthority,
    replay_policy: ReplayAuthorityPolicyV1,
    replay_policy_artifact: ReplayAuthorityPolicyArtifactV1,
) -> AllocationJournalProvisioningReceiptV1:
    """Explicit create-once allocation journal provisioning from a signed intent."""

    if (
        type(paths) is not AuthorizationPaths
        or type(signer) is not TrustedEd25519SignerV1
        or type(journal) is not SQLiteAllocationJournal
        or type(intent) is not AllocationIntentV2
        or type(executor_control_policy) is not ExecutorControlPolicyV1
        or type(postgres_control_policy) is not PostgreSQLControlPolicyV1
        or type(replay_policy) is not ReplayAuthorityPolicyV1
        or type(replay_policy_artifact) is not ReplayAuthorityPolicyArtifactV1
    ):
        raise AuthorizationError("allocation_journal_genesis")
    intent = _require_signed_non_tls_allocation_intent(intent, signer=signer)
    executor_control_policy = cast(
        ExecutorControlPolicyV1,
        _canonical_artifact_model(
            executor_control_policy,
            ExecutorControlPolicyV1,
            phase="executor_control_policy_artifact",
        ),
    )
    postgres_control_policy = cast(
        PostgreSQLControlPolicyV1,
        _canonical_artifact_model(
            postgres_control_policy,
            PostgreSQLControlPolicyV1,
            phase="postgres_control_policy_artifact",
        ),
    )
    _verify_allocation_control_policy_bindings(
        intent=intent,
        executor=executor_control_policy,
        postgres=postgres_control_policy,
        signer=signer,
    )
    replay_policy = cast(
        ReplayAuthorityPolicyV1,
        _canonical_artifact_model(
            replay_policy,
            ReplayAuthorityPolicyV1,
            phase="replay_authority_policy",
        ),
    )
    replay_policy_artifact = cast(
        ReplayAuthorityPolicyArtifactV1,
        _canonical_artifact_model(
            replay_policy_artifact,
            ReplayAuthorityPolicyArtifactV1,
            phase="replay_policy_artifact",
        ),
    )
    _replay_claim_method(replay_authority)
    now = _system_utc_clock()
    replay_policy_verified = _safe_call(
        lambda: verify_replay_authority_policy_artifact(
            replay_policy_artifact,
            signer=signer,
            allocation_intent=intent,
            expected_policy_sha256=replay_policy.sha256(),
        )
    )
    if replay_policy_verified is _SAFE_CALL_FAILURE:
        raise AuthorizationError("replay_policy_artifact")
    try:
        created = datetime.fromisoformat(intent.created_at.removesuffix("Z") + "+00:00")
        retained = datetime.fromisoformat(intent.retention_expires_at.removesuffix("Z") + "+00:00")
    except ValueError:
        raise AuthorizationError("allocation_intent_freshness") from None
    if (
        created.tzinfo is None
        or retained.tzinfo is None
        or created.astimezone(UTC) > now
        or now - created.astimezone(UTC) > _STAGE_ATTESTATION_FRESHNESS
        or retained.astimezone(UTC) <= now
        or intent.disposal_owner != expected_disposal_owner
        or intent.approver_identity != expected_approver_identity
    ):
        raise AuthorizationError("allocation_intent_freshness")
    verified = _VerifiedAllocationIntent(
        intent=intent,
        intent_sha256=allocation_intent_sha256(intent),
        capability=_ALLOCATION_INTENT_CAPABILITY,
    )
    _verify_allocation_intent_binding(verified, journal=journal, replay_policy=replay_policy)
    with ArtifactRootLease(paths.root) as artifact_lease:
        artifact_lease.assert_stable()
        journal_status = journal.migration_status()
        if (
            type(journal_status) is not AllocationJournalStatus
            or journal_status.value != AllocationJournalStatus.ABSENT.value
        ):
            raise AuthorizationError("allocation_journal_replayed")
        artifact_lease.assert_absent(
            paths.allocation_intent_name(), phase="allocation_journal_replayed"
        )
        artifact_lease.assert_absent(
            paths.allocation_receipt_name(), phase="allocation_journal_replayed"
        )
        artifact_lease.write_once_or_require_exact(
            paths.executor_control_policy_name(),
            _signed_model_artifact_bytes(
                executor_control_policy, phase="executor_control_policy_artifact"
            ),
            phase="executor_control_policy_artifact",
        )
        artifact_lease.write_once_or_require_exact(
            paths.postgres_control_policy_name(),
            _signed_model_artifact_bytes(
                postgres_control_policy, phase="postgres_control_policy_artifact"
            ),
            phase="postgres_control_policy_artifact",
        )
        persisted_controls, persisted_control_raw = _read_allocation_control_policies(
            paths,
            intent=intent,
            signer=signer,
            reader=artifact_lease.reader(),
        )
        if (
            persisted_controls.executor != executor_control_policy
            or persisted_controls.postgres != postgres_control_policy
            or not hmac.compare_digest(
                persisted_control_raw[paths.executor_control_policy_name()],
                _signed_model_artifact_bytes(
                    executor_control_policy, phase="executor_control_policy_artifact"
                ),
            )
            or not hmac.compare_digest(
                persisted_control_raw[paths.postgres_control_policy_name()],
                _signed_model_artifact_bytes(
                    postgres_control_policy, phase="postgres_control_policy_artifact"
                ),
            )
        ):
            raise AuthorizationError("allocation_control_policy_artifact")
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
            allocation_intent=intent,
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
            _allocation_genesis_tombstone(replay_policy, verified),
            phase="allocation_journal_replayed",
        )
        artifact_lease.assert_stable()
        artifact_lease.write_once(
            paths.allocation_intent_name(),
            _allocation_intent_artifact_bytes(intent),
            phase="allocation_journal_replayed",
        )
        journal._complete_verified_intent(verified)
        journal.assert_intent(verified)
        artifact_lease.assert_stable()
    return AllocationJournalProvisioningReceiptV1(
        schema_version="rsd.allocation-journal-provisioning-receipt.v1",
        status="provisioned",
        operation_kind=_ALLOCATION_OPERATION_KIND,
        allocation_operation_id=intent.allocation_operation_id,
        journal_uuid=intent.journal_uuid,
        allocation_intent_sha256=verified.intent_sha256,
        provisioned_at=now.isoformat(timespec="seconds").replace("+00:00", "Z"),
    )


def provision_allocation_journal(
    paths: AuthorizationPaths,
    *,
    signer: TrustedEd25519SignerV1,
    expected_disposal_owner: str,
    expected_approver_identity: str,
    journal: SQLiteAllocationJournal,
    intent: AllocationIntentV2,
    executor_control_policy: ExecutorControlPolicyV1,
    postgres_control_policy: PostgreSQLControlPolicyV1,
    replay_authority: ProtocolReplayAuthority,
    replay_policy: ReplayAuthorityPolicyV1,
    replay_policy_artifact: ReplayAuthorityPolicyArtifactV1,
) -> AllocationJournalProvisioningReceiptV1:
    """Provision the separate pre-creation journal exactly once."""

    return _provision_allocation_journal(
        paths,
        signer=signer,
        expected_disposal_owner=expected_disposal_owner,
        expected_approver_identity=expected_approver_identity,
        journal=journal,
        intent=intent,
        executor_control_policy=executor_control_policy,
        postgres_control_policy=postgres_control_policy,
        replay_authority=replay_authority,
        replay_policy=replay_policy,
        replay_policy_artifact=replay_policy_artifact,
    )


def _mark_allocation_effect_ambiguous(
    journal: SQLiteAllocationJournal, verified: _VerifiedAllocation
) -> None:
    if _safe_call(lambda: journal._fail_effect(verified)) is _SAFE_CALL_FAILURE:
        raise AuthorizationError("initial_effect_failed_recovery_required")


def _run_allocation_authorization(
    paths: AuthorizationPaths,
    *,
    signer: TrustedEd25519SignerV1,
    allocation_intent: AllocationIntentV2,
    provider: ProviderProvenanceAdapter,
    expected_disposal_owner: str,
    expected_approver_identity: str,
    journal: SQLiteAllocationJournal,
    executor: AllocationExecutor,
    executor_control: ExecutorControlAdapter,
    postgres_control: PostgreSQLControlCapability,
    replay_authority: ProtocolReplayAuthority,
    replay_policy: ReplayAuthorityPolicyV1,
) -> AllocationExecutionReceiptV1:
    """Authorize only the typed isolated-empty pre-observation effect scope."""

    if (
        type(paths) is not AuthorizationPaths
        or type(signer) is not TrustedEd25519SignerV1
        or type(allocation_intent) is not AllocationIntentV2
        or type(journal) is not SQLiteAllocationJournal
        or type(replay_policy) is not ReplayAuthorityPolicyV1
    ):
        raise AuthorizationError("allocation_journal_effect")
    allocation_intent = _require_signed_non_tls_allocation_intent(allocation_intent, signer=signer)
    replay_policy = cast(
        ReplayAuthorityPolicyV1,
        _canonical_artifact_model(
            replay_policy,
            ReplayAuthorityPolicyV1,
            phase="replay_authority_policy",
        ),
    )
    _replay_claim_method(replay_authority)
    with ArtifactRootLease(paths.root) as artifact_lease:
        artifact_lease.assert_stable()
        _require_current_allocation_journal(journal.migration_status())
        verified_intent, initial_raw = _read_verified_allocation_intent(
            paths,
            signer=signer,
            expected_disposal_owner=expected_disposal_owner,
            expected_approver_identity=expected_approver_identity,
            now=_system_utc_clock(),
            reader=artifact_lease.reader(),
        )
        _verify_allocation_intent_binding(
            verified_intent, journal=journal, replay_policy=replay_policy
        )
        if verified_intent.intent != allocation_intent:
            raise AuthorizationError("allocation_intent_binding")
        verified_intent = _VerifiedAllocationIntent(
            intent=_require_tls_termination_amendment(verified_intent.intent),
            intent_sha256=verified_intent.intent_sha256,
            capability=_ALLOCATION_INTENT_CAPABILITY,
        )
        replay_artifact, replay_raw = _read_replay_policy_artifact(
            paths,
            signer=signer,
            allocation_intent=verified_intent.intent,
            replay_policy=replay_policy,
            reader=artifact_lease.reader(),
        )
        controls, control_snapshot = _read_allocation_control_policies(
            paths,
            intent=verified_intent.intent,
            signer=signer,
            reader=artifact_lease.reader(),
        )
        fingerprints, material_snapshot = _trusted_provider_fingerprints(
            signer=signer,
            allocation_intent=verified_intent.intent,
            expected_disposal_owner=expected_disposal_owner,
            expected_approver_identity=expected_approver_identity,
            now=_system_utc_clock(),
            reader=artifact_lease.reader(),
        )
        journal.assert_intent(verified_intent)
        journal_pin = journal._pin_execution_identity()
        artifact_lease.assert_absent(
            paths.allocation_receipt_name(), phase="allocation_operation_replayed"
        )
        references = verified_intent.intent.provider_references.all()
        manager, provider_lease = _acquire_provider_lease(provider, references)
        executor_manager: object | None = None
        postgres_manager: object | None = None
        released = True
        executor_released = True
        postgres_released = True
        execution_receipt: AllocationExecutionReceiptV1 | None = None
        try:
            executor_manager, executor_lease = _acquire_control_lease(
                executor_control, controls.executor, phase="executor_control_provenance"
            )
            postgres_manager, postgres_lease = _acquire_control_lease(
                postgres_control, controls.postgres, phase="postgres_control_provenance"
            )
            initial_provider_sha256, expectations = _provider_commitment(
                references=references,
                lease=provider_lease,
                fingerprints=fingerprints,
                recheck=False,
            )
            initial_executor_sha256, executor_expectation = _executor_control_commitment(
                cast(ExecutorControlLease, executor_lease), controls.executor, recheck=False
            )
            initial_postgres_sha256, postgres_expectation = _postgres_control_commitment(
                cast(PostgreSQLControlLease, postgres_lease), controls.postgres, recheck=False
            )
            artifact_lease.assert_stable()
            journal._assert_pinned_execution_identity(journal_pin)
            repeated_intent, repeated_raw = _read_verified_allocation_intent(
                paths,
                signer=signer,
                expected_disposal_owner=expected_disposal_owner,
                expected_approver_identity=expected_approver_identity,
                now=_system_utc_clock(),
                reader=artifact_lease.reader(),
            )
            if repeated_intent != verified_intent or repeated_raw != initial_raw:
                raise AuthorizationError("allocation_artifact_race")
            repeated_replay_artifact, repeated_replay_raw = _read_replay_policy_artifact(
                paths,
                signer=signer,
                allocation_intent=repeated_intent.intent,
                replay_policy=replay_policy,
                reader=artifact_lease.reader(),
            )
            if repeated_replay_artifact != replay_artifact or repeated_replay_raw != replay_raw:
                raise AuthorizationError("allocation_artifact_race")
            repeated_controls, repeated_control_snapshot = _read_allocation_control_policies(
                paths,
                intent=repeated_intent.intent,
                signer=signer,
                reader=artifact_lease.reader(),
            )
            if controls != repeated_controls or control_snapshot != repeated_control_snapshot:
                raise AuthorizationError("allocation_artifact_race")
            repeated_fingerprints, repeated_material_snapshot = _trusted_provider_fingerprints(
                signer=signer,
                allocation_intent=repeated_intent.intent,
                expected_disposal_owner=expected_disposal_owner,
                expected_approver_identity=expected_approver_identity,
                now=_system_utc_clock(),
                reader=artifact_lease.reader(),
            )
            if (
                repeated_fingerprints != fingerprints
                or repeated_material_snapshot != material_snapshot
            ):
                raise AuthorizationError("allocation_artifact_race")
            final_provider_sha256, final_expectations = _provider_commitment(
                references=references,
                lease=provider_lease,
                fingerprints=fingerprints,
                recheck=True,
            )
            final_executor_sha256, final_executor_expectation = _executor_control_commitment(
                cast(ExecutorControlLease, executor_lease), controls.executor, recheck=True
            )
            final_postgres_sha256, final_postgres_expectation = _postgres_control_commitment(
                cast(PostgreSQLControlLease, postgres_lease), controls.postgres, recheck=True
            )
            artifact_lease.assert_stable()
            journal._assert_pinned_execution_identity(journal_pin)
            if (
                initial_provider_sha256 != final_provider_sha256
                or expectations != final_expectations
                or initial_executor_sha256 != final_executor_sha256
                or executor_expectation != final_executor_expectation
                or initial_postgres_sha256 != final_postgres_sha256
                or postgres_expectation != final_postgres_expectation
            ):
                raise AuthorizationError("allocation_control_race")
            terminal_fingerprints, terminal_material_snapshot = _trusted_provider_fingerprints(
                signer=signer,
                allocation_intent=verified_intent.intent,
                expected_disposal_owner=expected_disposal_owner,
                expected_approver_identity=expected_approver_identity,
                now=_system_utc_clock(),
                reader=artifact_lease.reader(),
            )
            if (
                terminal_fingerprints != fingerprints
                or terminal_material_snapshot != material_snapshot
            ):
                raise AuthorizationError("allocation_artifact_race")
            authorized_at = _system_utc_clock().isoformat(timespec="seconds").replace("+00:00", "Z")
            context = AllocationExecutionContext(
                operation_kind=_ALLOCATION_OPERATION_KIND,
                operation_scope="allocate_isolated_empty_resources_v2",
                allocation_operation_id=verified_intent.intent.allocation_operation_id,
                intent=verified_intent.intent,
                provider_expectations=final_expectations,
                executor_expectation=final_executor_expectation,
                postgres_control_expectation=final_postgres_expectation,
                allocation_intent_sha256=verified_intent.intent_sha256,
                idempotency_key=_allocation_idempotency_key(
                    allocation_operation_id=verified_intent.intent.allocation_operation_id,
                    intent_sha256=verified_intent.intent_sha256,
                    provider_sha256=final_provider_sha256,
                    executor_sha256=final_executor_sha256,
                    postgres_control_sha256=final_postgres_sha256,
                ),
                provider_provenance_sha256=final_provider_sha256,
                executor_provenance_sha256=final_executor_sha256,
                postgres_control_provenance_sha256=final_postgres_sha256,
            )
            verified = _VerifiedAllocation(
                context=context,
                nonce=secrets.token_hex(16),
                authorized_at=authorized_at,
                capability=_ALLOCATION_VERIFIED_CAPABILITY,
            )
            with journal._operation_lease(context.allocation_operation_id) as operation_lease:
                _check_allocation_execution_stability(
                    journal, journal_pin, verified_intent, artifact_lease, operation_lease
                )
                _claim_replay_tombstone(
                    replay_authority,
                    _allocation_operation_tombstone(replay_policy, verified),
                    phase="allocation_replay_authority_replayed",
                )
                _check_allocation_execution_stability(
                    journal, journal_pin, verified_intent, artifact_lease, operation_lease
                )
                journal._claim_verified(verified)
                journal._begin_effect(verified)
                _check_allocation_execution_stability(
                    journal, journal_pin, verified_intent, artifact_lease, operation_lease
                )
                outcome = _safe_call(
                    lambda: executor.allocate_empty_resources(
                        context,
                        cast(ExecutorControlLease, executor_lease),
                        cast(PostgreSQLControlLease, postgres_lease),
                    )
                )
                if outcome is _SAFE_CALL_FAILURE:
                    _mark_allocation_effect_ambiguous(journal, verified)
                    raise AuthorizationError("allocation_effect_failed_recovery_required")
                effect_receipt = _safe_call(
                    lambda: _validate_allocation_effect_receipt(context, outcome)
                )
                if type(effect_receipt) is not AllocationEffectReceiptV2:
                    _mark_allocation_effect_ambiguous(journal, verified)
                    raise AuthorizationError("allocation_effect_failed_recovery_required")
                post_effect_fingerprints = _safe_call(
                    lambda: _trusted_provider_fingerprints(
                        signer=signer,
                        allocation_intent=verified_intent.intent,
                        expected_disposal_owner=expected_disposal_owner,
                        expected_approver_identity=expected_approver_identity,
                        now=_system_utc_clock(),
                        reader=artifact_lease.reader(),
                    )
                )
                if post_effect_fingerprints is _SAFE_CALL_FAILURE or post_effect_fingerprints != (
                    fingerprints,
                    material_snapshot,
                ):
                    _mark_allocation_effect_ambiguous(journal, verified)
                    raise AuthorizationError("allocation_effect_failed_recovery_required")
                post_effect_executor = _safe_call(
                    lambda: _executor_control_commitment(
                        cast(ExecutorControlLease, executor_lease), controls.executor, recheck=True
                    )
                )
                post_effect_postgres = _safe_call(
                    lambda: _postgres_control_commitment(
                        cast(PostgreSQLControlLease, postgres_lease),
                        controls.postgres,
                        recheck=True,
                    )
                )
                post_effect_controls = _safe_call(
                    lambda: _read_allocation_control_policies(
                        paths,
                        intent=verified_intent.intent,
                        signer=signer,
                        reader=artifact_lease.reader(),
                    )
                )
                if (
                    post_effect_executor != (final_executor_sha256, final_executor_expectation)
                    or post_effect_postgres != (final_postgres_sha256, final_postgres_expectation)
                    or post_effect_controls != (controls, control_snapshot)
                ):
                    _mark_allocation_effect_ambiguous(journal, verified)
                    raise AuthorizationError("allocation_effect_failed_recovery_required")
                stable = _safe_call(
                    lambda: _check_allocation_execution_stability(
                        journal, journal_pin, verified_intent, artifact_lease, operation_lease
                    )
                )
                if stable is _SAFE_CALL_FAILURE:
                    _mark_allocation_effect_ambiguous(journal, verified)
                    raise AuthorizationError("allocation_effect_failed_recovery_required")
                receipt_written = _safe_call(
                    lambda: artifact_lease.write_once(
                        paths.allocation_receipt_name(),
                        _allocation_receipt_artifact_bytes(effect_receipt),
                        phase="allocation_effect_failed_recovery_required",
                    )
                )
                if receipt_written is _SAFE_CALL_FAILURE:
                    _mark_allocation_effect_ambiguous(journal, verified)
                    raise AuthorizationError("allocation_effect_failed_recovery_required")
                stable_before_commit = _safe_call(
                    lambda: _check_allocation_execution_stability(
                        journal, journal_pin, verified_intent, artifact_lease, operation_lease
                    )
                )
                if stable_before_commit is _SAFE_CALL_FAILURE:
                    _mark_allocation_effect_ambiguous(journal, verified)
                    raise AuthorizationError("allocation_effect_failed_recovery_required")
                committed = _safe_call(lambda: journal._commit_effect(verified, effect_receipt))
                if committed is _SAFE_CALL_FAILURE:
                    _mark_allocation_effect_ambiguous(journal, verified)
                    raise AuthorizationError("allocation_effect_failed_recovery_required")
                terminal_stable = _safe_call(
                    lambda: _check_allocation_execution_stability(
                        journal, journal_pin, verified_intent, artifact_lease, operation_lease
                    )
                )
                if terminal_stable is _SAFE_CALL_FAILURE:
                    raise AuthorizationError("allocation_terminal_stability")
                execution_receipt = AllocationExecutionReceiptV1(
                    schema_version="rsd.allocation-execution-receipt.v2",
                    status="allocated_isolated_empty_resources",
                    operation_kind=_ALLOCATION_OPERATION_KIND,
                    operation_scope="allocate_isolated_empty_resources_v2",
                    allocation_operation_id=context.allocation_operation_id,
                    allocation_intent_sha256=context.allocation_intent_sha256,
                    idempotency_key=context.idempotency_key,
                    effect_receipt_sha256=allocation_effect_receipt_sha256(effect_receipt),
                    allocated_resources_sha256=_digest(
                        _ALLOCATION_EFFECT_RECEIPT_DOMAIN
                        + json.dumps(
                            effect_receipt.allocated_resources.model_dump(mode="json"),
                            sort_keys=True,
                            separators=(",", ":"),
                        ).encode()
                    ),
                    committed_at=authorized_at,
                )
        finally:
            if postgres_manager is not None:
                postgres_released = _release_control_lease(postgres_manager)
            if executor_manager is not None:
                executor_released = _release_control_lease(executor_manager)
            released = _release_provider_lease(manager)
        if not released or not executor_released or not postgres_released:
            raise AuthorizationError("control_release")
        assert execution_receipt is not None
        return execution_receipt


def authorize_allocation_and_execute(
    paths: AuthorizationPaths,
    *,
    signer: TrustedEd25519SignerV1,
    allocation_intent: AllocationIntentV2,
    provider: ProviderProvenanceAdapter,
    expected_disposal_owner: str,
    expected_approver_identity: str,
    journal: SQLiteAllocationJournal,
    executor: AllocationExecutor,
    executor_control: ExecutorControlAdapter,
    postgres_control: PostgreSQLControlCapability,
    replay_authority: ProtocolReplayAuthority,
    replay_policy: ReplayAuthorityPolicyV1,
) -> AllocationExecutionReceiptV1:
    """Use the trusted system clock for the sole allocation boundary."""

    return _run_allocation_authorization(
        paths,
        signer=signer,
        allocation_intent=allocation_intent,
        provider=provider,
        expected_disposal_owner=expected_disposal_owner,
        expected_approver_identity=expected_approver_identity,
        journal=journal,
        executor=executor,
        executor_control=executor_control,
        postgres_control=postgres_control,
        replay_authority=replay_authority,
        replay_policy=replay_policy,
    )


def _mark_materialization_effect_ambiguous(
    journal: SQLiteAllocationJournal, verified: _VerifiedMaterialization
) -> None:
    if _safe_call(lambda: journal._fail_materialization_effect(verified)) is _SAFE_CALL_FAILURE:
        raise AuthorizationError("materialization_effect_failed_recovery_required")


def _mark_start_runtime_effect_ambiguous(
    journal: SQLiteAllocationJournal, verified: _VerifiedStartRuntime
) -> None:
    if _safe_call(lambda: journal._fail_start_runtime_effect(verified)) is _SAFE_CALL_FAILURE:
        raise AuthorizationError("start_runtime_effect_failed_recovery_required")


def _check_materialization_execution_stability(
    journal: SQLiteAllocationJournal,
    journal_pin: _AllocationJournalExecutionPin,
    allocation: _VerifiedAllocationIntent,
    materialization_intent: MaterializationIntentV1,
    materialization_receipt: MaterializationEffectReceiptV1,
    artifact_lease: ArtifactRootLease,
    operation_lease: _OperationLease,
) -> None:
    """Keep every allocation/materialization predecessor pinned through a start."""

    _check_allocation_execution_stability(
        journal, journal_pin, allocation, artifact_lease, operation_lease
    )
    journal.assert_committed_materialization_stage(materialization_intent, materialization_receipt)


def _run_materialization_authorization(
    paths: AuthorizationPaths,
    *,
    signer: TrustedEd25519SignerV1,
    allocation_intent: AllocationIntentV2,
    materialization_intent: MaterializationIntentV1,
    secret_capability_policy: SecretCapabilityPolicyV1,
    secret_handling_policy: SecretHandlingPolicyV1,
    provider: ProviderProvenanceAdapter,
    expected_disposal_owner: str,
    expected_approver_identity: str,
    journal: SQLiteAllocationJournal,
    executor: MaterializationExecutor,
    executor_control: ExecutorControlAdapter,
    postgres_login_transition: PostgreSQLLoginTransitionCapability,
    secret_material: SecretMaterialCapability,
    replay_authority: ProtocolReplayAuthority,
    replay_policy: ReplayAuthorityPolicyV1,
) -> MaterializationExecutionReceiptV1:
    """Authorize exactly one secret-lease-backed runtime materialization.

    This is intentionally the only public admission path that can hand an
    opaque material lease to the future executor.  It does not construct a
    raw mapping, process environment, command line, file, or receipt value.
    """

    if (
        type(paths) is not AuthorizationPaths
        or type(signer) is not TrustedEd25519SignerV1
        or type(allocation_intent) is not AllocationIntentV2
        or type(materialization_intent) is not MaterializationIntentV1
        or type(secret_capability_policy) is not SecretCapabilityPolicyV1
        or type(secret_handling_policy) is not SecretHandlingPolicyV1
        or type(journal) is not SQLiteAllocationJournal
        or type(replay_policy) is not ReplayAuthorityPolicyV1
    ):
        raise AuthorizationError("materialization_journal_effect")
    allocation_intent = _require_signed_non_tls_allocation_intent(allocation_intent, signer=signer)
    materialization_intent = _require_signed_non_tls_materialization_intent(
        materialization_intent,
        allocation_intent=allocation_intent,
        signer=signer,
    )
    secret_capability_policy = cast(
        SecretCapabilityPolicyV1,
        _canonical_artifact_model(
            secret_capability_policy,
            SecretCapabilityPolicyV1,
            phase="secret_capability_policy_artifact",
        ),
    )
    secret_handling_policy = cast(
        SecretHandlingPolicyV1,
        _canonical_artifact_model(
            secret_handling_policy,
            SecretHandlingPolicyV1,
            phase="secret_handling_policy_artifact",
        ),
    )
    _verify_secret_capability_policy_signature(secret_capability_policy, signer=signer)
    _verify_secret_handling_policy_signature(secret_handling_policy, signer=signer)
    replay_policy = cast(
        ReplayAuthorityPolicyV1,
        _canonical_artifact_model(
            replay_policy,
            ReplayAuthorityPolicyV1,
            phase="replay_authority_policy",
        ),
    )
    _replay_claim_method(replay_authority)
    with ArtifactRootLease(paths.root) as artifact_lease:
        artifact_lease.assert_stable()
        _require_current_allocation_journal(journal.migration_status())
        verified_allocation, _allocation_raw = _read_verified_allocation_intent(
            paths,
            signer=signer,
            expected_disposal_owner=expected_disposal_owner,
            expected_approver_identity=expected_approver_identity,
            now=_system_utc_clock(),
            reader=artifact_lease.reader(),
        )
        if verified_allocation.intent != allocation_intent:
            raise AuthorizationError("allocation_intent_binding")
        _verify_allocation_intent_binding(
            verified_allocation, journal=journal, replay_policy=replay_policy
        )
        allocation_stage, allocation_snapshot = _read_allocation_stage_artifacts(
            paths,
            signer=signer,
            expected_disposal_owner=expected_disposal_owner,
            expected_approver_identity=expected_approver_identity,
            now=_system_utc_clock(),
            reader=artifact_lease.reader(),
        )
        if allocation_stage.intent != verified_allocation.intent:
            raise AuthorizationError("allocation_intent_binding")
        journal.assert_intent(verified_allocation)
        journal_pin = journal._pin_execution_identity()
        _check_observed_stage_stability(journal, journal_pin, verified_allocation)
        journal.assert_committed_allocation_stage(
            verified_allocation,
            allocation_stage.receipt,
            allocation_stage.attestation,
        )
        _replay_artifact, _replay_raw = _read_replay_policy_artifact(
            paths,
            signer=signer,
            allocation_intent=verified_allocation.intent,
            replay_policy=replay_policy,
            reader=artifact_lease.reader(),
        )
        artifact_lease.assert_absent(
            paths.materialization_receipt_name(), phase="materialization_operation_replayed"
        )
        artifact_lease.write_once_or_require_exact(
            paths.materialization_intent_name(),
            _materialization_intent_artifact_bytes(materialization_intent),
            phase="materialization_intent_artifact",
        )
        artifact_lease.write_once_or_require_exact(
            paths.secret_capability_policy_name(),
            _signed_model_artifact_bytes(
                secret_capability_policy, phase="secret_capability_policy_artifact"
            ),
            phase="secret_capability_policy_artifact",
        )
        artifact_lease.write_once_or_require_exact(
            paths.secret_handling_policy_name(),
            _signed_model_artifact_bytes(
                secret_handling_policy, phase="secret_handling_policy_artifact"
            ),
            phase="secret_handling_policy_artifact",
        )
        persisted_intent_model, persisted_intent_raw = _read_canonical_signed_model(
            artifact_lease.reader(),
            name=paths.materialization_intent_name(),
            model_type=MaterializationIntentV1,
            phase="materialization_intent_artifact",
        )
        if type(persisted_intent_model) is not MaterializationIntentV1:
            raise AuthorizationError("materialization_intent_artifact")
        _verify_materialization_intent_signature(persisted_intent_model, signer=signer)
        if persisted_intent_model != materialization_intent or not hmac.compare_digest(
            persisted_intent_raw, _materialization_intent_artifact_bytes(materialization_intent)
        ):
            raise AuthorizationError("materialization_intent_artifact")
        _verify_materialization_intent_chain(
            allocation=allocation_stage,
            intent=persisted_intent_model,
            replay_policy=replay_policy,
            expected_disposal_owner=expected_disposal_owner,
            expected_approver_identity=expected_approver_identity,
            now=_system_utc_clock(),
        )
        fingerprints, material_snapshot = _trusted_provider_fingerprints(
            signer=signer,
            allocation_intent=verified_allocation.intent,
            expected_disposal_owner=expected_disposal_owner,
            expected_approver_identity=expected_approver_identity,
            now=_system_utc_clock(),
            reader=artifact_lease.reader(),
        )
        provider_material_attestation_sha256 = material_snapshot[-1]
        controls, control_snapshot = _read_materialization_control_policies(
            paths,
            allocation_intent=verified_allocation.intent,
            intent=persisted_intent_model,
            provider_material_attestation_sha256=provider_material_attestation_sha256,
            signer=signer,
            now=_system_utc_clock(),
            reader=artifact_lease.reader(),
        )
        if (
            controls.secret_capability != secret_capability_policy
            or controls.handling != secret_handling_policy
        ):
            raise AuthorizationError("materialization_control_policy_artifact")
        references = verified_allocation.intent.provider_references.all()
        provider_manager, provider_lease = _acquire_provider_lease(provider, references)
        executor_manager: object | None = None
        postgres_login_manager: object | None = None
        secret_manager: object | None = None
        provider_released = True
        executor_released = True
        postgres_login_released = True
        secret_released = True
        execution_receipt: MaterializationExecutionReceiptV1 | None = None
        try:
            executor_manager, executor_lease = _acquire_control_lease(
                executor_control, controls.executor, phase="executor_control_provenance"
            )
            postgres_login_manager, postgres_login_lease = _acquire_control_lease(
                postgres_login_transition,
                controls.postgres,
                phase="postgres_login_transition_provenance",
                secondary_policy=persisted_intent_model.postgres_login_transition,
                tertiary_policy=persisted_intent_model.ephemeral_postgres_connection,
            )
            secret_manager, secret_lease = _acquire_control_lease(
                secret_material,
                controls.secret_capability,
                phase="secret_material_provenance",
                secondary_policy=controls.handling,
            )
            initial_provider_sha256, expectations = _provider_commitment(
                references=references,
                lease=provider_lease,
                fingerprints=fingerprints,
                recheck=False,
            )
            initial_executor_sha256, executor_expectation = _executor_control_commitment(
                cast(ExecutorControlLease, executor_lease), controls.executor, recheck=False
            )
            initial_postgres_login_sha256, postgres_login_expectation = (
                _postgres_login_transition_commitment(
                    cast(PostgreSQLLoginTransitionLease, postgres_login_lease),
                    controls.postgres,
                    persisted_intent_model.postgres_login_transition,
                    persisted_intent_model.ephemeral_postgres_connection,
                    recheck=False,
                )
            )
            initial_secret_sha256, secret_expectation = _secret_material_commitment(
                cast(SecretMaterialLease, secret_lease),
                controls.secret_capability,
                controls.handling,
                recheck=False,
            )
            initial_delivery_sha256 = _secret_delivery_commitment(
                cast(SecretMaterialLease, secret_lease),
                persisted_intent_model.secret_delivery_request,
                controls.secret_capability,
                recheck=False,
            )
            artifact_lease.assert_stable()
            journal._assert_pinned_execution_identity(journal_pin)
            repeated_allocation, repeated_allocation_snapshot = _read_allocation_stage_artifacts(
                paths,
                signer=signer,
                expected_disposal_owner=expected_disposal_owner,
                expected_approver_identity=expected_approver_identity,
                now=_system_utc_clock(),
                reader=artifact_lease.reader(),
            )
            repeated_intent_model, repeated_intent_raw = _read_canonical_signed_model(
                artifact_lease.reader(),
                name=paths.materialization_intent_name(),
                model_type=MaterializationIntentV1,
                phase="materialization_intent_artifact",
            )
            if type(repeated_intent_model) is not MaterializationIntentV1:
                raise AuthorizationError("materialization_intent_artifact")
            _verify_materialization_intent_signature(repeated_intent_model, signer=signer)
            repeated_fingerprints, repeated_material_snapshot = _trusted_provider_fingerprints(
                signer=signer,
                allocation_intent=verified_allocation.intent,
                expected_disposal_owner=expected_disposal_owner,
                expected_approver_identity=expected_approver_identity,
                now=_system_utc_clock(),
                reader=artifact_lease.reader(),
            )
            repeated_controls, repeated_control_snapshot = _read_materialization_control_policies(
                paths,
                allocation_intent=verified_allocation.intent,
                intent=persisted_intent_model,
                provider_material_attestation_sha256=provider_material_attestation_sha256,
                signer=signer,
                now=_system_utc_clock(),
                reader=artifact_lease.reader(),
            )
            if (
                allocation_snapshot != repeated_allocation_snapshot
                or allocation_stage != repeated_allocation
                or persisted_intent_model != repeated_intent_model
                or persisted_intent_raw != repeated_intent_raw
                or fingerprints != repeated_fingerprints
                or material_snapshot != repeated_material_snapshot
                or controls != repeated_controls
                or control_snapshot != repeated_control_snapshot
            ):
                raise AuthorizationError("materialization_artifact_race")
            final_provider_sha256, final_expectations = _provider_commitment(
                references=references,
                lease=provider_lease,
                fingerprints=fingerprints,
                recheck=True,
            )
            final_executor_sha256, final_executor_expectation = _executor_control_commitment(
                cast(ExecutorControlLease, executor_lease), controls.executor, recheck=True
            )
            final_postgres_login_sha256, final_postgres_login_expectation = (
                _postgres_login_transition_commitment(
                    cast(PostgreSQLLoginTransitionLease, postgres_login_lease),
                    controls.postgres,
                    persisted_intent_model.postgres_login_transition,
                    persisted_intent_model.ephemeral_postgres_connection,
                    recheck=True,
                )
            )
            final_secret_sha256, final_secret_expectation = _secret_material_commitment(
                cast(SecretMaterialLease, secret_lease),
                controls.secret_capability,
                controls.handling,
                recheck=True,
            )
            final_delivery_sha256 = _secret_delivery_commitment(
                cast(SecretMaterialLease, secret_lease),
                persisted_intent_model.secret_delivery_request,
                controls.secret_capability,
                recheck=True,
            )
            if (
                initial_provider_sha256 != final_provider_sha256
                or expectations != final_expectations
                or initial_executor_sha256 != final_executor_sha256
                or executor_expectation != final_executor_expectation
                or initial_postgres_login_sha256 != final_postgres_login_sha256
                or postgres_login_expectation != final_postgres_login_expectation
                or initial_secret_sha256 != final_secret_sha256
                or secret_expectation != final_secret_expectation
                or initial_delivery_sha256 != final_delivery_sha256
            ):
                raise AuthorizationError("materialization_control_race")
            authorized_at = _system_utc_clock().isoformat(timespec="seconds").replace("+00:00", "Z")
            context = MaterializationExecutionContext(
                operation_kind=_MATERIALIZATION_OPERATION_KIND,
                operation_scope="materialize_and_start_runtime_v1",
                materialization_operation_id=persisted_intent_model.materialization_operation_id,
                intent=persisted_intent_model,
                allocation_attestation=allocation_stage.attestation,
                allocation_attestation_sha256=observed_allocation_attestation_sha256(
                    allocation_stage.attestation
                ),
                provider_expectations=final_expectations,
                executor_expectation=final_executor_expectation,
                executor_attestation_key_id=controls.executor.executor.attestation_key_id,
                executor_attestation_public_key_base64=(
                    controls.executor.executor.attestation_public_key_base64
                ),
                executor_attestation_public_key_fingerprint_sha256=(
                    controls.executor.executor.attestation_public_key_fingerprint_sha256
                ),
                postgres_login_expectation=final_postgres_login_expectation,
                secret_material_expectation=final_secret_expectation,
                secret_handling_policy_sha256=canonical_sha256(controls.handling),
                secret_delivery_request=persisted_intent_model.secret_delivery_request,
                materialization_intent_sha256=materialization_intent_sha256(persisted_intent_model),
                idempotency_key=_materialization_idempotency_key(
                    materialization_operation_id=persisted_intent_model.materialization_operation_id,
                    materialization_intent_sha256=materialization_intent_sha256(
                        persisted_intent_model
                    ),
                    allocation_effect_receipt_sha256=persisted_intent_model.allocation_effect_receipt_sha256,
                    observed_allocation_attestation_sha256=persisted_intent_model.observed_allocation_attestation_sha256,
                    provider_sha256=final_provider_sha256,
                    executor_sha256=final_executor_sha256,
                    postgres_login_sha256=final_postgres_login_sha256,
                    secret_capability_sha256=final_secret_sha256,
                    secret_delivery_sha256=final_delivery_sha256,
                ),
                provider_provenance_sha256=final_provider_sha256,
                executor_provenance_sha256=final_executor_sha256,
                postgres_login_provenance_sha256=final_postgres_login_sha256,
                secret_capability_provenance_sha256=final_secret_sha256,
                secret_delivery_provenance_sha256=final_delivery_sha256,
            )
            verified = _VerifiedMaterialization(
                context=context,
                nonce=secrets.token_hex(16),
                authorized_at=authorized_at,
                capability=_MATERIALIZATION_VERIFIED_CAPABILITY,
            )
            with journal._materialization_operation_lease(
                context.materialization_operation_id
            ) as operation_lease:
                _check_allocation_execution_stability(
                    journal, journal_pin, verified_allocation, artifact_lease, operation_lease
                )
                journal.assert_committed_allocation_stage(
                    verified_allocation,
                    allocation_stage.receipt,
                    allocation_stage.attestation,
                )
                _claim_replay_tombstone(
                    replay_authority,
                    _materialization_operation_tombstone(replay_policy, verified),
                    phase="materialization_replay_authority_replayed",
                )
                _check_allocation_execution_stability(
                    journal, journal_pin, verified_allocation, artifact_lease, operation_lease
                )
                journal._claim_materialization_verified(verified)
                journal._begin_materialization_effect(verified)
                outcome = _safe_call(
                    lambda: executor.materialize_and_start(
                        context,
                        cast(ExecutorControlLease, executor_lease),
                        cast(PostgreSQLLoginTransitionLease, postgres_login_lease),
                        cast(SecretMaterialLease, secret_lease),
                    )
                )
                if outcome is _SAFE_CALL_FAILURE:
                    _mark_materialization_effect_ambiguous(journal, verified)
                    raise AuthorizationError("materialization_effect_failed_recovery_required")
                effect_receipt = _safe_call(
                    lambda: _validate_materialization_effect_receipt(context, outcome)
                )
                if type(effect_receipt) is not MaterializationEffectReceiptV1:
                    _mark_materialization_effect_ambiguous(journal, verified)
                    raise AuthorizationError("materialization_effect_failed_recovery_required")
                post_provider = _safe_call(
                    lambda: _provider_commitment(
                        references=references,
                        lease=provider_lease,
                        fingerprints=fingerprints,
                        recheck=True,
                    )
                )
                post_executor = _safe_call(
                    lambda: _executor_control_commitment(
                        cast(ExecutorControlLease, executor_lease), controls.executor, recheck=True
                    )
                )
                post_secret = _safe_call(
                    lambda: _secret_material_commitment(
                        cast(SecretMaterialLease, secret_lease),
                        controls.secret_capability,
                        controls.handling,
                        recheck=True,
                    )
                )
                post_postgres_login = _safe_call(
                    lambda: _postgres_login_transition_commitment(
                        cast(PostgreSQLLoginTransitionLease, postgres_login_lease),
                        controls.postgres,
                        persisted_intent_model.postgres_login_transition,
                        persisted_intent_model.ephemeral_postgres_connection,
                        recheck=True,
                    )
                )
                post_delivery = _safe_call(
                    lambda: _secret_delivery_commitment(
                        cast(SecretMaterialLease, secret_lease),
                        persisted_intent_model.secret_delivery_request,
                        controls.secret_capability,
                        recheck=True,
                    )
                )
                post_controls = _safe_call(
                    lambda: _read_materialization_control_policies(
                        paths,
                        allocation_intent=verified_allocation.intent,
                        intent=persisted_intent_model,
                        provider_material_attestation_sha256=provider_material_attestation_sha256,
                        signer=signer,
                        now=_system_utc_clock(),
                        reader=artifact_lease.reader(),
                    )
                )
                stable = _safe_call(
                    lambda: _check_allocation_execution_stability(
                        journal, journal_pin, verified_allocation, artifact_lease, operation_lease
                    )
                )
                if (
                    post_provider != (final_provider_sha256, final_expectations)
                    or post_executor != (final_executor_sha256, final_executor_expectation)
                    or post_postgres_login
                    != (final_postgres_login_sha256, final_postgres_login_expectation)
                    or post_secret != (final_secret_sha256, final_secret_expectation)
                    or post_delivery != final_delivery_sha256
                    or post_controls != (controls, control_snapshot)
                    or stable is _SAFE_CALL_FAILURE
                ):
                    _mark_materialization_effect_ambiguous(journal, verified)
                    raise AuthorizationError("materialization_effect_failed_recovery_required")
                receipt_written = _safe_call(
                    lambda: artifact_lease.write_once(
                        paths.materialization_receipt_name(),
                        _materialization_receipt_artifact_bytes(effect_receipt),
                        phase="materialization_effect_failed_recovery_required",
                    )
                )
                if receipt_written is _SAFE_CALL_FAILURE:
                    _mark_materialization_effect_ambiguous(journal, verified)
                    raise AuthorizationError("materialization_effect_failed_recovery_required")
                stable_before_commit = _safe_call(
                    lambda: _check_allocation_execution_stability(
                        journal, journal_pin, verified_allocation, artifact_lease, operation_lease
                    )
                )
                if stable_before_commit is _SAFE_CALL_FAILURE:
                    _mark_materialization_effect_ambiguous(journal, verified)
                    raise AuthorizationError("materialization_effect_failed_recovery_required")
                committed = _safe_call(
                    lambda: journal._commit_materialization_effect(verified, effect_receipt)
                )
                if committed is _SAFE_CALL_FAILURE:
                    _mark_materialization_effect_ambiguous(journal, verified)
                    raise AuthorizationError("materialization_effect_failed_recovery_required")
                execution_receipt = MaterializationExecutionReceiptV1(
                    schema_version="rsd.materialization-execution-receipt.v1",
                    status="materialized_and_started_runtime",
                    operation_kind=_MATERIALIZATION_OPERATION_KIND,
                    operation_scope="materialize_and_start_runtime_v1",
                    materialization_operation_id=context.materialization_operation_id,
                    materialization_intent_sha256=context.materialization_intent_sha256,
                    allocation_operation_id=context.intent.allocation_operation_id,
                    allocation_effect_receipt_sha256=context.intent.allocation_effect_receipt_sha256,
                    observed_allocation_attestation_sha256=context.allocation_attestation_sha256,
                    idempotency_key=context.idempotency_key,
                    effect_receipt_sha256=materialization_effect_receipt_sha256(effect_receipt),
                    committed_at=authorized_at,
                )
        finally:
            if secret_manager is not None:
                secret_released = _release_control_lease(secret_manager)
            if executor_manager is not None:
                executor_released = _release_control_lease(executor_manager)
            if postgres_login_manager is not None:
                postgres_login_released = _release_control_lease(postgres_login_manager)
            provider_released = _release_provider_lease(provider_manager)
        if (
            not provider_released
            or not executor_released
            or not postgres_login_released
            or not secret_released
        ):
            raise AuthorizationError("control_release")
        assert execution_receipt is not None
        return execution_receipt


def authorize_materialization_and_execute(
    paths: AuthorizationPaths,
    *,
    signer: TrustedEd25519SignerV1,
    allocation_intent: AllocationIntentV2,
    materialization_intent: MaterializationIntentV1,
    secret_capability_policy: SecretCapabilityPolicyV1,
    secret_handling_policy: SecretHandlingPolicyV1,
    provider: ProviderProvenanceAdapter,
    expected_disposal_owner: str,
    expected_approver_identity: str,
    journal: SQLiteAllocationJournal,
    executor: MaterializationExecutor,
    executor_control: ExecutorControlAdapter,
    postgres_login_transition: PostgreSQLLoginTransitionCapability,
    secret_material: SecretMaterialCapability,
    replay_authority: ProtocolReplayAuthority,
    replay_policy: ReplayAuthorityPolicyV1,
) -> MaterializationExecutionReceiptV1:
    """Use the internal trusted UTC clock for one post-allocation start."""

    return _run_materialization_authorization(
        paths,
        signer=signer,
        allocation_intent=allocation_intent,
        materialization_intent=materialization_intent,
        secret_capability_policy=secret_capability_policy,
        secret_handling_policy=secret_handling_policy,
        provider=provider,
        expected_disposal_owner=expected_disposal_owner,
        expected_approver_identity=expected_approver_identity,
        journal=journal,
        executor=executor,
        executor_control=executor_control,
        postgres_login_transition=postgres_login_transition,
        secret_material=secret_material,
        replay_authority=replay_authority,
        replay_policy=replay_policy,
    )


def _run_start_runtime_authorization(
    paths: AuthorizationPaths,
    *,
    signer: TrustedEd25519SignerV1,
    allocation_intent: AllocationIntentV2,
    start_runtime_intent: StartRuntimeIntentV2,
    provider: ProviderProvenanceAdapter,
    expected_disposal_owner: str,
    expected_approver_identity: str,
    journal: SQLiteAllocationJournal,
    executor: StartRuntimeExecutor,
    executor_control: ExecutorControlAdapter,
    secret_material: SecretMaterialCapability,
    remote_executor_session: RemoteExecutorSessionCapability,
    replay_authority: ProtocolReplayAuthority,
    replay_policy: ReplayAuthorityPolicyV1,
) -> StartRuntimeExecutionReceiptV2:
    """Authorize one fresh opaque redelivery/start after observed materialization.

    This is intentionally a separate operation from materialization.  It
    cannot allocate resources, install an executor, mutate a PostgreSQL role,
    seed data, restore data, or expose a value.  A successful earlier start is
    never reusable: both its operation ID and delivery request nonce are
    durably and externally claimed before the effect callback runs.
    """

    if (
        type(paths) is not AuthorizationPaths
        or type(signer) is not TrustedEd25519SignerV1
        or type(allocation_intent) is not AllocationIntentV2
        or type(start_runtime_intent) is not StartRuntimeIntentV2
        or type(journal) is not SQLiteAllocationJournal
        or type(replay_policy) is not ReplayAuthorityPolicyV1
    ):
        raise AuthorizationError("start_runtime_journal_effect")
    allocation_intent = _require_signed_non_tls_allocation_intent(allocation_intent, signer=signer)
    start_runtime_intent = _require_signed_non_tls_start_runtime_intent(
        start_runtime_intent,
        allocation_intent=allocation_intent,
        signer=signer,
    )
    replay_policy = cast(
        ReplayAuthorityPolicyV1,
        _canonical_artifact_model(
            replay_policy,
            ReplayAuthorityPolicyV1,
            phase="replay_authority_policy",
        ),
    )
    _replay_claim_method(replay_authority)
    with ArtifactRootLease(paths.root) as artifact_lease:
        artifact_lease.assert_stable()
        _require_current_allocation_journal(journal.migration_status())
        artifact_lease.assert_absent(
            paths.start_runtime_receipt_name(start_runtime_intent.start_operation_id),
            phase="start_runtime_operation_replayed",
        )
        artifact_lease.write_once_or_require_exact(
            paths.start_runtime_intent_name(start_runtime_intent.start_operation_id),
            _signed_model_artifact_bytes(
                start_runtime_intent,
                phase="start_runtime_intent_artifact",
            ),
            phase="start_runtime_intent_artifact",
        )

        def verified_snapshot() -> tuple[
            _ArtifactVerification,
            dict[str, bytes],
            _VerifiedAllocationIntent,
            bytes,
            _AllocationStageArtifacts,
            dict[str, bytes],
            _MaterializationStageArtifacts,
            dict[str, bytes],
            StartRuntimeIntentV2,
            bytes,
            dict[str, str],
            tuple[str, str, str, str, str],
            _MaterializationControlPolicies,
            dict[str, bytes],
            ReplayAuthorityPolicyArtifactV1,
            bytes,
        ]:
            now = _system_utc_clock()
            artifacts, artifact_snapshot = _verify_artifact_snapshot(
                paths,
                signer=signer,
                expected_disposal_owner=expected_disposal_owner,
                expected_approver_identity=expected_approver_identity,
                now=now,
                reader=artifact_lease.reader(),
            )
            verified_allocation, allocation_intent_raw = _read_verified_allocation_intent(
                paths,
                signer=signer,
                expected_disposal_owner=expected_disposal_owner,
                expected_approver_identity=expected_approver_identity,
                now=now,
                reader=artifact_lease.reader(),
            )
            if verified_allocation.intent != allocation_intent:
                raise AuthorizationError("allocation_intent_binding")
            _verify_allocation_intent_binding(
                verified_allocation,
                journal=journal,
                replay_policy=replay_policy,
            )
            allocation, allocation_snapshot = _read_allocation_stage_artifacts(
                paths,
                signer=signer,
                expected_disposal_owner=expected_disposal_owner,
                expected_approver_identity=expected_approver_identity,
                now=now,
                reader=artifact_lease.reader(),
            )
            if allocation.intent != verified_allocation.intent:
                raise AuthorizationError("allocation_intent_binding")
            materialization, materialization_snapshot = _read_materialization_stage_artifacts(
                paths,
                signer=signer,
                expected_disposal_owner=expected_disposal_owner,
                expected_approver_identity=expected_approver_identity,
                now=now,
                reader=artifact_lease.reader(),
                allocation=allocation,
                proposal=artifacts.proposal,
                contract=artifacts.final_contract,
            )
            persisted_start, start_raw = _read_canonical_signed_model(
                artifact_lease.reader(),
                name=paths.start_runtime_intent_name(start_runtime_intent.start_operation_id),
                model_type=StartRuntimeIntentV2,
                phase="start_runtime_intent_artifact",
            )
            if type(persisted_start) is not StartRuntimeIntentV2:
                raise AuthorizationError("start_runtime_intent_artifact")
            _verify_start_runtime_intent_signature(persisted_start, signer=signer)
            fingerprints, material_snapshot = _trusted_provider_fingerprints(
                signer=signer,
                allocation_intent=verified_allocation.intent,
                expected_disposal_owner=expected_disposal_owner,
                expected_approver_identity=expected_approver_identity,
                now=now,
                reader=artifact_lease.reader(),
            )
            controls, control_snapshot = _read_materialization_control_policies(
                paths,
                allocation_intent=verified_allocation.intent,
                intent=materialization.intent,
                provider_material_attestation_sha256=material_snapshot[-1],
                signer=signer,
                now=now,
                reader=artifact_lease.reader(),
            )
            _verify_start_runtime_intent_chain(
                allocation=allocation,
                materialization=materialization,
                intent=persisted_start,
                controls=controls,
                provider_material_attestation_sha256=material_snapshot[-1],
                replay_policy=replay_policy,
                expected_disposal_owner=expected_disposal_owner,
                expected_approver_identity=expected_approver_identity,
                now=now,
            )
            replay_artifact, replay_raw = _read_replay_policy_artifact(
                paths,
                signer=signer,
                allocation_intent=verified_allocation.intent,
                replay_policy=replay_policy,
                reader=artifact_lease.reader(),
            )
            return (
                artifacts,
                artifact_snapshot,
                verified_allocation,
                allocation_intent_raw,
                allocation,
                allocation_snapshot,
                materialization,
                materialization_snapshot,
                persisted_start,
                start_raw,
                fingerprints,
                material_snapshot,
                controls,
                control_snapshot,
                replay_artifact,
                replay_raw,
            )

        snapshot = verified_snapshot()
        (
            artifacts,
            _artifact_snapshot,
            verified_allocation,
            _allocation_intent_raw,
            allocation_stage,
            _allocation_snapshot,
            materialization_stage,
            _materialization_snapshot,
            persisted_start,
            persisted_start_raw,
            fingerprints,
            _material_snapshot,
            controls,
            _control_snapshot,
            _replay_artifact,
            _replay_raw,
        ) = snapshot
        if persisted_start != start_runtime_intent or not hmac.compare_digest(
            persisted_start_raw,
            _signed_model_artifact_bytes(
                start_runtime_intent, phase="start_runtime_intent_artifact"
            ),
        ):
            raise AuthorizationError("start_runtime_intent_artifact")
        journal.assert_intent(verified_allocation)
        journal_pin = journal._pin_execution_identity()
        _check_observed_stage_stability(journal, journal_pin, verified_allocation)
        journal.assert_committed_allocation_stage(
            verified_allocation,
            allocation_stage.receipt,
            allocation_stage.attestation,
        )
        journal.assert_committed_materialization_stage(
            materialization_stage.intent,
            materialization_stage.receipt,
        )
        references = verified_allocation.intent.provider_references.all()
        provider_manager, provider_lease = _acquire_provider_lease(provider, references)
        executor_manager: object | None = None
        secret_manager: object | None = None
        remote_manager: object | None = None
        provider_released = True
        executor_released = True
        secret_released = True
        remote_released = True
        execution_receipt: StartRuntimeExecutionReceiptV2 | None = None
        try:
            executor_manager, executor_lease = _acquire_control_lease(
                executor_control,
                controls.executor,
                phase="executor_control_provenance",
            )
            secret_manager, secret_lease = _acquire_control_lease(
                secret_material,
                controls.secret_capability,
                phase="secret_material_provenance",
                secondary_policy=controls.handling,
            )
            remote_manager, remote_lease = _acquire_control_lease(
                remote_executor_session,
                persisted_start,
                phase="remote_executor_session_provenance",
            )
            initial_provider_sha256, expectations = _provider_commitment(
                references=references,
                lease=provider_lease,
                fingerprints=fingerprints,
                recheck=False,
            )
            initial_executor_sha256, executor_expectation = _executor_control_commitment(
                cast(ExecutorControlLease, executor_lease), controls.executor, recheck=False
            )
            initial_secret_sha256, secret_expectation = _secret_material_commitment(
                cast(SecretMaterialLease, secret_lease),
                controls.secret_capability,
                controls.handling,
                recheck=False,
            )
            initial_delivery_sha256 = _secret_delivery_commitment(
                cast(SecretMaterialLease, secret_lease),
                persisted_start.delivery_request,
                controls.secret_capability,
                recheck=False,
            )
            initial_remote_sha256 = _remote_executor_session_commitment(
                cast(RemoteExecutorSessionLease, remote_lease),
                persisted_start,
                controls.executor,
                recheck=False,
            )
            artifact_lease.assert_stable()
            journal._assert_pinned_execution_identity(journal_pin)
            if verified_snapshot() != snapshot:
                raise AuthorizationError("start_runtime_artifact_race")
            final_provider_sha256, final_expectations = _provider_commitment(
                references=references,
                lease=provider_lease,
                fingerprints=fingerprints,
                recheck=True,
            )
            final_executor_sha256, final_executor_expectation = _executor_control_commitment(
                cast(ExecutorControlLease, executor_lease), controls.executor, recheck=True
            )
            final_secret_sha256, final_secret_expectation = _secret_material_commitment(
                cast(SecretMaterialLease, secret_lease),
                controls.secret_capability,
                controls.handling,
                recheck=True,
            )
            final_delivery_sha256 = _secret_delivery_commitment(
                cast(SecretMaterialLease, secret_lease),
                persisted_start.delivery_request,
                controls.secret_capability,
                recheck=True,
            )
            final_remote_sha256 = _remote_executor_session_commitment(
                cast(RemoteExecutorSessionLease, remote_lease),
                persisted_start,
                controls.executor,
                recheck=True,
            )
            if (
                initial_provider_sha256 != final_provider_sha256
                or expectations != final_expectations
                or initial_executor_sha256 != final_executor_sha256
                or executor_expectation != final_executor_expectation
                or initial_secret_sha256 != final_secret_sha256
                or secret_expectation != final_secret_expectation
                or initial_delivery_sha256 != final_delivery_sha256
                or initial_remote_sha256 != final_remote_sha256
            ):
                raise AuthorizationError("start_runtime_control_race")
            authorized_at = _system_utc_clock().isoformat(timespec="seconds").replace("+00:00", "Z")
            context = StartRuntimeExecutionContext(
                operation_kind=_START_RUNTIME_OPERATION_KIND,
                operation_scope="start_runtime_v2",
                start_operation_id=persisted_start.start_operation_id,
                intent=persisted_start,
                materialization_intent=materialization_stage.intent,
                materialization_receipt=materialization_stage.receipt,
                observed_runtime_attestation=materialization_stage.attestation,
                provider_expectations=final_expectations,
                executor_expectation=final_executor_expectation,
                executor_attestation_key_id=controls.executor.executor.attestation_key_id,
                executor_attestation_public_key_base64=(
                    controls.executor.executor.attestation_public_key_base64
                ),
                executor_attestation_public_key_fingerprint_sha256=(
                    controls.executor.executor.attestation_public_key_fingerprint_sha256
                ),
                secret_material_expectation=final_secret_expectation,
                secret_handling_policy_sha256=canonical_sha256(controls.handling),
                secret_delivery_request=persisted_start.delivery_request,
                start_runtime_intent_sha256=start_runtime_intent_sha256(persisted_start),
                idempotency_key=_start_runtime_idempotency_key(
                    start_operation_id=persisted_start.start_operation_id,
                    start_runtime_intent_sha256=start_runtime_intent_sha256(persisted_start),
                    materialization_effect_receipt_sha256=(
                        persisted_start.materialization_effect_receipt_sha256
                    ),
                    observed_runtime_attestation_sha256=(
                        persisted_start.observed_runtime_attestation_sha256
                    ),
                    provider_sha256=final_provider_sha256,
                    executor_sha256=final_executor_sha256,
                    secret_capability_sha256=final_secret_sha256,
                    secret_delivery_sha256=final_delivery_sha256,
                    remote_session_sha256=final_remote_sha256,
                ),
                proposal_sha256=artifacts.receipt.proposal_sha256,
                contract_sha256=artifacts.receipt.contract_sha256,
                provider_provenance_sha256=final_provider_sha256,
                executor_provenance_sha256=final_executor_sha256,
                secret_capability_provenance_sha256=final_secret_sha256,
                secret_delivery_provenance_sha256=final_delivery_sha256,
                remote_session_provenance_sha256=final_remote_sha256,
            )
            verified = _VerifiedStartRuntime(
                context=context,
                nonce=secrets.token_hex(16),
                authorized_at=authorized_at,
                capability=_START_RUNTIME_VERIFIED_CAPABILITY,
            )
            with journal._start_runtime_operation_lease(
                context.start_operation_id
            ) as operation_lease:
                _check_materialization_execution_stability(
                    journal,
                    journal_pin,
                    verified_allocation,
                    materialization_stage.intent,
                    materialization_stage.receipt,
                    artifact_lease,
                    operation_lease,
                )
                _claim_replay_tombstone(
                    replay_authority,
                    _start_runtime_operation_tombstone(replay_policy, verified),
                    phase="start_runtime_replay_authority_replayed",
                )
                _check_materialization_execution_stability(
                    journal,
                    journal_pin,
                    verified_allocation,
                    materialization_stage.intent,
                    materialization_stage.receipt,
                    artifact_lease,
                    operation_lease,
                )
                journal._claim_start_runtime_verified(verified)
                journal._begin_start_runtime_effect(verified)
                outcome = _safe_call(
                    lambda: executor.start_runtime(
                        context,
                        cast(RemoteExecutorSessionLease, remote_lease),
                        cast(SecretMaterialLease, secret_lease),
                    )
                )
                if outcome is _SAFE_CALL_FAILURE:
                    _mark_start_runtime_effect_ambiguous(journal, verified)
                    raise AuthorizationError("start_runtime_effect_failed_recovery_required")
                effect_receipt = _safe_call(
                    lambda: _validate_start_runtime_effect_receipt(context, outcome)
                )
                if type(effect_receipt) is not StartRuntimeEffectReceiptV2:
                    _mark_start_runtime_effect_ambiguous(journal, verified)
                    raise AuthorizationError("start_runtime_effect_failed_recovery_required")
                post_provider = _safe_call(
                    lambda: _provider_commitment(
                        references=references,
                        lease=provider_lease,
                        fingerprints=fingerprints,
                        recheck=True,
                    )
                )
                post_executor = _safe_call(
                    lambda: _executor_control_commitment(
                        cast(ExecutorControlLease, executor_lease), controls.executor, recheck=True
                    )
                )
                post_secret = _safe_call(
                    lambda: _secret_material_commitment(
                        cast(SecretMaterialLease, secret_lease),
                        controls.secret_capability,
                        controls.handling,
                        recheck=True,
                    )
                )
                post_delivery = _safe_call(
                    lambda: _secret_delivery_commitment(
                        cast(SecretMaterialLease, secret_lease),
                        persisted_start.delivery_request,
                        controls.secret_capability,
                        recheck=True,
                    )
                )
                post_remote = _safe_call(
                    lambda: _remote_executor_session_commitment(
                        cast(RemoteExecutorSessionLease, remote_lease),
                        persisted_start,
                        controls.executor,
                        recheck=True,
                    )
                )
                post_snapshot = _safe_call(verified_snapshot)
                stable = _safe_call(
                    lambda: _check_materialization_execution_stability(
                        journal,
                        journal_pin,
                        verified_allocation,
                        materialization_stage.intent,
                        materialization_stage.receipt,
                        artifact_lease,
                        operation_lease,
                    )
                )
                if (
                    post_provider != (final_provider_sha256, final_expectations)
                    or post_executor != (final_executor_sha256, final_executor_expectation)
                    or post_secret != (final_secret_sha256, final_secret_expectation)
                    or post_delivery != final_delivery_sha256
                    or post_remote != final_remote_sha256
                    or post_snapshot != snapshot
                    or stable is _SAFE_CALL_FAILURE
                ):
                    _mark_start_runtime_effect_ambiguous(journal, verified)
                    raise AuthorizationError("start_runtime_effect_failed_recovery_required")
                receipt_written = _safe_call(
                    lambda: artifact_lease.write_once(
                        paths.start_runtime_receipt_name(context.start_operation_id),
                        _signed_model_artifact_bytes(
                            effect_receipt,
                            phase="start_runtime_effect_failed_recovery_required",
                        ),
                        phase="start_runtime_effect_failed_recovery_required",
                    )
                )
                if receipt_written is _SAFE_CALL_FAILURE:
                    _mark_start_runtime_effect_ambiguous(journal, verified)
                    raise AuthorizationError("start_runtime_effect_failed_recovery_required")
                stable_before_commit = _safe_call(
                    lambda: _check_materialization_execution_stability(
                        journal,
                        journal_pin,
                        verified_allocation,
                        materialization_stage.intent,
                        materialization_stage.receipt,
                        artifact_lease,
                        operation_lease,
                    )
                )
                if stable_before_commit is _SAFE_CALL_FAILURE:
                    _mark_start_runtime_effect_ambiguous(journal, verified)
                    raise AuthorizationError("start_runtime_effect_failed_recovery_required")
                committed = _safe_call(
                    lambda: journal._commit_start_runtime_effect(verified, effect_receipt)
                )
                if committed is _SAFE_CALL_FAILURE:
                    _mark_start_runtime_effect_ambiguous(journal, verified)
                    raise AuthorizationError("start_runtime_effect_failed_recovery_required")
                execution_receipt = StartRuntimeExecutionReceiptV2(
                    schema_version="rsd.start-runtime-execution-receipt.v2",
                    status="started_runtime",
                    operation_kind=_START_RUNTIME_OPERATION_KIND,
                    operation_scope="start_runtime_v2",
                    start_operation_id=context.start_operation_id,
                    start_runtime_intent_sha256=context.start_runtime_intent_sha256,
                    materialization_operation_id=(
                        context.materialization_intent.materialization_operation_id
                    ),
                    materialization_effect_receipt_sha256=(
                        materialization_effect_receipt_sha256(context.materialization_receipt)
                    ),
                    observed_runtime_attestation_sha256=(
                        context.intent.observed_runtime_attestation_sha256
                    ),
                    idempotency_key=context.idempotency_key,
                    effect_receipt_sha256=start_runtime_effect_receipt_sha256(effect_receipt),
                    committed_at=authorized_at,
                )
        finally:
            if remote_manager is not None:
                remote_released = _release_control_lease(remote_manager)
            if secret_manager is not None:
                secret_released = _release_control_lease(secret_manager)
            if executor_manager is not None:
                executor_released = _release_control_lease(executor_manager)
            provider_released = _release_provider_lease(provider_manager)
        if (
            not provider_released
            or not executor_released
            or not secret_released
            or not remote_released
        ):
            raise AuthorizationError("control_release")
        assert execution_receipt is not None
        return execution_receipt


def authorize_start_runtime_and_execute(
    paths: AuthorizationPaths,
    *,
    signer: TrustedEd25519SignerV1,
    allocation_intent: AllocationIntentV2,
    start_runtime_intent: StartRuntimeIntentV2,
    provider: ProviderProvenanceAdapter,
    expected_disposal_owner: str,
    expected_approver_identity: str,
    journal: SQLiteAllocationJournal,
    executor: StartRuntimeExecutor,
    executor_control: ExecutorControlAdapter,
    secret_material: SecretMaterialCapability,
    remote_executor_session: RemoteExecutorSessionCapability,
    replay_authority: ProtocolReplayAuthority,
    replay_policy: ReplayAuthorityPolicyV1,
) -> StartRuntimeExecutionReceiptV2:
    """Use the internal trusted UTC clock for one fresh opaque runtime start."""

    return _run_start_runtime_authorization(
        paths,
        signer=signer,
        allocation_intent=allocation_intent,
        start_runtime_intent=start_runtime_intent,
        provider=provider,
        expected_disposal_owner=expected_disposal_owner,
        expected_approver_identity=expected_approver_identity,
        journal=journal,
        executor=executor,
        executor_control=executor_control,
        secret_material=secret_material,
        remote_executor_session=remote_executor_session,
        replay_authority=replay_authority,
        replay_policy=replay_policy,
    )


def _provision_journal(
    paths: AuthorizationPaths,
    *,
    signer: TrustedEd25519SignerV1,
    expected_disposal_owner: str,
    expected_approver_identity: str,
    journal: SQLiteAuthorizationJournal,
    allocation_journal: SQLiteAllocationJournal,
    allocation_intent: AllocationIntentV2,
    receipt: JournalGenesisReceiptV1,
    replay_authority: ProtocolReplayAuthority,
    replay_policy: ReplayAuthorityPolicyV1,
) -> JournalProvisioningReceiptV1:
    """Explicit one-time journal genesis; never called by authorization/effect paths."""

    if (
        type(paths) is not AuthorizationPaths
        or type(signer) is not TrustedEd25519SignerV1
        or type(journal) is not SQLiteAuthorizationJournal
        or type(allocation_journal) is not SQLiteAllocationJournal
        or type(allocation_intent) is not AllocationIntentV2
        or type(receipt) is not JournalGenesisReceiptV1
        or type(replay_policy) is not ReplayAuthorityPolicyV1
    ):
        raise AuthorizationError("journal_genesis")
    allocation_intent = _require_signed_non_tls_allocation_intent(allocation_intent, signer=signer)
    receipt = cast(
        JournalGenesisReceiptV1,
        _canonical_artifact_model(receipt, JournalGenesisReceiptV1, phase="journal_genesis"),
    )
    replay_policy = cast(
        ReplayAuthorityPolicyV1,
        _canonical_artifact_model(
            replay_policy,
            ReplayAuthorityPolicyV1,
            phase="replay_authority_policy",
        ),
    )
    _replay_claim_method(replay_authority)
    now = _system_utc_clock()
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
        allocation_stage, _ = _read_allocation_stage_artifacts(
            paths,
            signer=signer,
            expected_disposal_owner=expected_disposal_owner,
            expected_approver_identity=expected_approver_identity,
            now=now,
            reader=artifact_lease.reader(),
        )
        if allocation_stage.intent != allocation_intent:
            raise AuthorizationError("allocation_intent_binding")
        verified_allocation_intent = _VerifiedAllocationIntent(
            intent=_require_tls_termination_amendment(allocation_stage.intent),
            intent_sha256=allocation_intent_sha256(allocation_stage.intent),
            capability=_ALLOCATION_INTENT_CAPABILITY,
        )
        _require_current_allocation_journal(allocation_journal.migration_status())
        _verify_allocation_intent_binding(
            verified_allocation_intent,
            journal=allocation_journal,
            replay_policy=replay_policy,
        )
        allocation_journal.assert_intent(verified_allocation_intent)
        initial_state = allocation_journal.operation_state(
            allocation_stage.intent.allocation_operation_id
        )
        if (
            type(initial_state) is not AllocationOperationState
            or initial_state.value != AllocationOperationState.ALLOCATED.value
        ):
            raise AuthorizationError("allocation_operation_state")
        allocation_journal_pin = allocation_journal._pin_execution_identity()
        materialization_stage, _ = _read_materialization_stage_artifacts(
            paths,
            signer=signer,
            expected_disposal_owner=expected_disposal_owner,
            expected_approver_identity=expected_approver_identity,
            now=now,
            reader=artifact_lease.reader(),
            allocation=allocation_stage,
            proposal=artifacts.proposal,
            contract=artifacts.final_contract,
        )
        allocation_journal.assert_committed_allocation_stage(
            verified_allocation_intent,
            allocation_stage.receipt,
            allocation_stage.attestation,
        )
        allocation_journal.assert_committed_materialization_stage(
            materialization_stage.intent,
            materialization_stage.receipt,
        )
        _check_observed_stage_stability(
            allocation_journal,
            allocation_journal_pin,
            verified_allocation_intent,
        )
        # Observed genesis shares the allocation stage's durable, signed replay
        # namespace.  It is never permitted to claim an external tombstone
        # from a transient caller policy object or before that predecessor has
        # committed its isolated-empty creation receipt.
        replay_artifact, replay_raw = _read_replay_policy_artifact(
            paths,
            signer=signer,
            allocation_intent=verified_allocation_intent.intent,
            replay_policy=replay_policy,
            reader=artifact_lease.reader(),
        )
        artifact_lease.assert_stable()
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
        if (
            type(status) is JournalMigrationStatus
            and status.value == JournalMigrationStatus.PROVISIONING_INCOMPLETE.value
        ):
            raise AuthorizationError("provisioning_incomplete")
        if (
            type(status) is not JournalMigrationStatus
            or status.value != JournalMigrationStatus.ABSENT.value
        ):
            raise AuthorizationError("journal_genesis_replayed")
        artifact_lease.assert_absent(paths.journal_genesis_name(), phase="journal_genesis_replayed")
        journal._begin_verified_genesis(verified)
        replay_before_claim, replay_before_claim_raw = _read_replay_policy_artifact(
            paths,
            signer=signer,
            allocation_intent=verified_allocation_intent.intent,
            replay_policy=replay_policy,
            reader=artifact_lease.reader(),
        )
        if replay_before_claim != replay_artifact or replay_before_claim_raw != replay_raw:
            raise AuthorizationError("replay_policy_artifact")
        artifact_lease.assert_stable()
        _check_observed_stage_stability(
            allocation_journal,
            allocation_journal_pin,
            verified_allocation_intent,
        )
        _claim_replay_tombstone(
            replay_authority,
            _genesis_tombstone(replay_policy, verified),
            phase="journal_genesis_replayed",
        )
        replay_after_claim, replay_after_claim_raw = _read_replay_policy_artifact(
            paths,
            signer=signer,
            allocation_intent=verified_allocation_intent.intent,
            replay_policy=replay_policy,
            reader=artifact_lease.reader(),
        )
        if replay_after_claim != replay_artifact or replay_after_claim_raw != replay_raw:
            raise AuthorizationError("replay_policy_artifact")
        artifact_lease.assert_stable()
        _check_observed_stage_stability(
            allocation_journal,
            allocation_journal_pin,
            verified_allocation_intent,
        )
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
    allocation_journal: SQLiteAllocationJournal,
    allocation_intent: AllocationIntentV2,
    receipt: JournalGenesisReceiptV1,
    replay_authority: ProtocolReplayAuthority,
    replay_policy: ReplayAuthorityPolicyV1,
) -> JournalProvisioningReceiptV1:
    """Provision exactly one signed journal identity for the supplied artifacts."""

    return _provision_journal(
        paths,
        signer=signer,
        expected_disposal_owner=expected_disposal_owner,
        expected_approver_identity=expected_approver_identity,
        journal=journal,
        allocation_journal=allocation_journal,
        allocation_intent=allocation_intent,
        receipt=receipt,
        replay_authority=replay_authority,
        replay_policy=replay_policy,
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
    receipt = cast(
        JournalGenesisReconciliationReceiptV1,
        _canonical_artifact_model(
            receipt,
            JournalGenesisReconciliationReceiptV1,
            phase="journal_genesis_reconciliation",
        ),
    )
    return journal.reconcile_genesis(receipt, signer=signer)


def reconcile_allocation_journal_genesis(
    journal: SQLiteAllocationJournal,
    receipt: AllocationJournalGenesisReconciliationReceiptV1,
    *,
    signer: TrustedEd25519SignerV1,
) -> AllocationJournalStatus:
    """Apply signed, non-retrying recovery evidence to initial genesis only."""

    if (
        type(journal) is not SQLiteAllocationJournal
        or type(receipt) is not AllocationJournalGenesisReconciliationReceiptV1
        or type(signer) is not TrustedEd25519SignerV1
    ):
        raise AuthorizationError("allocation_journal_reconciliation")
    receipt = cast(
        AllocationJournalGenesisReconciliationReceiptV1,
        _canonical_artifact_model(
            receipt,
            AllocationJournalGenesisReconciliationReceiptV1,
            phase="allocation_journal_reconciliation",
        ),
    )
    _verify_allocation_journal_genesis_reconciliation_receipt(receipt, signer=signer)
    return journal.reconcile_genesis(receipt)


def _require_current_journal(status: JournalMigrationStatus) -> None:
    if (
        type(status) is JournalMigrationStatus
        and status.value == JournalMigrationStatus.CURRENT.value
    ):
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


def _run_observed_authorization(
    paths: AuthorizationPaths,
    *,
    signer: TrustedEd25519SignerV1,
    allocation_intent: AllocationIntentV2,
    provider: ProviderProvenanceAdapter,
    expected_disposal_owner: str,
    expected_approver_identity: str,
    journal: SQLiteAuthorizationJournal,
    allocation_journal: SQLiteAllocationJournal,
    effect: Callable[[VerifiedExecutionContext], EffectReceiptV1],
    replay_authority: ProtocolReplayAuthority,
    replay_policy: ReplayAuthorityPolicyV1,
) -> ExecutionReceiptV1:
    """Authorize an observed effect using the internal UTC clock at each check."""

    if (
        type(paths) is not AuthorizationPaths
        or type(signer) is not TrustedEd25519SignerV1
        or type(allocation_intent) is not AllocationIntentV2
        or type(journal) is not SQLiteAuthorizationJournal
        or type(allocation_journal) is not SQLiteAllocationJournal
        or type(replay_policy) is not ReplayAuthorityPolicyV1
        or not callable(effect)
    ):
        raise AuthorizationError("journal_effect")
    allocation_intent = _require_signed_non_tls_allocation_intent(allocation_intent, signer=signer)
    replay_policy = cast(
        ReplayAuthorityPolicyV1,
        _canonical_artifact_model(
            replay_policy,
            ReplayAuthorityPolicyV1,
            phase="replay_authority_policy",
        ),
    )
    _replay_claim_method(replay_authority)
    with ArtifactRootLease(paths.root) as artifact_lease:
        artifact_lease.assert_stable()
        _require_current_journal(journal.migration_status())
        _require_current_allocation_journal(allocation_journal.migration_status())
        journal_pin = journal._pin_execution_identity()
        artifacts, genesis, snapshot = _verify_authorization_artifact_snapshot(
            paths,
            signer=signer,
            expected_disposal_owner=expected_disposal_owner,
            expected_approver_identity=expected_approver_identity,
            journal=journal,
            replay_policy=replay_policy,
            now=_system_utc_clock(),
            reader=artifact_lease.reader(),
        )
        allocation_stage, allocation_stage_snapshot = _read_allocation_stage_artifacts(
            paths,
            signer=signer,
            expected_disposal_owner=expected_disposal_owner,
            expected_approver_identity=expected_approver_identity,
            now=_system_utc_clock(),
            reader=artifact_lease.reader(),
        )
        verified_allocation_intent = _VerifiedAllocationIntent(
            intent=allocation_stage.intent,
            intent_sha256=allocation_intent_sha256(allocation_stage.intent),
            capability=_ALLOCATION_INTENT_CAPABILITY,
        )
        _verify_allocation_intent_binding(
            verified_allocation_intent, journal=allocation_journal, replay_policy=replay_policy
        )
        if verified_allocation_intent.intent != allocation_intent:
            raise AuthorizationError("allocation_intent_binding")
        verified_allocation_intent = _VerifiedAllocationIntent(
            intent=_require_tls_termination_amendment(verified_allocation_intent.intent),
            intent_sha256=verified_allocation_intent.intent_sha256,
            capability=_ALLOCATION_INTENT_CAPABILITY,
        )
        replay_artifact, replay_raw = _read_replay_policy_artifact(
            paths,
            signer=signer,
            allocation_intent=allocation_stage.intent,
            replay_policy=replay_policy,
            reader=artifact_lease.reader(),
        )
        fingerprints, material_snapshot = _trusted_provider_fingerprints(
            signer=signer,
            allocation_intent=allocation_stage.intent,
            expected_disposal_owner=expected_disposal_owner,
            expected_approver_identity=expected_approver_identity,
            now=_system_utc_clock(),
            reader=artifact_lease.reader(),
        )
        allocation_journal.assert_intent(verified_allocation_intent)
        initial_state = allocation_journal.operation_state(
            allocation_stage.intent.allocation_operation_id
        )
        if (
            type(initial_state) is not AllocationOperationState
            or initial_state.value != AllocationOperationState.ALLOCATED.value
        ):
            raise AuthorizationError("allocation_operation_state")
        allocation_journal_pin = allocation_journal._pin_execution_identity()
        materialization_stage, materialization_stage_snapshot = (
            _read_materialization_stage_artifacts(
                paths,
                signer=signer,
                expected_disposal_owner=expected_disposal_owner,
                expected_approver_identity=expected_approver_identity,
                now=_system_utc_clock(),
                reader=artifact_lease.reader(),
                allocation=allocation_stage,
                proposal=artifacts.proposal,
                contract=artifacts.final_contract,
            )
        )
        allocation_journal.assert_committed_allocation_stage(
            verified_allocation_intent,
            allocation_stage.receipt,
            allocation_stage.attestation,
        )
        allocation_journal.assert_committed_materialization_stage(
            materialization_stage.intent,
            materialization_stage.receipt,
        )
        artifact_lease.assert_stable()
        journal.assert_genesis(genesis)
        journal._assert_pinned_execution_identity(journal_pin)
        _check_observed_stage_stability(
            allocation_journal, allocation_journal_pin, verified_allocation_intent
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
                allocation_journal, allocation_journal_pin, verified_allocation_intent
            )
            repeated_artifacts, repeated_genesis, repeated_snapshot = (
                _verify_authorization_artifact_snapshot(
                    paths,
                    signer=signer,
                    expected_disposal_owner=expected_disposal_owner,
                    expected_approver_identity=expected_approver_identity,
                    journal=journal,
                    replay_policy=replay_policy,
                    now=_system_utc_clock(),
                    reader=artifact_lease.reader(),
                )
            )
            repeated_stage, repeated_stage_snapshot = _read_allocation_stage_artifacts(
                paths,
                signer=signer,
                expected_disposal_owner=expected_disposal_owner,
                expected_approver_identity=expected_approver_identity,
                now=_system_utc_clock(),
                reader=artifact_lease.reader(),
            )
            repeated_replay_artifact, repeated_replay_raw = _read_replay_policy_artifact(
                paths,
                signer=signer,
                allocation_intent=repeated_stage.intent,
                replay_policy=replay_policy,
                reader=artifact_lease.reader(),
            )
            repeated_fingerprints, repeated_material_snapshot = _trusted_provider_fingerprints(
                signer=signer,
                allocation_intent=repeated_stage.intent,
                expected_disposal_owner=expected_disposal_owner,
                expected_approver_identity=expected_approver_identity,
                now=_system_utc_clock(),
                reader=artifact_lease.reader(),
            )
            repeated_materialization_stage, repeated_materialization_stage_snapshot = (
                _read_materialization_stage_artifacts(
                    paths,
                    signer=signer,
                    expected_disposal_owner=expected_disposal_owner,
                    expected_approver_identity=expected_approver_identity,
                    now=_system_utc_clock(),
                    reader=artifact_lease.reader(),
                    allocation=repeated_stage,
                    proposal=repeated_artifacts.proposal,
                    contract=repeated_artifacts.final_contract,
                )
            )
            allocation_journal.assert_committed_materialization_stage(
                repeated_materialization_stage.intent,
                repeated_materialization_stage.receipt,
            )
            _check_observed_stage_stability(
                allocation_journal, allocation_journal_pin, verified_allocation_intent
            )
            artifact_lease.assert_stable()
            if (
                not _same_artifact_receipt(artifacts.receipt, repeated_artifacts.receipt)
                or genesis != repeated_genesis
                or snapshot != repeated_snapshot
                or allocation_stage_snapshot != repeated_stage_snapshot
                or materialization_stage_snapshot != repeated_materialization_stage_snapshot
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
                allocation_journal, allocation_journal_pin, verified_allocation_intent
            )
            if (
                initial_provider_sha256 != final_provider_sha256
                or expectations != final_expectations
            ):
                raise AuthorizationError("provider_race")
            authorization_clock = _system_utc_clock()
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
            terminal_stage, terminal_stage_snapshot = _read_allocation_stage_artifacts(
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
                allocation_intent=terminal_stage.intent,
                replay_policy=replay_policy,
                reader=artifact_lease.reader(),
            )
            terminal_fingerprints, terminal_material_snapshot = _trusted_provider_fingerprints(
                signer=signer,
                allocation_intent=terminal_stage.intent,
                expected_disposal_owner=expected_disposal_owner,
                expected_approver_identity=expected_approver_identity,
                now=authorization_clock,
                reader=artifact_lease.reader(),
            )
            terminal_materialization_stage, terminal_materialization_stage_snapshot = (
                _read_materialization_stage_artifacts(
                    paths,
                    signer=signer,
                    expected_disposal_owner=expected_disposal_owner,
                    expected_approver_identity=expected_approver_identity,
                    now=authorization_clock,
                    reader=artifact_lease.reader(),
                    allocation=terminal_stage,
                    proposal=terminal_artifacts.proposal,
                    contract=terminal_artifacts.final_contract,
                )
            )
            allocation_journal.assert_committed_materialization_stage(
                terminal_materialization_stage.intent,
                terminal_materialization_stage.receipt,
            )
            _check_observed_stage_stability(
                allocation_journal, allocation_journal_pin, verified_allocation_intent
            )
            artifact_lease.assert_stable()
            if (
                not _same_artifact_receipt(artifacts.receipt, repeated_artifacts.receipt)
                or not _same_artifact_receipt(artifacts.receipt, terminal_artifacts.receipt)
                or genesis != repeated_genesis
                or genesis != terminal_genesis
                or snapshot != repeated_snapshot
                or snapshot != terminal_snapshot
                or allocation_stage_snapshot != terminal_stage_snapshot
                or materialization_stage_snapshot != terminal_materialization_stage_snapshot
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
                    allocation_journal, allocation_journal_pin, verified_allocation_intent
                )
                _claim_replay_tombstone(
                    replay_authority,
                    _operation_tombstone(replay_policy, genesis, context),
                    phase="replay_authority_replayed",
                )
                _check_execution_stability(journal, journal_pin, artifact_lease, operation_lease)
                _check_observed_stage_stability(
                    allocation_journal, allocation_journal_pin, verified_allocation_intent
                )
                journal._claim_verified(verified)
                journal._begin_effect(verified)
                _check_execution_stability(journal, journal_pin, artifact_lease, operation_lease)
                _check_observed_stage_stability(
                    allocation_journal, allocation_journal_pin, verified_allocation_intent
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
                        allocation_journal, allocation_journal_pin, verified_allocation_intent
                    )
                )
                post_effect_materials = _safe_call(
                    lambda: _trusted_provider_fingerprints(
                        signer=signer,
                        allocation_intent=verified_allocation_intent.intent,
                        expected_disposal_owner=expected_disposal_owner,
                        expected_approver_identity=expected_approver_identity,
                        now=_system_utc_clock(),
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
                        allocation_journal, allocation_journal_pin, verified_allocation_intent
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


def authorize_and_execute(
    paths: AuthorizationPaths,
    *,
    signer: TrustedEd25519SignerV1,
    allocation_intent: AllocationIntentV2,
    provider: ProviderProvenanceAdapter,
    expected_disposal_owner: str,
    expected_approver_identity: str,
    journal: SQLiteAuthorizationJournal,
    allocation_journal: SQLiteAllocationJournal,
    effect: Callable[[VerifiedExecutionContext], EffectReceiptV1],
    replay_authority: ProtocolReplayAuthority,
    replay_policy: ReplayAuthorityPolicyV1,
) -> ExecutionReceiptV1:
    """Verify, lease, execute once, and commit using the trusted UTC clock."""

    return _run_observed_authorization(
        paths,
        signer=signer,
        allocation_intent=allocation_intent,
        provider=provider,
        expected_disposal_owner=expected_disposal_owner,
        expected_approver_identity=expected_approver_identity,
        journal=journal,
        allocation_journal=allocation_journal,
        effect=effect,
        replay_authority=replay_authority,
        replay_policy=replay_policy,
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
