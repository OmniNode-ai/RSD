"""Adversarial tests for the public, offline disposable acceptance compiler."""

from __future__ import annotations

import base64
import hashlib
import inspect
import json
import multiprocessing
import os
import shutil
import sqlite3
import time
import traceback
import uuid
from collections.abc import Callable, Mapping
from concurrent.futures import ThreadPoolExecutor
from contextlib import contextmanager
from datetime import UTC, datetime, timedelta
from pathlib import Path
from threading import Event, Lock
from typing import Literal, Protocol
from unittest.mock import patch

import pytest
import yaml
from cryptography import x509
from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey
from cryptography.x509.oid import NameOID

import omninode_rsd.lifecycle.authorization as authorization_module
import omninode_rsd.lifecycle.provider_crypto as provider_crypto_module
from omninode_rsd.lifecycle.authorization import (
    ArtifactRootLease,
    AuthorizationError,
    AuthorizationPaths,
    EffectReceiptV1,
    ExecutionReceiptV1,
    InitialJournalGenesisReconciliationReceiptV1,
    InitialProvisioningExecutionContext,
    InitialProvisioningJournalStatus,
    InitialProvisioningOperationState,
    JournalGenesisReceiptV1,
    JournalGenesisReconciliationReceiptV1,
    JournalMigrationStatus,
    MacOSKeychainReplayAuthority,
    ProtocolReplayAuthority,
    ProviderProvenance,
    ReplayAuthorityClaimResult,
    ReplayAuthorityPolicyV1,
    ReplayTombstoneV1,
    SQLiteAuthorizationJournal,
    SQLiteInitialProvisioningJournal,
    TrustedEd25519SignerV1,
    VerifiedExecutionContext,
    _canonical_signed_content,
    _initial_intent_message,
    _initial_journal_genesis_reconciliation_message,
    _journal_genesis_message,
    _journal_genesis_reconciliation_message,
    _observed_candidate_attestation_message,
    _signature_message,
    authorize_and_execute,
    authorize_initial_provisioning_and_execute,
    provision_initial_journal,
    provision_journal,
    reconcile_initial_journal_genesis,
    reconcile_journal_genesis,
)
from omninode_rsd.lifecycle.authorization import (
    main as authorization_main,
)
from omninode_rsd.lifecycle.infisical_disposable import (
    ApprovalEvidenceV1,
    CandidateCompositeV1,
    DetachedSignatureV1,
    DisposablePreflightError,
    DisposableTransportProfile,
    EvidenceBindingsV1,
    GovernedBaselineV1,
    GovernedIdentityV1,
    ImageReferenceV1,
    InitialPostgreSQLPlanV1,
    InitialProvisioningEffectReceiptV1,
    InitialProvisioningEvidenceBindingsV1,
    InitialProvisioningIntentV1,
    InitialProvisioningPlanV1,
    InitialServicePlanV1,
    InitialValkeyPlanV1,
    ObservedCandidateAttestationV1,
    ObservedResourceSetV1,
    ObservedServiceResourcesV1,
    ObservedValkeyResourcesV1,
    PostgreSQLAcceptanceOverlayV1,
    PostgreSQLContractV1,
    PreflightPaths,
    ProposalV1,
    ProviderDeclarationV1,
    ProviderReferencesV1,
    ProviderReferenceV1,
    RegistryImageVerificationV1,
    RegistryVerificationV1,
    RuntimeContractV1,
    ServiceIdentityV1,
    StableIdentifierKind,
    StableIdentifierV1,
    TargetAttestationV1,
    TransportContractV1,
    ValkeyIdentityV1,
    canonical_sha256,
    compile_preflight,
    initial_provisioning_effect_receipt_sha256,
    initial_provisioning_intent_sha256,
    main,
    proposal_sha256,
    validate_observed_candidate_transition,
)
from omninode_rsd.lifecycle.provider_crypto import (
    KeychainEd25519Signer,
    KeychainItemReferenceV1,
    MacOSKeychainProviderProvenanceAdapter,
    ProviderCryptoError,
    ProviderFingerprintAttestationV1,
    ProviderMaterialArtifactPaths,
    ProviderMaterialFingerprintV1,
    ProviderMaterialFormat,
    ProviderMaterialGenesisV1,
    ProviderMaterialPolicyV1,
    ProviderMaterialPurpose,
    ProviderMaterialSpecV1,
    ReplayAuthorityPolicyArtifactV1,
    SignerGenesisV1,
    load_keychain_ed25519_signer,
    load_verified_provider_material_bundle,
    load_verified_signer_genesis,
    persist_provider_material_genesis,
    persist_provider_material_policy,
    persist_signer_genesis,
    provider_fingerprint_attestation_message,
    provider_material_genesis_message,
    provider_material_genesis_status,
    provider_material_policy_message,
    provision_keychain_ed25519_signer,
    provision_keychain_materials,
    replay_authority_policy_message,
    signer_genesis_message,
)

_NOW = datetime(2026, 8, 27, 12, 0, tzinfo=UTC)
_COMMIT = "a" * 40
_HASH = "b" * 64
_IMAGE = ImageReferenceV1(reference=f"registry.example.test/infisical@sha256:{'c' * 64}")
_CACHE_IMAGE = ImageReferenceV1(reference=f"registry.example.test/valkey@sha256:{'d' * 64}")
_TEST_SIGNING_KEYS: dict[str, Ed25519PrivateKey] = {}
_TEST_PROVIDER_SIGNERS: dict[tuple[str, str], tuple[TrustedEd25519SignerV1, SignerGenesisV1]] = {}
_TEST_PROVISION_LOCK = Lock()
_TEST_REPLAY_POLICY = ReplayAuthorityPolicyV1(
    schema_version="rsd.replay-authority-policy.v1",
    service="omninode-rsd-test-replay",
    account_prefix="rsd-test-tombstone",
)
_TEST_REPLAY_AUTHORITIES: dict[str, _AtomicReplayAuthority] = {}
_TEST_REPLAY_AUTHORITIES_LOCK = Lock()


@contextmanager
def _patched_system_clock(module: object, clock: Callable[[], datetime]):
    """Test seam only: production entries never receive a caller clock."""

    with patch.object(module, "_system_utc_clock", clock):
        yield


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
) -> object:
    with _patched_system_clock(authorization_module, _clock):
        return provision_initial_journal(
            paths,
            signer=signer,
            expected_disposal_owner=expected_disposal_owner,
            expected_approver_identity=expected_approver_identity,
            journal=journal,
            intent=intent,
            replay_authority=replay_authority,
            replay_policy=replay_policy,
            replay_policy_artifact=replay_policy_artifact,
        )


def _authorize_initial_provisioning_and_execute_for_test(
    paths: AuthorizationPaths,
    *,
    signer: TrustedEd25519SignerV1,
    provider: object,
    expected_disposal_owner: str,
    expected_approver_identity: str,
    journal: SQLiteInitialProvisioningJournal,
    effect: Callable[[InitialProvisioningExecutionContext], InitialProvisioningEffectReceiptV1],
    replay_authority: ProtocolReplayAuthority,
    replay_policy: ReplayAuthorityPolicyV1,
    _clock: Callable[[], datetime],
) -> object:
    with _patched_system_clock(authorization_module, _clock):
        return authorize_initial_provisioning_and_execute(
            paths,
            signer=signer,
            provider=provider,
            expected_disposal_owner=expected_disposal_owner,
            expected_approver_identity=expected_approver_identity,
            journal=journal,
            effect=effect,
            replay_authority=replay_authority,
            replay_policy=replay_policy,
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
) -> object:
    with _patched_system_clock(authorization_module, _clock):
        return provision_journal(
            paths,
            signer=signer,
            expected_disposal_owner=expected_disposal_owner,
            expected_approver_identity=expected_approver_identity,
            journal=journal,
            receipt=receipt,
            replay_authority=replay_authority,
            replay_policy=replay_policy,
        )


def _authorize_and_execute_for_test(
    paths: AuthorizationPaths,
    *,
    signer: TrustedEd25519SignerV1,
    provider: object,
    expected_disposal_owner: str,
    expected_approver_identity: str,
    journal: SQLiteAuthorizationJournal,
    initial_journal: SQLiteInitialProvisioningJournal,
    effect: Callable[[VerifiedExecutionContext], EffectReceiptV1],
    replay_authority: ProtocolReplayAuthority,
    replay_policy: ReplayAuthorityPolicyV1,
    _clock: Callable[[], datetime],
) -> ExecutionReceiptV1:
    with _patched_system_clock(authorization_module, _clock):
        return authorize_and_execute(
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
        )


def _persist_provider_material_policy_for_test(
    paths: ProviderMaterialArtifactPaths,
    policy: ProviderMaterialPolicyV1,
    *,
    signer: object,
    signer_genesis: SignerGenesisV1,
    issuer: object,
    initial_intent: InitialProvisioningIntentV1,
    expected_disposal_owner: str,
    expected_approver_identity: str,
    _clock: Callable[[], datetime],
) -> None:
    with _patched_system_clock(provider_crypto_module, _clock):
        persist_provider_material_policy(
            paths,
            policy,
            signer=signer,
            signer_genesis=signer_genesis,
            issuer=issuer,
            initial_intent=initial_intent,
            expected_disposal_owner=expected_disposal_owner,
            expected_approver_identity=expected_approver_identity,
        )


def _persist_provider_material_genesis_for_test(
    paths: ProviderMaterialArtifactPaths,
    genesis: ProviderMaterialGenesisV1,
    *,
    policy: ProviderMaterialPolicyV1,
    attestation: ProviderFingerprintAttestationV1,
    signer: object,
    signer_genesis: SignerGenesisV1,
    issuer: object,
    initial_intent: InitialProvisioningIntentV1,
    expected_disposal_owner: str,
    expected_approver_identity: str,
    _clock: Callable[[], datetime],
) -> None:
    with _patched_system_clock(provider_crypto_module, _clock):
        persist_provider_material_genesis(
            paths,
            genesis,
            policy=policy,
            attestation=attestation,
            signer=signer,
            signer_genesis=signer_genesis,
            issuer=issuer,
            initial_intent=initial_intent,
            expected_disposal_owner=expected_disposal_owner,
            expected_approver_identity=expected_approver_identity,
        )


def _provision_keychain_materials_for_test(
    paths: ProviderMaterialArtifactPaths,
    *,
    policy: ProviderMaterialPolicyV1,
    genesis: ProviderMaterialGenesisV1,
    attestation: ProviderFingerprintAttestationV1,
    signer: object,
    signer_genesis: SignerGenesisV1,
    issuer: object,
    initial_intent: InitialProvisioningIntentV1,
    expected_disposal_owner: str,
    expected_approver_identity: str,
    materials: Mapping[ProviderMaterialPurpose, bytearray],
    _store: object,
    _clock: Callable[[], datetime],
) -> None:
    with _patched_system_clock(provider_crypto_module, _clock):
        provision_keychain_materials(
            paths,
            policy=policy,
            genesis=genesis,
            attestation=attestation,
            signer=signer,
            signer_genesis=signer_genesis,
            issuer=issuer,
            initial_intent=initial_intent,
            expected_disposal_owner=expected_disposal_owner,
            expected_approver_identity=expected_approver_identity,
            materials=materials,
            _store=_store,
        )


def _load_verified_provider_material_bundle_for_test(
    paths: ProviderMaterialArtifactPaths,
    *,
    signer: object,
    signer_genesis: SignerGenesisV1,
    issuer: object,
    initial_intent: InitialProvisioningIntentV1,
    expected_disposal_owner: str,
    expected_approver_identity: str,
    _clock: Callable[[], datetime],
) -> tuple[ProviderMaterialPolicyV1, ProviderMaterialGenesisV1, ProviderFingerprintAttestationV1]:
    with _patched_system_clock(provider_crypto_module, _clock):
        return load_verified_provider_material_bundle(
            paths,
            signer=signer,
            signer_genesis=signer_genesis,
            issuer=issuer,
            initial_intent=initial_intent,
            expected_disposal_owner=expected_disposal_owner,
            expected_approver_identity=expected_approver_identity,
        )


class _StringQueue(Protocol):
    def put(self, value: str) -> None: ...


class _AtomicReplayAuthority:
    """Test-only atomic store; production APIs never supply a fallback."""

    def __init__(self) -> None:
        self._claims: dict[tuple[str, str], bytes] = {}
        self.tombstones: list[ReplayTombstoneV1] = []
        self._lock = Lock()

    def claim_once(self, tombstone: ReplayTombstoneV1) -> ReplayAuthorityClaimResult:
        value = tombstone.value_bytes()
        key = (tombstone.service, tombstone.account)
        with self._lock:
            existing = self._claims.get(key)
            if existing is None:
                self._claims[key] = value
                self.tombstones.append(tombstone)
                return ReplayAuthorityClaimResult.CREATED
            if existing == value:
                return ReplayAuthorityClaimResult.DUPLICATE_SAME
            return ReplayAuthorityClaimResult.DUPLICATE_CONFLICT


def _test_replay_authority(journal: SQLiteAuthorizationJournal) -> _AtomicReplayAuthority:
    key = str(journal._path)
    with _TEST_REPLAY_AUTHORITIES_LOCK:
        authority = _TEST_REPLAY_AUTHORITIES.get(key)
        if authority is None:
            authority = _AtomicReplayAuthority()
            _TEST_REPLAY_AUTHORITIES[key] = authority
        return authority


class _FilesystemAtomicReplayAuthority:
    """Spawn-safe test fake for the authority's create-once contract."""

    def __init__(self, root: Path) -> None:
        self._root = root

    def claim_once(self, tombstone: ReplayTombstoneV1) -> ReplayAuthorityClaimResult:
        name = _digest(f"{tombstone.service}\x00{tombstone.account}".encode())
        path = self._root / name
        value = tombstone.value_bytes()
        flags = os.O_WRONLY | os.O_CREAT | os.O_EXCL | getattr(os, "O_CLOEXEC", 0)
        try:
            descriptor = os.open(path, flags, 0o600)
        except FileExistsError:
            deadline = time.monotonic() + 1.0
            while True:
                existing = path.read_bytes()
                if len(existing) == len(value) or time.monotonic() >= deadline:
                    return (
                        ReplayAuthorityClaimResult.DUPLICATE_SAME
                        if existing == value
                        else ReplayAuthorityClaimResult.DUPLICATE_CONFLICT
                    )
                time.sleep(0.001)
        try:
            remaining = memoryview(value)
            while remaining:
                written = os.write(descriptor, remaining)
                if written <= 0:
                    return ReplayAuthorityClaimResult.UNAVAILABLE
                remaining = remaining[written:]
            os.fsync(descriptor)
        finally:
            os.close(descriptor)
        return ReplayAuthorityClaimResult.CREATED


def _process_replay_authority_worker(root: str, queue: _StringQueue) -> None:
    policy = ReplayAuthorityPolicyV1(
        schema_version="rsd.replay-authority-policy.v1",
        service="omninode-rsd-test-replay",
        account_prefix="rsd-test-tombstone",
    )
    tombstone = ReplayTombstoneV1(
        schema_version="rsd.replay-tombstone.v1",
        kind="observed_operation",
        operation_kind="observed_lifecycle_v1",
        service=policy.service,
        account=f"{policy.account_prefix}.o.process-claim",
        journal_genesis_id="00000000-0000-4000-8000-000000000001",
        operation_id="process-claim",
        proposal_sha256="a" * 64,
        contract_sha256="b" * 64,
        provider_provenance_sha256="c" * 64,
        idempotency_key="d" * 64,
    )
    queue.put(_FilesystemAtomicReplayAuthority(Path(root)).claim_once(tombstone).value)


def _artifact_lock_worker(root: str, queue: _StringQueue) -> None:
    try:
        with ArtifactRootLease(Path(root)):
            queue.put("acquired")
    except AuthorizationError as error:
        queue.put(error.phase)


def _digest(data: bytes) -> str:
    return hashlib.sha256(data).hexdigest()


def _signature() -> DetachedSignatureV1:
    return DetachedSignatureV1(
        algorithm="ed25519-detached-v1",
        signer_key_id="test-signer",
        signer_public_key_fingerprint_sha256="1" * 64,
        detached_signature_sha256="2" * 64,
    )


def _reference(
    name: str, version: int, *, provider: str = "metadata-provider"
) -> ProviderReferenceV1:
    data = {
        "account": (
            f"account-{name}.v{version}" if provider == "macos_keychain" else f"account-{name}"
        ),
        "provider": provider,
        "service": f"service-{name}",
        "version": version,
    }
    return ProviderReferenceV1(
        **data,
        reference_sha256=_digest(
            __import__("json").dumps(data, sort_keys=True, separators=(",", ":")).encode()
        ),
    )


def _provider_references(
    *, provider: str = "metadata-provider", tls: bool = False
) -> ProviderReferencesV1:
    return ProviderReferencesV1(
        commitment_hmac=_reference("commitment", 1, provider=provider),
        backup_encryption=_reference("backup", 1, provider=provider),
        encryption_key=_reference("encryption", 1, provider=provider),
        auth_secret=_reference("auth", 1, provider=provider),
        primary_valkey_password=_reference("primary-cache", 1, provider=provider),
        restore_valkey_password=_reference("restore-cache", 1, provider=provider),
        tls_trust_anchor=_reference("trust", 1, provider=provider) if tls else None,
    )


def _service(
    *, number: int, project: str, network: str, restore: bool = False, tls: bool = False
) -> ServiceIdentityV1:
    authority = None
    if not restore:
        authority = (
            "https://" + ".".join(("198", "51", "100", str(number))) + ":443"
            if tls
            else "http://127.0.0.1:8080"
        )
    container_char = "a" if number == 31 else "b"
    return ServiceIdentityV1(
        authority=authority,
        authority_sha256=None if authority is None else _digest(authority.encode()),
        machine_id=f"machine-{number}",
        compose_project=project,
        service_name="infisical",
        network_name=network,
        network_id=_digest(f"network:{network}".encode()),
        container_id=container_char * 64,
        workload_name=f"workload-{number}",
        workload_id=_digest(f"workload:{number}".encode()),
        image=_IMAGE,
        listener_binding="isolated_network_only"
        if restore
        else ("tls_lan" if tls else "loopback_only"),
        host_listener_port=None if restore else (443 if tls else 8080),
        isolated_network_alias="restore-infisical" if restore else None,
    )


def _cache(
    *, project: str, network: str, volume: str, namespace: str, reference: str, char: str
) -> ValkeyIdentityV1:
    return ValkeyIdentityV1(
        compose_project=project,
        service_name="valkey",
        network_name=network,
        network_id=_digest(f"network:{network}".encode()),
        volume_name=volume,
        volume_id=_digest(f"volume:{volume}".encode()),
        container_id=char * 64,
        workload_name=f"workload-{namespace}",
        workload_id=_digest(f"workload:{namespace}".encode()),
        logical_namespace=namespace,
        credential_reference_sha256=reference,
        image=_CACHE_IMAGE,
    )


def _proposal(*, provider: str = "metadata-provider", tls: bool = False) -> ProposalV1:
    references = _provider_references(provider=provider, tls=tls)
    authority = "https://198.51.100.31:443" if tls else "http://127.0.0.1:8080"
    candidate = CandidateCompositeV1(
        authority=authority,
        authority_sha256=_digest(authority.encode()),
        primary_service=_service(
            number=31,
            project="primary-project",
            network="primary-network",
            tls=tls,
        ),
        restore_service=_service(
            number=32,
            project="restore-project",
            network="restore-network",
            restore=True,
            tls=tls,
        ),
        postgres=PostgreSQLContractV1(
            authority="postgresql://192.0.2.40:5432",
            system_identifier="12345678",
            database_name="rsdacceptance",
            database_oid=101,
            schema_name="rsdschema",
            owner_role="rsdowner",
            role_names=("rsdowner", "rsdreader"),
            schema_fingerprint_sha256=_HASH,
            membership_fingerprint_sha256=_HASH,
            database_acl_sha256=_HASH,
            stage_database_prefix="rsdstage",
            restore_database_prefix="rsdrestore",
        ),
        primary_valkey=_cache(
            project="primary-cache-project",
            network="primary-cache-network",
            volume="primary-volume",
            namespace="primary-ns",
            reference=references.primary_valkey_password.reference_sha256,
            char="3",
        ),
        restore_valkey=_cache(
            project="restore-cache-project",
            network="restore-cache-network",
            volume="restore-volume",
            namespace="restore-ns",
            reference=references.restore_valkey_password.reference_sha256,
            char="4",
        ),
    )
    return ProposalV1(
        schema_version="rsd.disposable-infisical-proposal.v1",
        operation_id="123e4567-e89b-42d3-a456-426614174000",
        source_commit=_COMMIT,
        transport=TransportContractV1(
            profile=(
                DisposableTransportProfile.TLS_VERIFIED
                if tls
                else DisposableTransportProfile.UNPUBLISHED_LOOPBACK_OR_NETWORK
            ),
            authority=authority,
            authority_sha256=_digest(authority.encode()),
            listener_binding="tls_lan" if tls else "loopback_only",
            host_listener_port=443 if tls else 8080,
            tls_trust_anchor_reference_sha256=(
                references.tls_trust_anchor.reference_sha256 if tls else None
            ),
            minimum_tls_version="TLSv1.3" if tls else None,
        ),
        candidate=candidate,
        primary_image=_IMAGE,
        restore_image=_IMAGE,
        provider_references=references,
        retention_expires_at="2030-01-01T00:00:00Z",
        disposal_owner="acceptance-owner",
        approval_reference_sha256="5" * 64,
        initial_provisioning_evidence=InitialProvisioningEvidenceBindingsV1(
            approval_sha256="0" * 64,
            governed_deny_sha256="1" * 64,
            governed_baseline_sha256="2" * 64,
            collision_evidence_sha256="3" * 64,
            registry_verification_sha256="4" * 64,
            provider_declaration_sha256="5" * 64,
        ),
    )


def _runtime_contract(proposal: ProposalV1) -> RuntimeContractV1:
    return RuntimeContractV1(
        **proposal.model_dump(mode="python"),
        proposal_sha256=proposal_sha256(proposal),
        evidence=EvidenceBindingsV1(
            approval_sha256="0" * 64,
            governed_baseline_sha256="1" * 64,
            target_attestation_sha256="2" * 64,
            provider_declaration_sha256="3" * 64,
            registry_verification_sha256="4" * 64,
            postgres_overlay_sha256="5" * 64,
        ),
    )


def _write(path: Path, name: str, model: object) -> str:
    raw = yaml.safe_dump(model.model_dump(mode="json"), sort_keys=True).encode()  # type: ignore[union-attr]
    (path / name).write_bytes(raw)
    (path / name).chmod(0o600)
    return _digest(raw)


def _materials(
    root: Path,
    *,
    governed_collision: bool = False,
    target_database_oid: int | None = None,
    overlay_database_oid: int | None = None,
    provider_epoch: str = "snapshot-1",
) -> None:
    root.mkdir(mode=0o700)
    proposal = _proposal()
    subject = proposal_sha256(proposal)
    _write(root, "proposal.yaml", proposal)
    approval = ApprovalEvidenceV1(
        schema_version="rsd.disposable-approval.v1",
        authorization_subject_sha256=subject,
        approval_reference_sha256=proposal.approval_reference_sha256,
        source_commit=_COMMIT,
        issued_at="2026-08-27T11:50:00Z",
        expires_at="2026-08-27T12:10:00Z",
        approver_identity="approval-owner",
        proposal_authorized=True,
        execution_authorized=False,
        signature=_signature(),
    )
    collision = (
        proposal.candidate.stable()[0]
        if governed_collision
        else StableIdentifierV1(kind=StableIdentifierKind.WORKLOAD, value="unrelated-workload")
    )
    governed = GovernedBaselineV1(
        schema_version="rsd.disposable-governed-baseline.v1",
        authorization_subject_sha256=subject,
        source_commit=_COMMIT,
        signature=_signature(),
        identities=(
            GovernedIdentityV1(surface="governed_surface", stable_identifiers=(collision,)),
        ),
    )
    target = TargetAttestationV1(
        schema_version="rsd.disposable-target-attestation.v1",
        authorization_subject_sha256=subject,
        snapshot_epoch_id="snapshot-1",
        observed_at="2026-08-27T11:59:00Z",
        candidate_composite_sha256=canonical_sha256(proposal.candidate),
        postgres_database_oid=(
            proposal.candidate.postgres.database_oid
            if target_database_oid is None
            else target_database_oid
        ),
        signature=_signature(),
    )
    provider = ProviderDeclarationV1(
        schema_version="rsd.disposable-provider-declaration.v1",
        authorization_subject_sha256=subject,
        snapshot_epoch_id=provider_epoch,
        observed_at="2026-08-27T11:59:00Z",
        proof_source="offline-provider-reference-declaration-v1",
        signature=_signature(),
        references=proposal.provider_references.all(),
    )
    registry = RegistryVerificationV1(
        schema_version="rsd.disposable-registry-verification.v1",
        authorization_subject_sha256=subject,
        snapshot_epoch_id="snapshot-1",
        observed_at="2026-08-27T11:59:00Z",
        signature=_signature(),
        images=(
            RegistryImageVerificationV1(
                role="primary",
                image=_IMAGE,
                platform="linux/amd64",
                platform_digest=f"sha256:{'6' * 64}",
            ),
            RegistryImageVerificationV1(
                role="restore",
                image=_IMAGE,
                platform="linux/amd64",
                platform_digest=f"sha256:{'7' * 64}",
            ),
        ),
    )
    overlay = PostgreSQLAcceptanceOverlayV1(
        schema_version="rsd.postgres-acceptance-overlay.v1",
        database_name="rsdacceptance",
        database_oid=101 if overlay_database_oid is None else overlay_database_oid,
        owner_role="rsdowner",
        secret_provider_kind="infisical",
        secret_project="acceptance-project",
        secret_environment="test",
        secret_path="/rsd/acceptance",
    )
    hashes = {
        "approval": _write(root, "approval.yaml", approval),
        "governed": _write(root, "governed-baseline.yaml", governed),
        "target": _write(root, "target-attestation.yaml", target),
        "provider": _write(root, "provider-declaration.yaml", provider),
        "registry": _write(root, "registry-verification.yaml", registry),
        "overlay": _write(root, "postgres-overlay.yaml", overlay),
    }
    contract = RuntimeContractV1(
        **proposal.model_dump(mode="python"),
        proposal_sha256=subject,
        evidence=EvidenceBindingsV1(
            approval_sha256=hashes["approval"],
            governed_baseline_sha256=hashes["governed"],
            target_attestation_sha256=hashes["target"],
            provider_declaration_sha256=hashes["provider"],
            registry_verification_sha256=hashes["registry"],
            postgres_overlay_sha256=hashes["overlay"],
        ),
    )
    _write(root, "runtime-contract.yaml", contract)


def test_compiles_non_authorizing_value_free_receipt(tmp_path: Path) -> None:
    root = tmp_path / "artifacts"
    _materials(root)

    receipt = compile_preflight(PreflightPaths(root=root), now=_NOW)

    assert receipt.status == "compiled"
    assert receipt.authorization_state == "not_authorized_pending_live_provenance"
    assert len(receipt.evidence_sha256) == 6


def test_governed_composite_match_denies_even_on_shared_host(tmp_path: Path) -> None:
    root = tmp_path / "artifacts"
    _materials(root, governed_collision=True)

    with pytest.raises(DisposablePreflightError, match="governed_identity"):
        compile_preflight(PreflightPaths(root=root), now=_NOW)


def test_reader_rejects_non_owner_only_artifact(tmp_path: Path) -> None:
    root = tmp_path / "artifacts"
    _materials(root)
    (root / "proposal.yaml").chmod(0o644)

    with pytest.raises(DisposablePreflightError, match="owner_only_input"):
        compile_preflight(PreflightPaths(root=root), now=_NOW)


def test_content_addressed_overlay_tampering_is_rejected(tmp_path: Path) -> None:
    root = tmp_path / "artifacts"
    _materials(root)
    overlay_path = root / "postgres-overlay.yaml"
    overlay_path.write_text(
        overlay_path.read_text(encoding="utf-8").replace("acceptance-project", "changed-project"),
        encoding="utf-8",
    )
    overlay_path.chmod(0o600)

    with pytest.raises(DisposablePreflightError, match="evidence_binding"):
        compile_preflight(PreflightPaths(root=root), now=_NOW)


def test_duplicate_yaml_key_is_rejected_before_model_coercion(tmp_path: Path) -> None:
    root = tmp_path / "artifacts"
    _materials(root)
    proposal_path = root / "proposal.yaml"
    proposal_path.write_text(
        "schema_version: rsd.disposable-infisical-proposal.v1\n"
        "schema_version: rsd.disposable-infisical-proposal.v1\n",
        encoding="utf-8",
    )
    proposal_path.chmod(0o600)

    with pytest.raises(DisposablePreflightError, match="proposal"):
        compile_preflight(PreflightPaths(root=root), now=_NOW)


def test_candidate_rejects_shared_restore_valkey_volume() -> None:
    candidate = _proposal().candidate
    raw = candidate.model_dump(mode="python")
    raw["restore_valkey"] = candidate.primary_valkey

    with pytest.raises(ValueError, match="all component container identities"):
        CandidateCompositeV1.model_validate(raw)


@pytest.mark.parametrize("field", ("container_id", "network_id", "workload_id"))
def test_candidate_rejects_service_to_valkey_identity_collision(field: str) -> None:
    candidate = _proposal().candidate
    raw = candidate.model_dump(mode="python")
    colliding_valkey = candidate.primary_valkey.model_dump(mode="python")
    colliding_valkey[field] = getattr(candidate.primary_service, field)
    raw["primary_valkey"] = colliding_valkey

    with pytest.raises(ValueError, match=f"all component {field.removesuffix('_id')} identities"):
        CandidateCompositeV1.model_validate(raw)


def test_candidate_rejects_restore_service_published_authority() -> None:
    candidate = _proposal(tls=True).candidate
    raw = candidate.model_dump(mode="python")
    published_restore = candidate.restore_service.model_dump(mode="python")
    published_restore.update(
        {
            "authority": candidate.authority,
            "authority_sha256": candidate.authority_sha256,
            "listener_binding": "tls_lan",
            "host_listener_port": 443,
            "isolated_network_alias": None,
        }
    )
    raw["restore_service"] = published_restore

    with pytest.raises(ValueError, match="restore service must be unpublished and isolated"):
        CandidateCompositeV1.model_validate(raw)


def test_proposal_rejects_transport_authority_mismatch_with_primary_candidate() -> None:
    proposal = _proposal(tls=True)
    authority = "https://" + ".".join(("198", "51", "100", "39")) + ":443"
    raw = proposal.model_dump(mode="python")
    raw["transport"] = TransportContractV1(
        profile=DisposableTransportProfile.TLS_VERIFIED,
        authority=authority,
        authority_sha256=_digest(authority.encode()),
        listener_binding="tls_lan",
        host_listener_port=443,
        tls_trust_anchor_reference_sha256=(
            proposal.provider_references.tls_trust_anchor.reference_sha256
        ),
        minimum_tls_version="TLSv1.3",
    )

    with pytest.raises(ValueError, match="transport must bind primary candidate service"):
        ProposalV1.model_validate(raw)


def test_proposal_rejects_claimed_loopback_when_candidate_is_tls_lan() -> None:
    proposal = _proposal(tls=True)
    references = proposal.provider_references.model_dump(mode="python")
    references["tls_trust_anchor"] = None
    raw = proposal.model_dump(mode="python")
    raw["provider_references"] = ProviderReferencesV1.model_validate(references)
    raw["transport"] = TransportContractV1(
        profile=DisposableTransportProfile.UNPUBLISHED_LOOPBACK_OR_NETWORK,
        authority="http://127.0.0.1:8080",
        authority_sha256=_digest(b"http://127.0.0.1:8080"),
        listener_binding="loopback_only",
        host_listener_port=8080,
    )

    with pytest.raises(ValueError, match="transport must bind primary candidate service"):
        ProposalV1.model_validate(raw)


def test_unpublished_network_transport_rejects_external_address_and_dns() -> None:
    external_authority = "http://" + ".".join(("8", "8", "8", "8")) + ":8080"
    for authority in (external_authority, "http://service.example.test:8080"):
        with pytest.raises(ValueError):
            TransportContractV1(
                profile=DisposableTransportProfile.UNPUBLISHED_LOOPBACK_OR_NETWORK,
                authority=authority,
                authority_sha256=_digest(authority.encode()),
                listener_binding="isolated_network_only",
                isolated_network_name="isolated-network",
                isolated_network_alias="internal-service",
            )


def test_proposal_accepts_candidate_bound_internal_network_transport() -> None:
    proposal = _proposal()
    authority = "http://" + ".".join(("198", "51", "100", "41")) + ":8080"
    candidate_raw = proposal.candidate.model_dump(mode="python")
    primary_raw = proposal.candidate.primary_service.model_dump(mode="python")
    primary_raw.update(
        {
            "authority": authority,
            "authority_sha256": _digest(authority.encode()),
            "listener_binding": "isolated_network_only",
            "host_listener_port": None,
            "isolated_network_alias": "primary-internal",
        }
    )
    candidate_raw["authority"] = authority
    candidate_raw["authority_sha256"] = _digest(authority.encode())
    candidate_raw["primary_service"] = primary_raw
    references_raw = proposal.provider_references.model_dump(mode="python")
    references_raw["tls_trust_anchor"] = None
    raw = proposal.model_dump(mode="python")
    raw["candidate"] = CandidateCompositeV1.model_validate(candidate_raw)
    raw["provider_references"] = ProviderReferencesV1.model_validate(references_raw)
    raw["transport"] = TransportContractV1(
        profile=DisposableTransportProfile.UNPUBLISHED_LOOPBACK_OR_NETWORK,
        authority=authority,
        authority_sha256=_digest(authority.encode()),
        listener_binding="isolated_network_only",
        isolated_network_name="primary-network",
        isolated_network_alias="primary-internal",
    )

    assert ProposalV1.model_validate(raw).transport.isolated_network_alias == "primary-internal"


def test_postgres_identity_requires_positive_oid() -> None:
    raw = _proposal().candidate.postgres.model_dump(mode="python")
    raw["database_oid"] = 0

    with pytest.raises(ValueError, match="database_oid"):
        PostgreSQLContractV1.model_validate(raw)


def test_final_contract_rejects_postgres_oid_replay_tampering() -> None:
    proposal = _proposal()
    candidate_raw = proposal.candidate.model_dump(mode="python")
    postgres_raw = proposal.candidate.postgres.model_dump(mode="python")
    postgres_raw["database_oid"] = 102
    candidate_raw["postgres"] = postgres_raw
    raw = proposal.model_dump(mode="python")
    raw["candidate"] = CandidateCompositeV1.model_validate(candidate_raw)

    with pytest.raises(ValueError, match="runtime contract does not bind proposal"):
        RuntimeContractV1(
            **raw,
            proposal_sha256=proposal_sha256(proposal),
            evidence=EvidenceBindingsV1(
                approval_sha256="0" * 64,
                governed_baseline_sha256="1" * 64,
                target_attestation_sha256="2" * 64,
                provider_declaration_sha256="3" * 64,
                registry_verification_sha256="4" * 64,
                postgres_overlay_sha256="5" * 64,
            ),
        )


def test_target_database_oid_and_overlay_oid_are_revalidated(tmp_path: Path) -> None:
    target_root = tmp_path / "target-oid"
    _materials(target_root, target_database_oid=102)

    with pytest.raises(DisposablePreflightError, match="target_attestation"):
        compile_preflight(PreflightPaths(root=target_root), now=_NOW)

    overlay_root = tmp_path / "overlay-oid"
    _materials(overlay_root, overlay_database_oid=102)

    with pytest.raises(DisposablePreflightError, match="postgres_overlay"):
        compile_preflight(PreflightPaths(root=overlay_root), now=_NOW)


def test_provider_snapshot_replay_is_rejected(tmp_path: Path) -> None:
    root = tmp_path / "replayed-provider"
    _materials(root, provider_epoch="snapshot-replayed")

    with pytest.raises(DisposablePreflightError, match="provider_declaration"):
        compile_preflight(PreflightPaths(root=root), now=_NOW)


def test_transport_rejects_cleartext_published_lan() -> None:
    authority = "http://198.51.100.77:8080"

    with pytest.raises(ValueError, match="transport profile is unsafe"):
        TransportContractV1(
            profile=DisposableTransportProfile.UNPUBLISHED_LOOPBACK_OR_NETWORK,
            authority=authority,
            authority_sha256=_digest(authority.encode()),
            listener_binding="isolated_network_only",
            host_listener_port=8080,
            isolated_network_name="isolated-network",
        )


def test_cli_blocks_without_creating_artifacts(
    tmp_path: Path, capsys: pytest.CaptureFixture[str]
) -> None:
    root = tmp_path / "missing"
    root.mkdir(mode=0o700)

    assert main(["preflight", "--root", str(root)]) == 2

    output = capsys.readouterr().out
    assert '"status":"blocked"' in output
    assert list(root.iterdir()) == []


class _Provider:
    def __init__(
        self,
        fingerprints: Mapping[str, str],
        *,
        mutate_artifact: Path | None = None,
        mutate_provider: bool = False,
    ) -> None:
        self._fingerprints = fingerprints
        self._mutate_artifact = mutate_artifact
        self._mutate_provider = mutate_provider
        self._mutated = False
        self._references: tuple[ProviderReferenceV1, ...] = ()

    def acquire(self, references: tuple[ProviderReferenceV1, ...]) -> _Provider:
        self._references = references
        return self

    def __enter__(self) -> _Provider:
        return self

    def __exit__(self, exception_type: object, exception: object, traceback: object) -> None:
        del exception_type, exception, traceback

    def inspect(self, reference: ProviderReferenceV1) -> ProviderProvenance | None:
        if self._mutate_artifact is not None and not self._mutated:
            self._mutate_artifact.write_text(
                self._mutate_artifact.read_text(encoding="utf-8") + "\n", encoding="utf-8"
            )
            self._mutate_artifact.chmod(0o600)
            self._mutated = True
        return ProviderProvenance(
            provider=reference.provider,
            service=reference.service,
            account=reference.account,
            version=reference.version,
            reference_sha256=reference.reference_sha256,
            fingerprint_sha256=self._fingerprints[reference.reference_sha256],
        )

    def recheck(self, reference: ProviderReferenceV1) -> ProviderProvenance | None:
        fingerprint = self._fingerprints[reference.reference_sha256]
        if self._mutate_provider and not self._mutated:
            self._mutated = True
            fingerprint = "0" * 64 if fingerprint != "0" * 64 else "1" * 64
        return ProviderProvenance(
            provider=reference.provider,
            service=reference.service,
            account=reference.account,
            version=reference.version,
            reference_sha256=reference.reference_sha256,
            fingerprint_sha256=fingerprint,
        )


def _authorize_materials(
    root: Path,
) -> tuple[TrustedEd25519SignerV1, dict[str, str], Ed25519PrivateKey]:
    """Create value-free sidecars after Phase-A materials have been compiled."""

    _materials(root)
    key = Ed25519PrivateKey.generate()
    public = key.public_key().public_bytes_raw()
    signer = TrustedEd25519SignerV1(
        key_id="test-signer",
        public_key_base64=base64.b64encode(public).decode(),
        public_key_fingerprint_sha256=_digest(public),
    )
    _TEST_SIGNING_KEYS[signer.public_key_fingerprint_sha256] = key
    evidence_names = (
        "approval.yaml",
        "governed-baseline.yaml",
        "target-attestation.yaml",
        "provider-declaration.yaml",
        "registry-verification.yaml",
    )
    for name in evidence_names:
        raw = yaml.safe_load((root / name).read_text(encoding="utf-8"))
        assert type(raw) is dict
        signature = raw["signature"]
        assert type(signature) is dict
        signature["signer_key_id"] = signer.key_id
        signature["signer_public_key_fingerprint_sha256"] = signer.public_key_fingerprint_sha256
        (root / name).write_bytes(yaml.safe_dump(raw, sort_keys=True).encode())
        (root / name).chmod(0o600)
    artifact_names = (
        "proposal.yaml",
        "runtime-contract.yaml",
        "approval.yaml",
        "governed-baseline.yaml",
        "target-attestation.yaml",
        "provider-declaration.yaml",
        "registry-verification.yaml",
        "postgres-overlay.yaml",
    )
    signatures: dict[str, bytes] = {}
    for name in evidence_names:
        content = (root / name).read_bytes()
        signed_content_sha256 = _digest(_canonical_signed_content(name, content))
        signature = key.sign(_signature_message(name, signed_content_sha256))
        signatures[name] = signature
        raw = yaml.safe_load(content)
        assert type(raw) is dict
        marker = raw["signature"]
        assert type(marker) is dict
        marker["detached_signature_sha256"] = _digest(signature)
        (root / name).write_bytes(yaml.safe_dump(raw, sort_keys=True).encode())
        (root / name).chmod(0o600)
    contract = yaml.safe_load((root / "runtime-contract.yaml").read_text(encoding="utf-8"))
    assert type(contract) is dict
    evidence = contract["evidence"]
    assert type(evidence) is dict
    for name, field in (
        ("approval.yaml", "approval_sha256"),
        ("governed-baseline.yaml", "governed_baseline_sha256"),
        ("target-attestation.yaml", "target_attestation_sha256"),
        ("provider-declaration.yaml", "provider_declaration_sha256"),
        ("registry-verification.yaml", "registry_verification_sha256"),
        ("postgres-overlay.yaml", "postgres_overlay_sha256"),
    ):
        evidence[field] = _digest((root / name).read_bytes())
    (root / "runtime-contract.yaml").write_bytes(yaml.safe_dump(contract, sort_keys=True).encode())
    (root / "runtime-contract.yaml").chmod(0o600)
    for name in artifact_names:
        content = (root / name).read_bytes()
        artifact_sha256 = _digest((root / name).read_bytes())
        signed_content_sha256 = _digest(_canonical_signed_content(name, content))
        signature = signatures.get(name, key.sign(_signature_message(name, signed_content_sha256)))
        sidecar = {
            "algorithm": "ed25519",
            "artifact_name": name,
            "artifact_sha256": artifact_sha256,
            "schema_version": "rsd.authorization-signature.v3",
            "signature_base64": base64.b64encode(signature).decode(),
            "signer_key_id": signer.key_id,
            "signed_content_sha256": signed_content_sha256,
        }
        target = root / AuthorizationPaths.signature_name(name)
        target.write_bytes(yaml.safe_dump(sidecar, sort_keys=True).encode())
        target.chmod(0o600)
    fingerprints = {
        reference.reference_sha256: _digest(f"fingerprint:{index}".encode())
        for index, reference in enumerate(_proposal().provider_references.all())
    }
    return signer, fingerprints, key


def _refresh_contract_evidence_hashes(root: Path) -> None:
    contract = yaml.safe_load((root / "runtime-contract.yaml").read_text(encoding="utf-8"))
    assert type(contract) is dict
    evidence = contract["evidence"]
    assert type(evidence) is dict
    for name, field in (
        ("approval.yaml", "approval_sha256"),
        ("governed-baseline.yaml", "governed_baseline_sha256"),
        ("target-attestation.yaml", "target_attestation_sha256"),
        ("provider-declaration.yaml", "provider_declaration_sha256"),
        ("registry-verification.yaml", "registry_verification_sha256"),
        ("postgres-overlay.yaml", "postgres_overlay_sha256"),
    ):
        evidence[field] = _digest((root / name).read_bytes())
    (root / "runtime-contract.yaml").write_bytes(yaml.safe_dump(contract, sort_keys=True).encode())
    (root / "runtime-contract.yaml").chmod(0o600)


def _refresh_sidecar(root: Path, name: str, key: Ed25519PrivateKey, *, resign: bool) -> None:
    target = root / AuthorizationPaths.signature_name(name)
    sidecar = yaml.safe_load(target.read_text(encoding="utf-8"))
    assert type(sidecar) is dict
    content = (root / name).read_bytes()
    signed_content_sha256 = _digest(_canonical_signed_content(name, content))
    sidecar["artifact_sha256"] = _digest(content)
    sidecar["signed_content_sha256"] = signed_content_sha256
    if resign:
        sidecar["signature_base64"] = base64.b64encode(
            key.sign(_signature_message(name, signed_content_sha256))
        ).decode()
    target.write_bytes(yaml.safe_dump(sidecar, sort_keys=True).encode())
    target.chmod(0o600)


def _journal(tmp_path: Path) -> SQLiteAuthorizationJournal:
    root = tmp_path / "journal"
    root.mkdir(mode=0o700, parents=True, exist_ok=True)
    root.chmod(0o700)
    return SQLiteAuthorizationJournal(root / "authorization.sqlite3")


def _initial_journal(tmp_path: Path, paths: AuthorizationPaths) -> SQLiteInitialProvisioningJournal:
    root = tmp_path / f"initial-journal-{_digest(os.fsencode(str(paths.root)))}"
    root.mkdir(mode=0o700, parents=True, exist_ok=True)
    root.chmod(0o700)
    return SQLiteInitialProvisioningJournal(root / "initial-provisioning.sqlite3")


def _planned_service(service: ServiceIdentityV1) -> InitialServicePlanV1:
    return InitialServicePlanV1(
        authority=service.authority,
        authority_sha256=service.authority_sha256,
        machine_id=service.machine_id,
        compose_project=service.compose_project,
        service_name=service.service_name,
        network_name=service.network_name,
        workload_name=service.workload_name,
        image=service.image,
        listener_binding=service.listener_binding,
        host_listener_port=service.host_listener_port,
        isolated_network_alias=service.isolated_network_alias,
    )


def _planned_postgres(postgres: PostgreSQLContractV1) -> InitialPostgreSQLPlanV1:
    return InitialPostgreSQLPlanV1(
        authority=postgres.authority,
        database_name=postgres.database_name,
        schema_name=postgres.schema_name,
        owner_role=postgres.owner_role,
        role_names=postgres.role_names,
        stage_database_prefix=postgres.stage_database_prefix,
        restore_database_prefix=postgres.restore_database_prefix,
    )


def _planned_valkey(cache: ValkeyIdentityV1) -> InitialValkeyPlanV1:
    return InitialValkeyPlanV1(
        compose_project=cache.compose_project,
        service_name=cache.service_name,
        network_name=cache.network_name,
        volume_name=cache.volume_name,
        workload_name=cache.workload_name,
        logical_namespace=cache.logical_namespace,
        credential_reference_sha256=cache.credential_reference_sha256,
        image=cache.image,
    )


def _initial_intent(
    paths: AuthorizationPaths,
    *,
    signer: TrustedEd25519SignerV1,
    journal: SQLiteInitialProvisioningJournal,
    proposal: ProposalV1 | None = None,
) -> InitialProvisioningIntentV1:
    proposal = _proposal() if proposal is None else proposal
    candidate = proposal.candidate
    unsigned = InitialProvisioningIntentV1(
        schema_version="rsd.initial-provisioning-intent.v1",
        operation_kind="initial_provisioning_v1",
        operation_scope="create_isolated_empty_resources_v1",
        provisioning_operation_id="123e4567-e89b-42d3-a456-426614174001",
        source_commit=proposal.source_commit,
        plan=InitialProvisioningPlanV1(
            transport=proposal.transport,
            primary_service=_planned_service(candidate.primary_service),
            restore_service=_planned_service(candidate.restore_service),
            postgres=_planned_postgres(candidate.postgres),
            primary_valkey=_planned_valkey(candidate.primary_valkey),
            restore_valkey=_planned_valkey(candidate.restore_valkey),
        ),
        provider_references=proposal.provider_references,
        evidence=proposal.initial_provisioning_evidence,
        retention_expires_at=proposal.retention_expires_at,
        disposal_owner=proposal.disposal_owner,
        approver_identity="approval-owner",
        approval_reference_sha256=proposal.approval_reference_sha256,
        journal_path=str(journal._path),
        journal_path_sha256=journal._path_sha256(),
        journal_uuid="123e4567-e89b-42d3-a456-426614174002",
        journal_schema_sha256=journal.journal_schema_sha256(),
        replay_policy_sha256=_TEST_REPLAY_POLICY.sha256(),
        created_at=_NOW.isoformat(timespec="seconds").replace("+00:00", "Z"),
        signer_key_id=signer.key_id,
        signature_base64=base64.b64encode(b"0" * 64).decode(),
    )
    key = _TEST_SIGNING_KEYS[signer.public_key_fingerprint_sha256]
    return unsigned.model_copy(
        update={
            "signature_base64": base64.b64encode(
                key.sign(_initial_intent_message(unsigned))
            ).decode()
        }
    )


def _replay_policy_artifact(
    intent: InitialProvisioningIntentV1,
    *,
    signer: TrustedEd25519SignerV1,
) -> ReplayAuthorityPolicyArtifactV1:
    unsigned = ReplayAuthorityPolicyArtifactV1(
        schema_version="rsd.provider-crypto.replay-authority-policy.v1",
        initial_intent_sha256=initial_provisioning_intent_sha256(intent),
        service=_TEST_REPLAY_POLICY.service,
        account_prefix=_TEST_REPLAY_POLICY.account_prefix,
        replay_policy_sha256=_TEST_REPLAY_POLICY.sha256(),
        created_at=_NOW.isoformat(timespec="seconds").replace("+00:00", "Z"),
        signer_key_id=signer.key_id,
        signature_base64=base64.b64encode(b"0" * 64).decode(),
    )
    key = _TEST_SIGNING_KEYS[signer.public_key_fingerprint_sha256]
    return unsigned.model_copy(
        update={
            "signature_base64": base64.b64encode(
                key.sign(replay_authority_policy_message(unsigned))
            ).decode()
        }
    )


def _provider_signer_for_intent(
    intent: InitialProvisioningIntentV1,
    *,
    issuer: TrustedEd25519SignerV1,
) -> tuple[TrustedEd25519SignerV1, SignerGenesisV1]:
    """Create one test-only child signer bound to this exact signed intent."""

    intent_sha256 = initial_provisioning_intent_sha256(intent)
    cache_key = (issuer.public_key_fingerprint_sha256, intent_sha256)
    cached = _TEST_PROVIDER_SIGNERS.get(cache_key)
    if cached is not None:
        return cached
    issuer_key = _TEST_SIGNING_KEYS[issuer.public_key_fingerprint_sha256]
    private_key = Ed25519PrivateKey.generate()
    seed = private_key.private_bytes(
        serialization.Encoding.Raw,
        serialization.PrivateFormat.Raw,
        serialization.NoEncryption(),
    )
    public = private_key.public_key().public_bytes(
        serialization.Encoding.Raw,
        serialization.PublicFormat.Raw,
    )
    suffix = intent_sha256[:16]
    fields = {
        "account": f"provider-signer-{suffix}.v1",
        "provider": "macos_keychain",
        "service": "provider-material-signer",
        "version": 1,
    }
    provider_signer = TrustedEd25519SignerV1(
        key_id=f"provider-material-{suffix}",
        public_key_base64=base64.b64encode(public).decode(),
        public_key_fingerprint_sha256=_digest(public),
    )
    unsigned = SignerGenesisV1(
        schema_version="rsd.provider-crypto.signer-genesis.v1",
        initial_intent_sha256=intent_sha256,
        issuer_key_id=issuer.key_id,
        key_id=provider_signer.key_id,
        public_key_base64=provider_signer.public_key_base64,
        public_key_fingerprint_sha256=provider_signer.public_key_fingerprint_sha256,
        seed_fingerprint_sha256=_digest(seed),
        keychain_reference=KeychainItemReferenceV1(
            **fields,
            reference_sha256=_digest(
                json.dumps(fields, sort_keys=True, separators=(",", ":")).encode()
            ),
        ),
        created_at=_NOW.isoformat(timespec="seconds").replace("+00:00", "Z"),
        signature_base64=base64.b64encode(b"0" * 64).decode(),
    )
    genesis = unsigned.model_copy(
        update={
            "signature_base64": base64.b64encode(
                issuer_key.sign(signer_genesis_message(unsigned))
            ).decode()
        }
    )
    _TEST_SIGNING_KEYS[provider_signer.public_key_fingerprint_sha256] = private_key
    result = (provider_signer, genesis)
    _TEST_PROVIDER_SIGNERS[cache_key] = result
    return result


def _provider_material_bundle(
    intent: InitialProvisioningIntentV1,
    *,
    signer: TrustedEd25519SignerV1,
    fingerprints: Mapping[str, str],
) -> tuple[ProviderMaterialPolicyV1, ProviderFingerprintAttestationV1, ProviderMaterialGenesisV1]:
    provider_signer, signer_genesis = _provider_signer_for_intent(intent, issuer=signer)
    references = intent.provider_references
    definitions: tuple[
        tuple[ProviderMaterialPurpose, ProviderMaterialFormat, int, int, ProviderReferenceV1], ...
    ] = (
        (
            ProviderMaterialPurpose.COMMITMENT_HMAC,
            ProviderMaterialFormat.HMAC_SHA256_RAW_32_V1,
            32,
            32,
            references.commitment_hmac,
        ),
        (
            ProviderMaterialPurpose.BACKUP_ENCRYPTION,
            ProviderMaterialFormat.AES_256_GCM_RAW_32_V1,
            32,
            32,
            references.backup_encryption,
        ),
        (
            ProviderMaterialPurpose.INFISICAL_ENCRYPTION_KEY,
            ProviderMaterialFormat.INFISICAL_HEX_16_V1,
            32,
            32,
            references.encryption_key,
        ),
        (
            ProviderMaterialPurpose.INFISICAL_AUTH_SECRET,
            ProviderMaterialFormat.INFISICAL_AUTH_SECRET_BASE64_32_V1,
            44,
            44,
            references.auth_secret,
        ),
        (
            ProviderMaterialPurpose.PRIMARY_VALKEY_PASSWORD,
            ProviderMaterialFormat.VALKEY_PASSWORD_BASE64URL_32_V1,
            43,
            43,
            references.primary_valkey_password,
        ),
        (
            ProviderMaterialPurpose.RESTORE_VALKEY_PASSWORD,
            ProviderMaterialFormat.VALKEY_PASSWORD_BASE64URL_32_V1,
            43,
            43,
            references.restore_valkey_password,
        ),
    )
    if references.tls_trust_anchor is not None:
        definitions = (
            *definitions,
            (
                ProviderMaterialPurpose.TLS_TRUST_ANCHOR,
                ProviderMaterialFormat.X509_CA_PEM_V1,
                1,
                131_072,
                references.tls_trust_anchor,
            ),
        )
    unsigned_policy = ProviderMaterialPolicyV1(
        schema_version="rsd.provider-crypto.material-policy.v1",
        initial_intent_sha256=initial_provisioning_intent_sha256(intent),
        disposal_owner="acceptance-owner",
        approver_identity="approval-owner",
        policy_id="123e4567-e89b-42d3-a456-426614174003",
        signer_keychain_reference=signer_genesis.keychain_reference,
        signer_seed_fingerprint_sha256=signer_genesis.seed_fingerprint_sha256,
        created_at=_NOW.isoformat(timespec="seconds").replace("+00:00", "Z"),
        retention_expires_at=intent.retention_expires_at,
        materials=tuple(
            ProviderMaterialSpecV1(
                purpose=purpose,
                reference=reference,
                format=material_format,
                value_min_bytes=minimum,
                value_max_bytes=maximum,
            )
            for purpose, material_format, minimum, maximum, reference in definitions
        ),
        signer_key_id=provider_signer.key_id,
        signature_base64=base64.b64encode(b"0" * 64).decode(),
    )
    key = _TEST_SIGNING_KEYS[provider_signer.public_key_fingerprint_sha256]
    policy = unsigned_policy.model_copy(
        update={
            "signature_base64": base64.b64encode(
                key.sign(provider_material_policy_message(unsigned_policy))
            ).decode()
        }
    )
    unsigned_attestation = ProviderFingerprintAttestationV1(
        schema_version="rsd.provider-crypto.fingerprint-attestation.v1",
        initial_intent_sha256=initial_provisioning_intent_sha256(intent),
        provider_material_policy_sha256=policy.policy_sha256(),
        attestation_id="123e4567-e89b-42d3-a456-426614174004",
        observed_at=_NOW.isoformat(timespec="seconds").replace("+00:00", "Z"),
        materials=tuple(
            ProviderMaterialFingerprintV1(
                purpose=purpose,
                reference_sha256=reference.reference_sha256,
                fingerprint_sha256=fingerprints[reference.reference_sha256],
            )
            for purpose, _format, _minimum, _maximum, reference in definitions
        ),
        signer_key_id=provider_signer.key_id,
        signature_base64=base64.b64encode(b"0" * 64).decode(),
    )
    attestation = unsigned_attestation.model_copy(
        update={
            "signature_base64": base64.b64encode(
                key.sign(provider_fingerprint_attestation_message(unsigned_attestation))
            ).decode()
        }
    )
    unsigned_genesis = ProviderMaterialGenesisV1(
        schema_version="rsd.provider-crypto.material-genesis.v1",
        status="pending",
        genesis_id="123e4567-e89b-42d3-a456-426614174005",
        initial_intent_sha256=initial_provisioning_intent_sha256(intent),
        provider_material_policy_sha256=policy.policy_sha256(),
        provider_fingerprint_attestation_sha256=_digest(
            json.dumps(
                attestation.model_dump(mode="json"), sort_keys=True, separators=(",", ":")
            ).encode()
        ),
        created_at=_NOW.isoformat(timespec="seconds").replace("+00:00", "Z"),
        signer_key_id=provider_signer.key_id,
        signature_base64=base64.b64encode(b"0" * 64).decode(),
    )
    genesis = unsigned_genesis.model_copy(
        update={
            "signature_base64": base64.b64encode(
                key.sign(provider_material_genesis_message(unsigned_genesis))
            ).decode()
        }
    )
    return policy, attestation, genesis


def _persist_completed_provider_material_bundle_for_test(
    paths: AuthorizationPaths,
    *,
    intent: InitialProvisioningIntentV1,
    signer: TrustedEd25519SignerV1,
    fingerprints: Mapping[str, str],
) -> tuple[ProviderMaterialPolicyV1, ProviderFingerprintAttestationV1, ProviderMaterialGenesisV1]:
    """Install a complete signed non-secret fixture before authorization tests.

    Production authorization never accepts these models from a caller.  This
    setup helper writes the same immutable artifact set a completed create-only
    bootstrap would leave, so the authorization test exercises the descriptor
    relative persisted-artifact path rather than an in-memory bypass.
    """

    _provider_signer, signer_genesis = _provider_signer_for_intent(intent, issuer=signer)
    policy, attestation, material_genesis = _provider_material_bundle(
        intent,
        signer=signer,
        fingerprints=fingerprints,
    )
    artifact_paths = ProviderMaterialArtifactPaths(paths.root)
    _write(paths.root, artifact_paths.signer_genesis_name(), signer_genesis)
    _write(paths.root, artifact_paths.policy_name(), policy)
    _write(paths.root, artifact_paths.genesis_name(), material_genesis)
    _write(paths.root, artifact_paths.attestation_name(), attestation)
    return policy, attestation, material_genesis


def _provider_material_values(
    *, include_tls_trust_anchor: bool = False
) -> dict[ProviderMaterialPurpose, bytearray]:
    values = {
        ProviderMaterialPurpose.COMMITMENT_HMAC: bytearray(b"c" * 32),
        ProviderMaterialPurpose.BACKUP_ENCRYPTION: bytearray(b"b" * 32),
        ProviderMaterialPurpose.INFISICAL_ENCRYPTION_KEY: bytearray(
            b"0123456789abcdef0123456789abcdef"
        ),
        ProviderMaterialPurpose.INFISICAL_AUTH_SECRET: bytearray(base64.b64encode(b"a" * 32)),
        ProviderMaterialPurpose.PRIMARY_VALKEY_PASSWORD: bytearray(
            base64.urlsafe_b64encode(b"p" * 32).rstrip(b"=")
        ),
        ProviderMaterialPurpose.RESTORE_VALKEY_PASSWORD: bytearray(
            base64.urlsafe_b64encode(b"r" * 32).rstrip(b"=")
        ),
    }
    if not include_tls_trust_anchor:
        return values
    certificate_key = Ed25519PrivateKey.generate()
    name = x509.Name([x509.NameAttribute(NameOID.COMMON_NAME, "provider-test-ca")])
    certificate = (
        x509.CertificateBuilder()
        .subject_name(name)
        .issuer_name(name)
        .public_key(certificate_key.public_key())
        .serial_number(1)
        .not_valid_before(_NOW - timedelta(days=1))
        .not_valid_after(_NOW + timedelta(days=1))
        .add_extension(x509.BasicConstraints(ca=True, path_length=None), critical=True)
        .sign(certificate_key, algorithm=None)
    )
    values[ProviderMaterialPurpose.TLS_TRUST_ANCHOR] = bytearray(
        certificate.public_bytes(serialization.Encoding.PEM)
    )
    return values


def _material_fingerprints(
    intent: InitialProvisioningIntentV1,
    values: Mapping[ProviderMaterialPurpose, bytearray],
) -> dict[str, str]:
    references = intent.provider_references
    bindings: tuple[tuple[ProviderMaterialPurpose, ProviderReferenceV1 | None], ...] = (
        (ProviderMaterialPurpose.COMMITMENT_HMAC, references.commitment_hmac),
        (ProviderMaterialPurpose.BACKUP_ENCRYPTION, references.backup_encryption),
        (ProviderMaterialPurpose.INFISICAL_ENCRYPTION_KEY, references.encryption_key),
        (ProviderMaterialPurpose.INFISICAL_AUTH_SECRET, references.auth_secret),
        (ProviderMaterialPurpose.PRIMARY_VALKEY_PASSWORD, references.primary_valkey_password),
        (ProviderMaterialPurpose.RESTORE_VALKEY_PASSWORD, references.restore_valkey_password),
        (ProviderMaterialPurpose.TLS_TRUST_ANCHOR, references.tls_trust_anchor),
    )
    return {
        reference.reference_sha256: _digest(values[purpose])
        for purpose, reference in bindings
        if reference is not None
    }


class _CreateOnlyMaterialStore:
    """In-memory test double; production APIs default to Security.framework."""

    def __init__(self, *, fail_after: int | None = None, failure_message: str = "") -> None:
        self.records: dict[tuple[str, str], bytes] = {}
        self._fail_after = fail_after
        self._failure_message = failure_message
        self._writes = 0

    def add_if_absent(self, service: str, account: str, value: bytearray) -> bool:
        if self._fail_after is not None and self._writes >= self._fail_after:
            raise RuntimeError(self._failure_message)
        key = (service, account)
        if key in self.records:
            return False
        self.records[key] = bytes(value)
        self._writes += 1
        return True

    def read_if_present(self, service: str, account: str) -> bytearray | None:
        value = self.records.get((service, account))
        return None if value is None else bytearray(value)


def _observed_service_resources(service: ServiceIdentityV1) -> ObservedServiceResourcesV1:
    return ObservedServiceResourcesV1(
        network_name=service.network_name,
        network_id=service.network_id,
        container_id=service.container_id,
        workload_name=service.workload_name,
        workload_id=service.workload_id,
    )


def _observed_valkey_resources(cache: ValkeyIdentityV1) -> ObservedValkeyResourcesV1:
    return ObservedValkeyResourcesV1(
        **_observed_service_resources(cache).model_dump(mode="python"),
        volume_name=cache.volume_name,
        volume_id=cache.volume_id,
    )


def _observed_resources(proposal: ProposalV1) -> ObservedResourceSetV1:
    candidate = proposal.candidate
    return ObservedResourceSetV1(
        postgres_system_identifier=candidate.postgres.system_identifier,
        postgres_database_oid=candidate.postgres.database_oid,
        primary_service=_observed_service_resources(candidate.primary_service),
        restore_service=_observed_service_resources(candidate.restore_service),
        primary_valkey=_observed_valkey_resources(candidate.primary_valkey),
        restore_valkey=_observed_valkey_resources(candidate.restore_valkey),
    )


def _initial_effect(
    context: InitialProvisioningExecutionContext,
) -> InitialProvisioningEffectReceiptV1:
    return InitialProvisioningEffectReceiptV1(
        schema_version="rsd.initial-provisioning-effect-receipt.v1",
        operation_kind="initial_provisioning_v1",
        operation_scope="create_isolated_empty_resources_v1",
        status="created_isolated_empty_resources",
        provisioning_operation_id=context.provisioning_operation_id,
        intent_sha256=context.intent_sha256,
        journal_uuid=context.intent.journal_uuid,
        idempotency_key=context.idempotency_key,
        observed_resources=_observed_resources(_proposal()),
        effect_receipt_sha256="e" * 64,
        completed_at=_NOW.isoformat(timespec="seconds").replace("+00:00", "Z"),
    )


def _observed_attestation(
    intent: InitialProvisioningIntentV1,
    receipt: InitialProvisioningEffectReceiptV1,
    *,
    signer: TrustedEd25519SignerV1,
    proposal: ProposalV1 | None = None,
) -> ObservedCandidateAttestationV1:
    proposal = _proposal() if proposal is None else proposal
    unsigned = ObservedCandidateAttestationV1(
        schema_version="rsd.observed-candidate-attestation.v1",
        operation_kind="observed_lifecycle_v1",
        provisioning_operation_id=intent.provisioning_operation_id,
        observed_operation_id=proposal.operation_id,
        initial_provisioning_intent_sha256=initial_provisioning_intent_sha256(intent),
        provisioning_effect_receipt_sha256=initial_provisioning_effect_receipt_sha256(receipt),
        proposal_sha256=proposal_sha256(proposal),
        candidate=proposal.candidate,
        candidate_composite_sha256=canonical_sha256(proposal.candidate),
        observed_resources=receipt.observed_resources,
        observed_at=_NOW.isoformat(timespec="seconds").replace("+00:00", "Z"),
        signer_key_id=signer.key_id,
        signature_base64=base64.b64encode(b"0" * 64).decode(),
    )
    key = _TEST_SIGNING_KEYS[signer.public_key_fingerprint_sha256]
    return unsigned.model_copy(
        update={
            "signature_base64": base64.b64encode(
                key.sign(_observed_candidate_attestation_message(unsigned))
            ).decode()
        }
    )


def _resign_initial_intent(
    intent: InitialProvisioningIntentV1,
    *,
    signer: TrustedEd25519SignerV1,
    updates: Mapping[str, object],
) -> InitialProvisioningIntentV1:
    raw = intent.model_dump(mode="python")
    raw.update(updates)
    raw["signature_base64"] = base64.b64encode(b"0" * 64).decode()
    unsigned = InitialProvisioningIntentV1.model_validate(raw)
    key = _TEST_SIGNING_KEYS[signer.public_key_fingerprint_sha256]
    return unsigned.model_copy(
        update={
            "signature_base64": base64.b64encode(
                key.sign(_initial_intent_message(unsigned))
            ).decode()
        }
    )


def _initial_genesis_reconciliation(
    intent: InitialProvisioningIntentV1,
    *,
    signer: TrustedEd25519SignerV1,
    outcome: Literal["provisioning_completed", "provisioning_abandoned"],
) -> InitialJournalGenesisReconciliationReceiptV1:
    unsigned = InitialJournalGenesisReconciliationReceiptV1(
        schema_version="rsd.initial-provisioning-journal-genesis-reconciliation.v1",
        outcome=outcome,
        journal_uuid=intent.journal_uuid,
        journal_path_sha256=intent.journal_path_sha256,
        intent_sha256=initial_provisioning_intent_sha256(intent),
        created_at=_NOW.isoformat(timespec="seconds").replace("+00:00", "Z"),
        signer_key_id=signer.key_id,
        signature_base64=base64.b64encode(b"0" * 64).decode(),
    )
    key = _TEST_SIGNING_KEYS[signer.public_key_fingerprint_sha256]
    return unsigned.model_copy(
        update={
            "signature_base64": base64.b64encode(
                key.sign(_initial_journal_genesis_reconciliation_message(unsigned))
            ).decode()
        }
    )


def _ensure_test_initial_stage(
    paths: AuthorizationPaths,
    *,
    signer: TrustedEd25519SignerV1,
    provider: _Provider,
    provider_fingerprints: Mapping[str, str],
    expected_disposal_owner: str,
    expected_approver_identity: str,
    journal: SQLiteInitialProvisioningJournal,
    replay_authority: ProtocolReplayAuthority,
) -> None:
    with _TEST_PROVISION_LOCK:
        if journal.migration_status() is InitialProvisioningJournalStatus.ABSENT:
            intent = _initial_intent(paths, signer=signer, journal=journal)
            _persist_completed_provider_material_bundle_for_test(
                paths,
                intent=intent,
                signer=signer,
                fingerprints=provider_fingerprints,
            )
            _provision_initial_journal_for_test(
                paths,
                signer=signer,
                expected_disposal_owner=expected_disposal_owner,
                expected_approver_identity=expected_approver_identity,
                journal=journal,
                intent=intent,
                replay_authority=replay_authority,
                replay_policy=_TEST_REPLAY_POLICY,
                replay_policy_artifact=_replay_policy_artifact(intent, signer=signer),
                _clock=lambda: _NOW,
            )
            _authorize_initial_provisioning_and_execute_for_test(
                paths,
                signer=signer,
                provider=provider,
                expected_disposal_owner=expected_disposal_owner,
                expected_approver_identity=expected_approver_identity,
                journal=journal,
                effect=_initial_effect,
                replay_authority=replay_authority,
                replay_policy=_TEST_REPLAY_POLICY,
                _clock=lambda: _NOW,
            )
            # Read the committed immutable receipt rather than trusting the helper object.
            raw = (paths.root / paths.initial_receipt_name()).read_bytes()
            stored = InitialProvisioningEffectReceiptV1.model_validate(yaml.safe_load(raw))
            _write(
                paths.root,
                paths.observed_attestation_name(),
                _observed_attestation(intent, stored, signer=signer),
            )


def _root_lock_path(root: Path) -> Path:
    canonical = root.resolve(strict=True)
    parent_details = os.lstat(canonical.parent)
    root_details = os.lstat(canonical)
    name, _ = ArtifactRootLease._lock_name_for_identities(
        (parent_details.st_dev, parent_details.st_ino),
        (root_details.st_dev, root_details.st_ino),
    )
    return canonical.parent / name


def _effect(context: VerifiedExecutionContext) -> EffectReceiptV1:
    assert not hasattr(context, "root")
    return EffectReceiptV1(
        schema_version="rsd.lifecycle-effect-receipt.v1",
        operation_kind="observed_lifecycle_v1",
        operation_id=context.operation_id,
        idempotency_key=context.idempotency_key,
        effect_receipt_sha256="f" * 64,
    )


def _journal_genesis_receipt(
    paths: AuthorizationPaths,
    *,
    signer: TrustedEd25519SignerV1,
    journal: SQLiteAuthorizationJournal,
    expected_disposal_owner: str,
    expected_approver_identity: str,
) -> JournalGenesisReceiptV1:
    key = _TEST_SIGNING_KEYS[signer.public_key_fingerprint_sha256]
    created = _NOW
    compiled = compile_preflight(paths.preflight(), now=created)
    unsigned = JournalGenesisReceiptV1(
        schema_version="rsd.authorization-journal-genesis.v1",
        operation_domain="rsd.observed-lifecycle-operation.v1",
        operation_kind="observed_lifecycle_v1",
        operation_id=compiled.operation_id,
        proposal_sha256=compiled.proposal_sha256,
        contract_sha256=compiled.contract_sha256,
        disposal_owner=expected_disposal_owner,
        approver_identity=expected_approver_identity,
        journal_path=str(journal._path),
        journal_path_sha256=journal._path_sha256(),
        journal_uuid=str(uuid.uuid4()),
        journal_schema_sha256=journal.journal_schema_sha256(),
        replay_policy_sha256=_TEST_REPLAY_POLICY.sha256(),
        created_at=created.isoformat(timespec="seconds").replace("+00:00", "Z"),
        signer_key_id=signer.key_id,
        signature_base64=base64.b64encode(b"0" * 64).decode(),
    )
    return unsigned.model_copy(
        update={
            "signature_base64": base64.b64encode(
                key.sign(_journal_genesis_message(unsigned))
            ).decode()
        }
    )


def _ensure_test_journal_provisioned(
    paths: AuthorizationPaths,
    *,
    signer: TrustedEd25519SignerV1,
    expected_disposal_owner: str,
    expected_approver_identity: str,
    journal: SQLiteAuthorizationJournal,
    replay_authority: ProtocolReplayAuthority | None = None,
) -> None:
    """Use the explicit public provisioning boundary; authorization never does this."""

    authority = _test_replay_authority(journal) if replay_authority is None else replay_authority
    with _TEST_PROVISION_LOCK:
        if journal.migration_status() is not JournalMigrationStatus.ABSENT:
            return
        receipt = _journal_genesis_receipt(
            paths,
            signer=signer,
            journal=journal,
            expected_disposal_owner=expected_disposal_owner,
            expected_approver_identity=expected_approver_identity,
        )
        _provision_journal_for_test(
            paths,
            signer=signer,
            expected_disposal_owner=expected_disposal_owner,
            expected_approver_identity=expected_approver_identity,
            journal=journal,
            receipt=receipt,
            replay_authority=authority,
            replay_policy=_TEST_REPLAY_POLICY,
            _clock=lambda: _NOW,
        )


def _genesis_reconciliation_receipt(
    receipt: JournalGenesisReceiptV1,
    *,
    signer: TrustedEd25519SignerV1,
    outcome: Literal["provisioning_completed", "provisioning_abandoned"],
) -> JournalGenesisReconciliationReceiptV1:
    key = _TEST_SIGNING_KEYS[signer.public_key_fingerprint_sha256]
    genesis_sha256 = _digest(
        yaml.safe_dump(receipt.model_dump(mode="json"), sort_keys=True).encode()
    )
    unsigned = JournalGenesisReconciliationReceiptV1(
        schema_version="rsd.authorization-journal-genesis-reconciliation.v1",
        outcome=outcome,
        journal_uuid=receipt.journal_uuid,
        journal_path_sha256=receipt.journal_path_sha256,
        genesis_sha256=genesis_sha256,
        created_at=_NOW.isoformat(timespec="seconds").replace("+00:00", "Z"),
        signer_key_id=signer.key_id,
        signature_base64=base64.b64encode(b"0" * 64).decode(),
    )
    return unsigned.model_copy(
        update={
            "signature_base64": base64.b64encode(
                key.sign(_journal_genesis_reconciliation_message(unsigned))
            ).decode()
        }
    )


def _execute_for_test(
    paths: AuthorizationPaths,
    *,
    signer: TrustedEd25519SignerV1,
    provider: _Provider,
    provider_fingerprints: Mapping[str, str],
    expected_disposal_owner: str,
    expected_approver_identity: str,
    journal: SQLiteAuthorizationJournal,
    effect: Callable[[VerifiedExecutionContext], EffectReceiptV1],
    now: datetime = _NOW,
    provision: bool = True,
    replay_authority: ProtocolReplayAuthority | None = None,
) -> ExecutionReceiptV1:
    authority = _test_replay_authority(journal) if replay_authority is None else replay_authority
    initial_journal = _initial_journal(paths.root.parent, paths)
    if provision:
        _ensure_test_journal_provisioned(
            paths,
            signer=signer,
            expected_disposal_owner=expected_disposal_owner,
            expected_approver_identity=expected_approver_identity,
            journal=journal,
            replay_authority=authority,
        )
    if journal.migration_status() is JournalMigrationStatus.CURRENT:
        _ensure_test_initial_stage(
            paths,
            signer=signer,
            provider=provider,
            provider_fingerprints=provider_fingerprints,
            expected_disposal_owner=expected_disposal_owner,
            expected_approver_identity=expected_approver_identity,
            journal=initial_journal,
            replay_authority=authority,
        )
    return _authorize_and_execute_for_test(
        paths,
        signer=signer,
        provider=provider,
        expected_disposal_owner=expected_disposal_owner,
        expected_approver_identity=expected_approver_identity,
        journal=journal,
        initial_journal=initial_journal,
        effect=effect,
        replay_authority=authority,
        replay_policy=_TEST_REPLAY_POLICY,
        _clock=lambda: now,
    )


def test_phase_b_executes_only_after_durable_claim(tmp_path: Path) -> None:
    root = tmp_path / "artifacts"
    signer, fingerprints, _ = _authorize_materials(root)

    receipt = _execute_for_test(
        AuthorizationPaths(root),
        signer=signer,
        provider=_Provider(fingerprints),
        provider_fingerprints=fingerprints,
        expected_disposal_owner="acceptance-owner",
        expected_approver_identity="approval-owner",
        journal=_journal(tmp_path),
        effect=_effect,
        now=_NOW,
    )

    assert receipt.status == "committed"
    assert "nonce" not in receipt.model_dump()


def test_initial_intent_is_name_only_and_transport_accepts_no_legacy_alias(
    tmp_path: Path,
) -> None:
    root = tmp_path / "artifacts"
    signer, _, _ = _authorize_materials(root)
    paths = AuthorizationPaths(root)
    intent = _initial_intent(paths, signer=signer, journal=_initial_journal(tmp_path, paths))

    assert "database_oid" not in intent.plan.postgres.model_dump()
    assert "container_id" not in intent.plan.primary_service.model_dump()
    assert "volume_id" not in intent.plan.primary_valkey.model_dump()

    for section, field, value in (
        ("postgres", "database_oid", 101),
        ("primary_service", "container_id", "a" * 64),
        ("primary_valkey", "volume_id", "b" * 64),
    ):
        raw = intent.model_dump(mode="python")
        raw["plan"][section][field] = value
        with pytest.raises(ValueError):
            InitialProvisioningIntentV1.model_validate(raw)

    transport = _proposal().transport.model_dump(mode="python")
    transport["isolated_network_id"] = "old-network-spelling"
    with pytest.raises(ValueError):
        TransportContractV1.model_validate(transport)


def test_transition_rejects_cross_intent_and_changed_planned_fields(tmp_path: Path) -> None:
    root = tmp_path / "artifacts"
    signer, _, _ = _authorize_materials(root)
    paths = AuthorizationPaths(root)
    intent = _initial_intent(paths, signer=signer, journal=_initial_journal(tmp_path, paths))
    proposal = _proposal()
    receipt = InitialProvisioningEffectReceiptV1(
        schema_version="rsd.initial-provisioning-effect-receipt.v1",
        operation_kind="initial_provisioning_v1",
        operation_scope="create_isolated_empty_resources_v1",
        status="created_isolated_empty_resources",
        provisioning_operation_id=intent.provisioning_operation_id,
        intent_sha256=initial_provisioning_intent_sha256(intent),
        journal_uuid=intent.journal_uuid,
        idempotency_key="a" * 64,
        observed_resources=_observed_resources(proposal),
        effect_receipt_sha256="b" * 64,
        completed_at=_NOW.isoformat(timespec="seconds").replace("+00:00", "Z"),
    )
    attestation = _observed_attestation(intent, receipt, signer=signer, proposal=proposal)

    validate_observed_candidate_transition(
        intent,
        receipt,
        attestation,
        proposal,
        _runtime_contract(proposal),
    )

    cross_intent = _resign_initial_intent(
        intent,
        signer=signer,
        updates={"provisioning_operation_id": "123e4567-e89b-42d3-a456-426614174099"},
    )
    with pytest.raises(ValueError, match="initial stage transition"):
        validate_observed_candidate_transition(
            cross_intent,
            receipt,
            attestation,
            proposal,
            _runtime_contract(proposal),
        )

    network_service = proposal.candidate.primary_service.model_copy(
        update={"network_name": "changed-network"}
    )
    network_candidate = proposal.candidate.model_copy(update={"primary_service": network_service})
    network_proposal = proposal.model_copy(update={"candidate": network_candidate})

    changed_postgres = proposal.candidate.postgres.model_copy(
        update={"database_name": "changed-database"}
    )
    database_candidate = proposal.candidate.model_copy(update={"postgres": changed_postgres})
    database_proposal = proposal.model_copy(update={"candidate": database_candidate})

    other_image = ImageReferenceV1(reference=f"registry.example.test/infisical@sha256:{'e' * 64}")
    image_candidate = proposal.candidate.model_copy(
        update={
            "primary_service": proposal.candidate.primary_service.model_copy(
                update={"image": other_image}
            ),
            "restore_service": proposal.candidate.restore_service.model_copy(
                update={"image": other_image}
            ),
        }
    )
    image_proposal = proposal.model_copy(
        update={
            "candidate": image_candidate,
            "primary_image": other_image,
            "restore_image": other_image,
        }
    )

    for changed in (network_proposal, database_proposal, image_proposal):
        changed_receipt = receipt.model_copy(
            update={"observed_resources": _observed_resources(changed)}
        )
        changed_attestation = _observed_attestation(
            intent, changed_receipt, signer=signer, proposal=changed
        )
        with pytest.raises(ValueError, match="initial plan does not match"):
            validate_observed_candidate_transition(
                intent,
                changed_receipt,
                changed_attestation,
                changed,
                _runtime_contract(changed),
            )

    missing_oid = proposal.candidate.postgres.model_dump(mode="python")
    del missing_oid["database_oid"]
    with pytest.raises(ValueError):
        PostgreSQLContractV1.model_validate(missing_oid)


def test_initial_scope_cannot_be_used_as_observed_effect_authority(tmp_path: Path) -> None:
    root = tmp_path / "artifacts"
    signer, fingerprints, _ = _authorize_materials(root)
    paths = AuthorizationPaths(root)
    journal = _initial_journal(tmp_path, paths)
    authority = _AtomicReplayAuthority()
    intent = _initial_intent(paths, signer=signer, journal=journal)
    _persist_completed_provider_material_bundle_for_test(
        paths,
        intent=intent,
        signer=signer,
        fingerprints=fingerprints,
    )
    _provision_initial_journal_for_test(
        paths,
        signer=signer,
        expected_disposal_owner="acceptance-owner",
        expected_approver_identity="approval-owner",
        journal=journal,
        intent=intent,
        replay_authority=authority,
        replay_policy=_TEST_REPLAY_POLICY,
        replay_policy_artifact=_replay_policy_artifact(intent, signer=signer),
        _clock=lambda: _NOW,
    )
    seen: list[InitialProvisioningExecutionContext] = []

    def overreaching_effect(context: InitialProvisioningExecutionContext) -> EffectReceiptV1:
        seen.append(context)
        return EffectReceiptV1(
            schema_version="rsd.lifecycle-effect-receipt.v1",
            operation_kind="observed_lifecycle_v1",
            operation_id=_proposal().operation_id,
            idempotency_key="a" * 64,
            effect_receipt_sha256="b" * 64,
        )

    with pytest.raises(AuthorizationError, match="initial_effect_failed_recovery_required"):
        _authorize_initial_provisioning_and_execute_for_test(
            paths,
            signer=signer,
            provider=_Provider(fingerprints),
            expected_disposal_owner="acceptance-owner",
            expected_approver_identity="approval-owner",
            journal=journal,
            effect=overreaching_effect,  # type: ignore[arg-type]
            replay_authority=authority,
            replay_policy=_TEST_REPLAY_POLICY,
            _clock=lambda: _NOW,
        )

    assert len(seen) == 1
    context = seen[0]
    assert context.operation_kind == "initial_provisioning_v1"
    assert context.operation_scope == "create_isolated_empty_resources_v1"
    assert not hasattr(context, "proposal")
    assert "database_oid" not in context.intent.plan.postgres.model_dump()
    assert (
        journal.operation_state(intent.provisioning_operation_id)
        is InitialProvisioningOperationState.FAILED_RECOVERY_REQUIRED
    )


def test_initial_genesis_reconciliation_never_retries_creation(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    root = tmp_path / "artifacts"
    signer, _, _ = _authorize_materials(root)
    paths = AuthorizationPaths(root)
    journal = _initial_journal(tmp_path, paths)
    authority = _AtomicReplayAuthority()
    intent = _initial_intent(paths, signer=signer, journal=journal)
    original = journal._set_marker_current

    def interrupt(marker: object) -> None:
        del marker
        raise AuthorizationError("simulated_interrupt")

    monkeypatch.setattr(journal, "_set_marker_current", interrupt)
    with pytest.raises(AuthorizationError, match="simulated_interrupt"):
        _provision_initial_journal_for_test(
            paths,
            signer=signer,
            expected_disposal_owner="acceptance-owner",
            expected_approver_identity="approval-owner",
            journal=journal,
            intent=intent,
            replay_authority=authority,
            replay_policy=_TEST_REPLAY_POLICY,
            replay_policy_artifact=_replay_policy_artifact(intent, signer=signer),
            _clock=lambda: _NOW,
        )
    monkeypatch.setattr(journal, "_set_marker_current", original)
    assert journal.migration_status() is InitialProvisioningJournalStatus.PROVISIONING_INCOMPLETE

    wrong_intent = _resign_initial_intent(
        intent,
        signer=signer,
        updates={"journal_uuid": "123e4567-e89b-42d3-a456-426614174098"},
    )
    with pytest.raises(AuthorizationError, match="initial_journal_reconciliation"):
        reconcile_initial_journal_genesis(
            journal,
            _initial_genesis_reconciliation(
                wrong_intent, signer=signer, outcome="provisioning_completed"
            ),
            signer=signer,
        )
    assert (
        reconcile_initial_journal_genesis(
            journal,
            _initial_genesis_reconciliation(
                intent, signer=signer, outcome="provisioning_completed"
            ),
            signer=signer,
        )
        is InitialProvisioningJournalStatus.CURRENT
    )
    with pytest.raises(AuthorizationError, match="initial_journal_replayed"):
        _provision_initial_journal_for_test(
            paths,
            signer=signer,
            expected_disposal_owner="acceptance-owner",
            expected_approver_identity="approval-owner",
            journal=journal,
            intent=intent,
            replay_authority=authority,
            replay_policy=_TEST_REPLAY_POLICY,
            replay_policy_artifact=_replay_policy_artifact(intent, signer=signer),
            _clock=lambda: _NOW,
        )


def test_external_initial_genesis_blocks_same_operation_at_a_new_path(tmp_path: Path) -> None:
    first_root = tmp_path / "first-artifacts"
    signer, _, _ = _authorize_materials(first_root)
    first_paths = AuthorizationPaths(first_root)
    authority = _AtomicReplayAuthority()
    first_journal = _initial_journal(tmp_path, first_paths)
    first_intent = _initial_intent(first_paths, signer=signer, journal=first_journal)
    _provision_initial_journal_for_test(
        first_paths,
        signer=signer,
        expected_disposal_owner="acceptance-owner",
        expected_approver_identity="approval-owner",
        journal=first_journal,
        intent=first_intent,
        replay_authority=authority,
        replay_policy=_TEST_REPLAY_POLICY,
        replay_policy_artifact=_replay_policy_artifact(first_intent, signer=signer),
        _clock=lambda: _NOW,
    )

    second_root = tmp_path / "second-artifacts"
    _authorize_materials(second_root)
    second_paths = AuthorizationPaths(second_root)
    second_journal = _initial_journal(tmp_path, second_paths)
    second_intent = _initial_intent(second_paths, signer=signer, journal=second_journal)
    with pytest.raises(AuthorizationError, match="initial_journal_replayed"):
        _provision_initial_journal_for_test(
            second_paths,
            signer=signer,
            expected_disposal_owner="acceptance-owner",
            expected_approver_identity="approval-owner",
            journal=second_journal,
            intent=second_intent,
            replay_authority=authority,
            replay_policy=_TEST_REPLAY_POLICY,
            replay_policy_artifact=_replay_policy_artifact(second_intent, signer=signer),
            _clock=lambda: _NOW,
        )
    assert (
        second_journal.migration_status()
        is InitialProvisioningJournalStatus.PROVISIONING_INCOMPLETE
    )


def test_public_execution_has_no_caller_controlled_clock(tmp_path: Path) -> None:
    root = tmp_path / "artifacts"
    signer, fingerprints, _ = _authorize_materials(root)
    journal = _journal(tmp_path)
    initial_journal = _initial_journal(tmp_path, AuthorizationPaths(root))

    assert "now" not in inspect.signature(authorize_and_execute).parameters
    assert "now" not in inspect.signature(authorize_initial_provisioning_and_execute).parameters
    assert "now" not in inspect.signature(provision_journal).parameters
    assert "now" not in inspect.signature(provision_initial_journal).parameters
    assert "clock" not in inspect.signature(authorize_and_execute).parameters
    assert "clock" not in inspect.signature(authorize_initial_provisioning_and_execute).parameters
    assert "now" not in inspect.signature(provision_keychain_ed25519_signer).parameters
    assert "clock" not in inspect.signature(provision_keychain_ed25519_signer).parameters
    assert "now" not in inspect.signature(provision_keychain_materials).parameters
    assert "clock" not in inspect.signature(provision_keychain_materials).parameters
    assert "now" not in inspect.signature(persist_provider_material_policy).parameters
    assert "clock" not in inspect.signature(persist_provider_material_policy).parameters
    assert not hasattr(provider_crypto_module, "_SYSTEM_CLOCK_CAPABILITY")
    assert not hasattr(provider_crypto_module, "_TEST_CLOCK_CAPABILITY")
    assert "provider_fingerprints" not in inspect.signature(authorize_and_execute).parameters
    assert "provider_material_policy" not in inspect.signature(authorize_and_execute).parameters
    assert (
        "provider_fingerprint_attestation"
        not in inspect.signature(authorize_and_execute).parameters
    )
    assert "provider_material_genesis" not in inspect.signature(authorize_and_execute).parameters
    assert (
        "provider_fingerprints"
        not in inspect.signature(authorize_initial_provisioning_and_execute).parameters
    )
    assert "_clock" not in inspect.signature(provision_journal).parameters
    assert (
        inspect.signature(authorize_and_execute).parameters["replay_authority"].default
        is inspect.Parameter.empty
    )
    assert (
        inspect.signature(provision_journal).parameters["replay_authority"].default
        is inspect.Parameter.empty
    )
    assert (
        inspect.signature(authorize_and_execute).parameters["replay_policy"].default
        is inspect.Parameter.empty
    )
    with pytest.raises(TypeError, match="unexpected keyword argument 'now'"):
        authorize_and_execute(
            AuthorizationPaths(root),
            signer=signer,
            provider=_Provider(fingerprints),
            expected_disposal_owner="acceptance-owner",
            expected_approver_identity="approval-owner",
            journal=journal,
            initial_journal=initial_journal,
            effect=_effect,
            replay_authority=_test_replay_authority(journal),
            replay_policy=_TEST_REPLAY_POLICY,
            now=_NOW,  # type: ignore[call-arg]
        )
    assert not hasattr(authorization_module, "_authorize_and_execute_with_clock")
    assert not hasattr(authorization_module, "_TEST_CLOCK_CAPABILITY")


def test_public_authorization_cannot_rewind_stale_stage_time(tmp_path: Path) -> None:
    """A historical fixture cannot reach an effect through a production API."""

    root = tmp_path / "stale-authorization-artifacts"
    signer, fingerprints, _ = _authorize_materials(root)
    paths = AuthorizationPaths(root)
    journal = _journal(tmp_path)
    initial_journal = _initial_journal(tmp_path, paths)
    authority = _test_replay_authority(journal)
    provider = _Provider(fingerprints)
    _ensure_test_journal_provisioned(
        paths,
        signer=signer,
        expected_disposal_owner="acceptance-owner",
        expected_approver_identity="approval-owner",
        journal=journal,
        replay_authority=authority,
    )
    _ensure_test_initial_stage(
        paths,
        signer=signer,
        provider=provider,
        provider_fingerprints=fingerprints,
        expected_disposal_owner="acceptance-owner",
        expected_approver_identity="approval-owner",
        journal=initial_journal,
        replay_authority=authority,
    )
    called = False

    def effect(context: VerifiedExecutionContext) -> EffectReceiptV1:
        nonlocal called
        called = True
        return _effect(context)

    with pytest.raises(AuthorizationError, match=r"phase_a_approval|initial_stage_freshness"):
        authorize_and_execute(
            paths,
            signer=signer,
            provider=provider,
            expected_disposal_owner="acceptance-owner",
            expected_approver_identity="approval-owner",
            journal=journal,
            initial_journal=initial_journal,
            effect=effect,
            replay_authority=authority,
            replay_policy=_TEST_REPLAY_POLICY,
        )
    assert not called


def test_phase_b_absent_journal_never_initializes_or_provisions(tmp_path: Path) -> None:
    root = tmp_path / "artifacts"
    signer, fingerprints, _ = _authorize_materials(root)
    journal = _journal(tmp_path)
    called = False

    def effect(context: VerifiedExecutionContext) -> EffectReceiptV1:
        nonlocal called
        called = True
        return _effect(context)

    with pytest.raises(AuthorizationError, match="journal_absent"):
        _execute_for_test(
            AuthorizationPaths(root),
            signer=signer,
            provider=_Provider(fingerprints),
            provider_fingerprints=fingerprints,
            expected_disposal_owner="acceptance-owner",
            expected_approver_identity="approval-owner",
            journal=journal,
            effect=effect,
            now=_NOW,
            provision=False,
        )

    assert not called
    assert journal.migration_status() is JournalMigrationStatus.ABSENT
    assert not journal._path.exists()
    assert not journal._anchor_path().exists()
    assert not journal._genesis_marker_path().exists()
    assert not (root / AuthorizationPaths.journal_genesis_name()).exists()


def test_missing_replay_authority_fails_before_journal_provisioning(tmp_path: Path) -> None:
    root = tmp_path / "artifacts"
    signer, _, _ = _authorize_materials(root)
    paths = AuthorizationPaths(root)
    journal = _journal(tmp_path)
    receipt = _journal_genesis_receipt(
        paths,
        signer=signer,
        journal=journal,
        expected_disposal_owner="acceptance-owner",
        expected_approver_identity="approval-owner",
    )
    with pytest.raises(AuthorizationError, match="replay_authority_failure"):
        _provision_journal_for_test(
            paths,
            signer=signer,
            expected_disposal_owner="acceptance-owner",
            expected_approver_identity="approval-owner",
            journal=journal,
            receipt=receipt,
            replay_authority=None,  # type: ignore[arg-type]
            replay_policy=_TEST_REPLAY_POLICY,
            _clock=lambda: _NOW,
        )
    assert journal.migration_status() is JournalMigrationStatus.ABSENT
    assert not (root / AuthorizationPaths.journal_genesis_name()).exists()


def test_initial_replay_policy_is_durable_before_tombstone_and_allows_exact_recovery(
    tmp_path: Path,
) -> None:
    root = tmp_path / "artifacts"
    signer, _fingerprints, _ = _authorize_materials(root)
    paths = AuthorizationPaths(root)
    journal = _initial_journal(tmp_path, paths)
    intent = _initial_intent(paths, signer=signer, journal=journal)
    policy_artifact = _replay_policy_artifact(intent, signer=signer)
    expected = yaml.safe_dump(policy_artifact.model_dump(mode="json"), sort_keys=True).encode()
    policy_path = root / paths.replay_policy_name()
    observed: list[tuple[bool, InitialProvisioningJournalStatus]] = []

    class _PolicyVisibleAuthority(_AtomicReplayAuthority):
        def claim_once(self, tombstone: ReplayTombstoneV1) -> ReplayAuthorityClaimResult:
            observed.append((policy_path.read_bytes() == expected, journal.migration_status()))
            return super().claim_once(tombstone)

    _provision_initial_journal_for_test(
        paths,
        signer=signer,
        expected_disposal_owner="acceptance-owner",
        expected_approver_identity="approval-owner",
        journal=journal,
        intent=intent,
        replay_authority=_PolicyVisibleAuthority(),
        replay_policy=_TEST_REPLAY_POLICY,
        replay_policy_artifact=policy_artifact,
        _clock=lambda: _NOW,
    )
    assert observed == [(True, InitialProvisioningJournalStatus.PROVISIONING_INCOMPLETE)]

    recovery_root = tmp_path / "recovery-artifacts"
    recovery_signer, _recovery_fingerprints, _ = _authorize_materials(recovery_root)
    recovery_paths = AuthorizationPaths(recovery_root)
    recovery_journal = _initial_journal(tmp_path, recovery_paths)
    recovery_intent = _initial_intent(
        recovery_paths,
        signer=recovery_signer,
        journal=recovery_journal,
    )
    recovery_artifact = _replay_policy_artifact(recovery_intent, signer=recovery_signer)
    _write(recovery_root, recovery_paths.replay_policy_name(), recovery_artifact)
    _provision_initial_journal_for_test(
        recovery_paths,
        signer=recovery_signer,
        expected_disposal_owner="acceptance-owner",
        expected_approver_identity="approval-owner",
        journal=recovery_journal,
        intent=recovery_intent,
        replay_authority=_AtomicReplayAuthority(),
        replay_policy=_TEST_REPLAY_POLICY,
        replay_policy_artifact=recovery_artifact,
        _clock=lambda: _NOW,
    )
    assert recovery_journal.migration_status() is InitialProvisioningJournalStatus.CURRENT


def test_initial_replay_policy_substitution_blocks_before_external_claim(tmp_path: Path) -> None:
    root = tmp_path / "artifacts"
    signer, _fingerprints, _ = _authorize_materials(root)
    paths = AuthorizationPaths(root)
    journal = _initial_journal(tmp_path, paths)
    intent = _initial_intent(paths, signer=signer, journal=journal)
    policy_artifact = _replay_policy_artifact(intent, signer=signer)
    replacement = policy_artifact.model_copy(
        update={"signature_base64": base64.b64encode(b"r" * 64).decode()}
    )
    _write(root, paths.replay_policy_name(), replacement)
    authority = _AtomicReplayAuthority()

    with pytest.raises(AuthorizationError, match="replay_policy_artifact"):
        _provision_initial_journal_for_test(
            paths,
            signer=signer,
            expected_disposal_owner="acceptance-owner",
            expected_approver_identity="approval-owner",
            journal=journal,
            intent=intent,
            replay_authority=authority,
            replay_policy=_TEST_REPLAY_POLICY,
            replay_policy_artifact=policy_artifact,
            _clock=lambda: _NOW,
        )
    assert not authority.tombstones
    assert journal.migration_status() is InitialProvisioningJournalStatus.ABSENT


def test_external_tombstone_blocks_local_rollback_and_deleted_operation_row(
    tmp_path: Path,
) -> None:
    root = tmp_path / "artifacts"
    signer, fingerprints, _ = _authorize_materials(root)
    paths = AuthorizationPaths(root)
    journal = _journal(tmp_path)
    authority = _test_replay_authority(journal)
    genesis = _journal_genesis_receipt(
        paths,
        signer=signer,
        journal=journal,
        expected_disposal_owner="acceptance-owner",
        expected_approver_identity="approval-owner",
    )
    _provision_journal_for_test(
        paths,
        signer=signer,
        expected_disposal_owner="acceptance-owner",
        expected_approver_identity="approval-owner",
        journal=journal,
        receipt=genesis,
        replay_authority=authority,
        replay_policy=_TEST_REPLAY_POLICY,
        _clock=lambda: _NOW,
    )
    effects: list[VerifiedExecutionContext] = []

    def effect(context: VerifiedExecutionContext) -> EffectReceiptV1:
        effects.append(context)
        return _effect(context)

    _execute_for_test(
        paths,
        signer=signer,
        provider=_Provider(fingerprints),
        provider_fingerprints=fingerprints,
        expected_disposal_owner="acceptance-owner",
        expected_approver_identity="approval-owner",
        journal=journal,
        effect=effect,
        provision=False,
        replay_authority=authority,
    )
    assert len(effects) == 1
    genesis_claim = next(
        tombstone for tombstone in authority.tombstones if tombstone.kind == "observed_genesis"
    )
    operation_claim = next(
        tombstone for tombstone in authority.tombstones if tombstone.kind == "observed_operation"
    )
    assert genesis_claim.kind == "observed_genesis"
    assert genesis_claim.journal_genesis_id == genesis.journal_uuid
    assert operation_claim.kind == "observed_operation"
    assert operation_claim.journal_genesis_id == genesis.journal_uuid
    assert operation_claim.operation_id == effects[0].operation_id
    assert operation_claim.proposal_sha256 == effects[0].proposal_sha256
    assert operation_claim.contract_sha256 == effects[0].contract_sha256
    assert operation_claim.provider_provenance_sha256 == effects[0].provider_provenance_sha256
    assert operation_claim.idempotency_key == effects[0].idempotency_key
    assert all(
        len(value) == 64 and value.decode("ascii").isalnum() for value in authority._claims.values()
    )

    connection = sqlite3.connect(journal._path)
    try:
        connection.execute("DELETE FROM authorization_operation_journal")
        connection.commit()
    finally:
        connection.close()
    with pytest.raises(AuthorizationError, match="replay_authority_replayed"):
        _execute_for_test(
            paths,
            signer=signer,
            provider=_Provider(fingerprints),
            provider_fingerprints=fingerprints,
            expected_disposal_owner="acceptance-owner",
            expected_approver_identity="approval-owner",
            journal=journal,
            effect=effect,
            provision=False,
            replay_authority=authority,
        )
    assert len(effects) == 1

    journal._path.unlink()
    journal._anchor_path().unlink()
    journal._genesis_marker_path().unlink()
    (root / AuthorizationPaths.journal_genesis_name()).unlink()
    assert journal.migration_status() is JournalMigrationStatus.ABSENT
    replacement = _journal_genesis_receipt(
        paths,
        signer=signer,
        journal=journal,
        expected_disposal_owner="acceptance-owner",
        expected_approver_identity="approval-owner",
    )
    with pytest.raises(AuthorizationError, match="journal_genesis_replayed"):
        _provision_journal_for_test(
            paths,
            signer=signer,
            expected_disposal_owner="acceptance-owner",
            expected_approver_identity="approval-owner",
            journal=journal,
            receipt=replacement,
            replay_authority=authority,
            replay_policy=_TEST_REPLAY_POLICY,
            _clock=lambda: _NOW,
        )
    assert journal.migration_status() is JournalMigrationStatus.PROVISIONING_INCOMPLETE
    assert not journal._path.exists()
    assert not journal._anchor_path().exists()
    assert len(effects) == 1


def test_test_replay_authority_claim_is_atomic_across_processes(tmp_path: Path) -> None:
    root = tmp_path / "replay-authority"
    root.mkdir(mode=0o700)
    root.chmod(0o700)
    context = multiprocessing.get_context("spawn")
    queue = context.Queue()
    workers = [
        context.Process(target=_process_replay_authority_worker, args=(str(root), queue))
        for _ in range(2)
    ]
    for worker in workers:
        worker.start()
    outcomes = [queue.get(timeout=10) for _ in workers]
    for worker in workers:
        worker.join(timeout=10)
        assert worker.exitcode == 0
    assert sorted(outcomes) == [
        ReplayAuthorityClaimResult.CREATED.value,
        ReplayAuthorityClaimResult.DUPLICATE_SAME.value,
    ]


def test_genesis_blocks_pair_removal_replay_and_identity_file_removal(tmp_path: Path) -> None:
    root = tmp_path / "artifacts"
    signer, fingerprints, _ = _authorize_materials(root)
    journal = _journal(tmp_path)
    paths = AuthorizationPaths(root)
    genesis = _journal_genesis_receipt(
        paths,
        signer=signer,
        journal=journal,
        expected_disposal_owner="acceptance-owner",
        expected_approver_identity="approval-owner",
    )
    _provision_journal_for_test(
        paths,
        signer=signer,
        expected_disposal_owner="acceptance-owner",
        expected_approver_identity="approval-owner",
        journal=journal,
        receipt=genesis,
        replay_authority=_test_replay_authority(journal),
        replay_policy=_TEST_REPLAY_POLICY,
        _clock=lambda: _NOW,
    )
    effects: list[str] = []

    def effect(context: VerifiedExecutionContext) -> EffectReceiptV1:
        effects.append(context.operation_id)
        return _effect(context)

    _execute_for_test(
        paths,
        signer=signer,
        provider=_Provider(fingerprints),
        provider_fingerprints=fingerprints,
        expected_disposal_owner="acceptance-owner",
        expected_approver_identity="approval-owner",
        journal=journal,
        effect=effect,
        provision=False,
    )
    assert effects == [_proposal().operation_id]

    journal._path.unlink()
    journal._anchor_path().unlink()
    assert journal.migration_status() is JournalMigrationStatus.JOURNAL_MISSING
    with pytest.raises(AuthorizationError, match="journal_missing"):
        _execute_for_test(
            paths,
            signer=signer,
            provider=_Provider(fingerprints),
            provider_fingerprints=fingerprints,
            expected_disposal_owner="acceptance-owner",
            expected_approver_identity="approval-owner",
            journal=journal,
            effect=effect,
            provision=False,
        )
    assert effects == [_proposal().operation_id]
    assert not journal._path.exists()
    assert not journal._anchor_path().exists()

    journal._genesis_marker_path().unlink()
    assert journal.migration_status() is JournalMigrationStatus.ABSENT
    with pytest.raises(AuthorizationError, match="journal_absent"):
        _execute_for_test(
            paths,
            signer=signer,
            provider=_Provider(fingerprints),
            provider_fingerprints=fingerprints,
            expected_disposal_owner="acceptance-owner",
            expected_approver_identity="approval-owner",
            journal=journal,
            effect=effect,
            provision=False,
        )
    assert effects == [_proposal().operation_id]
    assert not journal._path.exists()
    assert not journal._anchor_path().exists()
    assert (root / AuthorizationPaths.journal_genesis_name()).exists()
    with pytest.raises(AuthorizationError, match="journal_genesis_replayed"):
        _provision_journal_for_test(
            paths,
            signer=signer,
            expected_disposal_owner="acceptance-owner",
            expected_approver_identity="approval-owner",
            journal=journal,
            receipt=genesis,
            replay_authority=_test_replay_authority(journal),
            replay_policy=_TEST_REPLAY_POLICY,
            _clock=lambda: _NOW,
        )


def test_genesis_copy_or_removal_blocks_effect_before_claim(tmp_path: Path) -> None:
    source = tmp_path / "source"
    signer, fingerprints, _ = _authorize_materials(source)
    target = tmp_path / "target"
    shutil.copytree(source, target)
    source_journal = _journal(tmp_path / "source-journal")
    target_journal = _journal(tmp_path / "target-journal")
    source_paths = AuthorizationPaths(source)
    target_paths = AuthorizationPaths(target)
    for paths, journal in ((source_paths, source_journal), (target_paths, target_journal)):
        _provision_journal_for_test(
            paths,
            signer=signer,
            expected_disposal_owner="acceptance-owner",
            expected_approver_identity="approval-owner",
            journal=journal,
            receipt=_journal_genesis_receipt(
                paths,
                signer=signer,
                journal=journal,
                expected_disposal_owner="acceptance-owner",
                expected_approver_identity="approval-owner",
            ),
            replay_authority=_test_replay_authority(journal),
            replay_policy=_TEST_REPLAY_POLICY,
            _clock=lambda: _NOW,
        )
    target_genesis = target / AuthorizationPaths.journal_genesis_name()
    target_genesis.unlink()
    shutil.copy2(source / AuthorizationPaths.journal_genesis_name(), target_genesis)
    target_genesis.chmod(0o600)
    called = False

    def effect(context: VerifiedExecutionContext) -> EffectReceiptV1:
        nonlocal called
        called = True
        return _effect(context)

    with pytest.raises(AuthorizationError, match="journal_genesis_binding"):
        _execute_for_test(
            target_paths,
            signer=signer,
            provider=_Provider(fingerprints),
            provider_fingerprints=fingerprints,
            expected_disposal_owner="acceptance-owner",
            expected_approver_identity="approval-owner",
            journal=target_journal,
            effect=effect,
            provision=False,
        )
    assert not called

    source_genesis = source / AuthorizationPaths.journal_genesis_name()
    source_genesis.unlink()
    with pytest.raises(AuthorizationError, match="journal_genesis_artifact"):
        _execute_for_test(
            source_paths,
            signer=signer,
            provider=_Provider(fingerprints),
            provider_fingerprints=fingerprints,
            expected_disposal_owner="acceptance-owner",
            expected_approver_identity="approval-owner",
            journal=source_journal,
            effect=effect,
            provision=False,
        )
    assert not called


def test_genesis_rejects_second_provision_and_signed_mismatch(tmp_path: Path) -> None:
    root = tmp_path / "artifacts"
    signer, _, _ = _authorize_materials(root)
    paths = AuthorizationPaths(root)
    journal = _journal(tmp_path)
    receipt = _journal_genesis_receipt(
        paths,
        signer=signer,
        journal=journal,
        expected_disposal_owner="acceptance-owner",
        expected_approver_identity="approval-owner",
    )
    _provision_journal_for_test(
        paths,
        signer=signer,
        expected_disposal_owner="acceptance-owner",
        expected_approver_identity="approval-owner",
        journal=journal,
        receipt=receipt,
        replay_authority=_test_replay_authority(journal),
        replay_policy=_TEST_REPLAY_POLICY,
        _clock=lambda: _NOW,
    )
    with pytest.raises(AuthorizationError, match="journal_genesis_replayed"):
        _provision_journal_for_test(
            paths,
            signer=signer,
            expected_disposal_owner="acceptance-owner",
            expected_approver_identity="approval-owner",
            journal=journal,
            receipt=receipt,
            replay_authority=_test_replay_authority(journal),
            replay_policy=_TEST_REPLAY_POLICY,
            _clock=lambda: _NOW,
        )

    mismatch_root = tmp_path / "mismatch-artifacts"
    mismatch_signer, _, _ = _authorize_materials(mismatch_root)
    mismatch_paths = AuthorizationPaths(mismatch_root)
    mismatch_journal = _journal(tmp_path / "mismatch-journal")
    valid = _journal_genesis_receipt(
        mismatch_paths,
        signer=mismatch_signer,
        journal=mismatch_journal,
        expected_disposal_owner="acceptance-owner",
        expected_approver_identity="approval-owner",
    )
    invalid_signature = valid.model_copy(
        update={"signature_base64": base64.b64encode(b"1" * 64).decode()}
    )
    with pytest.raises(AuthorizationError, match="journal_genesis_signature"):
        _provision_journal_for_test(
            mismatch_paths,
            signer=mismatch_signer,
            expected_disposal_owner="acceptance-owner",
            expected_approver_identity="approval-owner",
            journal=mismatch_journal,
            receipt=invalid_signature,
            replay_authority=_test_replay_authority(mismatch_journal),
            replay_policy=_TEST_REPLAY_POLICY,
            _clock=lambda: _NOW,
        )
    assert mismatch_journal.migration_status() is JournalMigrationStatus.ABSENT
    assert not (mismatch_root / AuthorizationPaths.journal_genesis_name()).exists()

    wrong_owner = _journal_genesis_receipt(
        mismatch_paths,
        signer=mismatch_signer,
        journal=mismatch_journal,
        expected_disposal_owner="wrong-owner",
        expected_approver_identity="approval-owner",
    )
    with pytest.raises(AuthorizationError, match="journal_genesis_binding"):
        _provision_journal_for_test(
            mismatch_paths,
            signer=mismatch_signer,
            expected_disposal_owner="acceptance-owner",
            expected_approver_identity="approval-owner",
            journal=mismatch_journal,
            receipt=wrong_owner,
            replay_authority=_test_replay_authority(mismatch_journal),
            replay_policy=_TEST_REPLAY_POLICY,
            _clock=lambda: _NOW,
        )
    assert mismatch_journal.migration_status() is JournalMigrationStatus.ABSENT


def test_genesis_crash_windows_require_signed_reconciliation(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    root = tmp_path / "artifacts"
    signer, _, _ = _authorize_materials(root)
    paths = AuthorizationPaths(root)
    journal = _journal(tmp_path)
    receipt = _journal_genesis_receipt(
        paths,
        signer=signer,
        journal=journal,
        expected_disposal_owner="acceptance-owner",
        expected_approver_identity="approval-owner",
    )
    original_write_once = ArtifactRootLease.write_once

    def crash_before_artifact(
        lease: ArtifactRootLease, name: str, payload: bytes, *, phase: str
    ) -> None:
        del lease, name, payload, phase
        raise AuthorizationError("simulated_crash")

    monkeypatch.setattr(ArtifactRootLease, "write_once", crash_before_artifact)
    with pytest.raises(AuthorizationError, match="simulated_crash"):
        _provision_journal_for_test(
            paths,
            signer=signer,
            expected_disposal_owner="acceptance-owner",
            expected_approver_identity="approval-owner",
            journal=journal,
            receipt=receipt,
            replay_authority=_test_replay_authority(journal),
            replay_policy=_TEST_REPLAY_POLICY,
            _clock=lambda: _NOW,
        )
    monkeypatch.setattr(ArtifactRootLease, "write_once", original_write_once)
    assert journal.migration_status() is JournalMigrationStatus.PROVISIONING_INCOMPLETE
    assert not journal._path.exists()
    with pytest.raises(AuthorizationError, match="provisioning_incomplete"):
        _provision_journal_for_test(
            paths,
            signer=signer,
            expected_disposal_owner="acceptance-owner",
            expected_approver_identity="approval-owner",
            journal=journal,
            receipt=receipt,
            replay_authority=_test_replay_authority(journal),
            replay_policy=_TEST_REPLAY_POLICY,
            _clock=lambda: _NOW,
        )
    assert (
        reconcile_journal_genesis(
            journal,
            _genesis_reconciliation_receipt(
                receipt, signer=signer, outcome="provisioning_abandoned"
            ),
            signer=signer,
        )
        is JournalMigrationStatus.PROVISIONING_INCOMPLETE
    )

    completed_root = tmp_path / "completed-artifacts"
    completed_signer, completed_fingerprints, _ = _authorize_materials(completed_root)
    completed_paths = AuthorizationPaths(completed_root)
    completed_journal = _journal(tmp_path / "completed-journal")
    completed_receipt = _journal_genesis_receipt(
        completed_paths,
        signer=completed_signer,
        journal=completed_journal,
        expected_disposal_owner="acceptance-owner",
        expected_approver_identity="approval-owner",
    )
    original_set_state = completed_journal._set_genesis_marker_state

    def crash_after_database(marker: object, state: object) -> object:
        del marker, state
        raise AuthorizationError("simulated_crash")

    monkeypatch.setattr(completed_journal, "_set_genesis_marker_state", crash_after_database)
    with pytest.raises(AuthorizationError, match="simulated_crash"):
        _provision_journal_for_test(
            completed_paths,
            signer=completed_signer,
            expected_disposal_owner="acceptance-owner",
            expected_approver_identity="approval-owner",
            journal=completed_journal,
            receipt=completed_receipt,
            replay_authority=_test_replay_authority(completed_journal),
            replay_policy=_TEST_REPLAY_POLICY,
            _clock=lambda: _NOW,
        )
    monkeypatch.setattr(completed_journal, "_set_genesis_marker_state", original_set_state)
    assert completed_journal.migration_status() is JournalMigrationStatus.PROVISIONING_INCOMPLETE
    assert completed_journal._path.exists()
    assert completed_journal._anchor_path().exists()
    with pytest.raises(AuthorizationError, match="provisioning_incomplete"):
        _provision_journal_for_test(
            completed_paths,
            signer=completed_signer,
            expected_disposal_owner="acceptance-owner",
            expected_approver_identity="approval-owner",
            journal=completed_journal,
            receipt=completed_receipt,
            replay_authority=_test_replay_authority(completed_journal),
            replay_policy=_TEST_REPLAY_POLICY,
            _clock=lambda: _NOW,
        )
    assert (
        reconcile_journal_genesis(
            completed_journal,
            _genesis_reconciliation_receipt(
                completed_receipt, signer=completed_signer, outcome="provisioning_completed"
            ),
            signer=completed_signer,
        )
        is JournalMigrationStatus.CURRENT
    )
    receipt_after_recovery = _execute_for_test(
        completed_paths,
        signer=completed_signer,
        provider=_Provider(completed_fingerprints),
        provider_fingerprints=completed_fingerprints,
        expected_disposal_owner="acceptance-owner",
        expected_approver_identity="approval-owner",
        journal=completed_journal,
        effect=_effect,
        provision=False,
    )
    assert receipt_after_recovery.status == "committed"


def test_phase_b_detects_legacy_journal_before_effect(tmp_path: Path) -> None:
    root = tmp_path / "artifacts"
    signer, fingerprints, _ = _authorize_materials(root)
    journal = _journal(tmp_path)
    connection = sqlite3.connect(journal._path)
    try:
        connection.execute(
            """
            CREATE TABLE authorization_nonce_journal (
                nonce TEXT PRIMARY KEY NOT NULL,
                operation_id TEXT NOT NULL,
                receipt_sha256 TEXT NOT NULL,
                claimed_at TEXT NOT NULL
            ) WITHOUT ROWID
            """
        )
        connection.execute(
            """
            INSERT INTO authorization_nonce_journal
                (nonce, operation_id, receipt_sha256, claimed_at)
            VALUES (?, ?, ?, ?)
            """,
            ("a" * 32, _proposal().operation_id, "b" * 64, "2026-08-27T12:00:00Z"),
        )
        connection.commit()
    finally:
        connection.close()
    journal._path.chmod(0o600)
    called = False

    def effect(context: VerifiedExecutionContext) -> EffectReceiptV1:
        nonlocal called
        called = True
        return _effect(context)

    assert journal.migration_status() is JournalMigrationStatus.LEGACY_DETECTED
    with pytest.raises(AuthorizationError, match="journal_legacy_detected"):
        _execute_for_test(
            AuthorizationPaths(root),
            signer=signer,
            provider=_Provider(fingerprints),
            provider_fingerprints=fingerprints,
            expected_disposal_owner="acceptance-owner",
            expected_approver_identity="approval-owner",
            journal=journal,
            effect=effect,
            now=_NOW,
        )
    assert not called
    assert journal.migration_status() is JournalMigrationStatus.LEGACY_DETECTED


def test_phase_b_blocks_replaced_journal_before_effect(tmp_path: Path) -> None:
    root = tmp_path / "artifacts"
    signer, fingerprints, _ = _authorize_materials(root)
    journal = _journal(tmp_path)
    _execute_for_test(
        AuthorizationPaths(root),
        signer=signer,
        provider=_Provider(fingerprints),
        provider_fingerprints=fingerprints,
        expected_disposal_owner="acceptance-owner",
        expected_approver_identity="approval-owner",
        journal=journal,
        effect=_effect,
        now=_NOW,
    )
    archived = journal._path.with_name("authorization-before-replacement.sqlite3")
    os.replace(journal._path, archived)
    connection = sqlite3.connect(journal._path)
    connection.close()
    journal._path.chmod(0o600)
    called = False

    def effect(context: VerifiedExecutionContext) -> EffectReceiptV1:
        nonlocal called
        called = True
        return _effect(context)

    with pytest.raises(AuthorizationError, match="journal_identity_mismatch"):
        _execute_for_test(
            AuthorizationPaths(root),
            signer=signer,
            provider=_Provider(fingerprints),
            provider_fingerprints=fingerprints,
            expected_disposal_owner="acceptance-owner",
            expected_approver_identity="approval-owner",
            journal=journal,
            effect=effect,
            now=_NOW,
        )
    assert not called


def test_phase_b_pins_journal_anchor_before_provider_and_effect(tmp_path: Path) -> None:
    root = tmp_path / "artifacts"
    signer, fingerprints, _ = _authorize_materials(root)
    journal = _journal(tmp_path)
    _ensure_test_journal_provisioned(
        AuthorizationPaths(root),
        signer=signer,
        expected_disposal_owner="acceptance-owner",
        expected_approver_identity="approval-owner",
        journal=journal,
    )
    _ensure_test_initial_stage(
        AuthorizationPaths(root),
        signer=signer,
        provider=_Provider(fingerprints),
        provider_fingerprints=fingerprints,
        expected_disposal_owner="acceptance-owner",
        expected_approver_identity="approval-owner",
        journal=_initial_journal(tmp_path, AuthorizationPaths(root)),
        replay_authority=_test_replay_authority(journal),
    )

    class ReplacingProvider(_Provider):
        def inspect(self, reference: ProviderReferenceV1) -> ProviderProvenance | None:
            if not self._mutated:
                replacement = journal._anchor_path().with_name("replacement-anchor.json")
                shutil.copy2(journal._anchor_path(), replacement)
                replacement.chmod(0o600)
                os.replace(replacement, journal._anchor_path())
                self._mutated = True
            return super().inspect(reference)

    called = False

    def effect(context: VerifiedExecutionContext) -> EffectReceiptV1:
        nonlocal called
        called = True
        return _effect(context)

    with pytest.raises(AuthorizationError, match="journal_identity_pinned"):
        _execute_for_test(
            AuthorizationPaths(root),
            signer=signer,
            provider=ReplacingProvider(fingerprints),
            provider_fingerprints=fingerprints,
            expected_disposal_owner="acceptance-owner",
            expected_approver_identity="approval-owner",
            journal=journal,
            effect=effect,
            provision=False,
        )
    assert not called


def test_same_operation_with_fresh_nonce_executes_effect_once(tmp_path: Path) -> None:
    root = tmp_path / "artifacts"
    signer, fingerprints, _ = _authorize_materials(root)
    journal = _journal(tmp_path)
    effects: list[str] = []

    def effect(context: VerifiedExecutionContext) -> EffectReceiptV1:
        effects.append(context.idempotency_key)
        return _effect(context)

    def execute() -> str:
        try:
            _execute_for_test(
                AuthorizationPaths(root),
                signer=signer,
                provider=_Provider(fingerprints),
                provider_fingerprints=fingerprints,
                expected_disposal_owner="acceptance-owner",
                expected_approver_identity="approval-owner",
                journal=journal,
                effect=effect,
                now=_NOW,
            )
        except AuthorizationError as error:
            return error.phase
        return "committed"

    with ThreadPoolExecutor(max_workers=2) as executor:
        outcomes = list(executor.map(lambda _: execute(), range(2)))

    assert sorted(outcomes) == ["artifact_lock_busy", "committed"]
    assert len(effects) == 1
    assert execute() == "replay_authority_replayed"


def test_effect_failure_requires_recovery_and_never_replays(tmp_path: Path) -> None:
    root = tmp_path / "artifacts"
    signer, fingerprints, _ = _authorize_materials(root)
    journal = _journal(tmp_path)

    def fail_effect(context: VerifiedExecutionContext) -> EffectReceiptV1:
        del context
        raise RuntimeError("effect failure")

    with pytest.raises(AuthorizationError, match="effect_failed_recovery_required"):
        _execute_for_test(
            AuthorizationPaths(root),
            signer=signer,
            provider=_Provider(fingerprints),
            provider_fingerprints=fingerprints,
            expected_disposal_owner="acceptance-owner",
            expected_approver_identity="approval-owner",
            journal=journal,
            effect=fail_effect,
            now=_NOW,
        )
    assert journal.operation_state(_proposal().operation_id).value == "failed_recovery_required"
    with pytest.raises(AuthorizationError, match="replay_authority_replayed"):
        _execute_for_test(
            AuthorizationPaths(root),
            signer=signer,
            provider=_Provider(fingerprints),
            provider_fingerprints=fingerprints,
            expected_disposal_owner="acceptance-owner",
            expected_approver_identity="approval-owner",
            journal=journal,
            effect=_effect,
            now=_NOW,
        )


def _assert_value_safe_error(error: AuthorizationError, secret: str) -> None:
    assert secret not in str(error)
    assert secret not in repr(error)
    assert all(secret not in str(argument) for argument in error.args)
    assert error.__cause__ is None
    assert error.__context__ is None
    assert secret not in "".join(traceback.format_exception(error))


def test_keychain_replay_authority_is_create_only_and_stores_hashes() -> None:
    policy = ReplayAuthorityPolicyV1(
        schema_version="rsd.replay-authority-policy.v1",
        service="omninode-rsd-keychain-test",
        account_prefix="rsd-keychain-tombstone",
    )

    class Store:
        def __init__(self) -> None:
            self.records: dict[tuple[str, str], bytes] = {}
            self.calls: list[tuple[str, str, bytes]] = []

        def add_if_absent(self, service: str, account: str, value: bytes) -> bytes | None:
            self.calls.append((service, account, value))
            existing = self.records.get((service, account))
            if existing is not None:
                return existing
            self.records[(service, account)] = value
            return None

    tombstone = ReplayTombstoneV1(
        schema_version="rsd.replay-tombstone.v1",
        kind="observed_operation",
        operation_kind="observed_lifecycle_v1",
        service=policy.service,
        account=f"{policy.account_prefix}.o.hash-only",
        journal_genesis_id="00000000-0000-4000-8000-000000000001",
        operation_id="hash-only-operation",
        proposal_sha256="a" * 64,
        contract_sha256="b" * 64,
        provider_provenance_sha256="c" * 64,
        idempotency_key="d" * 64,
    )
    store = Store()
    authority = MacOSKeychainReplayAuthority(policy, _store=store)
    assert authority.claim_once(tombstone) is ReplayAuthorityClaimResult.CREATED
    assert authority.claim_once(tombstone) is ReplayAuthorityClaimResult.DUPLICATE_SAME
    assert len(store.calls) == 2
    assert all(
        service == policy.service
        and account == tombstone.account
        and value == tombstone.binding_sha256().encode("ascii")
        and len(value) == 64
        for service, account, value in store.calls
    )
    store.records[(policy.service, tombstone.account)] = b"x" * 64
    assert authority.claim_once(tombstone) is ReplayAuthorityClaimResult.DUPLICATE_CONFLICT


def test_replay_authority_failure_is_value_redacted_and_prevents_effect(tmp_path: Path) -> None:
    secret = "external-authority-value-must-not-escape"
    root = tmp_path / "artifacts"
    signer, fingerprints, _ = _authorize_materials(root)
    journal = _journal(tmp_path)
    _ensure_test_journal_provisioned(
        AuthorizationPaths(root),
        signer=signer,
        expected_disposal_owner="acceptance-owner",
        expected_approver_identity="approval-owner",
        journal=journal,
    )

    class FailingAuthority:
        def claim_once(self, tombstone: ReplayTombstoneV1) -> ReplayAuthorityClaimResult:
            del tombstone
            raise RuntimeError(secret) from ValueError(secret)

    called = False

    def effect(context: VerifiedExecutionContext) -> EffectReceiptV1:
        nonlocal called
        called = True
        return _effect(context)

    with pytest.raises(AuthorizationError) as failure:
        _execute_for_test(
            AuthorizationPaths(root),
            signer=signer,
            provider=_Provider(fingerprints),
            provider_fingerprints=fingerprints,
            expected_disposal_owner="acceptance-owner",
            expected_approver_identity="approval-owner",
            journal=journal,
            effect=effect,
            provision=False,
            replay_authority=FailingAuthority(),
        )
    assert failure.value.phase == "replay_authority_failure"
    _assert_value_safe_error(failure.value, secret)
    assert not called


def test_provider_and_effect_failures_do_not_expose_adapter_values(tmp_path: Path) -> None:
    secret = "provider-effect-value-must-not-escape"
    provider_root = tmp_path / "provider-artifacts"
    signer, fingerprints, _ = _authorize_materials(provider_root)

    class FailingProvider(_Provider):
        def inspect(self, reference: ProviderReferenceV1) -> ProviderProvenance | None:
            raise RuntimeError(secret) from ValueError(secret)

    with pytest.raises(AuthorizationError) as provider_failure:
        _execute_for_test(
            AuthorizationPaths(provider_root),
            signer=signer,
            provider=FailingProvider(fingerprints),
            provider_fingerprints=fingerprints,
            expected_disposal_owner="acceptance-owner",
            expected_approver_identity="approval-owner",
            journal=_journal(tmp_path),
            effect=_effect,
            now=_NOW,
        )
    assert provider_failure.value.phase == "provider_failure"
    _assert_value_safe_error(provider_failure.value, secret)

    release_root = tmp_path / "release-artifacts"
    signer, fingerprints, _ = _authorize_materials(release_root)
    release_journal_parent = tmp_path / "release-journal"
    release_journal_parent.mkdir(mode=0o700)
    release_journal_parent.chmod(0o700)
    release_journal = _journal(release_journal_parent)

    class ExitFailingProvider(_Provider):
        def __exit__(self, exception_type: object, exception: object, traceback: object) -> None:
            del exception_type, exception, traceback
            raise RuntimeError(secret) from ValueError(secret)

    with pytest.raises(AuthorizationError) as release_failure:
        _execute_for_test(
            AuthorizationPaths(release_root),
            signer=signer,
            provider=ExitFailingProvider(fingerprints),
            provider_fingerprints=fingerprints,
            expected_disposal_owner="acceptance-owner",
            expected_approver_identity="approval-owner",
            journal=release_journal,
            effect=_effect,
            now=_NOW,
        )
    assert release_failure.value.phase == "provider_release"
    _assert_value_safe_error(release_failure.value, secret)

    effect_root = tmp_path / "effect-artifacts"
    signer, fingerprints, _ = _authorize_materials(effect_root)
    effect_journal_parent = tmp_path / "effect-journal"
    effect_journal_parent.mkdir(mode=0o700)
    effect_journal_parent.chmod(0o700)
    journal = _journal(effect_journal_parent)

    def failing_effect(context: VerifiedExecutionContext) -> EffectReceiptV1:
        del context
        raise RuntimeError(secret) from ValueError(secret)

    with pytest.raises(AuthorizationError) as effect_failure:
        _execute_for_test(
            AuthorizationPaths(effect_root),
            signer=signer,
            provider=_Provider(fingerprints),
            provider_fingerprints=fingerprints,
            expected_disposal_owner="acceptance-owner",
            expected_approver_identity="approval-owner",
            journal=journal,
            effect=failing_effect,
            now=_NOW,
        )
    assert effect_failure.value.phase == "effect_failed_recovery_required"
    _assert_value_safe_error(effect_failure.value, secret)
    connection = sqlite3.connect(journal._path)
    try:
        row = connection.execute(
            "SELECT failure_phase FROM authorization_operation_journal"
        ).fetchone()
    finally:
        connection.close()
    assert row == ("effect",)


def test_owner_lock_rejects_cooperating_artifact_writer_without_waiting(tmp_path: Path) -> None:
    root = tmp_path / "artifacts"
    signer, fingerprints, _ = _authorize_materials(root)
    entered_provider = Event()
    release_provider = Event()

    class BlockingProvider(_Provider):
        def inspect(self, reference: ProviderReferenceV1) -> ProviderProvenance | None:
            entered_provider.set()
            assert release_provider.wait(timeout=5)
            return super().inspect(reference)

    def execute() -> None:
        _execute_for_test(
            AuthorizationPaths(root),
            signer=signer,
            provider=BlockingProvider(fingerprints),
            provider_fingerprints=fingerprints,
            expected_disposal_owner="acceptance-owner",
            expected_approver_identity="approval-owner",
            journal=_journal(tmp_path),
            effect=_effect,
            now=_NOW,
        )

    def writer() -> str:
        try:
            with ArtifactRootLease(root):
                return "acquired"
        except AuthorizationError as error:
            return error.phase

    with ThreadPoolExecutor(max_workers=2) as executor:
        running = executor.submit(execute)
        assert entered_provider.wait(timeout=5)
        blocked_writer = executor.submit(writer)
        assert blocked_writer.result(timeout=5) == "artifact_lock_busy"
        release_provider.set()
        running.result(timeout=5)


def test_owner_lock_rejects_competing_process_without_waiting(tmp_path: Path) -> None:
    root = tmp_path / "artifacts"
    _materials(root)
    context = multiprocessing.get_context("spawn")
    queue = context.Queue()
    worker = context.Process(target=_artifact_lock_worker, args=(str(root), queue))

    with ArtifactRootLease(root):
        worker.start()
        assert queue.get(timeout=10) == "artifact_lock_busy"
        worker.join(timeout=10)

    assert worker.exitcode == 0


def test_owner_lock_rejects_recursive_effect_lease(tmp_path: Path) -> None:
    root = tmp_path / "artifacts"
    signer, fingerprints, _ = _authorize_materials(root)

    def effect(context: VerifiedExecutionContext) -> EffectReceiptV1:
        with (
            pytest.raises(AuthorizationError, match="artifact_lock_reentrant"),
            ArtifactRootLease(root),
        ):
            pass
        return _effect(context)

    receipt = _execute_for_test(
        AuthorizationPaths(root),
        signer=signer,
        provider=_Provider(fingerprints),
        provider_fingerprints=fingerprints,
        expected_disposal_owner="acceptance-owner",
        expected_approver_identity="approval-owner",
        journal=_journal(tmp_path),
        effect=effect,
        now=_NOW,
    )

    assert receipt.status == "committed"


def test_owner_lock_converges_case_variants_on_same_root(tmp_path: Path) -> None:
    root = tmp_path / "artifacts"
    _materials(root)
    variant = root.with_name(root.name.swapcase())
    if not variant.exists():
        pytest.skip("filesystem is case-sensitive")
    assert _root_lock_path(root) == _root_lock_path(variant)
    entered = Event()
    release = Event()

    def hold() -> None:
        with ArtifactRootLease(root):
            entered.set()
            assert release.wait(timeout=5)

    def acquire_variant() -> str:
        try:
            with ArtifactRootLease(variant):
                return "acquired"
        except AuthorizationError as error:
            return error.phase

    with ThreadPoolExecutor(max_workers=2) as executor:
        held = executor.submit(hold)
        assert entered.wait(timeout=5)
        contender = executor.submit(acquire_variant)
        assert contender.result(timeout=5) == "artifact_lock_busy"
        release.set()
        held.result(timeout=5)


@pytest.mark.parametrize("mutation", ("root_replace", "lock_unlink"))
def test_phase_b_rejects_root_or_lock_replacement_before_effect(
    tmp_path: Path, mutation: str
) -> None:
    root = tmp_path / "artifacts"
    signer, fingerprints, _ = _authorize_materials(root)
    entered_provider = Event()
    release_provider = Event()
    called = False

    class BlockingProvider(_Provider):
        def inspect(self, reference: ProviderReferenceV1) -> ProviderProvenance | None:
            entered_provider.set()
            assert release_provider.wait(timeout=5)
            return super().inspect(reference)

    def effect(context: VerifiedExecutionContext) -> EffectReceiptV1:
        nonlocal called
        called = True
        return _effect(context)

    def execute() -> str:
        try:
            _execute_for_test(
                AuthorizationPaths(root),
                signer=signer,
                provider=BlockingProvider(fingerprints),
                provider_fingerprints=fingerprints,
                expected_disposal_owner="acceptance-owner",
                expected_approver_identity="approval-owner",
                journal=_journal(tmp_path),
                effect=effect,
                now=_NOW,
            )
        except AuthorizationError as error:
            return error.phase
        return "committed"

    with ThreadPoolExecutor(max_workers=1) as executor:
        running = executor.submit(execute)
        assert entered_provider.wait(timeout=5)
        if mutation == "root_replace":
            root.rename(tmp_path / "moved-artifacts")
            root.mkdir(mode=0o700)
            root.chmod(0o700)
        else:
            _root_lock_path(root).unlink()
        release_provider.set()
        outcome = running.result(timeout=5)

    assert outcome in {"artifact_lock_root", "artifact_lock_file", "artifact_lock_state"}
    assert not called


def test_recovery_cannot_race_a_live_effect(tmp_path: Path) -> None:
    root = tmp_path / "artifacts"
    signer, fingerprints, _ = _authorize_materials(root)
    journal = _journal(tmp_path)
    entered_effect = Event()
    release_effect = Event()

    def effect(context: VerifiedExecutionContext) -> EffectReceiptV1:
        entered_effect.set()
        assert release_effect.wait(timeout=5)
        return _effect(context)

    def execute() -> ExecutionReceiptV1:
        return _execute_for_test(
            AuthorizationPaths(root),
            signer=signer,
            provider=_Provider(fingerprints),
            provider_fingerprints=fingerprints,
            expected_disposal_owner="acceptance-owner",
            expected_approver_identity="approval-owner",
            journal=journal,
            effect=effect,
            now=_NOW,
        )

    with ThreadPoolExecutor(max_workers=1) as executor:
        running = executor.submit(execute)
        assert entered_effect.wait(timeout=5)
        with pytest.raises(AuthorizationError, match="operation_live"):
            journal.require_recovery(_proposal().operation_id)
        release_effect.set()
        assert running.result(timeout=5).status == "committed"


def test_phase_b_refuses_terminal_success_after_lock_changes_during_effect(tmp_path: Path) -> None:
    root = tmp_path / "artifacts"
    signer, fingerprints, _ = _authorize_materials(root)
    journal = _journal(tmp_path)
    entered_effect = Event()
    release_effect = Event()

    def effect(context: VerifiedExecutionContext) -> EffectReceiptV1:
        entered_effect.set()
        assert release_effect.wait(timeout=5)
        return _effect(context)

    def execute() -> str:
        try:
            _execute_for_test(
                AuthorizationPaths(root),
                signer=signer,
                provider=_Provider(fingerprints),
                provider_fingerprints=fingerprints,
                expected_disposal_owner="acceptance-owner",
                expected_approver_identity="approval-owner",
                journal=journal,
                effect=effect,
                now=_NOW,
            )
        except AuthorizationError as error:
            return error.phase
        return "committed"

    with ThreadPoolExecutor(max_workers=1) as executor:
        running = executor.submit(execute)
        assert entered_effect.wait(timeout=5)
        _root_lock_path(root).unlink()
        release_effect.set()
        assert running.result(timeout=5) == "effect_failed_recovery_required"
    assert journal.operation_state(_proposal().operation_id).value == "failed_recovery_required"


def test_artifact_lock_rejects_relaxed_mode_and_symlink(tmp_path: Path) -> None:
    root = tmp_path / "artifacts"
    _materials(root)
    with ArtifactRootLease(root):
        pass
    lock_path = _root_lock_path(root)
    lock_path.chmod(0o644)
    with pytest.raises(AuthorizationError, match="artifact_lock_file"), ArtifactRootLease(root):
        pass

    symlink_root = tmp_path / "symlink-artifacts"
    _materials(symlink_root)
    with ArtifactRootLease(symlink_root):
        pass
    target = tmp_path / "lock-target"
    target.write_bytes(b"lock")
    target.chmod(0o600)
    _root_lock_path(symlink_root).unlink()
    _root_lock_path(symlink_root).symlink_to(target)
    with (
        pytest.raises(AuthorizationError, match="artifact_lock_file"),
        ArtifactRootLease(symlink_root),
    ):
        pass

    root_target = tmp_path / "root-target"
    _materials(root_target)
    root_symlink = tmp_path / "root-symlink"
    root_symlink.symlink_to(root_target, target_is_directory=True)
    with (
        pytest.raises(AuthorizationError, match="artifact_lock_root"),
        ArtifactRootLease(root_symlink),
    ):
        pass


def test_phase_b_rejects_artifact_and_provider_mutation_before_effect(tmp_path: Path) -> None:
    root = tmp_path / "artifacts"
    signer, fingerprints, _ = _authorize_materials(root)
    paths = AuthorizationPaths(root)
    journal = _journal(tmp_path)
    authority = _test_replay_authority(journal)
    _ensure_test_journal_provisioned(
        paths,
        signer=signer,
        expected_disposal_owner="acceptance-owner",
        expected_approver_identity="approval-owner",
        journal=journal,
        replay_authority=authority,
    )
    _ensure_test_initial_stage(
        paths,
        signer=signer,
        provider=_Provider(fingerprints),
        provider_fingerprints=fingerprints,
        expected_disposal_owner="acceptance-owner",
        expected_approver_identity="approval-owner",
        journal=_initial_journal(tmp_path, paths),
        replay_authority=authority,
    )
    raced_sidecar = root / AuthorizationPaths.signature_name("proposal.yaml")
    called = False

    def effect(context: VerifiedExecutionContext) -> EffectReceiptV1:
        nonlocal called
        called = True
        return _effect(context)

    with pytest.raises(AuthorizationError, match="artifact_race"):
        _execute_for_test(
            paths,
            signer=signer,
            provider=_Provider(fingerprints, mutate_artifact=raced_sidecar),
            provider_fingerprints=fingerprints,
            expected_disposal_owner="acceptance-owner",
            expected_approver_identity="approval-owner",
            journal=journal,
            effect=effect,
            now=_NOW,
            provision=False,
            replay_authority=authority,
        )
    assert not called

    provider_root = tmp_path / "provider-artifacts"
    signer, fingerprints, _ = _authorize_materials(provider_root)
    provider_paths = AuthorizationPaths(provider_root)
    provider_journal = _journal(tmp_path / "provider-journal")
    provider_authority = _test_replay_authority(provider_journal)
    _ensure_test_journal_provisioned(
        provider_paths,
        signer=signer,
        expected_disposal_owner="acceptance-owner",
        expected_approver_identity="approval-owner",
        journal=provider_journal,
        replay_authority=provider_authority,
    )
    _ensure_test_initial_stage(
        provider_paths,
        signer=signer,
        provider=_Provider(fingerprints),
        provider_fingerprints=fingerprints,
        expected_disposal_owner="acceptance-owner",
        expected_approver_identity="approval-owner",
        journal=_initial_journal(provider_paths.root.parent, provider_paths),
        replay_authority=provider_authority,
    )
    with pytest.raises(AuthorizationError, match="provider_provenance"):
        _execute_for_test(
            provider_paths,
            signer=signer,
            provider=_Provider(fingerprints, mutate_provider=True),
            provider_fingerprints=fingerprints,
            expected_disposal_owner="acceptance-owner",
            expected_approver_identity="approval-owner",
            journal=provider_journal,
            effect=_effect,
            now=_NOW,
            provision=False,
            replay_authority=provider_authority,
        )


def test_phase_b_rejects_marker_only_signature_and_cli_is_read_only(tmp_path: Path) -> None:
    root = tmp_path / "artifacts"
    signer, fingerprints, _ = _authorize_materials(root)
    (root / AuthorizationPaths.signature_name("approval.yaml")).unlink()

    with pytest.raises(AuthorizationError, match="artifact_snapshot"):
        _execute_for_test(
            AuthorizationPaths(root),
            signer=signer,
            provider=_Provider(fingerprints),
            provider_fingerprints=fingerprints,
            expected_disposal_owner="acceptance-owner",
            expected_approver_identity="approval-owner",
            journal=_journal(tmp_path),
            effect=_effect,
            now=_NOW,
        )
    assert authorization_main(["authorize", "--root", str(root)]) == 2
    assert main(["authorize", "--root", str(root)]) == 2
    assert not (root / AuthorizationPaths.journal_genesis_name()).exists()


def test_phase_b_rejects_disposal_owner_or_approval_mismatch(tmp_path: Path) -> None:
    root = tmp_path / "artifacts"
    signer, fingerprints, _ = _authorize_materials(root)

    with pytest.raises(AuthorizationError, match="owner_approval"):
        _execute_for_test(
            AuthorizationPaths(root),
            signer=signer,
            provider=_Provider(fingerprints),
            provider_fingerprints=fingerprints,
            expected_disposal_owner="wrong-owner",
            expected_approver_identity="approval-owner",
            journal=_journal(tmp_path),
            effect=_effect,
            now=_NOW,
        )


def test_external_execution_receipt_cannot_reach_internal_claim(tmp_path: Path) -> None:
    receipt = ExecutionReceiptV1(
        schema_version="rsd.lifecycle-execution-receipt.v1",
        status="committed",
        operation_kind="observed_lifecycle_v1",
        operation_id="forged-operation",
        idempotency_key="a" * 64,
        effect_receipt_sha256="b" * 64,
        proposal_sha256="c" * 64,
        contract_sha256="d" * 64,
        provider_provenance_sha256="e" * 64,
        committed_at="2026-08-27T12:00:00Z",
    )

    with pytest.raises(AuthorizationError, match="journal"):
        _journal(tmp_path)._claim_verified(receipt)  # type: ignore[arg-type]


def test_phase_b_rejects_marker_tampering_even_when_phase_a_hashes_are_refreshed(
    tmp_path: Path,
) -> None:
    root = tmp_path / "artifacts"
    signer, fingerprints, key = _authorize_materials(root)
    approval_path = root / "approval.yaml"
    approval = yaml.safe_load(approval_path.read_text(encoding="utf-8"))
    assert type(approval) is dict
    marker = approval["signature"]
    assert type(marker) is dict
    marker["detached_signature_sha256"] = "0" * 64
    approval_path.write_bytes(yaml.safe_dump(approval, sort_keys=True).encode())
    approval_path.chmod(0o600)
    _refresh_contract_evidence_hashes(root)
    _refresh_sidecar(root, "approval.yaml", key, resign=False)
    _refresh_sidecar(root, "runtime-contract.yaml", key, resign=True)

    with pytest.raises(AuthorizationError, match="signature_marker"):
        _execute_for_test(
            AuthorizationPaths(root),
            signer=signer,
            provider=_Provider(fingerprints),
            provider_fingerprints=fingerprints,
            expected_disposal_owner="acceptance-owner",
            expected_approver_identity="approval-owner",
            journal=_journal(tmp_path),
            effect=_effect,
            now=_NOW,
        )


def test_phase_b_rejects_sidecar_swap_and_noncanonical_base64_alias(tmp_path: Path) -> None:
    root = tmp_path / "artifacts"
    signer, fingerprints, _ = _authorize_materials(root)
    proposal_sidecar = root / AuthorizationPaths.signature_name("proposal.yaml")
    approval_sidecar = root / AuthorizationPaths.signature_name("approval.yaml")
    proposal_sidecar.write_bytes(approval_sidecar.read_bytes())
    proposal_sidecar.chmod(0o600)

    with pytest.raises(AuthorizationError, match="signature_binding"):
        _execute_for_test(
            AuthorizationPaths(root),
            signer=signer,
            provider=_Provider(fingerprints),
            provider_fingerprints=fingerprints,
            expected_disposal_owner="acceptance-owner",
            expected_approver_identity="approval-owner",
            journal=_journal(tmp_path),
            effect=_effect,
            now=_NOW,
        )

    alias_root = tmp_path / "aliased-artifacts"
    signer, fingerprints, _ = _authorize_materials(alias_root)
    proposal_sidecar = alias_root / AuthorizationPaths.signature_name("proposal.yaml")
    sidecar = yaml.safe_load(proposal_sidecar.read_text(encoding="utf-8"))
    assert type(sidecar) is dict
    encoded = sidecar["signature_base64"]
    assert type(encoded) is str and encoded.endswith("==")
    alphabet = "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/"
    final_index = alphabet.index(encoded[-3])
    alias = alphabet[(final_index & 0b110000) | ((final_index + 1) & 0b001111)]
    sidecar["signature_base64"] = f"{encoded[:-3]}{alias}=="
    proposal_sidecar.write_bytes(yaml.safe_dump(sidecar, sort_keys=True).encode())
    proposal_sidecar.chmod(0o600)

    with pytest.raises(AuthorizationError, match="signature_artifact"):
        _execute_for_test(
            AuthorizationPaths(alias_root),
            signer=signer,
            provider=_Provider(fingerprints),
            provider_fingerprints=fingerprints,
            expected_disposal_owner="acceptance-owner",
            expected_approver_identity="approval-owner",
            journal=_journal(tmp_path),
            effect=_effect,
            now=_NOW,
        )


def test_provider_material_genesis_is_create_only_and_partial_state_blocks_retry(
    tmp_path: Path,
) -> None:
    root = tmp_path / "provider-artifacts"
    signer, _fingerprints, _ = _authorize_materials(root)
    paths = AuthorizationPaths(root)
    initial_journal = _initial_journal(tmp_path, paths)
    intent = _initial_intent(
        paths,
        signer=signer,
        journal=initial_journal,
        proposal=_proposal(provider="macos_keychain"),
    )
    values = _provider_material_values()
    fingerprints = _material_fingerprints(intent, values)
    policy, attestation, genesis = _provider_material_bundle(
        intent, signer=signer, fingerprints=fingerprints
    )
    artifact_paths = ProviderMaterialArtifactPaths(root)
    provider_signer, signer_genesis = _provider_signer_for_intent(intent, issuer=signer)
    persist_signer_genesis(
        artifact_paths,
        signer_genesis,
        issuer=signer,
        initial_intent=intent,
    )
    _persist_provider_material_policy_for_test(
        artifact_paths,
        policy,
        signer=provider_signer,
        signer_genesis=signer_genesis,
        issuer=signer,
        initial_intent=intent,
        expected_disposal_owner="acceptance-owner",
        expected_approver_identity="approval-owner",
        _clock=lambda: _NOW,
    )
    _persist_provider_material_genesis_for_test(
        artifact_paths,
        genesis,
        policy=policy,
        attestation=attestation,
        signer=provider_signer,
        signer_genesis=signer_genesis,
        issuer=signer,
        initial_intent=intent,
        expected_disposal_owner="acceptance-owner",
        expected_approver_identity="approval-owner",
        _clock=lambda: _NOW,
    )
    store = _CreateOnlyMaterialStore()
    _provision_keychain_materials_for_test(
        artifact_paths,
        policy=policy,
        genesis=genesis,
        attestation=attestation,
        signer=provider_signer,
        signer_genesis=signer_genesis,
        issuer=signer,
        initial_intent=intent,
        expected_disposal_owner="acceptance-owner",
        expected_approver_identity="approval-owner",
        materials=values,
        _store=store,
        _clock=lambda: _NOW,
    )
    assert all(not any(value) for value in values.values())
    assert (
        provider_material_genesis_status(artifact_paths, _store=store).value
        == "structurally_complete_unverified"
    )
    loaded_policy, loaded_genesis, loaded_attestation = (
        _load_verified_provider_material_bundle_for_test(
            artifact_paths,
            signer=provider_signer,
            signer_genesis=signer_genesis,
            issuer=signer,
            initial_intent=intent,
            expected_disposal_owner="acceptance-owner",
            expected_approver_identity="approval-owner",
            _clock=lambda: _NOW,
        )
    )
    assert loaded_policy == policy
    assert loaded_genesis == genesis
    assert loaded_attestation == attestation

    retry_values = _provider_material_values()
    with pytest.raises(ProviderCryptoError, match="material_genesis_state"):
        _provision_keychain_materials_for_test(
            artifact_paths,
            policy=policy,
            genesis=genesis,
            attestation=attestation,
            signer=provider_signer,
            signer_genesis=signer_genesis,
            issuer=signer,
            initial_intent=intent,
            expected_disposal_owner="acceptance-owner",
            expected_approver_identity="approval-owner",
            materials=retry_values,
            _store=store,
            _clock=lambda: _NOW,
        )
    assert all(not any(value) for value in retry_values.values())

    partial_root = tmp_path / "partial-provider-artifacts"
    partial_signer, _partial_fingerprints, _ = _authorize_materials(partial_root)
    partial_paths = AuthorizationPaths(partial_root)
    partial_intent = _initial_intent(
        partial_paths,
        signer=partial_signer,
        journal=_initial_journal(tmp_path, partial_paths),
        proposal=_proposal(provider="macos_keychain"),
    )
    partial_values = _provider_material_values()
    partial_fingerprints = _material_fingerprints(partial_intent, partial_values)
    partial_policy, partial_attestation, partial_genesis = _provider_material_bundle(
        partial_intent, signer=partial_signer, fingerprints=partial_fingerprints
    )
    partial_artifact_paths = ProviderMaterialArtifactPaths(partial_root)
    partial_provider_signer, partial_signer_genesis = _provider_signer_for_intent(
        partial_intent,
        issuer=partial_signer,
    )
    persist_signer_genesis(
        partial_artifact_paths,
        partial_signer_genesis,
        issuer=partial_signer,
        initial_intent=partial_intent,
    )
    _persist_provider_material_policy_for_test(
        partial_artifact_paths,
        partial_policy,
        signer=partial_provider_signer,
        signer_genesis=partial_signer_genesis,
        issuer=partial_signer,
        initial_intent=partial_intent,
        expected_disposal_owner="acceptance-owner",
        expected_approver_identity="approval-owner",
        _clock=lambda: _NOW,
    )
    _persist_provider_material_genesis_for_test(
        partial_artifact_paths,
        partial_genesis,
        policy=partial_policy,
        attestation=partial_attestation,
        signer=partial_provider_signer,
        signer_genesis=partial_signer_genesis,
        issuer=partial_signer,
        initial_intent=partial_intent,
        expected_disposal_owner="acceptance-owner",
        expected_approver_identity="approval-owner",
        _clock=lambda: _NOW,
    )
    provider_secret = "secret-bearing-provider-error"
    partial_store = _CreateOnlyMaterialStore(fail_after=1, failure_message=provider_secret)
    with pytest.raises(ProviderCryptoError, match="material_provider") as caught:
        _provision_keychain_materials_for_test(
            partial_artifact_paths,
            policy=partial_policy,
            genesis=partial_genesis,
            attestation=partial_attestation,
            signer=partial_provider_signer,
            signer_genesis=partial_signer_genesis,
            issuer=partial_signer,
            initial_intent=partial_intent,
            expected_disposal_owner="acceptance-owner",
            expected_approver_identity="approval-owner",
            materials=partial_values,
            _store=partial_store,
            _clock=lambda: _NOW,
        )
    assert provider_secret not in "".join(traceback.format_exception(caught.value))
    assert caught.value.__cause__ is None
    assert caught.value.__context__ is None
    assert all(not any(value) for value in partial_values.values())
    assert (
        provider_material_genesis_status(partial_artifact_paths, _store=partial_store).value
        == "partial_or_reconciliation_required"
    )


def test_keychain_provenance_adapter_rejects_copied_material_policy(tmp_path: Path) -> None:
    root = tmp_path / "adapter-canonical-policy"
    issuer, _fingerprints, _ = _authorize_materials(root)
    paths = AuthorizationPaths(root)
    intent = _initial_intent(
        paths,
        signer=issuer,
        journal=_initial_journal(tmp_path, paths),
        proposal=_proposal(provider="macos_keychain"),
    )
    values = _provider_material_values()
    fingerprints = _material_fingerprints(intent, values)
    policy, _attestation, _genesis = _provider_material_bundle(
        intent,
        signer=issuer,
        fingerprints=fingerprints,
    )
    drifted_spec = policy.materials[0].model_copy(
        update={"format": ProviderMaterialFormat.HMAC_SHA256_RAW_32_V1.value}
    )
    drifted_policy = policy.model_copy(update={"materials": (drifted_spec, *policy.materials[1:])})

    with pytest.raises(ProviderCryptoError, match="material_policy"):
        MacOSKeychainProviderProvenanceAdapter(
            drifted_policy,
            _store=_CreateOnlyMaterialStore(),
        )


def test_public_material_persistence_cannot_use_a_historical_clock(tmp_path: Path) -> None:
    root = tmp_path / "expired-provider-artifacts"
    issuer, _fingerprints, _ = _authorize_materials(root)
    paths = AuthorizationPaths(root)
    intent = _initial_intent(
        paths,
        signer=issuer,
        journal=_initial_journal(tmp_path, paths),
        proposal=_proposal(provider="macos_keychain"),
    )
    values = _provider_material_values()
    fingerprints = _material_fingerprints(intent, values)
    policy, _attestation, _genesis = _provider_material_bundle(
        intent,
        signer=issuer,
        fingerprints=fingerprints,
    )
    provider_signer, signer_genesis = _provider_signer_for_intent(intent, issuer=issuer)
    unsigned = policy.model_copy(
        update={
            "created_at": "1999-01-01T00:00:00Z",
            "retention_expires_at": "2000-01-01T00:00:00Z",
            "signature_base64": base64.b64encode(b"0" * 64).decode(),
        }
    )
    policy_key = _TEST_SIGNING_KEYS[provider_signer.public_key_fingerprint_sha256]
    expired_policy = unsigned.model_copy(
        update={
            "signature_base64": base64.b64encode(
                policy_key.sign(provider_material_policy_message(unsigned))
            ).decode()
        }
    )
    artifact_paths = ProviderMaterialArtifactPaths(root)

    assert "now" not in inspect.signature(persist_provider_material_policy).parameters
    persist_signer_genesis(
        artifact_paths,
        signer_genesis,
        issuer=issuer,
        initial_intent=intent,
    )
    with pytest.raises(ProviderCryptoError, match="material_policy"):
        persist_provider_material_policy(
            artifact_paths,
            expired_policy,
            signer=provider_signer,
            signer_genesis=signer_genesis,
            issuer=issuer,
            initial_intent=intent,
            expected_disposal_owner="acceptance-owner",
            expected_approver_identity="approval-owner",
        )
    assert not (root / artifact_paths.policy_name()).exists()


def test_signer_genesis_binds_keychain_seed_and_refuses_duplicate_creation(tmp_path: Path) -> None:
    root = tmp_path / "signer-artifacts"
    issuer, _fingerprints, issuer_key = _authorize_materials(root)
    paths = AuthorizationPaths(root)
    intent = _initial_intent(paths, signer=issuer, journal=_initial_journal(tmp_path, paths))
    seed = bytearray(b"s" * 32)
    public = (
        Ed25519PrivateKey.from_private_bytes(bytes(seed))
        .public_key()
        .public_bytes(
            serialization.Encoding.Raw,
            serialization.PublicFormat.Raw,
        )
    )
    reference_fields = {
        "account": "provider-signer-account.v1",
        "provider": "macos_keychain",
        "service": "provider-signer-service",
        "version": 1,
    }
    reference = KeychainItemReferenceV1(
        **reference_fields,
        reference_sha256=_digest(
            json.dumps(reference_fields, sort_keys=True, separators=(",", ":")).encode()
        ),
    )
    unsigned = SignerGenesisV1(
        schema_version="rsd.provider-crypto.signer-genesis.v1",
        initial_intent_sha256=initial_provisioning_intent_sha256(intent),
        issuer_key_id=issuer.key_id,
        key_id="provider-signer",
        public_key_base64=base64.b64encode(public).decode(),
        public_key_fingerprint_sha256=_digest(public),
        seed_fingerprint_sha256=_digest(seed),
        keychain_reference=reference,
        created_at=_NOW.isoformat(timespec="seconds").replace("+00:00", "Z"),
        signature_base64=base64.b64encode(b"0" * 64).decode(),
    )
    genesis = unsigned.model_copy(
        update={
            "signature_base64": base64.b64encode(
                issuer_key.sign(signer_genesis_message(unsigned))
            ).decode()
        }
    )
    artifact_paths = ProviderMaterialArtifactPaths(root)
    persist_signer_genesis(artifact_paths, genesis, issuer=issuer, initial_intent=intent)
    assert (
        load_verified_signer_genesis(artifact_paths, issuer=issuer, initial_intent=intent)
        == genesis
    )
    store = _CreateOnlyMaterialStore()
    signer = provision_keychain_ed25519_signer(
        artifact_paths,
        genesis,
        issuer=issuer,
        initial_intent=intent,
        seed=seed,
        _store=store,
    )
    assert isinstance(signer, KeychainEd25519Signer)
    assert not any(seed)
    artifact = ReplayAuthorityPolicyArtifactV1(
        schema_version="rsd.provider-crypto.replay-authority-policy.v1",
        initial_intent_sha256=initial_provisioning_intent_sha256(intent),
        service=_TEST_REPLAY_POLICY.service,
        account_prefix=_TEST_REPLAY_POLICY.account_prefix,
        replay_policy_sha256=_TEST_REPLAY_POLICY.sha256(),
        created_at=_NOW.isoformat(timespec="seconds").replace("+00:00", "Z"),
        signer_key_id=genesis.key_id,
        signature_base64=base64.b64encode(b"0" * 64).decode(),
    )
    assert not hasattr(signer, "sign")
    signer.key().verify(signer.sign_artifact(artifact), replay_authority_policy_message(artifact))

    class _RawService(str):
        pass

    drifted_artifact = artifact.model_copy(update={"service": _RawService(artifact.service)})
    with pytest.raises(ProviderCryptoError, match="keychain_signer_scope"):
        signer.sign_artifact(drifted_artifact)
    wrong_intent_artifact = artifact.model_copy(update={"initial_intent_sha256": "f" * 64})
    with pytest.raises(ProviderCryptoError, match="keychain_signer_scope"):
        signer.sign_artifact(wrong_intent_artifact)
    loaded_signer = load_keychain_ed25519_signer(
        artifact_paths,
        issuer=issuer,
        initial_intent=intent,
        _store=store,
    )
    loaded_signer.key().verify(
        loaded_signer.sign_artifact(artifact), replay_authority_policy_message(artifact)
    )

    forged_intent = intent.model_copy(
        update={"signature_base64": base64.b64encode(b"f" * 64).decode()}
    )
    with pytest.raises(ProviderCryptoError, match="initial_intent_signature"):
        load_verified_signer_genesis(
            artifact_paths,
            issuer=issuer,
            initial_intent=forged_intent,
        )

    store.records[(reference.service, reference.account)] = b"x" * 32
    with pytest.raises(ProviderCryptoError, match="keychain_signer") as caught:
        signer.sign_artifact(artifact)
    assert caught.value.__cause__ is None
    assert caught.value.__context__ is None

    duplicate_seed = bytearray(b"s" * 32)
    with pytest.raises(ProviderCryptoError, match="keychain_signer_replayed"):
        provision_keychain_ed25519_signer(
            artifact_paths,
            genesis,
            issuer=issuer,
            initial_intent=intent,
            seed=duplicate_seed,
            _store=store,
        )
    assert not any(duplicate_seed)


def test_signer_genesis_is_pinned_before_keychain_writes_and_orphans_block(
    tmp_path: Path,
) -> None:
    root = tmp_path / "durable-signer-artifacts"
    issuer, _fingerprints, issuer_key = _authorize_materials(root)
    paths = AuthorizationPaths(root)
    intent = _initial_intent(paths, signer=issuer, journal=_initial_journal(tmp_path, paths))
    provider_signer, genesis = _provider_signer_for_intent(intent, issuer=issuer)
    private_key = _TEST_SIGNING_KEYS[provider_signer.public_key_fingerprint_sha256]
    seed = bytearray(
        private_key.private_bytes(
            serialization.Encoding.Raw,
            serialization.PrivateFormat.Raw,
            serialization.NoEncryption(),
        )
    )
    artifact_paths = ProviderMaterialArtifactPaths(root)

    class _GenesisCheckingStore(_CreateOnlyMaterialStore):
        def __init__(self) -> None:
            super().__init__()
            self.checked = False

        def add_if_absent(self, service: str, account: str, value: bytearray) -> bool:
            genesis_path = root / artifact_paths.signer_genesis_name()
            assert genesis_path.is_file()
            assert genesis_path.stat().st_mode & 0o777 == 0o600
            assert (
                load_verified_signer_genesis(
                    artifact_paths,
                    issuer=issuer,
                    initial_intent=intent,
                )
                == genesis
            )
            self.checked = True
            return super().add_if_absent(service, account, value)

    store = _GenesisCheckingStore()
    provision_keychain_ed25519_signer(
        artifact_paths,
        genesis,
        issuer=issuer,
        initial_intent=intent,
        seed=seed,
        _store=store,
    )
    assert store.checked
    assert not any(seed)

    replacement_private = Ed25519PrivateKey.generate()
    replacement_public = replacement_private.public_key().public_bytes(
        serialization.Encoding.Raw,
        serialization.PublicFormat.Raw,
    )
    replacement_seed = bytearray(
        replacement_private.private_bytes(
            serialization.Encoding.Raw,
            serialization.PrivateFormat.Raw,
            serialization.NoEncryption(),
        )
    )
    unsigned_replacement = genesis.model_copy(
        update={
            "key_id": "replacement-provider-signer",
            "public_key_base64": base64.b64encode(replacement_public).decode(),
            "public_key_fingerprint_sha256": _digest(replacement_public),
            "seed_fingerprint_sha256": _digest(replacement_seed),
            "signature_base64": base64.b64encode(b"0" * 64).decode(),
        }
    )
    replacement = unsigned_replacement.model_copy(
        update={
            "signature_base64": base64.b64encode(
                issuer_key.sign(signer_genesis_message(unsigned_replacement))
            ).decode()
        }
    )
    blocked_store = _CreateOnlyMaterialStore()
    with pytest.raises(ProviderCryptoError, match="artifact_replayed"):
        provision_keychain_ed25519_signer(
            artifact_paths,
            replacement,
            issuer=issuer,
            initial_intent=intent,
            seed=replacement_seed,
            _store=blocked_store,
        )
    assert not blocked_store.records
    assert not any(replacement_seed)

    # The signed file is held under an exclusive descriptor lease during the
    # irreversible add.  A same-owner writer that ignores that advisory lease
    # can still mutate the open inode, so the post-add descriptor revalidation
    # must fail closed rather than report a successful bootstrap.
    mutating_root = tmp_path / "mutating-signer-artifacts"
    mutating_issuer, _mutating_fingerprints, _ = _authorize_materials(mutating_root)
    mutating_paths = AuthorizationPaths(mutating_root)
    mutating_intent = _initial_intent(
        mutating_paths,
        signer=mutating_issuer,
        journal=_initial_journal(tmp_path, mutating_paths),
    )
    mutating_provider_signer, mutating_genesis = _provider_signer_for_intent(
        mutating_intent,
        issuer=mutating_issuer,
    )
    mutating_private_key = _TEST_SIGNING_KEYS[
        mutating_provider_signer.public_key_fingerprint_sha256
    ]
    mutating_seed = bytearray(
        mutating_private_key.private_bytes(
            serialization.Encoding.Raw,
            serialization.PrivateFormat.Raw,
            serialization.NoEncryption(),
        )
    )
    mutating_artifact_paths = ProviderMaterialArtifactPaths(mutating_root)

    class _MutatingSignerStore(_CreateOnlyMaterialStore):
        def add_if_absent(self, service: str, account: str, value: bytearray) -> bool:
            created = super().add_if_absent(service, account, value)
            signer_path = mutating_root / mutating_artifact_paths.signer_genesis_name()
            with signer_path.open("r+b", buffering=0) as handle:
                original = handle.read(1)
                assert original
                handle.seek(0)
                handle.write(b"x" if original != b"x" else b"y")
                handle.flush()
                os.fsync(handle.fileno())
            return created

    mutating_store = _MutatingSignerStore()
    with pytest.raises(ProviderCryptoError, match="signer_genesis"):
        provision_keychain_ed25519_signer(
            mutating_artifact_paths,
            mutating_genesis,
            issuer=mutating_issuer,
            initial_intent=mutating_intent,
            seed=mutating_seed,
            _store=mutating_store,
        )
    # The irreversible row may already exist, but the public API has not
    # blessed it: recovery is an orphan/fail-closed state, never success.
    assert mutating_store.records
    assert not any(mutating_seed)

    orphan_root = tmp_path / "orphan-material-artifacts"
    orphan_issuer, _orphan_fingerprints, _ = _authorize_materials(orphan_root)
    orphan_paths = AuthorizationPaths(orphan_root)
    orphan_intent = _initial_intent(
        orphan_paths,
        signer=orphan_issuer,
        journal=_initial_journal(tmp_path, orphan_paths),
        proposal=_proposal(provider="macos_keychain"),
    )
    values = _provider_material_values()
    fingerprints = _material_fingerprints(orphan_intent, values)
    policy, attestation, material_genesis = _provider_material_bundle(
        orphan_intent,
        signer=orphan_issuer,
        fingerprints=fingerprints,
    )
    orphan_provider_signer, orphan_signer_genesis = _provider_signer_for_intent(
        orphan_intent,
        issuer=orphan_issuer,
    )
    orphan_artifact_paths = ProviderMaterialArtifactPaths(orphan_root)
    # A manually prepared policy/manifest without a durable signer trust
    # anchor is an orphaned crash/manual state, never a material-create path.
    _write(orphan_root, orphan_artifact_paths.policy_name(), policy)
    _write(orphan_root, orphan_artifact_paths.genesis_name(), material_genesis)
    orphan_store = _CreateOnlyMaterialStore()
    with pytest.raises(ProviderCryptoError, match="artifact_read"):
        provision_keychain_materials(
            orphan_artifact_paths,
            policy=policy,
            genesis=material_genesis,
            attestation=attestation,
            signer=orphan_provider_signer,
            signer_genesis=orphan_signer_genesis,
            issuer=orphan_issuer,
            initial_intent=orphan_intent,
            expected_disposal_owner="acceptance-owner",
            expected_approver_identity="approval-owner",
            materials=values,
            _store=orphan_store,
        )
    assert not orphan_store.records
    assert all(not any(value) for value in values.values())


def test_phase_b_rejects_forged_provider_attestation_before_effect(tmp_path: Path) -> None:
    root = tmp_path / "artifacts"
    signer, fingerprints, _ = _authorize_materials(root)
    paths = AuthorizationPaths(root)
    journal = _journal(tmp_path)
    authority = _test_replay_authority(journal)
    initial_journal = _initial_journal(tmp_path, paths)
    _ensure_test_journal_provisioned(
        paths,
        signer=signer,
        expected_disposal_owner="acceptance-owner",
        expected_approver_identity="approval-owner",
        journal=journal,
        replay_authority=authority,
    )
    _ensure_test_initial_stage(
        paths,
        signer=signer,
        provider=_Provider(fingerprints),
        provider_fingerprints=fingerprints,
        expected_disposal_owner="acceptance-owner",
        expected_approver_identity="approval-owner",
        journal=initial_journal,
        replay_authority=authority,
    )
    attestation_path = root / ProviderMaterialArtifactPaths.attestation_name()
    forged_attestation = yaml.safe_load(attestation_path.read_bytes())
    assert type(forged_attestation) is dict
    forged_attestation["signature_base64"] = base64.b64encode(b"f" * 64).decode()
    attestation_path.write_bytes(yaml.safe_dump(forged_attestation, sort_keys=True).encode())
    attestation_path.chmod(0o600)
    called = False

    def effect(context: VerifiedExecutionContext) -> EffectReceiptV1:
        nonlocal called
        called = True
        return _effect(context)

    with pytest.raises(AuthorizationError, match="provider_material_attestation") as caught:
        _authorize_and_execute_for_test(
            paths,
            signer=signer,
            provider=_Provider(fingerprints),
            expected_disposal_owner="acceptance-owner",
            expected_approver_identity="approval-owner",
            journal=journal,
            initial_journal=initial_journal,
            effect=effect,
            replay_authority=authority,
            replay_policy=_TEST_REPLAY_POLICY,
            _clock=lambda: _NOW,
        )
    assert not called
    assert caught.value.__cause__ is None
    assert caught.value.__context__ is None


def test_phase_b_rejects_manual_provider_without_terminal_material_artifacts(
    tmp_path: Path,
) -> None:
    root = tmp_path / "artifacts"
    signer, fingerprints, _ = _authorize_materials(root)
    paths = AuthorizationPaths(root)
    journal = _journal(tmp_path)
    authority = _test_replay_authority(journal)
    initial_journal = _initial_journal(tmp_path, paths)
    _ensure_test_journal_provisioned(
        paths,
        signer=signer,
        expected_disposal_owner="acceptance-owner",
        expected_approver_identity="approval-owner",
        journal=journal,
        replay_authority=authority,
    )
    _ensure_test_initial_stage(
        paths,
        signer=signer,
        provider=_Provider(fingerprints),
        provider_fingerprints=fingerprints,
        expected_disposal_owner="acceptance-owner",
        expected_approver_identity="approval-owner",
        journal=initial_journal,
        replay_authority=authority,
    )
    terminal_marker = root / ProviderMaterialArtifactPaths.attestation_name()
    terminal_marker.unlink()
    called = False

    def effect(context: VerifiedExecutionContext) -> EffectReceiptV1:
        nonlocal called
        called = True
        return _effect(context)

    with pytest.raises(AuthorizationError, match="provider_material_attestation"):
        _authorize_and_execute_for_test(
            paths,
            signer=signer,
            provider=_Provider(fingerprints),
            expected_disposal_owner="acceptance-owner",
            expected_approver_identity="approval-owner",
            journal=journal,
            initial_journal=initial_journal,
            effect=effect,
            replay_authority=authority,
            replay_policy=_TEST_REPLAY_POLICY,
            _clock=lambda: _NOW,
        )
    assert not called


def test_tls_initial_intent_never_claims_or_reaches_an_effect(tmp_path: Path) -> None:
    root = tmp_path / "tls-artifacts"
    signer, _fingerprints, _ = _authorize_materials(root)
    paths = AuthorizationPaths(root)
    journal = _initial_journal(tmp_path, paths)
    intent = _initial_intent(
        paths,
        signer=signer,
        journal=journal,
        proposal=_proposal(tls=True),
    )
    authority = _AtomicReplayAuthority()

    with pytest.raises(AuthorizationError, match="tls_termination_amendment_required"):
        _provision_initial_journal_for_test(
            paths,
            signer=signer,
            expected_disposal_owner="acceptance-owner",
            expected_approver_identity="approval-owner",
            journal=journal,
            intent=intent,
            replay_authority=authority,
            replay_policy=_TEST_REPLAY_POLICY,
            replay_policy_artifact=_replay_policy_artifact(intent, signer=signer),
            _clock=lambda: _NOW,
        )
    assert not authority.tombstones
    assert journal.migration_status() is InitialProvisioningJournalStatus.ABSENT


def test_tls_type_drift_is_blocked_before_replay_or_keychain_creation(tmp_path: Path) -> None:
    """Raw strings and construction escapes cannot turn TLS into a non-TLS plan."""

    root = tmp_path / "tls-type-drift-artifacts"
    issuer, _fingerprints, _ = _authorize_materials(root)
    paths = AuthorizationPaths(root)
    typed_journal = _initial_journal(tmp_path, paths)
    typed_intent = _initial_intent(
        paths,
        signer=issuer,
        journal=typed_journal,
        proposal=_proposal(tls=True),
    )
    provider_signer, signer_genesis = _provider_signer_for_intent(typed_intent, issuer=issuer)
    provider_key = _TEST_SIGNING_KEYS[provider_signer.public_key_fingerprint_sha256]
    provider_seed = provider_key.private_bytes(
        serialization.Encoding.Raw,
        serialization.PrivateFormat.Raw,
        serialization.NoEncryption(),
    )

    class _TlsProfileSubclass(str):
        pass

    raw_transport = typed_intent.plan.transport.model_copy(update={"profile": "tls_verified_v1"})
    subclass_transport = typed_intent.plan.transport.model_copy(
        update={"profile": _TlsProfileSubclass("tls_verified_v1")}
    )
    constructed_transport_fields = typed_intent.plan.transport.model_dump(mode="python")
    constructed_transport_fields["profile"] = "tls_verified_v1"
    constructed_transport = TransportContractV1.model_construct(**constructed_transport_fields)
    constructed_intent_fields = typed_intent.model_dump(mode="python")
    constructed_intent_fields["plan"] = typed_intent.plan.model_copy(
        update={"transport": constructed_transport}
    )
    drifted_intents = (
        typed_intent.model_copy(
            update={"plan": typed_intent.plan.model_copy(update={"transport": raw_transport})}
        ),
        typed_intent.model_copy(
            update={"plan": typed_intent.plan.model_copy(update={"transport": subclass_transport})}
        ),
        InitialProvisioningIntentV1.model_construct(**constructed_intent_fields),
    )

    for index, drifted_intent in enumerate(drifted_intents):
        authority = _AtomicReplayAuthority()
        journal = SQLiteInitialProvisioningJournal(tmp_path / f"tls-drift-{index}.sqlite3")
        with pytest.raises(AuthorizationError, match=r"initial_intent|tls_termination"):
            provision_initial_journal(
                paths,
                signer=issuer,
                expected_disposal_owner="acceptance-owner",
                expected_approver_identity="approval-owner",
                journal=journal,
                intent=drifted_intent,
                replay_authority=authority,
                replay_policy=_TEST_REPLAY_POLICY,
                replay_policy_artifact=_replay_policy_artifact(typed_intent, signer=issuer),
            )
        assert not authority.tombstones
        assert journal.migration_status() is InitialProvisioningJournalStatus.ABSENT

        seed = bytearray(provider_seed)
        store = _CreateOnlyMaterialStore()
        with pytest.raises(ProviderCryptoError, match=r"initial_intent|tls_termination"):
            provision_keychain_ed25519_signer(
                ProviderMaterialArtifactPaths(root),
                signer_genesis,
                issuer=issuer,
                initial_intent=drifted_intent,
                seed=seed,
                _store=store,
            )
        assert not store.records
        assert not any(seed)
        assert not (root / ProviderMaterialArtifactPaths.signer_genesis_name()).exists()
