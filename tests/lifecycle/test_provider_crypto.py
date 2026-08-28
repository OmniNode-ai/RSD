"""Adversarial tests for public provider-crypto bootstrap primitives."""

from __future__ import annotations

import base64
import hashlib
import json
import os
from datetime import UTC, datetime
from pathlib import Path

import pytest
from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey

import omninode_rsd.lifecycle.authorization as authorization
import omninode_rsd.lifecycle.provider_crypto as provider_crypto
from omninode_rsd.lifecycle.authorization import TrustedEd25519SignerV1
from omninode_rsd.lifecycle.infisical_disposable import (
    AllocationEvidenceBindingsV1,
    AllocationIntentV2,
    AllocationPlanV2,
    AllocationPostgreSQLPlanV2,
    AllocationTopologyV2,
    AllocationVolumePlanV1,
    ComponentPlacementV1,
    DisposableTransportProfile,
    ExecutorPlacementV1,
    IsolatedNetworkPlanV1,
    PostgreSQLGrantPlanV1,
    ProviderReferencesV1,
    ProviderReferenceV1,
    TransportContractV1,
    allocation_intent_sha256,
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
    ProviderMaterialGenesisStatus,
    ProviderMaterialGenesisV1,
    ProviderMaterialPolicyV1,
    ProviderMaterialPurpose,
    ProviderMaterialSpecV1,
    SignerGenesisV1,
    load_keychain_ed25519_signer,
    load_verified_provider_material_bundle,
    persist_provider_material_genesis,
    persist_provider_material_policy,
    persist_signer_genesis,
    provider_fingerprint_attestation_message,
    provider_material_genesis_message,
    provider_material_genesis_status,
    provider_material_policy_message,
    provision_keychain_ed25519_signer,
    provision_keychain_materials,
    signer_genesis_message,
)


def _sha256(value: bytes) -> str:
    return hashlib.sha256(value).hexdigest()


def _reference(name: str, version: int = 1) -> ProviderReferenceV1:
    fields = {
        "account": f"account-{name}.v{version}",
        "provider": "macos_keychain",
        "service": f"service-{name}",
        "version": version,
    }
    return ProviderReferenceV1(
        **fields,
        reference_sha256=_sha256(
            json.dumps(fields, sort_keys=True, separators=(",", ":")).encode()
        ),
    )


def _policy() -> ProviderMaterialPolicyV1:
    definitions: tuple[
        tuple[ProviderMaterialPurpose, ProviderMaterialFormat, int, int, ProviderReferenceV1], ...
    ] = (
        (
            ProviderMaterialPurpose.COMMITMENT_HMAC,
            ProviderMaterialFormat.HMAC_SHA256_RAW_32_V1,
            32,
            32,
            _reference("commitment"),
        ),
        (
            ProviderMaterialPurpose.BACKUP_ENCRYPTION,
            ProviderMaterialFormat.AES_256_GCM_RAW_32_V1,
            32,
            32,
            _reference("backup"),
        ),
        (
            ProviderMaterialPurpose.INFISICAL_ENCRYPTION_KEY,
            ProviderMaterialFormat.INFISICAL_HEX_16_V1,
            32,
            32,
            _reference("encryption"),
        ),
        (
            ProviderMaterialPurpose.INFISICAL_AUTH_SECRET,
            ProviderMaterialFormat.INFISICAL_AUTH_SECRET_BASE64_32_V1,
            44,
            44,
            _reference("auth"),
        ),
        (
            ProviderMaterialPurpose.PRIMARY_VALKEY_PASSWORD,
            ProviderMaterialFormat.VALKEY_PASSWORD_BASE64URL_32_V1,
            43,
            43,
            _reference("primary"),
        ),
        (
            ProviderMaterialPurpose.RESTORE_VALKEY_PASSWORD,
            ProviderMaterialFormat.VALKEY_PASSWORD_BASE64URL_32_V1,
            43,
            43,
            _reference("restore"),
        ),
    )
    signer_fields = {
        "account": "account-provider-signer.v1",
        "provider": "macos_keychain",
        "service": "service-provider-signer",
        "version": 1,
    }
    return ProviderMaterialPolicyV1(
        schema_version="rsd.provider-crypto.material-policy.v1",
        allocation_intent_sha256="a" * 64,
        disposal_owner="owner",
        approver_identity="approver",
        policy_id="123e4567-e89b-42d3-a456-426614174011",
        signer_keychain_reference=KeychainItemReferenceV1(
            **signer_fields,
            reference_sha256=_sha256(
                json.dumps(signer_fields, sort_keys=True, separators=(",", ":")).encode()
            ),
        ),
        signer_seed_fingerprint_sha256="f" * 64,
        created_at="2026-08-27T12:00:00Z",
        retention_expires_at="2026-08-27T12:10:00Z",
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
        signer_key_id="test-signer",
        signature_base64=base64.b64encode(b"0" * 64).decode(),
    )


def _values(policy: ProviderMaterialPolicyV1) -> dict[str, bytes]:
    values = (
        b"c" * 32,
        b"b" * 32,
        b"0123456789abcdef0123456789abcdef",
        base64.b64encode(b"a" * 32),
        base64.urlsafe_b64encode(b"p" * 32).rstrip(b"="),
        base64.urlsafe_b64encode(b"r" * 32).rstrip(b"="),
    )
    return {
        spec.reference.reference_sha256: value
        for spec, value in zip(policy.materials, values, strict=True)
    }


class _Store:
    def __init__(self) -> None:
        self.records: dict[tuple[str, str], bytes] = {}
        self.add_calls: list[tuple[str, str]] = []

    def add_if_absent(self, service: str, account: str, value: bytearray) -> bool:
        self.add_calls.append((service, account))
        key = (service, account)
        if key in self.records:
            return False
        self.records[key] = bytes(value)
        return True

    def read_if_present(self, service: str, account: str) -> bytearray | None:
        stored = self.records.get((service, account))
        return None if stored is None else bytearray(stored)


_BOOTSTRAP_CLOCK = datetime(2026, 8, 28, 12, 5, tzinfo=UTC)


def _macos_references() -> ProviderReferencesV1:
    return ProviderReferencesV1(
        commitment_hmac=_reference("commitment"),
        backup_encryption=_reference("backup"),
        encryption_key=_reference("encryption"),
        auth_secret=_reference("auth"),
        primary_valkey_password=_reference("primary"),
        restore_valkey_password=_reference("restore"),
    )


def _provider_values() -> dict[ProviderMaterialPurpose, bytearray]:
    return {
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


def _signed_provider_allocation_intent(
    tmp_path: Path,
) -> tuple[TrustedEd25519SignerV1, Ed25519PrivateKey, AllocationIntentV2]:
    """Build the smallest canonical V2 intent needed by provider-crypto tests."""

    issuer_key = Ed25519PrivateKey.generate()
    issuer_public = issuer_key.public_key().public_bytes_raw()
    issuer = TrustedEd25519SignerV1(
        key_id="provider-bootstrap-issuer",
        public_key_base64=base64.b64encode(issuer_public).decode("ascii"),
        public_key_fingerprint_sha256=_sha256(issuer_public),
    )
    primary = IsolatedNetworkPlanV1(
        name="provider-primary-net",
        driver="bridge",
        internal=True,
        subnet="192.0.2.0/28",
        gateway="192.0.2.1",
    )
    restore = IsolatedNetworkPlanV1(
        name="provider-restore-net",
        driver="bridge",
        internal=True,
        subnet="198.51.100.0/28",
        gateway="198.51.100.1",
    )
    topology = AllocationTopologyV2(
        primary_network=primary,
        restore_network=restore,
        primary_infisical=ComponentPlacementV1(
            component="primary_infisical",
            network_name=primary.name,
            alias="provider-primary-infisical",
            static_ipv4="192.0.2.2",
        ),
        primary_valkey=ComponentPlacementV1(
            component="primary_valkey",
            network_name=primary.name,
            alias="provider-primary-valkey",
            static_ipv4="192.0.2.3",
        ),
        restore_infisical=ComponentPlacementV1(
            component="restore_infisical",
            network_name=restore.name,
            alias="provider-restore-infisical",
            static_ipv4="198.51.100.2",
        ),
        restore_valkey=ComponentPlacementV1(
            component="restore_valkey",
            network_name=restore.name,
            alias="provider-restore-valkey",
            static_ipv4="198.51.100.3",
        ),
        executor=ExecutorPlacementV1(
            executor_id="provider-local-executor",
            placement="inside_disposable_networks_v1",
            attached_network_names=(primary.name, restore.name),
        ),
    )
    postgres_policy_sha256 = _sha256(b"provider-postgres-policy")
    plan = AllocationPlanV2(
        transport=TransportContractV1(
            profile=DisposableTransportProfile.UNPUBLISHED_LOOPBACK_OR_NETWORK,
            authority="http://192.0.2.2:8080",
            authority_sha256=_sha256(b"http://192.0.2.2:8080"),
            listener_binding="isolated_network_only",
            isolated_network_name=primary.name,
            isolated_network_alias="provider-primary-infisical",
        ),
        topology=topology,
        primary_valkey_volume=AllocationVolumePlanV1(
            name="provider-primary-volume", driver="local"
        ),
        restore_valkey_volume=AllocationVolumePlanV1(
            name="provider-restore-volume", driver="local"
        ),
        postgres=AllocationPostgreSQLPlanV2(
            authority="postgresql://192.0.2.40:5432",
            database_name="provider-database",
            schema_name="provider-schema",
            owner_role="provider-owner",
            role_names=("provider-owner", "provider-reader"),
            grants=(
                PostgreSQLGrantPlanV1(
                    role="provider-owner",
                    grantee="provider-reader",
                    privilege="SELECT",
                    schema_name="provider-schema",
                ),
            ),
            stage_database_prefix="provider-stage",
            restore_database_prefix="provider-restore",
            control_policy_sha256=postgres_policy_sha256,
        ),
    )
    journal_path = tmp_path / "provider-allocation-journal.sqlite3"
    evidence = AllocationEvidenceBindingsV1(
        approval_sha256=_sha256(b"provider-approval"),
        governed_deny_sha256=_sha256(b"provider-deny"),
        governed_baseline_sha256=_sha256(b"provider-baseline"),
        collision_evidence_sha256=_sha256(b"provider-collision"),
        registry_verification_sha256=_sha256(b"provider-registry"),
        provider_declaration_sha256=_sha256(b"provider-declaration"),
        executor_control_policy_sha256=_sha256(b"provider-executor-policy"),
        postgres_control_policy_sha256=postgres_policy_sha256,
    )
    unsigned = AllocationIntentV2(
        schema_version="rsd.allocation-intent.v2",
        operation_kind="allocation_v2",
        operation_scope="allocate_isolated_empty_resources_v2",
        allocation_operation_id="123e4567-e89b-42d3-a456-426614174050",
        source_commit="a" * 40,
        plan=plan,
        provider_references=_macos_references(),
        evidence=evidence,
        retention_expires_at="2026-08-28T12:20:00Z",
        disposal_owner="owner@example.test",
        approver_identity="approver@example.test",
        approval_reference_sha256=_sha256(b"provider-approval-reference"),
        journal_path=str(journal_path),
        journal_path_sha256=_sha256(os.fsencode(journal_path)),
        journal_uuid="123e4567-e89b-42d3-a456-426614174051",
        journal_schema_sha256=_sha256(b"provider-journal-schema"),
        replay_policy_sha256=_sha256(b"provider-replay-policy"),
        created_at="2026-08-28T12:00:00Z",
        signer_key_id=issuer.key_id,
        signature_base64=base64.b64encode(b"0" * 64).decode("ascii"),
    )
    signed = unsigned.model_copy(
        update={
            "signature_base64": base64.b64encode(
                issuer_key.sign(authorization._allocation_intent_message(unsigned))
            ).decode("ascii")
        }
    )
    return issuer, issuer_key, signed


def _signed_v2_material_bundle(
    tmp_path: Path,
) -> tuple[
    ProviderMaterialArtifactPaths,
    AllocationIntentV2,
    TrustedEd25519SignerV1,
    Ed25519PrivateKey,
    TrustedEd25519SignerV1,
    SignerGenesisV1,
    ProviderMaterialPolicyV1,
    ProviderFingerprintAttestationV1,
    ProviderMaterialGenesisV1,
]:
    """Build a signed V2 bootstrap fixture using only an injected memory store."""

    issuer, issuer_key, allocation_intent = _signed_provider_allocation_intent(tmp_path)
    material_key = Ed25519PrivateKey.generate()
    seed = material_key.private_bytes(
        serialization.Encoding.Raw,
        serialization.PrivateFormat.Raw,
        serialization.NoEncryption(),
    )
    public = material_key.public_key().public_bytes(
        serialization.Encoding.Raw, serialization.PublicFormat.Raw
    )
    signer_fields = {
        "account": "provider-signer.v1",
        "provider": "macos_keychain",
        "service": "provider-signer-service",
        "version": 1,
    }
    signer_reference = KeychainItemReferenceV1(
        **signer_fields,
        reference_sha256=_sha256(
            json.dumps(signer_fields, sort_keys=True, separators=(",", ":")).encode()
        ),
    )
    material_signer = TrustedEd25519SignerV1(
        key_id="provider-material-signer",
        public_key_base64=base64.b64encode(public).decode("ascii"),
        public_key_fingerprint_sha256=_sha256(public),
    )
    unsigned_signer_genesis = SignerGenesisV1(
        schema_version="rsd.provider-crypto.signer-genesis.v1",
        allocation_intent_sha256=allocation_intent_sha256(allocation_intent),
        issuer_key_id=issuer.key_id,
        key_id=material_signer.key_id,
        public_key_base64=material_signer.public_key_base64,
        public_key_fingerprint_sha256=material_signer.public_key_fingerprint_sha256,
        seed_fingerprint_sha256=_sha256(seed),
        keychain_reference=signer_reference,
        created_at="2026-08-28T12:00:00Z",
        signature_base64=base64.b64encode(b"0" * 64).decode("ascii"),
    )
    signer_genesis = unsigned_signer_genesis.model_copy(
        update={
            "signature_base64": base64.b64encode(
                issuer_key.sign(signer_genesis_message(unsigned_signer_genesis))
            ).decode("ascii")
        }
    )
    references = allocation_intent.provider_references
    material_references = {
        ProviderMaterialPurpose.COMMITMENT_HMAC: references.commitment_hmac,
        ProviderMaterialPurpose.BACKUP_ENCRYPTION: references.backup_encryption,
        ProviderMaterialPurpose.INFISICAL_ENCRYPTION_KEY: references.encryption_key,
        ProviderMaterialPurpose.INFISICAL_AUTH_SECRET: references.auth_secret,
        ProviderMaterialPurpose.PRIMARY_VALKEY_PASSWORD: references.primary_valkey_password,
        ProviderMaterialPurpose.RESTORE_VALKEY_PASSWORD: references.restore_valkey_password,
    }
    template = _policy()
    policy_specs = tuple(
        spec.model_copy(update={"reference": material_references[spec.purpose]})
        for spec in template.materials
    )
    unsigned_policy = template.model_copy(
        update={
            "allocation_intent_sha256": allocation_intent_sha256(allocation_intent),
            "disposal_owner": allocation_intent.disposal_owner,
            "approver_identity": allocation_intent.approver_identity,
            "signer_keychain_reference": signer_reference,
            "signer_seed_fingerprint_sha256": signer_genesis.seed_fingerprint_sha256,
            "created_at": "2026-08-28T12:00:00Z",
            "retention_expires_at": "2026-08-28T12:20:00Z",
            "materials": policy_specs,
            "signer_key_id": material_signer.key_id,
            "signature_base64": base64.b64encode(b"0" * 64).decode("ascii"),
        }
    )
    policy = unsigned_policy.model_copy(
        update={
            "signature_base64": base64.b64encode(
                material_key.sign(provider_material_policy_message(unsigned_policy))
            ).decode("ascii")
        }
    )
    values = _provider_values()
    unsigned_attestation = ProviderFingerprintAttestationV1(
        schema_version="rsd.provider-crypto.fingerprint-attestation.v1",
        allocation_intent_sha256=allocation_intent_sha256(allocation_intent),
        provider_material_policy_sha256=policy.policy_sha256(),
        attestation_id="123e4567-e89b-42d3-a456-426614174012",
        observed_at="2026-08-28T12:02:00Z",
        materials=tuple(
            ProviderMaterialFingerprintV1(
                purpose=spec.purpose,
                reference_sha256=spec.reference.reference_sha256,
                fingerprint_sha256=_sha256(values[spec.purpose]),
            )
            for spec in policy.materials
        ),
        signer_key_id=material_signer.key_id,
        signature_base64=base64.b64encode(b"0" * 64).decode("ascii"),
    )
    attestation = unsigned_attestation.model_copy(
        update={
            "signature_base64": base64.b64encode(
                material_key.sign(provider_fingerprint_attestation_message(unsigned_attestation))
            ).decode("ascii")
        }
    )
    unsigned_genesis = ProviderMaterialGenesisV1(
        schema_version="rsd.provider-crypto.material-genesis.v1",
        status="pending",
        genesis_id="123e4567-e89b-42d3-a456-426614174013",
        allocation_intent_sha256=allocation_intent_sha256(allocation_intent),
        provider_material_policy_sha256=policy.policy_sha256(),
        provider_fingerprint_attestation_sha256=_sha256(
            json.dumps(
                attestation.model_dump(mode="json"), sort_keys=True, separators=(",", ":")
            ).encode()
        ),
        created_at="2026-08-28T12:03:00Z",
        signer_key_id=material_signer.key_id,
        signature_base64=base64.b64encode(b"0" * 64).decode("ascii"),
    )
    genesis = unsigned_genesis.model_copy(
        update={
            "signature_base64": base64.b64encode(
                material_key.sign(provider_material_genesis_message(unsigned_genesis))
            ).decode("ascii")
        }
    )
    root = tmp_path / "provider-artifacts"
    root.mkdir(mode=0o700)
    return (
        ProviderMaterialArtifactPaths(root),
        allocation_intent,
        issuer,
        material_key,
        material_signer,
        signer_genesis,
        policy,
        attestation,
        genesis,
    )


def _persist_v2_material_bundle(
    bundle: tuple[
        ProviderMaterialArtifactPaths,
        AllocationIntentV2,
        TrustedEd25519SignerV1,
        Ed25519PrivateKey,
        TrustedEd25519SignerV1,
        SignerGenesisV1,
        ProviderMaterialPolicyV1,
        ProviderFingerprintAttestationV1,
        ProviderMaterialGenesisV1,
    ],
) -> None:
    paths, intent, issuer, _material_key, signer, signer_genesis, policy, attestation, genesis = (
        bundle
    )
    persist_signer_genesis(paths, signer_genesis, issuer=issuer, allocation_intent=intent)
    persist_provider_material_policy(
        paths,
        policy,
        signer=signer,
        signer_genesis=signer_genesis,
        issuer=issuer,
        allocation_intent=intent,
        expected_disposal_owner=intent.disposal_owner,
        expected_approver_identity=intent.approver_identity,
    )
    persist_provider_material_genesis(
        paths,
        genesis,
        policy=policy,
        attestation=attestation,
        signer=signer,
        signer_genesis=signer_genesis,
        issuer=issuer,
        allocation_intent=intent,
        expected_disposal_owner=intent.disposal_owner,
        expected_approver_identity=intent.approver_identity,
    )


def _constructed_tls_intent(intent: AllocationIntentV2) -> AllocationIntentV2:
    """Construct the only forbidden transport drift without invoking an API."""

    return intent.model_construct(
        **{
            **intent.model_dump(mode="python"),
            "plan": intent.plan.model_construct(
                **{
                    **intent.plan.model_dump(mode="python"),
                    "transport": intent.plan.transport.model_construct(
                        **{
                            **intent.plan.transport.model_dump(mode="python"),
                            "profile": DisposableTransportProfile.TLS_VERIFIED,
                        }
                    ),
                }
            ),
        }
    )


def test_keychain_provenance_adapter_exposes_no_material_value() -> None:
    policy = _policy()
    values = _values(policy)
    store = _Store()
    for spec in policy.materials:
        store.records[(spec.reference.service, spec.reference.account)] = values[
            spec.reference.reference_sha256
        ]

    adapter = MacOSKeychainProviderProvenanceAdapter(policy, _store=store)
    references = tuple(spec.reference for spec in policy.materials)
    with adapter.acquire(references) as lease:
        provenances = tuple(lease.inspect(reference) for reference in references)
        assert tuple(lease.recheck(reference) for reference in references) == provenances

    assert all(item is not None for item in provenances)
    for provenance in provenances:
        assert provenance is not None
        assert not hasattr(provenance, "value")
        assert provenance.fingerprint_sha256 == _sha256(values[provenance.reference_sha256])


def test_keychain_provenance_rejects_malformed_value_without_leaking_it() -> None:
    policy = _policy()
    values = _values(policy)
    target = policy.materials[2]
    malformed = values[target.reference.reference_sha256] + b"!"
    store = _Store()
    for spec in policy.materials:
        value = malformed if spec == target else values[spec.reference.reference_sha256]
        store.records[(spec.reference.service, spec.reference.account)] = value

    adapter = MacOSKeychainProviderProvenanceAdapter(policy, _store=store)
    with (
        adapter.acquire(tuple(spec.reference for spec in policy.materials)) as lease,
        pytest.raises(ProviderCryptoError, match="material_format") as caught,
    ):
        lease.inspect(target.reference)

    error = caught.value
    assert malformed.decode("ascii") not in str(error)
    assert error.__cause__ is None
    assert error.__context__ is None


def test_material_policy_rejects_duplicate_purpose_and_reference() -> None:
    policy = _policy()
    raw = policy.model_dump(mode="python")
    materials = list(raw["materials"])
    materials[1] = materials[0]
    raw["materials"] = tuple(materials)

    with pytest.raises(ValueError, match="provider material policy fields"):
        ProviderMaterialPolicyV1.model_validate(raw)


@pytest.mark.parametrize("material_index", range(6))
def test_material_policy_rejects_reusing_the_signer_keychain_item(
    material_index: int,
) -> None:
    policy = _policy()
    raw = policy.model_dump(mode="python")
    materials = list(raw["materials"])
    materials[material_index] = {
        **materials[material_index],
        "reference": raw["signer_keychain_reference"],
    }
    raw["materials"] = tuple(materials)

    with pytest.raises(ValueError, match="provider material policy fields"):
        ProviderMaterialPolicyV1.model_validate(raw)


@pytest.mark.parametrize(
    ("purpose", "alphabet", "last_offset"),
    (
        (
            ProviderMaterialPurpose.INFISICAL_AUTH_SECRET,
            b"ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/",
            -2,
        ),
        (
            ProviderMaterialPurpose.PRIMARY_VALKEY_PASSWORD,
            b"ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789-_",
            -1,
        ),
    ),
)
def test_keychain_provenance_rejects_noncanonical_trailing_bit_aliases(
    purpose: ProviderMaterialPurpose,
    alphabet: bytes,
    last_offset: int,
) -> None:
    policy = _policy()
    values = _values(policy)
    target = next(spec for spec in policy.materials if spec.purpose is purpose)
    alias = bytearray(values[target.reference.reference_sha256])
    position = len(alias) + last_offset
    index = alphabet.index(alias[position])
    alias[position] = alphabet[(index & ~0b11) | ((index + 1) & 0b11)]
    store = _Store()
    for spec in policy.materials:
        value = alias if spec is target else values[spec.reference.reference_sha256]
        store.records[(spec.reference.service, spec.reference.account)] = bytes(value)

    adapter = MacOSKeychainProviderProvenanceAdapter(policy, _store=store)
    with (
        pytest.raises(ProviderCryptoError, match="material_format"),
        adapter.acquire(tuple(spec.reference for spec in policy.materials)) as lease,
    ):
        lease.inspect(target.reference)


def test_keychain_reference_requires_an_immutable_versioned_account_name() -> None:
    fields = {
        "account": "account-without-version",
        "provider": "macos_keychain",
        "service": "service-versioned",
        "version": 1,
    }
    with pytest.raises(ValueError, match="keychain reference does not bind metadata"):
        KeychainItemReferenceV1(
            **fields,
            reference_sha256=_sha256(
                json.dumps(fields, sort_keys=True, separators=(",", ":")).encode()
            ),
        )


def test_v2_material_genesis_is_create_only_and_partial_state_is_terminal(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    monkeypatch.setattr(provider_crypto, "_system_utc_clock", lambda: _BOOTSTRAP_CLOCK)
    bundle = _signed_v2_material_bundle(tmp_path)
    _persist_v2_material_bundle(bundle)
    paths, intent, issuer, _material_key, signer, signer_genesis, policy, attestation, genesis = (
        bundle
    )
    store = _Store()
    values = _provider_values()

    provision_keychain_materials(
        paths,
        policy=policy,
        genesis=genesis,
        attestation=attestation,
        signer=signer,
        signer_genesis=signer_genesis,
        issuer=issuer,
        allocation_intent=intent,
        expected_disposal_owner=intent.disposal_owner,
        expected_approver_identity=intent.approver_identity,
        materials=values,
        _store=store,
    )
    assert all(not any(value) for value in values.values())
    assert provider_material_genesis_status(paths, _store=store) is (
        ProviderMaterialGenesisStatus.STRUCTURALLY_COMPLETE_UNVERIFIED
    )
    assert load_verified_provider_material_bundle(
        paths,
        signer=signer,
        signer_genesis=signer_genesis,
        issuer=issuer,
        allocation_intent=intent,
        expected_disposal_owner=intent.disposal_owner,
        expected_approver_identity=intent.approver_identity,
    ) == (policy, genesis, attestation)

    retry_values = _provider_values()
    with pytest.raises(ProviderCryptoError, match="material_genesis_state"):
        provision_keychain_materials(
            paths,
            policy=policy,
            genesis=genesis,
            attestation=attestation,
            signer=signer,
            signer_genesis=signer_genesis,
            issuer=issuer,
            allocation_intent=intent,
            expected_disposal_owner=intent.disposal_owner,
            expected_approver_identity=intent.approver_identity,
            materials=retry_values,
            _store=store,
        )
    assert all(not any(value) for value in retry_values.values())

    partial_root = tmp_path / "partial-materials"
    partial_root.mkdir(mode=0o700)
    partial_bundle = _signed_v2_material_bundle(partial_root)
    _persist_v2_material_bundle(partial_bundle)
    (
        partial_paths,
        partial_intent,
        partial_issuer,
        _partial_material_key,
        partial_signer,
        partial_signer_genesis,
        partial_policy,
        partial_attestation,
        partial_genesis,
    ) = partial_bundle

    class FailingStore(_Store):
        def __init__(self) -> None:
            super().__init__()
            self.remaining = 1

        def add_if_absent(self, service: str, account: str, value: bytearray) -> bool:
            if self.remaining == 0:
                raise RuntimeError("adapter-value-must-not-escape")
            self.remaining -= 1
            return super().add_if_absent(service, account, value)

    partial_values = _provider_values()
    partial_store = FailingStore()
    with pytest.raises(ProviderCryptoError, match="material_provider") as caught:
        provision_keychain_materials(
            partial_paths,
            policy=partial_policy,
            genesis=partial_genesis,
            attestation=partial_attestation,
            signer=partial_signer,
            signer_genesis=partial_signer_genesis,
            issuer=partial_issuer,
            allocation_intent=partial_intent,
            expected_disposal_owner=partial_intent.disposal_owner,
            expected_approver_identity=partial_intent.approver_identity,
            materials=partial_values,
            _store=partial_store,
        )
    assert "adapter-value-must-not-escape" not in str(caught.value)
    assert caught.value.__cause__ is None
    assert caught.value.__context__ is None
    assert all(not any(value) for value in partial_values.values())
    assert provider_material_genesis_status(partial_paths, _store=partial_store) is (
        ProviderMaterialGenesisStatus.PARTIAL_OR_RECONCILIATION_REQUIRED
    )


def test_v2_signer_genesis_is_durable_before_create_only_seed_write(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    monkeypatch.setattr(provider_crypto, "_system_utc_clock", lambda: _BOOTSTRAP_CLOCK)
    bundle = _signed_v2_material_bundle(tmp_path)
    paths, intent, issuer, material_key, _, signer_genesis, _, _, _ = bundle
    seed = bytearray(
        material_key.private_bytes(
            serialization.Encoding.Raw,
            serialization.PrivateFormat.Raw,
            serialization.NoEncryption(),
        )
    )

    class CheckingStore(_Store):
        checked = False

        def add_if_absent(self, service: str, account: str, value: bytearray) -> bool:
            artifact = paths.root / paths.signer_genesis_name()
            assert artifact.is_file()
            assert artifact.stat().st_mode & 0o777 == 0o600
            self.checked = True
            return super().add_if_absent(service, account, value)

    store = CheckingStore()
    signer = provision_keychain_ed25519_signer(
        paths,
        signer_genesis,
        issuer=issuer,
        allocation_intent=intent,
        seed=seed,
        _store=store,
    )
    assert store.checked
    assert not any(seed)
    assert signer.key_id == signer_genesis.key_id
    duplicate = bytearray(
        material_key.private_bytes(
            serialization.Encoding.Raw,
            serialization.PrivateFormat.Raw,
            serialization.NoEncryption(),
        )
    )
    with pytest.raises(ProviderCryptoError, match="keychain_signer_replayed"):
        provision_keychain_ed25519_signer(
            paths,
            signer_genesis,
            issuer=issuer,
            allocation_intent=intent,
            seed=duplicate,
            _store=store,
        )
    assert not any(duplicate)


def test_v2_provider_artifact_orphan_and_forged_attestation_never_authorize(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    monkeypatch.setattr(provider_crypto, "_system_utc_clock", lambda: _BOOTSTRAP_CLOCK)
    bundle = _signed_v2_material_bundle(tmp_path)
    _persist_v2_material_bundle(bundle)
    paths, intent, issuer, _material_key, signer, signer_genesis, policy, attestation, genesis = (
        bundle
    )
    store = _Store()
    values = _provider_values()
    provision_keychain_materials(
        paths,
        policy=policy,
        genesis=genesis,
        attestation=attestation,
        signer=signer,
        signer_genesis=signer_genesis,
        issuer=issuer,
        allocation_intent=intent,
        expected_disposal_owner=intent.disposal_owner,
        expected_approver_identity=intent.approver_identity,
        materials=values,
        _store=store,
    )
    forged = attestation.model_copy(
        update={"signature_base64": base64.b64encode(b"f" * 64).decode("ascii")}
    )
    with pytest.raises(ProviderCryptoError, match="artifact_signature"):
        provider_crypto.verify_provider_material_bundle(
            policy,
            forged,
            signer=signer,
            signer_genesis=signer_genesis,
            issuer=issuer,
            allocation_intent=intent,
            expected_disposal_owner=intent.disposal_owner,
            expected_approver_identity=intent.approver_identity,
        )
    (paths.root / paths.signer_genesis_name()).unlink()
    with pytest.raises(ProviderCryptoError, match="artifact_read"):
        load_verified_provider_material_bundle(
            paths,
            signer=signer,
            signer_genesis=signer_genesis,
            issuer=issuer,
            allocation_intent=intent,
            expected_disposal_owner=intent.disposal_owner,
            expected_approver_identity=intent.approver_identity,
        )
    assert (
        provider_material_genesis_status(paths, _store=store)
        is ProviderMaterialGenesisStatus.INVALID
    )


def test_v2_pending_material_manifest_cannot_be_used_as_provider_readiness(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    """A manually seeded, nonterminal manifest is not a material authorization."""

    monkeypatch.setattr(provider_crypto, "_system_utc_clock", lambda: _BOOTSTRAP_CLOCK)
    bundle = _signed_v2_material_bundle(tmp_path)
    _persist_v2_material_bundle(bundle)
    paths, intent, issuer, _material_key, signer, signer_genesis, _, _, _ = bundle

    with pytest.raises(ProviderCryptoError, match="material_genesis_pending"):
        load_verified_provider_material_bundle(
            paths,
            signer=signer,
            signer_genesis=signer_genesis,
            issuer=issuer,
            allocation_intent=intent,
            expected_disposal_owner=intent.disposal_owner,
            expected_approver_identity=intent.approver_identity,
        )
    assert provider_material_genesis_status(paths, _store=_Store()) is (
        ProviderMaterialGenesisStatus.PENDING
    )


def test_v2_copied_provider_material_policy_cannot_cross_allocation_intents(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    """A signed policy is bound to one signer genesis and one allocation intent."""

    monkeypatch.setattr(provider_crypto, "_system_utc_clock", lambda: _BOOTSTRAP_CLOCK)
    first_root = tmp_path / "first"
    second_root = tmp_path / "second"
    first_root.mkdir(mode=0o700)
    second_root.mkdir(mode=0o700)
    first = _signed_v2_material_bundle(first_root)
    second = _signed_v2_material_bundle(second_root)
    (
        first_paths,
        first_intent,
        first_issuer,
        _first_material_key,
        first_signer,
        first_genesis,
        first_policy,
        first_attestation,
        first_manifest,
    ) = first
    second_paths, second_intent, second_issuer, _, second_signer, second_genesis, _, _, _ = second
    _persist_v2_material_bundle(first)
    provision_keychain_materials(
        first_paths,
        policy=first_policy,
        genesis=first_manifest,
        attestation=first_attestation,
        signer=first_signer,
        signer_genesis=first_genesis,
        issuer=first_issuer,
        allocation_intent=first_intent,
        expected_disposal_owner=first_intent.disposal_owner,
        expected_approver_identity=first_intent.approver_identity,
        materials=_provider_values(),
        _store=_Store(),
    )
    _persist_v2_material_bundle(second)
    copied_policy = (first_paths.root / first_paths.policy_name()).read_bytes()
    copied_attestation = (first_paths.root / first_paths.attestation_name()).read_bytes()
    target = second_paths.root / second_paths.policy_name()
    target.write_bytes(copied_policy)
    target.chmod(0o600)
    attestation_target = second_paths.root / second_paths.attestation_name()
    attestation_target.write_bytes(copied_attestation)
    attestation_target.chmod(0o600)

    with pytest.raises(ProviderCryptoError, match="artifact_signature"):
        load_verified_provider_material_bundle(
            second_paths,
            signer=second_signer,
            signer_genesis=second_genesis,
            issuer=second_issuer,
            allocation_intent=second_intent,
            expected_disposal_owner=second_intent.disposal_owner,
            expected_approver_identity=second_intent.approver_identity,
        )


def test_v2_material_policy_uses_the_internal_clock_and_blocks_expired_policy(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    bundle = _signed_v2_material_bundle(tmp_path)
    paths, intent, issuer, material_key, signer, signer_genesis, policy, _, _ = bundle
    monkeypatch.setattr(provider_crypto, "_system_utc_clock", lambda: _BOOTSTRAP_CLOCK)
    persist_signer_genesis(paths, signer_genesis, issuer=issuer, allocation_intent=intent)
    unsigned = policy.model_copy(
        update={
            "created_at": "1999-01-01T00:00:00Z",
            "retention_expires_at": "2000-01-01T00:00:00Z",
            "signature_base64": base64.b64encode(b"0" * 64).decode("ascii"),
        }
    )
    expired = unsigned.model_copy(
        update={
            "signature_base64": base64.b64encode(
                material_key.sign(provider_material_policy_message(unsigned))
            ).decode("ascii")
        }
    )
    monkeypatch.setattr(
        provider_crypto, "_system_utc_clock", lambda: datetime(2030, 1, 1, tzinfo=UTC)
    )

    with pytest.raises(ProviderCryptoError, match="material_policy_binding"):
        persist_provider_material_policy(
            paths,
            expired,
            signer=signer,
            signer_genesis=signer_genesis,
            issuer=issuer,
            allocation_intent=intent,
            expected_disposal_owner=intent.disposal_owner,
            expected_approver_identity=intent.approver_identity,
        )
    assert not (paths.root / paths.policy_name()).exists()


def test_v2_tls_drift_cannot_construct_or_load_provider_readiness(
    tmp_path: Path,
) -> None:
    """Every signer/provider readiness entry stops before artifacts or Keychain use."""

    bundle = _signed_v2_material_bundle(tmp_path)
    paths, intent, issuer, material_key, signer, signer_genesis, _, _, _ = bundle
    tls_intent = _constructed_tls_intent(intent)
    seed = bytearray(
        material_key.private_bytes(
            serialization.Encoding.Raw,
            serialization.PrivateFormat.Raw,
            serialization.NoEncryption(),
        )
    )

    class NoKeychainStore(_Store):
        def read_if_present(self, service: str, account: str) -> bytearray | None:
            del service, account
            raise AssertionError("TLS must stop before a Keychain read")

        def add_if_absent(self, service: str, account: str, value: bytearray) -> bool:
            del service, account, value
            raise AssertionError("TLS must stop before a Keychain write")

    store = NoKeychainStore()
    with pytest.raises(ProviderCryptoError, match="allocation_intent"):
        provision_keychain_ed25519_signer(
            paths,
            signer_genesis,
            issuer=issuer,
            allocation_intent=tls_intent,
            seed=seed,
            _store=store,
        )
    assert not any(seed)
    with pytest.raises(ProviderCryptoError, match="allocation_intent"):
        KeychainEd25519Signer(
            signer_genesis,
            issuer=issuer,
            allocation_intent=tls_intent,
            _store=store,
        )
    with pytest.raises(ProviderCryptoError, match="allocation_intent"):
        load_keychain_ed25519_signer(
            paths,
            issuer=issuer,
            allocation_intent=tls_intent,
            _store=store,
        )
    with pytest.raises(ProviderCryptoError, match="allocation_intent"):
        load_verified_provider_material_bundle(
            paths,
            signer=signer,
            signer_genesis=signer_genesis,
            issuer=issuer,
            allocation_intent=tls_intent,
            expected_disposal_owner=intent.disposal_owner,
            expected_approver_identity=intent.approver_identity,
        )
    assert list(paths.root.iterdir()) == []
    assert store.add_calls == []
