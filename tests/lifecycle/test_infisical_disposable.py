"""Adversarial tests for the public V2 allocation/materialization contracts.

Every value in this module is a documentation-only fixture.  The tests invoke
models and injected protocol boundaries only: no Keychain, engine, database,
network, process, or provider is contacted.
"""

from __future__ import annotations

import base64
import hashlib
import inspect
import os
from datetime import UTC, datetime
from pathlib import Path
from typing import Any, cast

import pytest
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey

import omninode_rsd.lifecycle.authorization as authorization
from omninode_rsd.lifecycle.authorization import (
    AllocationExecutionContext,
    AllocationJournalStatus,
    ArtifactRootLease,
    AuthorizationError,
    AuthorizationPaths,
    ExecutorControlExpectationV1,
    MaterializationExecutionContext,
    MaterializationOperationState,
    PostgreSQLControlExpectationV1,
    ProviderExpectationV1,
    ReplayAuthorityClaimResult,
    ReplayAuthorityPolicyV1,
    ReplayTombstoneV1,
    SecretMaterialExpectationV1,
    SQLiteAllocationJournal,
    TrustedEd25519SignerV1,
    authorize_allocation_and_execute,
    authorize_materialization_and_execute,
    provision_allocation_journal,
)
from omninode_rsd.lifecycle.infisical_disposable import (
    AllocatedNetworkObservationV1,
    AllocatedPostgreSQLObservationV1,
    AllocatedResourceSetV2,
    AllocatedVolumeObservationV1,
    AllocationEffectReceiptV2,
    AllocationEvidenceBindingsV1,
    AllocationIntentV2,
    AllocationPlanV2,
    AllocationPostgreSQLPlanV2,
    AllocationTopologyV2,
    AllocationVolumePlanV1,
    ComponentPlacementV1,
    DisposableTransportProfile,
    EngineIdentityObservationV1,
    ExecutorControlPolicyV1,
    ExecutorIdentityV1,
    ExecutorPlacementV1,
    ImageConfigBindingV1,
    ImageReferenceV1,
    IsolatedNetworkPlanV1,
    MaterializationComponentPlanV1,
    MaterializationEffectReceiptV1,
    MaterializationEvidenceBindingsV1,
    MaterializationIntentV1,
    MaterializationPlanV1,
    NetworkOptionV1,
    NoHostPublicationEvidenceV1,
    NoHostPublicationGroundworkV1,
    ObservedAllocationAttestationV1,
    PostgreSQLControlPolicyV1,
    PostgreSQLGrantObservationV1,
    PostgreSQLGrantPlanV1,
    PostgreSQLRoleObservationV1,
    ProviderReferencesV1,
    ProviderReferenceV1,
    RuntimeContainerObservationV1,
    RuntimeNetworkAttachmentV1,
    SecretCapabilityPolicyV1,
    SecretHandlingPolicyV1,
    TransportContractV1,
    allocation_effect_receipt_sha256,
    allocation_intent_sha256,
    canonical_sha256,
    materialization_intent_sha256,
    observed_allocation_attestation_sha256,
    strict_canonical_allocation_intent,
    validate_observed_allocation_transition,
)
from omninode_rsd.lifecycle.provider_crypto import (
    ReplayAuthorityPolicyArtifactV1,
    replay_authority_policy_message,
)

_COMMIT = "a" * 40
_OWNER = "owner@example.test"
_APPROVER = "approver@example.test"
_ALLOCATION_ID = "123e4567-e89b-42d3-a456-426614174000"
_MATERIALIZATION_ID = "123e4567-e89b-42d3-a456-426614174002"
_JOURNAL_ID = "123e4567-e89b-42d3-a456-426614174001"
_NOW = "2026-08-28T12:00:00Z"
_RETAINS = "2026-08-28T12:20:00Z"
_SIGNATURE = base64.b64encode(b"s" * 64).decode("ascii")
_TEST_CLOCK = datetime(2026, 8, 28, 12, 5, tzinfo=UTC)


def _hash(label: str) -> str:
    return hashlib.sha256(label.encode("ascii")).hexdigest()


def _reference(name: str) -> ProviderReferenceV1:
    values = {
        "provider": "metadata-provider",
        "service": f"service-{name}",
        "account": f"account-{name}",
        "version": 1,
    }
    encoded = (
        '{"account":"'
        + values["account"]
        + '","provider":"'
        + values["provider"]
        + '","service":"'
        + values["service"]
        + '","version":1}'
    ).encode("ascii")
    return ProviderReferenceV1(**values, reference_sha256=hashlib.sha256(encoded).hexdigest())


def _references() -> ProviderReferencesV1:
    return ProviderReferencesV1(
        commitment_hmac=_reference("commitment"),
        backup_encryption=_reference("backup"),
        encryption_key=_reference("encryption"),
        auth_secret=_reference("auth"),
        primary_valkey_password=_reference("primary-cache"),
        restore_valkey_password=_reference("restore-cache"),
    )


def _image(name: str, character: str) -> ImageReferenceV1:
    return ImageReferenceV1(reference=f"registry.example.test/{name}@sha256:{character * 64}")


def _topology() -> AllocationTopologyV2:
    primary = IsolatedNetworkPlanV1(
        name="primary-net",
        driver="bridge",
        internal=True,
        subnet="192.0.2.0/28",
        gateway="192.0.2.1",
        options=(NetworkOptionV1(key="com.example.option", value="enabled"),),
    )
    restore = IsolatedNetworkPlanV1(
        name="restore-net",
        driver="bridge",
        internal=True,
        subnet="198.51.100.0/28",
        gateway="198.51.100.1",
    )
    return AllocationTopologyV2(
        primary_network=primary,
        restore_network=restore,
        primary_infisical=ComponentPlacementV1(
            component="primary_infisical",
            network_name=primary.name,
            alias="primary-infisical",
            static_ipv4="192.0.2.2",
        ),
        primary_valkey=ComponentPlacementV1(
            component="primary_valkey",
            network_name=primary.name,
            alias="primary-valkey",
            static_ipv4="192.0.2.3",
        ),
        restore_infisical=ComponentPlacementV1(
            component="restore_infisical",
            network_name=restore.name,
            alias="restore-infisical",
            static_ipv4="198.51.100.2",
        ),
        restore_valkey=ComponentPlacementV1(
            component="restore_valkey",
            network_name=restore.name,
            alias="restore-valkey",
            static_ipv4="198.51.100.3",
        ),
        executor=ExecutorPlacementV1(
            executor_id="local-executor",
            placement="inside_disposable_networks_v1",
            attached_network_names=(primary.name, restore.name),
        ),
    )


def _executor_policy(topology: AllocationTopologyV2) -> ExecutorControlPolicyV1:
    return ExecutorControlPolicyV1(
        schema_version="rsd.executor-control-policy.v1",
        source_commit=_COMMIT,
        executor=ExecutorIdentityV1(
            executor_id=topology.executor.executor_id,
            platform="local_unix_v1",
            authenticated_transport="unix_peer_credential_v1",
            endpoint_sha256=_hash("executor-endpoint"),
            host_fingerprint_sha256=_hash("executor-host"),
            control_capability_fingerprint_sha256=_hash("executor-control"),
        ),
        engine_fingerprint_sha256=_hash("engine"),
        allowed_operations=(
            "allocate_isolated_empty_resources_v2",
            "materialize_and_start_runtime_v1",
        ),
        image_configs=(
            ImageConfigBindingV1(
                component="primary_infisical",
                image=_image("infisical", "a"),
                config_sha256=_hash("primary-infisical-config"),
            ),
            ImageConfigBindingV1(
                component="primary_valkey",
                image=_image("valkey", "b"),
                config_sha256=_hash("primary-valkey-config"),
            ),
            ImageConfigBindingV1(
                component="restore_infisical",
                image=_image("infisical", "a"),
                config_sha256=_hash("restore-infisical-config"),
            ),
            ImageConfigBindingV1(
                component="restore_valkey",
                image=_image("valkey", "b"),
                config_sha256=_hash("restore-valkey-config"),
            ),
        ),
        created_at=_NOW,
        signer_key_id="test-signer",
        signature_base64=_SIGNATURE,
    )


def _postgres_policy(executor: ExecutorControlPolicyV1) -> PostgreSQLControlPolicyV1:
    return PostgreSQLControlPolicyV1(
        schema_version="rsd.postgresql-control-policy.v1",
        source_commit=_COMMIT,
        executor_identity_sha256=canonical_sha256(executor.executor),
        authority="postgresql://192.0.2.40:5432",
        maintenance_reference_sha256=_hash("postgres-maintenance"),
        database_name="acceptance-db",
        schema_name="acceptance-schema",
        owner_role="owner-role",
        role_names=("owner-role", "reader-role"),
        grants=(
            PostgreSQLGrantPlanV1(
                role="owner-role",
                grantee="reader-role",
                privilege="SELECT",
                schema_name="acceptance-schema",
            ),
        ),
        created_at=_NOW,
        signer_key_id="test-signer",
        signature_base64=_SIGNATURE,
    )


def _allocation_bundle(
    tmp_path: Path,
) -> tuple[AllocationIntentV2, ExecutorControlPolicyV1, PostgreSQLControlPolicyV1]:
    topology = _topology()
    executor = _executor_policy(topology)
    postgres = _postgres_policy(executor)
    plan = AllocationPlanV2(
        transport=TransportContractV1(
            profile=DisposableTransportProfile.UNPUBLISHED_LOOPBACK_OR_NETWORK,
            authority="http://192.0.2.2:8080",
            authority_sha256=_hash("http://192.0.2.2:8080"),
            listener_binding="isolated_network_only",
            isolated_network_name=topology.primary_network.name,
            isolated_network_alias=topology.primary_infisical.alias,
        ),
        topology=topology,
        primary_valkey_volume=AllocationVolumePlanV1(name="primary-volume", driver="local"),
        restore_valkey_volume=AllocationVolumePlanV1(name="restore-volume", driver="local"),
        postgres=AllocationPostgreSQLPlanV2(
            authority=postgres.authority,
            database_name=postgres.database_name,
            schema_name=postgres.schema_name,
            owner_role=postgres.owner_role,
            role_names=postgres.role_names,
            grants=postgres.grants,
            stage_database_prefix="stage-db",
            restore_database_prefix="restore-db",
            control_policy_sha256=canonical_sha256(postgres),
        ),
    )
    journal_path = tmp_path / "allocation-journal.sqlite3"
    return (
        AllocationIntentV2(
            schema_version="rsd.allocation-intent.v2",
            operation_kind="allocation_v2",
            operation_scope="allocate_isolated_empty_resources_v2",
            allocation_operation_id=_ALLOCATION_ID,
            source_commit=_COMMIT,
            plan=plan,
            provider_references=_references(),
            evidence=AllocationEvidenceBindingsV1(
                approval_sha256=_hash("approval"),
                governed_deny_sha256=_hash("deny"),
                governed_baseline_sha256=_hash("baseline"),
                collision_evidence_sha256=_hash("collision"),
                registry_verification_sha256=_hash("registry"),
                provider_declaration_sha256=_hash("provider-declaration"),
                executor_control_policy_sha256=canonical_sha256(executor),
                postgres_control_policy_sha256=canonical_sha256(postgres),
            ),
            retention_expires_at=_RETAINS,
            disposal_owner=_OWNER,
            approver_identity=_APPROVER,
            approval_reference_sha256=_hash("approval-reference"),
            journal_path=str(journal_path),
            journal_path_sha256=hashlib.sha256(os.fsencode(journal_path)).hexdigest(),
            journal_uuid=_JOURNAL_ID,
            journal_schema_sha256=_hash("allocation-journal-schema"),
            replay_policy_sha256=_hash("replay-policy"),
            created_at=_NOW,
            signer_key_id="test-signer",
            signature_base64=_SIGNATURE,
        ),
        executor,
        postgres,
    )


class _AtomicReplayAuthority:
    """Test-only create-once authority; production has no such default."""

    def __init__(self, *, root: Path | None = None) -> None:
        self.claims: dict[tuple[str, str], bytes] = {}
        self.root = root
        self.calls = 0

    def claim_once(self, tombstone: ReplayTombstoneV1) -> ReplayAuthorityClaimResult:
        self.calls += 1
        if self.root is not None:
            assert (self.root / AuthorizationPaths.replay_policy_name()).is_file()
        key = (tombstone.service, tombstone.account)
        value = tombstone.value_bytes()
        existing = self.claims.get(key)
        if existing is None:
            self.claims[key] = value
            return ReplayAuthorityClaimResult.CREATED
        return (
            ReplayAuthorityClaimResult.DUPLICATE_SAME
            if existing == value
            else ReplayAuthorityClaimResult.DUPLICATE_CONFLICT
        )


def _trusted_signer() -> tuple[TrustedEd25519SignerV1, Ed25519PrivateKey]:
    key = Ed25519PrivateKey.generate()
    public = key.public_key().public_bytes_raw()
    return (
        TrustedEd25519SignerV1(
            key_id="test-signer",
            public_key_base64=base64.b64encode(public).decode("ascii"),
            public_key_fingerprint_sha256=hashlib.sha256(public).hexdigest(),
        ),
        key,
    )


def _signed_allocation_bundle(
    tmp_path: Path,
) -> tuple[
    TrustedEd25519SignerV1,
    Ed25519PrivateKey,
    AllocationIntentV2,
    ExecutorControlPolicyV1,
    PostgreSQLControlPolicyV1,
    SQLiteAllocationJournal,
    ReplayAuthorityPolicyV1,
    ReplayAuthorityPolicyArtifactV1,
]:
    """Build a real-signature allocation genesis fixture without a live provider."""

    journal_root = tmp_path / "journal"
    journal_root.mkdir(mode=0o700)
    journal = SQLiteAllocationJournal(journal_root / "allocation.sqlite3")
    signer, key = _trusted_signer()
    unsigned_intent, unsigned_executor, unsigned_postgres = _allocation_bundle(tmp_path)
    executor = unsigned_executor.model_copy(
        update={
            "signature_base64": base64.b64encode(
                key.sign(authorization._executor_control_policy_message(unsigned_executor))
            ).decode("ascii")
        }
    )
    postgres = unsigned_postgres.model_copy(
        update={
            "signature_base64": base64.b64encode(
                key.sign(authorization._postgres_control_policy_message(unsigned_postgres))
            ).decode("ascii")
        }
    )
    plan = unsigned_intent.plan.model_copy(
        update={
            "postgres": unsigned_intent.plan.postgres.model_copy(
                update={"control_policy_sha256": canonical_sha256(postgres)}
            )
        }
    )
    policy = ReplayAuthorityPolicyV1(
        schema_version="rsd.replay-authority-policy.v1",
        service="replay-service",
        account_prefix="replay-prefix",
    )
    unsigned = unsigned_intent.model_copy(
        update={
            "plan": plan,
            "evidence": unsigned_intent.evidence.model_copy(
                update={
                    "executor_control_policy_sha256": canonical_sha256(executor),
                    "postgres_control_policy_sha256": canonical_sha256(postgres),
                }
            ),
            "journal_path": str(journal._path),
            "journal_path_sha256": journal._path_sha256(),
            "journal_schema_sha256": journal.journal_schema_sha256(),
            "replay_policy_sha256": policy.sha256(),
        }
    )
    intent = unsigned.model_copy(
        update={
            "signature_base64": base64.b64encode(
                key.sign(authorization._allocation_intent_message(unsigned))
            ).decode("ascii")
        }
    )
    unsigned_artifact = ReplayAuthorityPolicyArtifactV1(
        schema_version="rsd.provider-crypto.replay-authority-policy.v1",
        allocation_intent_sha256=allocation_intent_sha256(intent),
        service=policy.service,
        account_prefix=policy.account_prefix,
        replay_policy_sha256=policy.sha256(),
        created_at=_NOW,
        signer_key_id=signer.key_id,
        signature_base64=_SIGNATURE,
    )
    artifact = unsigned_artifact.model_copy(
        update={
            "signature_base64": base64.b64encode(
                key.sign(replay_authority_policy_message(unsigned_artifact))
            ).decode("ascii")
        }
    )
    return signer, key, intent, executor, postgres, journal, policy, artifact


def _allocated_resources(intent: AllocationIntentV2) -> AllocatedResourceSetV2:
    topology = intent.plan.topology
    postgres = intent.plan.postgres
    return AllocatedResourceSetV2(
        engine=EngineIdentityObservationV1(
            engine_id=_hash("engine-id"), engine_fingerprint_sha256=_hash("engine")
        ),
        primary_network=AllocatedNetworkObservationV1(
            name=topology.primary_network.name,
            network_id=_hash("primary-network-id"),
            driver="bridge",
            internal=True,
            subnet=topology.primary_network.subnet,
            gateway=topology.primary_network.gateway,
            options=topology.primary_network.options,
        ),
        restore_network=AllocatedNetworkObservationV1(
            name=topology.restore_network.name,
            network_id=_hash("restore-network-id"),
            driver="bridge",
            internal=True,
            subnet=topology.restore_network.subnet,
            gateway=topology.restore_network.gateway,
            options=topology.restore_network.options,
        ),
        primary_cache_volume=AllocatedVolumeObservationV1(
            name=intent.plan.primary_valkey_volume.name,
            volume_id=_hash("primary-volume-id"),
            driver="local",
            options=intent.plan.primary_valkey_volume.options,
        ),
        restore_cache_volume=AllocatedVolumeObservationV1(
            name=intent.plan.restore_valkey_volume.name,
            volume_id=_hash("restore-volume-id"),
            driver="local",
            options=intent.plan.restore_valkey_volume.options,
        ),
        postgres=AllocatedPostgreSQLObservationV1(
            system_identifier="12345678",
            database_name=postgres.database_name,
            database_oid=101,
            schema_name=postgres.schema_name,
            schema_oid=102,
            owner_role=postgres.owner_role,
            owner_role_oid=103,
            role_oids=(
                PostgreSQLRoleObservationV1(role="owner-role", role_oid=103),
                PostgreSQLRoleObservationV1(role="reader-role", role_oid=104),
            ),
            grants=(
                PostgreSQLGrantObservationV1(
                    role="owner-role",
                    grantee="reader-role",
                    privilege="SELECT",
                    schema_name=postgres.schema_name,
                ),
            ),
            acl_sha256=_hash("postgres-acl"),
        ),
        no_host_publication=NoHostPublicationGroundworkV1(
            host_network=False,
            publish_all_ports=False,
            allowed_attachment_set_sha256=canonical_sha256(topology),
        ),
    )


def _allocation_receipt(intent: AllocationIntentV2) -> AllocationEffectReceiptV2:
    return AllocationEffectReceiptV2(
        schema_version="rsd.allocation-effect-receipt.v2",
        operation_kind="allocation_v2",
        operation_scope="allocate_isolated_empty_resources_v2",
        status="allocated_isolated_empty_resources",
        allocation_operation_id=intent.allocation_operation_id,
        allocation_intent_sha256=allocation_intent_sha256(intent),
        journal_uuid=intent.journal_uuid,
        idempotency_key=_hash("allocation-idempotency"),
        allocated_resources=_allocated_resources(intent),
        effect_receipt_sha256=_hash("allocation-effect"),
        completed_at="2026-08-28T12:01:00Z",
    )


def _allocation_attestation(
    intent: AllocationIntentV2, receipt: AllocationEffectReceiptV2
) -> ObservedAllocationAttestationV1:
    return ObservedAllocationAttestationV1(
        schema_version="rsd.observed-allocation-attestation.v1",
        operation_kind="allocation_v2",
        allocation_operation_id=intent.allocation_operation_id,
        allocation_intent_sha256=allocation_intent_sha256(intent),
        allocation_effect_receipt_sha256=allocation_effect_receipt_sha256(receipt),
        allocation_topology_sha256=canonical_sha256(intent.plan.topology),
        allocated_resources=receipt.allocated_resources,
        observed_at="2026-08-28T12:02:00Z",
        signer_key_id="test-signer",
        signature_base64=_SIGNATURE,
    )


def _secret_policies(
    intent: AllocationIntentV2, executor: ExecutorControlPolicyV1
) -> tuple[SecretCapabilityPolicyV1, SecretHandlingPolicyV1]:
    handling = SecretHandlingPolicyV1(
        schema_version="rsd.secret-handling-policy.v1",
        source_commit=_COMMIT,
        allocation_intent_sha256=allocation_intent_sha256(intent),
        executor_identity_sha256=canonical_sha256(executor.executor),
        provider_identity_sha256=_hash("provider-material-attestation"),
        capability_fingerprint_sha256=_hash("secret-capability"),
        infisical_target_processes=("primary_infisical", "restore_infisical"),
        valkey_stdin_config_processes=("primary_valkey", "restore_valkey"),
        infisical_target_process_environment_allowed=True,
        valkey_stdin_config_allowed=True,
        environment_file_allowed=False,
        host_environment_allowed=False,
        docker_config_environment_allowed=False,
        argv_allowed=False,
        labels_allowed=False,
        logs_allowed=False,
        receipts_allowed=False,
        disk_plaintext_allowed=False,
        public_artifacts_allowed=False,
        restart_policy="no",
        restart_authorization_schema="rsd.start-runtime-intent.v2",
        restart_authorization_scope="start_runtime_v2",
        fresh_keychain_redelivery_required=True,
        created_at=_NOW,
        signer_key_id="test-signer",
        signature_base64=_SIGNATURE,
    )
    capability = SecretCapabilityPolicyV1(
        schema_version="rsd.secret-capability-policy.v1",
        source_commit=_COMMIT,
        executor_identity_sha256=canonical_sha256(executor.executor),
        provider_identity_sha256=_hash("provider-material-attestation"),
        capability_fingerprint_sha256=_hash("secret-capability"),
        secret_handling_policy_sha256=canonical_sha256(handling),
        delivery_mode="local_executor_secret_lease_v1",
        allowed_purposes=(
            "commitment_hmac",
            "backup_encryption",
            "encryption_key",
            "auth_secret",
            "primary_valkey_password",
            "restore_valkey_password",
        ),
        created_at=_NOW,
        signer_key_id="test-signer",
        signature_base64=_SIGNATURE,
    )
    return capability, handling


def _materialization_intent(
    allocation: AllocationIntentV2,
    executor: ExecutorControlPolicyV1,
    receipt: AllocationEffectReceiptV2,
    attestation: ObservedAllocationAttestationV1,
) -> tuple[MaterializationIntentV1, SecretCapabilityPolicyV1, SecretHandlingPolicyV1]:
    capability, handling = _secret_policies(allocation, executor)
    topology = allocation.plan.topology
    requirements: dict[str, tuple[str, ...]] = {
        "primary_infisical": ("encryption_key", "auth_secret", "primary_valkey_password"),
        "primary_valkey": ("primary_valkey_password",),
        "restore_infisical": ("encryption_key", "auth_secret", "restore_valkey_password"),
        "restore_valkey": ("restore_valkey_password",),
    }

    def component(
        name: str, volume: str | None, namespace: str | None
    ) -> MaterializationComponentPlanV1:
        placement = getattr(topology, name)
        return MaterializationComponentPlanV1(
            component=cast(Any, name),
            compose_project=f"project-{name}",
            service_name=f"service-{name}",
            workload_name=f"workload-{name}",
            image=_image(
                "valkey" if name.endswith("valkey") else "infisical",
                "b" if name.endswith("valkey") else "a",
            ),
            config_sha256=_hash(f"{name.replace('_', '-')}-config"),
            network_name=placement.network_name,
            network_alias=placement.alias,
            static_ipv4=placement.static_ipv4,
            volume_name=volume,
            logical_namespace=namespace,
            required_purposes=cast(Any, requirements[name]),
        )

    plan = MaterializationPlanV1(
        primary_infisical=component("primary_infisical", None, None),
        primary_valkey=component("primary_valkey", "primary-volume", "primary-cache"),
        restore_infisical=component("restore_infisical", None, None),
        restore_valkey=component("restore_valkey", "restore-volume", "restore-cache"),
    )
    return (
        MaterializationIntentV1(
            schema_version="rsd.materialization-intent.v1",
            operation_kind="materialization_v1",
            operation_scope="materialize_and_start_runtime_v1",
            materialization_operation_id=_MATERIALIZATION_ID,
            allocation_operation_id=allocation.allocation_operation_id,
            source_commit=_COMMIT,
            allocation_intent_sha256=allocation_intent_sha256(allocation),
            allocation_effect_receipt_sha256=allocation_effect_receipt_sha256(receipt),
            observed_allocation_attestation_sha256=observed_allocation_attestation_sha256(
                attestation
            ),
            topology=topology,
            plan=plan,
            provider_references=allocation.provider_references,
            evidence=MaterializationEvidenceBindingsV1(
                allocation_intent_sha256=allocation_intent_sha256(allocation),
                allocation_effect_receipt_sha256=allocation_effect_receipt_sha256(receipt),
                observed_allocation_attestation_sha256=observed_allocation_attestation_sha256(
                    attestation
                ),
                executor_control_policy_sha256=canonical_sha256(executor),
                secret_capability_policy_sha256=canonical_sha256(capability),
                secret_handling_policy_sha256=canonical_sha256(handling),
                provider_material_attestation_sha256=_hash("provider-material-attestation"),
            ),
            retention_expires_at=_RETAINS,
            disposal_owner=_OWNER,
            approver_identity=_APPROVER,
            approval_reference_sha256=_hash("approval-reference"),
            journal_uuid=allocation.journal_uuid,
            replay_policy_sha256=allocation.replay_policy_sha256,
            created_at="2026-08-28T12:03:00Z",
            signer_key_id="test-signer",
            signature_base64=_SIGNATURE,
        ),
        capability,
        handling,
    )


def _materialization_context(
    intent: MaterializationIntentV1, allocation: ObservedAllocationAttestationV1
) -> MaterializationExecutionContext:
    return MaterializationExecutionContext(
        operation_kind="materialization_v1",
        operation_scope="materialize_and_start_runtime_v1",
        materialization_operation_id=intent.materialization_operation_id,
        intent=intent,
        allocation_attestation=allocation,
        allocation_attestation_sha256=observed_allocation_attestation_sha256(allocation),
        provider_expectations=(),
        executor_expectation=ExecutorControlExpectationV1(
            executor_id="local-executor",
            endpoint_sha256=_hash("executor-endpoint"),
            host_fingerprint_sha256=_hash("executor-host"),
            control_capability_fingerprint_sha256=_hash("executor-control"),
            engine_fingerprint_sha256=_hash("engine"),
        ),
        secret_material_expectation=SecretMaterialExpectationV1(
            provider_identity_sha256=_hash("provider-material-attestation"),
            capability_fingerprint_sha256=_hash("secret-capability"),
            secret_handling_policy_sha256=_hash("secret-handling"),
        ),
        secret_handling_policy_sha256=_hash("secret-handling"),
        materialization_intent_sha256=materialization_intent_sha256(intent),
        idempotency_key=_hash("materialization-idempotency"),
        provider_provenance_sha256=_hash("provider-provenance"),
        executor_provenance_sha256=_hash("executor-provenance"),
        secret_capability_provenance_sha256=_hash("secret-provenance"),
    )


def _allocation_context(intent: AllocationIntentV2) -> AllocationExecutionContext:
    return AllocationExecutionContext(
        operation_kind="allocation_v2",
        operation_scope="allocate_isolated_empty_resources_v2",
        allocation_operation_id=intent.allocation_operation_id,
        intent=intent,
        provider_expectations=(),
        executor_expectation=ExecutorControlExpectationV1(
            executor_id="local-executor",
            endpoint_sha256=_hash("executor-endpoint"),
            host_fingerprint_sha256=_hash("executor-host"),
            control_capability_fingerprint_sha256=_hash("executor-control"),
            engine_fingerprint_sha256=_hash("engine"),
        ),
        postgres_control_expectation=PostgreSQLControlExpectationV1(
            authority="postgresql://192.0.2.40:5432",
            maintenance_reference_sha256=_hash("postgres-maintenance"),
            capability_fingerprint_sha256=_hash("postgres-capability"),
        ),
        allocation_intent_sha256=allocation_intent_sha256(intent),
        idempotency_key=_hash("allocation-idempotency"),
        provider_provenance_sha256=_hash("provider-provenance"),
        executor_provenance_sha256=_hash("executor-provenance"),
        postgres_control_provenance_sha256=_hash("postgres-provenance"),
    )


def _materialization_receipt(
    context: MaterializationExecutionContext,
) -> MaterializationEffectReceiptV1:
    allocation = context.allocation_attestation.allocated_resources
    network_ids = {
        allocation.primary_network.name: allocation.primary_network.network_id,
        allocation.restore_network.name: allocation.restore_network.network_id,
    }

    def observation(name: str, marker: str) -> RuntimeContainerObservationV1:
        plan = getattr(context.intent.plan, name)
        placement = getattr(context.intent.topology, name)
        return RuntimeContainerObservationV1(
            component=cast(Any, name),
            container_id=_hash(f"container-{marker}"),
            workload_id=_hash(f"workload-{marker}"),
            image=plan.image,
            config_sha256=plan.config_sha256,
            attachments=(
                RuntimeNetworkAttachmentV1(
                    network_name=placement.network_name,
                    network_id=network_ids[placement.network_name],
                    alias=placement.alias,
                    static_ipv4=placement.static_ipv4,
                ),
            ),
            no_host_publication=NoHostPublicationEvidenceV1(
                network_mode="isolated_user_network_v1",
                host_network=False,
                publish_all_ports=False,
            ),
        )

    return MaterializationEffectReceiptV1(
        schema_version="rsd.materialization-effect-receipt.v1",
        operation_kind="materialization_v1",
        operation_scope="materialize_and_start_runtime_v1",
        status="materialized_and_started_runtime",
        materialization_operation_id=context.materialization_operation_id,
        materialization_intent_sha256=context.materialization_intent_sha256,
        allocation_operation_id=context.intent.allocation_operation_id,
        allocation_effect_receipt_sha256=context.intent.allocation_effect_receipt_sha256,
        observed_allocation_attestation_sha256=context.allocation_attestation_sha256,
        journal_uuid=context.intent.journal_uuid,
        idempotency_key=context.idempotency_key,
        executor_receipt_sha256=_hash("executor-receipt"),
        primary_infisical=observation("primary_infisical", "a"),
        primary_valkey=observation("primary_valkey", "b"),
        restore_infisical=observation("restore_infisical", "c"),
        restore_valkey=observation("restore_valkey", "d"),
        effect_receipt_sha256=_hash("materialization-effect"),
        completed_at="2026-08-28T12:04:00Z",
    )


def test_allocation_intent_excludes_observed_runtime_ids(tmp_path: Path) -> None:
    intent, _, _ = _allocation_bundle(tmp_path)
    rendered = str(intent.model_dump(mode="json"))

    assert intent.operation_scope == "allocate_isolated_empty_resources_v2"
    for field in ("container_id", "network_id", "volume_id", "database_oid", "workload_id"):
        assert field not in rendered


def test_allocation_receipt_is_the_first_model_that_reports_observed_ids(tmp_path: Path) -> None:
    intent, _, _ = _allocation_bundle(tmp_path)
    receipt = _allocation_receipt(intent)

    assert receipt.allocated_resources.primary_network.network_id == _hash("primary-network-id")
    assert receipt.allocated_resources.postgres.database_oid == 101
    assert receipt.allocated_resources.no_host_publication.container_ids == ()


def test_allocation_receipt_rejects_container_identity(tmp_path: Path) -> None:
    intent, _, _ = _allocation_bundle(tmp_path)
    data = _allocation_receipt(intent).model_dump(mode="python")
    resources = dict(data["allocated_resources"])
    resources["no_host_publication"] = {
        **resources["no_host_publication"],
        "container_ids": (_hash("forbidden-container"),),
    }
    data["allocated_resources"] = resources

    with pytest.raises(ValueError):
        AllocationEffectReceiptV2.model_validate(data)


def test_allocation_attestation_binds_exact_effect_and_topology(tmp_path: Path) -> None:
    intent, _, _ = _allocation_bundle(tmp_path)
    receipt = _allocation_receipt(intent)
    attestation = _allocation_attestation(intent, receipt)

    validate_observed_allocation_transition(intent, receipt, attestation)
    altered = attestation.model_copy(update={"allocation_topology_sha256": _hash("different")})
    with pytest.raises(ValueError, match="allocation observation transition"):
        validate_observed_allocation_transition(intent, receipt, altered)

    changed_postgres = attestation.allocated_resources.postgres.model_copy(
        update={"database_oid": 999}
    )
    with pytest.raises(ValueError, match="allocation observation transition"):
        validate_observed_allocation_transition(
            intent,
            receipt,
            attestation.model_copy(
                update={
                    "allocated_resources": attestation.allocated_resources.model_copy(
                        update={"postgres": changed_postgres}
                    )
                }
            ),
        )


def test_topology_rejects_cross_attachment_and_gateway_as_dynamic_address() -> None:
    topology = _topology()
    cross = topology.model_dump(mode="python")
    cross["primary_valkey"] = {
        **cross["primary_valkey"],
        "network_name": topology.restore_network.name,
    }
    with pytest.raises(ValueError, match="component attachment"):
        AllocationTopologyV2.model_validate(cross)

    gateway = topology.model_dump(mode="python")
    gateway["primary_infisical"] = {
        **gateway["primary_infisical"],
        "static_ipv4": topology.primary_network.gateway,
    }
    with pytest.raises(ValueError, match="static address"):
        AllocationTopologyV2.model_validate(gateway)


def test_materialization_requires_observed_allocation_hashes(tmp_path: Path) -> None:
    allocation, executor, _ = _allocation_bundle(tmp_path)
    receipt = _allocation_receipt(allocation)
    attestation = _allocation_attestation(allocation, receipt)
    materialization, _, _ = _materialization_intent(allocation, executor, receipt, attestation)

    assert materialization.allocation_intent_sha256 == allocation_intent_sha256(allocation)
    assert materialization.allocation_effect_receipt_sha256 == allocation_effect_receipt_sha256(
        receipt
    )
    assert (
        materialization.observed_allocation_attestation_sha256
        == observed_allocation_attestation_sha256(attestation)
    )
    assert materialization.operation_scope == "materialize_and_start_runtime_v1"


def test_materialization_chain_binds_provider_and_allocated_volumes(tmp_path: Path) -> None:
    allocation, executor, _ = _allocation_bundle(tmp_path)
    receipt = _allocation_receipt(allocation)
    attestation = _allocation_attestation(allocation, receipt)
    materialization, _, _ = _materialization_intent(allocation, executor, receipt, attestation)
    policy = ReplayAuthorityPolicyV1(
        schema_version="rsd.replay-authority-policy.v1",
        service="replay-service",
        account_prefix="replay-prefix",
    )
    chain_ready = materialization.model_copy(update={"replay_policy_sha256": policy.sha256()})
    stage = authorization._AllocationStageArtifacts(
        intent=allocation,
        receipt=receipt,
        attestation=attestation,
    )

    authorization._verify_materialization_intent_chain(
        allocation=stage,
        intent=chain_ready,
        replay_policy=policy,
        expected_disposal_owner=_OWNER,
        expected_approver_identity=_APPROVER,
        now=_TEST_CLOCK,
    )

    with pytest.raises(AuthorizationError, match="materialization_intent_binding"):
        authorization._verify_materialization_intent_chain(
            allocation=stage,
            intent=chain_ready.model_copy(
                update={
                    "provider_references": chain_ready.provider_references.model_copy(
                        update={"auth_secret": _reference("unexpected-auth")}
                    )
                }
            ),
            replay_policy=policy,
            expected_disposal_owner=_OWNER,
            expected_approver_identity=_APPROVER,
            now=_TEST_CLOCK,
        )

    wrong_volume = chain_ready.plan.primary_valkey.model_copy(update={"volume_name": "other"})
    with pytest.raises(AuthorizationError, match="materialization_intent_binding"):
        authorization._verify_materialization_intent_chain(
            allocation=stage,
            intent=chain_ready.model_copy(
                update={
                    "plan": chain_ready.plan.model_copy(update={"primary_valkey": wrong_volume})
                }
            ),
            replay_policy=policy,
            expected_disposal_owner=_OWNER,
            expected_approver_identity=_APPROVER,
            now=_TEST_CLOCK,
        )


def test_materialization_control_policy_pins_component_images_and_configs(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    allocation, executor, _ = _allocation_bundle(tmp_path)
    receipt = _allocation_receipt(allocation)
    attestation = _allocation_attestation(allocation, receipt)
    materialization, capability, handling = _materialization_intent(
        allocation, executor, receipt, attestation
    )
    for name in (
        "_verify_executor_control_policy_signature",
        "_verify_secret_capability_policy_signature",
        "_verify_secret_handling_policy_signature",
    ):
        monkeypatch.setattr(authorization, name, lambda *_args, **_kwargs: None)

    authorization._verify_materialization_control_policy_bindings(
        allocation_intent=allocation,
        intent=materialization,
        executor=executor,
        secret_capability=capability,
        secret_handling=handling,
        provider_material_attestation_sha256=_hash("provider-material-attestation"),
        signer=cast(Any, object()),
    )
    altered_primary = materialization.plan.primary_infisical.model_copy(
        update={"image": _image("other", "c")}
    )
    with pytest.raises(AuthorizationError, match="materialization_control_policy_binding"):
        authorization._verify_materialization_control_policy_bindings(
            allocation_intent=allocation,
            intent=materialization.model_copy(
                update={
                    "plan": materialization.plan.model_copy(
                        update={"primary_infisical": altered_primary}
                    )
                }
            ),
            executor=executor,
            secret_capability=capability,
            secret_handling=handling,
            provider_material_attestation_sha256=_hash("provider-material-attestation"),
            signer=cast(Any, object()),
        )


def test_materialization_receipt_rejects_cross_attachment_and_publication(tmp_path: Path) -> None:
    allocation, executor, _ = _allocation_bundle(tmp_path)
    allocation_receipt = _allocation_receipt(allocation)
    attestation = _allocation_attestation(allocation, allocation_receipt)
    materialization, _, _ = _materialization_intent(
        allocation, executor, allocation_receipt, attestation
    )
    context = _materialization_context(materialization, attestation)
    receipt = _materialization_receipt(context)

    assert authorization._validate_materialization_effect_receipt(context, receipt) == receipt
    cross = receipt.primary_valkey.model_copy(
        update={
            "attachments": (
                receipt.primary_valkey.attachments[0].model_copy(
                    update={"network_name": allocation.plan.topology.restore_network.name}
                ),
            )
        }
    )
    with pytest.raises(AuthorizationError, match="materialization_effect_receipt"):
        authorization._validate_materialization_effect_receipt(
            context, receipt.model_copy(update={"primary_valkey": cross})
        )

    publication = receipt.primary_infisical.model_copy(
        update={
            "no_host_publication": NoHostPublicationEvidenceV1.model_construct(
                network_mode="isolated_user_network_v1",
                host_network=False,
                publish_all_ports=False,
                port_bindings=("published",),
            )
        }
    )
    with pytest.raises(AuthorizationError, match="materialization_effect_receipt"):
        authorization._validate_materialization_effect_receipt(
            context, receipt.model_copy(update={"primary_infisical": publication})
        )


def test_secret_handling_policy_encodes_only_the_accepted_tcb(tmp_path: Path) -> None:
    intent, executor, _ = _allocation_bundle(tmp_path)
    capability, handling = _secret_policies(intent, executor)

    assert handling.infisical_target_processes == ("primary_infisical", "restore_infisical")
    assert handling.valkey_stdin_config_processes == ("primary_valkey", "restore_valkey")
    assert handling.restart_policy == "no"
    assert handling.fresh_keychain_redelivery_required is True
    assert capability.secret_handling_policy_sha256 == canonical_sha256(handling)
    with pytest.raises(ValueError):
        SecretHandlingPolicyV1.model_validate(
            {**handling.model_dump(mode="python"), "host_environment_allowed": True}
        )
    with pytest.raises(ValueError):
        SecretHandlingPolicyV1.model_validate(
            {
                **handling.model_dump(mode="python"),
                "infisical_target_processes": ("primary_infisical", "other-process"),
            }
        )


def test_constructed_tls_type_drift_is_rejected_before_a_mutation_boundary(tmp_path: Path) -> None:
    intent, _, _ = _allocation_bundle(tmp_path)
    raw = intent.model_construct(
        **{
            **intent.model_dump(mode="python"),
            "plan": intent.plan.model_construct(
                **{
                    **intent.plan.model_dump(mode="python"),
                    "transport": intent.plan.transport.model_construct(
                        **{
                            **intent.plan.transport.model_dump(mode="python"),
                            "profile": "tls_verified_v1",
                        }
                    ),
                }
            ),
        }
    )

    with pytest.raises(ValueError, match="model"):
        strict_canonical_allocation_intent(raw)


def test_replay_tombstones_are_stage_specific() -> None:
    policy = ReplayAuthorityPolicyV1(
        schema_version="rsd.replay-authority-policy.v1",
        service="replay-service",
        account_prefix="replay-prefix",
    )
    allocation = ReplayTombstoneV1(
        schema_version="rsd.replay-tombstone.v1",
        kind="allocation_operation",
        operation_kind="allocation_v2",
        service=policy.service,
        account="replay-prefix.a.claim",
        journal_genesis_id=_JOURNAL_ID,
        operation_id=_ALLOCATION_ID,
        allocation_intent_sha256=_hash("allocation-intent"),
        provider_provenance_sha256=_hash("provider-provenance"),
        idempotency_key=_hash("allocation-idempotency"),
    )
    assert allocation.kind == "allocation_operation"
    with pytest.raises(ValueError, match="replay tombstone"):
        ReplayTombstoneV1(
            schema_version="rsd.replay-tombstone.v1",
            kind="materialization_operation",
            operation_kind="materialization_v1",
            service=policy.service,
            account="replay-prefix.m.claim",
            journal_genesis_id=_JOURNAL_ID,
            operation_id=_MATERIALIZATION_ID,
            allocation_intent_sha256=_hash("allocation-intent"),
            materialization_intent_sha256=_hash("materialization-intent"),
            allocation_effect_receipt_sha256=_hash("allocation-receipt"),
            observed_allocation_attestation_sha256=_hash("allocation-attestation"),
            proposal_sha256=_hash("forbidden-proposal"),
            provider_provenance_sha256=_hash("provider-provenance"),
            idempotency_key=_hash("materialization-idempotency"),
        )


def test_mutation_boundaries_have_no_caller_clock_or_generic_callback() -> None:
    allocation = inspect.signature(authorize_allocation_and_execute).parameters
    materialization = inspect.signature(authorize_materialization_and_execute).parameters

    for parameters in (allocation, materialization):
        assert "now" not in parameters
        assert "clock" not in parameters
        assert "effect" not in parameters
        assert "executor" in parameters
    assert "secret_material" in materialization


def test_tls_type_drift_reaches_no_artifact_root_or_adapter(tmp_path: Path) -> None:
    intent, _, _ = _allocation_bundle(tmp_path)
    raw = intent.model_construct(
        **{
            **intent.model_dump(mode="python"),
            "plan": intent.plan.model_construct(
                **{
                    **intent.plan.model_dump(mode="python"),
                    "transport": intent.plan.transport.model_construct(
                        **{
                            **intent.plan.transport.model_dump(mode="python"),
                            "profile": "tls_verified_v1",
                        }
                    ),
                }
            ),
        }
    )
    root = tmp_path / "absent-artifacts"
    signer = TrustedEd25519SignerV1(
        key_id="test-signer",
        public_key_base64=base64.b64encode(b"k" * 32).decode("ascii"),
        public_key_fingerprint_sha256=hashlib.sha256(b"k" * 32).hexdigest(),
    )

    with pytest.raises(AuthorizationError):
        authorize_allocation_and_execute(
            AuthorizationPaths(root=root),
            signer=signer,
            allocation_intent=raw,
            provider=cast(Any, object()),
            expected_disposal_owner=_OWNER,
            expected_approver_identity=_APPROVER,
            journal=cast(Any, object()),
            executor=cast(Any, object()),
            executor_control=cast(Any, object()),
            postgres_control=cast(Any, object()),
            replay_authority=cast(Any, object()),
            replay_policy=ReplayAuthorityPolicyV1(
                schema_version="rsd.replay-authority-policy.v1",
                service="replay-service",
                account_prefix="replay-prefix",
            ),
        )
    assert not root.exists()


def test_cli_authorize_remains_read_only(
    tmp_path: Path, capsys: pytest.CaptureFixture[str]
) -> None:
    root = tmp_path / "absent"
    assert authorization.main(["authorize", "--root", str(root)]) == 2
    assert "injected_trust_required" in capsys.readouterr().out
    assert not root.exists()


def test_removed_initial_v1_names_are_not_reexported() -> None:
    import omninode_rsd.lifecycle.infisical_disposable as disposable

    assert not hasattr(disposable, "InitialProvisioningIntentV1")
    assert not hasattr(disposable, "InitialProvisioningEffectReceiptV1")
    assert not hasattr(disposable, "ObservedCandidateAttestationV1")


def test_allocation_context_is_value_free_and_non_bearer(tmp_path: Path) -> None:
    intent, _, _ = _allocation_bundle(tmp_path)
    context = AllocationExecutionContext(
        operation_kind="allocation_v2",
        operation_scope="allocate_isolated_empty_resources_v2",
        allocation_operation_id=intent.allocation_operation_id,
        intent=intent,
        provider_expectations=(
            ProviderExpectationV1(
                provider="metadata-provider",
                service="service-auth",
                account="account-auth",
                version=1,
                reference_sha256=_hash("reference"),
                fingerprint_sha256=_hash("fingerprint"),
            ),
        ),
        executor_expectation=ExecutorControlExpectationV1(
            executor_id="local-executor",
            endpoint_sha256=_hash("executor-endpoint"),
            host_fingerprint_sha256=_hash("executor-host"),
            control_capability_fingerprint_sha256=_hash("executor-control"),
            engine_fingerprint_sha256=_hash("engine"),
        ),
        postgres_control_expectation=PostgreSQLControlExpectationV1(
            authority="postgresql://192.0.2.40:5432",
            maintenance_reference_sha256=_hash("postgres-maintenance"),
            capability_fingerprint_sha256=_hash("postgres-capability"),
        ),
        allocation_intent_sha256=allocation_intent_sha256(intent),
        idempotency_key=_hash("allocation-idempotency"),
        provider_provenance_sha256=_hash("provider-provenance"),
        executor_provenance_sha256=_hash("executor-provenance"),
        postgres_control_provenance_sha256=_hash("postgres-provenance"),
    )

    fields = set(context.__dataclass_fields__)
    assert {"artifact_path", "journal", "nonce", "secret", "environment"}.isdisjoint(fields)


def test_allocation_journal_is_explicit_and_replay_policy_is_durable_first(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    monkeypatch.setattr(authorization, "_system_utc_clock", lambda: _TEST_CLOCK)
    signer, _, intent, executor, postgres, journal, policy, artifact = _signed_allocation_bundle(
        tmp_path
    )
    root = tmp_path / "artifacts"
    root.mkdir(mode=0o700)
    paths = AuthorizationPaths(root=root)
    authority = _AtomicReplayAuthority(root=root)

    assert journal.migration_status() is AllocationJournalStatus.ABSENT
    assert not journal._path.exists()
    receipt = provision_allocation_journal(
        paths,
        signer=signer,
        expected_disposal_owner=_OWNER,
        expected_approver_identity=_APPROVER,
        journal=journal,
        intent=intent,
        executor_control_policy=executor,
        postgres_control_policy=postgres,
        replay_authority=authority,
        replay_policy=policy,
        replay_policy_artifact=artifact,
    )

    assert receipt.status == "provisioned"
    assert journal.migration_status() is AllocationJournalStatus.CURRENT
    assert authority.calls == 1
    assert (root / paths.replay_policy_name()).is_file()
    assert (root / paths.executor_control_policy_name()).is_file()
    assert (root / paths.postgres_control_policy_name()).is_file()
    assert (root / paths.allocation_intent_name()).is_file()

    with pytest.raises(AuthorizationError, match="allocation_journal_replayed"):
        provision_allocation_journal(
            paths,
            signer=signer,
            expected_disposal_owner=_OWNER,
            expected_approver_identity=_APPROVER,
            journal=journal,
            intent=intent,
            executor_control_policy=executor,
            postgres_control_policy=postgres,
            replay_authority=authority,
            replay_policy=policy,
            replay_policy_artifact=artifact,
        )
    assert authority.calls == 1


def test_allocation_genesis_crash_leaves_a_terminal_pending_state(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    monkeypatch.setattr(authorization, "_system_utc_clock", lambda: _TEST_CLOCK)
    signer, _, intent, executor, postgres, journal, policy, artifact = _signed_allocation_bundle(
        tmp_path
    )
    root = tmp_path / "artifacts"
    root.mkdir(mode=0o700)
    paths = AuthorizationPaths(root=root)
    authority = _AtomicReplayAuthority(root=root)

    def fail_after_claim(_: object) -> None:
        raise AuthorizationError("test_crash")

    monkeypatch.setattr(journal, "_complete_verified_intent", fail_after_claim)
    with pytest.raises(AuthorizationError, match="test_crash"):
        provision_allocation_journal(
            paths,
            signer=signer,
            expected_disposal_owner=_OWNER,
            expected_approver_identity=_APPROVER,
            journal=journal,
            intent=intent,
            executor_control_policy=executor,
            postgres_control_policy=postgres,
            replay_authority=authority,
            replay_policy=policy,
            replay_policy_artifact=artifact,
        )

    assert authority.calls == 1
    assert journal.migration_status() is AllocationJournalStatus.PROVISIONING_INCOMPLETE
    assert not journal._path.exists()
    with pytest.raises(AuthorizationError, match="allocation_journal_replayed"):
        provision_allocation_journal(
            paths,
            signer=signer,
            expected_disposal_owner=_OWNER,
            expected_approver_identity=_APPROVER,
            journal=journal,
            intent=intent,
            executor_control_policy=executor,
            postgres_control_policy=postgres,
            replay_authority=authority,
            replay_policy=policy,
            replay_policy_artifact=artifact,
        )
    assert authority.calls == 1


def test_external_allocation_genesis_tombstone_blocks_a_second_local_journal(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    monkeypatch.setattr(authorization, "_system_utc_clock", lambda: _TEST_CLOCK)
    first = tmp_path / "first"
    second = tmp_path / "second"
    first.mkdir(mode=0o700)
    second.mkdir(mode=0o700)
    signer, _, intent, executor, postgres, journal, policy, artifact = _signed_allocation_bundle(
        first
    )
    first_root = first / "artifacts"
    first_root.mkdir(mode=0o700)
    authority = _AtomicReplayAuthority(root=first_root)
    provision_allocation_journal(
        AuthorizationPaths(root=first_root),
        signer=signer,
        expected_disposal_owner=_OWNER,
        expected_approver_identity=_APPROVER,
        journal=journal,
        intent=intent,
        executor_control_policy=executor,
        postgres_control_policy=postgres,
        replay_authority=authority,
        replay_policy=policy,
        replay_policy_artifact=artifact,
    )

    (
        second_signer,
        _,
        second_intent,
        second_executor,
        second_postgres,
        second_journal,
        _,
        second_artifact,
    ) = _signed_allocation_bundle(second)
    second_root = second / "artifacts"
    second_root.mkdir(mode=0o700)
    with pytest.raises(AuthorizationError, match="allocation_journal_replayed"):
        provision_allocation_journal(
            AuthorizationPaths(root=second_root),
            signer=second_signer,
            expected_disposal_owner=_OWNER,
            expected_approver_identity=_APPROVER,
            journal=second_journal,
            intent=second_intent,
            executor_control_policy=second_executor,
            postgres_control_policy=second_postgres,
            replay_authority=authority,
            replay_policy=policy,
            replay_policy_artifact=second_artifact,
        )
    assert authority.calls == 2
    assert second_journal.migration_status() is AllocationJournalStatus.PROVISIONING_INCOMPLETE
    assert not second_journal._path.exists()


def test_materialization_journal_requires_committed_allocation_and_never_replays(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    monkeypatch.setattr(authorization, "_system_utc_clock", lambda: _TEST_CLOCK)
    signer, _, intent, executor, postgres, journal, policy, artifact = _signed_allocation_bundle(
        tmp_path
    )
    root = tmp_path / "artifacts"
    root.mkdir(mode=0o700)
    provision_allocation_journal(
        AuthorizationPaths(root=root),
        signer=signer,
        expected_disposal_owner=_OWNER,
        expected_approver_identity=_APPROVER,
        journal=journal,
        intent=intent,
        executor_control_policy=executor,
        postgres_control_policy=postgres,
        replay_authority=_AtomicReplayAuthority(root=root),
        replay_policy=policy,
        replay_policy_artifact=artifact,
    )
    context = _allocation_context(intent)
    verified_intent = authorization._VerifiedAllocationIntent(
        intent=intent,
        intent_sha256=allocation_intent_sha256(intent),
        capability=authorization._ALLOCATION_INTENT_CAPABILITY,
    )
    allocation_verified = authorization._VerifiedAllocation(
        context=context,
        nonce="allocation-nonce",
        authorized_at=_NOW,
        capability=authorization._ALLOCATION_VERIFIED_CAPABILITY,
    )
    allocation_receipt = _allocation_receipt(intent).model_copy(
        update={"idempotency_key": context.idempotency_key}
    )
    attestation = _allocation_attestation(intent, allocation_receipt)
    materialization, _, _ = _materialization_intent(
        intent, executor, allocation_receipt, attestation
    )
    materialization_context = _materialization_context(materialization, attestation)
    materialization_verified = authorization._VerifiedMaterialization(
        context=materialization_context,
        nonce="materialization-nonce",
        authorized_at=_NOW,
        capability=authorization._MATERIALIZATION_VERIFIED_CAPABILITY,
    )

    with pytest.raises(AuthorizationError, match="materialization_allocation_predecessor"):
        journal._claim_materialization_verified(materialization_verified)

    journal._claim_verified(allocation_verified)
    journal._begin_effect(allocation_verified)
    journal._commit_effect(allocation_verified, allocation_receipt)
    journal.assert_committed_allocation_stage(verified_intent, allocation_receipt, attestation)
    journal._claim_materialization_verified(materialization_verified)
    journal._begin_materialization_effect(materialization_verified)
    materialization_receipt = _materialization_receipt(materialization_context)
    journal._commit_materialization_effect(materialization_verified, materialization_receipt)

    assert (
        journal.materialization_operation_state(materialization.materialization_operation_id)
        is MaterializationOperationState.MATERIALIZED
    )
    journal.assert_committed_materialization_stage(materialization, materialization_receipt)
    with pytest.raises(AuthorizationError, match="materialization_operation_replayed"):
        journal._claim_materialization_verified(materialization_verified)


def test_artifact_root_lease_rejects_relaxed_mode_symlink_and_recursion(tmp_path: Path) -> None:
    root = tmp_path / "artifacts"
    root.mkdir(mode=0o700)
    with (
        ArtifactRootLease(root),
        pytest.raises(AuthorizationError, match="artifact_lock_reentrant"),
        ArtifactRootLease(root),
    ):
        pass

    os.chmod(root, 0o755)
    with (
        pytest.raises(AuthorizationError, match=r"artifact_(root|lock_root)"),
        ArtifactRootLease(root),
    ):
        pass

    os.chmod(root, 0o700)
    link = tmp_path / "artifact-link"
    link.symlink_to(root, target_is_directory=True)
    with (
        pytest.raises(AuthorizationError, match=r"artifact_(root|lock_root)"),
        ArtifactRootLease(link),
    ):
        pass


def test_provider_and_effect_error_text_is_not_exposed_by_safe_boundary() -> None:
    marker = "value-that-must-not-escape"
    result = authorization._safe_call(lambda: (_ for _ in ()).throw(RuntimeError(marker)))

    assert result is authorization._SAFE_CALL_FAILURE
    assert marker not in repr(result)
