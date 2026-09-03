"""Adversarial tests for the public V2 allocation/materialization contracts.

Every value in this module is a documentation-only fixture.  The tests invoke
models and injected protocol boundaries only: no Keychain, engine, database,
network, process, or provider is contacted.
"""

from __future__ import annotations

import base64
import hashlib
import inspect
import json
import multiprocessing
import os
import shutil
import sqlite3
import uuid
from concurrent.futures import ThreadPoolExecutor
from contextlib import suppress
from datetime import UTC, datetime
from pathlib import Path
from typing import Any, cast

import pytest
import yaml
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey
from pydantic import ValidationError

import omninode_rsd.lifecycle.authorization as authorization
from omninode_rsd.lifecycle.authorization import (
    AllocationExecutionContext,
    AllocationJournalGenesisReconciliationReceiptV1,
    AllocationJournalStatus,
    AllocationOperationState,
    ArtifactRootLease,
    AuthorizationError,
    AuthorizationPaths,
    DetachedAuthorizationSignatureV1,
    ExecutorControlExpectationV1,
    MacOSKeychainReplayAuthority,
    MaterializationExecutionContext,
    MaterializationOperationState,
    PostgreSQLControlExpectationV1,
    PostgreSQLLoginTransitionExpectationV1,
    ProviderExpectationV1,
    ProviderProvenance,
    ReplayAuthorityClaimResult,
    ReplayAuthorityPolicyV1,
    ReplayTombstoneV1,
    SecretMaterialExpectationV1,
    SQLiteAllocationJournal,
    TrustedEd25519SignerV1,
    authorize_allocation_and_execute,
    authorize_materialization_and_execute,
    provision_allocation_journal,
    reconcile_allocation_journal_genesis,
)
from omninode_rsd.lifecycle.infisical_disposable import (
    AllocatedNetworkObservationV1,
    AllocatedPostgreSQLObservationV1,
    AllocatedResourceSetV2,
    AllocatedVolumeObservationV1,
    AllocationEffectReceiptV2,
    AllocationEvidenceBindingsV1,
    AllocationExecutorReceiptV1,
    AllocationIntentV2,
    AllocationPlanV2,
    AllocationPostgreSQLPlanV2,
    AllocationTopologyV2,
    AllocationVolumePlanV1,
    ComponentPlacementV1,
    ContainerAttachReceiptV1,
    ContainerAttachRequestV1,
    ContainerAttachTerminalAckV1,
    ContainerBootstrapAttachProtocolV1,
    ContainerBootstrapInspectionV1,
    ContainerBootstrapTemplatesV1,
    ContainerBootstrapTemplateV1,
    ContainerBootstrapWrapperArtifactV1,
    ContainerBootstrapWrapperManifestV1,
    ContainerSecretSinkV1,
    ContainerTargetDeliveryV1,
    ContainerWrapperPid1PolicyV1,
    ContainerWrapperRuntimeRequirementsV1,
    DetachedSignatureV1,
    DisposableTransportProfile,
    DockerEngineControlPolicyV1,
    DockerEngineFilteredProjectionV1,
    DockerImageLocalEvidenceV1,
    DockerImagePolicyV1,
    DockerNamedVolumeMountV1,
    DockerUnixSocketPolicyV1,
    EngineIdentityObservationV1,
    ExecutorContainerInspectionV1,
    ExecutorControlPolicyV1,
    ExecutorIdentityV1,
    ExecutorPlacementV1,
    ImageConfigBindingV1,
    ImageReferenceV1,
    IsolatedNetworkPlanV1,
    MaterializationComponentPlanV1,
    MaterializationEffectReceiptV1,
    MaterializationEvidenceBindingsV1,
    MaterializationExecutorReceiptV1,
    MaterializationIntentV1,
    MaterializationPlanV1,
    NetworkOptionV1,
    NoHostPublicationEvidenceV1,
    NoHostPublicationGroundworkV1,
    ObservedAllocationAttestationV1,
    ObservedRestoreDatabaseAttestationV1,
    OciImageResolutionAttestationV1,
    PostgreSQLAllocationRoleStateV1,
    PostgreSQLConnectionUriGrammarV1,
    PostgreSQLControlPolicyV1,
    PostgreSQLGrantObservationV1,
    PostgreSQLGrantPlanV1,
    PostgreSQLLoginTransitionIntentsV1,
    PostgreSQLLoginTransitionIntentV1,
    PostgreSQLLoginTransitionReceiptsV1,
    PostgreSQLLoginTransitionReceiptV1,
    PostgreSQLPreparedControlPolicyV2,
    PostgreSQLPreparedOperationV1,
    PostgreSQLRoleObservationV1,
    PostgreSQLRuntimeDatabaseIdentitiesV1,
    PostgreSQLRuntimeDatabaseIdentityV1,
    PostgreSQLScramVerifierInstallsV1,
    PostgreSQLScramVerifierInstallV1,
    ProviderMaterialFingerprintBindingV1,
    ProviderReferencesV2,
    ProviderReferenceV1,
    RuntimeContainerObservationV1,
    RuntimeNetworkAttachmentV1,
    SecretCapabilityPolicyV1,
    SecretDeliveryReceiptV1,
    SecretDeliveryRequestV1,
    SecretDeliverySinkV1,
    SecretDeliverySlotReceiptV1,
    SecretDeliverySlotV1,
    SecretHandlingPolicyV1,
    SSHConnectionPolicyV1,
    TargetDeliveryFieldV1,
    TargetDeliveryMapV1,
    TargetDeliveryValueKindV1,
    TransportContractV1,
    ValkeyConnectionUriGrammarV1,
    allocation_effect_receipt_sha256,
    allocation_intent_sha256,
    canonical_sha256,
    container_attach_ack_sha256,
    container_attach_chunk_descriptors_sha256,
    container_attach_receipt_sha256,
    container_attach_request_sha256,
    container_bootstrap_attach_protocol_sha256,
    container_bootstrap_wrapper_artifact_sha256,
    container_bootstrap_wrapper_manifest_sha256,
    container_create_template_sha256,
    docker_engine_fingerprint_sha256,
    docker_image_policy_binding,
    docker_unix_socket_identity_sha256,
    docker_volume_instance_fingerprint_sha256,
    materialization_intent_sha256,
    observed_allocation_attestation_sha256,
    observed_restore_database_attestation_sha256,
    oci_image_resolution_attestation_message,
    postgresql_connection_uri_rendered_byte_count,
    runtime_connection_uri_grammar_sha256,
    strict_canonical_allocation_intent,
    target_delivery_map_sha256,
    validate_observed_allocation_transition,
    valkey_connection_uri_rendered_byte_count,
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
_POSTGRES_SCHEME = "postgresql:" + "//"
_REDIS_SCHEME = "redis:" + "//"
_TEST_CLOCK = datetime(2026, 8, 28, 12, 5, tzinfo=UTC)
_EXECUTOR_ATTESTATION_PRIVATE_KEY = Ed25519PrivateKey.from_private_bytes(b"e" * 32)
_EXECUTOR_ATTESTATION_PUBLIC_BYTES = (
    _EXECUTOR_ATTESTATION_PRIVATE_KEY.public_key().public_bytes_raw()
)
_EXECUTOR_ATTESTATION_PUBLIC_KEY = base64.b64encode(_EXECUTOR_ATTESTATION_PUBLIC_BYTES).decode(
    "ascii"
)
_POLICY_SIGNER_PRIVATE_KEY = Ed25519PrivateKey.from_private_bytes(b"p" * 32)


class _TLSProfileAlias(str):
    """A hostile scalar subclass used only at the model-construction boundary."""


def _hash(label: str) -> str:
    return hashlib.sha256(label.encode("ascii")).hexdigest()


def _postgres_uri_grammar(
    *, authority: str, rendered_uri_byte_count: int
) -> PostgreSQLConnectionUriGrammarV1:
    return PostgreSQLConnectionUriGrammarV1(
        schema_version="rsd.postgresql-connection-uri-grammar.v1",
        database_identity="primary_database",
        authority=authority,
        database_name="runtime-db",
        application_role="application-role",
        application_password_reference_sha256=_hash("postgres-application-password"),
        prepared_operation_id=_MATERIALIZATION_ID,
        target_process="primary_infisical",
        environment_variable="DB_CONNECTION_URI",
        uri_grammar="postgresql_user_password_authority_database_v1",
        application_password_format="postgres_application_password_base64url_32_v1",
        application_password_encoded_byte_count=43,
        rendered_uri_byte_count=rendered_uri_byte_count,
        return_uri_allowed=False,
        persistent_storage_allowed=False,
        logging_allowed=False,
        public_artifact_allowed=False,
    )


def _valkey_uri_grammar(
    *, authority: str, rendered_uri_byte_count: int
) -> ValkeyConnectionUriGrammarV1:
    return ValkeyConnectionUriGrammarV1(
        schema_version="rsd.valkey-connection-uri-grammar.v1",
        cache_identity="primary_valkey",
        authority=authority,
        database_index=0,
        password_reference_sha256=_hash("primary-valkey-password"),
        target_process="primary_infisical",
        environment_variable="REDIS_URL",
        uri_grammar="redis_password_authority_database_v1",
        password_format="valkey_password_base64url_32_v1",
        password_encoded_byte_count=43,
        rendered_uri_byte_count=rendered_uri_byte_count,
        return_uri_allowed=False,
        persistent_storage_allowed=False,
        logging_allowed=False,
        public_artifact_allowed=False,
    )


@pytest.mark.parametrize(
    ("postgres_authority", "valkey_authority"),
    (
        (
            _POSTGRES_SCHEME + "192.0.2.40:5432",
            _REDIS_SCHEME + "198.51.100.3:6379",
        ),
        (
            _POSTGRES_SCHEME + "[2001:db8::40]:5432",
            _REDIS_SCHEME + "[2001:db8::3]:6379",
        ),
    ),
)
def test_uri_grammar_byte_counts_preserve_canonical_ipv4_and_ipv6_authorities(
    postgres_authority: str, valkey_authority: str
) -> None:
    """Rendered byte commitments retain IPv6 brackets and all URI delimiters."""

    application_role = "application-role"
    database_name = "runtime-db"
    postgres_expected = len(
        (
            _POSTGRES_SCHEME
            + application_role
            + ":"
            + ("A" * 43)
            + "@"
            + postgres_authority.removeprefix(_POSTGRES_SCHEME)
            + "/"
            + database_name
        ).encode("utf-8")
    )
    valkey_expected = len(
        (
            _REDIS_SCHEME
            + ":"
            + ("A" * 43)
            + "@"
            + valkey_authority.removeprefix(_REDIS_SCHEME)
            + "/0"
        ).encode("utf-8")
    )

    assert (
        postgresql_connection_uri_rendered_byte_count(
            authority=postgres_authority,
            application_role=application_role,
            database_name=database_name,
        )
        == postgres_expected
    )
    assert (
        valkey_connection_uri_rendered_byte_count(authority=valkey_authority, database_index=0)
        == valkey_expected
    )
    assert (
        _postgres_uri_grammar(
            authority=postgres_authority, rendered_uri_byte_count=postgres_expected
        ).rendered_uri_byte_count
        == postgres_expected
    )
    assert (
        _valkey_uri_grammar(
            authority=valkey_authority, rendered_uri_byte_count=valkey_expected
        ).rendered_uri_byte_count
        == valkey_expected
    )


def test_uri_grammar_rejects_dns_and_enforces_the_signed_count_cap() -> None:
    """This profile is IP-literal-only; DNS and count overflow stay fail-closed."""

    postgres_dns = _POSTGRES_SCHEME + "database.example.test:5432"
    valkey_dns = _REDIS_SCHEME + "cache.example.test:6379"
    with pytest.raises(ValueError, match="IP literal"):
        postgresql_connection_uri_rendered_byte_count(
            authority=postgres_dns,
            application_role="application-role",
            database_name="runtime-db",
        )
    with pytest.raises(ValueError, match="IP literal"):
        valkey_connection_uri_rendered_byte_count(authority=valkey_dns, database_index=0)
    with pytest.raises(ValueError, match="IP literal"):
        _postgres_uri_grammar(authority=postgres_dns, rendered_uri_byte_count=1)
    with pytest.raises(ValueError, match="IP literal"):
        _valkey_uri_grammar(authority=valkey_dns, rendered_uri_byte_count=1)

    postgres_authority = _POSTGRES_SCHEME + "[2001:db8::40]:5432"
    valkey_authority = _REDIS_SCHEME + "[2001:db8::3]:6379"
    with pytest.raises(ValidationError) as postgres_error:
        _postgres_uri_grammar(authority=postgres_authority, rendered_uri_byte_count=1025)
    with pytest.raises(ValidationError) as valkey_error:
        _valkey_uri_grammar(authority=valkey_authority, rendered_uri_byte_count=1025)
    assert any(
        error["loc"] == ("rendered_uri_byte_count",) and error["type"] == "less_than_equal"
        for error in postgres_error.value.errors()
    )
    assert any(
        error["loc"] == ("rendered_uri_byte_count",) and error["type"] == "less_than_equal"
        for error in valkey_error.value.errors()
    )


def test_executor_ssh_policy_rejects_malformed_host_key_pin() -> None:
    """A non-digest host pin cannot become a trusted remote authority."""

    with pytest.raises(ValueError, match="remote executor policy"):
        SSHConnectionPolicyV1(
            host_key_fingerprints_sha256=("not-a-sha256",),
            dedicated_user="executor-user",
            client_key_fingerprint_sha256=_hash("executor-client-key"),
            force_command="omninode_rsd_executor_v1",
            force_command_sha256=_hash("omninode_rsd_executor_v1"),
            batch_mode=True,
            strict_host_key_checking=True,
            disable_forwarding=True,
            permit_tty=False,
            forward_agent=False,
            forward_x11=False,
            permit_port_forwarding=False,
            permit_streamlocal_forwarding=False,
            control_master=False,
        )


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


def _references() -> ProviderReferencesV2:
    return ProviderReferencesV2(
        commitment_hmac=_reference("commitment"),
        backup_encryption=_reference("backup"),
        encryption_key=_reference("encryption"),
        auth_secret=_reference("auth"),
        primary_valkey_password=_reference("primary-cache"),
        restore_valkey_password=_reference("restore-cache"),
        postgres_application_password=_reference("postgres-application"),
    )


def _image(name: str, character: str) -> ImageReferenceV1:
    return ImageReferenceV1(reference=f"registry.example.test/{name}@sha256:{character * 64}")


def _image_policy(name: str, character: str, *, config_sha256: str) -> DockerImagePolicyV1:
    image = _image(name, character)
    unsigned_attestation = OciImageResolutionAttestationV1(
        schema_version="rsd.oci-image-resolution-attestation.v1",
        source_commit=_COMMIT,
        image=image,
        registry_index_digest_sha256=character * 64,
        linux_amd64_manifest_digest_sha256=_hash(f"{name}-linux-amd64-manifest"),
        config_digest_sha256=config_sha256,
        platform="linux/amd64",
        resolved_at=_NOW,
        signer_key_id="test-signer",
        signature_base64=_SIGNATURE,
    )
    attestation = unsigned_attestation.model_copy(
        update={
            "signature_base64": base64.b64encode(
                _POLICY_SIGNER_PRIVATE_KEY.sign(
                    oci_image_resolution_attestation_message(unsigned_attestation)
                )
            ).decode("ascii")
        }
    )
    return DockerImagePolicyV1(
        image=image,
        registry_index_digest_sha256=character * 64,
        linux_amd64_manifest_digest_sha256=_hash(f"{name}-linux-amd64-manifest"),
        config_digest_sha256=config_sha256,
        resolution_attestation=attestation,
    )


def _engine_projection() -> DockerEngineFilteredProjectionV1:
    return DockerEngineFilteredProjectionV1(
        daemon_id="daemon-test-1",
        api_version="1.47",
        operating_system="linux",
        architecture="amd64",
    )


def _engine_observation() -> EngineIdentityObservationV1:
    projection = _engine_projection()
    return EngineIdentityObservationV1(
        projection=projection,
        engine_fingerprint_sha256=docker_engine_fingerprint_sha256(projection),
    )


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
            placement="host_control_plane_v1",
        ),
    )


def _executor_policy(topology: AllocationTopologyV2) -> ExecutorControlPolicyV1:
    return ExecutorControlPolicyV1(
        schema_version="rsd.executor-control-policy.v1",
        source_commit=_COMMIT,
        executor=ExecutorIdentityV1(
            executor_id=topology.executor.executor_id,
            platform="remote_linux_systemd_v1",
            authenticated_transport="ssh_forced_command_v1",
            endpoint_sha256=_hash("executor-endpoint"),
            host_fingerprint_sha256=_hash("executor-host"),
            control_capability_fingerprint_sha256=_hash("executor-control"),
            attestation_key_id="executor-attestation",
            attestation_public_key_base64=_EXECUTOR_ATTESTATION_PUBLIC_KEY,
            attestation_public_key_fingerprint_sha256=hashlib.sha256(
                _EXECUTOR_ATTESTATION_PUBLIC_BYTES
            ).hexdigest(),
            credential_custody="tpm2_systemd_encrypted_credential_v1",
            monotonic_revision=1,
            expires_at=_RETAINS,
        ),
        installation_policy_sha256=_hash("executor-installation-policy"),
        engine_fingerprint_sha256=docker_engine_fingerprint_sha256(_engine_projection()),
        allowed_operations=(
            "allocate_isolated_empty_resources_v2",
            "materialize_and_start_runtime_v1",
            "start_runtime_v2",
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
        application_role="application-role",
        role_names=("owner-role", "application-role"),
        allocation_role_states=(
            PostgreSQLAllocationRoleStateV1(
                role="owner-role",
                role_kind="database_owner",
                can_login=False,
                password_absent=True,
            ),
            PostgreSQLAllocationRoleStateV1(
                role="application-role",
                role_kind="application",
                can_login=False,
                password_absent=True,
            ),
        ),
        grants=(
            PostgreSQLGrantPlanV1(
                role="owner-role",
                grantee="application-role",
                privilege="SELECT",
                schema_name="acceptance-schema",
            ),
        ),
        created_at=_NOW,
        signer_key_id="test-signer",
        signature_base64=_SIGNATURE,
    )


def _docker_policy(executor: ExecutorControlPolicyV1) -> DockerEngineControlPolicyV1:
    projection = _engine_projection()
    socket_path = "/run/omninode-rsd-engine.sock"
    socket_path_sha256 = hashlib.sha256(socket_path.encode()).hexdigest()
    return DockerEngineControlPolicyV1(
        schema_version="rsd.docker-engine-control-policy.v1",
        source_commit=_COMMIT,
        executor_identity_sha256=canonical_sha256(executor.executor),
        unix_socket=DockerUnixSocketPolicyV1(
            socket_path=socket_path,
            socket_path_sha256=socket_path_sha256,
            socket_identity_sha256=docker_unix_socket_identity_sha256(
                socket_path_sha256=socket_path_sha256,
                device=101,
                inode=202,
                owner_uid=1,
                group_gid=2,
                mode=0o600,
            ),
            device=101,
            inode=202,
            owner_uid=1,
            group_gid=2,
            mode=0o600,
            endpoint_scheme="unix",
            symlink_allowed=False,
            replacement_allowed=False,
        ),
        api_version=projection.api_version,
        engine_projection=projection,
        engine_fingerprint_sha256=docker_engine_fingerprint_sha256(projection),
        allowed_operations=(
            "engine_ping",
            "engine_version",
            "engine_info",
            "image_inspect",
            "image_manifest_inspect",
            "network_create",
            "network_inspect",
            "volume_create",
            "volume_inspect",
            "container_inspect",
            "exec_create",
            "exec_inspect",
            "exec_start",
        ),
        max_request_bytes=4096,
        max_response_bytes=8192,
        max_hijack_bytes=8192,
        max_hijack_frames=128,
        request_timeout_seconds=10,
        hijack_timeout_seconds=10,
        hijack_absolute_timeout_seconds=20,
        created_at=_NOW,
        signer_key_id="test-signer",
        signature_base64=_SIGNATURE,
    )


def _postgres_prepared_policy(
    executor: ExecutorControlPolicyV1,
) -> PostgreSQLPreparedControlPolicyV2:
    primary_verifier = PostgreSQLScramVerifierInstallV1(
        schema_version="rsd.postgresql-scram-verifier-install.v1",
        database_identity="primary_database",
        prepared_operation_id="123e4567-e89b-42d3-a456-426614174003",
        application_password_reference_sha256=(
            _references().postgres_application_password.reference_sha256
        ),
        algorithm="scram-sha-256",
        iterations=4096,
        salt_bytes=16,
        derivation_scope="executor_bounded_memory_v1",
        sink="postgresql_prepared_psql_stdin_verifier_v1",
        plaintext_to_psql_allowed=False,
        verifier_in_receipt_allowed=False,
        sql_in_receipt_allowed=False,
        output_in_receipt_allowed=False,
        logs_allowed=False,
        template_sha256=_hash("primary-postgres-verifier-template"),
    )
    restore_verifier = PostgreSQLScramVerifierInstallV1(
        schema_version="rsd.postgresql-scram-verifier-install.v1",
        database_identity="restore_database",
        prepared_operation_id="123e4567-e89b-42d3-a456-426614174006",
        application_password_reference_sha256=(
            _references().postgres_application_password.reference_sha256
        ),
        algorithm="scram-sha-256",
        iterations=4096,
        salt_bytes=16,
        derivation_scope="executor_bounded_memory_v1",
        sink="postgresql_prepared_psql_stdin_verifier_v1",
        plaintext_to_psql_allowed=False,
        verifier_in_receipt_allowed=False,
        sql_in_receipt_allowed=False,
        output_in_receipt_allowed=False,
        logs_allowed=False,
        template_sha256=_hash("restore-postgres-verifier-template"),
    )
    return PostgreSQLPreparedControlPolicyV2(
        schema_version="rsd.postgresql-prepared-control-policy.v2",
        source_commit=_COMMIT,
        executor_identity_sha256=canonical_sha256(executor.executor),
        control_container_id=_hash("postgres-control-container"),
        control_image=_image_policy(
            "postgres-control", "c", config_sha256=_hash("postgres-control-config")
        ),
        control_config_sha256=_hash("postgres-control-config-binding"),
        unix_socket_identity_sha256=_hash("postgres-control-socket"),
        psql_absolute_path="/usr/bin/psql",
        psql_binary_sha256=_hash("postgres-psql-binary"),
        psql_operating_system_user="postgres",
        postgres_unix_socket_directory="/run/postgresql",
        maintenance_database="postgres",
        fixed_psql_argv=(
            "/usr/bin/psql",
            "-X",
            "-q",
            "-A",
            "-t",
            "-v",
            "ON_ERROR_STOP=1",
            "-h",
            "/run/postgresql",
            "-U",
            "postgres",
            "-d",
            "postgres",
            "-f",
            "-",
        ),
        system_identifier="12345678",
        password_encryption="scram-sha-256",
        statement_logging="disabled",
        operations=(
            PostgreSQLPreparedOperationV1(
                operation_id="123e4567-e89b-42d3-a456-426614174004",
                kind="allocation_nologin_v1",
                psql_template_sha256=_hash("postgres-allocation-template"),
                result_projection_sha256=_hash("postgres-allocation-result"),
                stdin_protocol="postgresql_prepared_psql_stdin_v1",
                secret_input=False,
            ),
            PostgreSQLPreparedOperationV1(
                operation_id=primary_verifier.prepared_operation_id,
                kind="install_primary_scram_verifier_v1",
                psql_template_sha256=primary_verifier.template_sha256,
                result_projection_sha256=_hash("primary-postgres-verifier-result"),
                stdin_protocol="postgresql_prepared_psql_stdin_v1",
                secret_input=True,
            ),
            PostgreSQLPreparedOperationV1(
                operation_id=restore_verifier.prepared_operation_id,
                kind="install_restore_scram_verifier_v1",
                psql_template_sha256=restore_verifier.template_sha256,
                result_projection_sha256=_hash("restore-postgres-verifier-result"),
                stdin_protocol="postgresql_prepared_psql_stdin_v1",
                secret_input=True,
            ),
        ),
        scram_verifier_installs=PostgreSQLScramVerifierInstallsV1(
            primary_database=primary_verifier,
            restore_database=restore_verifier,
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
    docker = _docker_policy(executor)
    postgres_prepared = _postgres_prepared_policy(executor)
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
            application_role=postgres.application_role,
            role_names=postgres.role_names,
            allocation_role_states=postgres.allocation_role_states,
            grants=postgres.grants,
            stage_database_prefix="stage-db",
            restore_database_prefix="restore-db",
            control_policy_sha256=canonical_sha256(postgres),
            prepared_control_policy_sha256=canonical_sha256(postgres_prepared),
        ),
        docker_engine_control_policy_sha256=canonical_sha256(docker),
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
                docker_engine_control_policy_sha256=canonical_sha256(docker),
                postgres_control_policy_sha256=canonical_sha256(postgres),
                postgres_prepared_control_policy_sha256=canonical_sha256(postgres_prepared),
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


class _FileReplayAuthority:
    """A process-safe test double for the required external create-once contract."""

    def __init__(self, root: Path) -> None:
        self._root = root

    def claim_once(self, tombstone: ReplayTombstoneV1) -> ReplayAuthorityClaimResult:
        target = (
            self._root
            / hashlib.sha256(f"{tombstone.service}:{tombstone.account}".encode("ascii")).hexdigest()
        )
        temporary = self._root / f".replay-claim-{uuid.uuid4().hex}"
        descriptor: int | None = None
        try:
            descriptor = os.open(
                temporary,
                os.O_WRONLY | os.O_CREAT | os.O_EXCL | getattr(os, "O_NOFOLLOW", 0),
                0o600,
            )
            os.write(descriptor, tombstone.value_bytes())
            os.fsync(descriptor)
            os.link(temporary, target, follow_symlinks=False)
            return ReplayAuthorityClaimResult.CREATED
        except FileExistsError:
            try:
                existing = target.read_bytes()
            except OSError:
                return ReplayAuthorityClaimResult.UNAVAILABLE
            return (
                ReplayAuthorityClaimResult.DUPLICATE_SAME
                if existing == tombstone.value_bytes()
                else ReplayAuthorityClaimResult.DUPLICATE_CONFLICT
            )
        except OSError:
            return ReplayAuthorityClaimResult.UNAVAILABLE
        finally:
            if descriptor is not None:
                os.close(descriptor)
            with suppress(FileNotFoundError):
                temporary.unlink()


def _hold_allocation_operation_lease(
    journal_path: str,
    operation_id: str,
    acquired: object,
    release: object,
) -> None:
    """Hold an OS lease in a child process for a recovery-race regression."""

    # ``multiprocessing.Event`` intentionally has no useful static interface
    # here; these are test-process objects only and never cross a public API.
    journal = SQLiteAllocationJournal(Path(journal_path))
    with journal._operation_lease(operation_id):
        cast(Any, acquired).set()
        cast(Any, release).wait(timeout=10)


def _try_artifact_root_lock(root: str, queue: object) -> None:
    """Exercise the actual advisory root lock from a separate process."""

    try:
        with ArtifactRootLease(Path(root)):
            outcome = "acquired"
    except AuthorizationError as error:
        outcome = error.phase
    cast(Any, queue).put(outcome)


def _claim_file_replay_tombstone(
    root: str,
    tombstone: dict[str, object],
    start: object,
    queue: object,
) -> None:
    """Run one external replay claim in a fresh process."""

    cast(Any, start).wait(timeout=10)
    result = _FileReplayAuthority(Path(root)).claim_once(
        ReplayTombstoneV1.model_validate(tombstone)
    )
    cast(Any, queue).put(result.value)


def _trusted_signer() -> tuple[TrustedEd25519SignerV1, Ed25519PrivateKey]:
    key = _POLICY_SIGNER_PRIVATE_KEY
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
    DockerEngineControlPolicyV1,
    PostgreSQLControlPolicyV1,
    PostgreSQLPreparedControlPolicyV2,
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
    unsigned_docker = _docker_policy(unsigned_executor)
    unsigned_postgres_prepared = _postgres_prepared_policy(unsigned_executor)
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
    docker = unsigned_docker.model_copy(
        update={
            "signature_base64": base64.b64encode(
                key.sign(authorization._docker_engine_control_policy_message(unsigned_docker))
            ).decode("ascii")
        }
    )
    postgres_prepared = unsigned_postgres_prepared.model_copy(
        update={
            "signature_base64": base64.b64encode(
                key.sign(
                    authorization._postgres_prepared_control_policy_message(
                        unsigned_postgres_prepared
                    )
                )
            ).decode("ascii")
        }
    )
    plan = unsigned_intent.plan.model_copy(
        update={
            "postgres": unsigned_intent.plan.postgres.model_copy(
                update={
                    "control_policy_sha256": canonical_sha256(postgres),
                    "prepared_control_policy_sha256": canonical_sha256(postgres_prepared),
                }
            ),
            "docker_engine_control_policy_sha256": canonical_sha256(docker),
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
                    "docker_engine_control_policy_sha256": canonical_sha256(docker),
                    "postgres_control_policy_sha256": canonical_sha256(postgres),
                    "postgres_prepared_control_policy_sha256": canonical_sha256(postgres_prepared),
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
    return (
        signer,
        key,
        intent,
        executor,
        docker,
        postgres,
        postgres_prepared,
        journal,
        policy,
        artifact,
    )


def _allocated_resources(intent: AllocationIntentV2) -> AllocatedResourceSetV2:
    topology = intent.plan.topology
    postgres = intent.plan.postgres
    engine = _engine_observation()
    primary_volume_created_at = "2026-08-28T12:00:30Z"
    restore_volume_created_at = "2026-08-28T12:00:31Z"
    return AllocatedResourceSetV2(
        engine=engine,
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
            engine_fingerprint_sha256=engine.engine_fingerprint_sha256,
            driver="local",
            scope="local",
            created_at=primary_volume_created_at,
            options=intent.plan.primary_valkey_volume.options,
            volume_instance_fingerprint_sha256=docker_volume_instance_fingerprint_sha256(
                name=intent.plan.primary_valkey_volume.name,
                engine_fingerprint_sha256=engine.engine_fingerprint_sha256,
                driver="local",
                scope="local",
                created_at=primary_volume_created_at,
                options=intent.plan.primary_valkey_volume.options,
            ),
        ),
        restore_cache_volume=AllocatedVolumeObservationV1(
            name=intent.plan.restore_valkey_volume.name,
            engine_fingerprint_sha256=engine.engine_fingerprint_sha256,
            driver="local",
            scope="local",
            created_at=restore_volume_created_at,
            options=intent.plan.restore_valkey_volume.options,
            volume_instance_fingerprint_sha256=docker_volume_instance_fingerprint_sha256(
                name=intent.plan.restore_valkey_volume.name,
                engine_fingerprint_sha256=engine.engine_fingerprint_sha256,
                driver="local",
                scope="local",
                created_at=restore_volume_created_at,
                options=intent.plan.restore_valkey_volume.options,
            ),
        ),
        postgres=AllocatedPostgreSQLObservationV1(
            system_identifier="12345678",
            database_name=postgres.database_name,
            database_oid=101,
            schema_name=postgres.schema_name,
            schema_oid=102,
            prepared_operation_id="123e4567-e89b-42d3-a456-426614174004",
            prepared_operation_result_sha256=_hash("postgres-allocation-result"),
            owner_role=postgres.owner_role,
            owner_role_oid=103,
            application_role=postgres.application_role,
            application_role_oid=104,
            role_oids=(
                PostgreSQLRoleObservationV1(
                    role="owner-role", role_oid=103, can_login=False, password_absent=True
                ),
                PostgreSQLRoleObservationV1(
                    role="application-role", role_oid=104, can_login=False, password_absent=True
                ),
            ),
            grants=(
                PostgreSQLGrantObservationV1(
                    role="owner-role",
                    grantee="application-role",
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


def _control_image_local_evidence(intent: AllocationIntentV2) -> DockerImageLocalEvidenceV1:
    """Build the value-free two-reference Engine evidence used by allocation tests."""

    image = _postgres_prepared_policy(_executor_policy(intent.plan.topology)).control_image
    repository = image.image.reference.rsplit("@", 1)[0]
    return DockerImageLocalEvidenceV1(
        schema_version="rsd.docker-image-local-evidence.v1",
        resolution_attestation_sha256=canonical_sha256(image.resolution_attestation),
        registry_index_reference=image.image,
        linux_amd64_manifest_reference=ImageReferenceV1(
            reference=(f"{repository}@sha256:{image.linux_amd64_manifest_digest_sha256}")
        ),
        registry_index_digest_sha256=image.registry_index_digest_sha256,
        linux_amd64_manifest_digest_sha256=image.linux_amd64_manifest_digest_sha256,
        config_digest_sha256=image.config_digest_sha256,
        index_reference_inspected=True,
        platform_manifest_reference_inspected=True,
        operating_system="linux",
        architecture="amd64",
    )


def _allocation_receipt(intent: AllocationIntentV2) -> AllocationEffectReceiptV2:
    resources = _allocated_resources(intent)
    unsigned_executor_receipt = AllocationExecutorReceiptV1(
        schema_version="rsd.allocation-executor-receipt.v1",
        operation_scope="allocate_isolated_empty_resources_v2",
        allocation_operation_id=intent.allocation_operation_id,
        allocation_intent_sha256=allocation_intent_sha256(intent),
        idempotency_key=_hash("allocation-idempotency"),
        executor_id=intent.plan.topology.executor.executor_id,
        engine_control_policy_sha256=intent.plan.docker_engine_control_policy_sha256,
        postgres_prepared_control_policy_sha256=(
            intent.plan.postgres.prepared_control_policy_sha256
        ),
        host_fingerprint_sha256=_executor_policy(
            intent.plan.topology
        ).executor.host_fingerprint_sha256,
        engine=resources.engine,
        control_image_local_evidence=_control_image_local_evidence(intent),
        allocated_resources=resources,
        allocated_resources_projection_sha256=canonical_sha256(resources),
        engine_operation_journal_sha256=_hash("allocation-engine-operation-journal"),
        completed_at="2026-08-28T12:01:00Z",
        signer_key_id="executor-attestation",
        signature_base64=_SIGNATURE,
    )
    executor_receipt = unsigned_executor_receipt.model_copy(
        update={
            "signature_base64": base64.b64encode(
                _EXECUTOR_ATTESTATION_PRIVATE_KEY.sign(
                    authorization._allocation_executor_receipt_message(unsigned_executor_receipt)
                )
            ).decode("ascii")
        }
    )
    return AllocationEffectReceiptV2(
        schema_version="rsd.allocation-effect-receipt.v2",
        operation_kind="allocation_v2",
        operation_scope="allocate_isolated_empty_resources_v2",
        status="allocated_isolated_empty_resources",
        allocation_operation_id=intent.allocation_operation_id,
        allocation_intent_sha256=allocation_intent_sha256(intent),
        journal_uuid=intent.journal_uuid,
        idempotency_key=_hash("allocation-idempotency"),
        allocated_resources=resources,
        executor_receipt_sha256=canonical_sha256(executor_receipt),
        executor_receipt=executor_receipt,
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


def _restore_database_attestation(
    intent: AllocationIntentV2,
    allocation: ObservedAllocationAttestationV1,
    *,
    signer_private: Ed25519PrivateKey | None = None,
) -> ObservedRestoreDatabaseAttestationV1:
    """Build the later, independent restore observation used by V2 tests."""

    source = allocation.allocated_resources.postgres
    observed = AllocatedPostgreSQLObservationV1(
        system_identifier=source.system_identifier,
        database_name=f"{intent.plan.postgres.restore_database_prefix}-stage",
        database_oid=201,
        schema_name=source.schema_name,
        schema_oid=202,
        prepared_operation_id="123e4567-e89b-42d3-a456-426614174006",
        prepared_operation_result_sha256=_hash("restore-postgres-verifier-result"),
        owner_role="restore-owner-role",
        owner_role_oid=203,
        application_role="restore-application-role",
        application_role_oid=204,
        role_oids=(
            PostgreSQLRoleObservationV1(
                role="restore-owner-role", role_oid=203, can_login=False, password_absent=True
            ),
            PostgreSQLRoleObservationV1(
                role="restore-application-role",
                role_oid=204,
                can_login=False,
                password_absent=True,
            ),
        ),
        grants=(
            PostgreSQLGrantObservationV1(
                role="restore-owner-role",
                grantee="restore-application-role",
                privilege="SELECT",
                schema_name=source.schema_name,
            ),
        ),
        acl_sha256=_hash("restore-postgres-acl"),
    )
    unsigned = ObservedRestoreDatabaseAttestationV1(
        schema_version="rsd.observed-restore-database-attestation.v1",
        operation_kind="restore_database_observation_v1",
        restore_observation_operation_id="123e4567-e89b-42d3-a456-426614174007",
        allocation_operation_id=intent.allocation_operation_id,
        allocation_intent_sha256=allocation_intent_sha256(intent),
        allocation_effect_receipt_sha256=allocation.allocation_effect_receipt_sha256,
        observed_allocation_attestation_sha256=observed_allocation_attestation_sha256(allocation),
        journal_uuid=intent.journal_uuid,
        source_database_observation_sha256=canonical_sha256(source),
        source_backup_commitment_sha256=_hash("source-backup-commitment"),
        restore_commitment_sha256=_hash("restore-commitment"),
        authority=intent.plan.postgres.authority,
        restore_database=observed,
        observed_at="2026-08-28T12:02:30Z",
        signer_key_id="test-signer",
        signature_base64=_SIGNATURE,
    )
    if signer_private is None:
        return unsigned
    return unsigned.model_copy(
        update={
            "signature_base64": base64.b64encode(
                signer_private.sign(
                    authorization._observed_restore_database_attestation_message(unsigned)
                )
            ).decode("ascii")
        }
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
        postgres_uri_target_processes=("primary_infisical", "restore_infisical"),
        valkey_uri_target_processes=("primary_infisical", "restore_infisical"),
        infisical_target_process_environment_allowed=True,
        valkey_stdin_config_allowed=True,
        postgres_uri_target_process_environment_allowed=True,
        valkey_uri_target_process_environment_allowed=True,
        postgres_connection_uri_environment_variable="DB_CONNECTION_URI",
        valkey_connection_uri_environment_variable="REDIS_URL",
        valkey_stdin_configuration_directive="requirepass",
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
        postgres_scram_verifier_executor_derivation_allowed=True,
        postgres_scram_verifier_psql_stdin_allowed=True,
        postgres_plaintext_password_to_psql_allowed=False,
        postgres_verifier_in_receipt_allowed=False,
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
        delivery_mode="remote_executor_secret_delivery_v2",
        allowed_purposes=(
            "commitment_hmac",
            "backup_encryption",
            "encryption_key",
            "auth_secret",
            "primary_valkey_password",
            "restore_valkey_password",
            "postgres_application_password",
        ),
        macos_only_purposes=("commitment_hmac", "backup_encryption"),
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
    *,
    restore_observation: ObservedRestoreDatabaseAttestationV1 | None = None,
) -> tuple[
    MaterializationIntentV1,
    ObservedRestoreDatabaseAttestationV1,
    SecretCapabilityPolicyV1,
    SecretHandlingPolicyV1,
    ContainerBootstrapWrapperManifestV1,
    TargetDeliveryMapV1,
    ContainerBootstrapAttachProtocolV1,
]:
    capability, handling = _secret_policies(allocation, executor)
    topology = allocation.plan.topology
    restore_observation = restore_observation or _restore_database_attestation(
        allocation, attestation
    )
    requirements: dict[str, tuple[str, ...]] = {
        "primary_infisical": (
            "encryption_key",
            "auth_secret",
            "primary_valkey_password",
            "postgres_application_password",
        ),
        "primary_valkey": ("primary_valkey_password",),
        "restore_infisical": (
            "encryption_key",
            "auth_secret",
            "restore_valkey_password",
            "postgres_application_password",
        ),
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
    attach_protocol = ContainerBootstrapAttachProtocolV1(
        schema_version="rsd.container-bootstrap-attach-protocol.v1",
        protocol_name="rsd_container_bootstrap_attach_v1",
        frame_magic="ONCA",
        frame_version=1,
        metadata_encoding="canonical_json_utf8_v1",
        allowed_operation_scopes=("materialize_and_start_runtime_v1", "start_runtime_v2"),
        ready_state="ready_v1",
        claim_state="claimed_v1",
        terminal_ack_state="terminal_ack_v1",
        ambiguous_state="attach_ambiguous_v1",
        max_metadata_bytes=4096,
        max_chunk_bytes=4096,
        max_chunks_per_target=4,
        max_total_secret_bytes=8192,
        ready_timeout_seconds=10,
        claim_timeout_seconds=10,
        terminal_ack_timeout_seconds=10,
        eof_required_after_terminal_ack=True,
        chunk_order_required=True,
        replay_allowed=False,
        auto_retry_after_secret_delivery_allowed=False,
        secret_persistence_allowed=False,
        secret_logging_allowed=False,
        secret_receipt_allowed=False,
        created_at=_NOW,
        signer_key_id="test-signer",
        signature_base64=_SIGNATURE,
    )
    attach_protocol_hash = container_bootstrap_attach_protocol_sha256(attach_protocol)

    def wrapper_artifact(name: str) -> ContainerBootstrapWrapperArtifactV1:
        component_plan = getattr(plan, name)
        base = _image_policy(
            f"base-{name}",
            "c" if name.endswith("infisical") else "d",
            config_sha256=_hash(f"{name}-base-config"),
        )
        derived = _image_policy(
            "valkey" if name.endswith("valkey") else "infisical",
            "b" if name.endswith("valkey") else "a",
            config_sha256=component_plan.config_sha256,
        )
        argv_prefix = ("/usr/local/bin/rsd-bootstrap", name)
        base_entrypoint = ("/usr/bin/target-process",)
        base_command = ("--serve",)
        fields: dict[str, Any] = {
            "component": name,
            "artifact_sha256": _hash(f"{name}-wrapper-bytes"),
            "artifact_byte_count": 1024,
            "build_provenance_sha256": _hash(f"{name}-wrapper-provenance"),
            "build_recipe_sha256": _hash(f"{name}-wrapper-recipe"),
            "base_image_policy": base,
            "derived_image_policy": derived,
            "executable_path": "/usr/local/bin/rsd-bootstrap",
            "wrapper_argv_prefix": argv_prefix,
            "base_entrypoint": base_entrypoint,
            "base_command": base_command,
            "entrypoint_command_merge": "exec_wrapper_then_base_entrypoint_and_cmd_v1",
            "merged_argv_sha256": hashlib.sha256(
                json.dumps(
                    argv_prefix + base_entrypoint + base_command, separators=(",", ":")
                ).encode("utf-8")
            ).hexdigest(),
            "runtime_requirements": ContainerWrapperRuntimeRequirementsV1(
                architecture="linux/amd64",
                executable_mode="0755",
                requires_exec_form=True,
                requires_private_pid_namespace=True,
                requires_read_only_root_filesystem=True,
                requires_log_driver_none=True,
                requires_restart_policy_no=True,
                writable_disk_allowed=False,
                secret_file_allowed=False,
                secret_log_allowed=False,
            ),
            "pid1_policy": ContainerWrapperPid1PolicyV1(
                schema_version="rsd.container-wrapper-pid1-policy.v1",
                signal_order=("SIGTERM", "SIGINT"),
                forwards_signals_to_child=True,
                reaps_children=True,
                propagates_child_exit_status=True,
                terminal_ack_before_exit_required=True,
                shutdown_timeout_seconds=10,
            ),
            "attach_protocol_sha256": attach_protocol_hash,
            "artifact_binding_sha256": "0" * 64,
        }
        draft = ContainerBootstrapWrapperArtifactV1.model_construct(**fields)
        fields["artifact_binding_sha256"] = container_bootstrap_wrapper_artifact_sha256(draft)
        return ContainerBootstrapWrapperArtifactV1(**fields)

    wrapper_manifest = ContainerBootstrapWrapperManifestV1(
        schema_version="rsd.container-bootstrap-wrapper-manifest.v1",
        source_commit=_COMMIT,
        allocation_intent_sha256=allocation_intent_sha256(allocation),
        attach_protocol_sha256=attach_protocol_hash,
        primary_infisical=wrapper_artifact("primary_infisical"),
        primary_valkey=wrapper_artifact("primary_valkey"),
        restore_infisical=wrapper_artifact("restore_infisical"),
        restore_valkey=wrapper_artifact("restore_valkey"),
        created_at=_NOW,
        signer_key_id="test-signer",
        signature_base64=_SIGNATURE,
    )
    wrapper_manifest_hash = container_bootstrap_wrapper_manifest_sha256(wrapper_manifest)

    def template(name: str) -> ContainerBootstrapTemplateV1:
        component_plan = getattr(plan, name)
        placement = getattr(topology, name)
        artifact = getattr(wrapper_manifest, name)
        entrypoint = artifact.wrapper_argv_prefix
        mounts: tuple[DockerNamedVolumeMountV1, ...] = (
            (
                DockerNamedVolumeMountV1(
                    mount_type="volume",
                    source_volume_name=cast(str, component_plan.volume_name),
                    target_path="/data",
                    read_only=False,
                    bind_allowed=False,
                    tmpfs_allowed=False,
                    propagation="none",
                ),
            )
            if name.endswith("valkey")
            else ()
        )
        fields: dict[str, Any] = {
            "schema_version": "rsd.container-bootstrap-template.v1",
            "component": name,
            "image": component_plan.image,
            "image_policy": artifact.derived_image_policy,
            "entrypoint": entrypoint,
            "command": artifact.base_entrypoint + artifact.base_command,
            "entrypoint_sha256": hashlib.sha256(
                json.dumps(entrypoint, separators=(",", ":")).encode("utf-8")
            ).hexdigest(),
            "template_sha256": _hash(f"{name}-template"),
            "wrapper_manifest_sha256": wrapper_manifest_hash,
            "wrapper_artifact_binding_sha256": artifact.artifact_binding_sha256,
            "attach_protocol_sha256": attach_protocol_hash,
            "create_request_sha256": _hash(f"{name}-placeholder-create-request"),
            "numeric_user": "1000:1000",
            "working_directory": "/work",
            "open_stdin": True,
            "stdin_once": True,
            "attach_stdin": True,
            "tty": False,
            "run_as_non_root": True,
            "read_only_root_filesystem": True,
            "cap_drop_all": True,
            "cap_add": (),
            "no_new_privileges": True,
            "security_options": ("no-new-privileges:true",),
            "private_pid": True,
            "pid_mode": "isolated_pid_namespace_v1",
            "log_driver": "none",
            "restart_policy": "no",
            "mounts": mounts,
            "docker_socket_mounted": False,
            "host_network": False,
            "network_mode": "exact_isolated_network_v1",
            "publish_all_ports": False,
            "port_bindings": (),
            "labels": (),
            "network_name": placement.network_name,
            "network_alias": placement.alias,
            "static_ipv4": placement.static_ipv4,
            "accepted_secret_sink": (
                ContainerSecretSinkV1.VALKEY_STDIN_CONFIGURATION
                if name.endswith("valkey")
                else ContainerSecretSinkV1.INFISICAL_TARGET_PROCESS_ENVIRONMENT
            ),
        }
        draft = ContainerBootstrapTemplateV1.model_construct(**fields)
        fields["create_request_sha256"] = container_create_template_sha256(draft)
        return ContainerBootstrapTemplateV1(**fields)

    templates = ContainerBootstrapTemplatesV1(
        primary_infisical=template("primary_infisical"),
        primary_valkey=template("primary_valkey"),
        restore_infisical=template("restore_infisical"),
        restore_valkey=template("restore_valkey"),
    )
    observed_postgres = attestation.allocated_resources.postgres
    postgres_prepared = _postgres_prepared_policy(executor)
    application_password_reference = (
        allocation.provider_references.postgres_application_password.reference_sha256
    )

    def login_transition(
        *,
        database_identity: str,
        prepared_operation_id: str,
        database_name: str,
        database_oid: int,
        schema_oid: int,
        owner_role: str,
        owner_role_oid: int,
        application_role: str,
        application_role_oid: int,
    ) -> PostgreSQLLoginTransitionIntentV1:
        install = (
            postgres_prepared.scram_verifier_installs.primary_database
            if database_identity == "primary_database"
            else postgres_prepared.scram_verifier_installs.restore_database
        )
        return PostgreSQLLoginTransitionIntentV1(
            schema_version="rsd.postgresql-login-transition-intent.v1",
            transition_kind="enable_application_login_with_provider_verifier_v1",
            database_identity=cast(Any, database_identity),
            prepared_operation_id=prepared_operation_id,
            system_identifier=observed_postgres.system_identifier,
            database_name=database_name,
            database_oid=database_oid,
            schema_oid=schema_oid,
            owner_role=owner_role,
            owner_role_oid=owner_role_oid,
            application_role=application_role,
            application_role_oid=application_role_oid,
            application_password_reference_sha256=application_password_reference,
            prepared_control_policy_sha256=canonical_sha256(postgres_prepared),
            scram_verifier_install=install,
            owner_can_login=False,
            owner_password_absent=True,
            application_can_login=True,
            application_password_verifier_installed=True,
        )

    primary_transition = login_transition(
        database_identity="primary_database",
        prepared_operation_id=postgres_prepared.scram_verifier_installs.primary_database.prepared_operation_id,
        database_name=observed_postgres.database_name,
        database_oid=observed_postgres.database_oid,
        schema_oid=observed_postgres.schema_oid,
        owner_role=observed_postgres.owner_role,
        owner_role_oid=observed_postgres.owner_role_oid,
        application_role=observed_postgres.application_role,
        application_role_oid=observed_postgres.application_role_oid,
    )
    restore_transition = login_transition(
        database_identity="restore_database",
        prepared_operation_id=restore_observation.restore_database.prepared_operation_id,
        database_name=restore_observation.restore_database.database_name,
        database_oid=restore_observation.restore_database.database_oid,
        schema_oid=restore_observation.restore_database.schema_oid,
        owner_role=restore_observation.restore_database.owner_role,
        owner_role_oid=restore_observation.restore_database.owner_role_oid,
        application_role=restore_observation.restore_database.application_role,
        application_role_oid=restore_observation.restore_database.application_role_oid,
    )
    postgres_login_transitions = PostgreSQLLoginTransitionIntentsV1(
        primary_database=primary_transition,
        restore_database=restore_transition,
    )
    primary_uri = PostgreSQLConnectionUriGrammarV1(
        schema_version="rsd.postgresql-connection-uri-grammar.v1",
        database_identity="primary_database",
        authority=allocation.plan.postgres.authority,
        database_name=primary_transition.database_name,
        application_role=primary_transition.application_role,
        application_password_reference_sha256=application_password_reference,
        prepared_operation_id=primary_transition.prepared_operation_id,
        target_process="primary_infisical",
        environment_variable="DB_CONNECTION_URI",
        uri_grammar="postgresql_user_password_authority_database_v1",
        application_password_format="postgres_application_password_base64url_32_v1",
        application_password_encoded_byte_count=43,
        rendered_uri_byte_count=postgresql_connection_uri_rendered_byte_count(
            authority=allocation.plan.postgres.authority,
            application_role=primary_transition.application_role,
            database_name=primary_transition.database_name,
        ),
        return_uri_allowed=False,
        persistent_storage_allowed=False,
        logging_allowed=False,
        public_artifact_allowed=False,
    )
    restore_uri = PostgreSQLConnectionUriGrammarV1(
        schema_version="rsd.postgresql-connection-uri-grammar.v1",
        database_identity="restore_database",
        authority=allocation.plan.postgres.authority,
        database_name=restore_transition.database_name,
        application_role=restore_transition.application_role,
        application_password_reference_sha256=application_password_reference,
        prepared_operation_id=restore_transition.prepared_operation_id,
        target_process="restore_infisical",
        environment_variable="DB_CONNECTION_URI",
        uri_grammar="postgresql_user_password_authority_database_v1",
        application_password_format="postgres_application_password_base64url_32_v1",
        application_password_encoded_byte_count=43,
        rendered_uri_byte_count=postgresql_connection_uri_rendered_byte_count(
            authority=allocation.plan.postgres.authority,
            application_role=restore_transition.application_role,
            database_name=restore_transition.database_name,
        ),
        return_uri_allowed=False,
        persistent_storage_allowed=False,
        logging_allowed=False,
        public_artifact_allowed=False,
    )
    database_identities = PostgreSQLRuntimeDatabaseIdentitiesV1(
        primary_database=PostgreSQLRuntimeDatabaseIdentityV1(
            database_identity="primary_database",
            observation_binding_sha256=canonical_sha256(observed_postgres),
            schema_oid=primary_transition.schema_oid,
            login_transition=primary_transition,
            connection_uri=primary_uri,
        ),
        restore_database=PostgreSQLRuntimeDatabaseIdentityV1(
            database_identity="restore_database",
            observation_binding_sha256=observed_restore_database_attestation_sha256(
                restore_observation
            ),
            schema_oid=restore_transition.schema_oid,
            login_transition=restore_transition,
            connection_uri=restore_uri,
        ),
    )
    primary_valkey_uri = ValkeyConnectionUriGrammarV1(
        schema_version="rsd.valkey-connection-uri-grammar.v1",
        cache_identity="primary_valkey",
        authority=f"{_REDIS_SCHEME}{topology.primary_valkey.static_ipv4}:6379",
        database_index=0,
        password_reference_sha256=(
            allocation.provider_references.primary_valkey_password.reference_sha256
        ),
        target_process="primary_infisical",
        environment_variable="REDIS_URL",
        uri_grammar="redis_password_authority_database_v1",
        password_format="valkey_password_base64url_32_v1",
        password_encoded_byte_count=43,
        rendered_uri_byte_count=valkey_connection_uri_rendered_byte_count(
            authority=f"{_REDIS_SCHEME}{topology.primary_valkey.static_ipv4}:6379",
            database_index=0,
        ),
        return_uri_allowed=False,
        persistent_storage_allowed=False,
        logging_allowed=False,
        public_artifact_allowed=False,
    )
    restore_valkey_uri = ValkeyConnectionUriGrammarV1(
        schema_version="rsd.valkey-connection-uri-grammar.v1",
        cache_identity="restore_valkey",
        authority=f"{_REDIS_SCHEME}{topology.restore_valkey.static_ipv4}:6379",
        database_index=0,
        password_reference_sha256=(
            allocation.provider_references.restore_valkey_password.reference_sha256
        ),
        target_process="restore_infisical",
        environment_variable="REDIS_URL",
        uri_grammar="redis_password_authority_database_v1",
        password_format="valkey_password_base64url_32_v1",
        password_encoded_byte_count=43,
        rendered_uri_byte_count=valkey_connection_uri_rendered_byte_count(
            authority=f"{_REDIS_SCHEME}{topology.restore_valkey.static_ipv4}:6379",
            database_index=0,
        ),
        return_uri_allowed=False,
        persistent_storage_allowed=False,
        logging_allowed=False,
        public_artifact_allowed=False,
    )
    delivery_request = SecretDeliveryRequestV1(
        schema_version="rsd.secret-delivery-request.v1",
        operation_scope="materialize_and_start_runtime_v1",
        operation_id=_MATERIALIZATION_ID,
        journal_uuid=allocation.journal_uuid,
        provider_material_attestation_sha256=_hash("provider-material-attestation"),
        channel_binding_sha256=_hash("materialization-channel"),
        session_binding_sha256=_hash("materialization-session"),
        request_nonce_sha256=_hash("materialization-request-nonce"),
        slots=(
            SecretDeliverySlotV1(
                purpose="encryption_key",
                reference_sha256=allocation.provider_references.encryption_key.reference_sha256,
                format="infisical_hex_16_v1",
                encoded_byte_count=32,
                sink=SecretDeliverySinkV1.TARGET_DELIVERY_MAP,
                target_identities=("primary_infisical", "restore_infisical"),
            ),
            SecretDeliverySlotV1(
                purpose="auth_secret",
                reference_sha256=allocation.provider_references.auth_secret.reference_sha256,
                format="infisical_auth_secret_base64_32_v1",
                encoded_byte_count=44,
                sink=SecretDeliverySinkV1.TARGET_DELIVERY_MAP,
                target_identities=("primary_infisical", "restore_infisical"),
            ),
            SecretDeliverySlotV1(
                purpose="primary_valkey_password",
                reference_sha256=(
                    allocation.provider_references.primary_valkey_password.reference_sha256
                ),
                format="valkey_password_base64url_32_v1",
                encoded_byte_count=43,
                sink=SecretDeliverySinkV1.TARGET_DELIVERY_MAP,
                target_identities=("primary_infisical", "primary_valkey"),
            ),
            SecretDeliverySlotV1(
                purpose="restore_valkey_password",
                reference_sha256=(
                    allocation.provider_references.restore_valkey_password.reference_sha256
                ),
                format="valkey_password_base64url_32_v1",
                encoded_byte_count=43,
                sink=SecretDeliverySinkV1.TARGET_DELIVERY_MAP,
                target_identities=("restore_infisical", "restore_valkey"),
            ),
            SecretDeliverySlotV1(
                purpose="postgres_application_password",
                reference_sha256=(
                    allocation.provider_references.postgres_application_password.reference_sha256
                ),
                format="postgres_application_password_base64url_32_v1",
                encoded_byte_count=43,
                sink=SecretDeliverySinkV1.POSTGRESQL_SCRAM_VERIFIER_DERIVATION,
                target_identities=(
                    "primary_database",
                    "restore_database",
                    "primary_infisical",
                    "restore_infisical",
                ),
            ),
        ),
    )
    fingerprint_bindings = (
        ProviderMaterialFingerprintBindingV1(
            purpose="encryption_key",
            reference_sha256=allocation.provider_references.encryption_key.reference_sha256,
            fingerprint_sha256=_hash("encryption-material-fingerprint"),
        ),
        ProviderMaterialFingerprintBindingV1(
            purpose="auth_secret",
            reference_sha256=allocation.provider_references.auth_secret.reference_sha256,
            fingerprint_sha256=_hash("auth-material-fingerprint"),
        ),
        ProviderMaterialFingerprintBindingV1(
            purpose="primary_valkey_password",
            reference_sha256=(
                allocation.provider_references.primary_valkey_password.reference_sha256
            ),
            fingerprint_sha256=_hash("primary-valkey-material-fingerprint"),
        ),
        ProviderMaterialFingerprintBindingV1(
            purpose="restore_valkey_password",
            reference_sha256=(
                allocation.provider_references.restore_valkey_password.reference_sha256
            ),
            fingerprint_sha256=_hash("restore-valkey-material-fingerprint"),
        ),
        ProviderMaterialFingerprintBindingV1(
            purpose="postgres_application_password",
            reference_sha256=application_password_reference,
            fingerprint_sha256=_hash("postgres-application-material-fingerprint"),
        ),
    )
    fingerprints = {item.purpose: item for item in fingerprint_bindings}

    def field(
        ordinal: int,
        purpose: str,
        target_field: str,
        value_kind: TargetDeliveryValueKindV1,
        field_format: str,
        encoded_byte_count: int,
        sink: ContainerSecretSinkV1,
        derivation_binding_sha256: str,
    ) -> TargetDeliveryFieldV1:
        binding = fingerprints[purpose]
        return TargetDeliveryFieldV1(
            ordinal=ordinal,
            source_purpose=cast(Any, purpose),
            source_reference_sha256=binding.reference_sha256,
            source_fingerprint_sha256=binding.fingerprint_sha256,
            value_kind=value_kind,
            target_field=cast(Any, target_field),
            format=cast(Any, field_format),
            encoded_byte_count=encoded_byte_count,
            sink=sink,
            derivation_binding_sha256=derivation_binding_sha256,
            persistence_allowed=False,
            logging_allowed=False,
            receipt_allowed=False,
        )

    def target(
        name: str, sink: ContainerSecretSinkV1, fields: tuple[TargetDeliveryFieldV1, ...]
    ) -> ContainerTargetDeliveryV1:
        artifact = getattr(wrapper_manifest, name)
        return ContainerTargetDeliveryV1(
            component=cast(Any, name),
            derived_image_policy_sha256=canonical_sha256(artifact.derived_image_policy),
            wrapper_artifact_binding_sha256=artifact.artifact_binding_sha256,
            attach_protocol_sha256=attach_protocol_hash,
            sink=sink,
            fields=fields,
        )

    target_delivery_map = TargetDeliveryMapV1(
        schema_version="rsd.target-delivery-map.v1",
        source_commit=_COMMIT,
        allocation_intent_sha256=allocation_intent_sha256(allocation),
        topology=topology,
        wrapper_manifest_sha256=wrapper_manifest_hash,
        attach_protocol_sha256=attach_protocol_hash,
        secret_handling_policy_sha256=canonical_sha256(handling),
        provider_references=allocation.provider_references,
        material_fingerprints=fingerprint_bindings,
        database_identities=database_identities,
        primary_valkey_connection_uri=primary_valkey_uri,
        restore_valkey_connection_uri=restore_valkey_uri,
        primary_infisical=target(
            "primary_infisical",
            ContainerSecretSinkV1.INFISICAL_TARGET_PROCESS_ENVIRONMENT,
            (
                field(
                    1,
                    "encryption_key",
                    "ENCRYPTION_KEY",
                    TargetDeliveryValueKindV1.DIRECT_PROVIDER_MATERIAL,
                    "infisical_hex_16_v1",
                    32,
                    ContainerSecretSinkV1.INFISICAL_TARGET_PROCESS_ENVIRONMENT,
                    fingerprints["encryption_key"].fingerprint_sha256,
                ),
                field(
                    2,
                    "auth_secret",
                    "AUTH_SECRET",
                    TargetDeliveryValueKindV1.DIRECT_PROVIDER_MATERIAL,
                    "infisical_auth_secret_base64_32_v1",
                    44,
                    ContainerSecretSinkV1.INFISICAL_TARGET_PROCESS_ENVIRONMENT,
                    fingerprints["auth_secret"].fingerprint_sha256,
                ),
                field(
                    3,
                    "postgres_application_password",
                    "DB_CONNECTION_URI",
                    TargetDeliveryValueKindV1.DERIVED_POSTGRESQL_URI,
                    "derived_postgresql_uri_v1",
                    primary_uri.rendered_uri_byte_count,
                    ContainerSecretSinkV1.INFISICAL_TARGET_PROCESS_ENVIRONMENT,
                    runtime_connection_uri_grammar_sha256(primary_uri),
                ),
                field(
                    4,
                    "primary_valkey_password",
                    "REDIS_URL",
                    TargetDeliveryValueKindV1.DERIVED_VALKEY_URI,
                    "derived_valkey_uri_v1",
                    primary_valkey_uri.rendered_uri_byte_count,
                    ContainerSecretSinkV1.INFISICAL_TARGET_PROCESS_ENVIRONMENT,
                    runtime_connection_uri_grammar_sha256(primary_valkey_uri),
                ),
            ),
        ),
        primary_valkey=target(
            "primary_valkey",
            ContainerSecretSinkV1.VALKEY_STDIN_CONFIGURATION,
            (
                field(
                    1,
                    "primary_valkey_password",
                    "requirepass",
                    TargetDeliveryValueKindV1.DIRECT_PROVIDER_MATERIAL,
                    "valkey_password_base64url_32_v1",
                    43,
                    ContainerSecretSinkV1.VALKEY_STDIN_CONFIGURATION,
                    fingerprints["primary_valkey_password"].fingerprint_sha256,
                ),
            ),
        ),
        restore_infisical=target(
            "restore_infisical",
            ContainerSecretSinkV1.INFISICAL_TARGET_PROCESS_ENVIRONMENT,
            (
                field(
                    1,
                    "encryption_key",
                    "ENCRYPTION_KEY",
                    TargetDeliveryValueKindV1.DIRECT_PROVIDER_MATERIAL,
                    "infisical_hex_16_v1",
                    32,
                    ContainerSecretSinkV1.INFISICAL_TARGET_PROCESS_ENVIRONMENT,
                    fingerprints["encryption_key"].fingerprint_sha256,
                ),
                field(
                    2,
                    "auth_secret",
                    "AUTH_SECRET",
                    TargetDeliveryValueKindV1.DIRECT_PROVIDER_MATERIAL,
                    "infisical_auth_secret_base64_32_v1",
                    44,
                    ContainerSecretSinkV1.INFISICAL_TARGET_PROCESS_ENVIRONMENT,
                    fingerprints["auth_secret"].fingerprint_sha256,
                ),
                field(
                    3,
                    "postgres_application_password",
                    "DB_CONNECTION_URI",
                    TargetDeliveryValueKindV1.DERIVED_POSTGRESQL_URI,
                    "derived_postgresql_uri_v1",
                    restore_uri.rendered_uri_byte_count,
                    ContainerSecretSinkV1.INFISICAL_TARGET_PROCESS_ENVIRONMENT,
                    runtime_connection_uri_grammar_sha256(restore_uri),
                ),
                field(
                    4,
                    "restore_valkey_password",
                    "REDIS_URL",
                    TargetDeliveryValueKindV1.DERIVED_VALKEY_URI,
                    "derived_valkey_uri_v1",
                    restore_valkey_uri.rendered_uri_byte_count,
                    ContainerSecretSinkV1.INFISICAL_TARGET_PROCESS_ENVIRONMENT,
                    runtime_connection_uri_grammar_sha256(restore_valkey_uri),
                ),
            ),
        ),
        restore_valkey=target(
            "restore_valkey",
            ContainerSecretSinkV1.VALKEY_STDIN_CONFIGURATION,
            (
                field(
                    1,
                    "restore_valkey_password",
                    "requirepass",
                    TargetDeliveryValueKindV1.DIRECT_PROVIDER_MATERIAL,
                    "valkey_password_base64url_32_v1",
                    43,
                    ContainerSecretSinkV1.VALKEY_STDIN_CONFIGURATION,
                    fingerprints["restore_valkey_password"].fingerprint_sha256,
                ),
            ),
        ),
        created_at=_NOW,
        signer_key_id="test-signer",
        signature_base64=_SIGNATURE,
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
            observed_restore_database_attestation_sha256=(
                observed_restore_database_attestation_sha256(restore_observation)
            ),
            executor_installation_intent_sha256=_hash("executor-installation-intent"),
            executor_installation_receipt_sha256=_hash("executor-installation-receipt"),
            topology=topology,
            plan=plan,
            bootstrap_templates=templates,
            wrapper_manifest_sha256=wrapper_manifest_hash,
            target_delivery_map_sha256=target_delivery_map_sha256(target_delivery_map),
            container_attach_protocol_sha256=attach_protocol_hash,
            postgres_login_transitions=postgres_login_transitions,
            secret_delivery_request=delivery_request,
            provider_references=allocation.provider_references,
            evidence=MaterializationEvidenceBindingsV1(
                allocation_intent_sha256=allocation_intent_sha256(allocation),
                allocation_effect_receipt_sha256=allocation_effect_receipt_sha256(receipt),
                observed_allocation_attestation_sha256=observed_allocation_attestation_sha256(
                    attestation
                ),
                observed_restore_database_attestation_sha256=(
                    observed_restore_database_attestation_sha256(restore_observation)
                ),
                executor_control_policy_sha256=canonical_sha256(executor),
                docker_engine_control_policy_sha256=canonical_sha256(_docker_policy(executor)),
                postgres_prepared_control_policy_sha256=canonical_sha256(postgres_prepared),
                executor_installation_policy_sha256=executor.installation_policy_sha256,
                executor_installation_intent_sha256=_hash("executor-installation-intent"),
                executor_installation_receipt_sha256=_hash("executor-installation-receipt"),
                secret_capability_policy_sha256=canonical_sha256(capability),
                secret_handling_policy_sha256=canonical_sha256(handling),
                provider_material_attestation_sha256=_hash("provider-material-attestation"),
                wrapper_manifest_sha256=wrapper_manifest_hash,
                target_delivery_map_sha256=target_delivery_map_sha256(target_delivery_map),
                container_attach_protocol_sha256=attach_protocol_hash,
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
        restore_observation,
        capability,
        handling,
        wrapper_manifest,
        target_delivery_map,
        attach_protocol,
    )


def _materialization_context(
    intent: MaterializationIntentV1,
    allocation: ObservedAllocationAttestationV1,
    restore_database_attestation: ObservedRestoreDatabaseAttestationV1,
    wrapper_manifest: ContainerBootstrapWrapperManifestV1,
    target_delivery_map: TargetDeliveryMapV1,
    attach_protocol: ContainerBootstrapAttachProtocolV1,
) -> MaterializationExecutionContext:
    def expectation(database_identity: str) -> PostgreSQLLoginTransitionExpectationV1:
        database = getattr(target_delivery_map.database_identities, database_identity)
        transition = database.login_transition
        return PostgreSQLLoginTransitionExpectationV1(
            database_identity=cast(Any, database_identity),
            authority=database.connection_uri.authority,
            system_identifier=transition.system_identifier,
            database_oid=transition.database_oid,
            schema_oid=transition.schema_oid,
            owner_role_oid=transition.owner_role_oid,
            application_role_oid=transition.application_role_oid,
            prepared_operation_id=transition.prepared_operation_id,
            application_password_reference_sha256=(
                transition.application_password_reference_sha256
            ),
            capability_fingerprint_sha256=_hash(f"{database_identity}-postgres-login-capability"),
        )

    return MaterializationExecutionContext(
        operation_kind="materialization_v1",
        operation_scope="materialize_and_start_runtime_v1",
        materialization_operation_id=intent.materialization_operation_id,
        intent=intent,
        allocation_attestation=allocation,
        allocation_attestation_sha256=observed_allocation_attestation_sha256(allocation),
        restore_database_attestation=restore_database_attestation,
        restore_database_attestation_sha256=observed_restore_database_attestation_sha256(
            restore_database_attestation
        ),
        provider_expectations=(),
        executor_expectation=ExecutorControlExpectationV1(
            executor_id="local-executor",
            endpoint_sha256=_hash("executor-endpoint"),
            host_fingerprint_sha256=_hash("executor-host"),
            control_capability_fingerprint_sha256=_hash("executor-control"),
            engine_fingerprint_sha256=_hash("engine"),
        ),
        executor_attestation_key_id="executor-attestation",
        executor_attestation_public_key_base64=_EXECUTOR_ATTESTATION_PUBLIC_KEY,
        executor_attestation_public_key_fingerprint_sha256=hashlib.sha256(
            _EXECUTOR_ATTESTATION_PUBLIC_BYTES
        ).hexdigest(),
        docker_engine_control_policy_sha256=(intent.evidence.docker_engine_control_policy_sha256),
        postgres_login_expectations=(
            expectation("primary_database"),
            expectation("restore_database"),
        ),
        postgres_prepared_control_policy_sha256=(
            intent.postgres_login_transitions.primary_database.prepared_control_policy_sha256
        ),
        postgres_verifier_result_projection_sha256s=(
            _hash("primary-postgres-verifier-result"),
            _hash("restore-postgres-verifier-result"),
        ),
        secret_material_expectation=SecretMaterialExpectationV1(
            provider_identity_sha256=_hash("provider-material-attestation"),
            capability_fingerprint_sha256=_hash("secret-capability"),
            secret_handling_policy_sha256=intent.evidence.secret_handling_policy_sha256,
        ),
        secret_handling_policy_sha256=intent.evidence.secret_handling_policy_sha256,
        wrapper_manifest=wrapper_manifest,
        target_delivery_map=target_delivery_map,
        container_attach_protocol=attach_protocol,
        secret_delivery_request=intent.secret_delivery_request,
        materialization_intent_sha256=materialization_intent_sha256(intent),
        idempotency_key=_hash("materialization-idempotency"),
        provider_provenance_sha256=_hash("provider-provenance"),
        executor_provenance_sha256=_hash("executor-provenance"),
        postgres_login_provenance_sha256=_hash("postgres-login-provenance"),
        secret_capability_provenance_sha256=_hash("secret-provenance"),
        secret_delivery_provenance_sha256=_hash("secret-delivery-provenance"),
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
            engine_fingerprint_sha256=docker_engine_fingerprint_sha256(_engine_projection()),
        ),
        executor_attestation_key_id="executor-attestation",
        executor_attestation_public_key_base64=_EXECUTOR_ATTESTATION_PUBLIC_KEY,
        executor_attestation_public_key_fingerprint_sha256=hashlib.sha256(
            _EXECUTOR_ATTESTATION_PUBLIC_BYTES
        ).hexdigest(),
        docker_engine_control_policy_sha256=intent.evidence.docker_engine_control_policy_sha256,
        postgres_control_expectation=PostgreSQLControlExpectationV1(
            authority="postgresql://192.0.2.40:5432",
            maintenance_reference_sha256=_hash("postgres-maintenance"),
            capability_fingerprint_sha256=_hash("postgres-capability"),
        ),
        postgres_prepared_control_policy_sha256=(
            intent.plan.postgres.prepared_control_policy_sha256
        ),
        expected_control_image_local_evidence=_control_image_local_evidence(intent),
        postgres_allocation_prepared_operation_id="123e4567-e89b-42d3-a456-426614174004",
        postgres_allocation_result_projection_sha256=_hash("postgres-allocation-result"),
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

    def inspection(name: str) -> ContainerBootstrapInspectionV1:
        template = getattr(context.intent.bootstrap_templates, name)
        return ContainerBootstrapInspectionV1(
            image_policy_binding=docker_image_policy_binding(template.image_policy),
            entrypoint=template.entrypoint,
            command=template.command,
            entrypoint_sha256=template.entrypoint_sha256,
            template_sha256=template.template_sha256,
            wrapper_manifest_sha256=template.wrapper_manifest_sha256,
            wrapper_artifact_binding_sha256=template.wrapper_artifact_binding_sha256,
            attach_protocol_sha256=template.attach_protocol_sha256,
            create_request_sha256=template.create_request_sha256,
            numeric_user=template.numeric_user,
            working_directory=template.working_directory,
            open_stdin=True,
            stdin_once=True,
            attach_stdin=True,
            tty=False,
            run_as_non_root=True,
            read_only_root_filesystem=True,
            cap_drop_all=True,
            cap_add=(),
            no_new_privileges=True,
            security_options=("no-new-privileges:true",),
            private_pid=True,
            pid_mode="isolated_pid_namespace_v1",
            log_driver="none",
            restart_policy="no",
            mounts=template.mounts,
            docker_socket_mounted=False,
            host_network=False,
            network_mode="exact_isolated_network_v1",
            publish_all_ports=False,
            port_bindings=(),
            labels=(),
            network_name=template.network_name,
            network_alias=template.network_alias,
            static_ipv4=template.static_ipv4,
            accepted_secret_sink=template.accepted_secret_sink,
            running=True,
        )

    def observation(name: str, marker: str) -> RuntimeContainerObservationV1:
        plan = getattr(context.intent.plan, name)
        placement = getattr(context.intent.topology, name)
        return RuntimeContainerObservationV1(
            component=cast(Any, name),
            container_id=_hash(f"container-{marker}"),
            image=plan.image,
            config_sha256=plan.config_sha256,
            image_policy_binding=docker_image_policy_binding(
                getattr(context.intent.bootstrap_templates, name).image_policy
            ),
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
            inspection=inspection(name),
        )

    def attach_receipt(
        name: str, marker: str, inspected: ContainerBootstrapInspectionV1
    ) -> ContainerAttachReceiptV1:
        target = getattr(context.target_delivery_map, name)
        request = ContainerAttachRequestV1(
            schema_version="rsd.container-attach-request.v1",
            operation_scope=context.operation_scope,
            operation_id=context.materialization_operation_id,
            component=cast(Any, name),
            container_id=_hash(f"container-{marker}"),
            derived_image_policy_sha256=target.derived_image_policy_sha256,
            wrapper_manifest_sha256=context.intent.wrapper_manifest_sha256,
            wrapper_artifact_binding_sha256=target.wrapper_artifact_binding_sha256,
            attach_protocol_sha256=context.intent.container_attach_protocol_sha256,
            target_delivery_map_sha256=context.intent.target_delivery_map_sha256,
            request_nonce_sha256=context.secret_delivery_request.request_nonce_sha256,
            channel_binding_sha256=context.secret_delivery_request.channel_binding_sha256,
            session_binding_sha256=context.secret_delivery_request.session_binding_sha256,
            expected_ready_state="ready_v1",
            expected_claim_state="claimed_v1",
            expected_terminal_ack_state="terminal_ack_v1",
            fields=target.fields,
        )
        request_sha256 = container_attach_request_sha256(request)
        descriptor_sha256 = container_attach_chunk_descriptors_sha256(request.fields)
        ack = ContainerAttachTerminalAckV1(
            schema_version="rsd.container-attach-terminal-ack.v1",
            request_sha256=request_sha256,
            state="terminal_ack_v1",
            chunk_count=len(request.fields),
            chunk_descriptors_sha256=descriptor_sha256,
            chunks_zeroized=True,
            persistence_allowed=False,
            logging_allowed=False,
            receipt_contains_secret=False,
            eof_observed=True,
        )
        return ContainerAttachReceiptV1(
            schema_version="rsd.container-attach-receipt.v1",
            request_sha256=request_sha256,
            component=cast(Any, name),
            container_id=request.container_id,
            ready_state="ready_v1",
            claim_state="claimed_v1",
            chunk_count=len(request.fields),
            chunk_descriptors_sha256=descriptor_sha256,
            terminal_ack_state="terminal_ack_v1",
            terminal_ack_sha256=container_attach_ack_sha256(ack),
            chunks_zeroized=True,
            persistence_allowed=False,
            logging_allowed=False,
            receipt_contains_secret=False,
            eof_observed=True,
        )

    def executor_inspection(name: str, marker: str) -> ExecutorContainerInspectionV1:
        inspected = inspection(name)
        completed_attach = attach_receipt(name, marker, inspected)
        return ExecutorContainerInspectionV1(
            component=cast(Any, name),
            container_id=_hash(f"container-{marker}"),
            inspection=inspected,
            attach_receipt=completed_attach,
            attach_receipt_sha256=container_attach_receipt_sha256(completed_attach),
        )

    inspections = (
        executor_inspection("primary_infisical", "a"),
        executor_inspection("primary_valkey", "b"),
        executor_inspection("restore_infisical", "c"),
        executor_inspection("restore_valkey", "d"),
    )
    unsigned_executor_receipt = MaterializationExecutorReceiptV1(
        schema_version="rsd.materialization-executor-receipt.v1",
        executor_id=context.executor_expectation.executor_id,
        installation_receipt_sha256=_hash("executor-installation-receipt"),
        wrapper_manifest_sha256=context.intent.wrapper_manifest_sha256,
        target_delivery_map_sha256=context.intent.target_delivery_map_sha256,
        container_attach_protocol_sha256=context.intent.container_attach_protocol_sha256,
        operation_scope="materialize_and_start_runtime_v1",
        operation_id=context.materialization_operation_id,
        idempotency_key=context.idempotency_key,
        materialization_intent_sha256=context.materialization_intent_sha256,
        observed_allocation_attestation_sha256=context.allocation_attestation_sha256,
        docker_engine_control_policy_sha256=context.docker_engine_control_policy_sha256,
        secret_delivery_receipt_sha256=_hash("pending-secret-delivery-receipt"),
        channel_binding_sha256=context.secret_delivery_request.channel_binding_sha256,
        session_binding_sha256=context.secret_delivery_request.session_binding_sha256,
        host_fingerprint_sha256=context.executor_expectation.host_fingerprint_sha256,
        engine_fingerprint_sha256=context.executor_expectation.engine_fingerprint_sha256,
        engine_operation_journal_sha256=_hash("materialization-engine-operation-journal"),
        containers=inspections,
        completed_at="2026-08-28T12:04:00Z",
        signer_key_id="executor-attestation",
        signature_base64=_SIGNATURE,
    )

    def login_receipt(
        transition: PostgreSQLLoginTransitionIntentV1, result_projection_sha256: str
    ) -> PostgreSQLLoginTransitionReceiptV1:
        return PostgreSQLLoginTransitionReceiptV1(
            schema_version="rsd.postgresql-login-transition-receipt.v1",
            database_identity=transition.database_identity,
            prepared_operation_id=transition.prepared_operation_id,
            system_identifier=transition.system_identifier,
            database_name=transition.database_name,
            database_oid=transition.database_oid,
            schema_oid=transition.schema_oid,
            owner_role=transition.owner_role,
            owner_role_oid=transition.owner_role_oid,
            application_role=transition.application_role,
            application_role_oid=transition.application_role_oid,
            application_password_reference_sha256=(
                transition.application_password_reference_sha256
            ),
            prepared_control_policy_sha256=transition.prepared_control_policy_sha256,
            prepared_operation_result_sha256=result_projection_sha256,
            owner_can_login=False,
            owner_password_absent=True,
            application_can_login=True,
            application_password_verifier_installed=True,
        )

    login_receipts = PostgreSQLLoginTransitionReceiptsV1(
        primary_database=login_receipt(
            context.intent.postgres_login_transitions.primary_database,
            context.postgres_verifier_result_projection_sha256s[0],
        ),
        restore_database=login_receipt(
            context.intent.postgres_login_transitions.restore_database,
            context.postgres_verifier_result_projection_sha256s[1],
        ),
    )
    request = context.intent.secret_delivery_request
    delivery_receipt = SecretDeliveryReceiptV1(
        schema_version="rsd.secret-delivery-receipt.v1",
        operation_scope=request.operation_scope,
        operation_id=request.operation_id,
        journal_uuid=request.journal_uuid,
        request_nonce_sha256=request.request_nonce_sha256,
        channel_binding_sha256=request.channel_binding_sha256,
        session_binding_sha256=request.session_binding_sha256,
        slots=tuple(
            SecretDeliverySlotReceiptV1(
                purpose=slot.purpose,
                reference_sha256=slot.reference_sha256,
                sink=slot.sink,
                target_identities=slot.target_identities,
                delivered=True,
            )
            for slot in request.slots
        ),
        completed_at="2026-08-28T12:04:00Z",
    )
    unsigned_executor_receipt = unsigned_executor_receipt.model_copy(
        update={"secret_delivery_receipt_sha256": canonical_sha256(delivery_receipt)}
    )
    executor_receipt = unsigned_executor_receipt.model_copy(
        update={
            "signature_base64": base64.b64encode(
                _EXECUTOR_ATTESTATION_PRIVATE_KEY.sign(
                    authorization._materialization_executor_receipt_message(
                        unsigned_executor_receipt
                    )
                )
            ).decode("ascii")
        }
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
        wrapper_manifest_sha256=context.intent.wrapper_manifest_sha256,
        target_delivery_map_sha256=context.intent.target_delivery_map_sha256,
        container_attach_protocol_sha256=context.intent.container_attach_protocol_sha256,
        executor_receipt_sha256=canonical_sha256(executor_receipt),
        executor_receipt=executor_receipt,
        postgres_login_transitions=login_receipts,
        delivery_receipt=delivery_receipt,
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
    materialization, *_ = _materialization_intent(allocation, executor, receipt, attestation)

    assert materialization.allocation_intent_sha256 == allocation_intent_sha256(allocation)
    assert materialization.allocation_effect_receipt_sha256 == allocation_effect_receipt_sha256(
        receipt
    )
    assert (
        materialization.observed_allocation_attestation_sha256
        == observed_allocation_attestation_sha256(attestation)
    )
    assert materialization.operation_scope == "materialize_and_start_runtime_v1"


def test_restore_database_predecessor_rejects_attacker_oids_staleness_and_substitution(
    tmp_path: Path,
) -> None:
    """A recomputed materialization chain cannot nominate its own restore DB."""

    allocation, executor, _ = _allocation_bundle(tmp_path)
    receipt = _allocation_receipt(allocation)
    allocation_observation = _allocation_attestation(allocation, receipt)
    restore = _restore_database_attestation(allocation, allocation_observation)
    signer, signing_key = _trusted_signer()
    restore = _restore_database_attestation(
        allocation, allocation_observation, signer_private=signing_key
    )
    authorization._verify_observed_restore_database_attestation_signature(restore, signer=signer)

    attacker_data = restore.restore_database.model_dump(mode="python")
    attacker_data.update(
        {
            "database_name": "attacker-stage-db",
            "database_oid": 901,
            "schema_oid": 902,
            "prepared_operation_id": restore.restore_database.prepared_operation_id,
            "owner_role": "attacker-owner-role",
            "owner_role_oid": 903,
            "application_role": "attacker-application-role",
            "application_role_oid": 904,
            "role_oids": (
                PostgreSQLRoleObservationV1(
                    role="attacker-owner-role", role_oid=903, can_login=False, password_absent=True
                ),
                PostgreSQLRoleObservationV1(
                    role="attacker-application-role",
                    role_oid=904,
                    can_login=False,
                    password_absent=True,
                ),
            ),
            "grants": (
                PostgreSQLGrantObservationV1(
                    role="attacker-owner-role",
                    grantee="attacker-application-role",
                    privilege="SELECT",
                    schema_name=restore.restore_database.schema_name,
                ),
            ),
        }
    )
    attacker_database = AllocatedPostgreSQLObservationV1.model_validate(attacker_data)
    unsigned_attacker = restore.model_copy(
        update={
            "restore_database": attacker_database,
            "signature_base64": _SIGNATURE,
        }
    )
    attacker = unsigned_attacker.model_copy(
        update={
            "signature_base64": base64.b64encode(
                signing_key.sign(
                    authorization._observed_restore_database_attestation_message(unsigned_attacker)
                )
            ).decode("ascii")
        }
    )
    authorization._verify_observed_restore_database_attestation_signature(attacker, signer=signer)
    attacker_materialization, _, _, _, _, attacker_map, _ = _materialization_intent(
        allocation,
        executor,
        receipt,
        allocation_observation,
        restore_observation=attacker,
    )
    policy = ReplayAuthorityPolicyV1(
        schema_version="rsd.replay-authority-policy.v1",
        service="replay-service",
        account_prefix="replay-prefix",
    )
    stage = authorization._AllocationStageArtifacts(
        intent=allocation,
        receipt=receipt,
        attestation=allocation_observation,
    )
    with pytest.raises(AuthorizationError, match="materialization_restore_database_binding"):
        authorization._verify_materialization_intent_chain(
            allocation=stage,
            intent=attacker_materialization.model_copy(
                update={"replay_policy_sha256": policy.sha256()}
            ),
            restore_database_attestation=attacker,
            target_delivery_map=attacker_map,
            replay_policy=policy,
            expected_disposal_owner=_OWNER,
            expected_approver_identity=_APPROVER,
            now=_TEST_CLOCK,
        )

    stale = restore.model_copy(update={"observed_at": "2026-08-27T12:02:30Z"})
    materialization, _, _, _, _, target_delivery_map, _ = _materialization_intent(
        allocation,
        executor,
        receipt,
        allocation_observation,
        restore_observation=stale,
    )
    with pytest.raises(AuthorizationError, match="materialization_intent_freshness"):
        authorization._verify_materialization_intent_chain(
            allocation=stage,
            intent=materialization.model_copy(update={"replay_policy_sha256": policy.sha256()}),
            restore_database_attestation=stale,
            target_delivery_map=target_delivery_map,
            replay_policy=policy,
            expected_disposal_owner=_OWNER,
            expected_approver_identity=_APPROVER,
            now=_TEST_CLOCK,
        )

    substituted = restore.model_copy(update={"restore_commitment_sha256": _hash("substituted")})
    with pytest.raises(AuthorizationError, match="materialization_intent_binding"):
        authorization._verify_materialization_intent_chain(
            allocation=stage,
            intent=materialization.model_copy(update={"replay_policy_sha256": policy.sha256()}),
            restore_database_attestation=substituted,
            target_delivery_map=target_delivery_map,
            replay_policy=policy,
            expected_disposal_owner=_OWNER,
            expected_approver_identity=_APPROVER,
            now=_TEST_CLOCK,
        )


def test_restore_schema_oid_is_bound_through_recomputed_transition_and_delivery_map(
    tmp_path: Path,
) -> None:
    """A valid-looking new map cannot change only the restore schema OID."""

    allocation, executor, _ = _allocation_bundle(tmp_path)
    receipt = _allocation_receipt(allocation)
    allocation_observation = _allocation_attestation(allocation, receipt)
    materialization, restore, _, _, _, target_map, _ = _materialization_intent(
        allocation, executor, receipt, allocation_observation
    )
    changed_schema_oid = restore.restore_database.schema_oid + 1
    changed_restore_transition = (
        materialization.postgres_login_transitions.restore_database.model_copy(
            update={"schema_oid": changed_schema_oid}
        )
    )
    changed_transitions = materialization.postgres_login_transitions.model_copy(
        update={"restore_database": changed_restore_transition}
    )
    changed_restore_identity = target_map.database_identities.restore_database.model_copy(
        update={
            "schema_oid": changed_schema_oid,
            "login_transition": changed_restore_transition,
        }
    )
    changed_identities = target_map.database_identities.model_copy(
        update={"restore_database": changed_restore_identity}
    )
    changed_map = target_map.model_copy(update={"database_identities": changed_identities})
    changed_map_sha256 = target_delivery_map_sha256(changed_map)
    changed_materialization = materialization.model_copy(
        update={
            "postgres_login_transitions": changed_transitions,
            "target_delivery_map_sha256": changed_map_sha256,
            "evidence": materialization.evidence.model_copy(
                update={"target_delivery_map_sha256": changed_map_sha256}
            ),
        }
    )
    stage = authorization._AllocationStageArtifacts(
        intent=allocation,
        receipt=receipt,
        attestation=allocation_observation,
    )
    policy = ReplayAuthorityPolicyV1(
        schema_version="rsd.replay-authority-policy.v1",
        service="replay-service",
        account_prefix="replay-prefix",
    )
    with pytest.raises(AuthorizationError, match="materialization_postgres_transition_binding"):
        authorization._verify_materialization_intent_chain(
            allocation=stage,
            intent=changed_materialization.model_copy(
                update={"replay_policy_sha256": policy.sha256()}
            ),
            restore_database_attestation=restore,
            target_delivery_map=changed_map,
            replay_policy=policy,
            expected_disposal_owner=_OWNER,
            expected_approver_identity=_APPROVER,
            now=_TEST_CLOCK,
        )


def test_allocation_receipt_rejects_recomputed_local_image_evidence_substitution(
    tmp_path: Path,
) -> None:
    """A signed executor receipt must carry both expected local inspections."""

    intent, _, _ = _allocation_bundle(tmp_path)
    context = _allocation_context(intent)
    receipt = _allocation_receipt(intent)
    altered_evidence = receipt.executor_receipt.control_image_local_evidence.model_copy(
        update={"resolution_attestation_sha256": _hash("different-oci-resolution")}
    )
    unsigned_executor = receipt.executor_receipt.model_copy(
        update={
            "control_image_local_evidence": altered_evidence,
            "signature_base64": _SIGNATURE,
        }
    )
    altered_executor = unsigned_executor.model_copy(
        update={
            "signature_base64": base64.b64encode(
                _EXECUTOR_ATTESTATION_PRIVATE_KEY.sign(
                    authorization._allocation_executor_receipt_message(unsigned_executor)
                )
            ).decode("ascii")
        }
    )
    altered_receipt = receipt.model_copy(
        update={
            "executor_receipt": altered_executor,
            "executor_receipt_sha256": canonical_sha256(altered_executor),
        }
    )
    with pytest.raises(AuthorizationError, match="allocation_executor_receipt"):
        authorization._validate_allocation_effect_receipt(context, altered_receipt)


def test_prepared_control_artifact_requires_nested_signed_oci_resolution(tmp_path: Path) -> None:
    """The outer policy signature cannot authenticate a forged resolver proof."""

    _, executor, _ = _allocation_bundle(tmp_path)
    signer, signing_key = _trusted_signer()
    policy = _postgres_prepared_policy(executor)
    unsigned_policy = policy.model_copy(update={"signature_base64": _SIGNATURE})
    signed_policy = unsigned_policy.model_copy(
        update={
            "signature_base64": base64.b64encode(
                signing_key.sign(
                    authorization._postgres_prepared_control_policy_message(unsigned_policy)
                )
            ).decode("ascii")
        }
    )
    authorization._verify_postgres_prepared_control_policy_signature(signed_policy, signer=signer)

    forged_resolution = signed_policy.control_image.resolution_attestation.model_copy(
        update={"signature_base64": _SIGNATURE}
    )
    forged_image = signed_policy.control_image.model_copy(
        update={"resolution_attestation": forged_resolution}
    )
    unsigned_forged = signed_policy.model_copy(
        update={"control_image": forged_image, "signature_base64": _SIGNATURE}
    )
    forged_policy = unsigned_forged.model_copy(
        update={
            "signature_base64": base64.b64encode(
                signing_key.sign(
                    authorization._postgres_prepared_control_policy_message(unsigned_forged)
                )
            ).decode("ascii")
        }
    )
    with pytest.raises(AuthorizationError, match="oci_image_resolution_attestation_signature"):
        authorization._verify_postgres_prepared_control_policy_signature(
            forged_policy, signer=signer
        )


@pytest.mark.parametrize(
    ("uri_field", "authority"),
    (
        ("primary_valkey_connection_uri", "redis://192.0.2.77:6379"),
        ("restore_valkey_connection_uri", "redis://198.51.100.77:6379"),
        ("primary_valkey_connection_uri", "redis://192.0.2.3:6380"),
        ("restore_valkey_connection_uri", "redis://192.0.2.3:6379"),
    ),
)
def test_target_delivery_map_rejects_unplanned_valkey_authority_port_and_swap(
    tmp_path: Path, uri_field: str, authority: str
) -> None:
    allocation, executor, _ = _allocation_bundle(tmp_path)
    receipt = _allocation_receipt(allocation)
    attestation = _allocation_attestation(allocation, receipt)
    _, _, _, _, _, target_delivery_map, _ = _materialization_intent(
        allocation, executor, receipt, attestation
    )
    raw = target_delivery_map.model_dump(mode="python")
    uri = dict(raw[uri_field])
    uri["authority"] = authority
    uri["rendered_uri_byte_count"] = valkey_connection_uri_rendered_byte_count(
        authority=authority, database_index=0
    )
    raw[uri_field] = uri
    with pytest.raises(ValueError, match="target delivery map"):
        TargetDeliveryMapV1.model_validate(raw)


def test_runtime_topology_comparison_requires_exact_alias_and_static_address(
    tmp_path: Path,
) -> None:
    """A matching component/image/network cannot hide a changed attachment route."""

    import omninode_rsd.lifecycle.infisical_disposable as disposable

    allocation, executor, _ = _allocation_bundle(tmp_path)
    receipt = _allocation_receipt(allocation)
    attestation = _allocation_attestation(allocation, receipt)
    materialization, restore, _, _, wrapper, target_map, attach_protocol = _materialization_intent(
        allocation, executor, receipt, attestation
    )
    context = _materialization_context(
        materialization, attestation, restore, wrapper, target_map, attach_protocol
    )
    runtime = _materialization_receipt(context).primary_infisical
    placement = materialization.topology.primary_infisical
    network_id = attestation.allocated_resources.primary_network.network_id

    assert disposable._matches_runtime_topology(runtime, placement=placement, network_id=network_id)
    for update in (
        {"alias": "wrong-alias"},
        {"static_ipv4": materialization.topology.primary_valkey.static_ipv4},
    ):
        altered = runtime.model_copy(
            update={"attachments": (runtime.attachments[0].model_copy(update=update),)}
        )
        assert not disposable._matches_runtime_topology(
            altered, placement=placement, network_id=network_id
        )

    malformed = runtime.model_copy(update={"attachments": ()})
    assert not disposable._matches_runtime_component(malformed, cast(Any, object()))
    assert not disposable._matches_runtime_topology(
        malformed, placement=placement, network_id=network_id
    )


def test_materialization_chain_binds_provider_and_allocated_volumes(tmp_path: Path) -> None:
    allocation, executor, _ = _allocation_bundle(tmp_path)
    receipt = _allocation_receipt(allocation)
    attestation = _allocation_attestation(allocation, receipt)
    materialization, restore_observation, _, _, _, target_delivery_map, _ = _materialization_intent(
        allocation, executor, receipt, attestation
    )
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
        restore_database_attestation=restore_observation,
        target_delivery_map=target_delivery_map,
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
            restore_database_attestation=restore_observation,
            target_delivery_map=target_delivery_map,
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
            restore_database_attestation=restore_observation,
            target_delivery_map=target_delivery_map,
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
    (
        materialization,
        _restore_observation,
        capability,
        handling,
        wrapper_manifest,
        target_delivery_map,
        attach_protocol,
    ) = _materialization_intent(allocation, executor, receipt, attestation)
    docker = _docker_policy(executor)
    postgres_prepared = _postgres_prepared_policy(executor)
    for name in (
        "_verify_executor_control_policy_signature",
        "_verify_docker_engine_control_policy_signature",
        "_verify_postgres_prepared_control_policy_signature",
        "_verify_secret_capability_policy_signature",
        "_verify_secret_handling_policy_signature",
        "_verify_container_wrapper_manifest_signature",
        "_verify_target_delivery_map_signature",
        "_verify_container_attach_protocol_signature",
    ):
        monkeypatch.setattr(authorization, name, lambda *_args, **_kwargs: None)

    authorization._verify_materialization_control_policy_bindings(
        allocation_intent=allocation,
        intent=materialization,
        executor=executor,
        docker=docker,
        postgres_prepared=postgres_prepared,
        secret_capability=capability,
        secret_handling=handling,
        wrapper_manifest=wrapper_manifest,
        target_delivery_map=target_delivery_map,
        attach_protocol=attach_protocol,
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
            docker=docker,
            postgres_prepared=postgres_prepared,
            secret_capability=capability,
            secret_handling=handling,
            wrapper_manifest=wrapper_manifest,
            target_delivery_map=target_delivery_map,
            attach_protocol=attach_protocol,
            provider_material_attestation_sha256=_hash("provider-material-attestation"),
            signer=cast(Any, object()),
        )

    swapped_target = target_delivery_map.primary_infisical.model_copy(
        update={"derived_image_policy_sha256": _hash("substituted-derived-image")}
    )
    with pytest.raises(AuthorizationError, match="materialization_control_policy_binding"):
        authorization._verify_materialization_control_policy_bindings(
            allocation_intent=allocation,
            intent=materialization,
            executor=executor,
            docker=docker,
            postgres_prepared=postgres_prepared,
            secret_capability=capability,
            secret_handling=handling,
            wrapper_manifest=wrapper_manifest,
            target_delivery_map=target_delivery_map.model_copy(
                update={"primary_infisical": swapped_target}
            ),
            attach_protocol=attach_protocol,
            provider_material_attestation_sha256=_hash("provider-material-attestation"),
            signer=cast(Any, object()),
        )


def test_materialization_receipt_rejects_cross_attachment_and_publication(tmp_path: Path) -> None:
    allocation, executor, _ = _allocation_bundle(tmp_path)
    allocation_receipt = _allocation_receipt(allocation)
    attestation = _allocation_attestation(allocation, allocation_receipt)
    (
        materialization,
        restore_observation,
        _,
        _,
        wrapper_manifest,
        target_delivery_map,
        attach_protocol,
    ) = _materialization_intent(allocation, executor, allocation_receipt, attestation)
    context = _materialization_context(
        materialization,
        attestation,
        restore_observation,
        wrapper_manifest,
        target_delivery_map,
        attach_protocol,
    )
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


def test_materialization_reconstructs_compact_attach_receipt_before_signature(
    tmp_path: Path,
) -> None:
    """The signed route, not executor-chosen compact fields, defines delivery."""

    allocation, executor, _ = _allocation_bundle(tmp_path)
    allocation_receipt = _allocation_receipt(allocation)
    attestation = _allocation_attestation(allocation, allocation_receipt)
    (
        materialization,
        restore_observation,
        _,
        _,
        wrapper_manifest,
        target_delivery_map,
        attach_protocol,
    ) = _materialization_intent(allocation, executor, allocation_receipt, attestation)
    context = _materialization_context(
        materialization,
        attestation,
        restore_observation,
        wrapper_manifest,
        target_delivery_map,
        attach_protocol,
    )
    receipt = _materialization_receipt(context)
    original = receipt.executor_receipt.containers[0]
    original_attach = original.attach_receipt

    def rebuilt_effect(
        *, request_sha256: str, descriptors_sha256: str
    ) -> MaterializationEffectReceiptV1:
        ack = ContainerAttachTerminalAckV1(
            schema_version="rsd.container-attach-terminal-ack.v1",
            request_sha256=request_sha256,
            state="terminal_ack_v1",
            chunk_count=original_attach.chunk_count,
            chunk_descriptors_sha256=descriptors_sha256,
            chunks_zeroized=True,
            persistence_allowed=False,
            logging_allowed=False,
            receipt_contains_secret=False,
            eof_observed=True,
        )
        altered_attach = ContainerAttachReceiptV1.model_validate(
            {
                **original_attach.model_dump(mode="json"),
                "request_sha256": request_sha256,
                "chunk_descriptors_sha256": descriptors_sha256,
                "terminal_ack_sha256": container_attach_ack_sha256(ack),
            }
        )
        altered_container = ExecutorContainerInspectionV1(
            component=original.component,
            container_id=original.container_id,
            inspection=original.inspection,
            attach_receipt=altered_attach,
            attach_receipt_sha256=container_attach_receipt_sha256(altered_attach),
        )
        altered_executor = receipt.executor_receipt.model_copy(
            update={
                "containers": (
                    altered_container,
                    *receipt.executor_receipt.containers[1:],
                )
            }
        )
        return receipt.model_copy(
            update={
                "executor_receipt": altered_executor,
                "executor_receipt_sha256": canonical_sha256(altered_executor),
            }
        )

    with pytest.raises(AuthorizationError, match="materialization_executor_attach_receipt"):
        authorization._validate_materialization_effect_receipt(
            context,
            rebuilt_effect(
                request_sha256=_hash("substituted-materialization-attach-request"),
                descriptors_sha256=original_attach.chunk_descriptors_sha256,
            ),
        )

    with pytest.raises(AuthorizationError, match="materialization_executor_attach_receipt"):
        authorization._validate_materialization_effect_receipt(
            context,
            rebuilt_effect(
                request_sha256=original_attach.request_sha256,
                descriptors_sha256=_hash("substituted-materialization-attach-descriptors"),
            ),
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
            engine_fingerprint_sha256=docker_engine_fingerprint_sha256(_engine_projection()),
        ),
        executor_attestation_key_id="executor-attestation",
        executor_attestation_public_key_base64=_EXECUTOR_ATTESTATION_PUBLIC_KEY,
        executor_attestation_public_key_fingerprint_sha256=hashlib.sha256(
            _EXECUTOR_ATTESTATION_PUBLIC_BYTES
        ).hexdigest(),
        docker_engine_control_policy_sha256=intent.evidence.docker_engine_control_policy_sha256,
        postgres_control_expectation=PostgreSQLControlExpectationV1(
            authority="postgresql://192.0.2.40:5432",
            maintenance_reference_sha256=_hash("postgres-maintenance"),
            capability_fingerprint_sha256=_hash("postgres-capability"),
        ),
        postgres_prepared_control_policy_sha256=(
            intent.plan.postgres.prepared_control_policy_sha256
        ),
        expected_control_image_local_evidence=_control_image_local_evidence(intent),
        postgres_allocation_prepared_operation_id="123e4567-e89b-42d3-a456-426614174004",
        postgres_allocation_result_projection_sha256=_hash("postgres-allocation-result"),
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
    signer, _, intent, executor, docker, postgres, postgres_prepared, journal, policy, artifact = (
        _signed_allocation_bundle(tmp_path)
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
        docker_engine_control_policy=docker,
        postgres_prepared_control_policy=postgres_prepared,
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
            docker_engine_control_policy=docker,
            postgres_prepared_control_policy=postgres_prepared,
            replay_authority=authority,
            replay_policy=policy,
            replay_policy_artifact=artifact,
        )
    assert authority.calls == 1


def test_v2_allocation_authorization_absent_journal_never_initializes(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    """The execution boundary cannot turn an absent allocation journal into genesis."""

    monkeypatch.setattr(authorization, "_system_utc_clock", lambda: _TEST_CLOCK)
    signer, _, intent, _, _, _, _, journal, policy, _ = _signed_allocation_bundle(tmp_path)
    root = tmp_path / "artifacts"
    root.mkdir(mode=0o700)
    authority = _AtomicReplayAuthority(root=root)

    with pytest.raises(AuthorizationError, match="allocation_journal_absent"):
        authorize_allocation_and_execute(
            AuthorizationPaths(root=root),
            signer=signer,
            allocation_intent=intent,
            provider=cast(Any, object()),
            expected_disposal_owner=_OWNER,
            expected_approver_identity=_APPROVER,
            journal=journal,
            executor=cast(Any, object()),
            executor_control=cast(Any, object()),
            postgres_control=cast(Any, object()),
            replay_authority=authority,
            replay_policy=policy,
        )

    assert journal.migration_status() is AllocationJournalStatus.ABSENT
    assert not journal._path.exists()
    assert authority.calls == 0


def test_allocation_genesis_crash_leaves_a_terminal_pending_state(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    monkeypatch.setattr(authorization, "_system_utc_clock", lambda: _TEST_CLOCK)
    signer, _, intent, executor, docker, postgres, postgres_prepared, journal, policy, artifact = (
        _signed_allocation_bundle(tmp_path)
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
            docker_engine_control_policy=docker,
            postgres_prepared_control_policy=postgres_prepared,
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
            docker_engine_control_policy=docker,
            postgres_prepared_control_policy=postgres_prepared,
            replay_authority=authority,
            replay_policy=policy,
            replay_policy_artifact=artifact,
        )
    assert authority.calls == 1


def test_v2_allocation_journal_unknown_or_legacy_local_state_blocks_without_recreation(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    """An unrelated legacy-shaped database is neither adopted nor migrated by V2."""

    monkeypatch.setattr(authorization, "_system_utc_clock", lambda: _TEST_CLOCK)
    signer, _, intent, executor, docker, postgres, postgres_prepared, journal, policy, artifact = (
        _signed_allocation_bundle(tmp_path)
    )
    connection = sqlite3.connect(journal._path)
    try:
        connection.execute("CREATE TABLE authorization_nonce_journal (nonce TEXT PRIMARY KEY)")
        connection.commit()
    finally:
        connection.close()
    journal._path.chmod(0o600)
    root = tmp_path / "artifacts"
    root.mkdir(mode=0o700)
    authority = _AtomicReplayAuthority()

    assert journal.migration_status() is AllocationJournalStatus.JOURNAL_MISSING
    with pytest.raises(AuthorizationError, match="allocation_journal_replayed"):
        provision_allocation_journal(
            AuthorizationPaths(root=root),
            signer=signer,
            expected_disposal_owner=_OWNER,
            expected_approver_identity=_APPROVER,
            journal=journal,
            intent=intent,
            executor_control_policy=executor,
            postgres_control_policy=postgres,
            docker_engine_control_policy=docker,
            postgres_prepared_control_policy=postgres_prepared,
            replay_authority=authority,
            replay_policy=policy,
            replay_policy_artifact=artifact,
        )
    assert authority.calls == 0
    assert journal._path.exists()


def test_external_allocation_genesis_tombstone_blocks_a_second_local_journal(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    monkeypatch.setattr(authorization, "_system_utc_clock", lambda: _TEST_CLOCK)
    first = tmp_path / "first"
    second = tmp_path / "second"
    first.mkdir(mode=0o700)
    second.mkdir(mode=0o700)
    signer, _, intent, executor, docker, postgres, postgres_prepared, journal, policy, artifact = (
        _signed_allocation_bundle(first)
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
        docker_engine_control_policy=docker,
        postgres_prepared_control_policy=postgres_prepared,
        replay_authority=authority,
        replay_policy=policy,
        replay_policy_artifact=artifact,
    )

    (
        second_signer,
        _,
        second_intent,
        second_executor,
        second_docker,
        second_postgres,
        second_postgres_prepared,
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
            docker_engine_control_policy=second_docker,
            postgres_prepared_control_policy=second_postgres_prepared,
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
    signer, _, intent, executor, docker, postgres, postgres_prepared, journal, policy, artifact = (
        _signed_allocation_bundle(tmp_path)
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
        docker_engine_control_policy=docker,
        postgres_prepared_control_policy=postgres_prepared,
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
    (
        materialization,
        restore_observation,
        _,
        _,
        wrapper_manifest,
        target_delivery_map,
        attach_protocol,
    ) = _materialization_intent(intent, executor, allocation_receipt, attestation)
    materialization_context = _materialization_context(
        materialization,
        attestation,
        restore_observation,
        wrapper_manifest,
        target_delivery_map,
        attach_protocol,
    )
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


def test_v2_artifact_root_lease_rejects_non_owner_mode_and_symlink(
    tmp_path: Path,
) -> None:
    """A V2 boundary never adopts a permissive root or a substituted symlink."""

    root = tmp_path / "artifacts"
    root.mkdir(mode=0o700)
    os.chmod(root, 0o755)
    with (
        pytest.raises(AuthorizationError, match=r"artifact_(root|lock_root)"),
        ArtifactRootLease(root),
    ):
        pytest.fail("a non-owner-only artifact root acquired a lease")

    os.chmod(root, 0o700)
    substituted = tmp_path / "substituted-artifacts"
    substituted.symlink_to(root, target_is_directory=True)
    with (
        pytest.raises(AuthorizationError, match=r"artifact_(root|lock_root)"),
        ArtifactRootLease(substituted),
    ):
        pytest.fail("a symlink artifact root acquired a lease")


def test_provider_and_effect_error_text_is_not_exposed_by_safe_boundary() -> None:
    marker = "value-that-must-not-escape"
    result = authorization._safe_call(lambda: (_ for _ in ()).throw(RuntimeError(marker)))

    assert result is authorization._SAFE_CALL_FAILURE
    assert marker not in repr(result)


def _provisioned_allocation(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> tuple[
    AuthorizationPaths,
    TrustedEd25519SignerV1,
    AllocationIntentV2,
    ExecutorControlPolicyV1,
    PostgreSQLControlPolicyV1,
    SQLiteAllocationJournal,
    ReplayAuthorityPolicyV1,
    _AtomicReplayAuthority,
]:
    """Create a durable V2 allocation fixture through the signed boundary."""

    monkeypatch.setattr(authorization, "_system_utc_clock", lambda: _TEST_CLOCK)
    signer, _, intent, executor, docker, postgres, postgres_prepared, journal, policy, artifact = (
        _signed_allocation_bundle(tmp_path)
    )
    root = tmp_path / "artifacts"
    root.mkdir(mode=0o700)
    paths = AuthorizationPaths(root=root)
    authority = _AtomicReplayAuthority(root=root)
    provision_allocation_journal(
        paths,
        signer=signer,
        expected_disposal_owner=_OWNER,
        expected_approver_identity=_APPROVER,
        journal=journal,
        intent=intent,
        executor_control_policy=executor,
        postgres_control_policy=postgres,
        docker_engine_control_policy=docker,
        postgres_prepared_control_policy=postgres_prepared,
        replay_authority=authority,
        replay_policy=policy,
        replay_policy_artifact=artifact,
    )
    return paths, signer, intent, executor, postgres, journal, policy, authority


def _persisted_allocation_control_policies(
    paths: AuthorizationPaths,
) -> tuple[DockerEngineControlPolicyV1, PostgreSQLPreparedControlPolicyV2]:
    """Reload the signed allocation controls instead of reconstructing them."""

    docker = DockerEngineControlPolicyV1.model_validate(
        yaml.safe_load(
            (paths.root / paths.docker_engine_control_policy_name()).read_text(encoding="utf-8")
        )
    )
    postgres_prepared = PostgreSQLPreparedControlPolicyV2.model_validate(
        yaml.safe_load(
            (paths.root / paths.postgres_prepared_control_policy_name()).read_text(encoding="utf-8")
        )
    )
    return docker, postgres_prepared


def _verified_allocation(
    intent: AllocationIntentV2, nonce: str
) -> authorization._VerifiedAllocation:
    return authorization._VerifiedAllocation(
        context=_allocation_context(intent),
        nonce=nonce,
        authorized_at=_NOW,
        capability=authorization._ALLOCATION_VERIFIED_CAPABILITY,
    )


def test_v2_allocation_operation_replay_rejects_a_fresh_nonce(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    _, _, intent, _, _, journal, _, _ = _provisioned_allocation(tmp_path, monkeypatch)
    verified = _verified_allocation(intent, "first-allocation-nonce")
    receipt = _allocation_receipt(intent).model_copy(
        update={"idempotency_key": verified.context.idempotency_key}
    )

    journal._claim_verified(verified)
    journal._begin_effect(verified)
    journal._commit_effect(verified, receipt)

    assert (
        journal.operation_state(intent.allocation_operation_id)
        is AllocationOperationState.ALLOCATED
    )
    with pytest.raises(AuthorizationError, match="allocation_operation_replayed"):
        journal._claim_verified(_verified_allocation(intent, "fresh-allocation-nonce"))


def test_v2_allocation_claim_is_durable_before_effect_transition(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    """The operation row must become durable before an effect may be marked live."""

    _, _, intent, _, _, journal, _, _ = _provisioned_allocation(tmp_path, monkeypatch)
    verified = _verified_allocation(intent, "claimed-before-effect-nonce")

    assert journal.operation_state(intent.allocation_operation_id) is None
    journal._claim_verified(verified)
    assert (
        journal.operation_state(intent.allocation_operation_id) is AllocationOperationState.CLAIMED
    )

    journal._begin_effect(verified)
    assert (
        journal.operation_state(intent.allocation_operation_id)
        is AllocationOperationState.IN_PROGRESS
    )


def test_v2_allocation_effect_failure_is_terminal_and_never_replays(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    _, _, intent, _, _, journal, _, _ = _provisioned_allocation(tmp_path, monkeypatch)
    verified = _verified_allocation(intent, "failed-allocation-nonce")
    journal._claim_verified(verified)
    journal._begin_effect(verified)
    journal._fail_effect(verified)

    assert (
        journal.operation_state(intent.allocation_operation_id)
        is AllocationOperationState.FAILED_RECOVERY_REQUIRED
    )
    with pytest.raises(AuthorizationError, match="allocation_operation_replayed"):
        journal._claim_verified(_verified_allocation(intent, "retry-allocation-nonce"))
    with pytest.raises(AuthorizationError, match="allocation_operation_state"):
        journal.require_recovery(intent.allocation_operation_id)


def test_v2_materialization_failure_is_terminal_and_never_replays(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    _, _, intent, executor, _, journal, _, _ = _provisioned_allocation(tmp_path, monkeypatch)
    allocation = _verified_allocation(intent, "allocation-nonce")
    allocation_receipt = _allocation_receipt(intent).model_copy(
        update={"idempotency_key": allocation.context.idempotency_key}
    )
    attestation = _allocation_attestation(intent, allocation_receipt)
    verified_intent = authorization._VerifiedAllocationIntent(
        intent=intent,
        intent_sha256=allocation_intent_sha256(intent),
        capability=authorization._ALLOCATION_INTENT_CAPABILITY,
    )
    journal._claim_verified(allocation)
    journal._begin_effect(allocation)
    journal._commit_effect(allocation, allocation_receipt)
    journal.assert_committed_allocation_stage(verified_intent, allocation_receipt, attestation)
    (
        materialization,
        restore_observation,
        _,
        _,
        wrapper_manifest,
        target_delivery_map,
        attach_protocol,
    ) = _materialization_intent(intent, executor, allocation_receipt, attestation)
    context = _materialization_context(
        materialization,
        attestation,
        restore_observation,
        wrapper_manifest,
        target_delivery_map,
        attach_protocol,
    )
    verified = authorization._VerifiedMaterialization(
        context=context,
        nonce="failed-materialization-nonce",
        authorized_at=_NOW,
        capability=authorization._MATERIALIZATION_VERIFIED_CAPABILITY,
    )
    journal._claim_materialization_verified(verified)
    journal._begin_materialization_effect(verified)
    journal._fail_materialization_effect(verified)

    assert (
        journal.materialization_operation_state(materialization.materialization_operation_id)
        is MaterializationOperationState.FAILED_RECOVERY_REQUIRED
    )
    with pytest.raises(AuthorizationError, match="materialization_operation_replayed"):
        journal._claim_materialization_verified(
            authorization._VerifiedMaterialization(
                context=context,
                nonce="retry-materialization-nonce",
                authorized_at=_NOW,
                capability=authorization._MATERIALIZATION_VERIFIED_CAPABILITY,
            )
        )


def test_v2_external_tombstone_blocks_a_local_operation_row_rollback(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    _, _, intent, _, _, journal, policy, authority = _provisioned_allocation(tmp_path, monkeypatch)
    verified = _verified_allocation(intent, "rollback-allocation-nonce")
    tombstone = authorization._allocation_operation_tombstone(policy, verified)
    authorization._claim_replay_tombstone(
        authority, tombstone, phase="allocation_replay_authority_replayed"
    )
    journal._claim_verified(verified)

    connection = sqlite3.connect(journal._path)
    try:
        connection.execute("DELETE FROM allocation_operation_journal")
        connection.commit()
    finally:
        connection.close()

    with pytest.raises(AuthorizationError, match="allocation_replay_authority_replayed"):
        authorization._claim_replay_tombstone(
            authority,
            authorization._allocation_operation_tombstone(
                policy, _verified_allocation(intent, "rollback-fresh-nonce")
            ),
            phase="allocation_replay_authority_replayed",
        )


def test_v2_allocation_genesis_crash_after_tombstone_is_not_retried(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    monkeypatch.setattr(authorization, "_system_utc_clock", lambda: _TEST_CLOCK)
    signer, _, intent, executor, docker, postgres, postgres_prepared, journal, policy, artifact = (
        _signed_allocation_bundle(tmp_path)
    )
    root = tmp_path / "artifacts"
    root.mkdir(mode=0o700)
    paths = AuthorizationPaths(root=root)
    authority = _AtomicReplayAuthority(root=root)
    original = ArtifactRootLease.write_once

    def fail_intent(lease: ArtifactRootLease, name: str, payload: bytes, *, phase: str) -> None:
        if name == paths.allocation_intent_name():
            raise AuthorizationError("simulated_crash")
        original(lease, name, payload, phase=phase)

    monkeypatch.setattr(ArtifactRootLease, "write_once", fail_intent)
    with pytest.raises(AuthorizationError, match="simulated_crash"):
        provision_allocation_journal(
            paths,
            signer=signer,
            expected_disposal_owner=_OWNER,
            expected_approver_identity=_APPROVER,
            journal=journal,
            intent=intent,
            executor_control_policy=executor,
            postgres_control_policy=postgres,
            docker_engine_control_policy=docker,
            postgres_prepared_control_policy=postgres_prepared,
            replay_authority=authority,
            replay_policy=policy,
            replay_policy_artifact=artifact,
        )
    assert authority.calls == 1
    assert journal.migration_status() is AllocationJournalStatus.PROVISIONING_INCOMPLETE
    assert (root / paths.replay_policy_name()).is_file()
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
            docker_engine_control_policy=docker,
            postgres_prepared_control_policy=postgres_prepared,
            replay_authority=authority,
            replay_policy=policy,
            replay_policy_artifact=artifact,
        )


def test_v2_artifact_root_replacement_and_lock_unlink_block_stability(tmp_path: Path) -> None:
    root = tmp_path / "artifacts"
    root.mkdir(mode=0o700)
    with ArtifactRootLease(root) as lease:
        displaced = tmp_path / "displaced-artifacts"
        root.rename(displaced)
        root.mkdir(mode=0o700)
        with pytest.raises(AuthorizationError, match="artifact_lock_root"):
            lease.assert_stable()

    shutil.rmtree(root)
    root.mkdir(mode=0o700)
    with ArtifactRootLease(root) as lease:
        assert lease._parent is not None
        assert lease._lock_name is not None
        (lease._parent / lease._lock_name).unlink()
        with pytest.raises(AuthorizationError, match="artifact_lock_file"):
            lease.assert_stable()


def test_v2_artifact_lock_rejects_a_cooperating_thread_without_waiting(tmp_path: Path) -> None:
    root = tmp_path / "artifacts"
    root.mkdir(mode=0o700)
    with ArtifactRootLease(root), ThreadPoolExecutor(max_workers=1) as executor:
        future = executor.submit(lambda: ArtifactRootLease(root).__enter__())
        with pytest.raises(AuthorizationError, match="artifact_lock_busy"):
            future.result()


def test_v2_artifact_lock_rejects_a_competing_process_without_waiting(tmp_path: Path) -> None:
    root = tmp_path / "artifacts"
    root.mkdir(mode=0o700)
    context = multiprocessing.get_context("spawn")
    queue = context.Queue()
    contender = context.Process(target=_try_artifact_root_lock, args=(str(root), queue))

    with ArtifactRootLease(root):
        contender.start()
        assert queue.get(timeout=10) == "artifact_lock_busy"
        contender.join(timeout=10)
    assert contender.exitcode == 0


def test_v2_artifact_lock_converges_case_variants_by_opened_root_identity(
    tmp_path: Path,
) -> None:
    root = tmp_path / "artifact-root"
    root.mkdir(mode=0o700)
    variant = root.with_name(root.name.swapcase())
    if not variant.exists():
        pytest.skip("filesystem does not resolve spelling variants to one inode")

    with ArtifactRootLease(root), ThreadPoolExecutor(max_workers=1) as executor:
        contender = executor.submit(lambda: ArtifactRootLease(variant).__enter__())
        with pytest.raises(AuthorizationError, match="artifact_lock_busy"):
            contender.result()


def test_v2_provider_snapshot_change_is_not_a_stable_provenance_commitment(tmp_path: Path) -> None:
    intent, _, _ = _allocation_bundle(tmp_path)
    fingerprints = {
        reference.reference_sha256: _hash(reference.account)
        for reference in intent.provider_references.all()
    }

    class Lease:
        changed = False

        def inspect(self, reference: ProviderReferenceV1) -> ProviderProvenance:
            return ProviderProvenance(
                provider=reference.provider,
                service=reference.service,
                account=reference.account,
                version=reference.version,
                reference_sha256=reference.reference_sha256,
                fingerprint_sha256=fingerprints[reference.reference_sha256],
            )

        def recheck(self, reference: ProviderReferenceV1) -> ProviderProvenance:
            fingerprint = fingerprints[reference.reference_sha256]
            if not self.changed:
                self.changed = True
                fingerprint = _hash("changed-provider-fingerprint")
            return ProviderProvenance(
                provider=reference.provider,
                service=reference.service,
                account=reference.account,
                version=reference.version,
                reference_sha256=reference.reference_sha256,
                fingerprint_sha256=fingerprint,
            )

    lease = Lease()
    authorization._provider_commitment(
        references=intent.provider_references.all(),
        lease=lease,
        fingerprints=fingerprints,
        recheck=False,
    )
    with pytest.raises(AuthorizationError, match="provider_provenance"):
        authorization._provider_commitment(
            references=intent.provider_references.all(),
            lease=lease,
            fingerprints=fingerprints,
            recheck=True,
        )


def test_v2_sidecar_swap_marker_tamper_and_noncanonical_signature_block() -> None:
    signer, key = _trusted_signer()
    artifact_name = "proposal.yaml"
    artifact = b'{"field":"value"}'
    signed_content_sha256 = hashlib.sha256(
        authorization._canonical_signed_content(artifact_name, artifact)
    ).hexdigest()
    signature = key.sign(authorization._signature_message(artifact_name, signed_content_sha256))
    sidecar = DetachedAuthorizationSignatureV1(
        schema_version="rsd.authorization-signature.v3",
        algorithm="ed25519",
        artifact_name=artifact_name,
        artifact_sha256=hashlib.sha256(artifact).hexdigest(),
        signed_content_sha256=signed_content_sha256,
        signer_key_id=signer.key_id,
        signature_base64=base64.b64encode(signature).decode("ascii"),
    )
    assert (
        authorization._verify_signature(
            sidecar=sidecar, artifact_name=artifact_name, artifact=artifact, signer=signer
        )
        == signature
    )
    with pytest.raises(AuthorizationError, match="signature_binding"):
        authorization._verify_signature(
            sidecar=sidecar.model_copy(update={"artifact_name": "runtime-contract.yaml"}),
            artifact_name=artifact_name,
            artifact=artifact,
            signer=signer,
        )
    alphabet = b"ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/"
    alias = bytearray(sidecar.signature_base64.encode("ascii"))
    index = alphabet.index(alias[-3])
    alias[-3] = alphabet[(index & 0b110000) | ((index + 1) & 0b001111)]
    with pytest.raises(AuthorizationError, match="signature_verification"):
        authorization._verify_signature(
            sidecar=sidecar.model_copy(update={"signature_base64": alias.decode("ascii")}),
            artifact_name=artifact_name,
            artifact=artifact,
            signer=signer,
        )
    marker = type(
        "MarkedEvidence",
        (),
        {
            "signature": DetachedSignatureV1(
                algorithm="ed25519-detached-v1",
                signer_key_id=signer.key_id,
                signer_public_key_fingerprint_sha256=signer.public_key_fingerprint_sha256,
                detached_signature_sha256=_hash("tampered-marker"),
            )
        },
    )()
    with pytest.raises(AuthorizationError, match="signature_marker"):
        authorization._verify_embedded_marker(signature=signature, model=marker, signer=signer)


def _authorization_sidecar_fixture() -> tuple[
    TrustedEd25519SignerV1,
    bytes,
    bytes,
    DetachedAuthorizationSignatureV1,
]:
    signer, key = _trusted_signer()
    artifact_name = "proposal.yaml"
    artifact = b'{"field":"value"}'
    signed_content_sha256 = hashlib.sha256(
        authorization._canonical_signed_content(artifact_name, artifact)
    ).hexdigest()
    signature = key.sign(authorization._signature_message(artifact_name, signed_content_sha256))
    sidecar = DetachedAuthorizationSignatureV1(
        schema_version="rsd.authorization-signature.v3",
        algorithm="ed25519",
        artifact_name=artifact_name,
        artifact_sha256=hashlib.sha256(artifact).hexdigest(),
        signed_content_sha256=signed_content_sha256,
        signer_key_id=signer.key_id,
        signature_base64=base64.b64encode(signature).decode("ascii"),
    )
    return signer, artifact, signature, sidecar


def test_v2_marker_only_signature_metadata_cannot_authorize_artifact() -> None:
    """The embedded marker must name a verified detached signature digest."""

    signer, _artifact, signature, _sidecar = _authorization_sidecar_fixture()
    marker = type(
        "MarkedEvidence",
        (),
        {
            "signature": DetachedSignatureV1(
                algorithm="ed25519-detached-v1",
                signer_key_id=signer.key_id,
                signer_public_key_fingerprint_sha256=signer.public_key_fingerprint_sha256,
                detached_signature_sha256=_hash("marker-only-metadata"),
            )
        },
    )()

    with pytest.raises(AuthorizationError, match="signature_marker"):
        authorization._verify_embedded_marker(signature=signature, model=marker, signer=signer)


def test_v2_sidecar_swap_and_noncanonical_signature_alias_are_rejected() -> None:
    """A valid signature cannot be reused under another artifact or spelling."""

    signer, artifact, _signature, sidecar = _authorization_sidecar_fixture()
    with pytest.raises(AuthorizationError, match="signature_binding"):
        authorization._verify_signature(
            sidecar=sidecar.model_copy(update={"artifact_name": "runtime-contract.yaml"}),
            artifact_name="proposal.yaml",
            artifact=artifact,
            signer=signer,
        )
    alphabet = b"ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/"
    alias = bytearray(sidecar.signature_base64.encode("ascii"))
    index = alphabet.index(alias[-3])
    alias[-3] = alphabet[(index & 0b110000) | ((index + 1) & 0b001111)]
    with pytest.raises(AuthorizationError, match="signature_verification"):
        authorization._verify_signature(
            sidecar=sidecar.model_copy(update={"signature_base64": alias.decode("ascii")}),
            artifact_name="proposal.yaml",
            artifact=artifact,
            signer=signer,
        )


def test_v2_owner_and_approval_mismatch_block_before_provisioning(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    signer, _, intent, executor, docker, postgres, postgres_prepared, journal, policy, artifact = (
        _signed_allocation_bundle(tmp_path)
    )
    root = tmp_path / "artifacts"
    paths = AuthorizationPaths(root=root)
    authority = _AtomicReplayAuthority()
    monkeypatch.setattr(authorization, "_system_utc_clock", lambda: _TEST_CLOCK)
    with pytest.raises(AuthorizationError, match="allocation_intent_freshness"):
        provision_allocation_journal(
            paths,
            signer=signer,
            expected_disposal_owner="other-owner@example.test",
            expected_approver_identity=_APPROVER,
            journal=journal,
            intent=intent,
            executor_control_policy=executor,
            postgres_control_policy=postgres,
            docker_engine_control_policy=docker,
            postgres_prepared_control_policy=postgres_prepared,
            replay_authority=authority,
            replay_policy=policy,
            replay_policy_artifact=artifact,
        )
    assert not root.exists()
    assert authority.calls == 0
    with pytest.raises(AuthorizationError, match="allocation_intent_freshness"):
        provision_allocation_journal(
            paths,
            signer=signer,
            expected_disposal_owner=_OWNER,
            expected_approver_identity="other-approver@example.test",
            journal=journal,
            intent=intent,
            executor_control_policy=executor,
            postgres_control_policy=postgres,
            docker_engine_control_policy=docker,
            postgres_prepared_control_policy=postgres_prepared,
            replay_authority=authority,
            replay_policy=policy,
            replay_policy_artifact=artifact,
        )
    assert not root.exists()
    assert authority.calls == 0


def test_v2_historical_time_blocks_allocation_provisioning(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    """The internal current-time read cannot be rewound through a public argument."""

    signer, _, intent, executor, docker, postgres, postgres_prepared, journal, policy, artifact = (
        _signed_allocation_bundle(tmp_path)
    )
    root = tmp_path / "artifacts"
    authority = _AtomicReplayAuthority()
    monkeypatch.setattr(
        authorization, "_system_utc_clock", lambda: datetime(2030, 1, 1, tzinfo=UTC)
    )
    with pytest.raises(AuthorizationError, match="allocation_intent_freshness"):
        provision_allocation_journal(
            AuthorizationPaths(root=root),
            signer=signer,
            expected_disposal_owner=_OWNER,
            expected_approver_identity=_APPROVER,
            journal=journal,
            intent=intent,
            executor_control_policy=executor,
            postgres_control_policy=postgres,
            docker_engine_control_policy=docker,
            postgres_prepared_control_policy=postgres_prepared,
            replay_authority=authority,
            replay_policy=policy,
            replay_policy_artifact=artifact,
        )
    assert not root.exists()
    assert authority.calls == 0


def test_v2_missing_replay_authority_blocks_before_journal_provisioning(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    signer, _, intent, executor, docker, postgres, postgres_prepared, journal, policy, artifact = (
        _signed_allocation_bundle(tmp_path)
    )
    root = tmp_path / "artifacts"
    paths = AuthorizationPaths(root=root)
    monkeypatch.setattr(authorization, "_system_utc_clock", lambda: _TEST_CLOCK)

    with pytest.raises(AuthorizationError, match="replay_authority_failure"):
        provision_allocation_journal(
            paths,
            signer=signer,
            expected_disposal_owner=_OWNER,
            expected_approver_identity=_APPROVER,
            journal=journal,
            intent=intent,
            executor_control_policy=executor,
            postgres_control_policy=postgres,
            docker_engine_control_policy=docker,
            postgres_prepared_control_policy=postgres_prepared,
            replay_authority=cast(Any, object()),
            replay_policy=policy,
            replay_policy_artifact=artifact,
        )
    assert not root.exists()


def test_v2_replay_policy_substitution_blocks_before_external_claim(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    signer, _, intent, executor, docker, postgres, postgres_prepared, journal, policy, artifact = (
        _signed_allocation_bundle(tmp_path)
    )
    root = tmp_path / "artifacts"
    root.mkdir(mode=0o700)
    paths = AuthorizationPaths(root=root)
    monkeypatch.setattr(authorization, "_system_utc_clock", lambda: _TEST_CLOCK)

    (root / paths.replay_policy_name()).write_bytes(b"substituted-policy")
    (root / paths.replay_policy_name()).chmod(0o600)
    authority = _AtomicReplayAuthority()
    with pytest.raises(AuthorizationError, match="replay_policy_artifact"):
        provision_allocation_journal(
            paths,
            signer=signer,
            expected_disposal_owner=_OWNER,
            expected_approver_identity=_APPROVER,
            journal=journal,
            intent=intent,
            executor_control_policy=executor,
            postgres_control_policy=postgres,
            docker_engine_control_policy=docker,
            postgres_prepared_control_policy=postgres_prepared,
            replay_authority=authority,
            replay_policy=policy,
            replay_policy_artifact=artifact,
        )
    assert authority.calls == 0


def test_v2_keychain_replay_authority_is_create_only_and_stores_hashes(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    _, _, intent, _, _, _, _, _, policy, _ = _signed_allocation_bundle(tmp_path)
    verified = authorization._VerifiedAllocationIntent(
        intent=intent,
        intent_sha256=allocation_intent_sha256(intent),
        capability=authorization._ALLOCATION_INTENT_CAPABILITY,
    )
    tombstone = authorization._allocation_genesis_tombstone(policy, verified)

    class Store:
        def __init__(self) -> None:
            self.records: dict[tuple[str, str], bytes] = {}

        def add_if_absent(self, service: str, account: str, value: bytes) -> bytes | None:
            assert len(value) == 64
            assert all(character in b"0123456789abcdef" for character in value)
            key = (service, account)
            existing = self.records.get(key)
            if existing is None:
                self.records[key] = value
            return existing

    store = Store()
    authority = MacOSKeychainReplayAuthority(policy, _store=store)
    assert authority.claim_once(tombstone) is ReplayAuthorityClaimResult.CREATED
    assert authority.claim_once(tombstone) is ReplayAuthorityClaimResult.DUPLICATE_SAME
    conflicting = tombstone.model_copy(
        update={"journal_genesis_id": "123e4567-e89b-42d3-a456-426614174099"}
    )
    assert authority.claim_once(conflicting) is ReplayAuthorityClaimResult.DUPLICATE_CONFLICT
    assert store.records == {(tombstone.service, tombstone.account): tombstone.value_bytes()}


def test_v2_external_replay_claim_is_atomic_across_processes(tmp_path: Path) -> None:
    """An external create-once adapter admits exactly one concurrent claim."""

    _, _, intent, _, _, _, _, _, policy, _ = _signed_allocation_bundle(tmp_path)
    verified = authorization._VerifiedAllocationIntent(
        intent=intent,
        intent_sha256=allocation_intent_sha256(intent),
        capability=authorization._ALLOCATION_INTENT_CAPABILITY,
    )
    tombstone = authorization._allocation_genesis_tombstone(policy, verified)
    root = tmp_path / "external-replay"
    root.mkdir(mode=0o700)
    context = multiprocessing.get_context("spawn")
    start = context.Event()
    queue = context.Queue()
    workers = [
        context.Process(
            target=_claim_file_replay_tombstone,
            args=(str(root), tombstone.model_dump(mode="python"), start, queue),
        )
        for _ in range(2)
    ]
    for worker in workers:
        worker.start()
    start.set()
    results = sorted(queue.get(timeout=10) for _ in workers)
    for worker in workers:
        worker.join(timeout=10)

    assert results == ["created", "duplicate_same"]
    assert all(worker.exitcode == 0 for worker in workers)


def test_v2_replay_authority_errors_are_redacted_and_block_the_claim(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    _, _, intent, _, _, _, _, _, policy, _ = _signed_allocation_bundle(tmp_path)
    verified = authorization._VerifiedAllocationIntent(
        intent=intent,
        intent_sha256=allocation_intent_sha256(intent),
        capability=authorization._ALLOCATION_INTENT_CAPABILITY,
    )

    class FailingAuthority:
        def claim_once(self, tombstone: ReplayTombstoneV1) -> ReplayAuthorityClaimResult:
            del tombstone
            raise RuntimeError("provider-secret-value-must-not-escape")

    with pytest.raises(AuthorizationError, match="replay_authority_failure") as caught:
        authorization._claim_replay_tombstone(
            FailingAuthority(),
            authorization._allocation_genesis_tombstone(policy, verified),
            phase="allocation_journal_replayed",
        )
    assert "provider-secret-value-must-not-escape" not in str(caught.value)
    assert caught.value.__cause__ is None
    assert caught.value.__context__ is None


def test_v2_forged_allocation_grant_cannot_reach_the_journal(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    _, _, intent, _, _, journal, _, _ = _provisioned_allocation(tmp_path, monkeypatch)
    verified = _verified_allocation(intent, "forged-allocation-nonce")
    forged = authorization._VerifiedAllocation(
        context=verified.context,
        nonce=verified.nonce,
        authorized_at=verified.authorized_at,
        capability=object(),
    )

    with pytest.raises(AuthorizationError, match="allocation_journal"):
        journal._claim_verified(forged)
    assert journal.operation_state(intent.allocation_operation_id) is None


def test_v2_recovery_cannot_race_a_live_allocation_effect(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    _, _, intent, _, _, journal, _, _ = _provisioned_allocation(tmp_path, monkeypatch)
    verified = _verified_allocation(intent, "live-allocation-nonce")
    journal._claim_verified(verified)
    context = multiprocessing.get_context("spawn")
    acquired = context.Event()
    release = context.Event()
    process = context.Process(
        target=_hold_allocation_operation_lease,
        args=(str(journal._path), intent.allocation_operation_id, acquired, release),
    )
    process.start()
    try:
        assert acquired.wait(timeout=10)
        with pytest.raises(AuthorizationError, match="operation_live"):
            journal.require_recovery(intent.allocation_operation_id)
    finally:
        release.set()
        process.join(timeout=10)
    assert process.exitcode == 0
    assert journal.require_recovery(intent.allocation_operation_id) is (
        AllocationOperationState.FAILED_RECOVERY_REQUIRED
    )


def test_v2_allocation_journal_pair_removal_never_recreates_replay_protection(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    """Removing the local database-and-anchor pair cannot reopen allocation."""

    paths, signer, intent, executor, postgres, journal, policy, authority = _provisioned_allocation(
        tmp_path, monkeypatch
    )
    docker, postgres_prepared = _persisted_allocation_control_policies(paths)
    journal._path.unlink()
    journal._anchor_path().unlink()

    assert journal.migration_status() is AllocationJournalStatus.JOURNAL_MISSING
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
            docker_engine_control_policy=docker,
            postgres_prepared_control_policy=postgres_prepared,
            replay_authority=authority,
            replay_policy=policy,
            replay_policy_artifact=ReplayAuthorityPolicyArtifactV1.model_validate(
                yaml.safe_load(
                    (paths.root / paths.replay_policy_name()).read_text(encoding="utf-8")
                )
            ),
        )
    assert authority.calls == 1


def test_v2_allocation_journal_marker_removal_blocks_without_recreation(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    """A removed signed marker cannot make a completed genesis provisionable again."""

    paths, signer, intent, executor, postgres, journal, policy, authority = _provisioned_allocation(
        tmp_path, monkeypatch
    )
    docker, postgres_prepared = _persisted_allocation_control_policies(paths)
    journal._marker_path().unlink()

    assert journal.migration_status() is AllocationJournalStatus.JOURNAL_MISSING
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
            docker_engine_control_policy=docker,
            postgres_prepared_control_policy=postgres_prepared,
            replay_authority=authority,
            replay_policy=policy,
            replay_policy_artifact=ReplayAuthorityPolicyArtifactV1.model_validate(
                yaml.safe_load(
                    (paths.root / paths.replay_policy_name()).read_text(encoding="utf-8")
                )
            ),
        )
    assert authority.calls == 1


def test_v2_signed_journal_intent_mismatch_is_not_a_second_provisioning(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    """A separately valid signature cannot rotate a current allocation journal."""

    monkeypatch.setattr(authorization, "_system_utc_clock", lambda: _TEST_CLOCK)
    (
        signer,
        key,
        intent,
        executor,
        docker,
        postgres,
        postgres_prepared,
        journal,
        policy,
        artifact,
    ) = _signed_allocation_bundle(tmp_path)
    root = tmp_path / "artifacts"
    root.mkdir(mode=0o700)
    paths = AuthorizationPaths(root=root)
    authority = _AtomicReplayAuthority(root=root)
    provision_allocation_journal(
        paths,
        signer=signer,
        expected_disposal_owner=_OWNER,
        expected_approver_identity=_APPROVER,
        journal=journal,
        intent=intent,
        executor_control_policy=executor,
        postgres_control_policy=postgres,
        docker_engine_control_policy=docker,
        postgres_prepared_control_policy=postgres_prepared,
        replay_authority=authority,
        replay_policy=policy,
        replay_policy_artifact=artifact,
    )
    unsigned = intent.model_copy(
        update={
            "journal_uuid": "123e4567-e89b-42d3-a456-426614174099",
            "signature_base64": base64.b64encode(b"0" * 64).decode("ascii"),
        }
    )
    mismatched = unsigned.model_copy(
        update={
            "signature_base64": base64.b64encode(
                key.sign(authorization._allocation_intent_message(unsigned))
            ).decode("ascii")
        }
    )

    with pytest.raises(AuthorizationError, match="replay_policy_artifact"):
        provision_allocation_journal(
            paths,
            signer=signer,
            expected_disposal_owner=_OWNER,
            expected_approver_identity=_APPROVER,
            journal=journal,
            intent=mismatched,
            executor_control_policy=executor,
            postgres_control_policy=postgres,
            docker_engine_control_policy=docker,
            postgres_prepared_control_policy=postgres_prepared,
            replay_authority=authority,
            replay_policy=policy,
            replay_policy_artifact=artifact,
        )
    assert authority.calls == 1


def test_v2_allocation_genesis_recovery_requires_a_signed_nonretry_receipt(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    """A crash can be abandoned only by a signer-approved recovery record."""

    monkeypatch.setattr(authorization, "_system_utc_clock", lambda: _TEST_CLOCK)
    (
        signer,
        key,
        intent,
        executor,
        docker,
        postgres,
        postgres_prepared,
        journal,
        policy,
        artifact,
    ) = _signed_allocation_bundle(tmp_path)
    root = tmp_path / "artifacts"
    root.mkdir(mode=0o700)
    paths = AuthorizationPaths(root=root)
    authority = _AtomicReplayAuthority(root=root)
    monkeypatch.setattr(
        journal,
        "_complete_verified_intent",
        lambda _verified: (_ for _ in ()).throw(AuthorizationError("simulated_crash")),
    )
    with pytest.raises(AuthorizationError, match="simulated_crash"):
        provision_allocation_journal(
            paths,
            signer=signer,
            expected_disposal_owner=_OWNER,
            expected_approver_identity=_APPROVER,
            journal=journal,
            intent=intent,
            executor_control_policy=executor,
            postgres_control_policy=postgres,
            docker_engine_control_policy=docker,
            postgres_prepared_control_policy=postgres_prepared,
            replay_authority=authority,
            replay_policy=policy,
            replay_policy_artifact=artifact,
        )
    unsigned = AllocationJournalGenesisReconciliationReceiptV1(
        schema_version="rsd.allocation-journal-genesis-reconciliation.v1",
        outcome="provisioning_abandoned",
        journal_uuid=intent.journal_uuid,
        journal_path_sha256=intent.journal_path_sha256,
        intent_sha256=allocation_intent_sha256(intent),
        created_at=_NOW,
        signer_key_id=signer.key_id,
        signature_base64=base64.b64encode(b"0" * 64).decode("ascii"),
    )
    with pytest.raises(AuthorizationError, match="allocation_journal_reconciliation_signature"):
        reconcile_allocation_journal_genesis(journal, unsigned, signer=signer)
    signed = unsigned.model_copy(
        update={
            "signature_base64": base64.b64encode(
                key.sign(authorization._allocation_journal_genesis_reconciliation_message(unsigned))
            ).decode("ascii")
        }
    )

    assert reconcile_allocation_journal_genesis(journal, signed, signer=signer) is (
        AllocationJournalStatus.ABANDONED
    )
    assert authority.calls == 1


def test_v2_allocation_journal_execution_pin_is_stable_before_effect(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    """The effect boundary records all durable identity objects before execution."""

    _, _, _, _, _, journal, _, _ = _provisioned_allocation(tmp_path, monkeypatch)
    pin = journal._pin_execution_identity()

    assert pin.database_details[2] == pin.anchor_details[2] == pin.marker_details[2] == 1
    journal._assert_pinned_execution_identity(pin)


def test_v2_pinned_allocation_journal_identity_blocks_anchor_replacement(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    _, _, _, _, _, journal, _, _ = _provisioned_allocation(tmp_path, monkeypatch)
    pin = journal._pin_execution_identity()
    anchor = journal._anchor_path()
    displaced = anchor.with_name(f"{anchor.name}.displaced")
    anchor.rename(displaced)
    anchor.write_bytes(displaced.read_bytes())
    anchor.chmod(0o600)

    with pytest.raises(AuthorizationError, match="allocation_journal_identity_pinned"):
        journal._assert_pinned_execution_identity(pin)


def test_v2_pinned_allocation_journal_identity_blocks_anchor_removal(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    """Removing the anchor after the pre-effect snapshot cannot degrade to absence."""

    _, _, _, _, _, journal, _, _ = _provisioned_allocation(tmp_path, monkeypatch)
    pin = journal._pin_execution_identity()
    journal._anchor_path().unlink()

    with pytest.raises(AuthorizationError, match="allocation_journal_identity_pinned"):
        journal._assert_pinned_execution_identity(pin)


def test_v2_allocation_terminal_pin_blocks_marker_replacement_before_commit(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    """A terminal transition cannot follow replacement of the signed marker."""

    _, _, intent, _, _, journal, _, _ = _provisioned_allocation(tmp_path, monkeypatch)
    verified = _verified_allocation(intent, "marker-replacement-nonce")
    journal._claim_verified(verified)
    journal._begin_effect(verified)
    pin = journal._pin_execution_identity()
    marker = journal._marker_path()
    displaced = marker.with_name(f"{marker.name}.displaced")
    marker.rename(displaced)
    marker.write_bytes(displaced.read_bytes())
    marker.chmod(0o600)

    with pytest.raises(AuthorizationError, match="allocation_journal_identity_pinned"):
        journal._assert_pinned_execution_identity(pin)
    assert (
        journal.operation_state(intent.allocation_operation_id)
        is AllocationOperationState.IN_PROGRESS
    )


def test_v2_pinned_allocation_journal_identity_blocks_database_replacement(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    """A new database inode cannot be committed under a previously pinned journal."""

    _, _, _, _, _, journal, _, _ = _provisioned_allocation(tmp_path, monkeypatch)
    pin = journal._pin_execution_identity()
    database = journal._path
    displaced = database.with_name(f"{database.name}.displaced")
    database.rename(displaced)
    database.write_bytes(displaced.read_bytes())
    database.chmod(0o600)

    with pytest.raises(AuthorizationError, match="allocation_journal_identity_pinned"):
        journal._assert_pinned_execution_identity(pin)


@pytest.mark.parametrize(
    "profile",
    (
        DisposableTransportProfile.TLS_VERIFIED,
        "tls_verified_v1",
        _TLSProfileAlias("tls_verified_v1"),
    ),
)
def test_v2_tls_type_drift_blocks_provisioning_before_root_or_tombstone(
    profile: object, tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    signer, _, intent, executor, docker, postgres, postgres_prepared, journal, policy, artifact = (
        _signed_allocation_bundle(tmp_path)
    )
    drift = intent.model_construct(
        **{
            **intent.model_dump(mode="python"),
            "plan": intent.plan.model_construct(
                **{
                    **intent.plan.model_dump(mode="python"),
                    "transport": intent.plan.transport.model_construct(
                        **{
                            **intent.plan.transport.model_dump(mode="python"),
                            "profile": profile,
                        }
                    ),
                }
            ),
        }
    )
    root = tmp_path / "absent-artifacts"
    authority = _AtomicReplayAuthority()
    monkeypatch.setattr(authorization, "_system_utc_clock", lambda: _TEST_CLOCK)
    with pytest.raises(AuthorizationError, match="allocation_intent_artifact"):
        provision_allocation_journal(
            AuthorizationPaths(root=root),
            signer=signer,
            expected_disposal_owner=_OWNER,
            expected_approver_identity=_APPROVER,
            journal=journal,
            intent=drift,
            executor_control_policy=executor,
            postgres_control_policy=postgres,
            docker_engine_control_policy=docker,
            postgres_prepared_control_policy=postgres_prepared,
            replay_authority=authority,
            replay_policy=policy,
            replay_policy_artifact=artifact,
        )
    assert not root.exists()
    assert authority.calls == 0
