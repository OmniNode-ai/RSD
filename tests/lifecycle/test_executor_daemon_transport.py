"""Adversarial offline tests for the remote-executor daemon boundary.

These tests use only in-memory frame sources, a provisioned temporary journal,
and typed fakes.  They never contact a host, launch a process, or invoke an
engine/provider.
"""

from __future__ import annotations

import base64
import hashlib
import io
import json
import sqlite3
import stat
import traceback
from datetime import UTC, datetime
from pathlib import Path
from types import SimpleNamespace
from typing import cast
from uuid import UUID

import pytest
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey

import omninode_rsd.lifecycle.executor_daemon as daemon
import omninode_rsd.lifecycle.executor_transport as transport
from omninode_rsd.lifecycle.executor_daemon import (
    AllocationExecutorBackendContextV1,
    ExecutorAllocationBackendEvidenceV1,
    ExecutorBackendContextV2,
    ExecutorBackendReceiptV2,
    ExecutorDaemonError,
    ExecutorDaemonSessionEngine,
    ExecutorRecoveryReceiptV2,
    ExecutorSecretSink,
    ExecutorSessionJournal,
    ExecutorSessionStateV2,
    MemorySafetyLease,
)
from omninode_rsd.lifecycle.executor_transport import (
    ExecutorAllocationTransportReceiptV1,
    ExecutorAllocationTransportRequestV1,
    ExecutorClientHelloV2,
    ExecutorHelloV2,
    ExecutorTransportPolicyV2,
    ExecutorTransportReceiptV2,
    ExecutorTransportRequestV2,
    RemoteEffectAuthorizationWitnessV1,
    SecureShellIdentityReferenceV1,
)
from omninode_rsd.lifecycle.infisical_disposable import (
    AllocatedNetworkObservationV1,
    AllocatedPostgreSQLObservationV1,
    AllocatedResourceSetV2,
    AllocatedVolumeObservationV1,
    AllocationExecutorReceiptV1,
    ContainerBootstrapInspectionV1,
    ContainerSecretSinkV1,
    DockerEngineFilteredProjectionV1,
    DockerImagePolicyV1,
    DockerNamedVolumeMountV1,
    EngineIdentityObservationV1,
    ExecutorContainerInspectionV1,
    ExecutorIdentityV1,
    ExecutorInstallationPolicyV1,
    ExecutorInstallationReceiptV1,
    ImageReferenceV1,
    MaterializationExecutorReceiptV1,
    NoHostPublicationGroundworkV1,
    PostgreSQLGrantObservationV1,
    PostgreSQLRoleObservationV1,
    SecretDeliverySinkV1,
    SecretDeliverySlotV1,
    SSHConnectionPolicyV1,
    StartRuntimeExecutorReceiptV2,
    canonical_sha256,
    docker_engine_fingerprint_sha256,
    docker_volume_instance_fingerprint_sha256,
)
from omninode_rsd.lifecycle.provider_crypto import (
    SignerGenesisV1,
    executor_allocation_metadata_message,
)
from omninode_rsd.lifecycle.transport import CanonicalFrameWriter, read_raw_transport

_NOW = datetime(2026, 8, 28, 12, 0, tzinfo=UTC)
_NOW_TEXT = "2026-08-28T12:00:00Z"
_ALLOCATION = "a" * 64
_UUIDS = (
    "123e4567-e89b-42d3-a456-426614174001",
    "123e4567-e89b-42d3-a456-426614174002",
    "123e4567-e89b-42d3-a456-426614174003",
    "123e4567-e89b-42d3-a456-426614174004",
    "123e4567-e89b-42d3-a456-426614174005",
)


@pytest.fixture(autouse=True)
def _fixed_clock_and_uuid(monkeypatch: pytest.MonkeyPatch) -> None:
    """Keep session test timestamps and generated request IDs deterministic."""

    monkeypatch.setattr(transport, "_system_utc_clock", lambda: _NOW)
    monkeypatch.setattr(daemon, "uuid4", lambda: UUID(_UUIDS[4]))


def _hash(label: str) -> str:
    return hashlib.sha256(label.encode("ascii")).hexdigest()


def _reference(label: str) -> str:
    return _hash(label)


def _allocation_engine_fingerprint() -> str:
    projection = DockerEngineFilteredProjectionV1(
        daemon_id="daemon-identity.v1",
        api_version="1.47",
        operating_system="linux",
        architecture="amd64",
    )
    return docker_engine_fingerprint_sha256(projection)


def _allocation_resources(engine: EngineIdentityObservationV1) -> AllocatedResourceSetV2:
    """Typed non-secret allocation evidence for the daemon-only fake."""

    primary_created = "2026-08-28T12:00:00Z"
    restore_created = "2026-08-28T12:00:01Z"
    primary_volume = AllocatedVolumeObservationV1(
        name="primary-cache-volume",
        engine_fingerprint_sha256=engine.engine_fingerprint_sha256,
        driver="local",
        scope="local",
        created_at=primary_created,
        options=(),
        volume_instance_fingerprint_sha256=docker_volume_instance_fingerprint_sha256(
            name="primary-cache-volume",
            engine_fingerprint_sha256=engine.engine_fingerprint_sha256,
            driver="local",
            scope="local",
            created_at=primary_created,
            options=(),
        ),
    )
    restore_volume = AllocatedVolumeObservationV1(
        name="restore-cache-volume",
        engine_fingerprint_sha256=engine.engine_fingerprint_sha256,
        driver="local",
        scope="local",
        created_at=restore_created,
        options=(),
        volume_instance_fingerprint_sha256=docker_volume_instance_fingerprint_sha256(
            name="restore-cache-volume",
            engine_fingerprint_sha256=engine.engine_fingerprint_sha256,
            driver="local",
            scope="local",
            created_at=restore_created,
            options=(),
        ),
    )
    return AllocatedResourceSetV2(
        engine=engine,
        primary_network=AllocatedNetworkObservationV1(
            name="primary-network",
            network_id=_hash("primary-network"),
            driver="bridge",
            internal=True,
            subnet="192.0.2.0/24",
            gateway="192.0.2.1",
            options=(),
        ),
        restore_network=AllocatedNetworkObservationV1(
            name="restore-network",
            network_id=_hash("restore-network"),
            driver="bridge",
            internal=True,
            subnet="198.51.100.0/24",
            gateway="198.51.100.1",
            options=(),
        ),
        primary_cache_volume=primary_volume,
        restore_cache_volume=restore_volume,
        postgres=AllocatedPostgreSQLObservationV1(
            system_identifier="12345678",
            database_name="allocation-db",
            database_oid=101,
            schema_name="allocation-schema",
            schema_oid=102,
            prepared_operation_id=_UUIDS[2],
            prepared_operation_result_sha256=_hash("allocation-result"),
            owner_role="allocation-owner",
            owner_role_oid=103,
            application_role="allocation-application",
            application_role_oid=104,
            role_oids=(
                PostgreSQLRoleObservationV1(
                    role="allocation-owner",
                    role_oid=103,
                    can_login=False,
                    password_absent=True,
                ),
                PostgreSQLRoleObservationV1(
                    role="allocation-application",
                    role_oid=104,
                    can_login=False,
                    password_absent=True,
                ),
            ),
            grants=(
                PostgreSQLGrantObservationV1(
                    role="allocation-owner",
                    grantee="allocation-application",
                    privilege="SELECT",
                    schema_name="allocation-schema",
                ),
            ),
            acl_sha256=_hash("allocation-acl"),
        ),
        no_host_publication=NoHostPublicationGroundworkV1(
            host_network=False,
            publish_all_ports=False,
            allowed_attachment_set_sha256=_hash("allocation-topology"),
        ),
    )


def _slot(purpose: str) -> SecretDeliverySlotV1:
    expected = {
        "encryption_key": (
            "infisical_hex_16_v1",
            32,
            SecretDeliverySinkV1.INFISICAL_TARGET_PROCESS_ENVIRONMENT,
            ("primary_infisical", "restore_infisical"),
        ),
        "auth_secret": (
            "infisical_auth_secret_base64_32_v1",
            44,
            SecretDeliverySinkV1.INFISICAL_TARGET_PROCESS_ENVIRONMENT,
            ("primary_infisical", "restore_infisical"),
        ),
        "primary_valkey_password": (
            "valkey_password_base64url_32_v1",
            43,
            SecretDeliverySinkV1.VALKEY_STDIN_CONFIGURATION,
            ("primary_valkey",),
        ),
        "restore_valkey_password": (
            "valkey_password_base64url_32_v1",
            43,
            SecretDeliverySinkV1.VALKEY_STDIN_CONFIGURATION,
            ("restore_valkey",),
        ),
        "postgres_application_password": (
            "postgres_application_password_base64url_32_v1",
            43,
            SecretDeliverySinkV1.POSTGRES_APPLICATION_TARGET_ENVIRONMENT,
            ("postgres_application_target",),
        ),
    }[purpose]
    return SecretDeliverySlotV1(
        purpose=purpose,
        reference_sha256=_reference("slot-" + purpose),
        format=expected[0],
        encoded_byte_count=expected[1],
        sink=expected[2],
        target_processes=expected[3],
    )


def _genesis(key: Ed25519PrivateKey) -> SignerGenesisV1:
    public = key.public_key().public_bytes_raw()
    return SignerGenesisV1(
        schema_version="rsd.provider-crypto.signer-genesis.v1",
        allocation_intent_sha256=_ALLOCATION,
        issuer_key_id="issuer",
        key_id="client-signer",
        public_key_base64=base64.b64encode(public).decode("ascii"),
        public_key_fingerprint_sha256=hashlib.sha256(public).hexdigest(),
        seed_fingerprint_sha256=_hash("seed"),
        keychain_reference={
            "provider": "macos_keychain",
            "service": "signer-service",
            "account": "signer-account.v1",
            "version": 1,
            "reference_sha256": _hash(
                '{"account":"signer-account.v1","provider":"macos_keychain","service":"signer-service","version":1}'
            ),
        },
        created_at=_NOW_TEXT,
        signature_base64=base64.b64encode(b"s" * 64).decode("ascii"),
    )


def _policy() -> tuple[ExecutorTransportPolicyV2, ExecutorIdentityV1]:
    attestation = Ed25519PrivateKey.from_private_bytes(b"e" * 32).public_key().public_bytes_raw()
    attestation_b64 = base64.b64encode(attestation).decode("ascii")
    attestation_hash = hashlib.sha256(attestation).hexdigest()
    identity = ExecutorIdentityV1(
        executor_id="executor-one",
        platform="remote_linux_systemd_v1",
        authenticated_transport="ssh_forced_command_v1",
        endpoint_sha256=_hash("endpoint"),
        host_fingerprint_sha256=_hash("host"),
        control_capability_fingerprint_sha256=_hash("control"),
        attestation_key_id="executor-attestation",
        attestation_public_key_base64=attestation_b64,
        attestation_public_key_fingerprint_sha256=attestation_hash,
        credential_custody="tpm2_systemd_encrypted_credential_v1",
        monotonic_revision=1,
        expires_at="2026-08-28T13:00:00Z",
    )
    ssh = SSHConnectionPolicyV1(
        host_key_fingerprints_sha256=(_hash("host-key"),),
        dedicated_user="executor-user",
        client_key_fingerprint_sha256=_hash("client-key"),
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
    values = [_hash(f"commit-{index}") for index in range(10)]
    return (
        ExecutorTransportPolicyV2(
            schema_version="rsd.executor-transport-policy.v2",
            allocation_intent_sha256=_ALLOCATION,
            executor_installation_policy_sha256=values[0],
            executor_installation_receipt_sha256=values[1],
            executor_id=identity.executor_id,
            endpoint="executor.example.test",
            endpoint_sha256=_hash("executor.example.test"),
            ssh_executable_path="/opt/executor/ssh",
            ssh_executable_sha256=values[2],
            known_hosts_path="/opt/executor/known-hosts",
            known_hosts_sha256=values[3],
            identity=SecureShellIdentityReferenceV1(
                key_path="/opt/executor/key",
                public_key_path="/opt/executor/key.pub",
                public_key_fingerprint_sha256=values[4],
            ),
            ssh_policy=ssh,
            daemon_socket_path="/run/executor/socket",
            daemon_socket_policy_sha256=values[5],
            force_command_user_uid=1001,
            daemon_socket_group="executor-relay",
            daemon_socket_group_gid=1002,
            daemon_socket_mode=0o660,
            host_key_fingerprint_sha256=values[6],
            package_sha256=values[7],
            template_bundle_sha256=values[8],
            core_dump_disabled=True,
            swap_protection_required=True,
            mlock_required=True,
            max_session_seconds=60,
            created_at=_NOW_TEXT,
            expires_at="2026-08-28T12:30:00Z",
            signer_key_id="policy-signer",
            signature_base64=base64.b64encode(b"p" * 64).decode("ascii"),
        ),
        identity,
    )


def _request(
    policy: ExecutorTransportPolicyV2, signer: Ed25519PrivateKey
) -> ExecutorTransportRequestV2:
    witness = RemoteEffectAuthorizationWitnessV1(
        schema_version="rsd.remote-effect-authorization-witness.v1",
        operation_scope="materialize_and_start_runtime_v1",
        operation_id=_UUIDS[1],
        allocation_intent_sha256=_ALLOCATION,
        external_replay_tombstone_sha256=_hash("runtime-external-tombstone"),
        replay_policy_sha256=_hash("runtime-replay-policy"),
        executor_policy_sha256=policy.policy_sha256(),
        journal_uuid=_UUIDS[0],
        idempotency_key=_hash("runtime-idempotency"),
        effect_intent_sha256=_hash("materialization-intent"),
        predecessor_attestation_sha256=_hash("observed-allocation"),
        predecessor_operation_id=None,
        docker_engine_control_policy_sha256=_hash("docker-control"),
        postgres_prepared_control_policy_sha256=_hash("postgres-control"),
        host_fingerprint_sha256=_hash("executor-host"),
        engine_fingerprint_sha256=_hash("engine"),
        effect_plan_sha256=_hash("runtime-effect-plan"),
        engine_operation_plan_sha256=transport.executor_engine_operation_plan_sha256(
            operation_scope="materialize_and_start_runtime_v1",
            operation_id=_UUIDS[1],
        ),
        artifact_chain_sha256=_hash("runtime-artifact-chain"),
        issued_at="2026-08-28T11:59:00Z",
        expires_at="2026-08-28T12:00:30Z",
        signer_key_id="client-signer",
        signature_base64=base64.b64encode(b"0" * 64).decode("ascii"),
    )
    witness = witness.model_copy(
        update={
            "signature_base64": base64.b64encode(
                signer.sign(transport.remote_effect_authorization_witness_message(witness))
            ).decode("ascii")
        }
    )
    unsigned = ExecutorTransportRequestV2(
        schema_version="rsd.executor-transport-request.v2",
        message_kind="materialize",
        operation_scope="materialize_and_start_runtime_v1",
        allocation_intent_sha256=_ALLOCATION,
        operation_id=_UUIDS[1],
        predecessor_materialization_operation_id=None,
        journal_uuid=_UUIDS[0],
        idempotency_key=witness.idempotency_key,
        effect_intent_sha256=cast(str, witness.effect_intent_sha256),
        predecessor_attestation_sha256=cast(str, witness.predecessor_attestation_sha256),
        docker_engine_control_policy_sha256=witness.docker_engine_control_policy_sha256,
        postgres_prepared_control_policy_sha256=(witness.postgres_prepared_control_policy_sha256),
        host_fingerprint_sha256=witness.host_fingerprint_sha256,
        engine_fingerprint_sha256=witness.engine_fingerprint_sha256,
        effect_plan_sha256=witness.effect_plan_sha256,
        artifact_chain_sha256=witness.artifact_chain_sha256,
        authorization_witness=witness,
        request_id=_UUIDS[2],
        client_nonce=_UUIDS[3],
        server_nonce=_UUIDS[4],
        session_id=_UUIDS[0],
        request_nonce_sha256=_hash("request-nonce"),
        channel_binding_sha256=_hash("channel"),
        session_binding_sha256=_hash("session"),
        host_key_fingerprint_sha256=policy.host_key_fingerprint_sha256,
        executor_id=policy.executor_id,
        executor_policy_sha256=policy.policy_sha256(),
        package_sha256=policy.package_sha256,
        template_bundle_sha256=policy.template_bundle_sha256,
        installation_receipt_sha256=policy.executor_installation_receipt_sha256,
        # The request is live for only thirty seconds under the fixed test
        # clock; a stale request must not be admitted by the verifier.
        expires_at="2026-08-28T12:00:30Z",
        chunk_count=5,
        slots=tuple(
            _slot(name)
            for name in (
                "encryption_key",
                "auth_secret",
                "primary_valkey_password",
                "restore_valkey_password",
                "postgres_application_password",
            )
        ),
        signer_key_id="client-signer",
        signature_base64=base64.b64encode(b"0" * 64).decode("ascii"),
    )
    from omninode_rsd.lifecycle.provider_crypto import executor_transport_metadata_message

    signature = signer.sign(
        executor_transport_metadata_message(
            allocation_intent_sha256=unsigned.allocation_intent_sha256,
            operation_scope=unsigned.operation_scope,
            operation_id=unsigned.operation_id,
            metadata_sha256=unsigned.metadata_sha256(),
        )
    )
    return unsigned.model_copy(
        update={"signature_base64": base64.b64encode(signature).decode("ascii")}
    )


def _allocation_request(
    policy: ExecutorTransportPolicyV2, signer: Ed25519PrivateKey
) -> ExecutorAllocationTransportRequestV1:
    """Build one fully signed, no-secret allocation request for the daemon."""

    witness = RemoteEffectAuthorizationWitnessV1(
        schema_version="rsd.remote-effect-authorization-witness.v1",
        operation_scope="allocate_isolated_empty_resources_v2",
        operation_id=_UUIDS[1],
        allocation_intent_sha256=_ALLOCATION,
        external_replay_tombstone_sha256=_hash("external-allocation-tombstone"),
        replay_policy_sha256=_hash("replay-policy"),
        executor_policy_sha256=policy.policy_sha256(),
        journal_uuid=_UUIDS[0],
        idempotency_key=_hash("allocation-idempotency"),
        docker_engine_control_policy_sha256=_hash("docker-control-policy"),
        postgres_prepared_control_policy_sha256=_hash("postgres-prepared-policy"),
        host_fingerprint_sha256=_hash("executor-host"),
        engine_fingerprint_sha256=_allocation_engine_fingerprint(),
        effect_plan_sha256=_hash("allocation-plan"),
        engine_operation_plan_sha256=transport.executor_engine_operation_plan_sha256(
            operation_scope="allocate_isolated_empty_resources_v2",
            operation_id=_UUIDS[1],
        ),
        artifact_chain_sha256=_hash("allocation-artifact-chain"),
        issued_at="2026-08-28T11:59:00Z",
        expires_at="2026-08-28T12:00:30Z",
        signer_key_id="client-signer",
        signature_base64=base64.b64encode(b"0" * 64).decode("ascii"),
    )
    witness = witness.model_copy(
        update={
            "signature_base64": base64.b64encode(
                signer.sign(transport.remote_effect_authorization_witness_message(witness))
            ).decode("ascii")
        }
    )
    unsigned = ExecutorAllocationTransportRequestV1(
        schema_version="rsd.executor-allocation-request.v1",
        message_kind="allocation",
        operation_scope="allocate_isolated_empty_resources_v2",
        allocation_intent_sha256=_ALLOCATION,
        allocation_operation_id=_UUIDS[1],
        idempotency_key=witness.idempotency_key,
        journal_uuid=_UUIDS[0],
        request_id=_UUIDS[2],
        client_nonce=_UUIDS[3],
        server_nonce=_UUIDS[4],
        session_id=_UUIDS[0],
        request_nonce_sha256=_hash("allocation-request-nonce"),
        channel_binding_sha256=_hash("allocation-channel"),
        session_binding_sha256=_hash("allocation-session"),
        host_key_fingerprint_sha256=policy.host_key_fingerprint_sha256,
        executor_id=policy.executor_id,
        executor_policy_sha256=policy.policy_sha256(),
        package_sha256=policy.package_sha256,
        template_bundle_sha256=policy.template_bundle_sha256,
        installation_receipt_sha256=policy.executor_installation_receipt_sha256,
        docker_engine_control_policy_sha256=witness.docker_engine_control_policy_sha256,
        postgres_prepared_control_policy_sha256=(witness.postgres_prepared_control_policy_sha256),
        host_fingerprint_sha256=witness.host_fingerprint_sha256,
        engine_fingerprint_sha256=witness.engine_fingerprint_sha256,
        allocation_plan_sha256=witness.effect_plan_sha256,
        artifact_chain_sha256=witness.artifact_chain_sha256,
        authorization_witness=witness,
        expires_at="2026-08-28T12:00:30Z",
        chunk_count=0,
        signer_key_id="client-signer",
        signature_base64=base64.b64encode(b"0" * 64).decode("ascii"),
    )
    signature = signer.sign(
        executor_allocation_metadata_message(
            allocation_intent_sha256=unsigned.allocation_intent_sha256,
            allocation_operation_id=unsigned.allocation_operation_id,
            metadata_sha256=unsigned.metadata_sha256(),
        )
    )
    return unsigned.model_copy(
        update={"signature_base64": base64.b64encode(signature).decode("ascii")}
    )


def _frame(model: object, *, count: int = 0, chunks: tuple[bytes, ...] = ()) -> bytes:
    sink = io.BytesIO()
    writer = CanonicalFrameWriter(sink)
    writer.begin(
        json.dumps(
            cast(object, model.model_dump(mode="json")), sort_keys=True, separators=(",", ":")
        ).encode("ascii"),
        chunk_count=count,
    )
    for value in chunks:
        writer.write_chunk(memoryview(value))
    writer.finish()
    return sink.getvalue()


class _Source:
    def __init__(self, data: bytes, events: list[str] | None = None) -> None:
        self._stream = io.BytesIO(data)
        self._calls = 0
        self._events = events

    def read_exact(self, count: int = -1) -> bytes:
        self._calls += 1
        if self._events is not None and self._calls >= 5:
            self._events.append("chunk-read")
        value = self._stream.read(count)
        if len(value) != count:
            raise ValueError("short frame")
        return value


class _MemoryLease:
    def release(self) -> None:
        return None


class _Memory:
    def verify_base(self) -> None:
        return None

    def lock(self, value: bytearray) -> MemorySafetyLease:
        assert value
        return _MemoryLease()


class _Attestation:
    key_id = "executor-attestation"

    def sign_hello(self, hello: object) -> str:
        del hello
        return base64.b64encode(b"h" * 64).decode("ascii")

    def sign_receipt(self, receipt: object) -> str:
        del receipt
        return base64.b64encode(b"r" * 64).decode("ascii")

    def sign_allocation_executor_receipt(self, receipt: object) -> str:
        del receipt
        return base64.b64encode(b"a" * 64).decode("ascii")

    def sign_allocation_transport_receipt(self, receipt: object) -> str:
        del receipt
        return base64.b64encode(b"t" * 64).decode("ascii")

    def sign_allocation_reconciliation_receipt(self, receipt: object) -> str:
        del receipt
        return base64.b64encode(b"c" * 64).decode("ascii")

    def sign_materialization_executor_receipt(self, receipt: object) -> str:
        del receipt
        return base64.b64encode(b"m" * 64).decode("ascii")

    def sign_start_runtime_executor_receipt(self, receipt: object) -> str:
        del receipt
        return base64.b64encode(b"s" * 64).decode("ascii")


class _AllocationAttestation:
    """Real deterministic attestation signatures for allocation receipt tests."""

    key_id = "executor-attestation"

    def __init__(self) -> None:
        self._key = Ed25519PrivateKey.from_private_bytes(b"e" * 32)

    def sign_hello(self, hello: object) -> str:
        return base64.b64encode(
            self._key.sign(transport.executor_hello_message(cast(ExecutorHelloV2, hello)))
        ).decode("ascii")

    def sign_receipt(self, receipt: object) -> str:
        return base64.b64encode(
            self._key.sign(
                transport.executor_transport_receipt_message(
                    cast(ExecutorTransportReceiptV2, receipt)
                )
            )
        ).decode("ascii")

    def sign_allocation_executor_receipt(self, receipt: object) -> str:
        from omninode_rsd.lifecycle.infisical_disposable import allocation_executor_receipt_message

        return base64.b64encode(
            self._key.sign(
                allocation_executor_receipt_message(cast(AllocationExecutorReceiptV1, receipt))
            )
        ).decode("ascii")

    def sign_allocation_transport_receipt(self, receipt: object) -> str:
        return base64.b64encode(
            self._key.sign(
                transport.executor_allocation_transport_receipt_message(
                    cast(ExecutorAllocationTransportReceiptV1, receipt)
                )
            )
        ).decode("ascii")

    def sign_allocation_reconciliation_receipt(self, receipt: object) -> str:
        from omninode_rsd.lifecycle.executor_allocation import (
            AllocationReconciliationReceiptV1,
            allocation_reconciliation_receipt_message,
        )

        return base64.b64encode(
            self._key.sign(
                allocation_reconciliation_receipt_message(
                    cast(AllocationReconciliationReceiptV1, receipt)
                )
            )
        ).decode("ascii")

    def sign_materialization_executor_receipt(self, receipt: object) -> str:
        from omninode_rsd.lifecycle.infisical_disposable import (
            materialization_executor_receipt_message,
        )

        return base64.b64encode(
            self._key.sign(
                materialization_executor_receipt_message(
                    cast(MaterializationExecutorReceiptV1, receipt)
                )
            )
        ).decode("ascii")

    def sign_start_runtime_executor_receipt(self, receipt: object) -> str:
        from omninode_rsd.lifecycle.infisical_disposable import (
            start_runtime_executor_receipt_message,
        )

        return base64.b64encode(
            self._key.sign(
                start_runtime_executor_receipt_message(cast(StartRuntimeExecutorReceiptV2, receipt))
            )
        ).decode("ascii")


class _Sink(ExecutorSecretSink):
    def __init__(self) -> None:
        self.values: list[bytes] = []

    def accept(self, descriptor: object, value: memoryview) -> None:
        del descriptor
        self.values.append(bytes(value))


def _runtime_inspections() -> tuple[
    ExecutorContainerInspectionV1,
    ExecutorContainerInspectionV1,
    ExecutorContainerInspectionV1,
    ExecutorContainerInspectionV1,
]:
    """Build canonical, value-free inspection evidence for the fake backend."""

    components = (
        ("primary_infisical", "a", "192.0.2.2"),
        ("primary_valkey", "b", "192.0.2.3"),
        ("restore_infisical", "c", "198.51.100.2"),
        ("restore_valkey", "d", "198.51.100.3"),
    )
    values: list[ExecutorContainerInspectionV1] = []
    for component, marker, address in components:
        image = ImageReferenceV1(
            reference=f"registry.example.test/{component}@sha256:{marker * 64}"
        )
        policy = DockerImagePolicyV1(
            image=image,
            registry_index_digest_sha256=marker * 64,
            linux_amd64_manifest_digest_sha256=_hash(component + "-manifest"),
            config_digest_sha256=_hash(component + "-config"),
        )
        entrypoint = ("/bootstrap",)
        entrypoint_sha256 = hashlib.sha256(
            json.dumps(entrypoint, sort_keys=True, separators=(",", ":")).encode("utf-8")
        ).hexdigest()
        is_valkey = component.endswith("valkey")
        mounts = (
            (
                DockerNamedVolumeMountV1(
                    mount_type="volume",
                    source_volume_name=f"{component}-volume",
                    target_path="/data",
                    read_only=False,
                    bind_allowed=False,
                    tmpfs_allowed=False,
                    propagation="none",
                ),
            )
            if is_valkey
            else ()
        )
        inspection = ContainerBootstrapInspectionV1(
            image_policy=policy,
            entrypoint=entrypoint,
            command=(),
            entrypoint_sha256=entrypoint_sha256,
            template_sha256=_hash(component + "-template"),
            bootstrap_wrapper_sha256=_hash(component + "-wrapper"),
            ingress_protocol_sha256=_hash(component + "-ingress"),
            create_request_sha256=_hash(component + "-create"),
            numeric_user="1001:1001",
            working_directory="/work",
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
            mounts=mounts,
            docker_socket_mounted=False,
            host_network=False,
            network_mode="exact_isolated_network_v1",
            publish_all_ports=False,
            port_bindings=(),
            labels=(),
            network_name=(
                "primary-network" if component.startswith("primary") else "restore-network"
            ),
            network_alias=component.replace("_", "-"),
            static_ipv4=address,
            accepted_secret_sink=(
                ContainerSecretSinkV1.VALKEY_STDIN_CONFIGURATION
                if is_valkey
                else ContainerSecretSinkV1.INFISICAL_TARGET_PROCESS_ENVIRONMENT
            ),
            running=True,
        )
        values.append(
            ExecutorContainerInspectionV1(
                component=component,
                container_id=_hash(component + "-container"),
                inspection=inspection,
            )
        )
    return cast(
        tuple[
            ExecutorContainerInspectionV1,
            ExecutorContainerInspectionV1,
            ExecutorContainerInspectionV1,
            ExecutorContainerInspectionV1,
        ],
        tuple(values),
    )


def _runtime_executor_receipt(
    context: ExecutorBackendContextV2,
) -> MaterializationExecutorReceiptV1 | StartRuntimeExecutorReceiptV2:
    """Return backend evidence with all session bindings supplied by the daemon."""

    _complete_engine_operation_plan(context.engine_operations, label="runtime")
    engine_journal_sha256 = context.engine_operations.completed_projection_sha256()
    containers = _runtime_inspections()
    if context.operation_scope == "materialize_and_start_runtime_v1":
        return MaterializationExecutorReceiptV1(
            schema_version="rsd.materialization-executor-receipt.v1",
            executor_id=context.executor_id,
            installation_receipt_sha256=context.installation_receipt_sha256,
            operation_scope=context.operation_scope,
            operation_id=context.operation_id,
            idempotency_key=context.idempotency_key,
            materialization_intent_sha256=context.effect_intent_sha256,
            observed_allocation_attestation_sha256=context.predecessor_attestation_sha256,
            docker_engine_control_policy_sha256=(context.docker_engine_control_policy_sha256),
            secret_delivery_receipt_sha256=_hash("delivery-receipt"),
            channel_binding_sha256=context.channel_binding_sha256,
            session_binding_sha256=context.session_binding_sha256,
            host_fingerprint_sha256=context.host_fingerprint_sha256,
            engine_fingerprint_sha256=context.engine_fingerprint_sha256,
            engine_operation_journal_sha256=engine_journal_sha256,
            containers=containers,
            completed_at=_NOW_TEXT,
            signer_key_id="backend-placeholder",
            signature_base64=base64.b64encode(b"0" * 64).decode("ascii"),
        )
    return StartRuntimeExecutorReceiptV2(
        schema_version="rsd.start-runtime-executor-receipt.v2",
        operation_kind="start_runtime_v2",
        operation_scope=context.operation_scope,
        start_operation_id=context.operation_id,
        start_runtime_intent_sha256=context.effect_intent_sha256,
        idempotency_key=context.idempotency_key,
        secret_delivery_receipt_sha256=_hash("delivery-receipt"),
        request_nonce_sha256=context.request_nonce_sha256,
        channel_binding_sha256=context.channel_binding_sha256,
        session_binding_sha256=context.session_binding_sha256,
        installation_receipt_sha256=context.installation_receipt_sha256,
        executor_id=context.executor_id,
        host_fingerprint_sha256=context.host_fingerprint_sha256,
        engine_fingerprint_sha256=context.engine_fingerprint_sha256,
        engine_operation_journal_sha256=engine_journal_sha256,
        containers=containers,
        completed_at=_NOW_TEXT,
        signer_key_id="backend-placeholder",
        signature_base64=base64.b64encode(b"0" * 64).decode("ascii"),
    )


def _complete_engine_operation_plan(
    recorder: daemon.ExecutorEngineOperationRecorder,
    *,
    label: str,
) -> None:
    """Drive the daemon-selected immutable plan without selecting a step."""

    while recorder.remaining_operations() > 0:
        operation = recorder.claim_next()
        recorder.complete(
            operation,
            filtered_projection_sha256=_hash(f"{label}-{operation.sequence}"),
        )


class _Backend:
    def __init__(self, *, fail: bool = False) -> None:
        self.fail = fail
        self.sink = _Sink()
        self.calls = 0

    def materialize_and_start(self, context: object, delivery: object) -> ExecutorBackendReceiptV2:
        self.calls += 1
        if self.fail:
            raise ExecutorDaemonError("backend_effect")
        cast(object, delivery).consume_into(self.sink)
        return ExecutorBackendReceiptV2(
            executor_receipt=_runtime_executor_receipt(cast(ExecutorBackendContextV2, context))
        )

    def start(self, context: object, delivery: object) -> ExecutorBackendReceiptV2:
        return self.materialize_and_start(context, delivery)


class _CheckpointGapBackend(_Backend):
    """Fake a crash between a claimed Engine step and its filtered receipt."""

    def materialize_and_start(self, context: object, delivery: object) -> ExecutorBackendReceiptV2:
        self.calls += 1
        checked_context = cast(ExecutorBackendContextV2, context)
        checked_delivery = cast(daemon.BoundedExecutorDelivery, delivery)
        checked_delivery.consume_into(self.sink)
        checked_context.engine_operations.claim_next()
        # The shared fake tries to generate terminal evidence after the
        # missing checkpoint.  The journal must reject the gap rather than
        # treating a later completed row as proof of this effect.
        return ExecutorBackendReceiptV2(executor_receipt=_runtime_executor_receipt(checked_context))


class _FutureRuntimeReceiptBackend(_Backend):
    """Return a structurally valid receipt whose inner completion is future-dated."""

    def materialize_and_start(self, context: object, delivery: object) -> ExecutorBackendReceiptV2:
        result = super().materialize_and_start(context, delivery)
        return ExecutorBackendReceiptV2(
            executor_receipt=result.executor_receipt.model_copy(
                update={"completed_at": "2026-08-28T12:00:01Z"}
            )
        )


class _SecretBearingRuntimeFailureBackend(_Backend):
    """Raise a fake backend error containing a value sentinel after delivery."""

    sentinel = "transport-backend-value-sentinel"

    def materialize_and_start(self, context: object, delivery: object) -> ExecutorBackendReceiptV2:
        self.calls += 1
        cast(daemon.BoundedExecutorDelivery, delivery).consume_into(self.sink)
        raise ExecutorDaemonError(self.sentinel)


class _AllocationBackend:
    def __init__(self, *, fail: bool = False, events: list[str] | None = None) -> None:
        self.fail = fail
        self.events = [] if events is None else events
        self.calls = 0

    def allocate_empty_resources(
        self, context: AllocationExecutorBackendContextV1
    ) -> ExecutorAllocationBackendEvidenceV1:
        self.calls += 1
        self.events.append("backend")
        if self.fail:
            raise RuntimeError("allocation backend sentinel must not escape")
        projection = DockerEngineFilteredProjectionV1(
            daemon_id="daemon-identity.v1",
            api_version="1.47",
            operating_system="linux",
            architecture="amd64",
        )
        engine = EngineIdentityObservationV1(
            projection=projection,
            engine_fingerprint_sha256=docker_engine_fingerprint_sha256(projection),
        )
        assert context.allocation_operation_id == _UUIDS[1]
        _complete_engine_operation_plan(context.engine_operations, label="allocation")
        return ExecutorAllocationBackendEvidenceV1(
            engine=engine,
            allocated_resources=_allocation_resources(engine),
            engine_operation_journal_sha256=(
                context.engine_operations.completed_projection_sha256()
            ),
            completed_at=_NOW_TEXT,
        )

    def materialize_and_start(self, context: object, delivery: object) -> ExecutorBackendReceiptV2:
        del context, delivery
        raise AssertionError("allocation test selected a delivery backend")

    def start(self, context: object, delivery: object) -> ExecutorBackendReceiptV2:
        del context, delivery
        raise AssertionError("allocation test selected a delivery backend")


def _engine(
    tmp_path: Path, backend: _Backend
) -> tuple[
    ExecutorDaemonSessionEngine,
    ExecutorTransportRequestV2,
    Ed25519PrivateKey,
    ExecutorTransportPolicyV2,
]:
    policy, _ = _policy()
    signer = Ed25519PrivateKey.from_private_bytes(b"c" * 32)
    genesis = _genesis(signer)
    journal = ExecutorSessionJournal.provision(tmp_path / "journal.sqlite3", journal_id=_UUIDS[0])
    return (
        daemon._executor_daemon_session_engine_for_test(
            policy=policy,
            signer_genesis=genesis,
            # Use a deterministic real attestation key for runtime evidence
            # too.  The client-side verifier tests therefore exercise both
            # the outer daemon signature and the typed inner receipt domain.
            attestation_signer=_AllocationAttestation(),
            journal=journal,
            backend=backend,
            memory_safety=_Memory(),
        ),
        _request(policy, signer),
        signer,
        policy,
    )


def _artifacts(
    policy: ExecutorTransportPolicyV2, genesis: SignerGenesisV1
) -> transport.VerifiedExecutorTransportArtifactsV2:
    """Mint only the explicitly internal sealed fixture bundle."""

    return transport._verified_executor_transport_artifacts_for_test(
        policy=policy,
        signer_genesis=genesis,
        installation_policy=ExecutorInstallationPolicyV1.model_construct(),
        installation_receipt=ExecutorInstallationReceiptV1.model_construct(),
    )


def _recovery_receipt(
    request: ExecutorTransportRequestV2,
    signer: Ed25519PrivateKey,
) -> ExecutorRecoveryReceiptV2:
    unsigned = ExecutorRecoveryReceiptV2(
        schema_version="rsd.executor-recovery-receipt.v2",
        allocation_intent_sha256=request.allocation_intent_sha256,
        operation_scope=request.operation_scope,
        operation_id=request.operation_id,
        request_id=request.request_id,
        journal_uuid=request.journal_uuid,
        executor_id=request.executor_id,
        executor_policy_sha256=request.executor_policy_sha256,
        session_binding_sha256=request.session_binding_sha256,
        request_metadata_sha256=request.metadata_sha256(),
        outcome="abandoned",
        outcome_receipt_sha256=_hash("operator-reconciliation"),
        completed_at="2026-08-28T12:01:00Z",
        signer_key_id="client-signer",
        signature_base64=base64.b64encode(b"0" * 64).decode("ascii"),
    )
    return unsigned.model_copy(
        update={
            "signature_base64": base64.b64encode(
                signer.sign(daemon._recovery_receipt_message(unsigned))
            ).decode("ascii")
        }
    )


def _session_bytes(request: ExecutorTransportRequestV2) -> bytes:
    client = ExecutorClientHelloV2(
        schema_version="rsd.executor-client-hello.v2",
        allocation_intent_sha256=_ALLOCATION,
        client_nonce=request.client_nonce,
        session_id=request.session_id,
        request_id=request.request_id,
        executor_id=request.executor_id,
        executor_policy_sha256=request.executor_policy_sha256,
        chunk_count=0,
    )
    secrets = tuple(
        (f"secret-{index}".encode("ascii") * 12)[: slot.encoded_byte_count]
        for index, slot in enumerate(request.slots)
    )
    return _frame(client) + _frame(request, count=5, chunks=secrets)


def _allocation_session_bytes(request: ExecutorAllocationTransportRequestV1) -> bytes:
    client = ExecutorClientHelloV2(
        schema_version="rsd.executor-client-hello.v2",
        allocation_intent_sha256=_ALLOCATION,
        client_nonce=request.client_nonce,
        session_id=request.session_id,
        request_id=request.request_id,
        executor_id=request.executor_id,
        executor_policy_sha256=request.executor_policy_sha256,
        chunk_count=0,
    )
    return _frame(client) + _frame(request)


def _allocation_engine(
    tmp_path: Path, backend: _AllocationBackend
) -> tuple[
    ExecutorDaemonSessionEngine,
    ExecutorAllocationTransportRequestV1,
    ExecutorTransportPolicyV2,
]:
    policy, _ = _policy()
    signer = Ed25519PrivateKey.from_private_bytes(b"c" * 32)
    journal = ExecutorSessionJournal.provision(tmp_path / "journal.sqlite3", journal_id=_UUIDS[0])
    return (
        daemon._executor_daemon_session_engine_for_test(
            policy=policy,
            signer_genesis=_genesis(signer),
            attestation_signer=_AllocationAttestation(),
            journal=journal,
            backend=backend,
            memory_safety=_Memory(),
        ),
        _allocation_request(policy, signer),
        policy,
    )


def test_zero_chunk_allocation_claims_before_effect_and_returns_typed_receipt(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    """Allocation admits no secret chunks and is claimed before backend work."""

    monkeypatch.setattr(daemon, "_system_utc_clock", lambda: _NOW)
    events: list[str] = []
    original = ExecutorSessionJournal.claim_allocation

    def claim(self: ExecutorSessionJournal, request: ExecutorAllocationTransportRequestV1) -> None:
        events.append("claim")
        original(self, request)

    monkeypatch.setattr(ExecutorSessionJournal, "claim_allocation", claim)
    backend = _AllocationBackend(events=events)
    engine, request, policy = _allocation_engine(tmp_path, backend)
    result = engine._serve_for_test(
        _Source(_allocation_session_bytes(request)), io.BytesIO(), peer_uid=1001
    )
    assert type(result) is transport.ExecutorAllocationTransportReceiptV1
    _, identity = _policy()
    verified = transport.verify_executor_allocation_transport_receipt(
        result,
        request=request,
        policy=policy,
        attestation_public_key_base64=identity.attestation_public_key_base64,
        attestation_key_id=identity.attestation_key_id,
    )
    assert verified.allocation_executor_receipt.idempotency_key == request.idempotency_key
    assert events == ["claim", "backend"]
    assert backend.calls == 1
    assert (
        engine._journal.state(request.allocation_operation_id) is ExecutorSessionStateV2.ALLOCATED
    )


def test_allocation_witness_policy_substitution_blocks_before_claim(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    """A client cannot substitute an unsigned Docker/psql policy commitment."""

    monkeypatch.setattr(daemon, "_system_utc_clock", lambda: _NOW)
    backend = _AllocationBackend()
    engine, request, _ = _allocation_engine(tmp_path, backend)
    forged = request.model_copy(
        update={"docker_engine_control_policy_sha256": _hash("substituted-docker-policy")}
    )
    with pytest.raises(ExecutorDaemonError, match="allocation_request"):
        engine._serve_for_test(
            _Source(_allocation_session_bytes(forged)), io.BytesIO(), peer_uid=1001
        )
    assert backend.calls == 0
    assert engine._journal.state(request.allocation_operation_id) is None


def test_allocation_transport_receipt_rejects_a_re_signed_inner_signature_swap(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    """A valid outer envelope cannot authenticate a substituted inner receipt."""

    monkeypatch.setattr(daemon, "_system_utc_clock", lambda: _NOW)
    backend = _AllocationBackend()
    engine, request, policy = _allocation_engine(tmp_path, backend)
    result = engine._serve_for_test(
        _Source(_allocation_session_bytes(request)), io.BytesIO(), peer_uid=1001
    )
    assert type(result) is ExecutorAllocationTransportReceiptV1
    swapped_inner = result.allocation_executor_receipt.model_copy(
        update={"signature_base64": base64.b64encode(b"x" * 64).decode("ascii")}
    )
    unsigned = result.model_copy(
        update={
            "allocation_executor_receipt": swapped_inner,
            "allocation_executor_receipt_sha256": canonical_sha256(swapped_inner),
            "signature_base64": base64.b64encode(b"0" * 64).decode("ascii"),
        }
    )
    tampered = unsigned.model_copy(
        update={
            "signature_base64": _AllocationAttestation().sign_allocation_transport_receipt(unsigned)
        }
    )
    _, identity = _policy()
    with pytest.raises(transport.ExecutorTransportError, match="allocation_receipt"):
        transport.verify_executor_allocation_transport_receipt(
            tampered,
            request=request,
            policy=policy,
            attestation_public_key_base64=identity.attestation_public_key_base64,
            attestation_key_id=identity.attestation_key_id,
        )


def test_allocation_transport_receipt_rejects_a_re_signed_host_substitution(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    """Allocation receipt host evidence is bound to the signed request, not its signature alone."""

    monkeypatch.setattr(daemon, "_system_utc_clock", lambda: _NOW)
    engine, request, policy = _allocation_engine(tmp_path, _AllocationBackend())
    result = engine._serve_for_test(
        _Source(_allocation_session_bytes(request)), io.BytesIO(), peer_uid=1001
    )
    assert type(result) is ExecutorAllocationTransportReceiptV1
    signer = _AllocationAttestation()
    unsigned_inner = result.allocation_executor_receipt.model_copy(
        update={
            "host_fingerprint_sha256": _hash("other-executor-host"),
            "signature_base64": base64.b64encode(b"0" * 64).decode("ascii"),
        }
    )
    forged_inner = unsigned_inner.model_copy(
        update={"signature_base64": signer.sign_allocation_executor_receipt(unsigned_inner)}
    )
    unsigned_outer = result.model_copy(
        update={
            "allocation_executor_receipt": forged_inner,
            "allocation_executor_receipt_sha256": canonical_sha256(forged_inner),
            "signature_base64": base64.b64encode(b"0" * 64).decode("ascii"),
        }
    )
    forged = unsigned_outer.model_copy(
        update={"signature_base64": signer.sign_allocation_transport_receipt(unsigned_outer)}
    )
    _, identity = _policy()
    with pytest.raises(transport.ExecutorTransportError, match="allocation_receipt"):
        transport.verify_executor_allocation_transport_receipt(
            forged,
            request=request,
            policy=policy,
            attestation_public_key_base64=identity.attestation_public_key_base64,
            attestation_key_id=identity.attestation_key_id,
        )


def test_signed_engine_checkpoint_plan_rejects_a_backend_selected_sequence(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    """The witness commits the full immutable plan before a backend can run."""

    monkeypatch.setattr(daemon, "_system_utc_clock", lambda: _NOW)
    backend = _Backend()
    engine, request, _, _ = _engine(tmp_path, backend)
    plan = transport.executor_engine_operation_plan_v1(
        operation_scope=request.operation_scope,
        operation_id=request.operation_id,
    )
    assert tuple((item.operation_kind.value, item.target.value) for item in plan.operations) == (
        ("postgres_scram_verifier_install", "application_postgres"),
        ("container_create", "primary_infisical"),
        ("container_inspect", "primary_infisical"),
        ("container_start", "primary_infisical"),
        ("container_inspect", "primary_infisical"),
        ("container_attach", "primary_infisical"),
        ("container_inspect", "primary_infisical"),
        *(
            (kind, component)
            for component in ("primary_valkey", "restore_infisical", "restore_valkey")
            for kind in (
                "container_create",
                "container_inspect",
                "container_start",
                "container_inspect",
                "container_attach",
                "container_inspect",
            )
        ),
    )
    unsigned_witness = request.authorization_witness.model_copy(
        update={
            "engine_operation_plan_sha256": _hash("backend-selected-short-plan"),
            "signature_base64": base64.b64encode(b"0" * 64).decode("ascii"),
        }
    )
    with pytest.raises(transport.ExecutorTransportError, match="remote_effect_witness"):
        transport.remote_effect_authorization_witness_message(unsigned_witness)
    forged_request = request.model_copy(update={"authorization_witness": unsigned_witness})
    with pytest.raises(ExecutorDaemonError):
        engine._serve_for_test(_Source(_session_bytes(forged_request)), io.BytesIO(), peer_uid=1001)
    assert backend.calls == 0
    assert engine._journal.state(request.operation_id) is None


def test_runtime_witness_substitution_blocks_before_claim_or_delivery(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    """A request cannot replace a witness-bound host identity before secret I/O."""

    monkeypatch.setattr(daemon, "_system_utc_clock", lambda: _NOW)
    backend = _Backend()
    engine, request, _, _ = _engine(tmp_path, backend)
    forged = request.model_copy(update={"host_fingerprint_sha256": _hash("other-host")})
    with pytest.raises(ExecutorDaemonError):
        engine._serve_for_test(_Source(_session_bytes(forged)), io.BytesIO(), peer_uid=1001)
    assert backend.calls == 0
    assert engine._journal.state(request.operation_id) is None


def test_allocation_only_dispatch_rejects_delivery_before_claim_or_chunk_read(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    """The sealed allocation socket is never a materialization/start sink."""

    monkeypatch.setattr(daemon, "_system_utc_clock", lambda: _NOW)
    backend = _Backend()
    engine, request, _, _ = _engine(tmp_path, backend)
    events: list[str] = []
    with pytest.raises(ExecutorDaemonError, match="allocation_only"):
        engine._serve_for_test(
            _Source(_session_bytes(request), events),
            io.BytesIO(),
            peer_uid=1001,
            allocation_only=True,
        )
    assert backend.calls == 0
    assert engine._journal.state(request.operation_id) is None
    assert "chunk-read" not in events


def test_runtime_typed_receipt_binds_host_and_engine_to_the_signed_request(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    """A re-signed outer receipt cannot substitute filtered host/Engine evidence."""

    monkeypatch.setattr(daemon, "_system_utc_clock", lambda: _NOW)
    backend = _Backend()
    engine, request, _, policy = _engine(tmp_path, backend)
    result = engine._serve_for_test(_Source(_session_bytes(request)), io.BytesIO(), peer_uid=1001)
    assert type(result) is ExecutorTransportReceiptV2
    inner = result.executor_receipt.model_copy(
        update={"engine_fingerprint_sha256": _hash("substituted-engine")}
    )
    unsigned = result.model_copy(
        update={
            "executor_receipt": inner,
            "executor_receipt_sha256": canonical_sha256(inner),
            "signature_base64": base64.b64encode(b"0" * 64).decode("ascii"),
        }
    )
    tampered = unsigned.model_copy(
        update={"signature_base64": _AllocationAttestation().sign_receipt(unsigned)}
    )
    _, identity = _policy()
    with pytest.raises(transport.ExecutorTransportError, match="transport_receipt"):
        transport.verify_executor_transport_receipt(
            tampered,
            request=request,
            policy=policy,
            attestation_public_key_base64=identity.attestation_public_key_base64,
            attestation_key_id=identity.attestation_key_id,
        )


def test_runtime_transport_receipt_carries_a_verifiable_typed_executor_projection(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    """Terminal transport evidence contains signed projections, not a lone hash."""

    monkeypatch.setattr(daemon, "_system_utc_clock", lambda: _NOW)
    backend = _Backend()
    engine, request, _, policy = _engine(tmp_path, backend)
    result = engine._serve_for_test(_Source(_session_bytes(request)), io.BytesIO(), peer_uid=1001)
    assert type(result) is ExecutorTransportReceiptV2
    _, identity = _policy()
    verified = transport.verify_executor_transport_receipt(
        result,
        request=request,
        policy=policy,
        attestation_public_key_base64=identity.attestation_public_key_base64,
        attestation_key_id=identity.attestation_key_id,
    )
    assert type(verified.executor_receipt) is MaterializationExecutorReceiptV1
    assert verified.executor_receipt.engine_operation_journal_sha256 != _hash("backend")


def test_runtime_transport_receipt_rejects_a_re_signed_future_inner_completion(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    """A valid outer envelope cannot make a future inner completion acceptable."""

    monkeypatch.setattr(daemon, "_system_utc_clock", lambda: _NOW)
    engine, request, _, policy = _engine(tmp_path, _Backend())
    result = engine._serve_for_test(_Source(_session_bytes(request)), io.BytesIO(), peer_uid=1001)
    assert type(result) is ExecutorTransportReceiptV2
    signer = _AllocationAttestation()
    unsigned_inner = result.executor_receipt.model_copy(
        update={
            "completed_at": "2026-08-28T12:00:01Z",
            "signature_base64": base64.b64encode(b"0" * 64).decode("ascii"),
        }
    )
    assert type(unsigned_inner) is MaterializationExecutorReceiptV1
    future_inner = unsigned_inner.model_copy(
        update={"signature_base64": signer.sign_materialization_executor_receipt(unsigned_inner)}
    )
    unsigned_outer = result.model_copy(
        update={
            "executor_receipt": future_inner,
            "executor_receipt_sha256": canonical_sha256(future_inner),
            "signature_base64": base64.b64encode(b"0" * 64).decode("ascii"),
        }
    )
    future_outer = unsigned_outer.model_copy(
        update={"signature_base64": signer.sign_receipt(unsigned_outer)}
    )
    _, identity = _policy()
    with pytest.raises(transport.ExecutorTransportError, match="transport_receipt"):
        transport.verify_executor_transport_receipt(
            future_outer,
            request=request,
            policy=policy,
            attestation_public_key_base64=identity.attestation_public_key_base64,
            attestation_key_id=identity.attestation_key_id,
        )


def test_allocation_backend_failure_is_ambiguous_and_value_redacted(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    """A claimed allocation never retries after an injected backend failure."""

    monkeypatch.setattr(daemon, "_system_utc_clock", lambda: _NOW)
    backend = _AllocationBackend(fail=True)
    engine, request, _ = _allocation_engine(tmp_path, backend)
    with pytest.raises(ExecutorDaemonError) as caught:
        engine._serve_for_test(
            _Source(_allocation_session_bytes(request)), io.BytesIO(), peer_uid=1001
        )
    rendered = "".join(traceback.format_exception(caught.type, caught.value, caught.tb, chain=True))
    assert "allocation backend sentinel" not in rendered
    assert caught.value.__cause__ is None
    assert caught.value.__context__ is None
    assert backend.calls == 1
    assert (
        engine._journal.state(request.allocation_operation_id)
        is ExecutorSessionStateV2.ALLOCATION_AMBIGUOUS
    )
    with pytest.raises(ExecutorDaemonError, match="session_replayed"):
        engine._serve_for_test(
            _Source(_allocation_session_bytes(request)), io.BytesIO(), peer_uid=1001
        )


def test_allocation_rejects_nonzero_chunk_frame_before_claim(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    """Raw framing cannot turn an allocation request into a secret carrier."""

    monkeypatch.setattr(daemon, "_system_utc_clock", lambda: _NOW)
    backend = _AllocationBackend()
    engine, request, _ = _allocation_engine(tmp_path, backend)
    raw = request.model_dump(mode="json")
    raw["chunk_count"] = 1
    stream = _frame(
        ExecutorClientHelloV2(
            schema_version="rsd.executor-client-hello.v2",
            allocation_intent_sha256=_ALLOCATION,
            client_nonce=request.client_nonce,
            session_id=request.session_id,
            request_id=request.request_id,
            executor_id=request.executor_id,
            executor_policy_sha256=request.executor_policy_sha256,
            chunk_count=0,
        )
    )
    sink = io.BytesIO()
    writer = CanonicalFrameWriter(sink)
    writer.begin(
        json.dumps(raw, sort_keys=True, separators=(",", ":")).encode("ascii"), chunk_count=1
    )
    writer.write_chunk(memoryview(b"not-authorized"))
    writer.finish()
    with pytest.raises(ExecutorDaemonError):
        engine._serve_for_test(_Source(stream + sink.getvalue()), io.BytesIO(), peer_uid=1001)
    assert backend.calls == 0
    assert engine._journal.state(request.allocation_operation_id) is None


def test_claim_is_durable_before_first_secret_read(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    monkeypatch.setattr(daemon, "_system_utc_clock", lambda: _NOW)
    events: list[str] = []
    original = ExecutorSessionJournal.claim_materialize

    def claim(self: ExecutorSessionJournal, request: ExecutorTransportRequestV2) -> None:
        events.append("claim")
        original(self, request)

    monkeypatch.setattr(ExecutorSessionJournal, "claim_materialize", claim)
    backend = _Backend()
    engine, request, _, _ = _engine(tmp_path, backend)
    source = _Source(_session_bytes(request), events)
    engine._serve_for_test(source, io.BytesIO(), peer_uid=1001)
    assert events.index("claim") < events.index("chunk-read")
    assert backend.calls == 1


def test_peer_uid_mismatch_does_not_consume_or_mutate(tmp_path: Path) -> None:
    backend = _Backend()
    engine, request, _, _ = _engine(tmp_path, backend)
    source = _Source(_session_bytes(request))
    with pytest.raises(ExecutorDaemonError, match="uds_peer"):
        engine._serve_for_test(source, io.BytesIO(), peer_uid=1002)
    assert source._calls == 0
    assert backend.calls == 0


def test_force_command_requires_the_signed_socket_group_before_any_uds_open(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    """The forced Secure Shell identity cannot reach a root-owned socket by UID alone."""

    policy, _ = _policy()
    artifacts = _artifacts(policy, _genesis(Ed25519PrivateKey.from_private_bytes(b"c" * 32)))
    relay = daemon.ForceCommandRelay(artifacts)
    calls: list[str] = []
    monkeypatch.setattr(daemon.os, "geteuid", lambda: policy.force_command_user_uid)
    monkeypatch.setattr(daemon.os, "getegid", lambda: 1003)
    monkeypatch.setattr(daemon.os, "getgroups", lambda: [1003])
    monkeypatch.setattr(
        daemon,
        "_DeadlineStandardStreams",
        lambda **kwargs: calls.append("stdio"),
    )
    monkeypatch.setattr(
        daemon,
        "_connect_force_command_uds",
        lambda value: calls.append("uds"),
    )

    with pytest.raises(ExecutorDaemonError, match="uds_peer"):
        relay.forward()
    assert calls == []


@pytest.mark.parametrize(
    "update",
    (
        {"daemon_socket_group_gid": 1003},
        {"daemon_socket_mode": 0o600},
    ),
)
def test_force_command_uds_requires_exact_signed_root_group_and_mode_before_connect(
    monkeypatch: pytest.MonkeyPatch,
    update: dict[str, int],
) -> None:
    policy, _ = _policy()
    altered = policy.model_copy(update=update)
    socket_status = SimpleNamespace(
        st_mode=stat.S_IFSOCK | 0o660,
        st_uid=0,
        st_gid=1002,
        st_nlink=1,
        st_dev=1,
        st_ino=2,
    )
    calls: list[str] = []
    monkeypatch.setattr(daemon.os, "lstat", lambda path: socket_status)
    monkeypatch.setattr(
        daemon.socket,
        "socket",
        lambda family, kind: calls.append("connect") or cast(object, None),
    )

    with pytest.raises(ExecutorDaemonError, match="force_command"):
        daemon._connect_force_command_uds(altered)
    assert calls == []


@pytest.mark.parametrize(
    "listen_pid,listen_fds,listen_names",
    (
        ("2", "1", "omninode-rsd-executor"),
        ("1", "2", "omninode-rsd-executor"),
        ("1", "1", "unexpected-listener"),
    ),
)
def test_systemd_activation_rejects_any_unexpected_descriptor_contract_before_fd_use(
    monkeypatch: pytest.MonkeyPatch,
    listen_pid: str,
    listen_fds: str,
    listen_names: str,
) -> None:
    monkeypatch.setattr(daemon.sys, "platform", "linux")
    monkeypatch.setattr(daemon.os, "geteuid", lambda: 0)
    monkeypatch.setattr(daemon.os, "getpid", lambda: 1)
    monkeypatch.setenv("LISTEN_PID", listen_pid)
    monkeypatch.setenv("LISTEN_FDS", listen_fds)
    monkeypatch.setenv("LISTEN_FDNAMES", listen_names)

    with pytest.raises(ExecutorDaemonError, match="activated_socket"):
        daemon._systemd_activated_listener()


def test_systemd_activated_session_refuses_default_backend_before_accepting_material(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    policy, _ = _policy()
    journal = ExecutorSessionJournal.provision(tmp_path / "journal.sqlite3", journal_id=_UUIDS[0])
    engine = daemon._executor_daemon_session_engine_for_test(
        policy=policy,
        signer_genesis=_genesis(Ed25519PrivateKey.from_private_bytes(b"c" * 32)),
        attestation_signer=_Attestation(),
        journal=journal,
        memory_safety=_Memory(),
    )
    calls: list[str] = []
    monkeypatch.setattr(
        daemon,
        "_systemd_activated_listener",
        lambda: calls.append("listener"),
    )

    with pytest.raises(ExecutorDaemonError, match="backend_unavailable"):
        daemon.serve_systemd_activated_session(engine)
    assert calls == []


def test_session_journal_rejects_a_schema_text_substitution_before_a_session(
    tmp_path: Path,
) -> None:
    """Metadata version alone cannot bless a journal with changed SQL semantics."""

    path = tmp_path / "journal.sqlite3"
    journal = ExecutorSessionJournal.provision(path, journal_id=_UUIDS[0])
    with sqlite3.connect(path) as connection:
        schema_version = connection.execute("PRAGMA schema_version").fetchone()
        assert schema_version is not None
        connection.execute("PRAGMA writable_schema = ON")
        result = connection.execute(
            "UPDATE sqlite_master "
            "SET sql = REPLACE(sql, 'executor_receipt_sha256 TEXT,', "
            "'executor_receipt_sha256 TEXT DEFAULT NULL,') "
            "WHERE type = 'table' AND name = 'sessions'"
        )
        assert result.rowcount == 1
        connection.execute("PRAGMA writable_schema = OFF")
        connection.execute(f"PRAGMA schema_version = {schema_version[0] + 1}")
    with pytest.raises(ExecutorDaemonError, match="session_journal"):
        journal.state(_UUIDS[1])


def test_live_daemon_constructor_rejects_caller_model_bundle(tmp_path: Path) -> None:
    """The daemon production factory must load verified artifacts itself."""

    policy, _ = _policy()
    journal = ExecutorSessionJournal.provision(tmp_path / "journal.sqlite3", journal_id=_UUIDS[0])
    with pytest.raises(ExecutorDaemonError, match="daemon_configuration"):
        ExecutorDaemonSessionEngine(
            policy=policy,
            signer_genesis=_genesis(Ed25519PrivateKey.from_private_bytes(b"c" * 32)),
            attestation_signer=_Attestation(),
            journal=journal,
            backend=_Backend(),
            memory_safety=_Memory(),
        )


def test_attestation_signer_rejects_direct_seed_injection() -> None:
    """Only a credential descriptor/path may supply the daemon signing seed."""

    _, identity = _policy()
    seed = bytearray(b"a" * 32)
    with pytest.raises(ExecutorDaemonError, match="attestation_credential"):
        daemon.SystemdCredentialAttestationSigner(seed, identity=identity)
    assert not any(seed)


def test_uds_frame_deadline_rejects_a_stalled_peer(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    """A partial peer cannot retain the daemon's one-session lease forever."""

    class StalledSocket:
        def settimeout(self, value: float) -> None:
            del value

        def close(self) -> None:
            return None

    values = iter((1.0, 2.1))
    monkeypatch.setattr(daemon.time, "monotonic", lambda: next(values))
    frame = daemon._UnixSocketFrame(cast(object, StalledSocket()), timeout_seconds=1)
    with pytest.raises(ExecutorDaemonError, match="uds_timeout"):
        frame.read_exact(1)


def test_replay_is_rejected_after_terminal_state(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    monkeypatch.setattr(daemon, "_system_utc_clock", lambda: _NOW)
    backend = _Backend()
    engine, request, _, _ = _engine(tmp_path, backend)
    engine._serve_for_test(_Source(_session_bytes(request)), io.BytesIO(), peer_uid=1001)
    with pytest.raises(ExecutorDaemonError, match="session_replayed"):
        engine._serve_for_test(_Source(_session_bytes(request)), io.BytesIO(), peer_uid=1001)
    assert backend.calls == 1


def test_backend_failure_is_persisted_as_ambiguous_and_redacts_material(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    monkeypatch.setattr(daemon, "_system_utc_clock", lambda: _NOW)
    backend = _Backend(fail=True)
    engine, request, _, _ = _engine(tmp_path, backend)
    secret = b"must-never-appear-in-errors"
    stream = _frame(
        ExecutorClientHelloV2(
            schema_version="rsd.executor-client-hello.v2",
            allocation_intent_sha256=_ALLOCATION,
            client_nonce=request.client_nonce,
            session_id=request.session_id,
            request_id=request.request_id,
            executor_id=request.executor_id,
            executor_policy_sha256=request.executor_policy_sha256,
            chunk_count=0,
        )
    ) + _frame(
        request,
        count=5,
        chunks=tuple(
            (secret + bytes([index]))[: slot.encoded_byte_count]
            for index, slot in enumerate(request.slots)
        ),
    )
    with pytest.raises(ExecutorDaemonError) as caught:
        engine._serve_for_test(_Source(stream), io.BytesIO(), peer_uid=1001)
    assert secret.decode("ascii") not in str(caught.value)
    journal = engine._journal
    assert journal.state(request.operation_id) is ExecutorSessionStateV2.START_AMBIGUOUS


def test_backend_exception_chain_is_sanitized_after_secret_delivery(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    """A backend exception cannot preserve a value through error-chain fields."""

    monkeypatch.setattr(daemon, "_system_utc_clock", lambda: _NOW)
    backend = _SecretBearingRuntimeFailureBackend()
    engine, request, _, _ = _engine(tmp_path, backend)
    with pytest.raises(ExecutorDaemonError, match="backend_effect") as caught:
        engine._serve_for_test(_Source(_session_bytes(request)), io.BytesIO(), peer_uid=1001)
    rendered = "".join(traceback.format_exception(caught.type, caught.value, caught.tb, chain=True))
    assert backend.sentinel not in rendered
    assert caught.value.__cause__ is None
    assert caught.value.__context__ is None
    assert engine._journal.state(request.operation_id) is ExecutorSessionStateV2.START_AMBIGUOUS


def test_future_inner_runtime_receipt_is_ambiguous_before_daemon_attestation(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    """The daemon must not sign a backend receipt dated after its trusted clock."""

    monkeypatch.setattr(daemon, "_system_utc_clock", lambda: _NOW)
    backend = _FutureRuntimeReceiptBackend()
    engine, request, _, _ = _engine(tmp_path, backend)
    with pytest.raises(ExecutorDaemonError, match="backend_receipt"):
        engine._serve_for_test(_Source(_session_bytes(request)), io.BytesIO(), peer_uid=1001)
    assert backend.calls == 1
    assert engine._journal.state(request.operation_id) is ExecutorSessionStateV2.START_AMBIGUOUS


def test_unfinished_engine_checkpoint_is_ambiguous_and_cannot_be_replayed(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    """A crash before a per-step projection receipt never permits auto-adoption."""

    monkeypatch.setattr(daemon, "_system_utc_clock", lambda: _NOW)
    backend = _CheckpointGapBackend()
    engine, request, _, _ = _engine(tmp_path, backend)
    with pytest.raises(ExecutorDaemonError, match="backend_effect"):
        engine._serve_for_test(_Source(_session_bytes(request)), io.BytesIO(), peer_uid=1001)
    assert backend.calls == 1
    assert engine._journal.state(request.operation_id) is ExecutorSessionStateV2.START_AMBIGUOUS
    with pytest.raises(ExecutorDaemonError, match="session_replayed"):
        engine._serve_for_test(_Source(_session_bytes(request)), io.BytesIO(), peer_uid=1001)


def test_recovery_requires_the_verified_signer_and_exact_journal_session_binding(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    """A self-signed outcome cannot resolve a live ambiguous operation."""

    monkeypatch.setattr(daemon, "_system_utc_clock", lambda: _NOW)
    backend = _Backend(fail=True)
    engine, request, signer, policy = _engine(tmp_path, backend)
    with pytest.raises(ExecutorDaemonError, match="backend_effect"):
        engine._serve_for_test(_Source(_session_bytes(request)), io.BytesIO(), peer_uid=1001)
    artifacts = _artifacts(policy, _genesis(signer))
    receipt = _recovery_receipt(request, signer)

    attacker = Ed25519PrivateKey.generate()
    forged = _recovery_receipt(request, attacker)
    with pytest.raises(ExecutorDaemonError, match="session_recovery"):
        engine._journal.abandon(forged, artifacts=artifacts)
    assert engine._journal.state(request.operation_id) is ExecutorSessionStateV2.START_AMBIGUOUS

    cross_journal = receipt.model_copy(update={"journal_uuid": _UUIDS[4]})
    cross_journal = cross_journal.model_copy(
        update={
            "signature_base64": base64.b64encode(
                signer.sign(daemon._recovery_receipt_message(cross_journal))
            ).decode("ascii")
        }
    )
    with pytest.raises(ExecutorDaemonError, match="session_recovery"):
        engine._journal.abandon(cross_journal, artifacts=artifacts)
    assert engine._journal.state(request.operation_id) is ExecutorSessionStateV2.START_AMBIGUOUS

    engine._journal.abandon(receipt, artifacts=artifacts)
    assert engine._journal.state(request.operation_id) is ExecutorSessionStateV2.ABANDONED


def test_receipt_is_redacted_and_delivery_is_bounded(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    monkeypatch.setattr(daemon, "_system_utc_clock", lambda: _NOW)
    backend = _Backend()
    engine, request, _, _ = _engine(tmp_path, backend)
    output = io.BytesIO()
    engine._serve_for_test(_Source(_session_bytes(request)), output, peer_uid=1001)
    response = _Source(output.getvalue())
    hello = read_raw_transport(response, require_eof=False)
    receipt = read_raw_transport(response, require_eof=False)
    assert hello.chunks == ()
    assert receipt.chunks == ()
    assert all(value not in receipt.metadata_bytes for value in backend.sink.values)
    assert len(backend.sink.values) == 5
    assert engine._journal.state(request.operation_id) is ExecutorSessionStateV2.STARTED
