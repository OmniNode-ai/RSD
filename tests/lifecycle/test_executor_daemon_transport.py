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
import stat
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
    ExecutorClientHelloV2,
    ExecutorTransportPolicyV2,
    ExecutorTransportRequestV2,
    SecureShellIdentityReferenceV1,
)
from omninode_rsd.lifecycle.infisical_disposable import (
    ExecutorIdentityV1,
    ExecutorInstallationPolicyV1,
    ExecutorInstallationReceiptV1,
    SecretDeliverySinkV1,
    SecretDeliverySlotV1,
    SSHConnectionPolicyV1,
)
from omninode_rsd.lifecycle.provider_crypto import SignerGenesisV1
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
    unsigned = ExecutorTransportRequestV2(
        schema_version="rsd.executor-transport-request.v2",
        message_kind="materialize",
        operation_scope="materialize_and_start_runtime_v1",
        allocation_intent_sha256=_ALLOCATION,
        operation_id=_UUIDS[1],
        predecessor_materialization_operation_id=None,
        journal_uuid=_UUIDS[0],
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


class _Sink(ExecutorSecretSink):
    def __init__(self) -> None:
        self.values: list[bytes] = []

    def accept(self, descriptor: object, value: memoryview) -> None:
        del descriptor
        self.values.append(bytes(value))


class _Backend:
    def __init__(self, *, fail: bool = False) -> None:
        self.fail = fail
        self.sink = _Sink()
        self.calls = 0

    def materialize_and_start(self, context: object, delivery: object) -> ExecutorBackendReceiptV2:
        del context
        self.calls += 1
        if self.fail:
            raise ExecutorDaemonError("backend_effect")
        cast(object, delivery).consume_into(self.sink)
        return ExecutorBackendReceiptV2(backend_receipt_sha256=_hash("backend-receipt"))

    def start(self, context: object, delivery: object) -> ExecutorBackendReceiptV2:
        return self.materialize_and_start(context, delivery)


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
            attestation_signer=_Attestation(),
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
