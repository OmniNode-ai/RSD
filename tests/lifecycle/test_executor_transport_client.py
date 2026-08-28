"""Offline adversarial coverage for the remote executor client boundary."""

from __future__ import annotations

import base64
import hashlib
import io
import json
import struct
from datetime import UTC, datetime
from pathlib import Path
from typing import cast
from uuid import UUID

import pytest
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey

import omninode_rsd.lifecycle.executor_daemon as daemon
import omninode_rsd.lifecycle.executor_transport as transport
from omninode_rsd.lifecycle.executor_installation import (
    ExecutorInstallationManifestV2,
    ExecutorInstallationRenderError,
    render_executor_installation,
)
from omninode_rsd.lifecycle.infisical_disposable import (
    ExecutorIdentityV1,
    ExecutorInstallationPolicyV1,
    ExecutorInstallationReceiptV1,
    SecretCapabilityPolicyV1,
    SecretDeliveryRequestV1,
    SecretDeliverySinkV1,
    SecretDeliverySlotV1,
    SecretHandlingPolicyV1,
    SSHConnectionPolicyV1,
    canonical_sha256,
)
from omninode_rsd.lifecycle.provider_crypto import (
    KeychainItemReferenceV1,
    ProviderFingerprintAttestationV2,
    ProviderMaterialFingerprintV1,
    ProviderMaterialFormat,
    ProviderMaterialPolicyV2,
    ProviderMaterialPurpose,
    ProviderMaterialSpecV1,
    ProviderReferenceV1,
    SignerGenesisV1,
)
from omninode_rsd.lifecycle.transport import (
    _HEADER,
    FRAME_MAGIC,
    FRAME_VERSION,
    MAX_CHUNK_BYTES,
    MAX_CHUNKS,
    MAX_METADATA_BYTES,
    CanonicalFrameReader,
    TransportError,
    TransportMetadata,
    encode_transport,
)


def _h(value: str) -> str:
    return hashlib.sha256(value.encode("ascii")).hexdigest()


_H = _h
_NOW = datetime(2026, 8, 28, 12, 5, tzinfo=UTC)
_UUIDS = (
    "123e4567-e89b-42d3-a456-426614174000",
    "123e4567-e89b-42d3-a456-426614174001",
    "123e4567-e89b-42d3-a456-426614174002",
    "123e4567-e89b-42d3-a456-426614174003",
)


def _ssh_ed25519_blob(public_key: bytes) -> bytes:
    assert len(public_key) == 32
    return (
        struct.pack("!I", len(b"ssh-ed25519"))
        + b"ssh-ed25519"
        + struct.pack("!I", len(public_key))
        + public_key
    )


def _policy() -> transport.ExecutorTransportPolicyV2:
    host = _H("host-key")
    client = _H("client-key")
    ssh = SSHConnectionPolicyV1.model_construct(
        host_key_fingerprints_sha256=(host,),
        dedicated_user="executor-user",
        client_key_fingerprint_sha256=client,
        force_command="omninode_rsd_executor_v1",
        force_command_sha256=_H("omninode_rsd_executor_v1"),
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
    identity = transport.SecureShellIdentityReferenceV1(
        key_path="/tmp/executor-key",
        public_key_path="/tmp/executor-key.pub",
        public_key_fingerprint_sha256=client,
    )
    return transport.ExecutorTransportPolicyV2(
        schema_version="rsd.executor-transport-policy.v2",
        allocation_intent_sha256=_H("allocation"),
        executor_installation_policy_sha256=_H("installation-policy"),
        executor_installation_receipt_sha256=_H("installation-receipt"),
        executor_id="executor-1",
        endpoint="executor.example.test",
        endpoint_sha256=_H("executor.example.test"),
        ssh_executable_path="/usr/bin/ssh",
        ssh_executable_sha256=_H("ssh-executable"),
        known_hosts_path="/tmp/executor-known-hosts",
        known_hosts_sha256=_H("known-hosts"),
        identity=identity,
        ssh_policy=ssh,
        daemon_socket_path="/run/omninode-rsd/executor.sock",
        daemon_socket_policy_sha256=_H("socket-policy"),
        force_command_user_uid=1001,
        daemon_socket_group="executor-relay",
        daemon_socket_group_gid=1002,
        daemon_socket_mode=0o660,
        host_key_fingerprint_sha256=host,
        package_sha256=_H("package"),
        template_bundle_sha256=_H("template"),
        core_dump_disabled=True,
        swap_protection_required=True,
        mlock_required=True,
        max_session_seconds=60,
        created_at="2026-08-28T12:00:00Z",
        expires_at="2026-08-28T13:00:00Z",
        signer_key_id="signer-1",
        signature_base64=base64.b64encode(b"s" * 64).decode("ascii"),
    )


def _artifacts(
    policy: transport.ExecutorTransportPolicyV2,
) -> transport.VerifiedExecutorTransportArtifactsV2:
    attestation = Ed25519PrivateKey.from_private_bytes(b"a" * 32).public_key().public_bytes_raw()
    executor = ExecutorIdentityV1.model_construct(
        executor_id=policy.executor_id,
        platform="remote_linux_systemd_v1",
        authenticated_transport="ssh_forced_command_v1",
        endpoint_sha256=_H("executor-endpoint"),
        host_fingerprint_sha256=policy.host_key_fingerprint_sha256,
        control_capability_fingerprint_sha256=_H("control"),
        attestation_key_id="executor-attestation",
        attestation_public_key_base64=base64.b64encode(attestation).decode("ascii"),
        attestation_public_key_fingerprint_sha256=_H("attestation"),
        credential_custody="tpm2_systemd_encrypted_credential_v1",
        monotonic_revision=1,
        expires_at="2026-08-28T13:00:00Z",
    )
    installation = ExecutorInstallationPolicyV1.model_construct(
        executor=executor,
        ssh=policy.ssh_policy,
        package_sha256=policy.package_sha256,
        template_bundle_sha256=policy.template_bundle_sha256,
    )
    receipt = ExecutorInstallationReceiptV1.model_construct()
    genesis = SignerGenesisV1.model_construct()
    return transport._verified_executor_transport_artifacts_for_test(
        policy=policy,
        signer_genesis=genesis,
        installation_policy=installation,
        installation_receipt=receipt,
    )


class _Process:
    def __init__(self) -> None:
        self.stdin = io.BytesIO()
        self.stdout = io.BytesIO()
        self.stderr = io.BytesIO()
        self.killed = False

    def wait(self, timeout: float | None = None) -> int:
        del timeout
        return 0

    def poll(self) -> int | None:
        return 0

    def kill(self) -> None:
        self.killed = True


def test_canonical_reader_requires_complete_ordered_frames() -> None:
    encoded = encode_transport(
        TransportMetadata.start(
            client_nonce=UUID(_UUIDS[0]),
            server_nonce=UUID(_UUIDS[1]),
            session_id=UUID(_UUIDS[2]),
            operation_id=UUID(_UUIDS[3]),
            request_id=UUID("123e4567-e89b-42d3-a456-426614174004"),
            chunk_count=1,
        ),
        (b"opaque",),
    )

    class Source:
        def __init__(self, value: bytes) -> None:
            self._stream = io.BytesIO(value)

        def read_exact(self, count: int) -> bytes:
            return self._stream.read(count)

    reader = CanonicalFrameReader(Source(encoded))
    assert reader.read_metadata()
    assert reader.read_chunk() == b"opaque"
    reader.finish()
    with pytest.raises(TransportError):
        reader.read_chunk()


@pytest.mark.parametrize("bad_size", (MAX_METADATA_BYTES + 1, MAX_CHUNK_BYTES + 1))
def test_frame_reader_rejects_bounds_without_echoing_payload(bad_size: int) -> None:
    payload = b"do-not-echo-transport-material"
    header = _HEADER.pack(FRAME_MAGIC, FRAME_VERSION, 1, 0, bad_size)

    class Source:
        def read_exact(self, count: int) -> bytes:
            return (header + payload)[:count]

    with pytest.raises(TransportError) as caught:
        CanonicalFrameReader(Source()).read_metadata()
    assert payload.decode() not in str(caught.value)


def test_fixed_ssh_argv_has_no_shell_or_material_and_pins_known_hosts(tmp_path: Path) -> None:
    policy = _policy()
    raw_key = b"host-public-key"
    client_blob = _ssh_ed25519_blob(b"c" * 32)
    public = b"ssh-ed25519 " + base64.b64encode(client_blob) + b"\n"
    known = b"executor.example.test ssh-ed25519 " + base64.b64encode(raw_key) + b"\n"
    key = tmp_path / "key"
    key.write_bytes(b"opaque-key-material")
    key.chmod(0o600)
    public_path = tmp_path / "key.pub"
    public_path.write_bytes(public)
    public_path.chmod(0o600)
    known_hosts_path = tmp_path / "known_hosts"
    known_hosts_path.write_bytes(known)
    known_hosts_path.chmod(0o600)
    policy = policy.model_copy(
        update={
            "known_hosts_path": str(known_hosts_path),
            "known_hosts_sha256": hashlib.sha256(known).hexdigest(),
            "identity": policy.identity.model_copy(
                update={
                    "key_path": str(key),
                    "public_key_path": str(public_path),
                    "public_key_fingerprint_sha256": hashlib.sha256(client_blob).hexdigest(),
                }
            ),
            "host_key_fingerprint_sha256": _H("host-public-key"),
            "ssh_policy": policy.ssh_policy.model_copy(
                update={"host_key_fingerprints_sha256": (_H("host-public-key"),)}
                | {"client_key_fingerprint_sha256": hashlib.sha256(client_blob).hexdigest()}
            ),
        }
    )
    artifacts = _artifacts(policy)
    process = _Process()
    captured: dict[str, object] = {}

    def popen(argv: tuple[str, ...], **kwargs: object) -> _Process:
        captured["argv"] = argv
        captured["kwargs"] = kwargs
        return process

    client = transport._macos_secure_shell_client_for_test(
        artifacts,
        popen=popen,
        executable_validator=lambda path, digest: None,
        owner_reader=lambda path, maximum, phase: known if phase == "known_hosts" else public,
    )
    with client.open():
        pass
    argv = cast(tuple[str, ...], captured["argv"])
    kwargs = cast(dict[str, object], captured["kwargs"])
    assert "--" not in argv
    assert policy.endpoint in argv
    assert all("opaque-key-material" not in item for item in argv)
    assert kwargs["shell"] is False
    assert kwargs["env"] == {"LANG": "C", "LC_ALL": "C"}
    assert "StrictHostKeyChecking=yes" in argv
    assert "UpdateHostKeys=no" in argv
    assert "ControlMaster=no" in argv
    assert policy.identity.key_path not in argv
    assert any(item.startswith("UserKnownHostsFile=/dev/fd/") for item in argv)
    assert any(item.startswith("/dev/fd/") for item in argv)
    assert len(cast(tuple[int, ...], kwargs["pass_fds"])) == 2

    bad = policy.model_copy(update={"known_hosts_sha256": _H("different-hosts")})
    with pytest.raises(transport.ExecutorTransportError, match="known_hosts"):
        transport._macos_secure_shell_client_for_test(
            _artifacts(bad),
            popen=popen,
            executable_validator=lambda path, digest: None,
            owner_reader=lambda path, maximum, phase: known if phase == "known_hosts" else public,
        ).launch_spec()


@pytest.mark.parametrize(
    "public_key",
    (
        b"rsa-sha2-512 " + base64.b64encode(_ssh_ed25519_blob(b"r" * 32)) + b"\n",
        b"ssh-ed25519 " + base64.b64encode(b"not-an-open-ssh-key") + b"\n",
        b"ssh-ed25519 "
        + base64.b64encode(
            struct.pack("!I", len(b"ssh-ed25519"))
            + b"ssh-ed25519"
            + struct.pack("!I", 31)
            + b"x" * 31
        )
        + b"\n",
        b"ssh-ed25519 " + base64.b64encode(_ssh_ed25519_blob(b"r" * 32)) + b" comment\n",
    ),
)
def test_identity_reference_requires_a_canonical_ed25519_key_blob(public_key: bytes) -> None:
    """An outer Base64 token or key-type label is not a trust boundary."""

    with pytest.raises(transport.ExecutorTransportError, match="identity_reference"):
        transport._public_key_fingerprint(public_key)


def test_transport_policy_rejects_root_or_unbound_socket_identity() -> None:
    policy = _policy()
    for update in (
        {"force_command_user_uid": 0},
        {"daemon_socket_group": "root"},
        {"daemon_socket_group_gid": 0},
        {"daemon_socket_mode": 0o600},
    ):
        with pytest.raises(ValueError):
            transport.ExecutorTransportPolicyV2.model_validate(policy.model_dump() | update)


@pytest.mark.parametrize(
    "raw",
    (
        b"# comment\nexecutor.example.test ssh-ed25519 aG9zdC1wdWJsaWMta2V5\n",
        b"executor.example.test ssh-ed25519 aG9zdC1wdWJsaWMta2V5",
        b"executor.example.test,alias ssh-ed25519 aG9zdC1wdWJsaWMta2V5\n",
    ),
)
def test_known_hosts_parser_rejects_noncanonical_or_alias_forms(raw: bytes) -> None:
    with pytest.raises(transport.ExecutorTransportError, match="known_hosts"):
        transport._known_host_fingerprints(raw, endpoint="executor.example.test")


def test_live_client_rejects_caller_constructed_artifact_container() -> None:
    """Only the signature-verification loader may mint live transport inputs."""

    policy = _policy()
    with pytest.raises(transport.ExecutorTransportError, match="transport_artifacts"):
        transport.VerifiedExecutorTransportArtifactsV2(
            policy=policy,
            signer_genesis=SignerGenesisV1.model_construct(),
            installation_policy=ExecutorInstallationPolicyV1.model_construct(),
            installation_receipt=ExecutorInstallationReceiptV1.model_construct(),
        )


def test_live_client_rejects_caller_selected_process_or_file_seams() -> None:
    with pytest.raises(transport.ExecutorTransportError, match="transport_artifacts"):
        transport.MacOSSecureShellClient(
            _artifacts(_policy()),
            _popen=lambda argv, **kwargs: _Process(),
        )


def test_ssh_pipe_deadline_rejects_a_stalled_descriptor(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    """A partial remote peer cannot retain a delivery session indefinitely."""

    class StalledPipe(io.BytesIO):
        def fileno(self) -> int:
            return 17

    process = _Process()
    process.stdout = StalledPipe()
    session = transport.SecureShellProcessSession(process, timeout_seconds=1)
    monkeypatch.setattr(transport.select, "select", lambda *args: ([], [], []))
    with pytest.raises(transport.ExecutorTransportError, match="ssh_timeout"):
        session.read_exact(1)


def test_request_verifier_rejects_expired_or_cross_session_metadata(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    policy = _policy()
    signer_key = Ed25519PrivateKey.generate()
    public = signer_key.public_key().public_bytes_raw()
    genesis = SignerGenesisV1.model_construct(
        key_id="signer-1",
        allocation_intent_sha256=policy.allocation_intent_sha256,
        public_key_base64=base64.b64encode(public).decode("ascii"),
        public_key_fingerprint_sha256=hashlib.sha256(public).hexdigest(),
    )
    hello = transport.ExecutorHelloV2.model_construct(
        schema_version="rsd.executor-hello.v2",
        allocation_intent_sha256=policy.allocation_intent_sha256,
        client_nonce=_UUIDS[0],
        server_nonce=_UUIDS[1],
        session_id=_UUIDS[2],
        request_id=_UUIDS[3],
        executor_id=policy.executor_id,
        executor_policy_sha256=policy.policy_sha256(),
        package_sha256=policy.package_sha256,
        template_bundle_sha256=policy.template_bundle_sha256,
        expires_at="2026-08-28T12:05:30Z",
        chunk_count=0,
        signer_key_id="executor-attestation",
        signature_base64=base64.b64encode(b"h" * 64).decode("ascii"),
    )
    slots = (
        SecretDeliverySlotV1(
            purpose="encryption_key",
            reference_sha256=_H("encryption-key"),
            format="infisical_hex_16_v1",
            encoded_byte_count=32,
            sink=SecretDeliverySinkV1.INFISICAL_TARGET_PROCESS_ENVIRONMENT,
            target_processes=("primary_infisical", "restore_infisical"),
        ),
        SecretDeliverySlotV1(
            purpose="auth_secret",
            reference_sha256=_H("auth-secret"),
            format="infisical_auth_secret_base64_32_v1",
            encoded_byte_count=44,
            sink=SecretDeliverySinkV1.INFISICAL_TARGET_PROCESS_ENVIRONMENT,
            target_processes=("primary_infisical", "restore_infisical"),
        ),
        SecretDeliverySlotV1(
            purpose="primary_valkey_password",
            reference_sha256=_H("primary-valkey"),
            format="valkey_password_base64url_32_v1",
            encoded_byte_count=43,
            sink=SecretDeliverySinkV1.VALKEY_STDIN_CONFIGURATION,
            target_processes=("primary_valkey",),
        ),
        SecretDeliverySlotV1(
            purpose="restore_valkey_password",
            reference_sha256=_H("restore-valkey"),
            format="valkey_password_base64url_32_v1",
            encoded_byte_count=43,
            sink=SecretDeliverySinkV1.VALKEY_STDIN_CONFIGURATION,
            target_processes=("restore_valkey",),
        ),
        SecretDeliverySlotV1(
            purpose="postgres_application_password",
            reference_sha256=_H("postgres-password"),
            format="postgres_application_password_base64url_32_v1",
            encoded_byte_count=43,
            sink=SecretDeliverySinkV1.POSTGRES_APPLICATION_TARGET_ENVIRONMENT,
            target_processes=("postgres_application_target",),
        ),
    )
    witness = transport.RemoteEffectAuthorizationWitnessV1(
        schema_version="rsd.remote-effect-authorization-witness.v1",
        operation_scope="materialize_and_start_runtime_v1",
        operation_id=_UUIDS[0],
        allocation_intent_sha256=policy.allocation_intent_sha256,
        external_replay_tombstone_sha256=_H("external-tombstone"),
        replay_policy_sha256=_H("replay-policy"),
        executor_policy_sha256=policy.policy_sha256(),
        journal_uuid=_UUIDS[1],
        idempotency_key=_H("idempotency"),
        effect_intent_sha256=_H("effect-intent"),
        predecessor_attestation_sha256=_H("predecessor-attestation"),
        predecessor_operation_id=None,
        docker_engine_control_policy_sha256=_H("docker-policy"),
        postgres_prepared_control_policy_sha256=_H("postgres-policy"),
        host_fingerprint_sha256=_H("executor-host"),
        engine_fingerprint_sha256=_H("engine"),
        effect_plan_sha256=_H("effect-plan"),
        engine_operation_plan_sha256=transport.executor_engine_operation_plan_sha256(
            operation_scope="materialize_and_start_runtime_v1",
            operation_id=_UUIDS[0],
        ),
        artifact_chain_sha256=_H("artifact-chain"),
        issued_at="2026-08-28T12:04:59Z",
        expires_at="2026-08-28T12:05:30Z",
        signer_key_id="signer-1",
        signature_base64=base64.b64encode(b"w" * 64).decode("ascii"),
    )
    witness = witness.model_copy(
        update={
            "signature_base64": base64.b64encode(
                signer_key.sign(transport.remote_effect_authorization_witness_message(witness))
            ).decode("ascii")
        }
    )
    request = transport.ExecutorTransportRequestV2(
        schema_version="rsd.executor-transport-request.v2",
        message_kind="materialize",
        operation_scope="materialize_and_start_runtime_v1",
        allocation_intent_sha256=policy.allocation_intent_sha256,
        operation_id=_UUIDS[0],
        journal_uuid=_UUIDS[1],
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
        request_id=_UUIDS[3],
        client_nonce=_UUIDS[0],
        server_nonce=_UUIDS[1],
        session_id=_UUIDS[2],
        request_nonce_sha256=_H("nonce"),
        channel_binding_sha256=_H("channel"),
        session_binding_sha256=_H("session"),
        host_key_fingerprint_sha256=policy.host_key_fingerprint_sha256,
        executor_id=policy.executor_id,
        executor_policy_sha256=policy.policy_sha256(),
        package_sha256=policy.package_sha256,
        template_bundle_sha256=policy.template_bundle_sha256,
        installation_receipt_sha256=policy.executor_installation_receipt_sha256,
        expires_at="2026-08-28T12:05:30Z",
        chunk_count=5,
        slots=slots,
        signer_key_id="signer-1",
        signature_base64=base64.b64encode(b"s" * 64).decode(),
    )
    monkeypatch.setattr(transport, "_system_utc_clock", lambda: _NOW)
    with pytest.raises(transport.ExecutorTransportError, match="transport_request"):
        transport.verify_executor_transport_request(
            request, signer_genesis=genesis, hello=hello, policy=policy
        )
    with pytest.raises(transport.ExecutorTransportError):
        transport.verify_executor_transport_request(
            request.model_copy(update={"request_id": _UUIDS[0]}),
            signer_genesis=genesis,
            hello=hello,
            policy=policy,
        )

    # This deliberately malformed object exercises the verifier's strict
    # reparse boundary: an untrusted caller cannot construct an old hash-only
    # receipt now that runtime evidence is a required typed artifact.
    receipt = transport.ExecutorTransportReceiptV2.model_construct(
        schema_version="rsd.executor-transport-receipt.v2",
        operation_scope=request.operation_scope,
        operation_id=request.operation_id,
        request_id=request.request_id,
        journal_uuid=request.journal_uuid,
        client_nonce=request.client_nonce,
        server_nonce=request.server_nonce,
        session_id=request.session_id,
        request_nonce_sha256=request.request_nonce_sha256,
        channel_binding_sha256=request.channel_binding_sha256,
        session_binding_sha256=request.session_binding_sha256,
        executor_id=request.executor_id,
        executor_policy_sha256=request.executor_policy_sha256,
        package_sha256=request.package_sha256,
        template_bundle_sha256=request.template_bundle_sha256,
        delivery_binding_sha256=_H("wrong-delivery-binding"),
        authorization_witness_sha256=canonical_sha256(request.authorization_witness),
        executor_receipt_sha256=_H("backend-receipt"),
        executor_receipt=object(),
        status="materialized",
        completed_at="2026-08-28T12:05:01Z",
        chunk_count=0,
        signer_key_id="executor-attestation",
        signature_base64=base64.b64encode(b"r" * 64).decode("ascii"),
    )
    attestation_key = Ed25519PrivateKey.generate().public_key().public_bytes_raw()
    with pytest.raises(transport.ExecutorTransportError, match="transport_receipt"):
        transport.verify_executor_transport_receipt(
            receipt,
            request=request,
            policy=policy,
            attestation_public_key_base64=base64.b64encode(attestation_key).decode("ascii"),
            attestation_key_id="executor-attestation",
        )


def test_renderer_is_value_free_and_has_no_write_side_effect(tmp_path: Path) -> None:
    policy = _policy()
    client_key_blob = _ssh_ed25519_blob(b"c" * 32)
    client_key = "ssh-ed25519 " + base64.b64encode(client_key_blob).decode("ascii")
    client_fingerprint = hashlib.sha256(client_key_blob).hexdigest()
    policy = policy.model_copy(
        update={
            "identity": policy.identity.model_copy(
                update={"public_key_fingerprint_sha256": client_fingerprint}
            ),
            "ssh_policy": policy.ssh_policy.model_copy(
                update={"client_key_fingerprint_sha256": client_fingerprint}
            ),
        }
    )
    installation = ExecutorInstallationPolicyV1.model_construct(
        executor_id="unused",
        executor=ExecutorIdentityV1.model_construct(executor_id="executor-1"),
        ssh=policy.ssh_policy,
        package_sha256=policy.package_sha256,
        template_bundle_sha256=policy.template_bundle_sha256,
        unix_socket_policy_sha256=policy.daemon_socket_policy_sha256,
    )
    manifest = ExecutorInstallationManifestV2(
        schema_version="rsd.executor-installation-manifest.v2",
        executor_id="executor-1",
        force_command_user="executor-user",
        force_command_user_uid=1001,
        daemon_socket_group="executor-relay",
        daemon_socket_group_gid=1002,
        credential_name="rsd-credential",
        state_directory_name="rsd-executor-state",
        daemon_executable_path=str(tmp_path / "daemon"),
        force_command_path=str(tmp_path / "force"),
        systemd_unit_path=str(tmp_path / "unit.service"),
        socket_unit_path=str(tmp_path / "socket.socket"),
        sshd_fragment_path=str(tmp_path / "sshd"),
        authorized_key_policy_path=str(tmp_path / "authorized"),
        daemon_socket_path=policy.daemon_socket_path,
        client_authorized_key=client_key,
        daemon_socket_mode=0o660,
        daemon_file_mode=0o700,
        config_file_mode=0o644,
        authorized_key_file_mode=0o600,
    )
    rendered = render_executor_installation(
        manifest, transport_policy=policy, installation_policy=installation
    )
    assert rendered.files
    assert all(not Path(item.path).exists() for item in rendered.files)
    assert all("password" not in item.content.lower() for item in rendered.files)
    assert len(rendered.files) == 4
    assert "SocketUser=root" in rendered.files[1].content
    assert "SocketGroup=executor-relay" in rendered.files[1].content
    assert "SocketMode=0660" in rendered.files[1].content
    assert "FileDescriptorName=omninode-rsd-executor" in rendered.files[1].content
    assert "StateDirectory=rsd-executor-state" in rendered.files[0].content
    assert "StateDirectoryMode=0700" in rendered.files[0].content
    assert "ReadWritePaths=%S/rsd-executor-state" in rendered.files[0].content
    assert "WorkingDirectory=%S/rsd-executor-state" in rendered.files[0].content
    assert "AuthorizedKeysFile " + manifest.authorized_key_policy_path in rendered.files[2].content
    assert "DisableForwarding yes" in rendered.files[2].content
    assert "no-agent-forwarding" in rendered.files[3].content
    assert rendered.files[3].mode == 0o600
    assert rendered.files[3].content == (
        f'command="{manifest.force_command_path}",restrict,'
        "no-agent-forwarding,no-port-forwarding,no-pty,no-user-rc,no-X11-forwarding "
        f"{client_key}\n"
    )

    with pytest.raises(ExecutorInstallationRenderError, match="installation_binding"):
        render_executor_installation(
            manifest.model_copy(update={"force_command_user_uid": 1003}),
            transport_policy=policy,
            installation_policy=installation,
        )


@pytest.mark.parametrize(
    "key",
    (
        "rsa-sha2-512 " + base64.b64encode(_ssh_ed25519_blob(b"r" * 32)).decode("ascii"),
        "ssh-ed25519 " + base64.b64encode(b"not-an-open-ssh-key").decode("ascii"),
    ),
)
def test_installation_manifest_rejects_noncanonical_or_non_ed25519_key_blob(key: str) -> None:
    with pytest.raises(ValueError):
        ExecutorInstallationManifestV2(
            schema_version="rsd.executor-installation-manifest.v2",
            executor_id="executor-1",
            force_command_user="executor-user",
            force_command_user_uid=1001,
            daemon_socket_group="executor-relay",
            daemon_socket_group_gid=1002,
            credential_name="rsd-credential",
            state_directory_name="rsd-executor-state",
            daemon_executable_path="/opt/executor/daemon",
            force_command_path="/opt/executor/force",
            systemd_unit_path="/opt/executor/executor.service",
            socket_unit_path="/opt/executor/executor.socket",
            sshd_fragment_path="/opt/executor/sshd",
            authorized_key_policy_path="/opt/executor/authorized-key",
            daemon_socket_path="/run/executor/socket",
            client_authorized_key=key,
            daemon_socket_mode=0o660,
            daemon_file_mode=0o700,
            config_file_mode=0o644,
            authorized_key_file_mode=0o600,
        )


@pytest.mark.parametrize(
    "unsafe_path",
    (
        "/opt/executor/force command",
        "/opt/executor/force;command",
        "/opt/executor/force\ncommand",
        '/opt/executor/force"command',
    ),
)
def test_installation_manifest_rejects_command_injecting_paths(unsafe_path: str) -> None:
    """Rendered systemd/sshd text cannot acquire shell or config syntax."""

    with pytest.raises(ValueError, match="installation path"):
        ExecutorInstallationManifestV2(
            schema_version="rsd.executor-installation-manifest.v2",
            executor_id="executor-1",
            force_command_user="executor-user",
            force_command_user_uid=1001,
            daemon_socket_group="executor-relay",
            daemon_socket_group_gid=1002,
            credential_name="rsd-credential",
            state_directory_name="rsd-executor-state",
            daemon_executable_path="/opt/executor/daemon",
            force_command_path=unsafe_path,
            systemd_unit_path="/opt/executor/unit.service",
            socket_unit_path="/opt/executor/socket.socket",
            sshd_fragment_path="/opt/executor/sshd",
            authorized_key_policy_path="/opt/executor/authorized-key",
            daemon_socket_path="/run/executor/socket",
            client_authorized_key=(
                "ssh-ed25519 " + base64.b64encode(_ssh_ed25519_blob(b"c" * 32)).decode("ascii")
            ),
            daemon_socket_mode=0o660,
            daemon_file_mode=0o700,
            config_file_mode=0o644,
            authorized_key_file_mode=0o600,
        )


def test_keychain_stream_uses_exact_slots_and_zeroizes_each_read(tmp_path: Path) -> None:
    """The internal fixture store still receives no broad-purpose lookup."""

    del tmp_path
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
        ProviderMaterialPurpose.POSTGRES_APPLICATION_PASSWORD: bytearray(
            base64.urlsafe_b64encode(b"g" * 32).rstrip(b"=")
        ),
    }

    def reference(name: str) -> ProviderReferenceV1:
        fields = {
            "account": f"executor-{name}.v1",
            "provider": "macos_keychain",
            "service": f"executor-service-{name}",
            "version": 1,
        }
        encoded = json.dumps(fields, sort_keys=True, separators=(",", ":")).encode("ascii")
        return ProviderReferenceV1(**fields, reference_sha256=hashlib.sha256(encoded).hexdigest())

    definitions = (
        (ProviderMaterialPurpose.COMMITMENT_HMAC, ProviderMaterialFormat.HMAC_SHA256_RAW_32_V1, 32),
        (
            ProviderMaterialPurpose.BACKUP_ENCRYPTION,
            ProviderMaterialFormat.AES_256_GCM_RAW_32_V1,
            32,
        ),
        (
            ProviderMaterialPurpose.INFISICAL_ENCRYPTION_KEY,
            ProviderMaterialFormat.INFISICAL_HEX_16_V1,
            32,
        ),
        (
            ProviderMaterialPurpose.INFISICAL_AUTH_SECRET,
            ProviderMaterialFormat.INFISICAL_AUTH_SECRET_BASE64_32_V1,
            44,
        ),
        (
            ProviderMaterialPurpose.PRIMARY_VALKEY_PASSWORD,
            ProviderMaterialFormat.VALKEY_PASSWORD_BASE64URL_32_V1,
            43,
        ),
        (
            ProviderMaterialPurpose.RESTORE_VALKEY_PASSWORD,
            ProviderMaterialFormat.VALKEY_PASSWORD_BASE64URL_32_V1,
            43,
        ),
        (
            ProviderMaterialPurpose.POSTGRES_APPLICATION_PASSWORD,
            ProviderMaterialFormat.POSTGRES_APPLICATION_PASSWORD_BASE64URL_32_V1,
            43,
        ),
    )
    specs = tuple(
        ProviderMaterialSpecV1(
            purpose=purpose,
            reference=reference(purpose.value),
            format=format_value,
            value_min_bytes=length,
            value_max_bytes=length,
        )
        for purpose, format_value, length in definitions
    )
    signer_fields = {
        "account": "executor-signer.v1",
        "provider": "macos_keychain",
        "service": "executor-signer-service",
        "version": 1,
    }
    signer_json = json.dumps(signer_fields, sort_keys=True, separators=(",", ":")).encode("ascii")
    signer_reference = KeychainItemReferenceV1(
        **signer_fields, reference_sha256=hashlib.sha256(signer_json).hexdigest()
    )
    material_policy = ProviderMaterialPolicyV2(
        schema_version="rsd.provider-crypto.material-policy.v2",
        allocation_intent_sha256=_H("allocation"),
        disposal_owner="owner",
        approver_identity="approver",
        policy_id=_UUIDS[3],
        signer_keychain_reference=signer_reference,
        signer_seed_fingerprint_sha256=_H("seed"),
        created_at="2026-08-28T12:00:00Z",
        retention_expires_at="2026-08-28T13:00:00Z",
        materials=specs,
        signer_key_id="signer-1",
        signature_base64=base64.b64encode(b"s" * 64).decode("ascii"),
    )
    fingerprints = tuple(
        ProviderMaterialFingerprintV1(
            purpose=spec.purpose,
            reference_sha256=spec.reference.reference_sha256,
            fingerprint_sha256=hashlib.sha256(values[spec.purpose]).hexdigest(),
        )
        for spec in specs
    )
    attestation = ProviderFingerprintAttestationV2.model_construct(
        allocation_intent_sha256=material_policy.allocation_intent_sha256,
        provider_material_policy_sha256=material_policy.policy_sha256(),
        materials=fingerprints,
    )

    class Store:
        def __init__(self) -> None:
            self.buffers: list[bytearray] = []

        def read_if_present(self, service: str, account: str) -> bytearray | None:
            for spec in material_policy.materials:
                if spec.reference.service == service and spec.reference.account == account:
                    value = bytearray(values[spec.purpose])
                    self.buffers.append(value)
                    return value
            return None

    store = Store()
    handling = SecretHandlingPolicyV1.model_construct(
        provider_identity_sha256=canonical_sha256(attestation),
        capability_fingerprint_sha256=_H("capability"),
    )
    capability = SecretCapabilityPolicyV1.model_construct(
        provider_identity_sha256=canonical_sha256(attestation),
        capability_fingerprint_sha256=_H("capability"),
        secret_handling_policy_sha256=canonical_sha256(handling),
    )
    runtime = {
        "encryption_key": (
            SecretDeliverySinkV1.INFISICAL_TARGET_PROCESS_ENVIRONMENT,
            ("primary_infisical", "restore_infisical"),
        ),
        "auth_secret": (
            SecretDeliverySinkV1.INFISICAL_TARGET_PROCESS_ENVIRONMENT,
            ("primary_infisical", "restore_infisical"),
        ),
        "primary_valkey_password": (
            SecretDeliverySinkV1.VALKEY_STDIN_CONFIGURATION,
            ("primary_valkey",),
        ),
        "restore_valkey_password": (
            SecretDeliverySinkV1.VALKEY_STDIN_CONFIGURATION,
            ("restore_valkey",),
        ),
        "postgres_application_password": (
            SecretDeliverySinkV1.POSTGRES_APPLICATION_TARGET_ENVIRONMENT,
            ("postgres_application_target",),
        ),
    }
    slots = tuple(
        SecretDeliverySlotV1(
            purpose=purpose,
            reference_sha256=next(
                spec.reference.reference_sha256
                for spec in material_policy.materials
                if spec.purpose.value == purpose
            ),
            format=next(
                spec.format.value
                for spec in material_policy.materials
                if spec.purpose.value == purpose
            ),
            encoded_byte_count=len(
                values[
                    next(
                        spec.purpose
                        for spec in material_policy.materials
                        if spec.purpose.value == purpose
                    )
                ]
            ),
            sink=sink,
            target_processes=targets,
        )
        for purpose, (sink, targets) in runtime.items()
    )
    request = SecretDeliveryRequestV1(
        schema_version="rsd.secret-delivery-request.v1",
        operation_scope="materialize_and_start_runtime_v1",
        operation_id=_UUIDS[0],
        journal_uuid=_UUIDS[1],
        provider_material_attestation_sha256=canonical_sha256(attestation),
        channel_binding_sha256=_H("channel"),
        session_binding_sha256=_H("session"),
        request_nonce_sha256=_H("nonce"),
        slots=cast(tuple[SecretDeliverySlotV1, ...], slots),
    )

    class Writer:
        def __init__(self) -> None:
            self.values: list[bytes] = []

        def write_slot(self, descriptor: SecretDeliverySlotV1, value: memoryview) -> None:
            del descriptor
            self.values.append(bytes(value))

    writer = Writer()
    lease = transport._keychain_secret_material_lease_for_test(
        policy=material_policy,
        attestation=attestation,
        capability_policy=capability,
        handling_policy=handling,
        store=store,
    )
    receipt = lease.stream_to(request, writer, completed_at="2026-08-28T12:05:01Z")
    assert len(receipt.slots) == 5
    assert len(writer.values) == 5
    assert all(not any(buffer) for buffer in store.buffers)
    with pytest.raises(transport.ExecutorTransportError, match="material"):
        lease.stream_to(request, writer, completed_at="2026-08-28T12:05:01Z")
    assert len(writer.values) == 5
    lease.close()
    with pytest.raises(transport.ExecutorTransportError, match="material"):
        lease.stream_to(request, writer, completed_at="2026-08-28T12:05:01Z")


def test_force_command_rejects_wrong_effective_uid_before_connecting(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    called = False

    def connector() -> tuple[object, object]:
        nonlocal called
        called = True
        raise AssertionError("connector must not run for a wrong UID")

    monkeypatch.setattr(daemon.os, "geteuid", lambda: 7)
    with pytest.raises(daemon.ExecutorDaemonError, match="uds_peer"):
        daemon._force_command_forward_for_test(
            object(),  # type: ignore[arg-type]
            object(),  # type: ignore[arg-type]
            daemon_connector=connector,
            expected_uid=8,
        )
    assert not called


def test_force_command_relay_preserves_opaque_binary_groups(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    def group(payload: bytes) -> bytes:
        return _HEADER.pack(FRAME_MAGIC, FRAME_VERSION, 1, 0, len(payload)) + payload

    class Source:
        def __init__(self, value: bytes) -> None:
            self.stream = io.BytesIO(value)

        def read_exact(self, count: int) -> bytes:
            return self.stream.read(count)

    class Sink:
        def __init__(self) -> None:
            self.value = bytearray()

        def write(self, value: bytes) -> int:
            self.value.extend(value)
            return len(value)

        def flush(self) -> None:
            return None

    class Channel:
        def __init__(self, source: Source, sink: Sink) -> None:
            self.source = source
            self.sink = sink
            self.closed_input = False

        def read_exact(self, count: int) -> bytes:
            return self.source.read_exact(count)

        def write(self, value: bytes) -> int:
            return self.sink.write(value)

        def flush(self) -> None:
            self.sink.flush()

        def close_input(self) -> None:
            self.closed_input = True

        def close(self) -> None:
            return None

    incoming = group(b'{"chunk_count":0}') * 2
    response = group(b'{"chunk_count":0}') * 2
    daemon_sink = Sink()
    client_sink = Sink()
    monkeypatch.setattr(daemon.os, "geteuid", lambda: 7)
    daemon._force_command_forward_for_test(
        Source(incoming),
        client_sink,
        daemon_connector=lambda: Channel(Source(response), daemon_sink),
        expected_uid=7,
    )
    assert bytes(daemon_sink.value) == incoming + daemon._RELAY_EOF_FRAME
    assert bytes(client_sink.value) == response


def test_force_command_relay_rejects_aggregate_oversize_before_response(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    """The opaque relay still enforces the frame stream's total byte limit."""

    class Source:
        def __init__(self, value: bytes) -> None:
            self.stream = io.BytesIO(value)

        def read_exact(self, count: int) -> bytes:
            return self.stream.read(count)

    class Sink:
        def write(self, value: bytes) -> int:
            return len(value)

        def flush(self) -> None:
            return None

    class Channel:
        def read_exact(self, count: int) -> bytes:
            del count
            return b""

        def write(self, value: bytes) -> int:
            return len(value)

        def flush(self) -> None:
            return None

        def close_input(self) -> None:
            return None

        def close(self) -> None:
            return None

    metadata = b'{"chunk_count":64}'
    oversized_group = _HEADER.pack(FRAME_MAGIC, FRAME_VERSION, 1, 0, len(metadata)) + metadata
    oversized_group += b"".join(
        _HEADER.pack(FRAME_MAGIC, FRAME_VERSION, 2, sequence, MAX_CHUNK_BYTES)
        + b"x" * MAX_CHUNK_BYTES
        for sequence in range(1, MAX_CHUNKS + 1)
    )
    monkeypatch.setattr(daemon.os, "geteuid", lambda: 7)
    with pytest.raises(daemon.ExecutorDaemonError, match="force_command"):
        daemon._force_command_forward_for_test(
            Source(oversized_group),
            Sink(),
            daemon_connector=Channel,
            expected_uid=7,
        )


def test_force_command_rejects_trailing_client_bytes_before_relay_commit(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    """Only clean Secure Shell EOF may generate the daemon's relay commit marker."""

    def group(payload: bytes) -> bytes:
        return _HEADER.pack(FRAME_MAGIC, FRAME_VERSION, 1, 0, len(payload)) + payload

    class Source:
        def __init__(self, value: bytes) -> None:
            self.stream = io.BytesIO(value)

        def read_exact(self, count: int) -> bytes:
            return self.stream.read(count)

        def require_eof(self) -> None:
            if self.stream.read(1):
                raise daemon.ExecutorDaemonError("force_command")

    class Sink:
        def __init__(self) -> None:
            self.value = bytearray()

        def write(self, value: bytes) -> int:
            self.value.extend(value)
            return len(value)

        def flush(self) -> None:
            return None

    class Channel:
        def __init__(self, source: Source, sink: Sink) -> None:
            self.source = source
            self.sink = sink
            self.closed_input = False

        def read_exact(self, count: int) -> bytes:
            return self.source.read_exact(count)

        def write(self, value: bytes) -> int:
            return self.sink.write(value)

        def flush(self) -> None:
            self.sink.flush()

        def close_input(self) -> None:
            self.closed_input = True

        def close(self) -> None:
            return None

    incoming = group(b'{"chunk_count":0}') * 2
    daemon_sink = Sink()
    channel = Channel(Source(group(b'{"chunk_count":0}')), daemon_sink)
    monkeypatch.setattr(daemon.os, "geteuid", lambda: 7)
    with pytest.raises(daemon.ExecutorDaemonError, match="force_command"):
        daemon._force_command_forward_for_test(
            Source(incoming + b"x"),
            Sink(),
            daemon_connector=lambda: channel,
            expected_uid=7,
        )
    assert bytes(daemon_sink.value) == incoming
    assert not channel.closed_input
