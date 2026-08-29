"""Offline adversarial tests for the sealed zero-secret allocation adapter."""

from __future__ import annotations

import base64
import hashlib
import json
import os
import socket
import stat
import threading
from collections.abc import Callable
from contextlib import contextmanager
from pathlib import Path
from threading import Lock

import pytest
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey

import omninode_rsd.lifecycle.executor_allocation as allocation
import omninode_rsd.lifecycle.executor_daemon as daemon
from omninode_rsd.lifecycle.infisical_disposable import (
    DockerEngineControlPolicyV1,
    DockerEngineFilteredProjectionV1,
    DockerImageLocalEvidenceV1,
    DockerImagePolicyV1,
    DockerUnixSocketPolicyV1,
    EngineIdentityObservationV1,
    ImageReferenceV1,
    NetworkOptionV1,
    OciImageResolutionAttestationV1,
    PostgreSQLPreparedControlPolicyV2,
    PostgreSQLPreparedOperationV1,
    PostgreSQLScramVerifierInstallsV1,
    PostgreSQLScramVerifierInstallV1,
    docker_engine_fingerprint_sha256,
    docker_unix_socket_identity_sha256,
    docker_volume_instance_fingerprint_sha256,
)

_SIGNATURE = (
    "AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA=="
)
_COMMIT = "a" * 40
_HEX = "b" * 64
_CONTROL_ID = "c" * 64
_EXEC_ID = "d" * 64
_NOW = "2026-08-28T12:00:00Z"


def _hash(value: str) -> str:
    return hashlib.sha256(value.encode("ascii")).hexdigest()


def _socket_path(tmp_path: Path) -> Path:
    """Use a bounded AF_UNIX pathname even when pytest's root is long."""

    return Path("/tmp") / f"rsd-{_hash(os.fspath(tmp_path))[:16]}.sock"


def _response(
    status: int,
    body: bytes,
    *,
    content_type: str = "application/json",
) -> bytes:
    return (
        f"HTTP/1.1 {status} OK\r\n".encode("ascii")
        + f"Content-Type: {content_type}\r\n".encode("ascii")
        + f"Content-Length: {len(body)}\r\n\r\n".encode("ascii")
        + body
    )


def _json_response(status: int, value: object) -> bytes:
    return _response(
        status,
        json.dumps(value, sort_keys=True, separators=(",", ":")).encode("utf-8"),
    )


def _read_http_request(connection: socket.socket) -> bytes:
    data = bytearray()
    while b"\r\n\r\n" not in data:
        piece = connection.recv(4096)
        if not piece:
            raise AssertionError("short request headers")
        data.extend(piece)
    header_end = data.index(b"\r\n\r\n") + 4
    header = bytes(data[:header_end])
    length = 0
    for line in header.decode("ascii").split("\r\n"):
        if line.lower().startswith("content-length:"):
            length = int(line.split(":", 1)[1].strip())
    while len(data) < header_end + length:
        piece = connection.recv(4096)
        if not piece:
            raise AssertionError("short request body")
        data.extend(piece)
    return bytes(data)


class _EngineServer:
    """One local AF_UNIX fake with exact per-request response handlers."""

    def __init__(
        self,
        path: Path,
        handlers: tuple[Callable[[socket.socket], None], ...],
    ) -> None:
        self.path = path
        self._listener = socket.socket(socket.AF_UNIX, socket.SOCK_STREAM)
        self._listener.bind(os.fspath(path))
        os.chmod(path, 0o600)
        self._listener.listen(len(handlers) or 1)
        self._handlers = handlers
        self._failure: BaseException | None = None
        self._thread = threading.Thread(target=self._serve, daemon=True)
        self._thread.start()

    def _serve(self) -> None:
        try:
            for handler in self._handlers:
                connection, _ = self._listener.accept()
                try:
                    handler(connection)
                finally:
                    connection.close()
        except BaseException as error:  # pragma: no cover - surfaced at close
            self._failure = error
        finally:
            self._listener.close()

    def close(self) -> None:
        self._thread.join(timeout=3)
        if self._thread.is_alive():
            raise AssertionError("fake Engine did not finish")
        if self._failure is not None:
            raise self._failure
        if self.path.exists():
            self.path.unlink()


def _docker_policy(path: Path) -> DockerEngineControlPolicyV1:
    details = os.lstat(path)
    path_sha256 = hashlib.sha256(os.fsencode(path)).hexdigest()
    projection = DockerEngineFilteredProjectionV1(
        daemon_id="fake-engine-01",
        api_version="1.44",
        operating_system="linux",
        architecture="amd64",
    )
    return DockerEngineControlPolicyV1(
        schema_version="rsd.docker-engine-control-policy.v1",
        source_commit=_COMMIT,
        executor_identity_sha256=_hash("executor"),
        unix_socket=DockerUnixSocketPolicyV1(
            socket_path=os.fspath(path),
            socket_path_sha256=path_sha256,
            socket_identity_sha256=docker_unix_socket_identity_sha256(
                socket_path_sha256=path_sha256,
                device=details.st_dev,
                inode=details.st_ino,
                owner_uid=details.st_uid,
                group_gid=details.st_gid,
                mode=stat.S_IMODE(details.st_mode),
            ),
            device=details.st_dev,
            inode=details.st_ino,
            owner_uid=details.st_uid,
            group_gid=details.st_gid,
            mode=stat.S_IMODE(details.st_mode),
            endpoint_scheme="unix",
            symlink_allowed=False,
            replacement_allowed=False,
        ),
        api_version="1.44",
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
        max_request_bytes=65_536,
        max_response_bytes=65_536,
        max_hijack_bytes=65_536,
        max_hijack_frames=64,
        request_timeout_seconds=1,
        hijack_timeout_seconds=1,
        hijack_absolute_timeout_seconds=2,
        created_at=_NOW,
        signer_key_id="test-signer",
        signature_base64=_SIGNATURE,
    )


def _offline_docker_policy(tmp_path: Path) -> DockerEngineControlPolicyV1:
    """Build a signed-shape policy for parser-only tests without connecting."""

    path = _socket_path(tmp_path)
    server = _EngineServer(path, ())
    try:
        return _docker_policy(path)
    finally:
        server.close()


def _client(
    policy: DockerEngineControlPolicyV1,
    monkeypatch: pytest.MonkeyPatch,
) -> allocation._UnixDockerEngineClient:
    """Use fake UDS transport without weakening production path checks."""

    result = allocation._UnixDockerEngineClient(policy)
    # The concrete backend is Linux/root-only. Unit tests use a per-user,
    # temporary local UDS, so peer/ancestor checks are independently covered
    # by the sealed production loader and socket-identity regression below.
    monkeypatch.setattr(result, "_assert_socket_identity", lambda: None)
    monkeypatch.setattr(result, "_assert_peer_identity", lambda _connection: None)
    return result


def _image_policy() -> DockerImagePolicyV1:
    image = ImageReferenceV1(reference=f"registry.example/control@sha256:{_HEX}")
    return DockerImagePolicyV1(
        image=image,
        registry_index_digest_sha256=_HEX,
        linux_amd64_manifest_digest_sha256="e" * 64,
        config_digest_sha256="f" * 64,
        resolution_attestation=OciImageResolutionAttestationV1(
            schema_version="rsd.oci-image-resolution-attestation.v1",
            source_commit=_COMMIT,
            image=image,
            registry_index_digest_sha256=_HEX,
            linux_amd64_manifest_digest_sha256="e" * 64,
            config_digest_sha256="f" * 64,
            platform="linux/amd64",
            resolved_at=_NOW,
            signer_key_id="test-signer",
            signature_base64=_SIGNATURE,
        ),
    )


def _local_image_evidence() -> DockerImageLocalEvidenceV1:
    policy = _image_policy()
    repository = policy.image.reference.rsplit("@", 1)[0]
    return DockerImageLocalEvidenceV1(
        schema_version="rsd.docker-image-local-evidence.v1",
        resolution_attestation_sha256=allocation.canonical_sha256(policy.resolution_attestation),
        registry_index_reference=policy.image,
        linux_amd64_manifest_reference=ImageReferenceV1(
            reference=(f"{repository}@sha256:{policy.linux_amd64_manifest_digest_sha256}")
        ),
        registry_index_digest_sha256=policy.registry_index_digest_sha256,
        linux_amd64_manifest_digest_sha256=policy.linux_amd64_manifest_digest_sha256,
        config_digest_sha256=policy.config_digest_sha256,
        index_reference_inspected=True,
        platform_manifest_reference_inspected=True,
        operating_system="linux",
        architecture="amd64",
    )


def _prepared_policy() -> PostgreSQLPreparedControlPolicyV2:
    primary_verifier = PostgreSQLScramVerifierInstallV1(
        schema_version="rsd.postgresql-scram-verifier-install.v1",
        database_identity="primary_database",
        prepared_operation_id="123e4567-e89b-42d3-a456-426614174003",
        application_password_reference_sha256=_hash("application-password"),
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
        template_sha256=_hash("verifier-template"),
    )
    restore_verifier = PostgreSQLScramVerifierInstallV1(
        schema_version="rsd.postgresql-scram-verifier-install.v1",
        database_identity="restore_database",
        prepared_operation_id="123e4567-e89b-42d3-a456-426614174006",
        application_password_reference_sha256=_hash("application-password"),
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
        template_sha256=_hash("restore-verifier-template"),
    )
    return PostgreSQLPreparedControlPolicyV2(
        schema_version="rsd.postgresql-prepared-control-policy.v2",
        source_commit=_COMMIT,
        executor_identity_sha256=_hash("executor"),
        control_container_id=_CONTROL_ID,
        control_image=_image_policy(),
        control_config_sha256=_hash("control-config"),
        unix_socket_identity_sha256=_hash("postgres-socket"),
        psql_absolute_path="/usr/bin/psql",
        psql_binary_sha256=_hash("psql-binary"),
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
                psql_template_sha256=allocation.allocation_postgres_template_bundle_sha256(),
                result_projection_sha256=allocation.allocation_postgres_result_schema_sha256(),
                stdin_protocol="postgresql_prepared_psql_stdin_v1",
                secret_input=False,
            ),
            PostgreSQLPreparedOperationV1(
                operation_id=primary_verifier.prepared_operation_id,
                kind="install_primary_scram_verifier_v1",
                psql_template_sha256=primary_verifier.template_sha256,
                result_projection_sha256=_hash("primary-verifier-result"),
                stdin_protocol="postgresql_prepared_psql_stdin_v1",
                secret_input=True,
            ),
            PostgreSQLPreparedOperationV1(
                operation_id=restore_verifier.prepared_operation_id,
                kind="install_restore_scram_verifier_v1",
                psql_template_sha256=restore_verifier.template_sha256,
                result_projection_sha256=_hash("restore-verifier-result"),
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


def test_socket_replacement_blocks_before_a_request(tmp_path: Path) -> None:
    path = _socket_path(tmp_path)
    first = _EngineServer(path, ())
    policy = _docker_policy(path)
    first.close()
    replacement = _EngineServer(path, ())
    try:
        client = allocation._UnixDockerEngineClient(policy)
        with pytest.raises(allocation.AllocationBackendError, match="engine_socket"):
            client._assert_socket_identity()
    finally:
        replacement.close()


def test_engine_status_body_is_redacted_and_endpoint_traversal_never_connects(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    marker = b"engine-error-value-that-must-not-escape"
    path = _socket_path(tmp_path)
    calls: list[bytes] = []

    def status(connection: socket.socket) -> None:
        calls.append(_read_http_request(connection))
        connection.sendall(_response(500, marker, content_type="text/plain"))

    server = _EngineServer(path, (status,))
    try:
        client = _client(_docker_policy(path), monkeypatch)
        with pytest.raises(allocation.AllocationBackendError) as raised:
            client.ping()
        assert raised.value.phase == "engine_status"
        assert marker.decode("ascii") not in str(raised.value)
        assert raised.value.__cause__ is None
        with pytest.raises(allocation.AllocationBackendError, match="network"):
            client.assert_network_absent("../traversal")
    finally:
        server.close()
    assert len(calls) == 1


def test_engine_http_rejects_noncanonical_lengths_and_trailing_bytes(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    """A daemon cannot smuggle a second response behind a valid body."""

    path = _socket_path(tmp_path)

    def noncanonical_length(connection: socket.socket) -> None:
        _read_http_request(connection)
        connection.sendall(
            b"HTTP/1.1 200 OK\r\nContent-Type: text/plain\r\nContent-Length: +2\r\n\r\nOK"
        )

    def trailing_bytes(connection: socket.socket) -> None:
        _read_http_request(connection)
        connection.sendall(
            b"HTTP/1.1 200 OK\r\nContent-Type: text/plain\r\nContent-Length: 2\r\n\r\nOK!"
        )

    server = _EngineServer(path, (noncanonical_length, trailing_bytes))
    try:
        client = _client(_docker_policy(path), monkeypatch)
        for _ in range(2):
            with pytest.raises(allocation.AllocationBackendError, match="engine_framing"):
                client.ping()
    finally:
        server.close()


def test_network_create_is_exact_and_existing_name_is_never_adopted(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    path = _socket_path(tmp_path)
    requests: list[bytes] = []

    def existing(connection: socket.socket) -> None:
        requests.append(_read_http_request(connection))
        connection.sendall(_json_response(200, {"Name": "primary"}))

    def create(connection: socket.socket) -> None:
        requests.append(_read_http_request(connection))
        connection.sendall(_json_response(201, {}))

    server = _EngineServer(path, (existing, create))
    try:
        client = _client(_docker_policy(path), monkeypatch)
        with pytest.raises(allocation.AllocationBackendError, match="engine_status"):
            client.assert_network_absent("primary")
        client.create_network(
            name="primary",
            subnet="192.0.2.0/24",
            gateway="192.0.2.1",
            options=(NetworkOptionV1(key="com.example.option", value="value"),),
        )
    finally:
        server.close()
    body = json.loads(requests[1].split(b"\r\n\r\n", 1)[1])
    assert body == {
        "CheckDuplicate": True,
        "Driver": "bridge",
        "EnableIPv6": False,
        "IPAM": {"Config": [{"Gateway": "192.0.2.1", "Subnet": "192.0.2.0/24"}]},
        "Internal": True,
        "Labels": {},
        "Name": "primary",
        "Options": {"com.example.option": "value"},
    }


def test_volume_mountpoint_and_unknown_engine_fields_never_escape(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    marker = "host-path-and-label-sentinel"
    path = _socket_path(tmp_path)

    def inspect(connection: socket.socket) -> None:
        _read_http_request(connection)
        connection.sendall(
            _json_response(
                200,
                {
                    "Name": "cache",
                    "Driver": "local",
                    "Scope": "local",
                    "CreatedAt": _NOW,
                    "Options": {},
                    "Labels": {},
                    "Mountpoint": marker,
                    "Untrusted": {"label": marker},
                },
            )
        )

    server = _EngineServer(path, (inspect,))
    try:
        policy = _docker_policy(path)
        result = _client(policy, monkeypatch).inspect_volume(
            name="cache", engine_fingerprint_sha256=policy.engine_fingerprint_sha256, options=()
        )
    finally:
        server.close()
    assert result.volume_instance_fingerprint_sha256 == docker_volume_instance_fingerprint_sha256(
        name="cache",
        engine_fingerprint_sha256=policy.engine_fingerprint_sha256,
        driver="local",
        scope="local",
        created_at=result.created_at,
        options=(),
    )
    assert marker not in result.model_dump_json()


def test_network_ipam_substitution_is_rejected(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    path = _socket_path(tmp_path)

    def inspect(connection: socket.socket) -> None:
        _read_http_request(connection)
        connection.sendall(
            _json_response(
                200,
                {
                    "Name": "primary",
                    "Id": _HEX,
                    "Driver": "bridge",
                    "Internal": True,
                    "EnableIPv6": False,
                    "Attachable": False,
                    "Ingress": False,
                    "Containers": {},
                    "Options": {},
                    "IPAM": {"Config": [{"Subnet": "198.51.100.0/24", "Gateway": "198.51.100.1"}]},
                },
            )
        )

    server = _EngineServer(path, (inspect,))
    try:
        with pytest.raises(allocation.AllocationBackendError, match="network_projection"):
            _client(_docker_policy(path), monkeypatch).inspect_network(
                name="primary", subnet="192.0.2.0/24", gateway="192.0.2.1", options=()
            )
    finally:
        server.close()


def test_postgres_exec_uses_fixed_argv_empty_env_and_stdin_only(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    marker = b"sql-sentinel-only-on-stdin"
    path = _socket_path(tmp_path)
    requests: list[bytes] = []
    stdin_values: list[bytes] = []
    prepared = _prepared_policy()

    def create(connection: socket.socket) -> None:
        requests.append(_read_http_request(connection))
        connection.sendall(_json_response(201, {"Id": _EXEC_ID}))

    def start(connection: socket.socket) -> None:
        requests.append(_read_http_request(connection))
        connection.sendall(
            b"HTTP/1.1 101 UPGRADED\r\nConnection: Upgrade\r\nUpgrade: tcp\r\n"
            b"Content-Type: application/vnd.docker.raw-stream\r\n\r\n"
        )
        received = bytearray()
        while piece := connection.recv(4096):
            received.extend(piece)
        stdin_values.append(bytes(received))
        connection.sendall(b"\x01\x00\x00\x00" + len(b"ok\n").to_bytes(4, "big") + b"ok\n")

    server = _EngineServer(path, (create, start))
    try:
        client = _client(_docker_policy(path), monkeypatch)
        exec_id = client.create_exec(policy=prepared)
        assert client.start_exec(exec_id=exec_id, sql=bytearray(marker)) == b"ok\n"
    finally:
        server.close()
    request_body = json.loads(requests[0].split(b"\r\n\r\n", 1)[1])
    assert request_body["Cmd"] == list(prepared.fixed_psql_argv)
    assert request_body["Env"] == []
    assert request_body["User"] == "postgres"
    assert request_body["Privileged"] is False
    assert request_body["Tty"] is False
    assert marker not in requests[0]
    assert stdin_values == [marker]


def test_postgres_exec_inspection_binds_the_control_container_and_command(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    path = _socket_path(tmp_path)
    prepared = _prepared_policy()
    requests: list[bytes] = []

    def valid(connection: socket.socket) -> None:
        request = _read_http_request(connection)
        requests.append(request)
        connection.sendall(
            _json_response(
                200,
                {
                    "ID": _EXEC_ID,
                    "ContainerID": _CONTROL_ID,
                    "ExitCode": None,
                    "OpenStderr": True,
                    "OpenStdin": True,
                    "OpenStdout": True,
                    "ProcessConfig": {
                        "arguments": list(prepared.fixed_psql_argv[1:]),
                        "entrypoint": prepared.fixed_psql_argv[0],
                        "privileged": False,
                        "tty": False,
                        "user": prepared.psql_operating_system_user,
                    },
                    "Running": False,
                },
            )
        )

    def substituted(connection: socket.socket) -> None:
        _read_http_request(connection)
        connection.sendall(
            _json_response(
                200,
                {
                    "ID": _EXEC_ID,
                    "ContainerID": _CONTROL_ID,
                    "ExitCode": None,
                    "OpenStderr": True,
                    "OpenStdin": True,
                    "OpenStdout": True,
                    "ProcessConfig": {
                        "arguments": ["unexpected"],
                        "entrypoint": prepared.fixed_psql_argv[0],
                        "privileged": False,
                        "tty": False,
                        "user": prepared.psql_operating_system_user,
                    },
                    "Running": False,
                },
            )
        )

    server = _EngineServer(path, (valid, substituted))
    try:
        client = _client(_docker_policy(path), monkeypatch)
        client.inspect_exec(
            exec_id=_EXEC_ID,
            policy=prepared,
            command=prepared.fixed_psql_argv,
        )
        with pytest.raises(allocation.AllocationBackendError, match="postgres_exec"):
            client.inspect_exec(
                exec_id=_EXEC_ID,
                policy=prepared,
                command=prepared.fixed_psql_argv,
            )
    finally:
        server.close()
    assert requests[0].startswith(f"GET /v1.44/exec/{_EXEC_ID}/json HTTP/1.1\r\n".encode("ascii"))


def test_postgres_hijack_rejects_stdin_channel_and_template_drift(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    path = _socket_path(tmp_path)

    def start(connection: socket.socket) -> None:
        _read_http_request(connection)
        connection.sendall(
            b"HTTP/1.1 101 UPGRADED\r\nConnection: Upgrade\r\nUpgrade: tcp\r\n"
            b"Content-Type: application/vnd.docker.raw-stream\r\n\r\n"
        )
        connection.recv(4096)
        connection.sendall(b"\x00\x00\x00\x00\x00\x00\x00\x00")

    server = _EngineServer(path, (start,))
    try:
        with pytest.raises(allocation.AllocationBackendError, match="engine_multiplex"):
            _client(_docker_policy(path), monkeypatch).start_exec(
                exec_id=_EXEC_ID, sql=bytearray(b"SELECT 1;\n")
            )
    finally:
        server.close()
    drifted = _prepared_policy().model_copy(
        update={
            "operations": (
                _prepared_policy()
                .operations[0]
                .model_copy(update={"psql_template_sha256": _hash("drift")}),
                _prepared_policy().operations[1],
                _prepared_policy().operations[2],
            )
        }
    )
    with pytest.raises(allocation.AllocationBackendError, match="postgres_template"):
        allocation._require_allocation_prepared_binding(drifted)


def test_allocation_template_and_result_commitments_pin_executable_contract(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    """Changing any static SQL or accepted result field changes its signed digest."""

    template_digest = allocation.allocation_postgres_template_bundle_sha256()
    result_digest = allocation.allocation_postgres_result_schema_sha256()
    templates = allocation._ALLOCATION_SQL_TEMPLATES
    monkeypatch.setattr(
        allocation,
        "_ALLOCATION_SQL_TEMPLATES",
        (("roles", templates[0][1] + "-- changed\n"), *templates[1:]),
    )
    assert allocation.allocation_postgres_template_bundle_sha256() != template_digest
    monkeypatch.undo()
    monkeypatch.setattr(
        allocation,
        "_ALLOCATION_RESULT_FIELDS",
        (*allocation._ALLOCATION_RESULT_FIELDS, "unexpected_field"),
    )
    assert allocation.allocation_postgres_result_schema_sha256() != result_digest


def test_postgres_table_acl_uses_default_privileges_and_exact_acl_projection() -> None:
    """Empty schemas have no tables, so table grants must be durable defaults."""

    postgres = allocation.PostgreSQLControlPolicyV1.model_validate(
        {
            "schema_version": "rsd.postgresql-control-policy.v1",
            "source_commit": _COMMIT,
            "executor_identity_sha256": _hash("executor"),
            "authority": "postgresql://192.0.2.1:5432",
            "maintenance_reference_sha256": _hash("maintenance"),
            "database_name": "allocation-database",
            "schema_name": "allocation-schema",
            "owner_role": "allocation-owner",
            "application_role": "allocation-application",
            "role_names": ("allocation-owner", "allocation-application"),
            "allocation_role_states": (
                {
                    "role": "allocation-owner",
                    "role_kind": "database_owner",
                    "can_login": False,
                    "password_absent": True,
                },
                {
                    "role": "allocation-application",
                    "role_kind": "application",
                    "can_login": False,
                    "password_absent": True,
                },
            ),
            "grants": (
                {
                    "role": "allocation-owner",
                    "grantee": "allocation-application",
                    "privilege": "SELECT",
                    "schema_name": "allocation-schema",
                },
            ),
            "created_at": _NOW,
            "signer_key_id": "test-signer",
            "signature_base64": _SIGNATURE,
        }
    )
    acl_sql = bytes(allocation._sql_schema_acl(postgres)).decode("utf-8")
    observation_sql = bytes(allocation._sql_observation(postgres)).decode("utf-8")
    assert 'ALTER DEFAULT PRIVILEGES FOR ROLE "allocation-owner"' in acl_sql
    assert 'GRANT SELECT ON TABLES TO "allocation-application"' in acl_sql
    assert "aclexplode(defaults.defaclacl)" in observation_sql
    assert "has_schema_privilege" not in observation_sql


def test_engine_not_found_is_the_only_reconciliation_absence_signal(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    path = _socket_path(tmp_path)

    def unavailable(connection: socket.socket) -> None:
        _read_http_request(connection)
        connection.sendall(_json_response(500, {}))

    def malformed_absent(connection: socket.socket) -> None:
        _read_http_request(connection)
        connection.sendall(_json_response(404, {}))

    def similarly_named_absent(connection: socket.socket) -> None:
        _read_http_request(connection)
        connection.sendall(_json_response(404, {"message": "network primary-other not found"}))

    def absent(connection: socket.socket) -> None:
        _read_http_request(connection)
        connection.sendall(_json_response(404, {"message": "network primary not found"}))

    server = _EngineServer(path, (unavailable, malformed_absent, similarly_named_absent, absent))
    try:
        client = _client(_docker_policy(path), monkeypatch)
        with pytest.raises(allocation.AllocationBackendError) as unavailable_error:
            client.inspect_network(
                name="primary", subnet="192.0.2.0/24", gateway="192.0.2.1", options=()
            )
        with pytest.raises(allocation.AllocationBackendError) as malformed_absent_error:
            client.inspect_network(
                name="primary", subnet="192.0.2.0/24", gateway="192.0.2.1", options=()
            )
        with pytest.raises(allocation.AllocationBackendError) as similarly_named_error:
            client.inspect_network(
                name="primary", subnet="192.0.2.0/24", gateway="192.0.2.1", options=()
            )
        with pytest.raises(allocation.AllocationBackendError) as absent_error:
            client.inspect_network(
                name="primary", subnet="192.0.2.0/24", gateway="192.0.2.1", options=()
            )
    finally:
        server.close()
    assert allocation._is_confirmed_not_found(unavailable_error.value) is False
    assert allocation._is_confirmed_not_found(malformed_absent_error.value) is False
    assert allocation._is_confirmed_not_found(similarly_named_error.value) is False
    assert allocation._is_confirmed_not_found(absent_error.value) is True


def test_response_body_is_zeroized_if_post_response_socket_check_fails(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    marker = b"engine-response-sentinel"
    path = _socket_path(tmp_path)

    def response(connection: socket.socket) -> None:
        _read_http_request(connection)
        connection.sendall(_response(200, marker, content_type="text/plain"))

    server = _EngineServer(path, (response,))
    captured: list[bytes] = []
    original_zeroize = allocation._HttpResponse.zeroize
    checks = 0
    try:
        client = _client(_docker_policy(path), monkeypatch)

        def socket_check() -> None:
            nonlocal checks
            checks += 1
            if checks == 3:
                raise allocation.AllocationBackendError("engine_socket")

        def capture_zeroize(value: allocation._HttpResponse) -> None:
            original_zeroize(value)
            captured.append(bytes(value.body))

        monkeypatch.setattr(client, "_assert_socket_identity", socket_check)
        monkeypatch.setattr(allocation._HttpResponse, "zeroize", capture_zeroize)
        with pytest.raises(allocation.AllocationBackendError, match="engine_socket"):
            client.ping()
    finally:
        server.close()
    assert captured == [b"\x00" * len(marker)]


def test_reconciliation_uses_the_live_session_lease_before_signing() -> None:
    """A live allocation and a reconciliation receipt cannot race each other."""

    class LeaseJournal:
        acquired = 0

        @contextmanager
        def acquire_session_lease(self) -> object:
            self.acquired += 1
            yield

    class Attestation:
        key_id = "executor-attestation"

        def sign_allocation_reconciliation_receipt(self, _receipt: object) -> str:
            return _SIGNATURE

    engine = object.__new__(daemon.ExecutorDaemonSessionEngine)
    engine._backend = object.__new__(allocation.SealedAllocationBackendV1)
    engine._active = Lock()
    engine._journal = LeaseJournal()
    engine._attestation_signer = Attestation()
    engine._active.acquire()
    try:
        with pytest.raises(daemon.ExecutorDaemonError, match="session_busy"):
            engine.reconcile_allocation_read_only()
    finally:
        engine._active.release()
    assert engine._journal.acquired == 0

    projection_model = DockerEngineFilteredProjectionV1(
        daemon_id="fake-engine-01",
        api_version="1.44",
        operating_system="linux",
        architecture="amd64",
    )
    projection = allocation.AllocationReconciliationProjectionV1(
        schema_version="rsd.allocation-reconciliation-projection.v1",
        allocation_intent_sha256=_hash("intent"),
        engine=EngineIdentityObservationV1(
            projection=projection_model,
            engine_fingerprint_sha256=docker_engine_fingerprint_sha256(projection_model),
        ),
        control_image_local_evidence=_local_image_evidence(),
        state=allocation.AllocationReconciliationStateV1.ABSENT,
        observed_network_names=(),
        observed_volume_names=(),
        postgres_state=allocation.AllocationReconciliationPostgreSQLStateV1.ABSENT,
        observed_postgres=None,
        observed_at=_NOW,
    )
    backend = object.__new__(allocation.SealedAllocationBackendV1)
    backend.reconcile_read_only = lambda: projection
    engine._backend = backend
    receipt = engine.reconcile_allocation_read_only()
    assert engine._journal.acquired == 1
    assert receipt.projection == projection


def test_materialization_and_start_are_blocked_by_the_allocation_backend() -> None:
    backend = object.__new__(allocation.SealedAllocationBackendV1)

    class Delivery:
        zeroized = False

        def zeroize(self) -> None:
            self.zeroized = True

    delivery = Delivery()
    with pytest.raises(allocation.AllocationBackendError, match="backend_unavailable"):
        backend.materialize_and_start(object(), delivery)
    assert delivery.zeroized is True
    with pytest.raises(allocation.AllocationBackendError, match="backend_unavailable"):
        backend.start(object(), delivery)
    engine = object.__new__(daemon.ExecutorDaemonSessionEngine)
    engine._backend = backend
    with pytest.raises(daemon.ExecutorDaemonError, match="backend_unavailable"):
        daemon.serve_systemd_activated_session(engine)


def test_psql_binary_checksum_is_fixed_and_mismatch_is_value_redacted(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    path = _socket_path(tmp_path)
    prepared = _prepared_policy()
    requests: list[bytes] = []

    def create(connection: socket.socket) -> None:
        requests.append(_read_http_request(connection))
        connection.sendall(_json_response(201, {"Id": _EXEC_ID}))

    def start(connection: socket.socket) -> None:
        requests.append(_read_http_request(connection))
        connection.sendall(
            b"HTTP/1.1 101 UPGRADED\r\nConnection: Upgrade\r\nUpgrade: tcp\r\n"
            b"Content-Type: application/vnd.docker.raw-stream\r\n\r\n"
        )
        while connection.recv(4096):
            pass
        wrong = b"checksum-output-sentinel\n"
        connection.sendall(b"\x01\x00\x00\x00" + len(wrong).to_bytes(4, "big") + wrong)

    server = _EngineServer(path, (create, start))
    try:
        client = _client(_docker_policy(path), monkeypatch)
        exec_id = client.create_psql_hash_exec(policy=prepared)
        output = client.start_exec(exec_id=exec_id, sql=bytearray(b"\n"))
        with pytest.raises(allocation.AllocationBackendError, match="postgres_binary") as raised:
            client.assert_psql_binary_output(policy=prepared, output=output)
    finally:
        server.close()
    body = json.loads(requests[0].split(b"\r\n\r\n", 1)[1])
    assert body["Cmd"] == ["/usr/bin/sha256sum", "/usr/bin/psql"]
    assert body["Env"] == []
    assert b"checksum-output-sentinel" not in str(raised.value).encode("ascii")
    assert output == bytearray(b"\x00" * len(output))


def test_reconciliation_receipt_is_signed_but_never_a_resume_grant() -> None:
    # No Engine connection is made: this is the pure receipt verifier boundary.
    projection = DockerEngineFilteredProjectionV1(
        daemon_id="fake-engine-01",
        api_version="1.44",
        operating_system="linux",
        architecture="amd64",
    )
    engine = EngineIdentityObservationV1(
        projection=projection,
        engine_fingerprint_sha256=docker_engine_fingerprint_sha256(projection),
    )
    state = allocation.AllocationReconciliationProjectionV1(
        schema_version="rsd.allocation-reconciliation-projection.v1",
        allocation_intent_sha256=_hash("intent"),
        engine=engine,
        control_image_local_evidence=_local_image_evidence(),
        state=allocation.AllocationReconciliationStateV1.ABSENT,
        observed_network_names=(),
        observed_volume_names=(),
        postgres_state=allocation.AllocationReconciliationPostgreSQLStateV1.ABSENT,
        observed_postgres=None,
        observed_at=_NOW,
    )
    key = Ed25519PrivateKey.from_private_bytes(b"r" * 32)
    public = key.public_key().public_bytes_raw()
    unsigned = allocation.AllocationReconciliationReceiptV1(
        schema_version="rsd.allocation-reconciliation-receipt.v1",
        projection=state,
        projection_sha256=allocation.canonical_sha256(state),
        signer_key_id="executor-attestation",
        signature_base64=_SIGNATURE,
    )
    receipt = unsigned.model_copy(
        update={
            "signature_base64": base64.b64encode(
                key.sign(allocation.allocation_reconciliation_receipt_message(unsigned))
            ).decode("ascii")
        }
    )
    assert (
        allocation.verify_allocation_reconciliation_receipt(
            receipt,
            attestation_key_id="executor-attestation",
            attestation_public_key_base64=base64.b64encode(public).decode("ascii"),
        )
        == receipt
    )
    with pytest.raises(allocation.AllocationBackendError, match="reconciliation_receipt"):
        allocation.verify_allocation_reconciliation_receipt(
            receipt.model_copy(update={"projection_sha256": _hash("substituted")}),
            attestation_key_id="executor-attestation",
            attestation_public_key_base64=base64.b64encode(public).decode("ascii"),
        )


def _image_inspect_document(
    reference: ImageReferenceV1,
    *,
    image_id: str | None = None,
    operating_system: str = "linux",
    architecture: str = "amd64",
    repo_digests: object | None = None,
) -> dict[str, object]:
    """Return the only filtered Engine fields accepted for one image ref."""

    return {
        "Id": image_id if image_id is not None else f"sha256:{'f' * 64}",
        "Os": operating_system,
        "Architecture": architecture,
        "RepoDigests": [reference.reference] if repo_digests is None else repo_digests,
    }


def test_image_local_evidence_requires_two_exact_digest_references(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    """Engine corroborates each digest; it never invents index membership."""

    path = _socket_path(tmp_path)
    policy = _image_policy()
    manifest = allocation._UnixDockerEngineClient._manifest_reference(policy)
    requests: list[bytes] = []

    def index(connection: socket.socket) -> None:
        requests.append(_read_http_request(connection))
        connection.sendall(_json_response(200, _image_inspect_document(policy.image)))

    def platform_manifest(connection: socket.socket) -> None:
        requests.append(_read_http_request(connection))
        connection.sendall(_json_response(200, _image_inspect_document(manifest)))

    server = _EngineServer(path, (index, platform_manifest))
    try:
        client = _client(_docker_policy(path), monkeypatch)
        assert (
            client.inspect_image_reference(policy, reference=policy.image) == policy.image.reference
        )
        assert client.inspect_image_reference(policy, reference=manifest) == manifest.reference
        with pytest.raises(allocation.AllocationBackendError, match="control_image"):
            client.inspect_image_reference(
                policy,
                reference=ImageReferenceV1(reference=f"registry.example/control@sha256:{'1' * 64}"),
            )
    finally:
        server.close()

    assert requests[0].startswith(
        f"GET /v1.44/images/{policy.image.reference}/json HTTP/1.1\r\n".encode("ascii")
    )
    assert requests[1].startswith(
        f"GET /v1.44/images/{manifest.reference}/json HTTP/1.1\r\n".encode("ascii")
    )
    evidence = allocation.expected_docker_image_local_evidence(policy)
    assert evidence.registry_index_reference == policy.image
    assert evidence.linux_amd64_manifest_reference == manifest
    # The compact evidence declares this limitation explicitly: trusted signed
    # OCI resolution, not these Engine documents, proves index membership.
    assert evidence.resolution_attestation_sha256 == allocation.canonical_sha256(
        policy.resolution_attestation
    )


@pytest.mark.parametrize(
    ("document", "description"),
    (
        (
            lambda policy, manifest: _image_inspect_document(manifest, repo_digests=[]),
            "missing_manifest",
        ),
        (
            lambda policy, manifest: _image_inspect_document(
                policy.image,
                image_id=f"sha256:{policy.config_digest_sha256}",
                repo_digests=[policy.image.reference],
            ),
            "right_config_wrong_manifest",
        ),
        (
            lambda policy, manifest: _image_inspect_document(manifest, architecture="arm64"),
            "multiarch_swap",
        ),
        (
            lambda policy, manifest: _image_inspect_document(
                manifest,
                repo_digests=[f"{manifest.reference.rsplit('@', 1)[0]}@sha256:{'1' * 64}"],
            ),
            "tag_or_digest_drift",
        ),
    ),
)
def test_image_manifest_projection_rejects_substitution(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
    document: Callable[[DockerImagePolicyV1, ImageReferenceV1], dict[str, object]],
    description: str,
) -> None:
    """A correct config digest cannot stand in for the signed manifest ref."""

    path = _socket_path(tmp_path)
    policy = _image_policy()
    manifest = allocation._UnixDockerEngineClient._manifest_reference(policy)

    def handler(connection: socket.socket) -> None:
        _read_http_request(connection)
        connection.sendall(_json_response(200, document(policy, manifest)))

    server = _EngineServer(path, (handler,))
    try:
        with pytest.raises(allocation.AllocationBackendError, match="control_image"):
            _client(_docker_policy(path), monkeypatch).inspect_image_reference(
                policy, reference=manifest
            )
    finally:
        server.close()
    assert description


class _HijackConnection:
    """Deterministic stream fragment source for Engine multiplex parser tests."""

    def __init__(self, chunks: list[bytes]) -> None:
        self._chunks = chunks
        self.timeouts: list[float] = []

    def settimeout(self, value: float) -> None:
        self.timeouts.append(value)

    def recv(self, _limit: int) -> bytes:
        return self._chunks.pop(0) if self._chunks else b""


def _multiplex_frame(stream: int, payload: bytes) -> bytes:
    return bytes((stream, 0, 0, 0)) + len(payload).to_bytes(4, "big") + payload


def test_hijack_budgets_count_zero_length_frames_and_redact_stderr(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    """Zero-byte frames and unreturned stderr cannot keep a session alive."""

    policy = _offline_docker_policy(tmp_path).model_copy(
        update={"max_hijack_bytes": 8, "max_hijack_frames": 2}
    )
    client = object.__new__(allocation._UnixDockerEngineClient)
    client._policy = policy
    zero_flood = _HijackConnection([_multiplex_frame(1, b"") * 3, b""])
    with pytest.raises(allocation.AllocationBackendError, match="engine_multiplex"):
        client._read_multiplex(
            zero_flood,
            bytearray(),
            deadline=allocation._EngineIoDeadline.begin(absolute_timeout=2, idle_timeout=1),
        )

    marker = b"stderr-secret-sentinel"
    stderr = _HijackConnection([_multiplex_frame(2, marker), b""])
    with pytest.raises(allocation.AllocationBackendError, match="engine_multiplex") as raised:
        client._read_multiplex(
            stderr,
            bytearray(),
            deadline=allocation._EngineIoDeadline.begin(absolute_timeout=2, idle_timeout=1),
        )
    assert marker.decode("ascii") not in str(raised.value)
    assert marker.decode("ascii") not in repr(raised.value)
    assert zero_flood.timeouts and stderr.timeouts
    monkeypatch.undo()


def test_hijack_absolute_deadline_rejects_continuous_progress(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    """Sub-idle fragments still fail once the policy's absolute cap expires."""

    policy = _offline_docker_policy(tmp_path)
    client = object.__new__(allocation._UnixDockerEngineClient)
    client._policy = policy
    # One frame is delivered in short, successful fragments.  The third
    # blocking-operation preparation sees the absolute deadline and rejects
    # before another fragment can extend the stream indefinitely.
    clock_values = iter((0.0, 0.0, 0.1, 1.1))
    monkeypatch.setattr(allocation.time, "monotonic", lambda: next(clock_values))
    deadline = allocation._EngineIoDeadline.begin(absolute_timeout=1, idle_timeout=1)
    connection = _HijackConnection([b"\x01", b"\x00\x00\x00\x00\x00\x00", b""])
    with pytest.raises(allocation.AllocationBackendError, match="engine_multiplex"):
        client._read_multiplex(connection, bytearray(), deadline=deadline)


@pytest.mark.parametrize("invalid", (True, float("nan"), float("inf"), float("-inf"), -1.0, 1))
def test_engine_deadline_rejects_nonfinite_or_nonexact_monotonic_values(
    monkeypatch: pytest.MonkeyPatch, invalid: object
) -> None:
    monkeypatch.setattr(allocation.time, "monotonic", lambda: invalid)
    with pytest.raises(allocation.AllocationBackendError, match="engine_timeout"):
        allocation._EngineIoDeadline.begin(absolute_timeout=1, idle_timeout=1)


def test_engine_deadline_rejects_clock_regression_during_http_read(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    client = object.__new__(allocation._UnixDockerEngineClient)
    # The first timestamp seeds the deadline; the second begins a read, and
    # the third moves backwards after the peer made progress.
    clock_values = iter((2.0, 2.0, 1.5))
    monkeypatch.setattr(allocation.time, "monotonic", lambda: next(clock_values))
    deadline = allocation._EngineIoDeadline.begin(absolute_timeout=2, idle_timeout=1)
    connection = _HijackConnection([b"HTTP/1.1 200 OK\r\n\r\n"])
    with pytest.raises(allocation.AllocationBackendError, match="engine_timeout"):
        client._recv_until_headers(connection, deadline=deadline)
