"""Adversarial offline tests for the additive V2 attach/wrapper contract.

Every transport below is an in-memory fake.  The tests intentionally exercise
the contract without opening Docker, a Unix socket, a provider, database,
Keychain, network endpoint, or runtime process.
"""

from __future__ import annotations

import base64
import hashlib
import importlib.util
import json
import socket
import struct
import traceback
from dataclasses import dataclass, field
from datetime import UTC, datetime
from pathlib import Path
from typing import Any, cast

import pytest
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey

from omninode_rsd.lifecycle import container_attach_v2 as attach_v2
from omninode_rsd.lifecycle.container_attach_v2 import (
    ContainerAttachV2ContainerLifetimeClaimV1,
    ContainerAttachV2DaemonSession,
    ContainerAttachV2Error,
    ContainerAttachV2FrameType,
    ContainerAttachV2SessionState,
    ContainerAttachV2TicketClaimResult,
    ContainerAttachV2TicketClaimV1,
    ContainerAttachV2WrapperSession,
    ContainerAttachV2WriteCloseResult,
    verify_container_attach_v2_authorization,
)
from omninode_rsd.lifecycle.executor_daemon import ExecutorDaemonError, NoMutationBackend
from omninode_rsd.lifecycle.infisical_disposable import (
    ContainerAttachAuthorizationTicketV1,
    ContainerAttachReadyV2,
    ContainerAttachRequestV2,
    ContainerAttachTerminalAckV2,
    ContainerAttachTicketEnvelopeV2,
    ContainerAttachTicketTrustAnchorV1,
    ContainerAttachV2AuthorizationPolicyV1,
    ContainerBootstrapAttachProtocolV2,
    ContainerBootstrapEnvironmentConstructionPolicyV2,
    ContainerBootstrapFdPolicyV2,
    ContainerBootstrapInspectionV2,
    ContainerBootstrapMemorySafetyPolicyV2,
    ContainerBootstrapPid1PolicyV2,
    ContainerBootstrapStaticEnvironmentEntryV2,
    ContainerBootstrapStaticEnvironmentV2,
    ContainerBootstrapTemplateV2,
    ContainerBootstrapValkeyLaunchPolicyV2,
    ContainerBootstrapWrapperArtifactV2,
    ContainerBootstrapWrapperManifestV2,
    ContainerSecretSinkV1,
    DockerContainerAttachControlPolicyV2,
    DockerNamedVolumeMountV2,
    DockerUnixSocketPolicyV1,
    canonical_sha256,
    container_attach_authorization_ticket_message,
    container_attach_authorization_ticket_sha256,
    container_attach_chunk_descriptors_sha256,
    container_attach_runtime_instance_binding_sha256,
    container_attach_v2_authorization_policy_message,
    container_bootstrap_attach_v2_protocol_message,
    container_bootstrap_attach_v2_protocol_sha256,
    container_bootstrap_valkey_static_configuration_sha256,
    container_bootstrap_wrapper_v2_artifact_sha256,
    container_bootstrap_wrapper_v2_manifest_message,
    container_bootstrap_wrapper_v2_manifest_sha256,
    container_create_v2_template_sha256,
    docker_container_attach_v2_control_policy_message,
    docker_container_attach_v2_control_policy_sha256,
    docker_image_policy_binding,
    docker_unix_socket_identity_sha256,
    target_delivery_map_sha256,
)


def _load_v1_fixtures() -> Any:
    """Load the adjacent V1 test fixtures without making ``tests`` a package."""

    path = Path(__file__).with_name("test_infisical_disposable.py")
    spec = importlib.util.spec_from_file_location("_rsd_v1_attach_fixtures", path)
    if spec is None or spec.loader is None:
        raise RuntimeError("V1 fixture module is unavailable")
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    return module


v1_fixtures = _load_v1_fixtures()

_HEADER = struct.Struct("!4sBBI")
_MUX_HEADER = struct.Struct("!BxxxI")
_PRIVATE = Ed25519PrivateKey.from_private_bytes(b"v" * 32)
_PUBLIC = _PRIVATE.public_key().public_bytes_raw()
_NOW = datetime(2026, 8, 28, 12, 5, tzinfo=UTC)
_CONTAINER_ID = "c" * 64
_HOSTNAME = "rsd-runtime-hostname-123456"


def _hash(label: str) -> str:
    return hashlib.sha256(label.encode("ascii")).hexdigest()


def _signature(message: bytes) -> str:
    return base64.b64encode(_PRIVATE.sign(message)).decode("ascii")


def _v1_message(domain: bytes, model: object) -> bytes:
    return domain + json.dumps(
        cast(Any, model).model_dump(mode="json", exclude={"signature_base64"}),
        ensure_ascii=True,
        sort_keys=True,
        separators=(",", ":"),
    ).encode("utf-8")


def _signed_v1(domain: bytes, model: object) -> object:
    unsigned = cast(Any, model).model_copy(
        update={
            "signer_key_id": "v2-signer",
            "signature_base64": base64.b64encode(b"x" * 64).decode("ascii"),
        }
    )
    return unsigned.model_copy(
        update={"signature_base64": _signature(_v1_message(domain, unsigned))}
    )


def _resigned_v1_attach_chain(
    *, allocation: object, manifest: object, delivery_map: object, protocol: object
) -> tuple[object, object, object]:
    """Build a self-consistent V1 signed predecessor set under the V2 anchor."""

    signed_protocol = _signed_v1(b"omninode-rsd.container-attach-protocol.ed25519.v1\x00", protocol)
    protocol_sha256 = v1_fixtures.container_bootstrap_attach_protocol_sha256(signed_protocol)
    artifacts: dict[str, object] = {}
    for component in (
        "primary_infisical",
        "primary_valkey",
        "restore_infisical",
        "restore_valkey",
    ):
        original = getattr(manifest, component)
        draft = original.model_copy(
            update={
                "attach_protocol_sha256": protocol_sha256,
                "artifact_binding_sha256": "0" * 64,
            }
        )
        artifacts[component] = draft.model_copy(
            update={
                "artifact_binding_sha256": v1_fixtures.container_bootstrap_wrapper_artifact_sha256(
                    draft
                )
            }
        )
    unsigned_manifest = manifest.model_copy(
        update={
            "attach_protocol_sha256": protocol_sha256,
            **artifacts,
        }
    )
    signed_manifest = _signed_v1(
        b"omninode-rsd.container-wrapper-manifest.ed25519.v1\x00", unsigned_manifest
    )
    manifest_sha256 = v1_fixtures.container_bootstrap_wrapper_manifest_sha256(signed_manifest)
    targets = {
        component: getattr(delivery_map, component).model_copy(
            update={
                "wrapper_artifact_binding_sha256": artifacts[component].artifact_binding_sha256,
                "attach_protocol_sha256": protocol_sha256,
            }
        )
        for component in artifacts
    }
    unsigned_map = delivery_map.model_copy(
        update={
            "allocation_intent_sha256": v1_fixtures.allocation_intent_sha256(allocation),
            "wrapper_manifest_sha256": manifest_sha256,
            "attach_protocol_sha256": protocol_sha256,
            **targets,
        }
    )
    signed_map = _signed_v1(b"omninode-rsd.target-delivery-map.ed25519.v1\x00", unsigned_map)
    return signed_manifest, signed_map, signed_protocol


def _resigned_v1_materialization_intent(
    *, intent: object, manifest: object, delivery_map: object, protocol: object
) -> object:
    """Rebind every V1 materialization predecessor before signing it for V2."""

    v1_manifest_sha = v1_fixtures.container_bootstrap_wrapper_manifest_sha256(manifest)
    map_sha = target_delivery_map_sha256(delivery_map)
    protocol_sha = v1_fixtures.container_bootstrap_attach_protocol_sha256(protocol)
    old_templates = cast(Any, intent).bootstrap_templates
    updated_templates: dict[str, object] = {}
    for component in (
        "primary_infisical",
        "primary_valkey",
        "restore_infisical",
        "restore_valkey",
    ):
        original = getattr(old_templates, component)
        artifact = getattr(manifest, component)
        draft = original.model_copy(
            update={
                "wrapper_manifest_sha256": v1_manifest_sha,
                "wrapper_artifact_binding_sha256": artifact.artifact_binding_sha256,
                "attach_protocol_sha256": protocol_sha,
                "create_request_sha256": "0" * 64,
            }
        )
        updated_templates[component] = type(original)(
            **(
                draft.model_dump(mode="python")
                | {"create_request_sha256": v1_fixtures.container_create_template_sha256(draft)}
            )
        )
    templates = type(old_templates)(**updated_templates)
    old_evidence = cast(Any, intent).evidence
    evidence = type(old_evidence)(
        **(
            old_evidence.model_dump(mode="python")
            | {
                "wrapper_manifest_sha256": v1_manifest_sha,
                "target_delivery_map_sha256": map_sha,
                "container_attach_protocol_sha256": protocol_sha,
            }
        )
    )
    unsigned = cast(Any, intent).model_copy(
        update={
            "bootstrap_templates": templates,
            "wrapper_manifest_sha256": v1_manifest_sha,
            "target_delivery_map_sha256": map_sha,
            "container_attach_protocol_sha256": protocol_sha,
            "evidence": evidence,
        }
    )
    canonical = type(intent)(**unsigned.model_dump(mode="python"))
    return _signed_v1(b"omninode-rsd.materialization-intent.ed25519.v1\x00", canonical)


def _metadata(model: object) -> bytes:
    return json.dumps(
        cast(Any, model).model_dump(mode="json"),
        ensure_ascii=True,
        sort_keys=True,
        separators=(",", ":"),
    ).encode("ascii")


def _frame(frame_type: ContainerAttachV2FrameType, payload: bytes) -> bytes:
    return _HEADER.pack(b"ONC2", 2, int(frame_type), len(payload)) + payload


@dataclass(slots=True)
class _Clock:
    now: float = 100.0

    def monotonic(self) -> float:
        return self.now


@dataclass(slots=True)
class _Channel:
    clock: _Clock
    incoming: bytearray = field(default_factory=bytearray)
    outgoing: bytearray = field(default_factory=bytearray)
    close_calls: int = 0
    output_close_calls: int = 0
    fail_close: bool = False

    def read(self, count: int, *, deadline: object) -> bytes:
        del deadline
        if not self.incoming:
            return b""
        value = bytes(self.incoming[:count])
        del self.incoming[:count]
        return value

    def write(self, data: bytes | bytearray | memoryview, *, deadline: object) -> int:
        del deadline
        rendered = bytes(data)
        self.outgoing.extend(rendered)
        return len(rendered)

    def close_write(self, *, deadline: object) -> object:
        del deadline
        self.close_calls += 1
        if self.fail_close:
            raise RuntimeError("not a half-close")
        return ContainerAttachV2WriteCloseResult.HALF_CLOSED


class _TicketAuthority:
    def __init__(self) -> None:
        self.claims: list[ContainerAttachV2TicketClaimV1] = []
        self.container_claims: list[ContainerAttachV2ContainerLifetimeClaimV1] = []
        self._claimed_containers: set[str] = set()
        self.outcome = ContainerAttachV2TicketClaimResult.CLAIMED

    def claim_ticket_and_container_once(
        self,
        claim: ContainerAttachV2TicketClaimV1,
        container_lifetime_claim: ContainerAttachV2ContainerLifetimeClaimV1,
        *,
        deadline: object,
    ) -> object:
        del deadline
        self.claims.append(claim)
        self.container_claims.append(container_lifetime_claim)
        if container_lifetime_claim.container_id in self._claimed_containers:
            return ContainerAttachV2TicketClaimResult.REPLAYED
        outcome = self.outcome
        if outcome is ContainerAttachV2TicketClaimResult.CLAIMED:
            self._claimed_containers.add(container_lifetime_claim.container_id)
            self.outcome = ContainerAttachV2TicketClaimResult.REPLAYED
        return outcome


class _OrderingTicketAuthority(_TicketAuthority):
    """Fails if a claim frame is emitted before the durable claim attempt."""

    def __init__(self, channel: _Channel) -> None:
        super().__init__()
        self._channel = channel
        self.bytes_before_claim: int | None = None

    def claim_ticket_and_container_once(
        self,
        claim: ContainerAttachV2TicketClaimV1,
        container_lifetime_claim: ContainerAttachV2ContainerLifetimeClaimV1,
        *,
        deadline: object,
    ) -> object:
        self.bytes_before_claim = len(self._channel.outgoing)
        return super().claim_ticket_and_container_once(
            claim, container_lifetime_claim, deadline=deadline
        )


class _CommitThenRaiseTicketAuthority:
    """Models a durable claim that commits before its caller loses the response."""

    def __init__(self) -> None:
        self.claims: list[ContainerAttachV2TicketClaimV1] = []

    def claim_ticket_and_container_once(
        self,
        claim: ContainerAttachV2TicketClaimV1,
        container_lifetime_claim: ContainerAttachV2ContainerLifetimeClaimV1,
        *,
        deadline: object,
    ) -> object:
        del deadline
        self.claims.append(claim)
        del container_lifetime_claim
        raise RuntimeError("secret-sentinel")


class _HostileTicketReader:
    def read(self, count: int, *, deadline: object) -> bytes:
        del count, deadline
        raise ContainerAttachV2Error("secret-sentinel")


class _HostileSecretSink:
    def accept(self, descriptor: object, value: memoryview) -> None:
        del descriptor, value
        raise ContainerAttachV2Error("secret-sentinel")


class _RecordingSecretSink:
    def __init__(self) -> None:
        self.calls = 0

    def accept(self, descriptor: object, value: memoryview) -> None:
        del descriptor, value
        self.calls += 1


class _HostileWriter:
    def write(self, data: bytes | bytearray | memoryview, *, deadline: object) -> int:
        del data, deadline
        try:
            raise RuntimeError("secret-sentinel")
        except RuntimeError as cause:
            raise ContainerAttachV2Error("frame_write") from cause


@dataclass(slots=True)
class _ZeroizableDelivery:
    zeroized: bool = False

    def zeroize(self) -> None:
        self.zeroized = True


def _anchor() -> ContainerAttachTicketTrustAnchorV1:
    return ContainerAttachTicketTrustAnchorV1(
        schema_version="rsd.container-attach-ticket-trust-anchor.v1",
        key_id="v2-signer",
        public_key_base64=base64.b64encode(_PUBLIC).decode("ascii"),
        public_key_fingerprint_sha256=hashlib.sha256(_PUBLIC).hexdigest(),
        algorithm="ed25519",
    )


def _protocol(
    *, max_chunk_bytes: int = 4096, max_total_secret_bytes: int = 16384
) -> ContainerBootstrapAttachProtocolV2:
    unsigned = ContainerBootstrapAttachProtocolV2(
        schema_version="rsd.container-bootstrap-attach-protocol.v2",
        protocol_name="rsd_container_bootstrap_attach_v2",
        frame_magic="ONC2",
        frame_version=2,
        metadata_encoding="canonical_json_utf8_v1",
        allowed_operation_scopes=("materialize_and_start_runtime_v1", "start_runtime_v2"),
        first_frame="ticket_envelope_v2",
        ready_state="ready_v2",
        claim_state="claimed_v2",
        write_closed_state="write_closed_v2",
        terminal_ack_state="terminal_ack_v2",
        ambiguous_state="attach_ambiguous_v2",
        max_metadata_bytes=8192,
        max_chunk_bytes=max_chunk_bytes,
        max_chunks_per_target=4,
        max_total_secret_bytes=max_total_secret_bytes,
        max_stdout_bytes=65536,
        max_stdout_frames=32,
        ready_timeout_seconds=10,
        claim_timeout_seconds=10,
        terminal_ack_timeout_seconds=10,
        absolute_timeout_seconds=30,
        docker_non_tty_required=True,
        docker_stdout_only_required=True,
        docker_stderr_rejected=True,
        actual_write_half_close_required=True,
        eof_required_before_terminal_ack=True,
        protocol_output_eof_required_after_terminal_ack=True,
        one_attach_per_container_lifetime=True,
        replay_allowed=False,
        auto_retry_after_secret_delivery_allowed=False,
        secret_persistence_allowed=False,
        secret_logging_allowed=False,
        secret_receipt_allowed=False,
        created_at="2026-08-28T12:00:00Z",
        signer_key_id="v2-signer",
        signature_base64=base64.b64encode(b"x" * 64).decode("ascii"),
    )
    return unsigned.model_copy(
        update={
            "signature_base64": _signature(container_bootstrap_attach_v2_protocol_message(unsigned))
        }
    )


def _static_environment() -> ContainerBootstrapStaticEnvironmentV2:
    rendered = ()
    return ContainerBootstrapStaticEnvironmentV2(
        schema_version="rsd.container-bootstrap-static-environment.v2",
        entries=(),
        environment_sha256=hashlib.sha256(
            json.dumps(rendered, separators=(",", ":")).encode("utf-8")
        ).hexdigest(),
        target_delivery_fields_forbidden=True,
        inherited_environment_allowed=False,
    )


def _child_environment_policy(
    component: str,
    static_environment: ContainerBootstrapStaticEnvironmentV2 | None = None,
) -> ContainerBootstrapEnvironmentConstructionPolicyV2:
    image_environment = static_environment or _static_environment()
    child_entries = ()
    rendered = tuple(item.rendered for item in child_entries)
    expected_dynamic = (
        ("ENCRYPTION_KEY", "AUTH_SECRET", "DB_CONNECTION_URI", "REDIS_URL")
        if component.endswith("infisical")
        else ()
    )
    return ContainerBootstrapEnvironmentConstructionPolicyV2(
        schema_version="rsd.container-bootstrap-environment-construction-policy.v2",
        component=cast(Any, component),
        host_environment_allowed=False,
        env_file_allowed=False,
        docker_config_environment_allowed=False,
        inherited_environment_cleared_before_child_exec=True,
        inherited_environment_read_allowed=False,
        inherited_environment_pass_through_allowed=False,
        explicit_child_envp_required=True,
        global_setenv_for_target_values_allowed=False,
        static_entries=child_entries,
        static_environment_sha256=hashlib.sha256(
            json.dumps(rendered, separators=(",", ":")).encode("utf-8")
        ).hexdigest(),
        image_static_environment_sha256=image_environment.environment_sha256,
        dynamic_target_field_names=expected_dynamic,
        wrapper_network_client_allowed=False,
        telemetry_environment_allowed=False,
        target_value_in_argv_allowed=False,
        target_value_in_file_allowed=False,
        target_value_in_logs_allowed=False,
    )


def _valkey_policy(isolated_bind_address: str) -> ContainerBootstrapValkeyLaunchPolicyV2:
    fields: dict[str, object] = {
        "schema_version": "rsd.container-bootstrap-valkey-launch-policy.v2",
        "command": ("valkey-server", "-"),
        "stdin_configuration_required": True,
        "dynamic_environment_allowed": False,
        "dynamic_argv_allowed": False,
        "data_mount_target": "/data",
        "data_mount_read_only": True,
        "persistence_disabled": True,
        "config_file_allowed": False,
        "wrapper_only_password_assembly": True,
        "isolated_bind_address": isolated_bind_address,
        "listener_port": 6379,
        "protected_mode": "yes",
        "daemonize": "no",
        "save_schedule": "",
        "appendonly": "no",
        "shutdown_on_sigint": "nosave",
        "shutdown_on_sigterm": "nosave",
        "logfile": "/dev/null",
        "loglevel": "nothing",
        "syslog_enabled": "no",
        "crash_log_enabled": "no",
        "set_proc_title": "no",
        "requirepass_directive_count": 1,
        "requirepass_raw_byte_count": 32,
        "requirepass_canonical_base64url_unpadded": True,
        "requirepass_dynamic_directive": "requirepass",
        "requirepass_grammar": (
            "ascii_base64url_32_no_whitespace_controls_quotes_config_delimiters_v2"
        ),
        "acl_profile_sha256": _hash("valkey-acl-profile"),
        "acl_pinned_version_sha256": _hash("valkey-acl-version"),
        "acl_command_allowlist_sha256": _hash("valkey-acl-allowlist"),
        "acl_negative_test_evidence_sha256": _hash("valkey-acl-negative-tests"),
        "acl_denied_command_categories": (
            "acl_administration",
            "configuration",
            "debug_and_module_administration",
            "persistence",
            "replication_configuration",
            "shutdown",
        ),
        "static_directive_order": (
            "bind",
            "port",
            "protected-mode",
            "daemonize",
            "save",
            "appendonly",
            "shutdown-on-sigint",
            "shutdown-on-sigterm",
            "logfile",
            "loglevel",
            "syslog-enabled",
            "crash-log-enabled",
            "set-proc-title",
            "acl-profile",
            "requirepass",
        ),
        "static_configuration_sha256": "0" * 64,
    }
    draft = ContainerBootstrapValkeyLaunchPolicyV2.model_construct(**fields)
    fields["static_configuration_sha256"] = container_bootstrap_valkey_static_configuration_sha256(
        draft
    )
    return ContainerBootstrapValkeyLaunchPolicyV2(**fields)


def _fixture_isolated_bind_address(tmp_path: Path) -> str:
    """Use the signed allocation fixture instead of embedding an address in public tests."""
    allocation, _, _ = v1_fixtures._allocation_bundle(tmp_path)
    return allocation.plan.topology.primary_valkey.static_ipv4


def _fd_policy() -> ContainerBootstrapFdPolicyV2:
    return ContainerBootstrapFdPolicyV2(
        schema_version="rsd.container-bootstrap-fd-policy.v2",
        wrapper_stdin="engine_attach_stdin_v2",
        wrapper_stdout="engine_attach_stdout_protocol_only_v2",
        wrapper_stderr="dev_null",
        infisical_child_stdin="dev_null",
        valkey_child_stdin="private_wrapper_config_pipe",
        child_stdout="dev_null",
        child_stderr="dev_null",
        exec_status_pipe="private_cloexec_status_pipe",
        output_fd_secret_allowed=False,
        logging_allowed=False,
    )


def _pid_policy() -> ContainerBootstrapPid1PolicyV2:
    return ContainerBootstrapPid1PolicyV2(
        schema_version="rsd.container-bootstrap-pid1-policy.v2",
        signal_order=("SIGTERM", "SIGINT"),
        target_process_group_required=True,
        forwards_signals_to_process_group=True,
        reaps_all_children=True,
        propagates_target_leader_exit_status=True,
        terminal_ack_before_exit_required=True,
        child_process_readiness_distinct=True,
        service_readiness_distinct=True,
        shutdown_timeout_seconds=10,
    )


def _memory_policy() -> ContainerBootstrapMemorySafetyPolicyV2:
    return ContainerBootstrapMemorySafetyPolicyV2(
        schema_version="rsd.container-bootstrap-memory-safety-policy.v2",
        wrapper_owned_mutable_buffers_only=True,
        mlock_required_before_secret_delivery=True,
        core_dumps_disabled=True,
        dumpable_disabled=True,
        panic_or_backtrace_logging_allowed=False,
        wrapper_staging_buffers_zeroized=True,
        kernel_socket_buffer_zeroization_claimed=False,
        kernel_pipe_buffer_zeroization_claimed=False,
        swap_zeroization_claimed=False,
        target_process_memory_zeroization_claimed=False,
    )


def _v2_artifact(
    component: str,
    v1_artifact: object,
    protocol_sha256: str,
    *,
    isolated_bind_address: str | None = None,
) -> ContainerBootstrapWrapperArtifactV2:
    source = cast(Any, v1_artifact)
    static_environment = _static_environment()
    if component.endswith("valkey") and isolated_bind_address is None:
        raise RuntimeError("Valkey V2 fixture requires a planned isolated bind address")
    fields: dict[str, object] = {
        "component": component,
        "artifact_sha256": _hash(f"{component}-wrapper"),
        "artifact_byte_count": 4096,
        "executable_path": "/usr/local/libexec/rsd-wrapper",
        "executable_mode": "0755",
        "architecture": "linux/amd64",
        "build_provenance_sha256": _hash(f"{component}-provenance"),
        "build_recipe_sha256": _hash(f"{component}-recipe"),
        "static_patch_sha256": _hash(f"{component}-patch"),
        "v1_wrapper_artifact_binding_sha256": source.artifact_binding_sha256,
        "base_image_policy": source.base_image_policy,
        "derived_image_policy": source.derived_image_policy,
        "wrapper_argv_prefix": ("/usr/local/libexec/rsd-wrapper",),
        "base_entrypoint": source.base_entrypoint,
        "base_command": source.base_command,
        "entrypoint_command_merge": "exec_wrapper_then_base_entrypoint_and_cmd_v2",
        "merged_argv_sha256": _hash("placeholder"),
        "static_environment": static_environment,
        "child_environment_policy": _child_environment_policy(component, static_environment),
        "fd_policy": _fd_policy(),
        "pid1_policy": _pid_policy(),
        "memory_safety_policy": _memory_policy(),
        "valkey_launch_policy": (
            _valkey_policy(cast(str, isolated_bind_address))
            if component.endswith("valkey")
            else None
        ),
        "attach_protocol_v2_sha256": protocol_sha256,
        "artifact_binding_sha256": "0" * 64,
    }
    merged = json.dumps(
        cast(tuple[str, ...], fields["wrapper_argv_prefix"])
        + cast(tuple[str, ...], fields["base_entrypoint"])
        + cast(tuple[str, ...], fields["base_command"]),
        sort_keys=True,
        separators=(",", ":"),
    ).encode("utf-8")
    fields["merged_argv_sha256"] = hashlib.sha256(merged).hexdigest()
    draft = ContainerBootstrapWrapperArtifactV2.model_construct(**fields)
    fields["artifact_binding_sha256"] = container_bootstrap_wrapper_v2_artifact_sha256(draft)
    return ContainerBootstrapWrapperArtifactV2(**fields)


def _runtime_container_id(component: str) -> str:
    """Give each fixture target a distinct full Docker workload identity."""

    return _CONTAINER_ID if component == "primary_infisical" else _hash(f"{component}-container")


def _runtime_hostname(component: str) -> str:
    """Give each fixture target a distinct canonical runtime hostname."""

    return (
        _HOSTNAME
        if component == "primary_infisical"
        else f"rsd-{component.replace('_', '-')}-runtime-123456"
    )


def _controls(
    tmp_path: Path,
    *,
    component: str = "primary_infisical",
    max_chunk_bytes: int = 4096,
    max_total_secret_bytes: int = 16384,
    nonce_label: str = "v2-nonce",
) -> dict[str, object]:
    if component not in {
        "primary_infisical",
        "primary_valkey",
        "restore_infisical",
        "restore_valkey",
    }:
        raise ValueError("unknown V2 attach fixture component")
    allocation, executor, _ = v1_fixtures._allocation_bundle(tmp_path)
    receipt = v1_fixtures._allocation_receipt(allocation)
    observed = v1_fixtures._allocation_attestation(allocation, receipt)
    materialization, restore_observation, _, _, v1_manifest, delivery_map, v1_protocol = (
        v1_fixtures._materialization_intent(allocation, executor, receipt, observed)
    )
    v1_manifest, delivery_map, v1_protocol = _resigned_v1_attach_chain(
        allocation=allocation,
        manifest=v1_manifest,
        delivery_map=delivery_map,
        protocol=v1_protocol,
    )
    materialization = _resigned_v1_materialization_intent(
        intent=materialization,
        manifest=v1_manifest,
        delivery_map=delivery_map,
        protocol=v1_protocol,
    )
    protocol = _protocol(
        max_chunk_bytes=max_chunk_bytes,
        max_total_secret_bytes=max_total_secret_bytes,
    )
    protocol_sha = container_bootstrap_attach_v2_protocol_sha256(protocol)
    attach_policy = _attach_policy(materialization.evidence.executor_control_policy_sha256)
    artifacts = {
        component: _v2_artifact(
            component,
            getattr(v1_manifest, component),
            protocol_sha,
            isolated_bind_address=(
                getattr(allocation.plan.topology, component).static_ipv4
                if component.endswith("valkey")
                else None
            ),
        )
        for component in (
            "primary_infisical",
            "primary_valkey",
            "restore_infisical",
            "restore_valkey",
        )
    }
    unsigned_manifest = ContainerBootstrapWrapperManifestV2(
        schema_version="rsd.container-bootstrap-wrapper-manifest.v2",
        source_commit=v1_fixtures._COMMIT,
        allocation_intent_sha256=v1_fixtures.allocation_intent_sha256(allocation),
        v1_wrapper_manifest_sha256=v1_fixtures.container_bootstrap_wrapper_manifest_sha256(
            v1_manifest
        ),
        v1_target_delivery_map_sha256=target_delivery_map_sha256(delivery_map),
        v1_attach_protocol_sha256=v1_fixtures.container_bootstrap_attach_protocol_sha256(
            v1_protocol
        ),
        attach_protocol_v2_sha256=protocol_sha,
        primary_infisical=artifacts["primary_infisical"],
        primary_valkey=artifacts["primary_valkey"],
        restore_infisical=artifacts["restore_infisical"],
        restore_valkey=artifacts["restore_valkey"],
        created_at="2026-08-28T12:00:00Z",
        signer_key_id="v2-signer",
        signature_base64=base64.b64encode(b"x" * 64).decode("ascii"),
    )
    manifest = unsigned_manifest.model_copy(
        update={
            "signature_base64": _signature(
                container_bootstrap_wrapper_v2_manifest_message(unsigned_manifest)
            )
        }
    )
    artifact = artifacts[component]
    placement = getattr(allocation.plan.topology, component)
    delivery_target = getattr(delivery_map, component)
    component_plan = getattr(materialization.plan, component)
    is_valkey = component.endswith("valkey")
    container_id = _runtime_container_id(component)
    runtime_hostname = _runtime_hostname(component)
    mounts: tuple[DockerNamedVolumeMountV2, ...]
    if is_valkey:
        volume_name = component_plan.volume_name
        if type(volume_name) is not str:
            raise RuntimeError("Valkey V2 fixture requires its named volume")
        mounts = (
            DockerNamedVolumeMountV2(
                mount_type="volume",
                source_volume_name=volume_name,
                target_path="/data",
                read_only=True,
                bind_allowed=False,
                tmpfs_allowed=False,
                propagation="none",
            ),
        )
    else:
        mounts = ()
    template_fields: dict[str, object] = {
        "schema_version": "rsd.container-bootstrap-template.v2",
        "component": component,
        "image": artifact.derived_image_policy.image,
        "image_policy": artifact.derived_image_policy,
        "wrapper_manifest_v2_sha256": container_bootstrap_wrapper_v2_manifest_sha256(manifest),
        "wrapper_artifact_binding_sha256": artifact.artifact_binding_sha256,
        "attach_protocol_v2_sha256": protocol_sha,
        "entrypoint": artifact.wrapper_argv_prefix,
        "command": artifact.base_entrypoint + artifact.base_command,
        "merged_argv_sha256": artifact.merged_argv_sha256,
        "numeric_user": "1001:1001",
        "working_directory": "/app",
        "create_environment": (),
        "static_image_environment": artifact.static_environment,
        "child_environment_policy": artifact.child_environment_policy,
        "hostname_required": True,
        "open_stdin": True,
        "stdin_once": True,
        "attach_stdin": True,
        "tty": False,
        "healthcheck": "none",
        "run_as_non_root": True,
        "read_only_root_filesystem": True,
        "cap_drop_all": True,
        "cap_add": (),
        "no_new_privileges": True,
        "security_options": ("no-new-privileges:true",),
        "private_pid": True,
        "docker_init": False,
        "log_driver": "none",
        "restart_policy": "no",
        "mounts": mounts,
        "valkey_launch_policy": artifact.valkey_launch_policy,
        "docker_socket_mounted": False,
        "host_network": False,
        "publish_all_ports": False,
        "port_bindings": (),
        "labels": (),
        "network_name": placement.network_name,
        "network_alias": placement.alias,
        "static_ipv4": placement.static_ipv4,
        "accepted_secret_sink": (
            ContainerSecretSinkV1.VALKEY_STDIN_CONFIGURATION
            if is_valkey
            else ContainerSecretSinkV1.INFISICAL_TARGET_PROCESS_ENVIRONMENT
        ),
        "create_request_sha256": "0" * 64,
    }
    template_draft = ContainerBootstrapTemplateV2.model_construct(**template_fields)
    template_fields["create_request_sha256"] = container_create_v2_template_sha256(template_draft)
    template = ContainerBootstrapTemplateV2(**template_fields)
    inspection = ContainerBootstrapInspectionV2(
        schema_version="rsd.container-bootstrap-inspection.v2",
        component=cast(Any, component),
        container_id=container_id,
        runtime_hostname=runtime_hostname,
        image_policy_binding=docker_image_policy_binding(template.image_policy),
        create_environment=(),
        static_image_environment=template.static_image_environment,
        child_environment_policy=template.child_environment_policy,
        entrypoint=template.entrypoint,
        command=template.command,
        merged_argv_sha256=template.merged_argv_sha256,
        numeric_user=template.numeric_user,
        working_directory=template.working_directory,
        open_stdin=True,
        stdin_once=True,
        attach_stdin=True,
        tty=False,
        healthcheck="none",
        run_as_non_root=True,
        read_only_root_filesystem=True,
        cap_drop_all=True,
        cap_add=(),
        no_new_privileges=True,
        security_options=("no-new-privileges:true",),
        private_pid=True,
        docker_init=False,
        log_driver="none",
        restart_policy="no",
        mounts=mounts,
        valkey_launch_policy=artifact.valkey_launch_policy,
        docker_socket_mounted=False,
        host_network=False,
        publish_all_ports=False,
        port_bindings=(),
        labels=(),
        network_name=template.network_name,
        network_alias=template.network_alias,
        static_ipv4=template.static_ipv4,
        running=True,
    )
    unsigned_policy = ContainerAttachV2AuthorizationPolicyV1(
        schema_version="rsd.container-attach-v2-authorization-policy.v1",
        source_commit=v1_fixtures._COMMIT,
        allocation_intent_sha256=v1_fixtures.allocation_intent_sha256(allocation),
        allocation_effect_receipt_sha256=v1_fixtures.allocation_effect_receipt_sha256(receipt),
        observed_allocation_attestation_sha256=v1_fixtures.observed_allocation_attestation_sha256(
            observed
        ),
        observed_restore_database_attestation_sha256=(
            v1_fixtures.observed_restore_database_attestation_sha256(restore_observation)
        ),
        materialization_intent_sha256=v1_fixtures.materialization_intent_sha256(materialization),
        v1_wrapper_manifest_sha256=v1_fixtures.container_bootstrap_wrapper_manifest_sha256(
            v1_manifest
        ),
        v1_target_delivery_map_sha256=target_delivery_map_sha256(delivery_map),
        v1_attach_protocol_sha256=v1_fixtures.container_bootstrap_attach_protocol_sha256(
            v1_protocol
        ),
        wrapper_manifest_v2_sha256=container_bootstrap_wrapper_v2_manifest_sha256(manifest),
        attach_protocol_v2_sha256=protocol_sha,
        docker_attach_control_policy_sha256=docker_container_attach_v2_control_policy_sha256(
            attach_policy
        ),
        ticket_trust_anchor=_anchor(),
        ticket_max_lifetime_seconds=600,
        materialization_effect_allowed=False,
        start_effect_allowed=False,
        created_at="2026-08-28T12:00:00Z",
        expires_at="2026-08-28T12:20:00Z",
        signer_key_id="v2-signer",
        signature_base64=base64.b64encode(b"x" * 64).decode("ascii"),
    )
    policy = unsigned_policy.model_copy(
        update={
            "signature_base64": _signature(
                container_attach_v2_authorization_policy_message(unsigned_policy)
            )
        }
    )
    request = ContainerAttachRequestV2(
        schema_version="rsd.container-attach-request.v2",
        allocation_operation_id=allocation.allocation_operation_id,
        operation_scope="materialize_and_start_runtime_v1",
        operation_id=materialization.materialization_operation_id,
        component=cast(Any, component),
        component_role="valkey" if is_valkey else "infisical",
        container_id=container_id,
        runtime_hostname=runtime_hostname,
        runtime_instance_binding_sha256=container_attach_runtime_instance_binding_sha256(
            container_id=container_id, runtime_hostname=runtime_hostname
        ),
        derived_image_policy_sha256=canonical_sha256(artifact.derived_image_policy),
        wrapper_profile_sha256=canonical_sha256(artifact),
        wrapper_manifest_sha256=container_bootstrap_wrapper_v2_manifest_sha256(manifest),
        wrapper_artifact_binding_sha256=artifact.artifact_binding_sha256,
        attach_protocol_sha256=protocol_sha,
        target_delivery_map_sha256=target_delivery_map_sha256(delivery_map),
        request_nonce_sha256=_hash(nonce_label),
        channel_binding_sha256=_hash("v2-channel"),
        session_binding_sha256=_hash("v2-session"),
        expected_ready_state="ready_v2",
        expected_claim_state="claimed_v2",
        expected_terminal_ack_state="terminal_ack_v2",
        fields=delivery_target.fields,
    )
    unsigned_ticket = ContainerAttachAuthorizationTicketV1(
        schema_version="rsd.container-attach-authorization-ticket.v1",
        protocol_sha256=protocol_sha,
        request_sha256=attach_v2.container_attach_v2_request_sha256(request),
        allocation_operation_id=request.allocation_operation_id,
        operation_scope=request.operation_scope,
        operation_id=request.operation_id,
        component=request.component,
        component_role=request.component_role,
        container_id=request.container_id,
        runtime_hostname=request.runtime_hostname,
        runtime_instance_binding_sha256=request.runtime_instance_binding_sha256,
        request_nonce_sha256=request.request_nonce_sha256,
        channel_binding_sha256=request.channel_binding_sha256,
        session_binding_sha256=request.session_binding_sha256,
        wrapper_profile_sha256=request.wrapper_profile_sha256,
        wrapper_manifest_sha256=request.wrapper_manifest_sha256,
        wrapper_artifact_binding_sha256=request.wrapper_artifact_binding_sha256,
        target_delivery_map_sha256=request.target_delivery_map_sha256,
        base_registry_index_digest_sha256=artifact.base_image_policy.registry_index_digest_sha256,
        base_linux_amd64_manifest_digest_sha256=(
            artifact.base_image_policy.linux_amd64_manifest_digest_sha256
        ),
        base_config_digest_sha256=artifact.base_image_policy.config_digest_sha256,
        derived_registry_index_digest_sha256=(
            artifact.derived_image_policy.registry_index_digest_sha256
        ),
        derived_linux_amd64_manifest_digest_sha256=(
            artifact.derived_image_policy.linux_amd64_manifest_digest_sha256
        ),
        derived_config_digest_sha256=artifact.derived_image_policy.config_digest_sha256,
        issued_at="2026-08-28T12:01:00Z",
        expires_at="2026-08-28T12:10:00Z",
        signer_key_id="v2-signer",
        signature_base64=base64.b64encode(b"x" * 64).decode("ascii"),
    )
    ticket = unsigned_ticket.model_copy(
        update={
            "signature_base64": _signature(
                container_attach_authorization_ticket_message(unsigned_ticket)
            )
        }
    )
    return {
        "policy": policy,
        "protocol": protocol,
        "manifest": manifest,
        "delivery_map": delivery_map,
        "v1_manifest": v1_manifest,
        "v1_protocol": v1_protocol,
        "materialization": materialization,
        "attach_policy": attach_policy,
        "template": template,
        "inspection": inspection,
        "anchor": _anchor(),
        "envelope": ContainerAttachTicketEnvelopeV2(
            schema_version="rsd.container-attach-ticket-envelope.v2",
            request=request,
            ticket=ticket,
        ),
    }


def _authorization(tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> object:
    controls = _controls(tmp_path)
    monkeypatch.setattr(attach_v2, "_trusted_utc_now", lambda: _NOW)
    return _verify_controls(controls)


def _verify_controls(controls: dict[str, object], **changes: object) -> object:
    """Verify a fixture bundle after replacing an explicitly named artifact."""

    return verify_container_attach_v2_authorization(
        policy=cast(Any, changes.get("policy", controls["policy"])),
        protocol=cast(Any, changes.get("protocol", controls["protocol"])),
        wrapper_manifest=cast(Any, changes.get("manifest", controls["manifest"])),
        target_delivery_map=cast(Any, changes.get("delivery_map", controls["delivery_map"])),
        v1_wrapper_manifest=cast(Any, changes.get("v1_manifest", controls["v1_manifest"])),
        v1_attach_protocol=cast(Any, changes.get("v1_protocol", controls["v1_protocol"])),
        materialization_intent=cast(
            Any, changes.get("materialization", controls["materialization"])
        ),
        docker_attach_policy=cast(Any, changes.get("attach_policy", controls["attach_policy"])),
        template=cast(Any, changes.get("template", controls["template"])),
        inspection=cast(Any, changes.get("inspection", controls["inspection"])),
        envelope=cast(Any, changes.get("envelope", controls["envelope"])),
        trust_anchor=cast(Any, changes.get("anchor", controls["anchor"])),
    )


def _resign_v2_policy(
    policy: ContainerAttachV2AuthorizationPolicyV1, **changes: object
) -> ContainerAttachV2AuthorizationPolicyV1:
    """Reissue a test policy after an intentional signed-predecessor change."""

    unsigned = policy.model_copy(
        update={
            **changes,
            "signature_base64": base64.b64encode(b"x" * 64).decode("ascii"),
        }
    )
    return unsigned.model_copy(
        update={
            "signature_base64": _signature(
                container_attach_v2_authorization_policy_message(unsigned)
            )
        }
    )


def _resign_v2_manifest(
    manifest: ContainerBootstrapWrapperManifestV2, **changes: object
) -> ContainerBootstrapWrapperManifestV2:
    """Reissue a V2 wrapper manifest after an explicit adversarial substitution."""

    unsigned = manifest.model_copy(
        update={
            **changes,
            "signature_base64": base64.b64encode(b"x" * 64).decode("ascii"),
        }
    )
    return unsigned.model_copy(
        update={
            "signature_base64": _signature(
                container_bootstrap_wrapper_v2_manifest_message(unsigned)
            )
        }
    )


def _resign_v1_target_delivery_map(delivery_map: object, **changes: object) -> object:
    """Reissue one V1 map under the V2 fixture signer for an exploit test."""

    unsigned = cast(Any, delivery_map).model_copy(update=changes)
    return _signed_v1(b"omninode-rsd.target-delivery-map.ed25519.v1\x00", unsigned)


def _rehashed_v2_template(
    template: ContainerBootstrapTemplateV2, **changes: object
) -> ContainerBootstrapTemplateV2:
    """Rebuild a syntactically self-consistent V2 template for substitution tests."""

    draft = template.model_copy(update={**changes, "create_request_sha256": "0" * 64})
    fields = draft.model_dump(mode="python")
    fields["create_request_sha256"] = container_create_v2_template_sha256(draft)
    return ContainerBootstrapTemplateV2(**fields)


def _resign_docker_attach_policy(
    policy: DockerContainerAttachControlPolicyV2, **changes: object
) -> DockerContainerAttachControlPolicyV2:
    """Reissue a signed Docker attach policy under the fixture trust anchor."""

    unsigned = policy.model_copy(
        update={
            **changes,
            "signature_base64": base64.b64encode(b"x" * 64).decode("ascii"),
        }
    )
    return unsigned.model_copy(
        update={
            "signature_base64": _signature(
                docker_container_attach_v2_control_policy_message(unsigned)
            )
        }
    )


def _ready(authorization: object) -> ContainerAttachReadyV2:
    request = cast(Any, authorization).envelope.request
    return ContainerAttachReadyV2(
        schema_version="rsd.container-attach-ready.v2",
        request_sha256=attach_v2.container_attach_v2_request_sha256(request),
        ticket_sha256=container_attach_authorization_ticket_sha256(authorization.envelope.ticket),
        component=request.component,
        container_id=request.container_id,
        runtime_hostname=request.runtime_hostname,
        state="ready_v2",
        wrapper_profile_sha256=request.wrapper_profile_sha256,
        wrapper_artifact_binding_sha256=request.wrapper_artifact_binding_sha256,
        attach_protocol_sha256=request.attach_protocol_sha256,
        fields_sha256=container_attach_chunk_descriptors_sha256(request.fields),
    )


def _secret_frame(ordinal: int, value: bytes) -> bytes:
    payload = struct.pack("!H", ordinal) + value
    return _frame(ContainerAttachV2FrameType.SECRET_CHUNK, payload)


def _ready_daemon_session(
    authorization: object,
    clock: _Clock,
    authority: object,
) -> tuple[ContainerAttachV2DaemonSession, _Channel]:
    session = ContainerAttachV2DaemonSession(
        authorization=cast(Any, authorization),
        deadline_clock=clock,
        ticket_authority=cast(Any, authority),
    )
    channel = _Channel(clock)
    session.write_ticket_envelope(channel)
    session.read_ready(
        _Channel(
            clock,
            incoming=bytearray(
                _frame(ContainerAttachV2FrameType.READY, _metadata(_ready(authorization)))
            ),
        )
    )
    return session, channel


def test_v2_ticket_verifies_canonical_full_runtime_chain(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    authorization = _authorization(tmp_path, monkeypatch)
    assert authorization.envelope.request.container_id == _CONTAINER_ID
    assert authorization.envelope.ticket.runtime_hostname == _HOSTNAME
    assert authorization.policy.materialization_effect_allowed is False
    assert authorization.policy.start_effect_allowed is False


@pytest.mark.parametrize(
    "component",
    ("primary_infisical", "primary_valkey", "restore_infisical", "restore_valkey"),
)
def test_v2_ticket_verifies_each_exact_target_route_and_runtime_binding(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch, component: str
) -> None:
    """Every signed route is independently bound; no primary/restore alias exists."""

    controls = _controls(tmp_path, component=component)
    monkeypatch.setattr(attach_v2, "_trusted_utc_now", lambda: _NOW)
    authorization = _verify_controls(controls)
    request = authorization.envelope.request
    assert request.component == component
    assert request.container_id == _runtime_container_id(component)
    assert request.runtime_hostname == _runtime_hostname(component)
    if component.endswith("valkey"):
        assert request.component_role == "valkey"
        assert tuple(item.target_field for item in request.fields) == ("requirepass",)
        assert authorization.template.valkey_launch_policy is not None
        assert (
            authorization.template.valkey_launch_policy.isolated_bind_address
            == authorization.template.static_ipv4
        )
    else:
        assert request.component_role == "infisical"
        assert tuple(item.target_field for item in request.fields) == (
            "ENCRYPTION_KEY",
            "AUTH_SECRET",
            "DB_CONNECTION_URI",
            "REDIS_URL",
        )


def test_v2_rejects_primary_restore_target_template_inspection_swap(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    """A valid restore Valkey inspection cannot satisfy a primary Valkey ticket."""

    primary = _controls(tmp_path, component="primary_valkey")
    restore = _controls(tmp_path, component="restore_valkey")
    monkeypatch.setattr(attach_v2, "_trusted_utc_now", lambda: _NOW)
    with pytest.raises(ContainerAttachV2Error, match="authorization"):
        _verify_controls(
            primary,
            template=restore["template"],
            inspection=restore["inspection"],
        )


def test_v2_rejects_a_self_consistent_template_with_a_substituted_image_policy(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    """A recomputed create hash cannot detach the image from the signed wrapper artifact."""

    controls = _controls(tmp_path, component="primary_infisical")
    monkeypatch.setattr(attach_v2, "_trusted_utc_now", lambda: _NOW)
    alternate = controls["manifest"].restore_valkey.derived_image_policy
    template = _rehashed_v2_template(
        cast(ContainerBootstrapTemplateV2, controls["template"]),
        image=alternate.image,
        image_policy=alternate,
    )
    inspection = cast(ContainerBootstrapInspectionV2, controls["inspection"]).model_copy(
        update={"image_policy_binding": docker_image_policy_binding(alternate)}
    )

    with pytest.raises(ContainerAttachV2Error, match="authorization"):
        _verify_controls(controls, template=template, inspection=inspection)


def test_v2_artifact_cannot_rebind_its_v1_immutable_predecessor(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    """A fully re-signed V2 bundle cannot choose a different V1 wrapper artifact."""

    controls = _controls(tmp_path, component="primary_infisical")
    monkeypatch.setattr(attach_v2, "_trusted_utc_now", lambda: _NOW)
    original_manifest = cast(ContainerBootstrapWrapperManifestV2, controls["manifest"])
    original = original_manifest.primary_infisical
    hostile_v1_binding = _hash("unrelated-v1-wrapper-artifact")
    draft = original.model_copy(
        update={
            "v1_wrapper_artifact_binding_sha256": hostile_v1_binding,
            "artifact_binding_sha256": "0" * 64,
        }
    )
    hostile = draft.model_copy(
        update={"artifact_binding_sha256": container_bootstrap_wrapper_v2_artifact_sha256(draft)}
    )
    original_map = controls["delivery_map"]
    hostile_target = cast(Any, original_map).primary_infisical.model_copy(
        update={"wrapper_artifact_binding_sha256": hostile_v1_binding}
    )
    hostile_map = _resign_v1_target_delivery_map(
        original_map,
        primary_infisical=hostile_target,
    )
    hostile_materialization = _resigned_v1_materialization_intent(
        intent=controls["materialization"],
        manifest=controls["v1_manifest"],
        delivery_map=hostile_map,
        protocol=controls["v1_protocol"],
    )
    hostile_manifest = _resign_v2_manifest(
        original_manifest,
        primary_infisical=hostile,
        v1_target_delivery_map_sha256=target_delivery_map_sha256(hostile_map),
    )
    hostile_template = _rehashed_v2_template(
        cast(ContainerBootstrapTemplateV2, controls["template"]),
        wrapper_manifest_v2_sha256=container_bootstrap_wrapper_v2_manifest_sha256(hostile_manifest),
        wrapper_artifact_binding_sha256=hostile.artifact_binding_sha256,
    )
    hostile_policy = _resign_v2_policy(
        cast(ContainerAttachV2AuthorizationPolicyV1, controls["policy"]),
        materialization_intent_sha256=v1_fixtures.materialization_intent_sha256(
            hostile_materialization
        ),
        v1_target_delivery_map_sha256=target_delivery_map_sha256(hostile_map),
        wrapper_manifest_v2_sha256=container_bootstrap_wrapper_v2_manifest_sha256(hostile_manifest),
    )
    original_envelope = cast(ContainerAttachTicketEnvelopeV2, controls["envelope"])
    request = original_envelope.request.model_copy(
        update={
            "wrapper_profile_sha256": canonical_sha256(hostile),
            "wrapper_manifest_sha256": container_bootstrap_wrapper_v2_manifest_sha256(
                hostile_manifest
            ),
            "wrapper_artifact_binding_sha256": hostile.artifact_binding_sha256,
            "target_delivery_map_sha256": target_delivery_map_sha256(hostile_map),
        }
    )
    ticket = original_envelope.ticket.model_copy(
        update={
            "request_sha256": attach_v2.container_attach_v2_request_sha256(request),
            "wrapper_profile_sha256": request.wrapper_profile_sha256,
            "wrapper_manifest_sha256": request.wrapper_manifest_sha256,
            "wrapper_artifact_binding_sha256": request.wrapper_artifact_binding_sha256,
            "target_delivery_map_sha256": request.target_delivery_map_sha256,
            "signature_base64": base64.b64encode(b"x" * 64).decode("ascii"),
        }
    )
    hostile_ticket = ticket.model_copy(
        update={
            "signature_base64": _signature(container_attach_authorization_ticket_message(ticket))
        }
    )
    hostile_envelope = original_envelope.model_copy(
        update={"request": request, "ticket": hostile_ticket}
    )

    with pytest.raises(ContainerAttachV2Error, match="authorization"):
        _verify_controls(
            controls,
            policy=hostile_policy,
            manifest=hostile_manifest,
            delivery_map=hostile_map,
            materialization=hostile_materialization,
            template=hostile_template,
            envelope=hostile_envelope,
        )

    monkeypatch.setattr(
        attach_v2,
        "_v2_artifact_matches_v1_predecessor",
        lambda **_: True,
    )
    bypassed = _verify_controls(
        controls,
        policy=hostile_policy,
        manifest=hostile_manifest,
        delivery_map=hostile_map,
        materialization=hostile_materialization,
        template=hostile_template,
        envelope=hostile_envelope,
    )
    assert (
        bypassed.envelope.request.wrapper_artifact_binding_sha256 == hostile.artifact_binding_sha256
    )


def test_v2_rejects_a_recomputed_valkey_template_with_another_allocated_volume(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    """V2's read-only mount must still name the exact V1 materialization volume."""

    primary = _controls(tmp_path, component="primary_valkey")
    restore = _controls(tmp_path, component="restore_valkey")
    monkeypatch.setattr(attach_v2, "_trusted_utc_now", lambda: _NOW)
    original = cast(ContainerBootstrapTemplateV2, primary["template"])
    replacement_mount = original.mounts[0].model_copy(
        update={"source_volume_name": restore["template"].mounts[0].source_volume_name}
    )
    template = _rehashed_v2_template(primary["template"], mounts=(replacement_mount,))
    inspection = cast(ContainerBootstrapInspectionV2, primary["inspection"]).model_copy(
        update={"mounts": (replacement_mount,)}
    )

    with pytest.raises(ContainerAttachV2Error, match="authorization"):
        _verify_controls(primary, template=template, inspection=inspection)


def test_v2_rejects_reissued_attach_policy_with_a_different_executor_predecessor(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    controls = _controls(tmp_path)
    monkeypatch.setattr(attach_v2, "_trusted_utc_now", lambda: _NOW)
    attach_policy = _resign_docker_attach_policy(
        cast(DockerContainerAttachControlPolicyV2, controls["attach_policy"]),
        executor_control_policy_sha256=_hash("other-executor-control-policy"),
    )
    policy = _resign_v2_policy(
        cast(ContainerAttachV2AuthorizationPolicyV1, controls["policy"]),
        docker_attach_control_policy_sha256=docker_container_attach_v2_control_policy_sha256(
            attach_policy
        ),
    )

    with pytest.raises(ContainerAttachV2Error, match="authorization"):
        _verify_controls(controls, policy=policy, attach_policy=attach_policy)


def test_v2_rejects_reissued_attach_policy_from_another_source_commit(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    controls = _controls(tmp_path)
    monkeypatch.setattr(attach_v2, "_trusted_utc_now", lambda: _NOW)
    attach_policy = _resign_docker_attach_policy(
        cast(DockerContainerAttachControlPolicyV2, controls["attach_policy"]),
        source_commit="b" * 40,
    )
    policy = _resign_v2_policy(
        cast(ContainerAttachV2AuthorizationPolicyV1, controls["policy"]),
        docker_attach_control_policy_sha256=docker_container_attach_v2_control_policy_sha256(
            attach_policy
        ),
    )

    with pytest.raises(ContainerAttachV2Error, match="authorization"):
        _verify_controls(controls, policy=policy, attach_policy=attach_policy)


def test_v2_rejects_aggregate_secret_bytes_before_any_attach_boundary(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    """Per-field bounds never let a request exceed the independently signed total."""

    controls = _controls(
        tmp_path,
        max_chunk_bytes=128,
        max_total_secret_bytes=200,
    )
    monkeypatch.setattr(attach_v2, "_trusted_utc_now", lambda: _NOW)
    fields = controls["envelope"].request.fields
    assert all(item.encoded_byte_count <= 128 for item in fields)
    assert sum(item.encoded_byte_count for item in fields) > 200
    with pytest.raises(ContainerAttachV2Error, match="authorization"):
        _verify_controls(controls)


@pytest.mark.parametrize("field", ("container_id", "runtime_hostname", "wrapper_profile_sha256"))
def test_v2_ticket_substitution_is_rejected_before_attach(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch, field: str
) -> None:
    controls = _controls(tmp_path)
    monkeypatch.setattr(attach_v2, "_trusted_utc_now", lambda: _NOW)
    envelope = cast(ContainerAttachTicketEnvelopeV2, controls["envelope"])
    ticket = envelope.ticket.model_copy(
        update={field: "d" * 64 if field == "container_id" else _hash(field)}
    )
    if field == "runtime_hostname":
        ticket = envelope.ticket.model_copy(update={field: "rsd-runtime-hostname-654321"})
    signed = ticket.model_copy(
        update={
            "signature_base64": _signature(container_attach_authorization_ticket_message(ticket))
        }
    )
    hostile = envelope.model_copy(update={"ticket": signed})
    with pytest.raises(ContainerAttachV2Error, match=r"ticket|authorization"):
        verify_container_attach_v2_authorization(
            policy=cast(Any, controls["policy"]),
            protocol=cast(Any, controls["protocol"]),
            wrapper_manifest=cast(Any, controls["manifest"]),
            target_delivery_map=cast(Any, controls["delivery_map"]),
            v1_wrapper_manifest=cast(Any, controls["v1_manifest"]),
            v1_attach_protocol=cast(Any, controls["v1_protocol"]),
            materialization_intent=cast(Any, controls["materialization"]),
            docker_attach_policy=cast(Any, controls["attach_policy"]),
            template=cast(Any, controls["template"]),
            inspection=cast(Any, controls["inspection"]),
            envelope=hostile,
            trust_anchor=cast(Any, controls["anchor"]),
        )


def test_v2_ticket_stale_and_noncanonical_models_fail_closed(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    controls = _controls(tmp_path)
    monkeypatch.setattr(
        attach_v2, "_trusted_utc_now", lambda: datetime(2026, 8, 28, 12, 11, tzinfo=UTC)
    )
    with pytest.raises(ContainerAttachV2Error, match="ticket"):
        verify_container_attach_v2_authorization(
            policy=cast(Any, controls["policy"]),
            protocol=cast(Any, controls["protocol"]),
            wrapper_manifest=cast(Any, controls["manifest"]),
            target_delivery_map=cast(Any, controls["delivery_map"]),
            v1_wrapper_manifest=cast(Any, controls["v1_manifest"]),
            v1_attach_protocol=cast(Any, controls["v1_protocol"]),
            materialization_intent=cast(Any, controls["materialization"]),
            docker_attach_policy=cast(Any, controls["attach_policy"]),
            template=cast(Any, controls["template"]),
            inspection=cast(Any, controls["inspection"]),
            envelope=cast(Any, controls["envelope"]),
            trust_anchor=cast(Any, controls["anchor"]),
        )
    monkeypatch.setattr(attach_v2, "_trusted_utc_now", lambda: _NOW)
    envelope = cast(ContainerAttachTicketEnvelopeV2, controls["envelope"])
    raw_request = ContainerAttachRequestV2.model_construct(**envelope.request.model_dump())
    raw_request.__dict__["component_role"] = "infisical"
    hostile = envelope.model_copy(update={"request": raw_request})
    with pytest.raises(ContainerAttachV2Error, match="ticket_envelope"):
        verify_container_attach_v2_authorization(
            policy=cast(Any, controls["policy"]),
            protocol=cast(Any, controls["protocol"]),
            wrapper_manifest=cast(Any, controls["manifest"]),
            target_delivery_map=cast(Any, controls["delivery_map"]),
            v1_wrapper_manifest=cast(Any, controls["v1_manifest"]),
            v1_attach_protocol=cast(Any, controls["v1_protocol"]),
            materialization_intent=cast(Any, controls["materialization"]),
            docker_attach_policy=cast(Any, controls["attach_policy"]),
            template=cast(Any, controls["template"]),
            inspection=cast(Any, controls["inspection"]),
            envelope=hostile,
            trust_anchor=cast(Any, controls["anchor"]),
        )


def test_v2_retained_authorization_is_rechecked_before_ticket_or_raw_socket_use(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    authorization = cast(Any, _authorization(tmp_path, monkeypatch))
    clock = _Clock()
    session = ContainerAttachV2DaemonSession(
        authorization=authorization, deadline_clock=clock, ticket_authority=_TicketAuthority()
    )
    channel = _Channel(clock)
    monkeypatch.setattr(
        attach_v2, "_trusted_utc_now", lambda: datetime(2026, 8, 28, 12, 11, tzinfo=UTC)
    )
    with pytest.raises(ContainerAttachV2Error, match="ticket"):
        _ = session.expected_claim
    with pytest.raises(ContainerAttachV2Error, match="ticket"):
        session.write_ticket_envelope(channel)
    assert channel.outgoing == b""

    monkeypatch.setattr(attach_v2, "_trusted_utc_now", lambda: _NOW)
    handshake = b"HTTP/1.1 101 UPGRADED\r\nConnection: Upgrade\r\nUpgrade: tcp\r\n\r\n"
    raw = _RawSocket(bytearray(handshake))
    client = attach_v2._RawUnixDockerAttachV2ForTest._from_fake_socket_for_test(
        raw_socket=raw, authorization=authorization, deadline_clock=clock
    )
    sent_before_expiry = bytes(raw.sent)
    monkeypatch.setattr(
        attach_v2, "_trusted_utc_now", lambda: datetime(2026, 8, 28, 12, 11, tzinfo=UTC)
    )
    with pytest.raises(ContainerAttachV2Error, match="ticket"):
        client.write(b"x", deadline=_raw_deadline(client, phase="frame_write"))
    assert raw.sent == sent_before_expiry


def test_v2_has_no_public_pathname_docker_connector(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    del tmp_path, monkeypatch
    import omninode_rsd.lifecycle as lifecycle

    assert "RawUnixDockerAttachV2" not in attach_v2.__all__
    assert not hasattr(attach_v2, "RawUnixDockerAttachV2")
    assert not hasattr(lifecycle, "RawUnixDockerAttachV2")


def test_v2_stale_signed_materialization_predecessor_is_not_attach_authority(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    controls = _controls(tmp_path)
    monkeypatch.setattr(attach_v2, "_trusted_utc_now", lambda: _NOW)
    original = cast(Any, controls["materialization"])
    stale = _signed_v1(
        b"omninode-rsd.materialization-intent.ed25519.v1\x00",
        original.model_copy(update={"retention_expires_at": "2026-08-28T12:04:00Z"}),
    )
    policy = _resign_v2_policy(
        cast(ContainerAttachV2AuthorizationPolicyV1, controls["policy"]),
        materialization_intent_sha256=v1_fixtures.materialization_intent_sha256(stale),
    )
    with pytest.raises(ContainerAttachV2Error, match="ticket"):
        _verify_controls(controls, materialization=stale, policy=policy)


@pytest.mark.parametrize(
    "artifact_name",
    ("v1_manifest", "delivery_map", "v1_protocol", "materialization"),
)
def test_v2_rejects_every_unsigned_or_tampered_v1_predecessor(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch, artifact_name: str
) -> None:
    """Every V1 predecessor is a signed input, never just a caller hash."""

    controls = _controls(tmp_path)
    monkeypatch.setattr(attach_v2, "_trusted_utc_now", lambda: _NOW)
    original = cast(Any, controls[artifact_name])
    hostile = original.model_copy(
        update={"signature_base64": base64.b64encode(b"q" * 64).decode("ascii")}
    )
    with pytest.raises(ContainerAttachV2Error, match="authorization"):
        _verify_controls(controls, **{artifact_name: hostile})


def test_v2_rejects_cross_operation_materialization_intent_even_when_resigned(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    """A trusted signature cannot substitute a different materialization operation."""

    controls = _controls(tmp_path)
    monkeypatch.setattr(attach_v2, "_trusted_utc_now", lambda: _NOW)
    original = cast(Any, controls["materialization"])
    different_operation = "11111111-1111-4111-8111-111111111111"
    delivery_request = original.secret_delivery_request.model_copy(
        update={"operation_id": different_operation}
    )
    hostile = _signed_v1(
        b"omninode-rsd.materialization-intent.ed25519.v1\x00",
        original.model_copy(
            update={
                "materialization_operation_id": different_operation,
                "secret_delivery_request": delivery_request,
            }
        ),
    )
    with pytest.raises(ContainerAttachV2Error, match="authorization"):
        _verify_controls(controls, materialization=hostile)


def test_v2_verified_authorization_is_not_a_public_forgeable_grant(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    """Only verifier issuance can reach a daemon session or raw attach seam."""

    authorization = _authorization(tmp_path, monkeypatch)
    assert not hasattr(attach_v2, "VerifiedContainerAttachV2Authorization")
    with pytest.raises(TypeError, match="internally issued"):
        attach_v2._VerifiedContainerAttachV2Authorization(policy=authorization.policy)
    raw = _RawSocket(bytearray())
    with pytest.raises(ContainerAttachV2Error, match="authorization"):
        attach_v2._RawUnixDockerAttachV2ForTest._from_fake_socket_for_test(
            raw_socket=raw,
            authorization=cast(Any, object()),
            deadline_clock=_Clock(),
        )
    assert raw.sent == b""


def test_v2_sender_requires_ticket_claim_half_close_ack_and_output_eof(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    authorization = cast(Any, _authorization(tmp_path, monkeypatch))
    clock = _Clock()
    authority = _TicketAuthority()
    session = ContainerAttachV2DaemonSession(
        authorization=authorization, deadline_clock=clock, ticket_authority=authority
    )
    sender = _Channel(clock)
    session.write_ticket_envelope(sender)
    assert sender.outgoing.startswith(b"ONC2")
    request = authorization.envelope.request
    ready = ContainerAttachReadyV2(
        schema_version="rsd.container-attach-ready.v2",
        request_sha256=attach_v2.container_attach_v2_request_sha256(request),
        ticket_sha256=container_attach_authorization_ticket_sha256(authorization.envelope.ticket),
        component=request.component,
        container_id=request.container_id,
        runtime_hostname=request.runtime_hostname,
        state="ready_v2",
        wrapper_profile_sha256=request.wrapper_profile_sha256,
        wrapper_artifact_binding_sha256=request.wrapper_artifact_binding_sha256,
        attach_protocol_sha256=request.attach_protocol_sha256,
        fields_sha256=container_attach_chunk_descriptors_sha256(request.fields),
    )
    session.read_ready(
        _Channel(
            clock, incoming=bytearray(_frame(ContainerAttachV2FrameType.READY, _metadata(ready)))
        )
    )
    session.write_claim(sender)
    chunks = tuple(bytearray(b"s" * field.encoded_byte_count) for field in request.fields)
    session.write_secret_chunks(sender, chunks)
    assert all(set(chunk) == {0} for chunk in chunks)
    session.close_write(sender)
    assert sender.close_calls == 1
    claim = session.expected_claim
    ack = ContainerAttachTerminalAckV2(
        schema_version="rsd.container-attach-terminal-ack.v2",
        request_sha256=claim.request_sha256,
        ticket_sha256=claim.ticket_sha256,
        state="terminal_ack_v2",
        chunk_count=claim.chunk_count,
        chunk_descriptors_sha256=claim.chunk_descriptors_sha256,
        input_eof_observed=True,
        child_handoff_complete=True,
        staging_buffers_zeroized=True,
        protocol_output_close_required=True,
        child_process_readiness_claimed=False,
        service_readiness_claimed=False,
        persistence_allowed=False,
        logging_allowed=False,
        receipt_contains_secret=False,
    )
    ack_reader = _Channel(
        clock,
        incoming=bytearray(_frame(ContainerAttachV2FrameType.TERMINAL_ACK, _metadata(ack))),
    )
    session.read_terminal_ack(ack_reader)
    session.require_protocol_output_eof(ack_reader)
    receipt = session.receipt()
    assert receipt.input_eof_observed is True
    assert receipt.protocol_output_eof_observed is True
    assert session.state is ContainerAttachV2SessionState.CLOSED


def test_v2_replay_or_failed_half_close_is_terminal_and_scrubs_buffers(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    authorization = cast(Any, _authorization(tmp_path, monkeypatch))
    clock = _Clock()
    authority = _TicketAuthority()
    session = ContainerAttachV2DaemonSession(
        authorization=authorization, deadline_clock=clock, ticket_authority=authority
    )
    channel = _Channel(clock)
    session.write_ticket_envelope(channel)
    request = authorization.envelope.request
    ready = ContainerAttachReadyV2(
        schema_version="rsd.container-attach-ready.v2",
        request_sha256=attach_v2.container_attach_v2_request_sha256(request),
        ticket_sha256=container_attach_authorization_ticket_sha256(authorization.envelope.ticket),
        component=request.component,
        container_id=request.container_id,
        runtime_hostname=request.runtime_hostname,
        state="ready_v2",
        wrapper_profile_sha256=request.wrapper_profile_sha256,
        wrapper_artifact_binding_sha256=request.wrapper_artifact_binding_sha256,
        attach_protocol_sha256=request.attach_protocol_sha256,
        fields_sha256=container_attach_chunk_descriptors_sha256(request.fields),
    )
    session.read_ready(
        _Channel(
            clock, incoming=bytearray(_frame(ContainerAttachV2FrameType.READY, _metadata(ready)))
        )
    )
    authority.outcome = ContainerAttachV2TicketClaimResult.REPLAYED
    with pytest.raises(ContainerAttachV2Error, match="replay"):
        session.write_claim(channel)
    assert session.state is ContainerAttachV2SessionState.REJECTED
    chunks = tuple(bytearray(b"z" * field.encoded_byte_count) for field in request.fields)
    with pytest.raises(ContainerAttachV2Error, match="state"):
        session.write_secret_chunks(channel, chunks)
    assert all(set(chunk) == {0} for chunk in chunks)


def test_v2_claim_is_durable_before_claim_frame_or_secret_delivery(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    authorization = cast(Any, _authorization(tmp_path, monkeypatch))
    clock = _Clock()
    channel = _Channel(clock)
    authority = _OrderingTicketAuthority(channel)
    session = ContainerAttachV2DaemonSession(
        authorization=authorization, deadline_clock=clock, ticket_authority=authority
    )
    session.write_ticket_envelope(channel)
    ticket_bytes = len(channel.outgoing)
    session.read_ready(
        _Channel(
            clock,
            incoming=bytearray(
                _frame(ContainerAttachV2FrameType.READY, _metadata(_ready(authorization)))
            ),
        )
    )
    session.write_claim(channel)
    assert authority.bytes_before_claim == ticket_bytes
    assert len(authority.claims) == 1
    assert len(channel.outgoing) > ticket_bytes


def test_v2_authority_claims_each_container_lifetime_once_even_for_a_fresh_ticket(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    first_controls = _controls(tmp_path, nonce_label="first-ticket-nonce")
    second_controls = _controls(tmp_path, nonce_label="second-ticket-nonce")
    monkeypatch.setattr(attach_v2, "_trusted_utc_now", lambda: _NOW)
    first = cast(Any, _verify_controls(first_controls))
    second = cast(Any, _verify_controls(second_controls))
    assert first.envelope.ticket != second.envelope.ticket
    assert first.envelope.request.container_id == second.envelope.request.container_id
    clock = _Clock()
    authority = _TicketAuthority()
    first_session, first_channel = _ready_daemon_session(first, clock, authority)
    first_session.write_claim(first_channel)
    second_session, second_channel = _ready_daemon_session(second, clock, authority)
    with pytest.raises(ContainerAttachV2Error, match="replay"):
        second_session.write_claim(second_channel)
    assert second_session.state is ContainerAttachV2SessionState.REJECTED
    assert [claim.container_id for claim in authority.container_claims] == [
        first.envelope.request.container_id,
        second.envelope.request.container_id,
    ]
    assert all(claim.one_attach_per_container_lifetime for claim in authority.container_claims)


def test_v2_commit_then_raise_is_ambiguous_and_cannot_retry(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    authorization = cast(Any, _authorization(tmp_path, monkeypatch))
    clock = _Clock()
    authority = _CommitThenRaiseTicketAuthority()
    session, channel = _ready_daemon_session(authorization, clock, authority)
    with pytest.raises(ContainerAttachV2Error, match="claim") as caught:
        session.write_claim(channel)
    assert caught.value.__context__ is None
    assert caught.value.__cause__ is None
    assert session.state is ContainerAttachV2SessionState.AMBIGUOUS
    assert len(authority.claims) == 1
    with pytest.raises(ContainerAttachV2Error, match="state"):
        session.write_claim(channel)


def test_v2_rejected_non_tuple_secret_inputs_are_recursively_scrubbed(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    authorization = cast(Any, _authorization(tmp_path, monkeypatch))
    session, channel = _ready_daemon_session(authorization, _Clock(), _TicketAuthority())
    session.write_claim(channel)
    sentinel = bytearray(b"secret-sentinel")
    nested = [sentinel, (bytearray(b"second-sentinel"),)]
    with pytest.raises(ContainerAttachV2Error, match="secret_chunks"):
        session.write_secret_chunks(channel, cast(Any, nested))
    assert sentinel == b"\x00" * len(sentinel)
    assert nested[1][0] == b"\x00" * len(nested[1][0])


def test_v2_rejected_non_tuple_scrubs_mutable_views_without_touching_immutable_bytes(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    """A hostile collection is rejected, but every discoverable mutable secret is scrubbed."""
    authorization = cast(Any, _authorization(tmp_path, monkeypatch))
    session, channel = _ready_daemon_session(authorization, _Clock(), _TicketAuthority())
    session.write_claim(channel)
    backing = bytearray(b"view-secret-sentinel")
    immutable = b"immutable-sentinel"
    hostile = [memoryview(backing), {"immutable": immutable}]

    with pytest.raises(ContainerAttachV2Error, match="secret_chunks"):
        session.write_secret_chunks(channel, cast(Any, hostile))

    assert backing == b"\x00" * len(backing)
    assert immutable == b"immutable-sentinel"


def test_v2_valkey_requirepass_delivery_enforces_canonical_32_byte_base64url_before_sink(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    controls = _controls(tmp_path, component="primary_valkey")
    monkeypatch.setattr(attach_v2, "_trusted_utc_now", lambda: _NOW)
    authorization = cast(Any, _verify_controls(controls))
    clock = _Clock()
    sender, channel = _ready_daemon_session(authorization, clock, _TicketAuthority())
    sender.write_claim(channel)
    valid = bytearray(base64.urlsafe_b64encode(b"v" * 32).rstrip(b"="))
    sender.write_secret_chunks(channel, (valid,))
    assert sender.state is ContainerAttachV2SessionState.CHUNKS_SENT
    assert valid == b"\x00" * len(valid)

    invalid = bytearray(b"A" * 42 + b"B")
    retry, retry_channel = _ready_daemon_session(authorization, clock, _TicketAuthority())
    retry.write_claim(retry_channel)
    bytes_before_invalid = bytes(retry_channel.outgoing)
    with pytest.raises(ContainerAttachV2Error, match="frame_write"):
        retry.write_secret_chunks(retry_channel, (invalid,))
    assert invalid == b"\x00" * len(invalid)
    assert retry_channel.outgoing == bytes_before_invalid

    wrapper = ContainerAttachV2WrapperSession(authorization=authorization, deadline_clock=clock)
    wrapper.write_ready(_Channel(clock))
    wrapper.read_claim(
        _Channel(
            clock,
            incoming=bytearray(
                _frame(
                    ContainerAttachV2FrameType.CLAIM,
                    _metadata(attach_v2._expected_claim(authorization)),
                )
            ),
        )
    )
    sink = _RecordingSecretSink()
    with pytest.raises(ContainerAttachV2Error, match="target_sink"):
        wrapper.consume_secret_chunks(
            _Channel(clock, incoming=bytearray(_secret_frame(1, b"A" * 42 + b"B"))),
            sink,
        )
    assert sink.calls == 0
    assert wrapper.state is ContainerAttachV2SessionState.AMBIGUOUS


def test_v2_session_absolute_deadline_and_monotonic_regression_fail_closed(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    authorization = cast(Any, _authorization(tmp_path, monkeypatch))
    clock = _Clock()
    session = ContainerAttachV2DaemonSession(
        authorization=authorization, deadline_clock=clock, ticket_authority=_TicketAuthority()
    )
    sender = _Channel(clock)
    session.write_ticket_envelope(sender)
    clock.now += 31.0
    with pytest.raises(ContainerAttachV2Error, match="ready"):
        session.read_ready(
            _Channel(
                clock,
                incoming=bytearray(
                    _frame(ContainerAttachV2FrameType.READY, _metadata(_ready(authorization)))
                ),
            )
        )
    assert session.state is ContainerAttachV2SessionState.AMBIGUOUS

    clock = _Clock()
    session = ContainerAttachV2DaemonSession(
        authorization=authorization, deadline_clock=clock, ticket_authority=_TicketAuthority()
    )
    session.write_ticket_envelope(_Channel(clock))
    clock.now -= 1.0
    with pytest.raises(ContainerAttachV2Error, match="ready"):
        session.read_ready(_HostileTicketReader())
    assert session.state is ContainerAttachV2SessionState.AMBIGUOUS


def test_v2_nan_and_infinite_monotonic_clock_values_are_rejected_before_io(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    authorization = cast(Any, _authorization(tmp_path, monkeypatch))
    for invalid in (float("nan"), float("inf"), float("-inf")):
        with pytest.raises(ContainerAttachV2Error, match="deadline"):
            ContainerAttachV2DaemonSession(
                authorization=authorization,
                deadline_clock=_Clock(now=invalid),
                ticket_authority=_TicketAuthority(),
            )


def test_v2_hostile_secret_sink_and_reader_errors_are_detached_and_scrubbed(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    authorization = cast(Any, _authorization(tmp_path, monkeypatch))
    clock = _Clock()
    wrapper = ContainerAttachV2WrapperSession(authorization=authorization, deadline_clock=clock)
    wrapper.write_ready(_Channel(clock))
    claim = attach_v2._expected_claim(authorization)
    wrapper.read_claim(
        _Channel(
            clock,
            incoming=bytearray(_frame(ContainerAttachV2FrameType.CLAIM, _metadata(claim))),
        )
    )
    first = authorization.envelope.request.fields[0]
    payload = b"secret-sentinel" + b"x" * (first.encoded_byte_count - len(b"secret-sentinel"))
    reader = _Channel(
        clock,
        incoming=bytearray(_secret_frame(first.ordinal, payload)),
    )
    with pytest.raises(ContainerAttachV2Error) as caught:
        wrapper.consume_secret_chunks(reader, _HostileSecretSink())
    error = caught.value
    assert error.phase == "target_sink"
    assert "secret-sentinel" not in str(error)
    assert "secret-sentinel" not in repr(error)
    assert "secret-sentinel" not in repr(error.__dict__)
    assert error.__context__ is None
    assert error.__cause__ is None
    assert getattr(error, "__notes__", None) is None

    second_clock = _Clock()
    wrapper = ContainerAttachV2WrapperSession(
        authorization=authorization, deadline_clock=second_clock
    )
    wrapper.write_ready(_Channel(second_clock))
    # A fresh wrapper needs the same claim state before a hostile reader is reachable.
    claim = attach_v2._expected_claim(authorization)
    wrapper.read_claim(
        _Channel(
            second_clock,
            incoming=bytearray(_frame(ContainerAttachV2FrameType.CLAIM, _metadata(claim))),
        )
    )
    with pytest.raises(ContainerAttachV2Error) as reader_caught:
        wrapper.consume_secret_chunks(_HostileTicketReader(), _HostileSecretSink())
    reader_error = reader_caught.value
    assert reader_error.phase == "secret_chunk"
    assert "secret-sentinel" not in str(reader_error)
    assert reader_error.__context__ is None
    assert reader_error.__cause__ is None


def test_v2_hostile_writer_and_raw_attach_errors_are_detached(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    """Every collaborator error crosses V2 as a fresh fixed-phase public error."""

    authorization = cast(Any, _authorization(tmp_path, monkeypatch))
    session = ContainerAttachV2DaemonSession(
        authorization=authorization,
        deadline_clock=_Clock(),
        ticket_authority=_TicketAuthority(),
    )
    with pytest.raises(ContainerAttachV2Error) as caught:
        session.write_ticket_envelope(_HostileWriter())
    error = caught.value
    assert error.phase == "ticket_envelope"
    assert "secret-sentinel" not in str(error)
    assert "secret-sentinel" not in repr(error)
    assert "secret-sentinel" not in repr(error.__dict__)
    assert "secret-sentinel" not in "".join(traceback.format_exception(error))
    assert error.__context__ is None
    assert error.__cause__ is None
    assert getattr(error, "__notes__", None) is None

    handshake = b"HTTP/1.1 101 UPGRADED\r\nConnection: Upgrade\r\nUpgrade: tcp\r\n\r\n"
    raw = _HostileRawSocket(bytearray(handshake))
    client = attach_v2._RawUnixDockerAttachV2ForTest._from_fake_socket_for_test(
        raw_socket=raw,
        authorization=authorization,
        deadline_clock=_Clock(),
    )
    raw.fail_writes = True
    value = b"".join((b"secret", b"-", b"sentinel"))
    with pytest.raises(ContainerAttachV2Error) as raw_caught:
        client.write(value, deadline=_raw_deadline(client, phase="frame_write"))
    raw_error = raw_caught.value
    assert raw_error.phase == "frame_write"
    assert "secret-sentinel" not in str(raw_error)
    assert "secret-sentinel" not in repr(raw_error)
    assert "secret-sentinel" not in repr(raw_error.__dict__)
    assert "secret-sentinel" not in "".join(traceback.format_exception(raw_error))
    assert raw_error.__context__ is None
    assert raw_error.__cause__ is None
    assert getattr(raw_error, "__notes__", None) is None


def _attach_policy(executor_control_policy_sha256: str) -> DockerContainerAttachControlPolicyV2:
    socket_policy = DockerUnixSocketPolicyV1(
        socket_path="/var/run/docker.sock",
        socket_path_sha256=hashlib.sha256(b"/var/run/docker.sock").hexdigest(),
        socket_identity_sha256=docker_unix_socket_identity_sha256(
            socket_path_sha256=hashlib.sha256(b"/var/run/docker.sock").hexdigest(),
            device=1,
            inode=2,
            owner_uid=0,
            group_gid=0,
            mode=0o660,
        ),
        device=1,
        inode=2,
        owner_uid=0,
        group_gid=0,
        mode=0o660,
        endpoint_scheme="unix",
        symlink_allowed=False,
        replacement_allowed=False,
    )
    unsigned = DockerContainerAttachControlPolicyV2(
        schema_version="rsd.docker-container-attach-control-policy.v2",
        source_commit=v1_fixtures._COMMIT,
        executor_control_policy_sha256=executor_control_policy_sha256,
        unix_socket=socket_policy,
        api_version="1.47",
        allowed_operation="container_attach_non_tty_v2",
        request_method="POST",
        endpoint_shape=(
            "/v{api}/containers/{container_id}/attach?stdin=1&stdout=1&stderr=1&stream=1&logs=0"
        ),
        stdin_required=True,
        stdout_required=True,
        stderr_required=True,
        stream_required=True,
        tty_required=False,
        logs_allowed=False,
        max_request_bytes=4096,
        max_response_header_bytes=4096,
        max_stdout_bytes=65536,
        max_stdout_frames=32,
        request_timeout_seconds=10,
        idle_timeout_seconds=10,
        absolute_timeout_seconds=30,
        created_at="2026-08-28T12:00:00Z",
        signer_key_id="v2-signer",
        signature_base64=base64.b64encode(b"x" * 64).decode("ascii"),
    )
    return unsigned.model_copy(
        update={
            "signature_base64": _signature(
                docker_container_attach_v2_control_policy_message(unsigned)
            )
        }
    )


@pytest.mark.parametrize(
    ("field_name", "value"),
    (
        ("protected_mode", "no"),
        ("daemonize", "yes"),
        ("save_schedule", "900 1"),
        ("appendonly", "yes"),
        ("shutdown_on_sigint", "save"),
        ("shutdown_on_sigterm", "save"),
        ("logfile", "/tmp/valkey.log"),
        ("loglevel", "notice"),
        ("syslog_enabled", "yes"),
        ("crash_log_enabled", "yes"),
        ("set_proc_title", "yes"),
        ("requirepass_directive_count", 2),
        ("requirepass_raw_byte_count", 31),
        ("requirepass_canonical_base64url_unpadded", False),
        ("requirepass_dynamic_directive", "masterauth"),
    ),
)
def test_v2_valkey_profile_rejects_each_static_security_drift(
    tmp_path: Path, field_name: str, value: object
) -> None:
    policy = _valkey_policy(_fixture_isolated_bind_address(tmp_path))
    hostile = policy.model_copy(update={field_name: value})
    with pytest.raises(ValueError):
        ContainerBootstrapValkeyLaunchPolicyV2(**hostile.model_dump(mode="python"))


@pytest.mark.parametrize(
    "field_name",
    ("acl_denied_command_categories", "static_directive_order", "static_configuration_sha256"),
)
def test_v2_valkey_profile_rejects_acl_or_canonical_order_drift(
    tmp_path: Path, field_name: str
) -> None:
    policy = _valkey_policy(_fixture_isolated_bind_address(tmp_path))
    replacement: object
    if field_name == "acl_denied_command_categories":
        replacement = policy.acl_denied_command_categories[:-1]
    elif field_name == "static_directive_order":
        replacement = tuple(reversed(policy.static_directive_order))
    else:
        replacement = _hash("wrong-static-config")
    hostile = policy.model_copy(update={field_name: replacement})
    with pytest.raises(ValueError):
        ContainerBootstrapValkeyLaunchPolicyV2(**hostile.model_dump(mode="python"))


@pytest.mark.parametrize(
    ("field_name", "value"),
    (
        ("host_environment_allowed", True),
        ("env_file_allowed", True),
        ("docker_config_environment_allowed", True),
        ("inherited_environment_cleared_before_child_exec", False),
        ("inherited_environment_read_allowed", True),
        ("inherited_environment_pass_through_allowed", True),
        ("explicit_child_envp_required", False),
        ("global_setenv_for_target_values_allowed", True),
        ("wrapper_network_client_allowed", True),
        ("telemetry_environment_allowed", True),
        ("target_value_in_argv_allowed", True),
        ("target_value_in_file_allowed", True),
        ("target_value_in_logs_allowed", True),
    ),
)
def test_v2_child_environment_boundary_rejects_hostile_or_secret_carriers(
    field_name: str, value: object
) -> None:
    policy = _child_environment_policy("primary_infisical")
    hostile = policy.model_copy(update={field_name: value})
    with pytest.raises(ValueError):
        ContainerBootstrapEnvironmentConstructionPolicyV2(**hostile.model_dump(mode="python"))


@pytest.mark.parametrize("name", ("HOME", "REDIS_URL", "DOCKER_HOST", "ENV_FILE", "PATH"))
def test_v2_child_environment_boundary_rejects_hostile_static_names(name: str) -> None:
    image_environment = _static_environment()
    entry = ContainerBootstrapStaticEnvironmentEntryV2(name=name, value="safe")
    hostile = _child_environment_policy("primary_infisical", image_environment).model_copy(
        update={
            "static_entries": (entry,),
            "static_environment_sha256": hashlib.sha256(
                json.dumps((entry.rendered,), separators=(",", ":")).encode("utf-8")
            ).hexdigest(),
        }
    )
    with pytest.raises(ValueError, match="child environment"):
        ContainerBootstrapEnvironmentConstructionPolicyV2(**hostile.model_dump(mode="python"))


@dataclass(slots=True)
class _RawSocket:
    incoming: bytearray
    sent: bytearray = field(default_factory=bytearray)
    shutdowns: list[int] = field(default_factory=list)
    timeouts: list[float | None] = field(default_factory=list)

    def connect(self, address: str) -> None:
        raise AssertionError(address)

    def send(self, data: bytes | memoryview) -> int:
        rendered = bytes(data)
        self.sent.extend(rendered)
        return len(rendered)

    def recv(self, count: int) -> bytes:
        if not self.incoming:
            return b""
        value = bytes(self.incoming[:count])
        del self.incoming[:count]
        return value

    def settimeout(self, value: float | None) -> None:
        self.timeouts.append(value)

    def shutdown(self, how: int) -> None:
        self.shutdowns.append(how)

    def close(self) -> None:
        return None


@dataclass(slots=True)
class _HostileRawSocket(_RawSocket):
    fail_writes: bool = False

    def send(self, data: bytes | memoryview) -> int:
        if self.fail_writes:
            try:
                raise RuntimeError("secret-sentinel")
            except RuntimeError as cause:
                raise ContainerAttachV2Error("frame_write") from cause
        return super(_HostileRawSocket, self).send(data)


@dataclass(slots=True)
class _AdvancingRawSocket(_RawSocket):
    clock: _Clock = field(default_factory=_Clock)
    advance_on_recv: float = 0.0

    def recv(self, count: int) -> bytes:
        self.clock.now += self.advance_on_recv
        return super(_AdvancingRawSocket, self).recv(count)


def _raw_deadline(client: object, *, phase: str = "frame_payload") -> object:
    """Issue a test-only deadline from the adapter's own opaque session guard."""

    return cast(Any, client)._absolute_deadline._bounded(10, phase=phase)


def test_raw_unix_attach_uses_closed_upgrade_mux_and_actual_shutdown(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    authorization = _authorization(tmp_path, monkeypatch)
    payload = b"value-free-ack"
    wire = (
        b"HTTP/1.1 101 UPGRADED\r\nConnection: Upgrade\r\nUpgrade: tcp\r\n\r\n"
        + _MUX_HEADER.pack(1, len(payload))
        + payload
    )
    raw = _RawSocket(bytearray(wire))
    client = attach_v2._RawUnixDockerAttachV2ForTest._from_fake_socket_for_test(
        raw_socket=raw,
        authorization=authorization,
        deadline_clock=_Clock(),
    )
    assert b"logs=0" in raw.sent
    deadline = _raw_deadline(client)
    assert client.read(len(payload), deadline=deadline) == payload
    assert client.read(1, deadline=deadline) == b""
    assert (
        client.close_write(deadline=deadline)
        is attach_v2.ContainerAttachV2WriteCloseResult.HALF_CLOSED
    )
    assert raw.shutdowns == [socket.SHUT_WR]


def test_raw_unix_attach_rejects_stderr_and_never_echoes_payload(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    authorization = _authorization(tmp_path, monkeypatch)
    sentinel = b"secret-sentinel"
    wire = (
        b"HTTP/1.1 101 UPGRADED\r\nConnection: Upgrade\r\nUpgrade: tcp\r\n\r\n"
        + _MUX_HEADER.pack(2, len(sentinel))
        + sentinel
    )
    raw = _RawSocket(bytearray(wire))
    client = attach_v2._RawUnixDockerAttachV2ForTest._from_fake_socket_for_test(
        raw_socket=raw,
        authorization=authorization,
        deadline_clock=_Clock(),
    )
    deadline = _raw_deadline(client)
    with pytest.raises(ContainerAttachV2Error) as caught:
        client.read(1, deadline=deadline)
    assert sentinel.decode("ascii") not in str(caught.value)
    assert sentinel.decode("ascii") not in repr(caught.value)


def test_raw_unix_attach_rejects_duplicate_headers_and_zero_length_mux_frames(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    authorization = _authorization(tmp_path, monkeypatch)
    duplicate_header = _RawSocket(
        bytearray(
            b"HTTP/1.1 101 UPGRADED\r\nConnection: Upgrade\r\n"
            b"Connection: Upgrade\r\nUpgrade: tcp\r\n\r\n"
        )
    )
    with pytest.raises(ContainerAttachV2Error, match="attach_handshake"):
        attach_v2._RawUnixDockerAttachV2ForTest._from_fake_socket_for_test(
            raw_socket=duplicate_header,
            authorization=authorization,
            deadline_clock=_Clock(),
        )

    zero_frame = _RawSocket(
        bytearray(
            b"HTTP/1.1 101 UPGRADED\r\nConnection: Upgrade\r\nUpgrade: tcp\r\n\r\n"
            + _MUX_HEADER.pack(1, 0)
        )
    )
    client = attach_v2._RawUnixDockerAttachV2ForTest._from_fake_socket_for_test(
        raw_socket=zero_frame,
        authorization=authorization,
        deadline_clock=_Clock(),
    )
    with pytest.raises(ContainerAttachV2Error, match="frame_payload"):
        client.read(1, deadline=_raw_deadline(client))


def test_raw_unix_attach_enforces_its_own_absolute_and_idle_deadlines(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    authorization = _authorization(tmp_path, monkeypatch)
    handshake = b"HTTP/1.1 101 UPGRADED\r\nConnection: Upgrade\r\nUpgrade: tcp\r\n\r\n"
    frame = _MUX_HEADER.pack(1, 1) + b"x"
    clock = _Clock()
    raw = _AdvancingRawSocket(bytearray(handshake), clock=clock)
    client = attach_v2._RawUnixDockerAttachV2ForTest._from_fake_socket_for_test(
        raw_socket=raw, authorization=authorization, deadline_clock=clock
    )
    raw.incoming.extend(frame)
    raw.advance_on_recv = 11.0
    with pytest.raises(ContainerAttachV2Error, match="frame_payload"):
        client.read(1, deadline=_raw_deadline(client))

    clock = _Clock()
    raw = _RawSocket(bytearray(handshake))
    client = attach_v2._RawUnixDockerAttachV2ForTest._from_fake_socket_for_test(
        raw_socket=raw, authorization=authorization, deadline_clock=clock
    )
    raw.incoming.extend(frame)
    clock.now += 31.0
    with pytest.raises(ContainerAttachV2Error, match="frame_payload"):
        client.read(1, deadline=_raw_deadline(client))


def test_raw_unix_attach_rejects_deadlines_issued_by_another_session(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    authorization = _authorization(tmp_path, monkeypatch)
    raw = _RawSocket(
        bytearray(b"HTTP/1.1 101 UPGRADED\r\nConnection: Upgrade\r\nUpgrade: tcp\r\n\r\n")
    )
    client = attach_v2._RawUnixDockerAttachV2ForTest._from_fake_socket_for_test(
        raw_socket=raw, authorization=authorization, deadline_clock=_Clock()
    )
    foreign_deadline = attach_v2._deadline(
        attach_v2._MonotonicGuard(_Clock()), 10, phase="frame_payload"
    )
    with pytest.raises(ContainerAttachV2Error, match="frame_payload"):
        client.read(1, deadline=foreign_deadline)


def test_v2_contracts_keep_materialization_and_start_non_effectful() -> None:
    """The V2 contract cannot select a concrete materialization/start backend."""

    backend = NoMutationBackend()
    materialization_delivery = _ZeroizableDelivery()
    with pytest.raises(ExecutorDaemonError, match="backend_unavailable"):
        backend.materialize_and_start(cast(Any, object()), cast(Any, materialization_delivery))
    assert materialization_delivery.zeroized is True
    start_delivery = _ZeroizableDelivery()
    with pytest.raises(ExecutorDaemonError, match="backend_unavailable"):
        backend.start(cast(Any, object()), cast(Any, start_delivery))
    assert start_delivery.zeroized is True
    assert not hasattr(attach_v2, "materialize_and_start")
    assert not hasattr(attach_v2, "start_runtime")
