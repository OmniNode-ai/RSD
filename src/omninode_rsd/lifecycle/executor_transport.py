"""Bounded remote-executor transport contracts and macOS client boundary.

The module intentionally contains no Docker, database, network-service, or
runtime mutation backend.  It validates signed value-free session metadata,
constructs one fixed Secure Shell invocation, and streams a tightly bounded
set of Keychain values only through an injected binary-frame writer.  Raw
material is never represented by a public mapping or returned from this API.
"""

from __future__ import annotations

import base64
import binascii
import hashlib
import hmac
import json
import os
import re
import select
import stat
import struct
import subprocess
import sys
import time
from collections.abc import Callable, Iterator, Mapping
from contextlib import contextmanager, suppress
from dataclasses import dataclass, field
from datetime import UTC, datetime, timedelta
from enum import StrEnum
from pathlib import Path
from typing import Final, Literal, Protocol, cast, runtime_checkable

from cryptography.exceptions import InvalidSignature
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PublicKey
from pydantic import BaseModel, ConfigDict, Field, ValidationError, field_validator, model_validator

from omninode_rsd.lifecycle.authorization import (
    RemoteExecutorSessionLease,
    RemoteExecutorSessionProvenance,
    SecretDeliveryProvenance,
    SecretMaterialLease,
    SecretMaterialProvenance,
    TrustedEd25519SignerV1,
)
from omninode_rsd.lifecycle.infisical_disposable import (
    AllocationExecutorReceiptV1,
    AllocationIntentV2,
    ExecutorInstallationPolicyV1,
    ExecutorInstallationReceiptV1,
    MaterializationExecutorReceiptV1,
    SecretCapabilityPolicyV1,
    SecretDeliveryReceiptV1,
    SecretDeliveryRequestV1,
    SecretDeliverySlotReceiptV1,
    SecretDeliverySlotV1,
    SecretHandlingPolicyV1,
    SSHConnectionPolicyV1,
    StartRuntimeExecutorReceiptV2,
    allocation_executor_receipt_message,
    canonical_sha256,
    materialization_executor_receipt_message,
    start_runtime_executor_receipt_message,
)
from omninode_rsd.lifecycle.provider_crypto import (
    KeychainEd25519Signer,
    ProviderCryptoError,
    ProviderFingerprintAttestationV2,
    ProviderMaterialArtifactPaths,
    ProviderMaterialFormat,
    ProviderMaterialPolicyV2,
    ProviderMaterialPurpose,
    SignerGenesisV1,
    executor_allocation_metadata_message,
    executor_transport_metadata_message,
    load_verified_provider_material_bundle,
    verify_signer_genesis,
)
from omninode_rsd.lifecycle.transport import (
    CanonicalFrameWriter,
    TransportError,
    read_raw_transport,
)

_SHA256: Final = r"^[0-9a-f]{64}$"
_IDENTIFIER: Final = r"^[A-Za-z][A-Za-z0-9_.-]{0,127}$"
_UUID: Final = r"^[0-9a-f]{8}-[0-9a-f]{4}-[1-5][0-9a-f]{3}-[89ab][0-9a-f]{3}-[0-9a-f]{12}$"
_TIMESTAMP: Final = re.compile(
    r"[0-9]{4}-[0-9]{2}-[0-9]{2}T[0-9]{2}:[0-9]{2}:[0-9]{2}(?:[.][0-9]{1,6})?Z\Z"
)
_POLICY_DOMAIN: Final = b"omninode-rsd.executor-transport-policy.ed25519.v2\x00"
_HELLO_DOMAIN: Final = b"omninode-rsd.executor-hello.ed25519.v2\x00"
_RECEIPT_DOMAIN: Final = b"omninode-rsd.executor-transport-receipt.ed25519.v2\x00"
_ALLOCATION_REQUEST_DOMAIN: Final = b"omninode-rsd.executor-allocation-request.ed25519.v1\x00"
_ALLOCATION_RECEIPT_DOMAIN: Final = b"omninode-rsd.executor-allocation-receipt.ed25519.v1\x00"
_REMOTE_EFFECT_WITNESS_DOMAIN: Final = b"omninode-rsd.remote-effect-witness.ed25519.v1\x00"
_ENGINE_OPERATION_PLAN_DOMAIN: Final = b"omninode-rsd.executor-engine-operation-plan.v1\x00"
_INSTALLATION_POLICY_DOMAIN: Final = b"omninode-rsd.executor-installation-policy.ed25519.v1\x00"
_INSTALLATION_RECEIPT_DOMAIN: Final = b"omninode-rsd.executor-installation-receipt.ed25519.v1\x00"
_SECRET_CAPABILITY_POLICY_DOMAIN: Final = b"omninode-rsd.secret-capability-policy.ed25519.v1\x00"
_SECRET_HANDLING_POLICY_DOMAIN: Final = b"omninode-rsd.secret-handling-policy.ed25519.v1\x00"
_MAX_FILE_BYTES: Final = 131_072
_MAX_SESSION_SECONDS: Final = 60
_ED25519_PUBLIC_KEY_BLOB_BYTES: Final = 51
_ED25519_PUBLIC_KEY_BASE64_BYTES: Final = 68
_EXPECTED_PURPOSES: Final[tuple[str, str, str, str, str]] = (
    "encryption_key",
    "auth_secret",
    "primary_valkey_password",
    "restore_valkey_password",
    "postgres_application_password",
)
_MATERIAL_LEASE_CAPABILITY: Final = object()
_VERIFIED_ARTIFACTS_CAPABILITY: Final = object()
_TRANSPORT_TEST_CAPABILITY: Final = object()
_BASE64_ALPHABET: Final = b"ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/"
_BASE64URL_ALPHABET: Final = b"ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789-_"
_TRANSPORT_POLICY_ARTIFACT: Final = "executor-transport-policy.json"
_INSTALLATION_POLICY_ARTIFACT: Final = "executor-installation-policy.json"
_INSTALLATION_RECEIPT_ARTIFACT: Final = "executor-installation-receipt.json"
_SIGNER_GENESIS_ARTIFACT: Final = "signer-genesis.json"


class ExecutorTransportError(RuntimeError):
    """Value-redacted failure at the remote executor transport boundary."""

    def __init__(self, phase: str) -> None:
        self.phase = phase
        super().__init__(f"executor transport failed at phase: {phase}")


class _Model(BaseModel):
    model_config = ConfigDict(extra="forbid", frozen=True, strict=True, validate_default=True)


class AnySigner(Protocol):
    """Narrow public-key verifier shape used for policy signatures."""

    @property
    def key_id(self) -> str: ...

    def key(self) -> Ed25519PublicKey: ...


@dataclass(frozen=True, slots=True)
class VerifiedExecutorTransportArtifactsV2:
    """Canonical, signature-verified inputs required by a live transport path.

    This is intentionally an opaque construction boundary: process launch,
    daemon session handling, and Keychain delivery cannot be configured from
    caller-constructed policy models alone.
    """

    policy: ExecutorTransportPolicyV2
    signer_genesis: SignerGenesisV1
    installation_policy: ExecutorInstallationPolicyV1
    installation_receipt: ExecutorInstallationReceiptV1
    _capability: object | None = field(default=None, repr=False, compare=False)

    def __post_init__(self) -> None:
        if self._capability is not _VERIFIED_ARTIFACTS_CAPABILITY:
            raise ExecutorTransportError("transport_artifacts")

    @property
    def attestation_public_key_base64(self) -> str:
        return self.installation_policy.executor.attestation_public_key_base64

    @property
    def attestation_key_id(self) -> str:
        return self.installation_policy.executor.attestation_key_id


def _digest(value: bytes | bytearray | memoryview) -> str:
    return hashlib.sha256(value).hexdigest()


def _canonical_json(value: object) -> bytes:
    try:
        return json.dumps(
            value,
            allow_nan=False,
            ensure_ascii=True,
            sort_keys=True,
            separators=(",", ":"),
        ).encode("ascii")
    except (TypeError, ValueError):
        raise ExecutorTransportError("canonical_encoding") from None


def _timestamp(value: str) -> datetime:
    if type(value) is not str or _TIMESTAMP.fullmatch(value) is None:
        raise ValueError("timestamp is invalid")
    try:
        parsed = datetime.fromisoformat(value.removesuffix("Z") + "+00:00")
    except ValueError:
        raise ValueError("timestamp is invalid") from None
    if parsed.tzinfo is None or parsed.utcoffset() is None:
        raise ValueError("timestamp is invalid")
    return parsed.astimezone(UTC)


def _system_utc_clock() -> datetime:
    """The production transport clock; it is patched only inside unit tests."""

    return datetime.now(UTC)


def _canonical_base64(value: str) -> bytes:
    if type(value) is not str:
        raise ValueError("base64 is invalid")
    try:
        decoded = base64.b64decode(value, validate=True)
    except (binascii.Error, ValueError):
        raise ValueError("base64 is invalid") from None
    if base64.b64encode(decoded).decode("ascii") != value:
        raise ValueError("base64 is invalid")
    return decoded


def _strict_model(value: object, model_type: type[_Model], *, phase: str) -> _Model:
    """Canonicalize and reject model-construct/model-copy type drift."""

    if type(value) is not model_type:
        raise ExecutorTransportError(phase)
    model = value
    try:
        encoded = _canonical_json(model.model_dump(mode="json", warnings="error"))
        canonical = model_type.model_validate_json(encoded)
    except (ValidationError, ValueError, TypeError):
        raise ExecutorTransportError(phase) from None
    if type(canonical) is not model_type or not _same_model_shape(model, canonical):
        raise ExecutorTransportError(phase)
    return canonical


def _same_model_shape(original: object, canonical: object) -> bool:
    if type(original) is not type(canonical):
        return False
    if isinstance(original, BaseModel):
        if not isinstance(canonical, BaseModel):
            return False
        return all(
            _same_model_shape(getattr(original, name), getattr(canonical, name))
            for name in original.__class__.model_fields
        )
    if type(original) is tuple:
        right = cast(tuple[object, ...], canonical)
        return len(original) == len(right) and all(
            _same_model_shape(left, item) for left, item in zip(original, right, strict=True)
        )
    return True


def _path(value: str, *, field: str) -> str:
    if type(value) is not str or not value or len(value) > 4096:
        raise ValueError(f"{field} is invalid")
    path = Path(value)
    if not path.is_absolute() or os.path.normpath(value) != value:
        raise ValueError(f"{field} is invalid")
    return value


class ExecutorTransportMessageKind(StrEnum):
    """Wire operation kinds admitted by the remote daemon."""

    HELLO = "hello"
    ALLOCATION = "allocation"
    MATERIALIZE = "materialize"
    START = "start"


class SecureShellIdentityReferenceV1(_Model):
    """Owner-only file references used by the fixed Secure Shell launcher."""

    key_path: str
    public_key_path: str
    public_key_fingerprint_sha256: str = Field(pattern=_SHA256)

    @field_validator("key_path", "public_key_path")
    @classmethod
    def canonical_path(cls, value: str) -> str:
        return _path(value, field="identity path")

    @model_validator(mode="after")
    def distinct_paths(self) -> SecureShellIdentityReferenceV1:
        if self.key_path == self.public_key_path:
            raise ValueError("identity reference is invalid")
        return self


@dataclass(frozen=True, slots=True)
class ExecutorTransportArtifactPathsV2:
    """Fixed owner-only non-secret artifact names for a transport session."""

    root: Path

    def __post_init__(self) -> None:
        # ``pathlib.Path`` is a platform factory (``PosixPath`` on macOS and
        # Linux), so an exact-type comparison would reject every ordinary
        # production path.  The subsequent descriptor-relative checks carry
        # the security boundary; this guard only admits concrete Path values.
        if not isinstance(self.root, Path) or not self.root.is_absolute():
            raise ExecutorTransportError("transport_artifacts")

    @staticmethod
    def transport_policy_name() -> str:
        return _TRANSPORT_POLICY_ARTIFACT

    @staticmethod
    def installation_policy_name() -> str:
        return _INSTALLATION_POLICY_ARTIFACT

    @staticmethod
    def installation_receipt_name() -> str:
        return _INSTALLATION_RECEIPT_ARTIFACT

    @staticmethod
    def signer_genesis_name() -> str:
        return _SIGNER_GENESIS_ARTIFACT


class ExecutorTransportPolicyV2(_Model):
    """Signed local-to-remote transport and memory-safety contract."""

    schema_version: Literal["rsd.executor-transport-policy.v2"]
    allocation_intent_sha256: str = Field(pattern=_SHA256)
    executor_installation_policy_sha256: str = Field(pattern=_SHA256)
    executor_installation_receipt_sha256: str = Field(pattern=_SHA256)
    executor_id: str = Field(pattern=_IDENTIFIER)
    endpoint: str = Field(pattern=r"^[A-Za-z0-9][A-Za-z0-9.-]{0,252}$")
    endpoint_sha256: str = Field(pattern=_SHA256)
    ssh_executable_path: str
    ssh_executable_sha256: str = Field(pattern=_SHA256)
    known_hosts_path: str
    known_hosts_sha256: str = Field(pattern=_SHA256)
    identity: SecureShellIdentityReferenceV1
    ssh_policy: SSHConnectionPolicyV1
    daemon_socket_path: str
    daemon_socket_policy_sha256: str = Field(pattern=_SHA256)
    force_command_user_uid: int = Field(ge=1, le=2_147_483_647)
    daemon_socket_group: str = Field(pattern=_IDENTIFIER)
    daemon_socket_group_gid: int = Field(ge=1, le=2_147_483_647)
    daemon_socket_mode: Literal[432]
    host_key_fingerprint_sha256: str = Field(pattern=_SHA256)
    package_sha256: str = Field(pattern=_SHA256)
    template_bundle_sha256: str = Field(pattern=_SHA256)
    core_dump_disabled: Literal[True]
    swap_protection_required: Literal[True]
    mlock_required: Literal[True]
    max_session_seconds: int = Field(ge=1, le=_MAX_SESSION_SECONDS)
    created_at: str
    expires_at: str
    signer_key_id: str = Field(pattern=_IDENTIFIER)
    signature_base64: str = Field(min_length=4, max_length=256)

    @field_validator("ssh_executable_path", "known_hosts_path", "daemon_socket_path")
    @classmethod
    def canonical_paths(cls, value: str) -> str:
        return _path(value, field="transport path")

    @field_validator("created_at", "expires_at")
    @classmethod
    def canonical_timestamp(cls, value: str) -> str:
        _timestamp(value)
        return value

    @model_validator(mode="after")
    def bounded_policy(self) -> ExecutorTransportPolicyV2:
        commitments = (
            self.executor_installation_policy_sha256,
            self.executor_installation_receipt_sha256,
            self.endpoint_sha256,
            self.ssh_executable_sha256,
            self.known_hosts_sha256,
            self.identity.public_key_fingerprint_sha256,
            self.daemon_socket_policy_sha256,
            self.host_key_fingerprint_sha256,
            self.package_sha256,
            self.template_bundle_sha256,
        )
        if (
            self.endpoint_sha256 != _digest(self.endpoint.encode("ascii"))
            or len(set(commitments)) != len(commitments)
            or self.daemon_socket_group == "root"
            or _timestamp(self.expires_at) <= _timestamp(self.created_at)
            or len(_canonical_base64(self.signature_base64)) != 64
        ):
            raise ValueError("executor transport policy is invalid")
        return self

    def policy_sha256(self) -> str:
        return _digest(_canonical_json(self.model_dump(mode="json")))


class ExecutorHelloV2(_Model):
    """Signed server greeting that establishes one nonmultiplexed channel."""

    schema_version: Literal["rsd.executor-hello.v2"]
    allocation_intent_sha256: str = Field(pattern=_SHA256)
    client_nonce: str = Field(pattern=_UUID)
    server_nonce: str = Field(pattern=_UUID)
    session_id: str = Field(pattern=_UUID)
    request_id: str = Field(pattern=_UUID)
    executor_id: str = Field(pattern=_IDENTIFIER)
    executor_policy_sha256: str = Field(pattern=_SHA256)
    package_sha256: str = Field(pattern=_SHA256)
    template_bundle_sha256: str = Field(pattern=_SHA256)
    chunk_count: Literal[0]
    expires_at: str
    signer_key_id: str = Field(pattern=_IDENTIFIER)
    signature_base64: str = Field(min_length=4, max_length=256)

    @field_validator("expires_at")
    @classmethod
    def canonical_expiry(cls, value: str) -> str:
        _timestamp(value)
        return value

    @model_validator(mode="after")
    def complete_hello(self) -> ExecutorHelloV2:
        if len(_canonical_base64(self.signature_base64)) != 64:
            raise ValueError("executor hello is invalid")
        return self


class ExecutorClientHelloV2(_Model):
    """Value-free first frame that lets a daemon bind its signed greeting."""

    schema_version: Literal["rsd.executor-client-hello.v2"]
    allocation_intent_sha256: str = Field(pattern=_SHA256)
    client_nonce: str = Field(pattern=_UUID)
    session_id: str = Field(pattern=_UUID)
    request_id: str = Field(pattern=_UUID)
    executor_id: str = Field(pattern=_IDENTIFIER)
    executor_policy_sha256: str = Field(pattern=_SHA256)
    chunk_count: Literal[0]

    @model_validator(mode="after")
    def fixed_hello(self) -> ExecutorClientHelloV2:
        return self


class ExecutorEngineOperationKindV1(StrEnum):
    """Closed Engine/PostgreSQL steps a future backend may checkpoint."""

    NETWORK_CREATE = "network_create"
    NETWORK_INSPECT = "network_inspect"
    VOLUME_CREATE = "volume_create"
    VOLUME_INSPECT = "volume_inspect"
    POSTGRES_PREPARED_CONTROL = "postgres_prepared_control"
    CONTAINER_CREATE = "container_create"
    CONTAINER_INSPECT = "container_inspect"
    CONTAINER_START = "container_start"
    CONTAINER_ATTACH = "container_attach"
    POSTGRES_SCRAM_VERIFIER_INSTALL = "postgres_scram_verifier_install"


class ExecutorEngineOperationTargetV1(StrEnum):
    """Value-free target identities for the closed checkpoint plan."""

    PRIMARY_NETWORK = "primary_network"
    RESTORE_NETWORK = "restore_network"
    PRIMARY_CACHE_VOLUME = "primary_cache_volume"
    RESTORE_CACHE_VOLUME = "restore_cache_volume"
    ALLOCATION_POSTGRES = "allocation_postgres"
    APPLICATION_POSTGRES = "application_postgres"
    PRIMARY_INFISICAL = "primary_infisical"
    PRIMARY_VALKEY = "primary_valkey"
    RESTORE_INFISICAL = "restore_infisical"
    RESTORE_VALKEY = "restore_valkey"


class ExecutorEngineOperationStepV1(_Model):
    """One fixed, non-secret Engine/PostgreSQL checkpoint step."""

    operation_kind: ExecutorEngineOperationKindV1
    target: ExecutorEngineOperationTargetV1


_RUNTIME_COMPONENT_TARGETS: Final[tuple[ExecutorEngineOperationTargetV1, ...]] = (
    ExecutorEngineOperationTargetV1.PRIMARY_INFISICAL,
    ExecutorEngineOperationTargetV1.PRIMARY_VALKEY,
    ExecutorEngineOperationTargetV1.RESTORE_INFISICAL,
    ExecutorEngineOperationTargetV1.RESTORE_VALKEY,
)


def _expected_engine_operation_steps(
    operation_scope: str,
) -> tuple[ExecutorEngineOperationStepV1, ...]:
    """Return the complete immutable operation sequence for one effect scope."""

    step = ExecutorEngineOperationStepV1
    kind = ExecutorEngineOperationKindV1
    target = ExecutorEngineOperationTargetV1
    if operation_scope == "allocate_isolated_empty_resources_v2":
        return (
            step(operation_kind=kind.NETWORK_CREATE, target=target.PRIMARY_NETWORK),
            step(operation_kind=kind.NETWORK_INSPECT, target=target.PRIMARY_NETWORK),
            step(operation_kind=kind.NETWORK_CREATE, target=target.RESTORE_NETWORK),
            step(operation_kind=kind.NETWORK_INSPECT, target=target.RESTORE_NETWORK),
            step(operation_kind=kind.VOLUME_CREATE, target=target.PRIMARY_CACHE_VOLUME),
            step(operation_kind=kind.VOLUME_INSPECT, target=target.PRIMARY_CACHE_VOLUME),
            step(operation_kind=kind.VOLUME_CREATE, target=target.RESTORE_CACHE_VOLUME),
            step(operation_kind=kind.VOLUME_INSPECT, target=target.RESTORE_CACHE_VOLUME),
            step(
                operation_kind=kind.POSTGRES_PREPARED_CONTROL,
                target=target.ALLOCATION_POSTGRES,
            ),
        )
    if operation_scope == "materialize_and_start_runtime_v1":
        steps: list[ExecutorEngineOperationStepV1] = [
            step(
                operation_kind=kind.POSTGRES_SCRAM_VERIFIER_INSTALL,
                target=target.APPLICATION_POSTGRES,
            )
        ]
        for component in _RUNTIME_COMPONENT_TARGETS:
            steps.extend(
                (
                    step(operation_kind=kind.CONTAINER_CREATE, target=component),
                    step(operation_kind=kind.CONTAINER_INSPECT, target=component),
                    step(operation_kind=kind.CONTAINER_START, target=component),
                    step(operation_kind=kind.CONTAINER_INSPECT, target=component),
                    step(operation_kind=kind.CONTAINER_ATTACH, target=component),
                    step(operation_kind=kind.CONTAINER_INSPECT, target=component),
                )
            )
        return tuple(steps)
    if operation_scope == "start_runtime_v2":
        steps = []
        for component in _RUNTIME_COMPONENT_TARGETS:
            steps.extend(
                (
                    step(operation_kind=kind.CONTAINER_INSPECT, target=component),
                    step(operation_kind=kind.CONTAINER_START, target=component),
                    step(operation_kind=kind.CONTAINER_INSPECT, target=component),
                    step(operation_kind=kind.CONTAINER_ATTACH, target=component),
                    step(operation_kind=kind.CONTAINER_INSPECT, target=component),
                )
            )
        return tuple(steps)
    raise ValueError("engine operation scope is invalid")


class ExecutorEngineOperationPlanV1(_Model):
    """Signed, exact checkpoint sequence for one remote effect operation."""

    schema_version: Literal["rsd.executor-engine-operation-plan.v1"]
    operation_scope: Literal[
        "allocate_isolated_empty_resources_v2",
        "materialize_and_start_runtime_v1",
        "start_runtime_v2",
    ]
    operation_id: str = Field(pattern=_UUID)
    operations: tuple[ExecutorEngineOperationStepV1, ...]

    @field_validator("operations", mode="before")
    @classmethod
    def declared_operations(cls, value: object) -> tuple[object, ...]:
        if type(value) not in {tuple, list}:
            raise ValueError("engine operation plan is invalid")
        return tuple(cast(tuple[object, ...] | list[object], value))

    @model_validator(mode="after")
    def exact_closed_sequence(self) -> ExecutorEngineOperationPlanV1:
        if self.operations != _expected_engine_operation_steps(self.operation_scope):
            raise ValueError("engine operation plan is invalid")
        return self

    def plan_sha256(self) -> str:
        """Return the domain-separated exact sequence commitment."""

        return _digest(
            _ENGINE_OPERATION_PLAN_DOMAIN + _canonical_json(self.model_dump(mode="json"))
        )


def executor_engine_operation_plan_v1(
    *,
    operation_scope: Literal[
        "allocate_isolated_empty_resources_v2",
        "materialize_and_start_runtime_v1",
        "start_runtime_v2",
    ],
    operation_id: str,
) -> ExecutorEngineOperationPlanV1:
    """Construct the only plan permitted for one signed effect operation."""

    try:
        return ExecutorEngineOperationPlanV1(
            schema_version="rsd.executor-engine-operation-plan.v1",
            operation_scope=operation_scope,
            operation_id=operation_id,
            operations=_expected_engine_operation_steps(operation_scope),
        )
    except (TypeError, ValidationError, ValueError):
        raise ExecutorTransportError("engine_operation_plan") from None


def executor_engine_operation_plan_sha256(
    *,
    operation_scope: Literal[
        "allocate_isolated_empty_resources_v2",
        "materialize_and_start_runtime_v1",
        "start_runtime_v2",
    ],
    operation_id: str,
) -> str:
    """Return the exact signed checkpoint-plan commitment for an operation."""

    return executor_engine_operation_plan_v1(
        operation_scope=operation_scope,
        operation_id=operation_id,
    ).plan_sha256()


class ExecutorTransportRequestV2(_Model):
    """Signed value-free Start or Materialize metadata sent before any chunk."""

    schema_version: Literal["rsd.executor-transport-request.v2"]
    message_kind: Literal["materialize", "start"]
    operation_scope: Literal["materialize_and_start_runtime_v1", "start_runtime_v2"]
    allocation_intent_sha256: str = Field(pattern=_SHA256)
    operation_id: str = Field(pattern=_UUID)
    predecessor_materialization_operation_id: str | None = Field(default=None, pattern=_UUID)
    journal_uuid: str = Field(pattern=_UUID)
    idempotency_key: str = Field(pattern=_SHA256)
    effect_intent_sha256: str = Field(pattern=_SHA256)
    predecessor_attestation_sha256: str = Field(pattern=_SHA256)
    docker_engine_control_policy_sha256: str = Field(pattern=_SHA256)
    postgres_prepared_control_policy_sha256: str = Field(pattern=_SHA256)
    host_fingerprint_sha256: str = Field(pattern=_SHA256)
    engine_fingerprint_sha256: str = Field(pattern=_SHA256)
    effect_plan_sha256: str = Field(pattern=_SHA256)
    artifact_chain_sha256: str = Field(pattern=_SHA256)
    authorization_witness: RemoteEffectAuthorizationWitnessV1
    request_id: str = Field(pattern=_UUID)
    client_nonce: str = Field(pattern=_UUID)
    server_nonce: str = Field(pattern=_UUID)
    session_id: str = Field(pattern=_UUID)
    request_nonce_sha256: str = Field(pattern=_SHA256)
    channel_binding_sha256: str = Field(pattern=_SHA256)
    session_binding_sha256: str = Field(pattern=_SHA256)
    host_key_fingerprint_sha256: str = Field(pattern=_SHA256)
    executor_id: str = Field(pattern=_IDENTIFIER)
    executor_policy_sha256: str = Field(pattern=_SHA256)
    package_sha256: str = Field(pattern=_SHA256)
    template_bundle_sha256: str = Field(pattern=_SHA256)
    installation_receipt_sha256: str = Field(pattern=_SHA256)
    expires_at: str
    chunk_count: Literal[5]
    slots: tuple[
        SecretDeliverySlotV1,
        SecretDeliverySlotV1,
        SecretDeliverySlotV1,
        SecretDeliverySlotV1,
        SecretDeliverySlotV1,
    ]
    signer_key_id: str = Field(pattern=_IDENTIFIER)
    signature_base64: str = Field(min_length=4, max_length=256)

    @field_validator("expires_at")
    @classmethod
    def canonical_expiry(cls, value: str) -> str:
        _timestamp(value)
        return value

    @field_validator("slots", mode="before")
    @classmethod
    def exact_slots(cls, value: object) -> tuple[object, ...]:
        if type(value) not in {tuple, list}:
            raise ValueError("transport slot descriptors are invalid")
        return tuple(cast(tuple[object, ...] | list[object], value))

    @model_validator(mode="after")
    def complete_signed_request(self) -> ExecutorTransportRequestV2:
        required_kind = {
            "materialize_and_start_runtime_v1": "materialize",
            "start_runtime_v2": "start",
        }[self.operation_scope]
        bindings = (
            self.idempotency_key,
            self.effect_intent_sha256,
            self.predecessor_attestation_sha256,
            self.docker_engine_control_policy_sha256,
            self.postgres_prepared_control_policy_sha256,
            self.host_fingerprint_sha256,
            self.engine_fingerprint_sha256,
            self.effect_plan_sha256,
            self.artifact_chain_sha256,
            self.request_nonce_sha256,
            self.channel_binding_sha256,
            self.session_binding_sha256,
            self.host_key_fingerprint_sha256,
            self.executor_policy_sha256,
            self.package_sha256,
            self.template_bundle_sha256,
            self.installation_receipt_sha256,
        )
        if (
            self.message_kind != required_kind
            or (
                self.operation_scope == "materialize_and_start_runtime_v1"
                and self.predecessor_materialization_operation_id is not None
            )
            or (
                self.operation_scope == "start_runtime_v2"
                and self.predecessor_materialization_operation_id is None
            )
            or tuple(slot.purpose for slot in self.slots) != _EXPECTED_PURPOSES
            or len(set(bindings)) != len(bindings)
            or self.authorization_witness.operation_scope != self.operation_scope
            or self.authorization_witness.operation_id != self.operation_id
            or self.authorization_witness.allocation_intent_sha256 != self.allocation_intent_sha256
            or self.authorization_witness.journal_uuid != self.journal_uuid
            or self.authorization_witness.idempotency_key != self.idempotency_key
            or self.authorization_witness.effect_intent_sha256 != self.effect_intent_sha256
            or self.authorization_witness.predecessor_attestation_sha256
            != self.predecessor_attestation_sha256
            or self.authorization_witness.predecessor_operation_id
            != self.predecessor_materialization_operation_id
            or self.authorization_witness.docker_engine_control_policy_sha256
            != self.docker_engine_control_policy_sha256
            or self.authorization_witness.postgres_prepared_control_policy_sha256
            != self.postgres_prepared_control_policy_sha256
            or self.authorization_witness.host_fingerprint_sha256 != self.host_fingerprint_sha256
            or self.authorization_witness.engine_fingerprint_sha256
            != self.engine_fingerprint_sha256
            or self.authorization_witness.effect_plan_sha256 != self.effect_plan_sha256
            or self.authorization_witness.artifact_chain_sha256 != self.artifact_chain_sha256
            or _timestamp(self.expires_at) > _timestamp(self.authorization_witness.expires_at)
            or len(_canonical_base64(self.signature_base64)) != 64
        ):
            raise ValueError("executor transport request is invalid")
        return self

    def metadata_sha256(self) -> str:
        return _digest(_canonical_json(self.model_dump(mode="json", exclude={"signature_base64"})))


class RemoteEffectAuthorizationWitnessV1(_Model):
    """Trusted-signer proof that the external replay claim already succeeded.

    The daemon treats this as an authorization witness, not as a bearer grant:
    it is bound to one exact operation, signed policy/plan chain, and the
    non-secret hash of the externally durable tombstone claim.  It contains
    neither raw Engine data nor a secret value.
    """

    schema_version: Literal["rsd.remote-effect-authorization-witness.v1"]
    operation_scope: Literal[
        "allocate_isolated_empty_resources_v2",
        "materialize_and_start_runtime_v1",
        "start_runtime_v2",
    ]
    operation_id: str = Field(pattern=_UUID)
    allocation_intent_sha256: str = Field(pattern=_SHA256)
    external_replay_tombstone_sha256: str = Field(pattern=_SHA256)
    replay_policy_sha256: str = Field(pattern=_SHA256)
    executor_policy_sha256: str = Field(pattern=_SHA256)
    journal_uuid: str = Field(pattern=_UUID)
    idempotency_key: str = Field(pattern=_SHA256)
    effect_intent_sha256: str | None = Field(default=None, pattern=_SHA256)
    predecessor_attestation_sha256: str | None = Field(default=None, pattern=_SHA256)
    predecessor_operation_id: str | None = Field(default=None, pattern=_UUID)
    docker_engine_control_policy_sha256: str = Field(pattern=_SHA256)
    postgres_prepared_control_policy_sha256: str = Field(pattern=_SHA256)
    host_fingerprint_sha256: str = Field(pattern=_SHA256)
    engine_fingerprint_sha256: str = Field(pattern=_SHA256)
    effect_plan_sha256: str = Field(pattern=_SHA256)
    engine_operation_plan_sha256: str = Field(pattern=_SHA256)
    artifact_chain_sha256: str = Field(pattern=_SHA256)
    issued_at: str
    expires_at: str
    signer_key_id: str = Field(pattern=_IDENTIFIER)
    signature_base64: str = Field(min_length=4, max_length=256)

    @field_validator("issued_at", "expires_at")
    @classmethod
    def canonical_time(cls, value: str) -> str:
        _timestamp(value)
        return value

    @model_validator(mode="after")
    def exact_one_shot_witness(self) -> RemoteEffectAuthorizationWitnessV1:
        bindings = (
            self.external_replay_tombstone_sha256,
            self.replay_policy_sha256,
            self.executor_policy_sha256,
            self.idempotency_key,
            self.docker_engine_control_policy_sha256,
            self.postgres_prepared_control_policy_sha256,
            self.host_fingerprint_sha256,
            self.engine_fingerprint_sha256,
            self.effect_plan_sha256,
            self.engine_operation_plan_sha256,
            self.artifact_chain_sha256,
        )
        runtime_scope = self.operation_scope != "allocate_isolated_empty_resources_v2"
        has_runtime_bindings = (
            self.effect_intent_sha256 is not None
            and self.predecessor_attestation_sha256 is not None
        )
        needs_predecessor_operation = self.operation_scope == "start_runtime_v2"
        if (
            len(set(bindings)) != len(bindings)
            or _timestamp(self.expires_at) <= _timestamp(self.issued_at)
            or len(_canonical_base64(self.signature_base64)) != 64
            or runtime_scope != has_runtime_bindings
            or (self.predecessor_operation_id is not None) != needs_predecessor_operation
            or self.engine_operation_plan_sha256
            != executor_engine_operation_plan_sha256(
                operation_scope=self.operation_scope,
                operation_id=self.operation_id,
            )
        ):
            raise ValueError("remote effect witness is invalid")
        return self


# ``ExecutorTransportRequestV2`` intentionally refers to this witness before
# its declaration so the allocation and runtime envelopes retain independent
# wire models.  Rebuild only after the closed witness model is available.
ExecutorTransportRequestV2.model_rebuild()


class ExecutorAllocationTransportRequestV1(_Model):
    """A distinct zero-secret allocation request; it cannot carry slots."""

    schema_version: Literal["rsd.executor-allocation-request.v1"]
    message_kind: Literal["allocation"]
    operation_scope: Literal["allocate_isolated_empty_resources_v2"]
    allocation_intent_sha256: str = Field(pattern=_SHA256)
    allocation_operation_id: str = Field(pattern=_UUID)
    idempotency_key: str = Field(pattern=_SHA256)
    journal_uuid: str = Field(pattern=_UUID)
    request_id: str = Field(pattern=_UUID)
    client_nonce: str = Field(pattern=_UUID)
    server_nonce: str = Field(pattern=_UUID)
    session_id: str = Field(pattern=_UUID)
    request_nonce_sha256: str = Field(pattern=_SHA256)
    channel_binding_sha256: str = Field(pattern=_SHA256)
    session_binding_sha256: str = Field(pattern=_SHA256)
    host_key_fingerprint_sha256: str = Field(pattern=_SHA256)
    executor_id: str = Field(pattern=_IDENTIFIER)
    executor_policy_sha256: str = Field(pattern=_SHA256)
    package_sha256: str = Field(pattern=_SHA256)
    template_bundle_sha256: str = Field(pattern=_SHA256)
    installation_receipt_sha256: str = Field(pattern=_SHA256)
    docker_engine_control_policy_sha256: str = Field(pattern=_SHA256)
    postgres_prepared_control_policy_sha256: str = Field(pattern=_SHA256)
    host_fingerprint_sha256: str = Field(pattern=_SHA256)
    engine_fingerprint_sha256: str = Field(pattern=_SHA256)
    allocation_plan_sha256: str = Field(pattern=_SHA256)
    artifact_chain_sha256: str = Field(pattern=_SHA256)
    authorization_witness: RemoteEffectAuthorizationWitnessV1
    expires_at: str
    chunk_count: Literal[0]
    signer_key_id: str = Field(pattern=_IDENTIFIER)
    signature_base64: str = Field(min_length=4, max_length=256)

    @field_validator("expires_at")
    @classmethod
    def canonical_expiry(cls, value: str) -> str:
        _timestamp(value)
        return value

    @model_validator(mode="after")
    def zero_secret_request(self) -> ExecutorAllocationTransportRequestV1:
        bindings = (
            self.request_nonce_sha256,
            self.channel_binding_sha256,
            self.session_binding_sha256,
            self.idempotency_key,
            self.host_key_fingerprint_sha256,
            self.executor_policy_sha256,
            self.package_sha256,
            self.template_bundle_sha256,
            self.installation_receipt_sha256,
            self.docker_engine_control_policy_sha256,
            self.postgres_prepared_control_policy_sha256,
            self.host_fingerprint_sha256,
            self.engine_fingerprint_sha256,
            self.allocation_plan_sha256,
            self.artifact_chain_sha256,
        )
        witness = self.authorization_witness
        if (
            len(set(bindings)) != len(bindings)
            or witness.operation_scope != self.operation_scope
            or witness.operation_id != self.allocation_operation_id
            or witness.allocation_intent_sha256 != self.allocation_intent_sha256
            or witness.executor_policy_sha256 != self.executor_policy_sha256
            or witness.journal_uuid != self.journal_uuid
            or witness.idempotency_key != self.idempotency_key
            or witness.docker_engine_control_policy_sha256
            != self.docker_engine_control_policy_sha256
            or witness.postgres_prepared_control_policy_sha256
            != self.postgres_prepared_control_policy_sha256
            or witness.host_fingerprint_sha256 != self.host_fingerprint_sha256
            or witness.engine_fingerprint_sha256 != self.engine_fingerprint_sha256
            or witness.effect_plan_sha256 != self.allocation_plan_sha256
            or witness.artifact_chain_sha256 != self.artifact_chain_sha256
            or _timestamp(self.expires_at) > _timestamp(witness.expires_at)
            or len(_canonical_base64(self.signature_base64)) != 64
        ):
            raise ValueError("executor allocation request is invalid")
        return self

    def metadata_sha256(self) -> str:
        return _digest(_canonical_json(self.model_dump(mode="json", exclude={"signature_base64"})))


class ExecutorAllocationTransportReceiptV1(_Model):
    """Daemon-attested typed allocation evidence, never raw Engine JSON."""

    schema_version: Literal["rsd.executor-allocation-receipt.v1"]
    operation_scope: Literal["allocate_isolated_empty_resources_v2"]
    allocation_operation_id: str = Field(pattern=_UUID)
    request_id: str = Field(pattern=_UUID)
    journal_uuid: str = Field(pattern=_UUID)
    client_nonce: str = Field(pattern=_UUID)
    server_nonce: str = Field(pattern=_UUID)
    session_id: str = Field(pattern=_UUID)
    executor_id: str = Field(pattern=_IDENTIFIER)
    executor_policy_sha256: str = Field(pattern=_SHA256)
    allocation_request_sha256: str = Field(pattern=_SHA256)
    allocation_executor_receipt_sha256: str = Field(pattern=_SHA256)
    allocation_executor_receipt: AllocationExecutorReceiptV1
    status: Literal["allocated"]
    completed_at: str
    chunk_count: Literal[0]
    signer_key_id: str = Field(pattern=_IDENTIFIER)
    signature_base64: str = Field(min_length=4, max_length=256)

    @field_validator("completed_at")
    @classmethod
    def canonical_completed(cls, value: str) -> str:
        _timestamp(value)
        return value

    @model_validator(mode="after")
    def exact_typed_receipt(self) -> ExecutorAllocationTransportReceiptV1:
        if (
            self.allocation_executor_receipt_sha256
            != canonical_sha256(self.allocation_executor_receipt)
            or self.allocation_executor_receipt.allocation_operation_id
            != self.allocation_operation_id
            or len(_canonical_base64(self.signature_base64)) != 64
        ):
            raise ValueError("executor allocation receipt is invalid")
        return self


def remote_effect_authorization_witness_message(
    witness: RemoteEffectAuthorizationWitnessV1,
) -> bytes:
    """Build the exact trusted-signer witness preimage."""

    canonical = cast(
        RemoteEffectAuthorizationWitnessV1,
        _strict_model(witness, RemoteEffectAuthorizationWitnessV1, phase="remote_effect_witness"),
    )
    return _REMOTE_EFFECT_WITNESS_DOMAIN + _canonical_json(
        canonical.model_dump(mode="json", exclude={"signature_base64"})
    )


def executor_allocation_transport_request_message(
    request: ExecutorAllocationTransportRequestV1,
) -> bytes:
    """Build the client-signer preimage for one zero-secret allocation request."""

    canonical = cast(
        ExecutorAllocationTransportRequestV1,
        _strict_model(request, ExecutorAllocationTransportRequestV1, phase="allocation_request"),
    )
    return _ALLOCATION_REQUEST_DOMAIN + _canonical_json(
        canonical.model_dump(mode="json", exclude={"signature_base64"})
    )


def executor_allocation_transport_receipt_message(
    receipt: ExecutorAllocationTransportReceiptV1,
) -> bytes:
    """Build the executor-attestation preimage for filtered allocation evidence."""

    canonical = cast(
        ExecutorAllocationTransportReceiptV1,
        _strict_model(receipt, ExecutorAllocationTransportReceiptV1, phase="allocation_receipt"),
    )
    return _ALLOCATION_RECEIPT_DOMAIN + _canonical_json(
        canonical.model_dump(mode="json", exclude={"signature_base64"})
    )


def sign_executor_allocation_transport_request(
    request: ExecutorAllocationTransportRequestV1,
    *,
    signer: KeychainEd25519Signer,
) -> ExecutorAllocationTransportRequestV1:
    """Use the narrow Keychain capability for one zero-secret allocation.

    The public signer is never asked to sign Docker, PostgreSQL, or secret
    bytes directly.  It signs only the canonical metadata commitment under a
    separate allocation domain.
    """

    request = cast(
        ExecutorAllocationTransportRequestV1,
        _strict_model(request, ExecutorAllocationTransportRequestV1, phase="allocation_request"),
    )
    if type(signer) is not KeychainEd25519Signer or request.signer_key_id != signer.key_id:
        raise ExecutorTransportError("allocation_request_signature")
    try:
        signature = signer.sign_executor_allocation_metadata(
            allocation_intent_sha256=request.allocation_intent_sha256,
            allocation_operation_id=request.allocation_operation_id,
            metadata_sha256=request.metadata_sha256(),
        )
        encoded = base64.b64encode(signature).decode("ascii")
    except Exception:
        raise ExecutorTransportError("allocation_request_signature") from None
    try:
        return request.model_copy(update={"signature_base64": encoded})
    except ValidationError:
        raise ExecutorTransportError("allocation_request_signature") from None


def executor_transport_policy_message(policy: ExecutorTransportPolicyV2) -> bytes:
    """Canonical domain-separated bytes for a signed transport policy."""

    canonical = cast(
        ExecutorTransportPolicyV2,
        _strict_model(policy, ExecutorTransportPolicyV2, phase="transport_policy"),
    )
    return _POLICY_DOMAIN + _canonical_json(
        canonical.model_dump(mode="json", exclude={"signature_base64"})
    )


def executor_hello_message(hello: ExecutorHelloV2) -> bytes:
    """Canonical domain-separated bytes for a daemon-attested greeting."""

    canonical = cast(ExecutorHelloV2, _strict_model(hello, ExecutorHelloV2, phase="hello"))
    return _HELLO_DOMAIN + _canonical_json(
        canonical.model_dump(mode="json", exclude={"signature_base64"})
    )


def verify_executor_transport_policy(
    policy: ExecutorTransportPolicyV2,
    *,
    signer: object,
    allocation_intent: AllocationIntentV2,
    installation_policy: ExecutorInstallationPolicyV1,
    installation_receipt: ExecutorInstallationReceiptV1,
) -> ExecutorTransportPolicyV2:
    """Verify policy signature, canonical shape, static chain, and UTC expiry."""

    policy = cast(
        ExecutorTransportPolicyV2,
        _strict_model(policy, ExecutorTransportPolicyV2, phase="transport_policy"),
    )
    if (
        type(allocation_intent) is not AllocationIntentV2
        or type(installation_policy) is not ExecutorInstallationPolicyV1
        or type(installation_receipt) is not ExecutorInstallationReceiptV1
        or not hasattr(signer, "key")
        or not hasattr(signer, "key_id")
    ):
        raise ExecutorTransportError("transport_policy")
    now = _system_utc_clock()
    try:
        typed_signer = cast(AnySigner, signer)
        signer_key_id = typed_signer.key_id
        key = typed_signer.key()
        if (
            type(signer_key_id) is not str
            or signer_key_id != policy.signer_key_id
            or _timestamp(policy.created_at) > now
            or _timestamp(policy.expires_at) <= now
            or policy.allocation_intent_sha256 != canonical_sha256(allocation_intent)
            or policy.executor_installation_policy_sha256 != canonical_sha256(installation_policy)
            or policy.executor_installation_receipt_sha256 != canonical_sha256(installation_receipt)
            or policy.executor_id != installation_policy.executor.executor_id
            or policy.ssh_policy != installation_policy.ssh
            or policy.package_sha256 != installation_policy.package_sha256
            or policy.template_bundle_sha256 != installation_policy.template_bundle_sha256
            or policy.daemon_socket_policy_sha256 != installation_policy.unix_socket_policy_sha256
            or policy.host_key_fingerprint_sha256
            != installation_policy.executor.host_fingerprint_sha256
        ):
            raise ValueError
        key.verify(
            _canonical_base64(policy.signature_base64),
            executor_transport_policy_message(policy),
        )
    except (InvalidSignature, ValueError, TypeError, binascii.Error, AttributeError):
        raise ExecutorTransportError("transport_policy") from None
    return policy


def _legacy_direct_message(domain: bytes, model: BaseModel) -> bytes:
    """Recreate the published V1 embedded-signature canonical preimage."""

    try:
        return domain + _canonical_json(model.model_dump(mode="json", exclude={"signature_base64"}))
    except (TypeError, ValueError):
        raise ExecutorTransportError("transport_artifacts") from None


def _verify_installation_artifacts(
    installation_policy: ExecutorInstallationPolicyV1,
    installation_receipt: ExecutorInstallationReceiptV1,
    *,
    signer: TrustedEd25519SignerV1,
    allocation_intent: AllocationIntentV2,
) -> tuple[ExecutorInstallationPolicyV1, ExecutorInstallationReceiptV1]:
    """Verify the pre-existing signed installation chain without a file lookup."""

    if (
        type(installation_policy) is not ExecutorInstallationPolicyV1
        or type(installation_receipt) is not ExecutorInstallationReceiptV1
        or type(signer) is not TrustedEd25519SignerV1
        or type(allocation_intent) is not AllocationIntentV2
    ):
        raise ExecutorTransportError("transport_artifacts")
    try:
        policy = ExecutorInstallationPolicyV1.model_validate_json(
            _canonical_json(installation_policy.model_dump(mode="json", warnings="error"))
        )
        receipt = ExecutorInstallationReceiptV1.model_validate_json(
            _canonical_json(installation_receipt.model_dump(mode="json", warnings="error"))
        )
        if policy != installation_policy or receipt != installation_receipt:
            raise ValueError
        if (
            policy.signer_key_id != signer.key_id
            or policy.allocation_intent_sha256 != canonical_sha256(allocation_intent)
        ):
            raise ValueError
        signer.key().verify(
            _canonical_base64(policy.signature_base64),
            _legacy_direct_message(_INSTALLATION_POLICY_DOMAIN, policy),
        )
        attestation_key = _canonical_base64(policy.executor.attestation_public_key_base64)
        if (
            len(attestation_key) != 32
            or _digest(attestation_key) != policy.executor.attestation_public_key_fingerprint_sha256
            or receipt.signer_key_id != policy.executor.attestation_key_id
            or receipt.allocation_intent_sha256 != canonical_sha256(allocation_intent)
            or receipt.executor_installation_policy_sha256 != canonical_sha256(policy)
            or receipt.executor_id != policy.executor.executor_id
            or receipt.host_fingerprint_sha256 != policy.allowed_host_fingerprint_sha256
            or receipt.engine_fingerprint_sha256 != policy.allowed_engine_fingerprint_sha256
            or receipt.package_sha256 != policy.package_sha256
            or receipt.executable_sha256 != policy.executable_sha256
            or receipt.template_bundle_sha256 != policy.template_bundle_sha256
            or receipt.systemd_unit_sha256 != policy.systemd_unit_sha256
            or receipt.unix_socket_policy_sha256 != policy.unix_socket_policy_sha256
            or receipt.ssh_policy_sha256 != canonical_sha256(policy.ssh)
            or receipt.attestation_public_key_fingerprint_sha256
            != policy.executor.attestation_public_key_fingerprint_sha256
            or receipt.monotonic_revision != policy.executor.monotonic_revision
        ):
            raise ValueError
        Ed25519PublicKey.from_public_bytes(attestation_key).verify(
            _canonical_base64(receipt.signature_base64),
            _legacy_direct_message(_INSTALLATION_RECEIPT_DOMAIN, receipt),
        )
    except (InvalidSignature, ValidationError, ValueError, TypeError, binascii.Error):
        raise ExecutorTransportError("transport_artifacts") from None
    return policy, receipt


def verify_executor_transport_artifacts(
    *,
    policy: ExecutorTransportPolicyV2,
    signer_genesis: SignerGenesisV1,
    installation_policy: ExecutorInstallationPolicyV1,
    installation_receipt: ExecutorInstallationReceiptV1,
    signer: TrustedEd25519SignerV1,
    issuer: TrustedEd25519SignerV1,
    allocation_intent: AllocationIntentV2,
) -> VerifiedExecutorTransportArtifactsV2:
    """Build the only verified-artifact input accepted by live transport APIs."""

    if (
        type(signer_genesis) is not SignerGenesisV1
        or type(signer) is not TrustedEd25519SignerV1
        or type(issuer) is not TrustedEd25519SignerV1
        or type(allocation_intent) is not AllocationIntentV2
    ):
        raise ExecutorTransportError("transport_artifacts")
    try:
        canonical_genesis = SignerGenesisV1.model_validate_json(
            _canonical_json(signer_genesis.model_dump(mode="json", warnings="error"))
        )
        if canonical_genesis != signer_genesis:
            raise ValueError
        verify_signer_genesis(canonical_genesis, issuer=issuer, allocation_intent=allocation_intent)
        canonical_policy, canonical_receipt = _verify_installation_artifacts(
            installation_policy,
            installation_receipt,
            signer=signer,
            allocation_intent=allocation_intent,
        )
        canonical_transport = verify_executor_transport_policy(
            policy,
            signer=signer,
            allocation_intent=allocation_intent,
            installation_policy=canonical_policy,
            installation_receipt=canonical_receipt,
        )
        if (
            canonical_transport.allocation_intent_sha256
            != canonical_genesis.allocation_intent_sha256
        ):
            raise ValueError
    except (ExecutorTransportError, ValidationError, ValueError, TypeError):
        raise ExecutorTransportError("transport_artifacts") from None
    return VerifiedExecutorTransportArtifactsV2(
        policy=canonical_transport,
        signer_genesis=canonical_genesis,
        installation_policy=canonical_policy,
        installation_receipt=canonical_receipt,
        _capability=_VERIFIED_ARTIFACTS_CAPABILITY,
    )


def _verified_executor_transport_artifacts_for_test(
    *,
    policy: ExecutorTransportPolicyV2,
    signer_genesis: SignerGenesisV1,
    installation_policy: ExecutorInstallationPolicyV1,
    installation_receipt: ExecutorInstallationReceiptV1,
) -> VerifiedExecutorTransportArtifactsV2:
    """Create an explicitly internal fixture only for offline unit tests.

    Production callers must use ``load_verified_executor_transport_artifacts``
    or ``verify_executor_transport_artifacts``.  This helper intentionally is
    not exported from the package surface, cannot read a provider, and cannot
    launch a session by itself.
    """

    return VerifiedExecutorTransportArtifactsV2(
        policy=policy,
        signer_genesis=signer_genesis,
        installation_policy=installation_policy,
        installation_receipt=installation_receipt,
        _capability=_VERIFIED_ARTIFACTS_CAPABILITY,
    )


def _load_canonical_transport_artifact(raw: bytes, model_type: type[BaseModel]) -> BaseModel:
    """Decode one persisted JSON artifact only if its bytes are canonical."""

    try:
        if type(raw) is not bytes or not raw or len(raw) > _MAX_FILE_BYTES:
            raise ValueError
        model = model_type.model_validate_json(raw)
        if _canonical_json(model.model_dump(mode="json", warnings="error")) != raw:
            raise ValueError
        return model
    except (ValidationError, ValueError, TypeError):
        raise ExecutorTransportError("transport_artifacts") from None


def load_verified_executor_transport_artifacts(
    paths: ExecutorTransportArtifactPathsV2,
    *,
    signer: TrustedEd25519SignerV1,
    issuer: TrustedEd25519SignerV1,
    allocation_intent: AllocationIntentV2,
) -> VerifiedExecutorTransportArtifactsV2:
    """Descriptor-load and verify all signed, non-secret transport inputs."""

    if type(paths) is not ExecutorTransportArtifactPathsV2:
        raise ExecutorTransportError("transport_artifacts")
    with _OwnerOnlyTransportArtifacts(paths) as reader:
        policy = cast(
            ExecutorTransportPolicyV2,
            _load_canonical_transport_artifact(
                reader.read(paths.transport_policy_name()), ExecutorTransportPolicyV2
            ),
        )
        installation_policy = cast(
            ExecutorInstallationPolicyV1,
            _load_canonical_transport_artifact(
                reader.read(paths.installation_policy_name()), ExecutorInstallationPolicyV1
            ),
        )
        installation_receipt = cast(
            ExecutorInstallationReceiptV1,
            _load_canonical_transport_artifact(
                reader.read(paths.installation_receipt_name()), ExecutorInstallationReceiptV1
            ),
        )
        genesis = cast(
            SignerGenesisV1,
            _load_canonical_transport_artifact(
                reader.read(paths.signer_genesis_name()), SignerGenesisV1
            ),
        )
        return verify_executor_transport_artifacts(
            policy=policy,
            signer_genesis=genesis,
            installation_policy=installation_policy,
            installation_receipt=installation_receipt,
            signer=signer,
            issuer=issuer,
            allocation_intent=allocation_intent,
        )


def _verify_secret_delivery_policies(
    capability_policy: SecretCapabilityPolicyV1,
    handling_policy: SecretHandlingPolicyV1,
    *,
    signer: TrustedEd25519SignerV1,
    artifacts: VerifiedExecutorTransportArtifactsV2,
    provider_identity_sha256: str,
) -> tuple[SecretCapabilityPolicyV1, SecretHandlingPolicyV1]:
    """Verify signed value-free policy chain before any Keychain lookup."""

    if (
        type(capability_policy) is not SecretCapabilityPolicyV1
        or type(handling_policy) is not SecretHandlingPolicyV1
        or type(signer) is not TrustedEd25519SignerV1
        or type(artifacts) is not VerifiedExecutorTransportArtifactsV2
        or re.fullmatch(_SHA256, provider_identity_sha256) is None
    ):
        raise ExecutorTransportError("material_lease")
    try:
        capability = SecretCapabilityPolicyV1.model_validate_json(
            _canonical_json(capability_policy.model_dump(mode="json", warnings="error"))
        )
        handling = SecretHandlingPolicyV1.model_validate_json(
            _canonical_json(handling_policy.model_dump(mode="json", warnings="error"))
        )
        if capability != capability_policy or handling != handling_policy:
            raise ValueError
        if capability.signer_key_id != signer.key_id or handling.signer_key_id != signer.key_id:
            raise ValueError
        signer.key().verify(
            _canonical_base64(capability.signature_base64),
            _legacy_direct_message(_SECRET_CAPABILITY_POLICY_DOMAIN, capability),
        )
        signer.key().verify(
            _canonical_base64(handling.signature_base64),
            _legacy_direct_message(_SECRET_HANDLING_POLICY_DOMAIN, handling),
        )
        executor_identity = canonical_sha256(artifacts.installation_policy.executor)
        if (
            capability.source_commit != artifacts.installation_policy.source_commit
            or handling.source_commit != artifacts.installation_policy.source_commit
            or capability.executor_identity_sha256 != executor_identity
            or handling.executor_identity_sha256 != executor_identity
            or capability.provider_identity_sha256 != provider_identity_sha256
            or handling.provider_identity_sha256 != provider_identity_sha256
            or handling.allocation_intent_sha256 != artifacts.policy.allocation_intent_sha256
            or handling.capability_fingerprint_sha256 != capability.capability_fingerprint_sha256
            or capability.secret_handling_policy_sha256 != canonical_sha256(handling)
        ):
            raise ValueError
    except (InvalidSignature, ValidationError, ValueError, TypeError, binascii.Error):
        raise ExecutorTransportError("material_lease") from None
    return capability, handling


class ExecutorTransportReceiptV2(_Model):
    """Redacted daemon result with typed executor evidence, never a hash bridge."""

    schema_version: Literal["rsd.executor-transport-receipt.v2"]
    operation_scope: Literal["materialize_and_start_runtime_v1", "start_runtime_v2"]
    operation_id: str = Field(pattern=_UUID)
    request_id: str = Field(pattern=_UUID)
    journal_uuid: str = Field(pattern=_UUID)
    client_nonce: str = Field(pattern=_UUID)
    server_nonce: str = Field(pattern=_UUID)
    session_id: str = Field(pattern=_UUID)
    request_nonce_sha256: str = Field(pattern=_SHA256)
    channel_binding_sha256: str = Field(pattern=_SHA256)
    session_binding_sha256: str = Field(pattern=_SHA256)
    executor_id: str = Field(pattern=_IDENTIFIER)
    executor_policy_sha256: str = Field(pattern=_SHA256)
    package_sha256: str = Field(pattern=_SHA256)
    template_bundle_sha256: str = Field(pattern=_SHA256)
    delivery_binding_sha256: str = Field(pattern=_SHA256)
    authorization_witness_sha256: str = Field(pattern=_SHA256)
    executor_receipt_sha256: str = Field(pattern=_SHA256)
    executor_receipt: MaterializationExecutorReceiptV1 | StartRuntimeExecutorReceiptV2
    status: Literal["materialized", "started"]
    completed_at: str
    chunk_count: Literal[0]
    signer_key_id: str = Field(pattern=_IDENTIFIER)
    signature_base64: str = Field(min_length=4, max_length=256)

    @field_validator("completed_at")
    @classmethod
    def canonical_completed(cls, value: str) -> str:
        _timestamp(value)
        return value

    @model_validator(mode="after")
    def canonical_receipt(self) -> ExecutorTransportReceiptV2:
        inner = self.executor_receipt
        if self.operation_scope == "materialize_and_start_runtime_v1":
            if (
                type(inner) is not MaterializationExecutorReceiptV1
                or inner.operation_scope != self.operation_scope
                or inner.operation_id != self.operation_id
                or inner.executor_id != self.executor_id
                or inner.channel_binding_sha256 != self.channel_binding_sha256
                or inner.session_binding_sha256 != self.session_binding_sha256
            ):
                raise ValueError("executor transport receipt is invalid")
        elif (
            type(inner) is not StartRuntimeExecutorReceiptV2
            or inner.operation_scope != self.operation_scope
            or inner.start_operation_id != self.operation_id
            or inner.executor_id != self.executor_id
            or inner.channel_binding_sha256 != self.channel_binding_sha256
            or inner.session_binding_sha256 != self.session_binding_sha256
        ):
            raise ValueError("executor transport receipt is invalid")
        if (
            self.executor_receipt_sha256 != canonical_sha256(inner)
            or len(_canonical_base64(self.signature_base64)) != 64
        ):
            raise ValueError("executor transport receipt is invalid")
        return self


def executor_transport_receipt_message(receipt: ExecutorTransportReceiptV2) -> bytes:
    """Canonical domain-separated bytes for a daemon transport receipt."""

    canonical = cast(
        ExecutorTransportReceiptV2,
        _strict_model(receipt, ExecutorTransportReceiptV2, phase="transport_receipt"),
    )
    return _RECEIPT_DOMAIN + _canonical_json(
        canonical.model_dump(mode="json", exclude={"signature_base64"})
    )


def transport_delivery_binding_sha256(request: ExecutorTransportRequestV2) -> str:
    """Stable value-free delivery commitment shared by client and daemon."""

    request = cast(
        ExecutorTransportRequestV2,
        _strict_model(request, ExecutorTransportRequestV2, phase="transport_request"),
    )
    return _digest(
        _canonical_json(
            {
                "operation_id": request.operation_id,
                "request_id": request.request_id,
                "request_nonce_sha256": request.request_nonce_sha256,
                "session_binding_sha256": request.session_binding_sha256,
                "slots": [slot.model_dump(mode="json") for slot in request.slots],
            }
        )
    )


def sign_executor_transport_request(
    request: ExecutorTransportRequestV2,
    *,
    signer: KeychainEd25519Signer,
) -> ExecutorTransportRequestV2:
    """Use the bounded Keychain signing capability for exact request metadata."""

    request = cast(
        ExecutorTransportRequestV2,
        _strict_model(request, ExecutorTransportRequestV2, phase="transport_request"),
    )
    if type(signer) is not KeychainEd25519Signer or request.signer_key_id != signer.key_id:
        raise ExecutorTransportError("transport_request_signature")
    try:
        signature = signer.sign_executor_transport_metadata(
            allocation_intent_sha256=request.allocation_intent_sha256,
            operation_scope=request.operation_scope,
            operation_id=request.operation_id,
            metadata_sha256=request.metadata_sha256(),
        )
        encoded = base64.b64encode(signature).decode("ascii")
    except Exception:
        raise ExecutorTransportError("transport_request_signature") from None
    try:
        return request.model_copy(update={"signature_base64": encoded})
    except ValidationError:
        raise ExecutorTransportError("transport_request_signature") from None


def verify_executor_transport_request(
    request: ExecutorTransportRequestV2,
    *,
    signer_genesis: SignerGenesisV1,
    hello: ExecutorHelloV2,
    policy: ExecutorTransportPolicyV2,
) -> ExecutorTransportRequestV2:
    """Verify client signature and every hello/policy/session binding."""

    request = cast(
        ExecutorTransportRequestV2,
        _strict_model(request, ExecutorTransportRequestV2, phase="transport_request"),
    )
    hello = cast(ExecutorHelloV2, _strict_model(hello, ExecutorHelloV2, phase="hello"))
    policy = cast(
        ExecutorTransportPolicyV2,
        _strict_model(policy, ExecutorTransportPolicyV2, phase="transport_policy"),
    )
    if type(signer_genesis) is not SignerGenesisV1:
        raise ExecutorTransportError("transport_request_signature")
    witness = verify_remote_effect_authorization_witness(
        request.authorization_witness,
        signer_genesis=signer_genesis,
    )
    now = _system_utc_clock()
    try:
        public_key = _canonical_base64(signer_genesis.public_key_base64)
        if (
            len(public_key) != 32
            or _digest(public_key) != signer_genesis.public_key_fingerprint_sha256
            or request.signer_key_id != signer_genesis.key_id
            or request.allocation_intent_sha256 != signer_genesis.allocation_intent_sha256
            or request.allocation_intent_sha256 != hello.allocation_intent_sha256
            or request.executor_id != hello.executor_id
            or request.executor_id != policy.executor_id
            or request.server_nonce != hello.server_nonce
            or request.client_nonce != hello.client_nonce
            or request.session_id != hello.session_id
            or request.request_id != hello.request_id
            or request.executor_policy_sha256 != hello.executor_policy_sha256
            or request.executor_policy_sha256 != policy.policy_sha256()
            or request.package_sha256 != hello.package_sha256
            or request.package_sha256 != policy.package_sha256
            or request.template_bundle_sha256 != hello.template_bundle_sha256
            or request.template_bundle_sha256 != policy.template_bundle_sha256
            or request.host_key_fingerprint_sha256 != policy.host_key_fingerprint_sha256
            or request.installation_receipt_sha256 != policy.executor_installation_receipt_sha256
            or request.authorization_witness != witness
            or witness.operation_scope != request.operation_scope
            or witness.operation_id != request.operation_id
            or witness.journal_uuid != request.journal_uuid
            or witness.idempotency_key != request.idempotency_key
            or witness.effect_intent_sha256 != request.effect_intent_sha256
            or witness.predecessor_attestation_sha256 != request.predecessor_attestation_sha256
            or witness.predecessor_operation_id != request.predecessor_materialization_operation_id
            or witness.docker_engine_control_policy_sha256
            != request.docker_engine_control_policy_sha256
            or witness.postgres_prepared_control_policy_sha256
            != request.postgres_prepared_control_policy_sha256
            or witness.host_fingerprint_sha256 != request.host_fingerprint_sha256
            or witness.engine_fingerprint_sha256 != request.engine_fingerprint_sha256
            or witness.effect_plan_sha256 != request.effect_plan_sha256
            or witness.artifact_chain_sha256 != request.artifact_chain_sha256
            # The client must not be able to select a historical clock or an
            # unbounded future authorization.  ``expires_at`` is an expiry,
            # not a completion timestamp: it must still be live and fit in
            # the signed, one-shot session window.
            or _timestamp(request.expires_at) <= now
            or _timestamp(request.expires_at) > now + timedelta(seconds=policy.max_session_seconds)
            or _timestamp(witness.expires_at) > now + timedelta(seconds=policy.max_session_seconds)
        ):
            raise ValueError
        Ed25519PublicKey.from_public_bytes(public_key).verify(
            _canonical_base64(request.signature_base64),
            executor_transport_metadata_message(
                allocation_intent_sha256=request.allocation_intent_sha256,
                operation_scope=request.operation_scope,
                operation_id=request.operation_id,
                metadata_sha256=request.metadata_sha256(),
            ),
        )
    except (InvalidSignature, ValueError, TypeError, binascii.Error):
        raise ExecutorTransportError("transport_request_signature") from None
    return request


def verify_remote_effect_authorization_witness(
    witness: RemoteEffectAuthorizationWitnessV1,
    *,
    signer_genesis: SignerGenesisV1,
) -> RemoteEffectAuthorizationWitnessV1:
    """Verify the durable-replay witness before a daemon accepts an effect."""

    witness = cast(
        RemoteEffectAuthorizationWitnessV1,
        _strict_model(witness, RemoteEffectAuthorizationWitnessV1, phase="remote_effect_witness"),
    )
    if type(signer_genesis) is not SignerGenesisV1:
        raise ExecutorTransportError("remote_effect_witness")
    now = _system_utc_clock()
    try:
        public_key = _canonical_base64(signer_genesis.public_key_base64)
        if (
            len(public_key) != 32
            or _digest(public_key) != signer_genesis.public_key_fingerprint_sha256
            or witness.signer_key_id != signer_genesis.key_id
            or witness.allocation_intent_sha256 != signer_genesis.allocation_intent_sha256
            or _timestamp(witness.issued_at) > now
            or _timestamp(witness.expires_at) <= now
        ):
            raise ValueError
        Ed25519PublicKey.from_public_bytes(public_key).verify(
            _canonical_base64(witness.signature_base64),
            remote_effect_authorization_witness_message(witness),
        )
    except (InvalidSignature, ValueError, TypeError, binascii.Error):
        raise ExecutorTransportError("remote_effect_witness") from None
    return witness


def verify_executor_allocation_transport_request(
    request: ExecutorAllocationTransportRequestV1,
    *,
    signer_genesis: SignerGenesisV1,
    hello: ExecutorHelloV2,
    policy: ExecutorTransportPolicyV2,
) -> ExecutorAllocationTransportRequestV1:
    """Verify zero-chunk allocation metadata and its replay witness together."""

    request = cast(
        ExecutorAllocationTransportRequestV1,
        _strict_model(request, ExecutorAllocationTransportRequestV1, phase="allocation_request"),
    )
    hello = cast(ExecutorHelloV2, _strict_model(hello, ExecutorHelloV2, phase="hello"))
    policy = cast(
        ExecutorTransportPolicyV2,
        _strict_model(policy, ExecutorTransportPolicyV2, phase="transport_policy"),
    )
    witness = verify_remote_effect_authorization_witness(
        request.authorization_witness, signer_genesis=signer_genesis
    )
    now = _system_utc_clock()
    try:
        public_key = _canonical_base64(signer_genesis.public_key_base64)
        if (
            len(public_key) != 32
            or _digest(public_key) != signer_genesis.public_key_fingerprint_sha256
            or request.signer_key_id != signer_genesis.key_id
            or request.allocation_intent_sha256 != signer_genesis.allocation_intent_sha256
            or request.allocation_intent_sha256 != hello.allocation_intent_sha256
            or request.executor_id != hello.executor_id
            or request.executor_id != policy.executor_id
            or request.server_nonce != hello.server_nonce
            or request.client_nonce != hello.client_nonce
            or request.session_id != hello.session_id
            or request.request_id != hello.request_id
            or request.executor_policy_sha256 != hello.executor_policy_sha256
            or request.executor_policy_sha256 != policy.policy_sha256()
            or request.package_sha256 != hello.package_sha256
            or request.package_sha256 != policy.package_sha256
            or request.template_bundle_sha256 != hello.template_bundle_sha256
            or request.template_bundle_sha256 != policy.template_bundle_sha256
            or request.host_key_fingerprint_sha256 != policy.host_key_fingerprint_sha256
            or request.installation_receipt_sha256 != policy.executor_installation_receipt_sha256
            or request.authorization_witness != witness
            or witness.operation_scope != request.operation_scope
            or witness.operation_id != request.allocation_operation_id
            or witness.journal_uuid != request.journal_uuid
            or witness.idempotency_key != request.idempotency_key
            or witness.docker_engine_control_policy_sha256
            != request.docker_engine_control_policy_sha256
            or witness.postgres_prepared_control_policy_sha256
            != request.postgres_prepared_control_policy_sha256
            or witness.host_fingerprint_sha256 != request.host_fingerprint_sha256
            or witness.engine_fingerprint_sha256 != request.engine_fingerprint_sha256
            or witness.effect_plan_sha256 != request.allocation_plan_sha256
            or witness.artifact_chain_sha256 != request.artifact_chain_sha256
            or _timestamp(request.expires_at) <= now
            or _timestamp(request.expires_at) > now + timedelta(seconds=policy.max_session_seconds)
            or _timestamp(witness.expires_at) > now + timedelta(seconds=policy.max_session_seconds)
        ):
            raise ValueError
        Ed25519PublicKey.from_public_bytes(public_key).verify(
            _canonical_base64(request.signature_base64),
            executor_allocation_metadata_message(
                allocation_intent_sha256=request.allocation_intent_sha256,
                allocation_operation_id=request.allocation_operation_id,
                metadata_sha256=request.metadata_sha256(),
            ),
        )
    except (InvalidSignature, ValueError, TypeError, binascii.Error):
        raise ExecutorTransportError("allocation_request_signature") from None
    return request


def verify_executor_allocation_transport_receipt(
    receipt: ExecutorAllocationTransportReceiptV1,
    *,
    request: ExecutorAllocationTransportRequestV1,
    policy: ExecutorTransportPolicyV2,
    attestation_public_key_base64: str,
    attestation_key_id: str,
) -> ExecutorAllocationTransportReceiptV1:
    """Verify typed filtered allocation evidence against its one request."""

    receipt = cast(
        ExecutorAllocationTransportReceiptV1,
        _strict_model(receipt, ExecutorAllocationTransportReceiptV1, phase="allocation_receipt"),
    )
    request = cast(
        ExecutorAllocationTransportRequestV1,
        _strict_model(request, ExecutorAllocationTransportRequestV1, phase="allocation_request"),
    )
    policy = cast(
        ExecutorTransportPolicyV2,
        _strict_model(policy, ExecutorTransportPolicyV2, phase="transport_policy"),
    )
    try:
        public_key = _canonical_base64(attestation_public_key_base64)
        if (
            len(public_key) != 32
            or receipt.signer_key_id != attestation_key_id
            or receipt.allocation_operation_id != request.allocation_operation_id
            or receipt.request_id != request.request_id
            or receipt.journal_uuid != request.journal_uuid
            or receipt.client_nonce != request.client_nonce
            or receipt.server_nonce != request.server_nonce
            or receipt.session_id != request.session_id
            or receipt.executor_id != policy.executor_id
            or receipt.executor_policy_sha256 != policy.policy_sha256()
            or receipt.allocation_request_sha256 != request.metadata_sha256()
            or receipt.allocation_executor_receipt.operation_scope != request.operation_scope
            or receipt.allocation_executor_receipt.allocation_intent_sha256
            != request.allocation_intent_sha256
            or receipt.allocation_executor_receipt.idempotency_key != request.idempotency_key
            or receipt.allocation_executor_receipt.signer_key_id != attestation_key_id
            or receipt.allocation_executor_receipt.executor_id != request.executor_id
            or receipt.allocation_executor_receipt.engine_control_policy_sha256
            != request.docker_engine_control_policy_sha256
            or receipt.allocation_executor_receipt.postgres_prepared_control_policy_sha256
            != request.postgres_prepared_control_policy_sha256
            or receipt.allocation_executor_receipt.host_fingerprint_sha256
            != request.host_fingerprint_sha256
            or receipt.allocation_executor_receipt.engine.engine_fingerprint_sha256
            != request.engine_fingerprint_sha256
            or _timestamp(receipt.completed_at) > _system_utc_clock()
            or _timestamp(receipt.allocation_executor_receipt.completed_at) > _system_utc_clock()
        ):
            raise ValueError
        Ed25519PublicKey.from_public_bytes(public_key).verify(
            _canonical_base64(receipt.allocation_executor_receipt.signature_base64),
            allocation_executor_receipt_message(receipt.allocation_executor_receipt),
        )
        Ed25519PublicKey.from_public_bytes(public_key).verify(
            _canonical_base64(receipt.signature_base64),
            executor_allocation_transport_receipt_message(receipt),
        )
    except (InvalidSignature, ValueError, TypeError, binascii.Error):
        raise ExecutorTransportError("allocation_receipt") from None
    return receipt


def verify_executor_hello(
    hello: ExecutorHelloV2,
    *,
    policy: ExecutorTransportPolicyV2,
    attestation_public_key_base64: str,
    attestation_key_id: str,
) -> ExecutorHelloV2:
    """Verify one daemon greeting against the pinned executor attestation key."""

    hello = cast(ExecutorHelloV2, _strict_model(hello, ExecutorHelloV2, phase="hello"))
    policy = cast(
        ExecutorTransportPolicyV2,
        _strict_model(policy, ExecutorTransportPolicyV2, phase="transport_policy"),
    )
    now = _system_utc_clock()
    try:
        public_key = _canonical_base64(attestation_public_key_base64)
        if (
            len(public_key) != 32
            or hello.signer_key_id != attestation_key_id
            or hello.allocation_intent_sha256 != policy.allocation_intent_sha256
            or hello.executor_id != policy.executor_id
            or hello.executor_policy_sha256 != policy.policy_sha256()
            or hello.package_sha256 != policy.package_sha256
            or hello.template_bundle_sha256 != policy.template_bundle_sha256
            or _timestamp(hello.expires_at) <= now
            or _timestamp(hello.expires_at) > now + timedelta(seconds=policy.max_session_seconds)
        ):
            raise ValueError
        Ed25519PublicKey.from_public_bytes(public_key).verify(
            _canonical_base64(hello.signature_base64), executor_hello_message(hello)
        )
    except (InvalidSignature, ValueError, TypeError, binascii.Error):
        raise ExecutorTransportError("hello_signature") from None
    return hello


def verify_executor_transport_receipt(
    receipt: ExecutorTransportReceiptV2,
    *,
    request: ExecutorTransportRequestV2,
    policy: ExecutorTransportPolicyV2,
    attestation_public_key_base64: str,
    attestation_key_id: str,
) -> ExecutorTransportReceiptV2:
    """Verify a redacted terminal receipt against one signed request."""

    receipt = cast(
        ExecutorTransportReceiptV2,
        _strict_model(receipt, ExecutorTransportReceiptV2, phase="transport_receipt"),
    )
    request = cast(
        ExecutorTransportRequestV2,
        _strict_model(request, ExecutorTransportRequestV2, phase="transport_request"),
    )
    policy = cast(
        ExecutorTransportPolicyV2,
        _strict_model(policy, ExecutorTransportPolicyV2, phase="transport_policy"),
    )
    try:
        public_key = _canonical_base64(attestation_public_key_base64)
        expected_status = {
            "materialize_and_start_runtime_v1": "materialized",
            "start_runtime_v2": "started",
        }[request.operation_scope]
        if (
            len(public_key) != 32
            or receipt.signer_key_id != attestation_key_id
            or receipt.operation_scope != request.operation_scope
            or receipt.operation_id != request.operation_id
            or receipt.request_id != request.request_id
            or receipt.journal_uuid != request.journal_uuid
            or receipt.client_nonce != request.client_nonce
            or receipt.server_nonce != request.server_nonce
            or receipt.session_id != request.session_id
            or receipt.request_nonce_sha256 != request.request_nonce_sha256
            or receipt.channel_binding_sha256 != request.channel_binding_sha256
            or receipt.session_binding_sha256 != request.session_binding_sha256
            or receipt.executor_id != policy.executor_id
            or receipt.executor_policy_sha256 != policy.policy_sha256()
            or receipt.package_sha256 != policy.package_sha256
            or receipt.template_bundle_sha256 != policy.template_bundle_sha256
            or receipt.delivery_binding_sha256 != transport_delivery_binding_sha256(request)
            or receipt.authorization_witness_sha256
            != canonical_sha256(request.authorization_witness)
            or receipt.status != expected_status
            or receipt.executor_receipt.signer_key_id != attestation_key_id
            or _timestamp(receipt.completed_at) > _system_utc_clock()
        ):
            raise ValueError
        if request.operation_scope == "materialize_and_start_runtime_v1":
            if type(receipt.executor_receipt) is not MaterializationExecutorReceiptV1:
                raise ValueError
            if (
                receipt.executor_receipt.installation_receipt_sha256
                != request.installation_receipt_sha256
                or receipt.executor_receipt.idempotency_key != request.idempotency_key
                or receipt.executor_receipt.materialization_intent_sha256
                != request.effect_intent_sha256
                or receipt.executor_receipt.observed_allocation_attestation_sha256
                != request.predecessor_attestation_sha256
                or receipt.executor_receipt.docker_engine_control_policy_sha256
                != request.docker_engine_control_policy_sha256
                or receipt.executor_receipt.host_fingerprint_sha256
                != request.host_fingerprint_sha256
                or receipt.executor_receipt.engine_fingerprint_sha256
                != request.engine_fingerprint_sha256
                or _timestamp(receipt.executor_receipt.completed_at) > _system_utc_clock()
            ):
                raise ValueError
            inner_message = materialization_executor_receipt_message(receipt.executor_receipt)
        else:
            if type(receipt.executor_receipt) is not StartRuntimeExecutorReceiptV2:
                raise ValueError
            if (
                receipt.executor_receipt.installation_receipt_sha256
                != request.installation_receipt_sha256
                or receipt.executor_receipt.idempotency_key != request.idempotency_key
                or receipt.executor_receipt.start_runtime_intent_sha256
                != request.effect_intent_sha256
                or receipt.executor_receipt.request_nonce_sha256 != request.request_nonce_sha256
                or receipt.executor_receipt.host_fingerprint_sha256
                != request.host_fingerprint_sha256
                or receipt.executor_receipt.engine_fingerprint_sha256
                != request.engine_fingerprint_sha256
                or _timestamp(receipt.executor_receipt.completed_at) > _system_utc_clock()
            ):
                raise ValueError
            inner_message = start_runtime_executor_receipt_message(receipt.executor_receipt)
        Ed25519PublicKey.from_public_bytes(public_key).verify(
            _canonical_base64(receipt.executor_receipt.signature_base64), inner_message
        )
        Ed25519PublicKey.from_public_bytes(public_key).verify(
            _canonical_base64(receipt.signature_base64),
            executor_transport_receipt_message(receipt),
        )
    except (InvalidSignature, ValueError, TypeError, binascii.Error):
        raise ExecutorTransportError("transport_receipt") from None
    return receipt


def request_from_delivery(
    *,
    allocation_intent_sha256: str,
    request: SecretDeliveryRequestV1,
    message_kind: Literal["materialize", "start"],
    client_nonce: str,
    server_nonce: str,
    session_id: str,
    request_id: str,
    host_key_fingerprint_sha256: str,
    executor_id: str,
    policy: ExecutorTransportPolicyV2,
    predecessor_materialization_operation_id: str | None,
    authorization_witness: RemoteEffectAuthorizationWitnessV1,
    expires_at: str,
    signer_key_id: str,
    signature_base64: str,
) -> ExecutorTransportRequestV2:
    """Construct exact metadata from an already validated delivery request."""

    if type(request) is not SecretDeliveryRequestV1:
        raise ExecutorTransportError("transport_request")
    witness = cast(
        RemoteEffectAuthorizationWitnessV1,
        _strict_model(
            authorization_witness,
            RemoteEffectAuthorizationWitnessV1,
            phase="remote_effect_witness",
        ),
    )
    if (
        witness.operation_scope != request.operation_scope
        or witness.operation_id != request.operation_id
        or witness.journal_uuid != request.journal_uuid
        or witness.effect_intent_sha256 is None
        or witness.predecessor_attestation_sha256 is None
    ):
        raise ExecutorTransportError("transport_request")
    return ExecutorTransportRequestV2(
        schema_version="rsd.executor-transport-request.v2",
        message_kind=message_kind,
        operation_scope=request.operation_scope,
        allocation_intent_sha256=allocation_intent_sha256,
        operation_id=request.operation_id,
        predecessor_materialization_operation_id=predecessor_materialization_operation_id,
        journal_uuid=request.journal_uuid,
        idempotency_key=witness.idempotency_key,
        effect_intent_sha256=witness.effect_intent_sha256,
        predecessor_attestation_sha256=witness.predecessor_attestation_sha256,
        docker_engine_control_policy_sha256=witness.docker_engine_control_policy_sha256,
        postgres_prepared_control_policy_sha256=(witness.postgres_prepared_control_policy_sha256),
        host_fingerprint_sha256=witness.host_fingerprint_sha256,
        engine_fingerprint_sha256=witness.engine_fingerprint_sha256,
        effect_plan_sha256=witness.effect_plan_sha256,
        artifact_chain_sha256=witness.artifact_chain_sha256,
        authorization_witness=witness,
        request_id=request_id,
        client_nonce=client_nonce,
        server_nonce=server_nonce,
        session_id=session_id,
        request_nonce_sha256=request.request_nonce_sha256,
        channel_binding_sha256=request.channel_binding_sha256,
        session_binding_sha256=request.session_binding_sha256,
        host_key_fingerprint_sha256=host_key_fingerprint_sha256,
        executor_id=executor_id,
        executor_policy_sha256=policy.policy_sha256(),
        package_sha256=policy.package_sha256,
        template_bundle_sha256=policy.template_bundle_sha256,
        installation_receipt_sha256=policy.executor_installation_receipt_sha256,
        expires_at=expires_at,
        chunk_count=5,
        slots=request.slots,
        signer_key_id=signer_key_id,
        signature_base64=signature_base64,
    )


def _owner_only_bytes(path: str, *, maximum: int, phase: str) -> bytes:
    """Read one no-follow owner-only regular file without retaining failures."""

    try:
        before = os.lstat(path)
        if (
            not stat.S_ISREG(before.st_mode)
            or before.st_uid != os.geteuid()
            or stat.S_IMODE(before.st_mode) & 0o077
            or before.st_nlink != 1
        ):
            raise ValueError
        flags = os.O_RDONLY | getattr(os, "O_NOFOLLOW", 0)
        descriptor = os.open(path, flags)
        try:
            opened = os.fstat(descriptor)
            if (
                opened.st_dev != before.st_dev
                or opened.st_ino != before.st_ino
                or opened.st_nlink != 1
                or not stat.S_ISREG(opened.st_mode)
                or opened.st_uid != os.geteuid()
                or stat.S_IMODE(opened.st_mode) & 0o077
            ):
                raise ValueError
            raw = bytearray()
            while len(raw) <= maximum:
                block = os.read(descriptor, min(8192, maximum + 1 - len(raw)))
                if not block:
                    break
                raw.extend(block)
            if len(raw) > maximum:
                raise ValueError
            after = os.fstat(descriptor)
            if (after.st_dev, after.st_ino, after.st_nlink) != (
                opened.st_dev,
                opened.st_ino,
                opened.st_nlink,
            ):
                raise ValueError
            return bytes(raw)
        finally:
            os.close(descriptor)
    except Exception:
        raise ExecutorTransportError(phase) from None


def _owner_only_file_metadata(path: str, *, phase: str) -> None:
    """Validate a no-follow identity file without reading its contents."""

    try:
        before = os.lstat(path)
        if (
            not stat.S_ISREG(before.st_mode)
            or before.st_uid != os.geteuid()
            or stat.S_IMODE(before.st_mode) & 0o077
            or before.st_nlink != 1
        ):
            raise ValueError
        descriptor = os.open(path, os.O_RDONLY | getattr(os, "O_NOFOLLOW", 0))
        try:
            opened = os.fstat(descriptor)
            if (
                (opened.st_dev, opened.st_ino, opened.st_nlink)
                != (before.st_dev, before.st_ino, before.st_nlink)
                or not stat.S_ISREG(opened.st_mode)
                or opened.st_uid != os.geteuid()
                or stat.S_IMODE(opened.st_mode) & 0o077
            ):
                raise ValueError
        finally:
            os.close(descriptor)
    except Exception:
        raise ExecutorTransportError(phase) from None


def _open_pinned_owner_file(path: str, *, phase: str) -> int:
    """Return one no-follow owner-only descriptor held stable for child use.

    OpenSSH normally reopens its known-hosts and identity paths after the
    launcher has checked them.  The live launcher instead gives it inherited
    descriptor paths, so a same-owner rename between validation and exec
    cannot substitute either input.
    """

    descriptor: int | None = None
    try:
        before = os.lstat(path)
        if (
            not stat.S_ISREG(before.st_mode)
            or before.st_uid != os.geteuid()
            or stat.S_IMODE(before.st_mode) & 0o077
            or before.st_nlink != 1
        ):
            raise ValueError
        descriptor = os.open(path, os.O_RDONLY | getattr(os, "O_NOFOLLOW", 0))
        opened = os.fstat(descriptor)
        after = os.lstat(path)
        if (
            (opened.st_dev, opened.st_ino, opened.st_nlink)
            != (before.st_dev, before.st_ino, before.st_nlink)
            or (after.st_dev, after.st_ino, after.st_nlink)
            != (before.st_dev, before.st_ino, before.st_nlink)
            or not stat.S_ISREG(opened.st_mode)
            or opened.st_uid != os.geteuid()
            or stat.S_IMODE(opened.st_mode) & 0o077
        ):
            raise ValueError
        return descriptor
    except Exception:
        if descriptor is not None:
            with suppress(Exception):
                os.close(descriptor)
        raise ExecutorTransportError(phase) from None


class _OwnerOnlyTransportArtifacts:
    """Descriptor-relative reader for exactly one non-secret artifact root."""

    def __init__(self, paths: ExecutorTransportArtifactPathsV2) -> None:
        self._paths = paths
        self._descriptor: int | None = None
        self._node: os.stat_result | None = None

    def __enter__(self) -> _OwnerOnlyTransportArtifacts:
        try:
            before = os.lstat(self._paths.root)
            if (
                not stat.S_ISDIR(before.st_mode)
                or before.st_uid != os.geteuid()
                or stat.S_IMODE(before.st_mode) & 0o077
                or before.st_nlink < 2
            ):
                raise ValueError
            descriptor = os.open(
                self._paths.root,
                os.O_RDONLY | getattr(os, "O_DIRECTORY", 0) | getattr(os, "O_NOFOLLOW", 0),
            )
            opened = os.fstat(descriptor)
            if (
                not stat.S_ISDIR(opened.st_mode)
                or (opened.st_dev, opened.st_ino) != (before.st_dev, before.st_ino)
                or opened.st_uid != os.geteuid()
                or stat.S_IMODE(opened.st_mode) & 0o077
            ):
                os.close(descriptor)
                raise ValueError
            self._descriptor = descriptor
            self._node = opened
            return self
        except ExecutorTransportError:
            raise
        except Exception:
            raise ExecutorTransportError("transport_artifacts") from None

    def read(self, name: str) -> bytes:
        if (
            self._descriptor is None
            or self._node is None
            or name
            not in {
                _TRANSPORT_POLICY_ARTIFACT,
                _INSTALLATION_POLICY_ARTIFACT,
                _INSTALLATION_RECEIPT_ARTIFACT,
                _SIGNER_GENESIS_ARTIFACT,
            }
        ):
            raise ExecutorTransportError("transport_artifacts")
        try:
            before = os.stat(name, dir_fd=self._descriptor, follow_symlinks=False)
            if (
                not stat.S_ISREG(before.st_mode)
                or before.st_uid != os.geteuid()
                or stat.S_IMODE(before.st_mode) & 0o077
                or before.st_nlink != 1
                or before.st_size < 1
                or before.st_size > _MAX_FILE_BYTES
            ):
                raise ValueError
            descriptor = os.open(
                name,
                os.O_RDONLY | getattr(os, "O_NOFOLLOW", 0),
                dir_fd=self._descriptor,
            )
            try:
                opened = os.fstat(descriptor)
                if (
                    (opened.st_dev, opened.st_ino, opened.st_nlink)
                    != (before.st_dev, before.st_ino, before.st_nlink)
                    or not stat.S_ISREG(opened.st_mode)
                    or opened.st_uid != os.geteuid()
                    or stat.S_IMODE(opened.st_mode) & 0o077
                ):
                    raise ValueError
                raw = bytearray()
                while len(raw) <= _MAX_FILE_BYTES:
                    block = os.read(descriptor, min(8192, _MAX_FILE_BYTES + 1 - len(raw)))
                    if not block:
                        break
                    raw.extend(block)
                after = os.fstat(descriptor)
                if len(raw) > _MAX_FILE_BYTES or (after.st_dev, after.st_ino, after.st_nlink) != (
                    opened.st_dev,
                    opened.st_ino,
                    opened.st_nlink,
                ):
                    raise ValueError
                return bytes(raw)
            finally:
                os.close(descriptor)
        except ExecutorTransportError:
            raise
        except Exception:
            raise ExecutorTransportError("transport_artifacts") from None

    def __exit__(self, exc_type: object, exc: object, traceback: object) -> None:
        del exc_type, traceback
        if self._descriptor is None or self._node is None:
            return
        descriptor = self._descriptor
        self._descriptor = None
        try:
            after = os.fstat(descriptor)
            path_after = os.lstat(self._paths.root)
            if (after.st_dev, after.st_ino, after.st_nlink) != (
                self._node.st_dev,
                self._node.st_ino,
                self._node.st_nlink,
            ) or (path_after.st_dev, path_after.st_ino, path_after.st_nlink) != (
                self._node.st_dev,
                self._node.st_ino,
                self._node.st_nlink,
            ):
                raise ValueError
        except Exception:
            # An artifact root change is fail-closed.  This exit cannot safely
            # replace an active exception with a value-bearing filesystem one.
            if exc is None:
                raise ExecutorTransportError("transport_artifacts") from None
        finally:
            os.close(descriptor)


def _known_host_fingerprints(raw: bytes, *, endpoint: str) -> frozenset[str]:
    """Parse a canonical narrow known-hosts file without a helper subprocess."""

    try:
        if type(raw) is not bytes or not raw or not raw.endswith(b"\n") or b"\r" in raw:
            raise ValueError
        endpoint_bytes = endpoint.encode("ascii")
    except UnicodeDecodeError:
        raise ExecutorTransportError("known_hosts") from None
    except (TypeError, ValueError):
        raise ExecutorTransportError("known_hosts") from None
    result: set[str] = set()
    lines = raw[:-1].split(b"\n")
    if not lines or lines != sorted(lines):
        raise ExecutorTransportError("known_hosts")
    for line in lines:
        fields = line.split(b" ")
        if len(fields) != 3 or any(not field for field in fields):
            raise ExecutorTransportError("known_hosts")
        names, key_type, encoded = fields[:3]
        if names != endpoint_bytes or key_type not in {
            b"ssh-ed25519",
            b"ecdsa-sha2-nistp256",
            b"rsa-sha2-512",
        }:
            raise ExecutorTransportError("known_hosts")
        try:
            raw_key = base64.b64decode(encoded, validate=True)
        except (binascii.Error, ValueError):
            raise ExecutorTransportError("known_hosts") from None
        if base64.b64encode(raw_key) != encoded:
            raise ExecutorTransportError("known_hosts")
        fingerprint = _digest(raw_key)
        if fingerprint in result:
            raise ExecutorTransportError("known_hosts")
        result.add(fingerprint)
    if not result:
        raise ExecutorTransportError("known_hosts")
    return frozenset(result)


def _ssh_ed25519_blob(raw: bytes) -> bytes:
    """Parse exactly one canonical OpenSSH Ed25519 public-key blob.

    The outer key type is not security authority: OpenSSH fingerprints the
    binary wire blob.  This parser therefore verifies both length-prefixed
    strings, the fixed algorithm marker, the exact 32-byte public key, and
    the absence of trailing fields before a fingerprint is accepted.
    """

    def read_string(offset: int) -> tuple[bytes, int]:
        if offset + 4 > len(raw):
            raise ValueError
        length = struct.unpack("!I", raw[offset : offset + 4])[0]
        end = offset + 4 + length
        if end < offset or end > len(raw):
            raise ValueError
        return raw[offset + 4 : end], end

    try:
        if type(raw) is not bytes or len(raw) != _ED25519_PUBLIC_KEY_BLOB_BYTES:
            raise ValueError
        algorithm, offset = read_string(0)
        public_key, offset = read_string(offset)
        if algorithm != b"ssh-ed25519" or len(public_key) != 32 or offset != len(raw):
            raise ValueError
    except (TypeError, ValueError, struct.error):
        raise ExecutorTransportError("identity_reference") from None
    return raw


def _public_key_fingerprint(raw: bytes) -> str:
    """Verify one owner-only canonical OpenSSH Ed25519 public-key reference."""

    try:
        if (
            len(raw) != _ED25519_PUBLIC_KEY_BASE64_BYTES + 1 + len(b"ssh-ed25519 ")
            or not raw.endswith(b"\n")
            or raw.count(b"\n") != 1
            or b"\r" in raw
        ):
            raise ValueError
        line = raw[:-1].decode("ascii")
        fields = line.split(" ")
        if len(fields) != 2 or fields[0] != "ssh-ed25519":
            raise ValueError
        decoded = base64.b64decode(fields[1], validate=True)
        if base64.b64encode(decoded).decode("ascii") != fields[1]:
            raise ValueError
        return _digest(_ssh_ed25519_blob(decoded))
    except (UnicodeDecodeError, ValueError, binascii.Error, ExecutorTransportError):
        raise ExecutorTransportError("identity_reference") from None


def _validate_executable(path: str, *, expected_sha256: str) -> None:
    """Pin an executable inode/content before it appears in a process argv."""

    try:
        before = os.lstat(path)
        if (
            not stat.S_ISREG(before.st_mode)
            or before.st_uid != 0
            or stat.S_IMODE(before.st_mode) & 0o022
            or before.st_nlink < 1
        ):
            raise ValueError
        descriptor = os.open(path, os.O_RDONLY | getattr(os, "O_NOFOLLOW", 0))
        try:
            opened = os.fstat(descriptor)
            if (opened.st_dev, opened.st_ino) != (before.st_dev, before.st_ino):
                raise ValueError
            digest = hashlib.sha256()
            while True:
                block = os.read(descriptor, 65536)
                if not block:
                    break
                digest.update(block)
            if not hmac.compare_digest(digest.hexdigest(), expected_sha256):
                raise ValueError
        finally:
            os.close(descriptor)
    except Exception:
        raise ExecutorTransportError("ssh_executable") from None


@dataclass(frozen=True, slots=True)
class SecureShellLaunchSpec:
    """One fixed, non-secret argv/environment tuple for a transport process."""

    argv: tuple[str, ...]
    environment: Mapping[str, str]


class _Pipe(Protocol):
    def close(self) -> object: ...

    def flush(self) -> object: ...

    def write(self, data: bytes | memoryview) -> int | None: ...

    def read(self, size: int = -1) -> bytes: ...


class _Process(Protocol):
    stdin: _Pipe | None
    stdout: _Pipe | None
    stderr: _Pipe | None

    def wait(self, timeout: float | None = None) -> int: ...

    def poll(self) -> int | None: ...

    def kill(self) -> object: ...


PopenFactory = Callable[..., _Process]


class SecureShellProcessSession:
    """Bounded binary pipe ownership with generic failure reporting only."""

    def __init__(self, process: _Process, *, timeout_seconds: int) -> None:
        if type(timeout_seconds) is not int or not 1 <= timeout_seconds <= _MAX_SESSION_SECONDS:
            raise ExecutorTransportError("ssh_timeout")
        if process.stdin is None or process.stdout is None or process.stderr is None:
            raise ExecutorTransportError("ssh_process")
        self._process = process
        self._timeout_seconds = timeout_seconds
        self._deadline = time.monotonic() + timeout_seconds
        self._closed = False
        self._input_closed = False

    def _remaining(self) -> float:
        remaining = self._deadline - time.monotonic()
        if remaining <= 0:
            raise ExecutorTransportError("ssh_timeout")
        return remaining

    @staticmethod
    def _descriptor(stream: _Pipe) -> int | None:
        """Use descriptor I/O in production; BytesIO is an internal test seam."""

        candidate = getattr(stream, "fileno", None)
        if not callable(candidate):
            return None
        try:
            descriptor = candidate()
        except Exception:
            return None
        return descriptor if type(descriptor) is int and descriptor >= 0 else None

    def write(self, data: bytes | memoryview) -> None:
        if self._closed or self._input_closed or type(data) not in {bytes, memoryview}:
            raise ExecutorTransportError("ssh_pipe")
        try:
            stream = cast(_Pipe, self._process.stdin)
            descriptor = self._descriptor(stream)
            if descriptor is None:
                result = stream.write(data)
                if result is not None and result != len(data):
                    raise ValueError
                stream.flush()
                return
            remaining = memoryview(data)
            while remaining:
                _readable, writable, _exceptional = select.select(
                    [], [descriptor], [], self._remaining()
                )
                if not writable:
                    raise ExecutorTransportError("ssh_timeout")
                written = os.write(descriptor, remaining)
                if written <= 0:
                    raise ValueError
                remaining = remaining[written:]
        except ExecutorTransportError:
            raise
        except Exception:
            raise ExecutorTransportError("ssh_pipe") from None

    def flush(self) -> None:
        """Meet the direct frame-writer sink contract without exposing a pipe."""

        if self._closed or self._input_closed:
            raise ExecutorTransportError("ssh_pipe")

    def read_exact(self, count: int) -> bytes:
        if self._closed or type(count) is not int or not 1 <= count <= _MAX_FILE_BYTES:
            raise ExecutorTransportError("ssh_pipe")
        result = bytearray()
        try:
            stream = cast(_Pipe, self._process.stdout)
            descriptor = self._descriptor(stream)
            if descriptor is None:
                while len(result) < count:
                    chunk = stream.read(count - len(result))
                    if not chunk:
                        raise ValueError
                    result.extend(chunk)
            else:
                while len(result) < count:
                    readable, _writable, _exceptional = select.select(
                        [descriptor], [], [], self._remaining()
                    )
                    if not readable:
                        raise ExecutorTransportError("ssh_timeout")
                    chunk = os.read(descriptor, count - len(result))
                    if not chunk:
                        raise ValueError
                    result.extend(chunk)
            return bytes(result)
        except ExecutorTransportError:
            raise
        except Exception:
            raise ExecutorTransportError("ssh_pipe") from None

    def close_input(self) -> None:
        """Send the protocol's mandatory client half-close after one request.

        The remote ForceCommand relay propagates this close to its UDS peer.
        The daemon consequently observes an unambiguous end-of-input before it
        is allowed to invoke a backend effect. No later frame can be accepted
        on this single-use channel.
        """

        if self._closed or self._input_closed:
            raise ExecutorTransportError("ssh_pipe")
        try:
            cast(_Pipe, self._process.stdin).close()
            self._input_closed = True
        except Exception:
            raise ExecutorTransportError("ssh_pipe") from None

    def require_eof(self) -> None:
        """Require a clean final stdout EOF with no trailing framed bytes."""

        if self._closed or not self._input_closed:
            raise ExecutorTransportError("ssh_pipe")
        try:
            stream = cast(_Pipe, self._process.stdout)
            descriptor = self._descriptor(stream)
            if descriptor is None:
                trailing = stream.read(1)
            else:
                readable, _writable, _exceptional = select.select(
                    [descriptor], [], [], self._remaining()
                )
                if not readable:
                    raise ExecutorTransportError("ssh_timeout")
                trailing = os.read(descriptor, 1)
            if trailing:
                raise ValueError
            status = self._process.wait(timeout=self._remaining())
            if type(status) is not int or status != 0:
                raise ValueError
        except ExecutorTransportError:
            raise
        except Exception:
            raise ExecutorTransportError("ssh_pipe") from None

    def close(self) -> None:
        if self._closed:
            return
        self._closed = True
        if not self._input_closed:
            with suppress(Exception):
                cast(_Pipe, self._process.stdin).close()
            self._input_closed = True
        try:
            self._process.wait(timeout=max(0.0, self._deadline - time.monotonic()))
        except Exception:
            with suppress(Exception):
                self._process.kill()
            with suppress(Exception):
                self._process.wait(timeout=1.0)
        for stream in (self._process.stdout, self._process.stderr):
            with suppress(Exception):
                cast(_Pipe, stream).close()


class MacOSSecureShellClient:
    """Construct and own the one fixed macOS OpenSSH client process.

    A caller cannot append options, select a remote command, supply an
    environment, or reuse a control socket.  Test code may inject a process
    factory; production construction uses only ``subprocess.Popen``.
    """

    def __init__(
        self,
        artifacts: VerifiedExecutorTransportArtifactsV2,
        *,
        _popen: PopenFactory | None = None,
        _executable_validator: Callable[[str, str], None] | None = None,
        _owner_reader: Callable[[str, int, str], bytes] | None = None,
        _test_capability: object | None = None,
    ) -> None:
        if (
            type(artifacts) is not VerifiedExecutorTransportArtifactsV2
            or (
                (
                    _popen is not None
                    or _executable_validator is not None
                    or _owner_reader is not None
                )
                and _test_capability is not _TRANSPORT_TEST_CAPABILITY
            )
            or (_test_capability is not None and _test_capability is not _TRANSPORT_TEST_CAPABILITY)
        ):
            raise ExecutorTransportError("transport_artifacts")
        self._artifacts = artifacts
        self._policy = artifacts.policy
        self._popen = _popen
        self._executable_validator = _executable_validator
        self._owner_reader = _owner_reader

    def launch_spec(self) -> SecureShellLaunchSpec:
        """Validate pinned executable/known-hosts/identity and build fixed argv."""

        policy = self._policy
        reader = self._owner_reader or (
            lambda path, maximum, phase: _owner_only_bytes(path, maximum=maximum, phase=phase)
        )
        validator = self._executable_validator or (
            lambda path, digest: _validate_executable(path, expected_sha256=digest)
        )
        validator(policy.ssh_executable_path, policy.ssh_executable_sha256)
        known_hosts = reader(policy.known_hosts_path, _MAX_FILE_BYTES, "known_hosts")
        if not hmac.compare_digest(_digest(known_hosts), policy.known_hosts_sha256):
            raise ExecutorTransportError("known_hosts")
        fingerprints = _known_host_fingerprints(known_hosts, endpoint=policy.endpoint)
        if fingerprints != frozenset(policy.ssh_policy.host_key_fingerprints_sha256):
            raise ExecutorTransportError("known_hosts")
        public_key = reader(policy.identity.public_key_path, _MAX_FILE_BYTES, "identity_reference")
        if (
            not hmac.compare_digest(
                _public_key_fingerprint(public_key), policy.identity.public_key_fingerprint_sha256
            )
            or policy.identity.public_key_fingerprint_sha256
            != policy.ssh_policy.client_key_fingerprint_sha256
        ):
            raise ExecutorTransportError("identity_reference")
        _owner_only_file_metadata(policy.identity.key_path, phase="identity_reference")
        argv = (
            policy.ssh_executable_path,
            "-F",
            "/dev/null",
            "-o",
            "BatchMode=yes",
            "-o",
            "StrictHostKeyChecking=yes",
            "-o",
            "UpdateHostKeys=no",
            "-o",
            "GlobalKnownHostsFile=/dev/null",
            "-o",
            "ForwardAgent=no",
            "-o",
            "ForwardX11=no",
            "-o",
            "RequestTTY=no",
            "-o",
            "ClearAllForwardings=yes",
            "-o",
            "ControlMaster=no",
            "-o",
            "ControlPath=none",
            "-o",
            "ProxyCommand=none",
            "-o",
            "IdentityAgent=none",
            "-o",
            "IdentitiesOnly=yes",
            "-o",
            "PasswordAuthentication=no",
            "-o",
            "KbdInteractiveAuthentication=no",
            "-o",
            "NumberOfPasswordPrompts=0",
            "-o",
            "PreferredAuthentications=publickey",
            "-o",
            "CanonicalizeHostname=no",
            "-o",
            "PermitLocalCommand=no",
            "-o",
            f"UserKnownHostsFile={policy.known_hosts_path}",
            "-i",
            policy.identity.key_path,
            "-l",
            policy.ssh_policy.dedicated_user,
            policy.endpoint,
            policy.ssh_policy.force_command,
        )
        return SecureShellLaunchSpec(argv=argv, environment={"LANG": "C", "LC_ALL": "C"})

    @contextmanager
    def open(self) -> Iterator[SecureShellProcessSession]:
        """Launch only the fixed command and force cleanup for all outcomes."""

        if self._popen is None and sys.platform != "darwin":
            raise ExecutorTransportError("ssh_platform")
        # ``launch_spec`` performs the policy/digest/public-key verification.
        # Pin the two path inputs again as inherited descriptors for the actual
        # exec, rather than allowing OpenSSH to reopen mutable path names.
        base_spec = self.launch_spec()
        known_hosts_descriptor: int | None = None
        identity_descriptor: int | None = None
        try:
            known_hosts_descriptor = _open_pinned_owner_file(
                self._policy.known_hosts_path, phase="known_hosts"
            )
            known_hosts = bytearray()
            try:
                while len(known_hosts) <= _MAX_FILE_BYTES:
                    block = os.read(
                        known_hosts_descriptor,
                        min(8192, _MAX_FILE_BYTES + 1 - len(known_hosts)),
                    )
                    if not block:
                        break
                    known_hosts.extend(block)
                if len(known_hosts) > _MAX_FILE_BYTES:
                    raise ValueError
                immutable_hosts = bytes(known_hosts)
                if not hmac.compare_digest(
                    _digest(immutable_hosts), self._policy.known_hosts_sha256
                ) or _known_host_fingerprints(
                    immutable_hosts, endpoint=self._policy.endpoint
                ) != frozenset(self._policy.ssh_policy.host_key_fingerprints_sha256):
                    raise ValueError
                os.lseek(known_hosts_descriptor, 0, os.SEEK_SET)
            finally:
                _zeroize(known_hosts)
            identity_descriptor = _open_pinned_owner_file(
                self._policy.identity.key_path, phase="identity_reference"
            )
            known_hosts_fd_path = f"/dev/fd/{known_hosts_descriptor}"
            identity_fd_path = f"/dev/fd/{identity_descriptor}"
            spec = SecureShellLaunchSpec(
                argv=tuple(
                    f"UserKnownHostsFile={known_hosts_fd_path}"
                    if item == f"UserKnownHostsFile={self._policy.known_hosts_path}"
                    else identity_fd_path
                    if item == self._policy.identity.key_path
                    else item
                    for item in base_spec.argv
                ),
                environment=base_spec.environment,
            )
        except ExecutorTransportError:
            raise
        except Exception:
            raise ExecutorTransportError("ssh_input") from None
        factory: PopenFactory = self._popen or cast(PopenFactory, subprocess.Popen)
        try:
            process = factory(
                spec.argv,
                stdin=subprocess.PIPE,
                stdout=subprocess.PIPE,
                stderr=subprocess.PIPE,
                text=False,
                shell=False,
                close_fds=True,
                start_new_session=True,
                env=dict(spec.environment),
                pass_fds=(known_hosts_descriptor, identity_descriptor),
            )
        except Exception:
            raise ExecutorTransportError("ssh_launch") from None
        finally:
            if known_hosts_descriptor is not None:
                with suppress(Exception):
                    os.close(known_hosts_descriptor)
            if identity_descriptor is not None:
                with suppress(Exception):
                    os.close(identity_descriptor)
        session = SecureShellProcessSession(
            process,
            timeout_seconds=self._policy.max_session_seconds,
        )
        try:
            yield session
        finally:
            session.close()


def _macos_secure_shell_client_for_test(
    artifacts: VerifiedExecutorTransportArtifactsV2,
    *,
    popen: PopenFactory | None = None,
    executable_validator: Callable[[str, str], None] | None = None,
    owner_reader: Callable[[str, int, str], bytes] | None = None,
) -> MacOSSecureShellClient:
    """Create an internal fake-injected client for offline unit coverage only."""

    return MacOSSecureShellClient(
        artifacts,
        _popen=popen,
        _executable_validator=executable_validator,
        _owner_reader=owner_reader,
        _test_capability=_TRANSPORT_TEST_CAPABILITY,
    )


class ExecutorRequestFrameWriter:
    """Direct frame writer for one signed request and its exact five slots."""

    def __init__(
        self,
        session: SecureShellProcessSession,
        request: ExecutorTransportRequestV2,
    ) -> None:
        if type(session) is not SecureShellProcessSession:
            raise ExecutorTransportError("transport_writer")
        self._request = cast(
            ExecutorTransportRequestV2,
            _strict_model(request, ExecutorTransportRequestV2, phase="transport_request"),
        )
        self._writer = CanonicalFrameWriter(session)
        self._writer.begin(
            _canonical_json(self._request.model_dump(mode="json")),
            chunk_count=self._request.chunk_count,
        )
        self._position = 0
        self._finished = False

    @property
    def transport_request(self) -> ExecutorTransportRequestV2:
        """Return only the already-validated metadata binding for a lease check."""

        return self._request

    def write_slot(self, descriptor: SecretDeliverySlotV1, value: memoryview) -> None:
        if self._finished or type(descriptor) is not SecretDeliverySlotV1:
            raise ExecutorTransportError("transport_writer")
        if (
            self._position >= len(self._request.slots)
            or descriptor != self._request.slots[self._position]
        ):
            raise ExecutorTransportError("transport_writer")
        if type(value) is not memoryview or len(value) != descriptor.encoded_byte_count:
            raise ExecutorTransportError("transport_writer")
        try:
            self._writer.write_chunk(value)
        except TransportError:
            raise ExecutorTransportError("transport_writer") from None
        self._position += 1

    def finish(self) -> None:
        if self._finished or self._position != len(self._request.slots):
            raise ExecutorTransportError("transport_writer")
        try:
            self._writer.finish()
        except TransportError:
            raise ExecutorTransportError("transport_writer") from None
        self._finished = True


@runtime_checkable
class _StreamingSecretLease(Protocol):
    def stream_to(
        self,
        request: SecretDeliveryRequestV1,
        writer: SecretFrameWriter,
        *,
        completed_at: str,
    ) -> SecretDeliveryReceiptV1: ...


class RemoteExecutorTransportClient:
    """One-shot secure-shell delivery client with no automatic retry path."""

    def __init__(
        self,
        client: MacOSSecureShellClient,
        *,
        artifacts: VerifiedExecutorTransportArtifactsV2,
    ) -> None:
        if (
            type(client) is not MacOSSecureShellClient
            or type(artifacts) is not VerifiedExecutorTransportArtifactsV2
        ):
            raise ExecutorTransportError("transport_client")
        self._client = client
        self._artifacts = artifacts
        self._policy = artifacts.policy

    def deliver(
        self,
        request: ExecutorTransportRequestV2,
        delivery_request: SecretDeliveryRequestV1,
        material_lease: SecretMaterialLease,
    ) -> tuple[SecretDeliveryReceiptV1, ExecutorTransportReceiptV2]:
        """Perform exactly one delivery; any post-write failure is ambiguous."""

        if type(delivery_request) is not SecretDeliveryRequestV1:
            raise ExecutorTransportError("transport_delivery")
        if not isinstance(material_lease, _StreamingSecretLease):
            raise ExecutorTransportError("transport_delivery")
        delivery_started = False
        try:
            with self._client.open() as session:
                request = cast(
                    ExecutorTransportRequestV2,
                    _strict_model(request, ExecutorTransportRequestV2, phase="transport_request"),
                )
                client_hello = ExecutorClientHelloV2(
                    schema_version="rsd.executor-client-hello.v2",
                    allocation_intent_sha256=request.allocation_intent_sha256,
                    client_nonce=request.client_nonce,
                    session_id=request.session_id,
                    request_id=request.request_id,
                    executor_id=request.executor_id,
                    executor_policy_sha256=request.executor_policy_sha256,
                    chunk_count=0,
                )
                hello_writer = CanonicalFrameWriter(session)
                hello_writer.begin(
                    _canonical_json(client_hello.model_dump(mode="json")),
                    chunk_count=0,
                )
                hello_writer.finish()
                raw_hello = read_raw_transport(session, require_eof=False)
                hello = ExecutorHelloV2.model_validate_json(raw_hello.metadata_bytes)
                hello = verify_executor_hello(
                    hello,
                    policy=self._policy,
                    attestation_public_key_base64=self._artifacts.attestation_public_key_base64,
                    attestation_key_id=self._artifacts.attestation_key_id,
                )
                request = verify_executor_transport_request(
                    request,
                    signer_genesis=self._artifacts.signer_genesis,
                    hello=hello,
                    policy=self._policy,
                )
                if (
                    request.operation_id != delivery_request.operation_id
                    or request.journal_uuid != delivery_request.journal_uuid
                    or request.request_nonce_sha256 != delivery_request.request_nonce_sha256
                    or request.channel_binding_sha256 != delivery_request.channel_binding_sha256
                    or request.session_binding_sha256 != delivery_request.session_binding_sha256
                    or request.slots != delivery_request.slots
                ):
                    raise ExecutorTransportError("transport_delivery")
                # From this point the client has sent signed metadata into an
                # authenticated channel.  Any failure is deliberately
                # terminal/ambiguous, even if no chunk has yet been emitted:
                # the peer may have durably claimed the operation already.
                delivery_started = True
                writer = ExecutorRequestFrameWriter(session, request)
                delivery = cast(_StreamingSecretLease, material_lease).stream_to(
                    delivery_request,
                    writer,
                    completed_at=_system_utc_clock()
                    .isoformat(timespec="seconds")
                    .replace("+00:00", "Z"),
                )
                writer.finish()
                session.close_input()
                raw_receipt = read_raw_transport(session)
                if raw_receipt.chunks:
                    raise ExecutorTransportError("transport_receipt")
                receipt = ExecutorTransportReceiptV2.model_validate_json(raw_receipt.metadata_bytes)
                receipt = verify_executor_transport_receipt(
                    receipt,
                    request=request,
                    policy=self._policy,
                    attestation_public_key_base64=self._artifacts.attestation_public_key_base64,
                    attestation_key_id=self._artifacts.attestation_key_id,
                )
                if receipt.delivery_binding_sha256 != transport_delivery_binding_sha256(request):
                    raise ExecutorTransportError("transport_receipt")
                return delivery, receipt
        except ExecutorTransportError as error:
            if delivery_started:
                raise ExecutorTransportError("transport_delivery_ambiguous") from None
            raise error
        except (TransportError, ValidationError, ValueError):
            raise ExecutorTransportError("transport_delivery_ambiguous") from None

    def allocate(
        self,
        request: ExecutorAllocationTransportRequestV1,
    ) -> ExecutorAllocationTransportReceiptV1:
        """Submit exactly one zero-secret allocation request.

        This API deliberately has no material lease, slot writer, or raw
        payload parameter.  Once signed allocation metadata begins writing to
        the authenticated channel, every failure is terminally ambiguous: the
        daemon may have claimed its durable operation journal already.
        """

        request_started = False
        try:
            with self._client.open() as session:
                request = cast(
                    ExecutorAllocationTransportRequestV1,
                    _strict_model(
                        request,
                        ExecutorAllocationTransportRequestV1,
                        phase="allocation_request",
                    ),
                )
                client_hello = ExecutorClientHelloV2(
                    schema_version="rsd.executor-client-hello.v2",
                    allocation_intent_sha256=request.allocation_intent_sha256,
                    client_nonce=request.client_nonce,
                    session_id=request.session_id,
                    request_id=request.request_id,
                    executor_id=request.executor_id,
                    executor_policy_sha256=request.executor_policy_sha256,
                    chunk_count=0,
                )
                hello_writer = CanonicalFrameWriter(session)
                hello_writer.begin(
                    _canonical_json(client_hello.model_dump(mode="json")),
                    chunk_count=0,
                )
                hello_writer.finish()
                raw_hello = read_raw_transport(session, require_eof=False)
                hello = ExecutorHelloV2.model_validate_json(raw_hello.metadata_bytes)
                hello = verify_executor_hello(
                    hello,
                    policy=self._policy,
                    attestation_public_key_base64=self._artifacts.attestation_public_key_base64,
                    attestation_key_id=self._artifacts.attestation_key_id,
                )
                request = verify_executor_allocation_transport_request(
                    request,
                    signer_genesis=self._artifacts.signer_genesis,
                    hello=hello,
                    policy=self._policy,
                )
                request_started = True
                writer = CanonicalFrameWriter(session)
                writer.begin(
                    _canonical_json(request.model_dump(mode="json")),
                    chunk_count=0,
                )
                writer.finish()
                session.close_input()
                raw_receipt = read_raw_transport(session)
                if raw_receipt.chunks:
                    raise ExecutorTransportError("allocation_receipt")
                receipt = ExecutorAllocationTransportReceiptV1.model_validate_json(
                    raw_receipt.metadata_bytes
                )
                return verify_executor_allocation_transport_receipt(
                    receipt,
                    request=request,
                    policy=self._policy,
                    attestation_public_key_base64=self._artifacts.attestation_public_key_base64,
                    attestation_key_id=self._artifacts.attestation_key_id,
                )
        except ExecutorTransportError as error:
            if request_started:
                raise ExecutorTransportError("allocation_transport_ambiguous") from None
            raise error
        except (TransportError, ValidationError, ValueError):
            if request_started:
                raise ExecutorTransportError("allocation_transport_ambiguous") from None
            raise ExecutorTransportError("allocation_transport") from None


class _KeychainValueStore(Protocol):
    def read_if_present(self, service: str, account: str) -> bytearray | None: ...


class SecretFrameWriter(Protocol):
    """Internal sink used to stream one bounded value without a raw mapping."""

    def write_slot(self, descriptor: SecretDeliverySlotV1, value: memoryview) -> None: ...


def _zeroize(value: bytearray) -> None:
    value[:] = b"\x00" * len(value)


def _validate_material_value(format_value: ProviderMaterialFormat, value: bytearray) -> None:
    """Validate exactly the five delivery encodings without exposing their text."""

    if format_value is ProviderMaterialFormat.INFISICAL_HEX_16_V1:
        if len(value) != 32 or any(item not in b"0123456789abcdef" for item in value):
            raise ExecutorTransportError("material_format")
        return
    if format_value is ProviderMaterialFormat.INFISICAL_AUTH_SECRET_BASE64_32_V1:
        _validate_canonical_32_byte_encoding(value, alphabet=_BASE64_ALPHABET, padded=True)
        return
    elif format_value in {
        ProviderMaterialFormat.VALKEY_PASSWORD_BASE64URL_32_V1,
        ProviderMaterialFormat.POSTGRES_APPLICATION_PASSWORD_BASE64URL_32_V1,
    }:
        _validate_canonical_32_byte_encoding(value, alphabet=_BASE64URL_ALPHABET, padded=False)
        return
    else:
        raise ExecutorTransportError("material_format")


def _validate_canonical_32_byte_encoding(
    value: bytearray,
    *,
    alphabet: bytes,
    padded: bool,
) -> None:
    """Validate canonical 32-byte Base64 spelling without copying a secret.

    Both admitted encodings represent 32 bytes.  Their final sextet carries
    only four significant bits, so its low two bits must be zero; that direct
    check rejects trailing-bit aliases without constructing an immutable
    decoded/recoded value.  This is encoding validation, not cryptography.
    """

    expected_length = 44 if padded else 43
    if type(value) is not bytearray or len(value) != expected_length:
        raise ExecutorTransportError("material_format")
    data_length = 43
    if padded and value[-1] != ord("="):
        raise ExecutorTransportError("material_format")
    if any(item not in alphabet for item in value[:data_length]):
        raise ExecutorTransportError("material_format")
    if alphabet.index(value[data_length - 1]) & 0b11:
        raise ExecutorTransportError("material_format")


class MacOSKeychainSecretMaterialLease:
    """Direct Security.framework-backed bounded delivery lease.

    The production constructor obtains the existing direct generic-password
    bridge only on macOS.  Its test-only store seam is underscored and no
    public method returns a material value or a mapping of values.
    """

    def __init__(
        self,
        *,
        policy: ProviderMaterialPolicyV2,
        attestation: ProviderFingerprintAttestationV2,
        capability_policy: SecretCapabilityPolicyV1,
        handling_policy: SecretHandlingPolicyV1,
        _capability: object,
        _store: _KeychainValueStore | None = None,
    ) -> None:
        if (
            _capability is not _MATERIAL_LEASE_CAPABILITY
            or type(policy) is not ProviderMaterialPolicyV2
            or type(attestation) is not ProviderFingerprintAttestationV2
            or type(capability_policy) is not SecretCapabilityPolicyV1
            or type(handling_policy) is not SecretHandlingPolicyV1
        ):
            raise ExecutorTransportError("material_lease")
        material_by_reference = {item.reference.reference_sha256: item for item in policy.materials}
        attested_references = tuple(item.reference_sha256 for item in attestation.materials)
        if (
            attestation.provider_material_policy_sha256 != policy.policy_sha256()
            or set(attested_references) != set(material_by_reference)
            or len(attested_references) != len(material_by_reference)
            or any(
                material_by_reference[item.reference_sha256].purpose != item.purpose
                for item in attestation.materials
            )
        ):
            raise ExecutorTransportError("material_lease")
        self._policy = policy
        self._attestation = attestation
        self._capability_policy = capability_policy
        self._handling_policy = handling_policy
        self._provider_identity_sha256 = canonical_sha256(attestation)
        self._capability_fingerprint_sha256 = capability_policy.capability_fingerprint_sha256
        self._store = _store
        self._closed = False
        self._delivery_request_sha256: str | None = None

    def _store_or_fail(self) -> _KeychainValueStore:
        if self._closed:
            raise ExecutorTransportError("material_lease")
        if self._store is not None:
            return self._store
        if sys.platform != "darwin":
            raise ExecutorTransportError("keychain_platform")
        try:
            from omninode_rsd.lifecycle.provider_crypto import _default_keychain_store

            return cast(_KeychainValueStore, _default_keychain_store())
        except Exception:
            raise ExecutorTransportError("keychain_store") from None

    def _exact_delivery(self, request: SecretDeliveryRequestV1) -> None:
        if (
            type(request) is not SecretDeliveryRequestV1
            or self._closed
            or self._delivery_request_sha256 is not None
        ):
            raise ExecutorTransportError("material_delivery")
        if (
            tuple(slot.purpose for slot in request.slots) != _EXPECTED_PURPOSES
            or request.provider_material_attestation_sha256 != canonical_sha256(self._attestation)
            or self._capability_policy.provider_identity_sha256 != self._provider_identity_sha256
            or self._capability_policy.capability_fingerprint_sha256
            != self._capability_fingerprint_sha256
            or self._capability_policy.secret_handling_policy_sha256
            != canonical_sha256(self._handling_policy)
        ):
            raise ExecutorTransportError("material_delivery")

    def inspect(
        self,
        policy: SecretCapabilityPolicyV1,
        handling_policy: SecretHandlingPolicyV1,
    ) -> SecretMaterialProvenance | None:
        if (
            self._closed
            or policy != self._capability_policy
            or handling_policy != self._handling_policy
        ):
            return None
        return SecretMaterialProvenance(
            provider_identity_sha256=self._provider_identity_sha256,
            capability_fingerprint_sha256=self._capability_fingerprint_sha256,
        )

    def recheck(
        self,
        policy: SecretCapabilityPolicyV1,
        handling_policy: SecretHandlingPolicyV1,
    ) -> SecretMaterialProvenance | None:
        return self.inspect(policy, handling_policy)

    def inspect_delivery(self, request: SecretDeliveryRequestV1) -> SecretDeliveryProvenance | None:
        try:
            self._exact_delivery(request)
        except ExecutorTransportError:
            return None
        return SecretDeliveryProvenance(
            request_nonce_sha256=request.request_nonce_sha256,
            channel_binding_sha256=request.channel_binding_sha256,
            session_binding_sha256=request.session_binding_sha256,
            capability_fingerprint_sha256=self._capability_fingerprint_sha256,
        )

    def recheck_delivery(self, request: SecretDeliveryRequestV1) -> SecretDeliveryProvenance | None:
        return self.inspect_delivery(request)

    def deliver(self, request: SecretDeliveryRequestV1) -> SecretDeliveryReceiptV1 | None:
        """Reject an unbound delivery attempt; a frame writer is mandatory."""

        del request
        return None

    def stream_to(
        self,
        request: SecretDeliveryRequestV1,
        writer: SecretFrameWriter,
        *,
        completed_at: str,
    ) -> SecretDeliveryReceiptV1:
        """Read one slot at a time and write its buffer directly to the frame sink."""

        self._exact_delivery(request)
        if (
            self._delivery_request_sha256 is not None
            or not hasattr(writer, "write_slot")
            or not _TIMESTAMP.fullmatch(completed_at)
        ):
            raise ExecutorTransportError("material_delivery")
        if type(writer) is ExecutorRequestFrameWriter:
            transport_request = writer.transport_request
            if (
                transport_request.operation_scope != request.operation_scope
                or transport_request.operation_id != request.operation_id
                or transport_request.journal_uuid != request.journal_uuid
                or transport_request.request_nonce_sha256 != request.request_nonce_sha256
                or transport_request.channel_binding_sha256 != request.channel_binding_sha256
                or transport_request.session_binding_sha256 != request.session_binding_sha256
                or transport_request.slots != request.slots
            ):
                raise ExecutorTransportError("material_delivery")
        elif self._store is None:
            # The production lease may write only through the internal framed
            # writer produced after the client has verified a signed request.
            raise ExecutorTransportError("material_delivery")
        # Claim this lease before its first Keychain lookup.  A partial write
        # is intentionally unretryable and must require a fresh authorization
        # and fresh Keychain redelivery.
        self._delivery_request_sha256 = canonical_sha256(request)
        policy_specs = {item.purpose.value: item for item in self._policy.materials}
        fingerprints = self._attestation.fingerprint_by_reference()
        receipts: list[SecretDeliverySlotReceiptV1] = []
        store = self._store_or_fail()
        try:
            for slot in request.slots:
                spec = policy_specs.get(slot.purpose)
                if (
                    spec is None
                    or spec.purpose
                    in {
                        ProviderMaterialPurpose.COMMITMENT_HMAC,
                        ProviderMaterialPurpose.BACKUP_ENCRYPTION,
                        ProviderMaterialPurpose.TLS_TRUST_ANCHOR,
                    }
                    or spec.reference.reference_sha256 != slot.reference_sha256
                    or spec.reference.provider != "macos_keychain"
                    or spec.format.value != slot.format
                    or spec.value_min_bytes != slot.encoded_byte_count
                    or spec.value_max_bytes != slot.encoded_byte_count
                ):
                    raise ExecutorTransportError("material_delivery")
                value: bytearray | None = None
                try:
                    value = store.read_if_present(spec.reference.service, spec.reference.account)
                except Exception:
                    raise ExecutorTransportError("keychain_read") from None
                if type(value) is not bytearray:
                    raise ExecutorTransportError("keychain_read")
                try:
                    _validate_material_value(spec.format, value)
                    expected = fingerprints.get(spec.reference.reference_sha256)
                    if expected is None or not hmac.compare_digest(_digest(value), expected):
                        raise ExecutorTransportError("material_fingerprint")
                    writer.write_slot(slot, memoryview(value))
                except ExecutorTransportError:
                    raise
                except Exception:
                    raise ExecutorTransportError("material_writer") from None
                finally:
                    if type(value) is bytearray:
                        _zeroize(value)
                receipts.append(
                    SecretDeliverySlotReceiptV1(
                        purpose=slot.purpose,
                        reference_sha256=slot.reference_sha256,
                        sink=slot.sink,
                        target_processes=slot.target_processes,
                        delivered=True,
                    )
                )
        except ExecutorTransportError:
            raise
        except Exception:
            raise ExecutorTransportError("material_delivery") from None
        return SecretDeliveryReceiptV1(
            schema_version="rsd.secret-delivery-receipt.v1",
            operation_scope=request.operation_scope,
            operation_id=request.operation_id,
            journal_uuid=request.journal_uuid,
            request_nonce_sha256=request.request_nonce_sha256,
            channel_binding_sha256=request.channel_binding_sha256,
            session_binding_sha256=request.session_binding_sha256,
            slots=cast(
                tuple[
                    SecretDeliverySlotReceiptV1,
                    SecretDeliverySlotReceiptV1,
                    SecretDeliverySlotReceiptV1,
                    SecretDeliverySlotReceiptV1,
                    SecretDeliverySlotReceiptV1,
                ],
                tuple(receipts),
            ),
            completed_at=completed_at,
        )

    def close(self) -> None:
        self._closed = True


class MacOSKeychainSecretMaterialCapability:
    """Acquire one value-free Keychain delivery lease with no ambient lookup."""

    def __init__(self, lease: MacOSKeychainSecretMaterialLease) -> None:
        if type(lease) is not MacOSKeychainSecretMaterialLease:
            raise ExecutorTransportError("material_capability")
        self._lease = lease

    @contextmanager
    def acquire(
        self,
        policy: SecretCapabilityPolicyV1,
        handling_policy: SecretHandlingPolicyV1,
    ) -> Iterator[SecretMaterialLease]:
        if self._lease.inspect(policy, handling_policy) is None:
            raise ExecutorTransportError("material_capability")
        try:
            yield self._lease
        finally:
            self._lease.close()


def load_keychain_secret_material_capability(
    paths: ProviderMaterialArtifactPaths,
    *,
    signer: TrustedEd25519SignerV1,
    issuer: TrustedEd25519SignerV1,
    allocation_intent: AllocationIntentV2,
    expected_disposal_owner: str,
    expected_approver_identity: str,
    artifacts: VerifiedExecutorTransportArtifactsV2,
    capability_policy: SecretCapabilityPolicyV1,
    handling_policy: SecretHandlingPolicyV1,
) -> MacOSKeychainSecretMaterialCapability:
    """Load a verified terminal Keychain material bundle for one transport.

    This production boundary has no caller-selected values, fingerprints,
    clock, or store.  It verifies persistent signed provider artifacts before
    a lease can read even one Keychain row.
    """

    if (
        type(paths) is not ProviderMaterialArtifactPaths
        or type(signer) is not TrustedEd25519SignerV1
        or type(issuer) is not TrustedEd25519SignerV1
        or type(allocation_intent) is not AllocationIntentV2
        or type(artifacts) is not VerifiedExecutorTransportArtifactsV2
        or type(expected_disposal_owner) is not str
        or type(expected_approver_identity) is not str
    ):
        raise ExecutorTransportError("material_lease")
    try:
        policy, _genesis, attestation = load_verified_provider_material_bundle(
            paths,
            signer=signer,
            signer_genesis=artifacts.signer_genesis,
            issuer=issuer,
            allocation_intent=allocation_intent,
            expected_disposal_owner=expected_disposal_owner,
            expected_approver_identity=expected_approver_identity,
        )
        provider_identity = canonical_sha256(attestation)
        capability, handling = _verify_secret_delivery_policies(
            capability_policy,
            handling_policy,
            signer=signer,
            artifacts=artifacts,
            provider_identity_sha256=provider_identity,
        )
        lease = MacOSKeychainSecretMaterialLease(
            policy=policy,
            attestation=attestation,
            capability_policy=capability,
            handling_policy=handling,
            _capability=_MATERIAL_LEASE_CAPABILITY,
        )
    except (ExecutorTransportError, ProviderCryptoError, ValueError, TypeError):
        raise ExecutorTransportError("material_lease") from None
    return MacOSKeychainSecretMaterialCapability(lease)


def _keychain_secret_material_lease_for_test(
    *,
    policy: ProviderMaterialPolicyV2,
    attestation: ProviderFingerprintAttestationV2,
    capability_policy: SecretCapabilityPolicyV1,
    handling_policy: SecretHandlingPolicyV1,
    store: _KeychainValueStore,
) -> MacOSKeychainSecretMaterialLease:
    """Internal deterministic seam; installed entry points cannot select it."""

    return MacOSKeychainSecretMaterialLease(
        policy=policy,
        attestation=attestation,
        capability_policy=capability_policy,
        handling_policy=handling_policy,
        _capability=_MATERIAL_LEASE_CAPABILITY,
        _store=store,
    )


@dataclass(frozen=True, slots=True)
class SecureShellSessionBindingsV2:
    """Value-free session bindings exposed to Phase-B authorization only."""

    executor_id: str
    host_fingerprint_sha256: str
    channel_binding_sha256: str
    session_binding_sha256: str
    attestation_key_fingerprint_sha256: str


class _SessionLease:
    def __init__(self, provenance: SecureShellSessionBindingsV2, *, expected_start_id: str) -> None:
        self._provenance = provenance
        self._expected_start_id = expected_start_id
        self._closed = False

    def inspect(self, intent: object) -> RemoteExecutorSessionProvenance | None:
        if self._closed or getattr(intent, "start_operation_id", None) != self._expected_start_id:
            return None
        return RemoteExecutorSessionProvenance(
            executor_id=self._provenance.executor_id,
            host_fingerprint_sha256=self._provenance.host_fingerprint_sha256,
            channel_binding_sha256=self._provenance.channel_binding_sha256,
            session_binding_sha256=self._provenance.session_binding_sha256,
            attestation_key_fingerprint_sha256=(
                self._provenance.attestation_key_fingerprint_sha256
            ),
        )

    def recheck(self, intent: object) -> RemoteExecutorSessionProvenance | None:
        return self.inspect(intent)

    def close(self) -> None:
        self._closed = True


class _StaticRemoteExecutorSessionCapability:
    """Internal deterministic test seam; installed APIs cannot select it."""

    def __init__(self, provenance: SecureShellSessionBindingsV2) -> None:
        self._provenance = provenance

    @contextmanager
    def acquire(self, intent: object) -> Iterator[RemoteExecutorSessionLease]:
        operation_id = getattr(intent, "start_operation_id", None)
        if type(operation_id) is not str or re.fullmatch(_UUID, operation_id) is None:
            raise ExecutorTransportError("remote_session")
        lease = _SessionLease(self._provenance, expected_start_id=operation_id)
        try:
            yield lease
        finally:
            lease.close()


__all__ = [
    "ExecutorAllocationTransportReceiptV1",
    "ExecutorAllocationTransportRequestV1",
    "ExecutorClientHelloV2",
    "ExecutorEngineOperationKindV1",
    "ExecutorEngineOperationPlanV1",
    "ExecutorEngineOperationStepV1",
    "ExecutorEngineOperationTargetV1",
    "ExecutorHelloV2",
    "ExecutorTransportArtifactPathsV2",
    "ExecutorTransportError",
    "ExecutorTransportMessageKind",
    "ExecutorTransportPolicyV2",
    "ExecutorTransportRequestV2",
    "MacOSKeychainSecretMaterialCapability",
    "MacOSSecureShellClient",
    "RemoteEffectAuthorizationWitnessV1",
    "RemoteExecutorTransportClient",
    "SecretFrameWriter",
    "SecureShellIdentityReferenceV1",
    "SecureShellLaunchSpec",
    "SecureShellProcessSession",
    "SecureShellSessionBindingsV2",
    "VerifiedExecutorTransportArtifactsV2",
    "executor_allocation_transport_receipt_message",
    "executor_allocation_transport_request_message",
    "executor_engine_operation_plan_sha256",
    "executor_engine_operation_plan_v1",
    "executor_hello_message",
    "executor_transport_policy_message",
    "load_keychain_secret_material_capability",
    "load_verified_executor_transport_artifacts",
    "remote_effect_authorization_witness_message",
    "request_from_delivery",
    "sign_executor_allocation_transport_request",
    "sign_executor_transport_request",
    "verify_executor_allocation_transport_receipt",
    "verify_executor_allocation_transport_request",
    "verify_executor_hello",
    "verify_executor_transport_artifacts",
    "verify_executor_transport_policy",
    "verify_executor_transport_receipt",
    "verify_executor_transport_request",
    "verify_remote_effect_authorization_witness",
]
