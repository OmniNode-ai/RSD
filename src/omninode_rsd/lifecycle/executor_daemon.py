"""Offline-safe remote executor daemon/session primitives.

This module provides a UDS-only session state machine and a typed injected
backend contract.  It intentionally does not implement Docker, PostgreSQL, or
any service mutation.  Its durable local journal is a replay guard, not a
replacement for the external Phase-B replay authority.
"""

from __future__ import annotations

import base64
import binascii
import ctypes
import fcntl
import hashlib
import hmac
import json
import os
import resource
import select
import socket
import sqlite3
import stat
import struct
import sys
import time
from collections.abc import Callable, Iterator
from contextlib import contextmanager, suppress
from dataclasses import dataclass
from datetime import UTC, datetime, timedelta
from enum import StrEnum
from pathlib import Path
from threading import Lock
from typing import TYPE_CHECKING, Final, Literal, Protocol, cast
from uuid import uuid4

from cryptography.exceptions import InvalidSignature
from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey, Ed25519PublicKey
from pydantic import BaseModel, ConfigDict, Field, ValidationError, field_validator, model_validator

from omninode_rsd.lifecycle.executor_transport import (
    ExecutorAllocationTransportReceiptV1,
    ExecutorAllocationTransportRequestV1,
    ExecutorClientHelloV2,
    ExecutorEngineOperationKindV1,
    ExecutorEngineOperationPlanV1,
    ExecutorEngineOperationTargetV1,
    ExecutorHelloV2,
    ExecutorTransportArtifactPathsV2,
    ExecutorTransportError,
    ExecutorTransportPolicyV2,
    ExecutorTransportReceiptV2,
    ExecutorTransportRequestV2,
    VerifiedExecutorTransportArtifactsV2,
    executor_allocation_transport_receipt_message,
    executor_engine_operation_plan_v1,
    executor_hello_message,
    executor_transport_receipt_message,
    load_verified_executor_transport_artifacts,
    transport_delivery_binding_sha256,
    verify_executor_allocation_transport_request,
    verify_executor_transport_request,
)
from omninode_rsd.lifecycle.infisical_disposable import (
    AllocatedResourceSetV2,
    AllocationExecutorReceiptV1,
    DockerImageLocalEvidenceV1,
    EngineIdentityObservationV1,
    ExecutorIdentityV1,
    MaterializationExecutorReceiptV1,
    SecretDeliverySlotV1,
    StartRuntimeExecutorReceiptV2,
    allocation_executor_receipt_message,
    canonical_sha256,
    materialization_executor_receipt_message,
    start_runtime_executor_receipt_message,
)
from omninode_rsd.lifecycle.provider_crypto import SignerGenesisV1
from omninode_rsd.lifecycle.transport import (
    FRAME_HEADER_BYTES,
    FRAME_MAGIC,
    FRAME_VERSION,
    MAX_CHUNK_BYTES,
    MAX_CHUNKS,
    MAX_METADATA_BYTES,
    MAX_TOTAL_BYTES,
    CanonicalFrameReader,
    CanonicalFrameWriter,
    FrameByteReader,
    FrameByteWriter,
    TransportError,
)

if TYPE_CHECKING:
    from omninode_rsd.lifecycle.executor_allocation import AllocationReconciliationReceiptV1

_SHA256: Final = r"^[0-9a-f]{64}$"
_UUID: Final = r"^[0-9a-f]{8}-[0-9a-f]{4}-[1-5][0-9a-f]{3}-[89ab][0-9a-f]{3}-[0-9a-f]{12}$"
_MAX_JOURNAL_BYTES: Final = 2_097_152
_JOURNAL_SCHEMA: Final = "rsd-executor-session-journal-v5"
_JOURNAL_SCHEMA_SHA256: Final = hashlib.sha256(_JOURNAL_SCHEMA.encode("ascii")).hexdigest()
_HELLO_TTL: Final = timedelta(seconds=60)
_RECOVERY_DOMAIN: Final = b"omninode-rsd.executor-recovery-receipt.ed25519.v2\x00"
_ENGINE_OPERATION_JOURNAL_DOMAIN: Final = b"omninode-rsd.executor-engine-operations.v1\x00"
_FRAME_HEADER: Final = struct.Struct("!4sBBII")
_RELAY_EOF_FRAME: Final = _FRAME_HEADER.pack(FRAME_MAGIC, FRAME_VERSION, 3, 0, 0)
_DAEMON_ENGINE_CAPABILITY: Final = object()
_ATTESTATION_SIGNER_CAPABILITY: Final = object()
_SYSTEMD_LISTEN_FD: Final = 3
_SYSTEMD_LISTEN_FD_COUNT: Final = "1"
_SYSTEMD_LISTEN_FD_NAME: Final = "omninode-rsd-executor"
_SOCK_TYPE_MASK: Final = 0xF


class ExecutorDaemonError(RuntimeError):
    """Value-redacted daemon/session failure."""

    def __init__(self, phase: str) -> None:
        self.phase = phase
        super().__init__(f"executor daemon failed at phase: {phase}")


class _Model(BaseModel):
    model_config = ConfigDict(extra="forbid", frozen=True, strict=True, validate_default=True)


def _system_utc_clock() -> datetime:
    """Production daemon clock; unit tests patch this module-local function."""

    return datetime.now(UTC)


def _timestamp(value: str) -> datetime:
    if type(value) is not str or not value.endswith("Z"):
        raise ValueError("timestamp is invalid")
    try:
        result = datetime.fromisoformat(value.removesuffix("Z") + "+00:00")
    except ValueError:
        raise ValueError("timestamp is invalid") from None
    if result.tzinfo is None or result.utcoffset() is None:
        raise ValueError("timestamp is invalid")
    return result.astimezone(UTC)


def _canonical_json(value: object) -> bytes:
    try:
        return json.dumps(value, allow_nan=False, sort_keys=True, separators=(",", ":")).encode(
            "utf-8"
        )
    except (TypeError, ValueError):
        raise ExecutorDaemonError("canonical_encoding") from None


def _digest(value: bytes | bytearray | memoryview) -> str:
    return hashlib.sha256(value).hexdigest()


def _zeroize(value: bytearray) -> None:
    value[:] = b"\x00" * len(value)


class ExecutorSessionStateV2(StrEnum):
    """Durable one-way session states; ambiguous states never auto-retry."""

    ALLOCATION_CLAIMED = "allocation_claimed"
    ALLOCATED = "allocated"
    ALLOCATION_AMBIGUOUS = "allocation_ambiguous"
    MATERIALIZE_CLAIMED = "materialize_claimed"
    MATERIALIZED = "materialized"
    START_CLAIMED = "start_claimed"
    START_AMBIGUOUS = "start_ambiguous"
    STARTED = "started"
    ABANDONED = "abandoned"


class ExecutorEngineOperationStateV1(StrEnum):
    """One-way durable state for a filtered Engine/PostgreSQL operation."""

    CLAIMED = "claimed"
    COMPLETED = "completed"
    AMBIGUOUS = "ambiguous"


@dataclass(frozen=True, slots=True)
class ExecutorEngineOperationClaimV1:
    """Opaque value-free claim returned to the injected future backend."""

    sequence: int
    operation_kind: ExecutorEngineOperationKindV1
    target: ExecutorEngineOperationTargetV1


class ExecutorEngineOperationRecorder(Protocol):
    """Bounded per-effect crash journal; raw engine data is never accepted."""

    def remaining_operations(self) -> int: ...

    def claim_next(self) -> ExecutorEngineOperationClaimV1: ...

    def complete(
        self,
        claim: ExecutorEngineOperationClaimV1,
        *,
        filtered_projection_sha256: str,
    ) -> None: ...

    def completed_projection_sha256(self) -> str: ...


class ExecutorRecoveryReceiptV2(_Model):
    """Typed signed operator outcome for an otherwise ambiguous session."""

    schema_version: Literal["rsd.executor-recovery-receipt.v2"]
    allocation_intent_sha256: str = Field(pattern=_SHA256)
    operation_scope: Literal[
        "allocate_isolated_empty_resources_v2",
        "materialize_and_start_runtime_v1",
        "start_runtime_v2",
    ]
    operation_id: str = Field(pattern=_UUID)
    request_id: str = Field(pattern=_UUID)
    journal_uuid: str = Field(pattern=_UUID)
    executor_id: str = Field(pattern=r"^[A-Za-z][A-Za-z0-9_.-]{0,127}$")
    executor_policy_sha256: str = Field(pattern=_SHA256)
    session_binding_sha256: str = Field(pattern=_SHA256)
    request_metadata_sha256: str = Field(pattern=_SHA256)
    outcome: Literal["abandoned"]
    outcome_receipt_sha256: str = Field(pattern=_SHA256)
    completed_at: str
    signer_key_id: str = Field(pattern=r"^[A-Za-z][A-Za-z0-9_.-]{0,127}$")
    signature_base64: str = Field(min_length=4, max_length=256)

    @field_validator("completed_at")
    @classmethod
    def canonical_time(cls, value: str) -> str:
        _timestamp(value)
        return value

    @model_validator(mode="after")
    def signed_outcome(self) -> ExecutorRecoveryReceiptV2:
        try:
            signature = base64.b64decode(self.signature_base64, validate=True)
        except (binascii.Error, ValueError):
            raise ValueError("executor recovery receipt is invalid") from None
        if (
            base64.b64encode(signature).decode("ascii") != self.signature_base64
            or len(signature) != 64
        ):
            raise ValueError("executor recovery receipt is invalid")
        return self


def _recovery_receipt_message(receipt: ExecutorRecoveryReceiptV2) -> bytes:
    """Build the exact domain-separated recovery signature preimage."""

    if type(receipt) is not ExecutorRecoveryReceiptV2:
        raise ExecutorDaemonError("session_recovery")
    try:
        return _RECOVERY_DOMAIN + _canonical_json(
            receipt.model_dump(mode="json", exclude={"signature_base64"})
        )
    except Exception:
        raise ExecutorDaemonError("session_recovery") from None


def verify_executor_recovery_receipt(
    receipt: ExecutorRecoveryReceiptV2,
    *,
    artifacts: VerifiedExecutorTransportArtifactsV2,
) -> ExecutorRecoveryReceiptV2:
    """Verify an operator decision under the verified transport signer anchor.

    Recovery is deliberately not an arbitrary ``key()`` protocol. The exact
    public key is reconstructed from the previously signature-verified signer
    genesis held by the sealed transport artifact bundle. The receipt also
    carries the policy and session commitments that the durable journal checks
    again immediately before its one-way ``ABANDONED`` transition.
    """

    if (
        type(receipt) is not ExecutorRecoveryReceiptV2
        or type(artifacts) is not VerifiedExecutorTransportArtifactsV2
    ):
        raise ExecutorDaemonError("session_recovery")
    try:
        canonical = ExecutorRecoveryReceiptV2.model_validate_json(
            _canonical_json(receipt.model_dump(mode="json"))
        )
        genesis = artifacts.signer_genesis
        policy = artifacts.policy
        encoded_key = genesis.public_key_base64
        if type(encoded_key) is not str:
            raise ValueError
        public_key = base64.b64decode(encoded_key, validate=True)
        if (
            canonical != receipt
            or base64.b64encode(public_key).decode("ascii") != encoded_key
            or len(public_key) != 32
            or _digest(public_key) != genesis.public_key_fingerprint_sha256
            or receipt.signer_key_id != genesis.key_id
            or receipt.allocation_intent_sha256 != genesis.allocation_intent_sha256
            or receipt.allocation_intent_sha256 != policy.allocation_intent_sha256
            or receipt.executor_id != policy.executor_id
            or receipt.executor_policy_sha256 != policy.policy_sha256()
        ):
            raise ValueError
        Ed25519PublicKey.from_public_bytes(public_key).verify(
            base64.b64decode(receipt.signature_base64, validate=True),
            _recovery_receipt_message(receipt),
        )
    except (
        InvalidSignature,
        ValueError,
        TypeError,
        binascii.Error,
        ValidationError,
        AttributeError,
    ):
        raise ExecutorDaemonError("session_recovery") from None
    return receipt


_JOURNAL_DDL: Final = """
CREATE TABLE metadata (
    singleton INTEGER PRIMARY KEY NOT NULL CHECK (singleton = 1),
    schema_sha256 TEXT NOT NULL,
    journal_id TEXT NOT NULL
) WITHOUT ROWID;
CREATE TABLE sessions (
    operation_id TEXT PRIMARY KEY NOT NULL,
    request_id TEXT NOT NULL UNIQUE,
    predecessor_operation_id TEXT,
    request_sha256 TEXT NOT NULL,
    allocation_intent_sha256 TEXT NOT NULL,
    operation_scope TEXT NOT NULL,
    executor_id TEXT NOT NULL,
    executor_policy_sha256 TEXT NOT NULL,
    session_binding_sha256 TEXT NOT NULL,
    state TEXT NOT NULL,
    delivery_binding_sha256 TEXT,
    executor_receipt_sha256 TEXT,
    recovery_receipt_sha256 TEXT,
    created_at TEXT NOT NULL,
    updated_at TEXT NOT NULL
) WITHOUT ROWID;
CREATE TABLE engine_operations (
    operation_id TEXT NOT NULL,
    request_id TEXT NOT NULL,
    sequence INTEGER NOT NULL,
    operation_kind TEXT NOT NULL,
    operation_target TEXT NOT NULL,
    filtered_projection_sha256 TEXT,
    state TEXT NOT NULL,
    created_at TEXT NOT NULL,
    updated_at TEXT NOT NULL,
    PRIMARY KEY (operation_id, sequence),
    FOREIGN KEY (operation_id) REFERENCES sessions(operation_id)
) WITHOUT ROWID;
"""


def _normalized_schema_sql(value: object) -> str:
    """Compare SQLite's durable schema text without whitespace variance."""

    if type(value) is not str:
        raise ExecutorDaemonError("session_journal")
    return " ".join(value.split())


_EXPECTED_JOURNAL_TABLE_SQL: Final[tuple[tuple[str, str], ...]] = (
    (
        "engine_operations",
        _normalized_schema_sql(
            """
            CREATE TABLE engine_operations (
                operation_id TEXT NOT NULL,
                request_id TEXT NOT NULL,
                sequence INTEGER NOT NULL,
                operation_kind TEXT NOT NULL,
                operation_target TEXT NOT NULL,
                filtered_projection_sha256 TEXT,
                state TEXT NOT NULL,
                created_at TEXT NOT NULL,
                updated_at TEXT NOT NULL,
                PRIMARY KEY (operation_id, sequence),
                FOREIGN KEY (operation_id) REFERENCES sessions(operation_id)
            ) WITHOUT ROWID
            """
        ),
    ),
    (
        "metadata",
        _normalized_schema_sql(
            """
            CREATE TABLE metadata (
                singleton INTEGER PRIMARY KEY NOT NULL CHECK (singleton = 1),
                schema_sha256 TEXT NOT NULL,
                journal_id TEXT NOT NULL
            ) WITHOUT ROWID
            """
        ),
    ),
    (
        "sessions",
        _normalized_schema_sql(
            """
            CREATE TABLE sessions (
                operation_id TEXT PRIMARY KEY NOT NULL,
                request_id TEXT NOT NULL UNIQUE,
                predecessor_operation_id TEXT,
                request_sha256 TEXT NOT NULL,
                allocation_intent_sha256 TEXT NOT NULL,
                operation_scope TEXT NOT NULL,
                executor_id TEXT NOT NULL,
                executor_policy_sha256 TEXT NOT NULL,
                session_binding_sha256 TEXT NOT NULL,
                state TEXT NOT NULL,
                delivery_binding_sha256 TEXT,
                executor_receipt_sha256 TEXT,
                recovery_receipt_sha256 TEXT,
                created_at TEXT NOT NULL,
                updated_at TEXT NOT NULL
            ) WITHOUT ROWID
            """
        ),
    ),
)


@dataclass(frozen=True, slots=True)
class _SessionRequestBinding:
    """The common value-free replay identity accepted by the durable journal."""

    operation_id: str
    request_id: str
    journal_uuid: str
    allocation_intent_sha256: str
    operation_scope: str
    executor_id: str
    executor_policy_sha256: str
    session_binding_sha256: str
    request_sha256: str


def _session_binding(
    request: ExecutorTransportRequestV2 | ExecutorAllocationTransportRequestV1,
) -> _SessionRequestBinding:
    """Normalize only already-verified requests for the local journal.

    Allocation intentionally uses its own field spelling in the public wire
    model.  The journal nevertheless keys every scope by one canonical
    operation ID and never accepts a caller-selected SQL row shape.
    """

    if type(request) is ExecutorTransportRequestV2:
        operation_id = request.operation_id
    elif type(request) is ExecutorAllocationTransportRequestV1:
        operation_id = request.allocation_operation_id
    else:
        raise ExecutorDaemonError("session_claim")
    values = (
        operation_id,
        request.request_id,
        request.journal_uuid,
        request.allocation_intent_sha256,
        request.operation_scope,
        request.executor_id,
        request.executor_policy_sha256,
        request.session_binding_sha256,
        request.metadata_sha256(),
    )
    if any(type(value) is not str for value in values):
        raise ExecutorDaemonError("session_claim")
    return _SessionRequestBinding(*values)


def _strict_file(path: Path, *, phase: str) -> os.stat_result:
    try:
        node = os.lstat(path)
        if (
            not stat.S_ISREG(node.st_mode)
            or node.st_uid != os.geteuid()
            or stat.S_IMODE(node.st_mode) & 0o077
            or node.st_nlink != 1
        ):
            raise ValueError
        return node
    except Exception:
        raise ExecutorDaemonError(phase) from None


def _strict_parent(path: Path, *, phase: str) -> None:
    try:
        node = os.lstat(path.parent)
        if (
            not stat.S_ISDIR(node.st_mode)
            or node.st_uid != os.geteuid()
            or stat.S_IMODE(node.st_mode) & 0o077
            or node.st_nlink < 2
        ):
            raise ValueError
    except Exception:
        raise ExecutorDaemonError(phase) from None


def _sync_journal(path: Path) -> None:
    """Synchronize a provisioned or committed journal name and its parent."""

    try:
        descriptor = os.open(path, os.O_RDONLY | getattr(os, "O_NOFOLLOW", 0))
        try:
            opened = os.fstat(descriptor)
            expected = _strict_file(path, phase="session_journal")
            if (opened.st_dev, opened.st_ino, opened.st_nlink) != (
                expected.st_dev,
                expected.st_ino,
                expected.st_nlink,
            ):
                raise ValueError
            os.fsync(descriptor)
        finally:
            os.close(descriptor)
        parent_descriptor = os.open(path.parent, os.O_RDONLY | getattr(os, "O_DIRECTORY", 0))
        try:
            os.fsync(parent_descriptor)
        finally:
            os.close(parent_descriptor)
    except Exception:
        raise ExecutorDaemonError("session_journal") from None


class ExecutorSessionJournal:
    """Durable local session/replay state with explicit one-time provisioning."""

    def __init__(self, path: Path) -> None:
        if (
            not isinstance(path, Path)
            or not path.is_absolute()
            or os.path.normpath(os.fspath(path)) != os.fspath(path)
        ):
            raise ExecutorDaemonError("session_journal")
        self._path = path
        self._lease_path = path.with_name(f"{path.name}.lease")
        self._lock = Lock()

    @classmethod
    def provision(cls, path: Path, *, journal_id: str) -> ExecutorSessionJournal:
        """Create one owner-only journal; ordinary session paths never create it."""

        if (
            not isinstance(path, Path)
            or type(journal_id) is not str
            or re_fullmatch(_UUID, journal_id) is None
            or not path.is_absolute()
        ):
            raise ExecutorDaemonError("session_journal")
        _strict_parent(path, phase="session_journal")
        try:
            descriptor = os.open(
                path,
                os.O_CREAT | os.O_EXCL | os.O_WRONLY | getattr(os, "O_NOFOLLOW", 0),
                0o600,
            )
            os.close(descriptor)
            lease_descriptor = os.open(
                path.with_name(f"{path.name}.lease"),
                os.O_CREAT | os.O_EXCL | os.O_WRONLY | getattr(os, "O_NOFOLLOW", 0),
                0o600,
            )
            os.close(lease_descriptor)
            connection = sqlite3.connect(path, isolation_level=None)
            try:
                connection.execute("PRAGMA synchronous = FULL")
                connection.executescript(_JOURNAL_DDL)
                connection.execute(
                    "INSERT INTO metadata(singleton, schema_sha256, journal_id) VALUES (1, ?, ?)",
                    (_JOURNAL_SCHEMA_SHA256, journal_id),
                )
                connection.execute("PRAGMA wal_checkpoint(FULL)")
            finally:
                connection.close()
            _sync_journal(path)
        except Exception:
            raise ExecutorDaemonError("session_journal") from None
        return cls(path)

    def _connection(self) -> sqlite3.Connection:
        _strict_parent(self._path, phase="session_journal")
        before = _strict_file(self._path, phase="session_journal")
        _strict_file(self._lease_path, phase="session_journal")
        try:
            connection = sqlite3.connect(self._path, isolation_level=None, timeout=0.0)
            connection.execute("PRAGMA synchronous = FULL")
            connection.execute("PRAGMA foreign_keys = ON")
            connection.execute("PRAGMA trusted_schema = OFF")
            row = connection.execute(
                "SELECT schema_sha256, journal_id FROM metadata WHERE singleton = 1"
            ).fetchone()
            objects = connection.execute(
                "SELECT type, name, sql FROM sqlite_master "
                "WHERE name NOT LIKE 'sqlite_%' ORDER BY type, name"
            ).fetchall()
            after = _strict_file(self._path, phase="session_journal")
            _strict_parent(self._path, phase="session_journal")
            if (
                row is None
                or row[0] != _JOURNAL_SCHEMA_SHA256
                or re_fullmatch(_UUID, row[1]) is None
                or tuple(
                    (name, _normalized_schema_sql(sql))
                    for object_type, name, sql in objects
                    if object_type == "table"
                )
                != _EXPECTED_JOURNAL_TABLE_SQL
                or tuple((object_type, name) for object_type, name, _ in objects)
                != (
                    ("table", "engine_operations"),
                    ("table", "metadata"),
                    ("table", "sessions"),
                )
                or (before.st_dev, before.st_ino, before.st_nlink)
                != (after.st_dev, after.st_ino, after.st_nlink)
            ):
                connection.close()
                raise ValueError
            return connection
        except ExecutorDaemonError:
            raise
        except Exception:
            raise ExecutorDaemonError("session_journal") from None

    def _transaction(self, action: Callable[[sqlite3.Connection], None]) -> None:
        with self._lock:
            connection = self._connection()
            try:
                connection.execute("BEGIN IMMEDIATE")
                action(connection)
                connection.execute("COMMIT")
                _sync_journal(self._path)
            except ExecutorDaemonError:
                with suppress(Exception):
                    connection.execute("ROLLBACK")
                raise
            except Exception:
                with suppress(Exception):
                    connection.execute("ROLLBACK")
                raise ExecutorDaemonError("session_journal") from None
            finally:
                connection.close()

    def state(self, operation_id: str) -> ExecutorSessionStateV2 | None:
        if type(operation_id) is not str:
            raise ExecutorDaemonError("session_journal")
        with self._lock:
            connection = self._connection()
            try:
                row = connection.execute(
                    "SELECT state FROM sessions WHERE operation_id = ?", (operation_id,)
                ).fetchone()
            except Exception:
                raise ExecutorDaemonError("session_journal") from None
            finally:
                connection.close()
        if row is None:
            return None
        try:
            return ExecutorSessionStateV2(row[0])
        except (TypeError, ValueError):
            raise ExecutorDaemonError("session_journal") from None

    def engine_operation_recorder(
        self,
        request: ExecutorTransportRequestV2 | ExecutorAllocationTransportRequestV1,
    ) -> ExecutorEngineOperationRecorder:
        """Return the sole bounded checkpoint writer for one claimed effect."""

        binding = _session_binding(request)
        try:
            plan = executor_engine_operation_plan_v1(
                operation_scope=request.operation_scope,
                operation_id=binding.operation_id,
            )
        except ExecutorTransportError:
            raise ExecutorDaemonError("engine_operation") from None
        if request.authorization_witness.engine_operation_plan_sha256 != plan.plan_sha256():
            raise ExecutorDaemonError("engine_operation")
        return _ExecutorEngineOperationRecorder(self, binding, plan)

    def _claim_engine_operation(
        self,
        binding: _SessionRequestBinding,
        plan: ExecutorEngineOperationPlanV1,
    ) -> ExecutorEngineOperationClaimV1:
        if (
            type(plan) is not ExecutorEngineOperationPlanV1
            or plan.operation_scope != binding.operation_scope
            or plan.operation_id != binding.operation_id
        ):
            raise ExecutorDaemonError("engine_operation")
        now = _system_utc_clock().isoformat(timespec="seconds").replace("+00:00", "Z")
        sequence: int | None = None
        expected_kind: ExecutorEngineOperationKindV1 | None = None
        expected_target: ExecutorEngineOperationTargetV1 | None = None

        def action(connection: sqlite3.Connection) -> None:
            nonlocal expected_kind, expected_target, sequence
            self._require_journal_uuid(connection, binding)
            expected_state = (
                ExecutorSessionStateV2.ALLOCATION_CLAIMED.value
                if binding.operation_scope == "allocate_isolated_empty_resources_v2"
                else ExecutorSessionStateV2.START_CLAIMED.value
            )
            parent = connection.execute(
                "SELECT state FROM sessions WHERE operation_id = ? AND request_id = ?",
                (binding.operation_id, binding.request_id),
            ).fetchone()
            if parent != (expected_state,):
                raise ExecutorDaemonError("engine_operation")
            row = connection.execute(
                "SELECT COALESCE(MAX(sequence), 0) FROM engine_operations WHERE operation_id = ?",
                (binding.operation_id,),
            ).fetchone()
            if row is None or type(row[0]) is not int:
                raise ExecutorDaemonError("engine_operation")
            sequence = row[0] + 1
            if sequence > len(plan.operations):
                raise ExecutorDaemonError("engine_operation")
            previous = connection.execute(
                """
                SELECT state FROM engine_operations
                WHERE operation_id = ? AND request_id = ? AND sequence = ?
                """,
                (binding.operation_id, binding.request_id, sequence - 1),
            ).fetchone()
            if sequence > 1 and previous != (ExecutorEngineOperationStateV1.COMPLETED.value,):
                raise ExecutorDaemonError("engine_operation")
            expected = plan.operations[sequence - 1]
            expected_kind = expected.operation_kind
            expected_target = expected.target
            connection.execute(
                """
                INSERT INTO engine_operations(
                    operation_id, request_id, sequence, operation_kind, operation_target,
                    filtered_projection_sha256, state, created_at, updated_at
                ) VALUES (?, ?, ?, ?, ?, NULL, ?, ?, ?)
                """,
                (
                    binding.operation_id,
                    binding.request_id,
                    sequence,
                    expected.operation_kind.value,
                    expected.target.value,
                    ExecutorEngineOperationStateV1.CLAIMED.value,
                    now,
                    now,
                ),
            )

        self._transaction(action)
        if sequence is None or expected_kind is None or expected_target is None:
            raise ExecutorDaemonError("engine_operation")
        return ExecutorEngineOperationClaimV1(
            sequence=sequence,
            operation_kind=expected_kind,
            target=expected_target,
        )

    def _complete_engine_operation(
        self,
        binding: _SessionRequestBinding,
        plan: ExecutorEngineOperationPlanV1,
        claim: ExecutorEngineOperationClaimV1,
        *,
        filtered_projection_sha256: str,
    ) -> None:
        if (
            type(claim) is not ExecutorEngineOperationClaimV1
            or type(claim.operation_kind) is not ExecutorEngineOperationKindV1
            or type(claim.target) is not ExecutorEngineOperationTargetV1
            or type(claim.sequence) is not int
            or claim.sequence < 1
            or claim.sequence > len(plan.operations)
            or re_fullmatch(_SHA256, filtered_projection_sha256) is None
        ):
            raise ExecutorDaemonError("engine_operation")
        expected = plan.operations[claim.sequence - 1]
        if (
            claim.operation_kind is not expected.operation_kind
            or claim.target is not expected.target
        ):
            raise ExecutorDaemonError("engine_operation")
        now = _system_utc_clock().isoformat(timespec="seconds").replace("+00:00", "Z")

        def action(connection: sqlite3.Connection) -> None:
            self._require_journal_uuid(connection, binding)
            result = connection.execute(
                """
                UPDATE engine_operations
                SET filtered_projection_sha256 = ?, state = ?, updated_at = ?
                WHERE operation_id = ? AND request_id = ? AND sequence = ?
                  AND operation_kind = ? AND operation_target = ? AND state = ?
                """,
                (
                    filtered_projection_sha256,
                    ExecutorEngineOperationStateV1.COMPLETED.value,
                    now,
                    binding.operation_id,
                    binding.request_id,
                    claim.sequence,
                    claim.operation_kind.value,
                    claim.target.value,
                    ExecutorEngineOperationStateV1.CLAIMED.value,
                ),
            )
            if result.rowcount != 1:
                raise ExecutorDaemonError("engine_operation")

        self._transaction(action)

    def _completed_engine_operation_projection_sha256(
        self,
        binding: _SessionRequestBinding,
        plan: ExecutorEngineOperationPlanV1,
    ) -> str:
        with self._lock:
            connection = self._connection()
            try:
                self._require_journal_uuid(connection, binding)
                rows = connection.execute(
                    """
                    SELECT sequence, operation_kind, operation_target,
                           filtered_projection_sha256, state
                    FROM engine_operations
                    WHERE operation_id = ? AND request_id = ?
                    ORDER BY sequence ASC
                    """,
                    (binding.operation_id, binding.request_id),
                ).fetchall()
            except ExecutorDaemonError:
                raise
            except Exception:
                raise ExecutorDaemonError("engine_operation") from None
            finally:
                connection.close()
        if len(rows) != len(plan.operations):
            raise ExecutorDaemonError("engine_operation")
        values: list[dict[str, object]] = []
        for expected_sequence, (sequence, operation_kind, target, projection, state) in enumerate(
            rows, start=1
        ):
            expected = plan.operations[expected_sequence - 1]
            if (
                type(sequence) is not int
                or sequence != expected_sequence
                or type(operation_kind) is not str
                or type(target) is not str
                or type(projection) is not str
                or re_fullmatch(_SHA256, projection) is None
                or state != ExecutorEngineOperationStateV1.COMPLETED.value
            ):
                raise ExecutorDaemonError("engine_operation")
            try:
                kind = ExecutorEngineOperationKindV1(operation_kind)
                operation_target = ExecutorEngineOperationTargetV1(target)
            except ValueError:
                raise ExecutorDaemonError("engine_operation") from None
            if kind is not expected.operation_kind or operation_target is not expected.target:
                raise ExecutorDaemonError("engine_operation")
            values.append(
                {
                    "sequence": sequence,
                    "operation_kind": operation_kind,
                    "operation_target": target,
                    "filtered_projection_sha256": projection,
                }
            )
        return _digest(
            _ENGINE_OPERATION_JOURNAL_DOMAIN
            + _canonical_json(
                {
                    "operation_id": binding.operation_id,
                    "request_sha256": binding.request_sha256,
                    "engine_operation_plan_sha256": plan.plan_sha256(),
                    "operations": values,
                }
            )
        )

    def _remaining_engine_operations(
        self,
        binding: _SessionRequestBinding,
        plan: ExecutorEngineOperationPlanV1,
    ) -> int:
        """Return the remaining fixed steps, rejecting a pending checkpoint gap."""

        with self._lock:
            connection = self._connection()
            try:
                self._require_journal_uuid(connection, binding)
                rows = connection.execute(
                    """
                    SELECT sequence, operation_kind, operation_target, state
                    FROM engine_operations
                    WHERE operation_id = ? AND request_id = ?
                    ORDER BY sequence ASC
                    """,
                    (binding.operation_id, binding.request_id),
                ).fetchall()
            except ExecutorDaemonError:
                raise
            except Exception:
                raise ExecutorDaemonError("engine_operation") from None
            finally:
                connection.close()
        if len(rows) > len(plan.operations):
            raise ExecutorDaemonError("engine_operation")
        for expected_sequence, (sequence, operation_kind, target, state) in enumerate(
            rows, start=1
        ):
            expected = plan.operations[expected_sequence - 1]
            if (
                sequence != expected_sequence
                or operation_kind != expected.operation_kind.value
                or target != expected.target.value
                or state != ExecutorEngineOperationStateV1.COMPLETED.value
            ):
                raise ExecutorDaemonError("engine_operation")
        return len(plan.operations) - len(rows)

    @contextmanager
    def acquire_session_lease(self) -> Iterator[None]:
        """Hold one nonblocking OS lease through a whole effect session."""

        descriptor: int | None = None
        try:
            _strict_parent(self._lease_path, phase="session_journal")
            before = _strict_file(self._lease_path, phase="session_journal")
            descriptor = os.open(
                self._lease_path,
                os.O_RDONLY | getattr(os, "O_NOFOLLOW", 0),
            )
            opened = os.fstat(descriptor)
            if (opened.st_dev, opened.st_ino, opened.st_nlink) != (
                before.st_dev,
                before.st_ino,
                before.st_nlink,
            ):
                raise ValueError
            fcntl.flock(descriptor, fcntl.LOCK_EX | fcntl.LOCK_NB)
        except BlockingIOError:
            if descriptor is not None:
                os.close(descriptor)
            raise ExecutorDaemonError("session_busy") from None
        except Exception:
            if descriptor is not None:
                with suppress(Exception):
                    os.close(descriptor)
            raise ExecutorDaemonError("session_journal") from None
        try:
            yield
        finally:
            with suppress(Exception):
                fcntl.flock(descriptor, fcntl.LOCK_UN)
            with suppress(Exception):
                os.close(descriptor)

    def _claim(
        self,
        request: ExecutorTransportRequestV2 | ExecutorAllocationTransportRequestV1,
        *,
        state: ExecutorSessionStateV2,
    ) -> None:
        binding = _session_binding(request)
        now = _system_utc_clock().isoformat(timespec="seconds").replace("+00:00", "Z")

        def action(connection: sqlite3.Connection) -> None:
            self._require_journal_uuid(connection, binding)
            try:
                connection.execute(
                    """
                    INSERT INTO sessions(
                        operation_id, request_id, predecessor_operation_id, request_sha256,
                        allocation_intent_sha256, operation_scope, executor_id,
                        executor_policy_sha256, session_binding_sha256, state, created_at,
                        updated_at
                    ) VALUES (?, ?, NULL, ?, ?, ?, ?, ?, ?, ?, ?, ?)
                    """,
                    (
                        binding.operation_id,
                        binding.request_id,
                        binding.request_sha256,
                        binding.allocation_intent_sha256,
                        binding.operation_scope,
                        binding.executor_id,
                        binding.executor_policy_sha256,
                        binding.session_binding_sha256,
                        state.value,
                        now,
                        now,
                    ),
                )
            except sqlite3.IntegrityError:
                raise ExecutorDaemonError("session_replayed") from None

        self._transaction(action)

    def claim_allocation(self, request: ExecutorAllocationTransportRequestV1) -> None:
        """Durably claim one zero-chunk allocation before the injected effect."""

        if (
            type(request) is not ExecutorAllocationTransportRequestV1
            or request.operation_scope != "allocate_isolated_empty_resources_v2"
            or request.chunk_count != 0
        ):
            raise ExecutorDaemonError("session_claim")
        self._claim(request, state=ExecutorSessionStateV2.ALLOCATION_CLAIMED)

    def claim_materialize(self, request: ExecutorTransportRequestV2) -> None:
        if request.operation_scope != "materialize_and_start_runtime_v1":
            raise ExecutorDaemonError("session_claim")
        self._claim(request, state=ExecutorSessionStateV2.MATERIALIZE_CLAIMED)

    def mark_allocated(
        self,
        request: ExecutorAllocationTransportRequestV1,
        *,
        executor_receipt_sha256: str,
    ) -> None:
        if re_fullmatch(_SHA256, executor_receipt_sha256) is None:
            raise ExecutorDaemonError("session_receipt")
        self._transition(
            request,
            expected=ExecutorSessionStateV2.ALLOCATION_CLAIMED,
            target=ExecutorSessionStateV2.ALLOCATED,
            executor_receipt_sha256=executor_receipt_sha256,
        )

    def mark_materialized(self, request: ExecutorTransportRequestV2) -> None:
        self._transition(
            request,
            expected=ExecutorSessionStateV2.MATERIALIZE_CLAIMED,
            target=ExecutorSessionStateV2.MATERIALIZED,
        )

    def claim_start(self, request: ExecutorTransportRequestV2) -> None:
        now = _system_utc_clock().isoformat(timespec="seconds").replace("+00:00", "Z")
        if request.operation_scope == "materialize_and_start_runtime_v1":
            self._transition(
                request,
                expected=ExecutorSessionStateV2.MATERIALIZED,
                target=ExecutorSessionStateV2.START_CLAIMED,
            )
            return
        if request.operation_scope != "start_runtime_v2":
            raise ExecutorDaemonError("session_claim")
        predecessor = request.predecessor_materialization_operation_id
        if predecessor is None:
            raise ExecutorDaemonError("session_claim")
        binding = _session_binding(request)

        def action(connection: sqlite3.Connection) -> None:
            self._require_journal_uuid(connection, binding)
            previous = connection.execute(
                "SELECT state FROM sessions WHERE operation_id = ?", (predecessor,)
            ).fetchone()
            if previous != (ExecutorSessionStateV2.STARTED.value,):
                raise ExecutorDaemonError("session_predecessor")
            try:
                connection.execute(
                    """
                    INSERT INTO sessions(
                        operation_id, request_id, predecessor_operation_id, request_sha256,
                        allocation_intent_sha256, operation_scope, executor_id,
                        executor_policy_sha256, session_binding_sha256, state, created_at,
                        updated_at
                    ) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
                    """,
                    (
                        request.operation_id,
                        request.request_id,
                        predecessor,
                        request.metadata_sha256(),
                        request.allocation_intent_sha256,
                        request.operation_scope,
                        request.executor_id,
                        request.executor_policy_sha256,
                        request.session_binding_sha256,
                        ExecutorSessionStateV2.START_CLAIMED.value,
                        now,
                        now,
                    ),
                )
            except sqlite3.IntegrityError:
                raise ExecutorDaemonError("session_replayed") from None

        self._transaction(action)

    def mark_started(
        self,
        request: ExecutorTransportRequestV2,
        *,
        delivery_binding_sha256: str,
        executor_receipt_sha256: str,
    ) -> None:
        if (
            re_fullmatch(_SHA256, delivery_binding_sha256) is None
            or re_fullmatch(_SHA256, executor_receipt_sha256) is None
        ):
            raise ExecutorDaemonError("session_receipt")
        self._transition(
            request,
            expected=ExecutorSessionStateV2.START_CLAIMED,
            target=ExecutorSessionStateV2.STARTED,
            delivery_binding_sha256=delivery_binding_sha256,
            executor_receipt_sha256=executor_receipt_sha256,
        )

    def mark_ambiguous(
        self, request: ExecutorTransportRequestV2 | ExecutorAllocationTransportRequestV1
    ) -> None:
        """Persist an unretryable outcome after any post-claim uncertainty."""

        binding = _session_binding(request)
        if binding.operation_scope == "allocate_isolated_empty_resources_v2":
            target = ExecutorSessionStateV2.ALLOCATION_AMBIGUOUS.value
            allowed_states = (ExecutorSessionStateV2.ALLOCATION_CLAIMED.value,) * 3
        elif binding.operation_scope in {
            "materialize_and_start_runtime_v1",
            "start_runtime_v2",
        }:
            target = ExecutorSessionStateV2.START_AMBIGUOUS.value
            allowed_states = (
                ExecutorSessionStateV2.MATERIALIZE_CLAIMED.value,
                ExecutorSessionStateV2.MATERIALIZED.value,
                ExecutorSessionStateV2.START_CLAIMED.value,
            )
        else:
            raise ExecutorDaemonError("session_state")
        now = _system_utc_clock().isoformat(timespec="seconds").replace("+00:00", "Z")

        def action(connection: sqlite3.Connection) -> None:
            self._require_journal_uuid(connection, binding)
            connection.execute(
                """
                UPDATE engine_operations SET state = ?, updated_at = ?
                WHERE operation_id = ? AND request_id = ? AND state = ?
                """,
                (
                    ExecutorEngineOperationStateV1.AMBIGUOUS.value,
                    now,
                    binding.operation_id,
                    binding.request_id,
                    ExecutorEngineOperationStateV1.CLAIMED.value,
                ),
            )
            result = connection.execute(
                """
                UPDATE sessions SET state = ?, updated_at = ?
                WHERE operation_id = ? AND request_id = ?
                  AND state IN (?, ?, ?)
                """,
                (
                    target,
                    now,
                    binding.operation_id,
                    binding.request_id,
                    *allowed_states,
                ),
            )
            if result.rowcount != 1:
                raise ExecutorDaemonError("session_state")

        self._transaction(action)

    def abandon(
        self,
        receipt: ExecutorRecoveryReceiptV2,
        *,
        artifacts: VerifiedExecutorTransportArtifactsV2,
    ) -> None:
        """Record a separately signed recovery outcome; it never retries work."""

        receipt = verify_executor_recovery_receipt(receipt, artifacts=artifacts)
        now = _system_utc_clock().isoformat(timespec="seconds").replace("+00:00", "Z")
        receipt_sha256 = _digest(_canonical_json(receipt.model_dump(mode="json")))
        ambiguous_state = (
            ExecutorSessionStateV2.ALLOCATION_AMBIGUOUS.value
            if receipt.operation_scope == "allocate_isolated_empty_resources_v2"
            else ExecutorSessionStateV2.START_AMBIGUOUS.value
        )

        def action(connection: sqlite3.Connection) -> None:
            journal = connection.execute(
                "SELECT journal_id FROM metadata WHERE singleton = 1"
            ).fetchone()
            row = connection.execute(
                """
                SELECT request_sha256, allocation_intent_sha256, operation_scope, executor_id,
                       executor_policy_sha256, session_binding_sha256, state
                FROM sessions WHERE operation_id = ? AND request_id = ?
                """,
                (receipt.operation_id, receipt.request_id),
            ).fetchone()
            expected = (
                receipt.request_metadata_sha256,
                receipt.allocation_intent_sha256,
                receipt.operation_scope,
                receipt.executor_id,
                receipt.executor_policy_sha256,
                receipt.session_binding_sha256,
                ambiguous_state,
            )
            if journal != (receipt.journal_uuid,) or row != expected:
                raise ExecutorDaemonError("session_recovery")
            result = connection.execute(
                """
                UPDATE sessions SET state = ?, recovery_receipt_sha256 = ?, updated_at = ?
                WHERE operation_id = ? AND request_id = ? AND state = ?
                """,
                (
                    ExecutorSessionStateV2.ABANDONED.value,
                    receipt_sha256,
                    now,
                    receipt.operation_id,
                    receipt.request_id,
                    ambiguous_state,
                ),
            )
            if result.rowcount != 1:
                raise ExecutorDaemonError("session_recovery")

        self._transaction(action)

    def _transition(
        self,
        request: ExecutorTransportRequestV2 | ExecutorAllocationTransportRequestV1,
        *,
        expected: ExecutorSessionStateV2,
        target: ExecutorSessionStateV2,
        delivery_binding_sha256: str | None = None,
        executor_receipt_sha256: str | None = None,
    ) -> None:
        binding = _session_binding(request)
        now = _system_utc_clock().isoformat(timespec="seconds").replace("+00:00", "Z")

        def action(connection: sqlite3.Connection) -> None:
            self._require_journal_uuid(connection, binding)
            result = connection.execute(
                """
                UPDATE sessions
                SET state = ?, delivery_binding_sha256 = COALESCE(?, delivery_binding_sha256),
                    executor_receipt_sha256 = COALESCE(?, executor_receipt_sha256), updated_at = ?
                WHERE operation_id = ? AND request_id = ? AND request_sha256 = ? AND state = ?
                """,
                (
                    target.value,
                    delivery_binding_sha256,
                    executor_receipt_sha256,
                    now,
                    binding.operation_id,
                    binding.request_id,
                    binding.request_sha256,
                    expected.value,
                ),
            )
            if result.rowcount != 1:
                raise ExecutorDaemonError("session_state")

        self._transaction(action)

    @staticmethod
    def _require_journal_uuid(
        connection: sqlite3.Connection,
        request: _SessionRequestBinding,
    ) -> None:
        """Reject a cross-journal request before its replay state can change."""

        row = connection.execute("SELECT journal_id FROM metadata WHERE singleton = 1").fetchone()
        if row != (request.journal_uuid,):
            raise ExecutorDaemonError("session_journal")


class _ExecutorEngineOperationRecorder:
    """Session-bound façade that exposes no database or raw engine evidence."""

    def __init__(
        self,
        journal: ExecutorSessionJournal,
        binding: _SessionRequestBinding,
        plan: ExecutorEngineOperationPlanV1,
    ) -> None:
        self._journal = journal
        self._binding = binding
        self._plan = plan

    def remaining_operations(self) -> int:
        return self._journal._remaining_engine_operations(self._binding, self._plan)

    def claim_next(self) -> ExecutorEngineOperationClaimV1:
        return self._journal._claim_engine_operation(self._binding, self._plan)

    def complete(
        self,
        claim: ExecutorEngineOperationClaimV1,
        *,
        filtered_projection_sha256: str,
    ) -> None:
        self._journal._complete_engine_operation(
            self._binding,
            self._plan,
            claim,
            filtered_projection_sha256=filtered_projection_sha256,
        )

    def completed_projection_sha256(self) -> str:
        return self._journal._completed_engine_operation_projection_sha256(
            self._binding, self._plan
        )


def re_fullmatch(pattern: str, value: object) -> object | None:
    """Avoid exposing malformed values from a journal-facing error path."""

    import re

    return re.fullmatch(pattern, value) if type(value) is str else None


class ExecutorSecretSink(Protocol):
    """Trusted backend sink for one bounded buffer; never a raw mapping."""

    def accept(self, descriptor: SecretDeliverySlotV1, value: memoryview) -> None: ...


class BoundedExecutorDelivery:
    """One-shot collection of frame buffers handed to a typed backend sink."""

    def __init__(self, items: tuple[tuple[SecretDeliverySlotV1, bytearray], ...]) -> None:
        if len(items) != 5:
            raise ExecutorDaemonError("delivery_buffers")
        self._items = items
        self._consumed = False

    def consume_into(self, sink: ExecutorSecretSink) -> None:
        if self._consumed or not hasattr(sink, "accept"):
            raise ExecutorDaemonError("delivery_sink")
        self._consumed = True
        try:
            for descriptor, value in self._items:
                sink.accept(descriptor, memoryview(value))
        except Exception:
            raise ExecutorDaemonError("backend_sink") from None
        finally:
            self.zeroize()

    def require_consumed(self) -> None:
        """Reject a backend that reports success without consuming the lease."""

        if not self._consumed:
            raise ExecutorDaemonError("delivery_sink")

    def zeroize(self) -> None:
        for _, value in self._items:
            _zeroize(value)


@dataclass(frozen=True, slots=True)
class ExecutorBackendContextV2:
    """Value-free context passed to an injected effect backend."""

    operation_scope: Literal["materialize_and_start_runtime_v1", "start_runtime_v2"]
    operation_id: str
    request_id: str
    journal_uuid: str
    allocation_intent_sha256: str
    idempotency_key: str
    effect_intent_sha256: str
    predecessor_attestation_sha256: str
    predecessor_materialization_operation_id: str | None
    docker_engine_control_policy_sha256: str
    postgres_prepared_control_policy_sha256: str
    host_fingerprint_sha256: str
    engine_fingerprint_sha256: str
    effect_plan_sha256: str
    artifact_chain_sha256: str
    authorization_witness_sha256: str
    request_nonce_sha256: str
    channel_binding_sha256: str
    session_binding_sha256: str
    executor_id: str
    policy_sha256: str
    installation_receipt_sha256: str
    delivery_binding_sha256: str
    engine_operations: ExecutorEngineOperationRecorder


@dataclass(frozen=True, slots=True)
class AllocationExecutorBackendContextV1:
    """Value-free, one-shot context for the future allocation backend.

    It exposes no Docker socket, raw policy artifact, SQL template, secret,
    or replay authority.  A future allowlisted backend receives only the
    commitments it must prove in its filtered executor receipt and a durable
    journal identity that prevents adoption/retry after a crash.
    """

    allocation_operation_id: str
    request_id: str
    journal_uuid: str
    allocation_intent_sha256: str
    idempotency_key: str
    executor_id: str
    executor_policy_sha256: str
    docker_engine_control_policy_sha256: str
    postgres_prepared_control_policy_sha256: str
    host_fingerprint_sha256: str
    engine_fingerprint_sha256: str
    allocation_plan_sha256: str
    artifact_chain_sha256: str
    authorization_witness_sha256: str
    engine_operations: ExecutorEngineOperationRecorder


@dataclass(frozen=True, slots=True)
class ExecutorAllocationBackendEvidenceV1:
    """Filtered backend observation that the daemon turns into an attestation.

    The backend cannot select operation identity, policy hashes, or signing
    fields.  It reports only typed engine identity and opaque projections; the
    daemon binds and signs every remaining field under its installed
    attestation key.
    """

    engine: EngineIdentityObservationV1
    control_image_local_evidence: DockerImageLocalEvidenceV1
    allocated_resources: AllocatedResourceSetV2
    engine_operation_journal_sha256: str
    completed_at: str


@dataclass(frozen=True, slots=True)
class ExecutorBackendReceiptV2:
    """Typed non-secret executor evidence; hash-only bridges are forbidden."""

    executor_receipt: MaterializationExecutorReceiptV1 | StartRuntimeExecutorReceiptV2


class ExecutorMutationBackend(Protocol):
    """Typed future engine boundary; it cannot receive a raw material mapping."""

    def materialize_and_start(
        self,
        context: ExecutorBackendContextV2,
        delivery: BoundedExecutorDelivery,
    ) -> ExecutorBackendReceiptV2: ...

    def allocate_empty_resources(
        self,
        context: AllocationExecutorBackendContextV1,
    ) -> ExecutorAllocationBackendEvidenceV1: ...

    def start(
        self,
        context: ExecutorBackendContextV2,
        delivery: BoundedExecutorDelivery,
    ) -> ExecutorBackendReceiptV2: ...


class NoMutationBackend:
    """Production-safe default: this commit cannot mutate a runtime engine."""

    def materialize_and_start(
        self,
        context: ExecutorBackendContextV2,
        delivery: BoundedExecutorDelivery,
    ) -> ExecutorBackendReceiptV2:
        del context
        delivery.zeroize()
        raise ExecutorDaemonError("backend_unavailable")

    def allocate_empty_resources(
        self,
        context: AllocationExecutorBackendContextV1,
    ) -> ExecutorAllocationBackendEvidenceV1:
        del context
        raise ExecutorDaemonError("backend_unavailable")

    def start(
        self,
        context: ExecutorBackendContextV2,
        delivery: BoundedExecutorDelivery,
    ) -> ExecutorBackendReceiptV2:
        del context
        delivery.zeroize()
        raise ExecutorDaemonError("backend_unavailable")


class MemorySafetyLease(Protocol):
    """A held page-lock lease released after buffers have been overwritten."""

    def release(self) -> None: ...


class MemorySafetyPreflight(Protocol):
    """Signed-policy preflight implementation injected for platform testing."""

    def verify_base(self) -> None: ...

    def lock(self, value: bytearray) -> MemorySafetyLease: ...


class _LinuxMemoryLease:
    def __init__(self, address: int, length: int, library: ctypes.CDLL) -> None:
        self._address = address
        self._length = length
        self._library = library
        self._released = False

    def release(self) -> None:
        if self._released:
            return
        self._released = True
        with suppress(Exception):
            self._library.munlock(ctypes.c_void_p(self._address), ctypes.c_size_t(self._length))


class LinuxMemorySafetyPreflight:
    """Linux core/swap/page-lock preflight; failure is always fail-closed."""

    def __init__(self) -> None:
        if sys.platform != "linux":
            raise ExecutorDaemonError("memory_platform")

    def verify_base(self) -> None:
        try:
            resource.setrlimit(resource.RLIMIT_CORE, (0, 0))
            soft, hard = resource.getrlimit(resource.RLIMIT_CORE)
            if soft != 0 or hard != 0:
                raise ValueError
            swaps = Path("/proc/swaps").read_text(encoding="ascii")
            if len([line for line in swaps.splitlines() if line.strip()]) > 1:
                raise ValueError
        except Exception:
            raise ExecutorDaemonError("memory_preflight") from None

    def lock(self, value: bytearray) -> MemorySafetyLease:
        if type(value) is not bytearray or not value:
            raise ExecutorDaemonError("memory_lock")
        try:
            library = ctypes.CDLL(None)
            library.mlock.argtypes = [ctypes.c_void_p, ctypes.c_size_t]
            library.mlock.restype = ctypes.c_int
            library.munlock.argtypes = [ctypes.c_void_p, ctypes.c_size_t]
            library.munlock.restype = ctypes.c_int
            address = ctypes.addressof((ctypes.c_ubyte * len(value)).from_buffer(value))
            if library.mlock(ctypes.c_void_p(address), ctypes.c_size_t(len(value))) != 0:
                raise ValueError
            return _LinuxMemoryLease(address, len(value), library)
        except Exception:
            raise ExecutorDaemonError("memory_lock") from None


class ExecutorAttestationSigner(Protocol):
    """Bounded daemon signer; no generic byte-signing surface is exposed."""

    @property
    def key_id(self) -> str: ...

    def sign_hello(self, hello: ExecutorHelloV2) -> str: ...

    def sign_receipt(self, receipt: ExecutorTransportReceiptV2) -> str: ...

    def sign_allocation_executor_receipt(self, receipt: AllocationExecutorReceiptV1) -> str: ...

    def sign_allocation_transport_receipt(
        self, receipt: ExecutorAllocationTransportReceiptV1
    ) -> str: ...

    def sign_allocation_reconciliation_receipt(self, receipt: object) -> str: ...

    def sign_materialization_executor_receipt(
        self, receipt: MaterializationExecutorReceiptV1
    ) -> str: ...

    def sign_start_runtime_executor_receipt(
        self, receipt: StartRuntimeExecutorReceiptV2
    ) -> str: ...


class SystemdCredentialAttestationSigner:
    """Ed25519 attestation signer loaded from a credential descriptor/path."""

    def __init__(
        self,
        seed: bytearray,
        *,
        identity: ExecutorIdentityV1,
        _capability: object | None = None,
    ) -> None:
        if (
            _capability is not _ATTESTATION_SIGNER_CAPABILITY
            or type(seed) is not bytearray
            or type(identity) is not ExecutorIdentityV1
        ):
            _zeroize(seed)
            raise ExecutorDaemonError("attestation_credential")
        try:
            derived = (
                Ed25519PrivateKey.from_private_bytes(seed)
                .public_key()
                .public_bytes(serialization.Encoding.Raw, serialization.PublicFormat.Raw)
            )
            expected = base64.b64decode(identity.attestation_public_key_base64, validate=True)
            if (
                len(seed) != 32
                or base64.b64encode(expected).decode("ascii")
                != identity.attestation_public_key_base64
                or not hmac.compare_digest(derived, expected)
            ):
                raise ValueError
        except Exception:
            _zeroize(seed)
            raise ExecutorDaemonError("attestation_credential") from None
        self._seed = seed
        self._identity = identity
        self._closed = False

    @classmethod
    def from_credential_fd(
        cls,
        descriptor: int,
        *,
        identity: ExecutorIdentityV1,
    ) -> SystemdCredentialAttestationSigner:
        """Read one bounded systemd credential descriptor into mutable memory."""

        if type(descriptor) is not int:
            raise ExecutorDaemonError("attestation_credential")
        value = bytearray()
        try:
            while len(value) <= 32:
                block = os.read(descriptor, 33 - len(value))
                if not block:
                    break
                value.extend(block)
            if len(value) != 32:
                raise ValueError
            return cls(
                value,
                identity=identity,
                _capability=_ATTESTATION_SIGNER_CAPABILITY,
            )
        except Exception:
            _zeroize(value)
            raise ExecutorDaemonError("attestation_credential") from None

    @classmethod
    def from_credential_path(
        cls,
        path: Path,
        *,
        identity: ExecutorIdentityV1,
    ) -> SystemdCredentialAttestationSigner:
        """Open one owner-only systemd credential without retaining its path bytes."""

        if not isinstance(path, Path) or not path.is_absolute():
            raise ExecutorDaemonError("attestation_credential")
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
                if (opened.st_dev, opened.st_ino, opened.st_nlink) != (
                    before.st_dev,
                    before.st_ino,
                    before.st_nlink,
                ):
                    raise ValueError
                return cls.from_credential_fd(descriptor, identity=identity)
            finally:
                os.close(descriptor)
        except ExecutorDaemonError:
            raise
        except Exception:
            raise ExecutorDaemonError("attestation_credential") from None

    @property
    def key_id(self) -> str:
        return self._identity.attestation_key_id

    def _sign(self, message: bytes) -> str:
        if self._closed:
            raise ExecutorDaemonError("attestation_credential")
        try:
            signature = Ed25519PrivateKey.from_private_bytes(self._seed).sign(message)
            return base64.b64encode(signature).decode("ascii")
        except Exception:
            raise ExecutorDaemonError("attestation_credential") from None

    def sign_hello(self, hello: ExecutorHelloV2) -> str:
        return self._sign(executor_hello_message(hello))

    def sign_receipt(self, receipt: ExecutorTransportReceiptV2) -> str:
        return self._sign(executor_transport_receipt_message(receipt))

    def sign_allocation_executor_receipt(self, receipt: AllocationExecutorReceiptV1) -> str:
        return self._sign(allocation_executor_receipt_message(receipt))

    def sign_allocation_transport_receipt(
        self, receipt: ExecutorAllocationTransportReceiptV1
    ) -> str:
        return self._sign(executor_allocation_transport_receipt_message(receipt))

    def sign_allocation_reconciliation_receipt(self, receipt: object) -> str:
        """Sign only the typed allocation reconciliation receipt domain."""

        from omninode_rsd.lifecycle.executor_allocation import (
            AllocationReconciliationReceiptV1,
            allocation_reconciliation_receipt_message,
        )

        if type(receipt) is not AllocationReconciliationReceiptV1:
            raise ExecutorDaemonError("attestation_credential")
        return self._sign(allocation_reconciliation_receipt_message(receipt))

    def sign_materialization_executor_receipt(
        self, receipt: MaterializationExecutorReceiptV1
    ) -> str:
        return self._sign(materialization_executor_receipt_message(receipt))

    def sign_start_runtime_executor_receipt(self, receipt: StartRuntimeExecutorReceiptV2) -> str:
        return self._sign(start_runtime_executor_receipt_message(receipt))

    def close(self) -> None:
        self._closed = True
        _zeroize(self._seed)


class ExecutorDaemonSessionEngine:
    """One nonmultiplexed UDS session engine with claim-before-chunk ordering."""

    def __init__(
        self,
        *,
        policy: ExecutorTransportPolicyV2,
        signer_genesis: SignerGenesisV1,
        attestation_signer: ExecutorAttestationSigner,
        journal: ExecutorSessionJournal,
        backend: ExecutorMutationBackend | None = None,
        memory_safety: MemorySafetyPreflight | None = None,
        _capability: object | None = None,
    ) -> None:
        if (
            _capability is not _DAEMON_ENGINE_CAPABILITY
            or type(policy) is not ExecutorTransportPolicyV2
            or type(signer_genesis) is not SignerGenesisV1
            or type(journal) is not ExecutorSessionJournal
            or not hasattr(attestation_signer, "sign_hello")
            or not hasattr(attestation_signer, "sign_receipt")
            or not hasattr(attestation_signer, "sign_allocation_executor_receipt")
            or not hasattr(attestation_signer, "sign_allocation_transport_receipt")
            or not hasattr(attestation_signer, "sign_allocation_reconciliation_receipt")
            or not hasattr(attestation_signer, "sign_materialization_executor_receipt")
            or not hasattr(attestation_signer, "sign_start_runtime_executor_receipt")
        ):
            raise ExecutorDaemonError("daemon_configuration")
        self._policy = policy
        self._signer_genesis = signer_genesis
        self._attestation_signer = attestation_signer
        self._journal = journal
        self._backend = NoMutationBackend() if backend is None else backend
        self._memory = LinuxMemorySafetyPreflight() if memory_safety is None else memory_safety
        self._active = Lock()

    def reconcile_allocation_read_only(self) -> AllocationReconciliationReceiptV1:
        """Produce a signed, non-resumable allocation reconciliation receipt.

        This entry point admits only the sealed allocation adapter. It never
        claims an operation or invokes a mutating backend method. It does hold
        the same nonblocking session lease as a live request so it cannot sign
        an inconsistent snapshot while allocation is running.
        """

        from omninode_rsd.lifecycle.executor_allocation import (
            AllocationReconciliationReceiptV1,
            SealedAllocationBackendV1,
        )

        if type(self._backend) is not SealedAllocationBackendV1:
            raise ExecutorDaemonError("backend_unavailable")
        if not self._active.acquire(blocking=False):
            raise ExecutorDaemonError("session_busy")
        try:
            with self._journal.acquire_session_lease():
                projection = self._backend.reconcile_read_only()
                unsigned = AllocationReconciliationReceiptV1(
                    schema_version="rsd.allocation-reconciliation-receipt.v1",
                    projection=projection,
                    projection_sha256=canonical_sha256(projection),
                    signer_key_id=self._attestation_signer.key_id,
                    signature_base64=base64.b64encode(b"0" * 64).decode("ascii"),
                )
                signature = self._attestation_signer.sign_allocation_reconciliation_receipt(
                    unsigned
                )
                return unsigned.model_copy(update={"signature_base64": signature})
        finally:
            self._active.release()

    @classmethod
    def from_verified_artifact_paths(
        cls,
        *,
        paths: ExecutorTransportArtifactPathsV2,
        signer: object,
        issuer: object,
        allocation_intent: object,
        attestation_signer: SystemdCredentialAttestationSigner,
        journal: ExecutorSessionJournal,
        allocation_backend_paths: object | None = None,
        memory_safety: MemorySafetyPreflight | None = None,
    ) -> ExecutorDaemonSessionEngine:
        """Production construction path with no caller-injected effect adapter.

        A missing allocation artifact root intentionally leaves the daemon on
        ``NoMutationBackend``.  The only concrete production adapter is loaded
        from its own descriptor-verified allocation artifact root; tests that
        need fakes use the explicitly test-only factory below.
        """

        # ``load_verified_executor_transport_artifacts`` makes the exact
        # concrete model checks and removes arbitrary object/caller clock
        # selection before a UDS session engine can exist.
        from omninode_rsd.lifecycle.authorization import TrustedEd25519SignerV1
        from omninode_rsd.lifecycle.infisical_disposable import AllocationIntentV2

        if (
            type(signer) is not TrustedEd25519SignerV1
            or type(issuer) is not TrustedEd25519SignerV1
            or type(allocation_intent) is not AllocationIntentV2
            or type(attestation_signer) is not SystemdCredentialAttestationSigner
        ):
            raise ExecutorDaemonError("daemon_configuration")
        try:
            artifacts = load_verified_executor_transport_artifacts(
                paths,
                signer=signer,
                issuer=issuer,
                allocation_intent=allocation_intent,
            )
            if attestation_signer.key_id != artifacts.attestation_key_id:
                raise ValueError
            resolved_backend: ExecutorMutationBackend | None = None
            if allocation_backend_paths is not None:
                from omninode_rsd.lifecycle.executor_allocation import (
                    AllocationBackendArtifactPathsV1,
                    load_sealed_allocation_backend,
                )

                if type(allocation_backend_paths) is not AllocationBackendArtifactPathsV1:
                    raise ValueError
                resolved_backend = load_sealed_allocation_backend(
                    allocation_backend_paths,
                    signer=signer,
                    transport=artifacts,
                )
            return cls(
                policy=artifacts.policy,
                signer_genesis=artifacts.signer_genesis,
                attestation_signer=attestation_signer,
                journal=journal,
                backend=resolved_backend,
                memory_safety=memory_safety,
                _capability=_DAEMON_ENGINE_CAPABILITY,
            )
        except (ExecutorTransportError, ExecutorDaemonError, ValueError, TypeError):
            raise ExecutorDaemonError("daemon_configuration") from None

    def _serve_for_test(
        self,
        source: FrameByteReader,
        sink: FrameByteWriter,
        *,
        peer_uid: int,
        allocation_only: bool = False,
    ) -> ExecutorTransportReceiptV2 | ExecutorAllocationTransportReceiptV1:
        """Internal fake-frame seam; installed flows use ``serve_socket`` only."""

        if type(peer_uid) is not int or peer_uid != self._policy.force_command_user_uid:
            raise ExecutorDaemonError("uds_peer")
        if not self._active.acquire(blocking=False):
            raise ExecutorDaemonError("session_busy")
        try:
            with self._journal.acquire_session_lease():
                return self._serve_held(source, sink, allocation_only=allocation_only)
        finally:
            self._active.release()

    def _attest_runtime_executor_receipt(
        self,
        request: ExecutorTransportRequestV2,
        result: ExecutorBackendReceiptV2,
    ) -> MaterializationExecutorReceiptV1 | StartRuntimeExecutorReceiptV2:
        """Bind a backend's typed evidence to this exact session and sign it.

        A future backend may observe only its allowlisted engine projections;
        it cannot choose the attestation key, transport operation, or channel
        commitments.  This replaces the former opaque backend-hash bridge.
        """

        if type(result) is not ExecutorBackendReceiptV2:
            raise ExecutorDaemonError("backend_receipt")
        now = _system_utc_clock()
        inner = result.executor_receipt
        if request.operation_scope == "materialize_and_start_runtime_v1":
            if type(inner) is not MaterializationExecutorReceiptV1:
                raise ExecutorDaemonError("backend_receipt")
            try:
                inner = MaterializationExecutorReceiptV1.model_validate_json(
                    _canonical_json(inner.model_dump(mode="json", warnings="error"))
                )
            except (ValidationError, ValueError, TypeError):
                raise ExecutorDaemonError("backend_receipt") from None
            if (
                inner.operation_scope != request.operation_scope
                or inner.operation_id != request.operation_id
                or inner.executor_id != request.executor_id
                or inner.installation_receipt_sha256 != request.installation_receipt_sha256
                or inner.idempotency_key != request.idempotency_key
                or inner.materialization_intent_sha256 != request.effect_intent_sha256
                or inner.observed_allocation_attestation_sha256
                != request.predecessor_attestation_sha256
                or inner.docker_engine_control_policy_sha256
                != request.docker_engine_control_policy_sha256
                or inner.host_fingerprint_sha256 != request.host_fingerprint_sha256
                or inner.engine_fingerprint_sha256 != request.engine_fingerprint_sha256
                or inner.channel_binding_sha256 != request.channel_binding_sha256
                or inner.session_binding_sha256 != request.session_binding_sha256
                or _timestamp(inner.completed_at) > now
            ):
                raise ExecutorDaemonError("backend_receipt")
            unsigned = inner.model_copy(
                update={
                    "signer_key_id": self._attestation_signer.key_id,
                    "signature_base64": base64.b64encode(b"0" * 64).decode("ascii"),
                }
            )
            return unsigned.model_copy(
                update={
                    "signature_base64": (
                        self._attestation_signer.sign_materialization_executor_receipt(unsigned)
                    )
                }
            )
        if type(inner) is not StartRuntimeExecutorReceiptV2:
            raise ExecutorDaemonError("backend_receipt")
        try:
            start_inner = StartRuntimeExecutorReceiptV2.model_validate_json(
                _canonical_json(inner.model_dump(mode="json", warnings="error"))
            )
        except (ValidationError, ValueError, TypeError):
            raise ExecutorDaemonError("backend_receipt") from None
        if (
            start_inner.operation_scope != request.operation_scope
            or start_inner.start_operation_id != request.operation_id
            or start_inner.executor_id != request.executor_id
            or start_inner.installation_receipt_sha256 != request.installation_receipt_sha256
            or start_inner.idempotency_key != request.idempotency_key
            or start_inner.start_runtime_intent_sha256 != request.effect_intent_sha256
            or start_inner.request_nonce_sha256 != request.request_nonce_sha256
            or start_inner.host_fingerprint_sha256 != request.host_fingerprint_sha256
            or start_inner.engine_fingerprint_sha256 != request.engine_fingerprint_sha256
            or start_inner.channel_binding_sha256 != request.channel_binding_sha256
            or start_inner.session_binding_sha256 != request.session_binding_sha256
            or _timestamp(start_inner.completed_at) > now
        ):
            raise ExecutorDaemonError("backend_receipt")
        unsigned_start = start_inner.model_copy(
            update={
                "signer_key_id": self._attestation_signer.key_id,
                "signature_base64": base64.b64encode(b"0" * 64).decode("ascii"),
            }
        )
        return unsigned_start.model_copy(
            update={
                "signature_base64": self._attestation_signer.sign_start_runtime_executor_receipt(
                    unsigned_start
                )
            }
        )

    def _serve_allocation_request(
        self,
        reader: CanonicalFrameReader,
        request_raw: bytes,
        *,
        hello: ExecutorHelloV2,
        source: FrameByteReader,
        sink: FrameByteWriter,
    ) -> ExecutorAllocationTransportReceiptV1:
        """Handle one fully framed, zero-secret allocation request.

        The durable claim is deliberately after frame completion and relay EOF
        authentication, but before the injected backend is invoked.  Any
        uncertainty after that claim becomes an explicit unretryable state.
        """

        request: ExecutorAllocationTransportRequestV1 | None = None
        claimed_here = False
        try:
            request = ExecutorAllocationTransportRequestV1.model_validate_json(request_raw)
            request = verify_executor_allocation_transport_request(
                request,
                signer_genesis=self._signer_genesis,
                hello=hello,
                policy=self._policy,
            )
            # This must reject a nonzero chunk count before any durable replay
            # state or backend path is reached.
            reader.finish()
            if type(source) is _UnixSocketFrame:
                _require_relay_eof_frame(source)
                source.require_eof()
            self._journal.claim_allocation(request)
            claimed_here = True
            context = AllocationExecutorBackendContextV1(
                allocation_operation_id=request.allocation_operation_id,
                request_id=request.request_id,
                journal_uuid=request.journal_uuid,
                allocation_intent_sha256=request.allocation_intent_sha256,
                idempotency_key=request.idempotency_key,
                executor_id=request.executor_id,
                executor_policy_sha256=request.executor_policy_sha256,
                docker_engine_control_policy_sha256=request.docker_engine_control_policy_sha256,
                postgres_prepared_control_policy_sha256=(
                    request.postgres_prepared_control_policy_sha256
                ),
                host_fingerprint_sha256=request.host_fingerprint_sha256,
                engine_fingerprint_sha256=request.engine_fingerprint_sha256,
                allocation_plan_sha256=request.allocation_plan_sha256,
                artifact_chain_sha256=request.artifact_chain_sha256,
                authorization_witness_sha256=_digest(
                    _canonical_json(request.authorization_witness.model_dump(mode="json"))
                ),
                engine_operations=self._journal.engine_operation_recorder(request),
            )
            allocation_backend_failed = False
            evidence: ExecutorAllocationBackendEvidenceV1 | None = None
            try:
                evidence = self._backend.allocate_empty_resources(context)
            except Exception:
                # Do not preserve a backend exception object: its repr, args,
                # cause, or context may contain a value delivered to the
                # future backend.  Raise only after the active exception has
                # unwound so the sanitized error has no exception chain.
                allocation_backend_failed = True
            if allocation_backend_failed:
                raise ExecutorDaemonError("allocation_backend")
            if (
                type(evidence) is not ExecutorAllocationBackendEvidenceV1
                or type(evidence.engine) is not EngineIdentityObservationV1
                or evidence.engine.engine_fingerprint_sha256 != request.engine_fingerprint_sha256
                or type(evidence.control_image_local_evidence) is not DockerImageLocalEvidenceV1
                or type(evidence.allocated_resources) is not AllocatedResourceSetV2
                or evidence.allocated_resources.engine != evidence.engine
                or re_fullmatch(_SHA256, evidence.engine_operation_journal_sha256) is None
                or _timestamp(evidence.completed_at) > _system_utc_clock()
                or evidence.engine_operation_journal_sha256
                != context.engine_operations.completed_projection_sha256()
            ):
                raise ExecutorDaemonError("allocation_backend_receipt")
            unsigned_inner = AllocationExecutorReceiptV1(
                schema_version="rsd.allocation-executor-receipt.v1",
                operation_scope="allocate_isolated_empty_resources_v2",
                allocation_operation_id=request.allocation_operation_id,
                allocation_intent_sha256=request.allocation_intent_sha256,
                idempotency_key=request.idempotency_key,
                executor_id=request.executor_id,
                engine_control_policy_sha256=request.docker_engine_control_policy_sha256,
                postgres_prepared_control_policy_sha256=(
                    request.postgres_prepared_control_policy_sha256
                ),
                host_fingerprint_sha256=request.host_fingerprint_sha256,
                engine=evidence.engine,
                control_image_local_evidence=evidence.control_image_local_evidence,
                allocated_resources=evidence.allocated_resources,
                allocated_resources_projection_sha256=canonical_sha256(
                    evidence.allocated_resources
                ),
                engine_operation_journal_sha256=evidence.engine_operation_journal_sha256,
                completed_at=evidence.completed_at,
                signer_key_id=self._attestation_signer.key_id,
                signature_base64=base64.b64encode(b"0" * 64).decode("ascii"),
            )
            inner = unsigned_inner.model_copy(
                update={
                    "signature_base64": self._attestation_signer.sign_allocation_executor_receipt(
                        unsigned_inner
                    )
                }
            )
            inner_sha256 = canonical_sha256(inner)
            self._journal.mark_allocated(request, executor_receipt_sha256=inner_sha256)
            unsigned_receipt = ExecutorAllocationTransportReceiptV1(
                schema_version="rsd.executor-allocation-receipt.v1",
                operation_scope="allocate_isolated_empty_resources_v2",
                allocation_operation_id=request.allocation_operation_id,
                request_id=request.request_id,
                journal_uuid=request.journal_uuid,
                client_nonce=request.client_nonce,
                server_nonce=request.server_nonce,
                session_id=request.session_id,
                executor_id=request.executor_id,
                executor_policy_sha256=request.executor_policy_sha256,
                allocation_request_sha256=request.metadata_sha256(),
                allocation_executor_receipt_sha256=inner_sha256,
                allocation_executor_receipt=inner,
                status="allocated",
                completed_at=evidence.completed_at,
                chunk_count=0,
                signer_key_id=self._attestation_signer.key_id,
                signature_base64=base64.b64encode(b"0" * 64).decode("ascii"),
            )
            receipt = unsigned_receipt.model_copy(
                update={
                    "signature_base64": self._attestation_signer.sign_allocation_transport_receipt(
                        unsigned_receipt
                    )
                }
            )
            writer = CanonicalFrameWriter(sink)
            writer.begin(_canonical_json(receipt.model_dump(mode="json")), chunk_count=0)
            writer.finish()
            return receipt
        except ExecutorDaemonError:
            if request is not None and claimed_here:
                with suppress(ExecutorDaemonError):
                    self._journal.mark_ambiguous(request)
            raise
        except (ExecutorTransportError, TransportError, ValidationError, ValueError):
            if request is not None and claimed_here:
                with suppress(ExecutorDaemonError):
                    self._journal.mark_ambiguous(request)
                raise ExecutorDaemonError("allocation_ambiguous") from None
            raise ExecutorDaemonError("allocation_request") from None
        except Exception:
            if request is not None and claimed_here:
                with suppress(ExecutorDaemonError):
                    self._journal.mark_ambiguous(request)
            raise ExecutorDaemonError("allocation_ambiguous") from None

    def _serve_held(
        self,
        source: FrameByteReader,
        sink: FrameByteWriter,
        *,
        allocation_only: bool = False,
    ) -> ExecutorTransportReceiptV2 | ExecutorAllocationTransportReceiptV1:
        """Perform one session while the global OS lease remains held."""

        request: ExecutorTransportRequestV2 | None = None
        claimed_here = False
        delivery: BoundedExecutorDelivery | None = None
        locks: list[MemorySafetyLease] = []
        try:
            self._memory.verify_base()
            hello_reader = CanonicalFrameReader(source)
            client_raw = hello_reader.read_metadata()
            hello_reader.finish()
            client = ExecutorClientHelloV2.model_validate_json(client_raw)
            if (
                client.allocation_intent_sha256 != self._signer_genesis.allocation_intent_sha256
                or client.executor_id != self._policy.executor_id
                or client.executor_policy_sha256 != self._policy.policy_sha256()
            ):
                raise ExecutorDaemonError("client_hello")
            now = _system_utc_clock()
            unsigned_hello = ExecutorHelloV2(
                schema_version="rsd.executor-hello.v2",
                allocation_intent_sha256=client.allocation_intent_sha256,
                client_nonce=client.client_nonce,
                server_nonce=str(uuid4()),
                session_id=client.session_id,
                request_id=client.request_id,
                executor_id=self._policy.executor_id,
                executor_policy_sha256=self._policy.policy_sha256(),
                package_sha256=self._policy.package_sha256,
                template_bundle_sha256=self._policy.template_bundle_sha256,
                expires_at=(now + _HELLO_TTL).isoformat(timespec="seconds").replace("+00:00", "Z"),
                chunk_count=0,
                signer_key_id=self._attestation_signer.key_id,
                signature_base64=base64.b64encode(b"0" * 64).decode("ascii"),
            )
            hello = unsigned_hello.model_copy(
                update={"signature_base64": self._attestation_signer.sign_hello(unsigned_hello)}
            )
            hello_writer = CanonicalFrameWriter(sink)
            hello_writer.begin(_canonical_json(hello.model_dump(mode="json")), chunk_count=0)
            hello_writer.finish()
            reader = CanonicalFrameReader(source)
            request_raw = reader.read_metadata()
            try:
                request_header = json.loads(request_raw)
                message_kind = (
                    request_header.get("message_kind") if type(request_header) is dict else None
                )
            except (TypeError, ValueError, json.JSONDecodeError):
                raise ExecutorDaemonError("session_request") from None
            if message_kind == "allocation":
                return self._serve_allocation_request(
                    reader,
                    request_raw,
                    hello=hello,
                    source=source,
                    sink=sink,
                )
            if allocation_only:
                # Reject a material/start metadata envelope before validation,
                # durable claim, or the first secret chunk read. The sealed
                # allocation systemd entry point must never become a delivery
                # endpoint merely because its UDS is reachable.
                raise ExecutorDaemonError("allocation_only")
            if message_kind not in {"materialize", "start"}:
                raise ExecutorDaemonError("session_request")
            request = ExecutorTransportRequestV2.model_validate_json(request_raw)
            request = verify_executor_transport_request(
                request,
                signer_genesis=self._signer_genesis,
                hello=hello,
                policy=self._policy,
            )
            # This durable claim precedes the first ``read_chunk`` call.
            if request.operation_scope == "materialize_and_start_runtime_v1":
                self._journal.claim_materialize(request)
            else:
                self._journal.claim_start(request)
            claimed_here = True
            items: list[tuple[SecretDeliverySlotV1, bytearray]] = []
            for descriptor in request.slots:
                raw = reader.read_chunk()
                value = bytearray(raw)
                if len(value) != descriptor.encoded_byte_count:
                    _zeroize(value)
                    raise ExecutorDaemonError("secret_chunk")
                lease = self._memory.lock(value)
                locks.append(lease)
                items.append((descriptor, value))
            reader.finish()
            if type(source) is _UnixSocketFrame:
                # The relay emits this authentication frame only after its
                # secure-shell standard input
                # has reached clean EOF, then half-closes the UDS. A raw EOF
                # alone is not authority: a relay-side error or client-side
                # duplicate frame cannot be mistaken for an approved end.
                _require_relay_eof_frame(source)
                source.require_eof()
            delivery = BoundedExecutorDelivery(tuple(items))
            binding = transport_delivery_binding_sha256(request)
            context = ExecutorBackendContextV2(
                operation_scope=request.operation_scope,
                operation_id=request.operation_id,
                request_id=request.request_id,
                journal_uuid=request.journal_uuid,
                allocation_intent_sha256=request.allocation_intent_sha256,
                idempotency_key=request.idempotency_key,
                effect_intent_sha256=request.effect_intent_sha256,
                predecessor_attestation_sha256=request.predecessor_attestation_sha256,
                predecessor_materialization_operation_id=(
                    request.predecessor_materialization_operation_id
                ),
                docker_engine_control_policy_sha256=(request.docker_engine_control_policy_sha256),
                postgres_prepared_control_policy_sha256=(
                    request.postgres_prepared_control_policy_sha256
                ),
                host_fingerprint_sha256=request.host_fingerprint_sha256,
                engine_fingerprint_sha256=request.engine_fingerprint_sha256,
                effect_plan_sha256=request.effect_plan_sha256,
                artifact_chain_sha256=request.artifact_chain_sha256,
                authorization_witness_sha256=canonical_sha256(request.authorization_witness),
                request_nonce_sha256=request.request_nonce_sha256,
                channel_binding_sha256=request.channel_binding_sha256,
                session_binding_sha256=request.session_binding_sha256,
                executor_id=request.executor_id,
                policy_sha256=request.executor_policy_sha256,
                installation_receipt_sha256=request.installation_receipt_sha256,
                delivery_binding_sha256=binding,
                engine_operations=self._journal.engine_operation_recorder(request),
            )
            backend_failed = False
            result: ExecutorBackendReceiptV2 | None = None
            if request.operation_scope == "materialize_and_start_runtime_v1":
                self._journal.mark_materialized(request)
                self._journal.claim_start(request)
                try:
                    result = self._backend.materialize_and_start(context, delivery)
                except Exception:
                    backend_failed = True
            else:
                try:
                    result = self._backend.start(context, delivery)
                except Exception:
                    backend_failed = True
            if backend_failed:
                # See allocation above: this occurs outside the ``except``
                # suite so public callers cannot traverse a secret-bearing
                # backend error through ``__cause__`` or ``__context__``.
                raise ExecutorDaemonError("backend_effect")
            delivery.require_consumed()
            if type(result) is not ExecutorBackendReceiptV2:
                raise ExecutorDaemonError("backend_receipt")
            inner = self._attest_runtime_executor_receipt(request, result)
            if (
                inner.engine_operation_journal_sha256
                != context.engine_operations.completed_projection_sha256()
            ):
                raise ExecutorDaemonError("backend_receipt")
            inner_sha256 = canonical_sha256(inner)
            self._journal.mark_started(
                request,
                delivery_binding_sha256=binding,
                executor_receipt_sha256=inner_sha256,
            )
            unsigned_receipt = ExecutorTransportReceiptV2(
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
                delivery_binding_sha256=binding,
                authorization_witness_sha256=canonical_sha256(request.authorization_witness),
                executor_receipt_sha256=inner_sha256,
                executor_receipt=inner,
                status=(
                    "materialized"
                    if request.operation_scope == "materialize_and_start_runtime_v1"
                    else "started"
                ),
                completed_at=(
                    _system_utc_clock().isoformat(timespec="seconds").replace("+00:00", "Z")
                ),
                chunk_count=0,
                signer_key_id=self._attestation_signer.key_id,
                signature_base64=base64.b64encode(b"0" * 64).decode("ascii"),
            )
            receipt = unsigned_receipt.model_copy(
                update={"signature_base64": self._attestation_signer.sign_receipt(unsigned_receipt)}
            )
            writer = CanonicalFrameWriter(sink)
            writer.begin(_canonical_json(receipt.model_dump(mode="json")), chunk_count=0)
            writer.finish()
            return receipt
        except (ExecutorDaemonError, ExecutorTransportError):
            if request is not None and claimed_here:
                with suppress(ExecutorDaemonError):
                    self._journal.mark_ambiguous(request)
            raise
        except (TransportError, ValidationError, ValueError):
            if request is not None and claimed_here:
                with suppress(ExecutorDaemonError):
                    self._journal.mark_ambiguous(request)
            raise ExecutorDaemonError("session_ambiguous") from None
        except Exception:
            if request is not None and claimed_here:
                with suppress(ExecutorDaemonError):
                    self._journal.mark_ambiguous(request)
            raise ExecutorDaemonError("session_ambiguous") from None
        finally:
            if delivery is not None:
                delivery.zeroize()
            for lease in reversed(locks):
                with suppress(Exception):
                    lease.release()

    def serve_socket(
        self, connection: socket.socket, *, allocation_only: bool = False
    ) -> ExecutorTransportReceiptV2 | ExecutorAllocationTransportReceiptV1:
        """Serve one AF_UNIX connection after obtaining its kernel peer UID."""

        if type(connection) is not socket.socket or connection.family != socket.AF_UNIX:
            raise ExecutorDaemonError("uds_peer")
        stream = _UnixSocketFrame(
            connection,
            timeout_seconds=self._policy.max_session_seconds,
        )
        try:
            peer_uid = unix_peer_uid(connection)
            if peer_uid != self._policy.force_command_user_uid:
                raise ExecutorDaemonError("uds_peer")
            if not self._active.acquire(blocking=False):
                raise ExecutorDaemonError("session_busy")
            try:
                with self._journal.acquire_session_lease():
                    return self._serve_held(stream, stream, allocation_only=allocation_only)
            finally:
                self._active.release()
        finally:
            # The protocol permits exactly one nonmultiplexed dialogue.  Close
            # rather than leaving unread trailing frames available to another
            # operation on the same peer socket.
            stream.close()


def _systemd_activated_listener() -> socket.socket:
    """Adopt only the one named listener passed by the root-owned socket unit."""

    try:
        if (
            sys.platform != "linux"
            or os.geteuid() != 0
            or os.environ.get("LISTEN_PID") != str(os.getpid())
            or os.environ.get("LISTEN_FDS") != _SYSTEMD_LISTEN_FD_COUNT
            or os.environ.get("LISTEN_FDNAMES") != _SYSTEMD_LISTEN_FD_NAME
        ):
            raise ValueError
        return socket.socket(fileno=_SYSTEMD_LISTEN_FD)
    except Exception:
        raise ExecutorDaemonError("activated_socket") from None


def _activated_listener_identity(
    listener: socket.socket,
    policy: ExecutorTransportPolicyV2,
) -> tuple[int, int, int, int, int, int]:
    """Pin the inherited listener to the signed root-owned path and mode."""

    try:
        if (
            type(listener) is not socket.socket
            or listener.family != socket.AF_UNIX
            or listener.type & _SOCK_TYPE_MASK != socket.SOCK_STREAM
            or not hasattr(socket, "SO_ACCEPTCONN")
            or listener.getsockopt(socket.SOL_SOCKET, socket.SO_ACCEPTCONN) != 1
            or listener.getsockname() != policy.daemon_socket_path
        ):
            raise ValueError
        path_status = os.lstat(policy.daemon_socket_path)
        descriptor_status = os.fstat(listener.fileno())
        if (
            not stat.S_ISSOCK(path_status.st_mode)
            or path_status.st_uid != 0
            or path_status.st_gid != policy.daemon_socket_group_gid
            or stat.S_IMODE(path_status.st_mode) != policy.daemon_socket_mode
            or path_status.st_nlink != 1
            or (
                path_status.st_dev,
                path_status.st_ino,
                path_status.st_nlink,
                path_status.st_uid,
                path_status.st_gid,
            )
            != (
                descriptor_status.st_dev,
                descriptor_status.st_ino,
                descriptor_status.st_nlink,
                descriptor_status.st_uid,
                descriptor_status.st_gid,
            )
        ):
            raise ValueError
        return (
            path_status.st_dev,
            path_status.st_ino,
            path_status.st_nlink,
            path_status.st_uid,
            path_status.st_gid,
            stat.S_IMODE(path_status.st_mode),
        )
    except Exception:
        raise ExecutorDaemonError("activated_socket") from None


def _serve_activated_listener(
    engine: ExecutorDaemonSessionEngine,
    listener: socket.socket,
    *,
    allocation_only: bool = False,
) -> ExecutorTransportReceiptV2 | ExecutorAllocationTransportReceiptV1:
    """Accept exactly one signed local connection from a systemd listener."""

    if type(engine) is not ExecutorDaemonSessionEngine:
        raise ExecutorDaemonError("activated_socket")
    connection: socket.socket | None = None
    try:
        before = _activated_listener_identity(listener, engine._policy)
        listener.settimeout(engine._policy.max_session_seconds)
        connection, _address = listener.accept()
        if _activated_listener_identity(listener, engine._policy) != before:
            raise ValueError
        result = engine.serve_socket(connection, allocation_only=allocation_only)
        connection = None
        return result
    except ExecutorDaemonError:
        raise
    except Exception:
        raise ExecutorDaemonError("activated_socket") from None
    finally:
        if connection is not None:
            with suppress(Exception):
                connection.close()


def serve_systemd_activated_session(
    engine: ExecutorDaemonSessionEngine,
) -> ExecutorTransportReceiptV2 | ExecutorAllocationTransportReceiptV1:
    """Serve one session from the exact systemd socket-activation descriptor.

    A signed, separately installed executable must construct the sealed engine
    and call this adapter.  This library never provisions that executable,
    starts a service, or supplies a mutation backend.
    """

    from omninode_rsd.lifecycle.executor_allocation import SealedAllocationBackendV1

    if type(engine) is not ExecutorDaemonSessionEngine or type(engine._backend) in {
        NoMutationBackend,
        SealedAllocationBackendV1,
    }:
        raise ExecutorDaemonError("backend_unavailable")
    listener = _systemd_activated_listener()
    try:
        return _serve_activated_listener(engine, listener)
    finally:
        with suppress(Exception):
            listener.close()


def serve_systemd_activated_allocation_session(
    engine: ExecutorDaemonSessionEngine,
) -> ExecutorAllocationTransportReceiptV1:
    """Serve exactly one allocation session from the sealed Engine backend.

    This narrow entry point cannot select materialization or start and does
    not install a service.  The generic systemd entry point remains available
    only to already-sealed future effect backends.
    """

    from omninode_rsd.lifecycle.executor_allocation import SealedAllocationBackendV1

    if (
        type(engine) is not ExecutorDaemonSessionEngine
        or type(cast(object, engine._backend)) is not SealedAllocationBackendV1
    ):
        raise ExecutorDaemonError("backend_unavailable")
    listener = _systemd_activated_listener()
    try:
        result = _serve_activated_listener(engine, listener, allocation_only=True)
        if type(result) is not ExecutorAllocationTransportReceiptV1:
            raise ExecutorDaemonError("allocation_backend")
        return result
    finally:
        with suppress(Exception):
            listener.close()


def _executor_daemon_session_engine_for_test(
    *,
    policy: ExecutorTransportPolicyV2,
    signer_genesis: SignerGenesisV1,
    attestation_signer: ExecutorAttestationSigner,
    journal: ExecutorSessionJournal,
    backend: ExecutorMutationBackend | None = None,
    memory_safety: MemorySafetyPreflight | None = None,
) -> ExecutorDaemonSessionEngine:
    """Build an explicitly internal fake-backed engine for offline unit tests.

    The installed construction boundary is
    ``ExecutorDaemonSessionEngine.from_verified_artifact_paths``; this helper
    never loads files, opens a socket, or selects a real backend.
    """

    return ExecutorDaemonSessionEngine(
        policy=policy,
        signer_genesis=signer_genesis,
        attestation_signer=attestation_signer,
        journal=journal,
        backend=backend,
        memory_safety=memory_safety,
        _capability=_DAEMON_ENGINE_CAPABILITY,
    )


class _UnixSocketFrame:
    """Exact binary adapter for one already-accepted AF_UNIX stream."""

    def __init__(self, connection: socket.socket, *, timeout_seconds: int) -> None:
        if type(timeout_seconds) is not int or not 1 <= timeout_seconds <= 60:
            raise ExecutorDaemonError("uds_frame")
        self._connection = connection
        self._deadline = time.monotonic() + timeout_seconds
        self._closed = False

    def _set_remaining_timeout(self) -> None:
        if self._closed:
            raise ExecutorDaemonError("uds_frame")
        remaining = self._deadline - time.monotonic()
        if remaining <= 0:
            raise ExecutorDaemonError("uds_timeout")
        self._connection.settimeout(remaining)

    def read_exact(self, count: int) -> bytes:
        if type(count) is not int or not 1 <= count <= _MAX_JOURNAL_BYTES:
            raise ExecutorDaemonError("uds_frame")
        result = bytearray()
        try:
            while len(result) < count:
                self._set_remaining_timeout()
                chunk = self._connection.recv(count - len(result))
                if not chunk:
                    raise ValueError
                result.extend(chunk)
            return bytes(result)
        except ExecutorDaemonError:
            raise
        except Exception:
            raise ExecutorDaemonError("uds_frame") from None

    def write(self, data: bytes | memoryview) -> int | None:
        if type(data) not in {bytes, memoryview} or not data:
            raise ExecutorDaemonError("uds_frame")
        try:
            self._set_remaining_timeout()
            self._connection.sendall(data)
        except ExecutorDaemonError:
            raise
        except Exception:
            raise ExecutorDaemonError("uds_frame") from None
        return len(data)

    def flush(self) -> None:
        if self._closed:
            raise ExecutorDaemonError("uds_frame")

    def require_eof(self) -> None:
        """Wait through the signed deadline for a clean client half-close."""

        if self._closed:
            raise ExecutorDaemonError("uds_frame")
        try:
            self._set_remaining_timeout()
            if self._connection.recv(1):
                raise ValueError
        except ExecutorDaemonError:
            raise
        except Exception:
            raise ExecutorDaemonError("uds_frame") from None

    def close(self) -> None:
        if self._closed:
            return
        self._closed = True
        with suppress(Exception):
            self._connection.close()


def unix_peer_uid(connection: socket.socket) -> int:
    """Return the kernel-authenticated UID for one Linux AF_UNIX peer."""

    if type(connection) is not socket.socket or connection.family != socket.AF_UNIX:
        raise ExecutorDaemonError("uds_peer")
    if sys.platform != "linux" or not hasattr(socket, "SO_PEERCRED"):
        raise ExecutorDaemonError("uds_peer")
    try:
        raw = connection.getsockopt(socket.SOL_SOCKET, socket.SO_PEERCRED, struct.calcsize("3i"))
        _pid, uid, _gid = struct.unpack("3i", raw)
        if uid < 0:
            raise ValueError
        return uid
    except Exception:
        raise ExecutorDaemonError("uds_peer") from None


def _write_all(sink: FrameByteWriter, value: bytes) -> None:
    try:
        written = sink.write(value)
        if written is not None and written != len(value):
            raise ValueError
        sink.flush()
    except Exception:
        raise ExecutorDaemonError("force_command") from None


def _write_relay_eof_frame(sink: FrameByteWriter) -> None:
    """Emit the relay-authentication marker after secure-shell input validation."""

    _write_all(sink, _RELAY_EOF_FRAME)


def _require_relay_eof_frame(source: FrameByteReader) -> None:
    """Require the exact relay marker; a bare close is never an effect permit."""

    try:
        if source.read_exact(FRAME_HEADER_BYTES) != _RELAY_EOF_FRAME:
            raise ValueError
    except Exception:
        raise ExecutorDaemonError("force_command") from None


class _DeadlineStandardStreams:
    """One bounded non-TTY stdin/stdout dialogue for the forced command."""

    def __init__(self, *, timeout_seconds: int) -> None:
        if type(timeout_seconds) is not int or not 1 <= timeout_seconds <= 60:
            raise ExecutorDaemonError("force_command")
        try:
            stdin = sys.stdin.buffer
            stdout = sys.stdout.buffer
            input_fd = stdin.fileno()
            output_fd = stdout.fileno()
            if (
                type(input_fd) is not int
                or type(output_fd) is not int
                or input_fd < 0
                or output_fd < 0
                or os.isatty(input_fd)
                or os.isatty(output_fd)
            ):
                raise ValueError
        except Exception:
            raise ExecutorDaemonError("force_command") from None
        self._input_fd = input_fd
        self._output_fd = output_fd
        self._deadline = time.monotonic() + timeout_seconds

    def _remaining(self) -> float:
        remaining = self._deadline - time.monotonic()
        if remaining <= 0:
            raise ExecutorDaemonError("force_command_timeout")
        return remaining

    def read_exact(self, count: int) -> bytes:
        if type(count) is not int or not 1 <= count <= _MAX_JOURNAL_BYTES:
            raise ExecutorDaemonError("force_command")
        result = bytearray()
        try:
            while len(result) < count:
                readable, _writable, _exceptional = select.select(
                    [self._input_fd], [], [], self._remaining()
                )
                if not readable:
                    raise ExecutorDaemonError("force_command_timeout")
                chunk = os.read(self._input_fd, count - len(result))
                if not chunk:
                    raise ValueError
                result.extend(chunk)
            return bytes(result)
        except ExecutorDaemonError:
            raise
        except Exception:
            raise ExecutorDaemonError("force_command") from None

    def write(self, data: bytes | memoryview) -> int | None:
        if type(data) not in {bytes, memoryview} or not data:
            raise ExecutorDaemonError("force_command")
        remaining = memoryview(data)
        try:
            while remaining:
                _readable, writable, _exceptional = select.select(
                    [], [self._output_fd], [], self._remaining()
                )
                if not writable:
                    raise ExecutorDaemonError("force_command_timeout")
                written = os.write(self._output_fd, remaining)
                if written <= 0:
                    raise ValueError
                remaining = remaining[written:]
        except ExecutorDaemonError:
            raise
        except Exception:
            raise ExecutorDaemonError("force_command") from None
        return len(data)

    def flush(self) -> None:
        """Descriptor writes are already synchronous for the frame protocol."""

        self._remaining()

    def require_eof(self) -> None:
        """Reject extra client bytes and bound a stalled client half-close."""

        try:
            readable, _writable, _exceptional = select.select(
                [self._input_fd], [], [], self._remaining()
            )
            if not readable:
                raise ExecutorDaemonError("force_command_timeout")
            if os.read(self._input_fd, 1):
                raise ValueError
        except ExecutorDaemonError:
            raise
        except Exception:
            raise ExecutorDaemonError("force_command") from None


class _ForceCommandUdsChannel:
    """Deadline-bound duplex AF_UNIX channel with one explicit half-close."""

    def __init__(self, connection: socket.socket, *, timeout_seconds: int) -> None:
        if type(connection) is not socket.socket or connection.family != socket.AF_UNIX:
            raise ExecutorDaemonError("force_command")
        if type(timeout_seconds) is not int or not 1 <= timeout_seconds <= 60:
            raise ExecutorDaemonError("force_command")
        self._connection = connection
        self._deadline = time.monotonic() + timeout_seconds
        self._input_closed = False
        self._closed = False

    def _remaining(self) -> float:
        remaining = self._deadline - time.monotonic()
        if remaining <= 0:
            raise ExecutorDaemonError("force_command_timeout")
        return remaining

    def read_exact(self, count: int) -> bytes:
        if self._closed or type(count) is not int or not 1 <= count <= _MAX_JOURNAL_BYTES:
            raise ExecutorDaemonError("force_command")
        result = bytearray()
        try:
            while len(result) < count:
                self._connection.settimeout(self._remaining())
                chunk = self._connection.recv(count - len(result))
                if not chunk:
                    raise ValueError
                result.extend(chunk)
            return bytes(result)
        except ExecutorDaemonError:
            raise
        except Exception:
            raise ExecutorDaemonError("force_command") from None

    def write(self, data: bytes | memoryview) -> int | None:
        if self._closed or self._input_closed or type(data) not in {bytes, memoryview} or not data:
            raise ExecutorDaemonError("force_command")
        try:
            self._connection.settimeout(self._remaining())
            self._connection.sendall(data)
        except ExecutorDaemonError:
            raise
        except Exception:
            raise ExecutorDaemonError("force_command") from None
        return len(data)

    def flush(self) -> None:
        if self._closed:
            raise ExecutorDaemonError("force_command")
        self._remaining()

    def close_input(self) -> None:
        if self._closed or self._input_closed:
            raise ExecutorDaemonError("force_command")
        try:
            self._connection.shutdown(socket.SHUT_WR)
            self._input_closed = True
        except Exception:
            raise ExecutorDaemonError("force_command") from None

    def close(self) -> None:
        if self._closed:
            return
        self._closed = True
        with suppress(Exception):
            self._connection.close()


def _connect_force_command_uds(policy: ExecutorTransportPolicyV2) -> _ForceCommandUdsChannel:
    """Open one signed root-owned/group-gated UDS without a network fallback."""

    path = Path(policy.daemon_socket_path)
    connection: socket.socket | None = None
    try:
        before = os.lstat(path)
        if (
            not stat.S_ISSOCK(before.st_mode)
            or before.st_uid != 0
            or before.st_gid != policy.daemon_socket_group_gid
            or stat.S_IMODE(before.st_mode) != policy.daemon_socket_mode
            or before.st_nlink != 1
        ):
            raise ValueError
        connection = socket.socket(socket.AF_UNIX, socket.SOCK_STREAM)
        connection.settimeout(policy.max_session_seconds)
        connection.connect(os.fspath(path))
        after = os.lstat(path)
        if (before.st_dev, before.st_ino, before.st_nlink, before.st_uid, before.st_gid) != (
            after.st_dev,
            after.st_ino,
            after.st_nlink,
            after.st_uid,
            after.st_gid,
        ) or stat.S_IMODE(after.st_mode) != policy.daemon_socket_mode:
            raise ValueError
        return _ForceCommandUdsChannel(connection, timeout_seconds=policy.max_session_seconds)
    except Exception:
        if connection is not None:
            with suppress(Exception):
                connection.close()
        raise ExecutorDaemonError("force_command") from None


class _ForceCommandDaemonChannel(FrameByteReader, FrameByteWriter, Protocol):
    """The single UDS dialogue supports an explicit write half-close."""

    def close_input(self) -> None: ...

    def close(self) -> None: ...


def _forward_group(source: FrameByteReader, sink: FrameByteWriter) -> None:
    """Forward one metadata group and opaque chunks without decoding chunks."""

    try:
        total = 0

        def read_bounded(count: int) -> bytes:
            nonlocal total
            value = source.read_exact(count)
            if type(value) is not bytes or len(value) != count:
                raise ValueError
            total += count
            if total > MAX_TOTAL_BYTES:
                raise ValueError
            return value

        header = read_bounded(FRAME_HEADER_BYTES)
        magic, version, kind, sequence, size = _FRAME_HEADER.unpack(header)
        if (
            magic != FRAME_MAGIC
            or version != FRAME_VERSION
            or kind != 1
            or sequence != 0
            or not 1 <= size <= MAX_METADATA_BYTES
        ):
            raise ValueError
        metadata = read_bounded(size)
        decoded = json.loads(metadata.decode("ascii"))
        count = decoded.get("chunk_count") if type(decoded) is dict else None
        if type(count) is not int or not 0 <= count <= MAX_CHUNKS:
            raise ValueError
        _write_all(sink, header)
        _write_all(sink, metadata)
        for sequence in range(1, count + 1):
            chunk_header = read_bounded(FRAME_HEADER_BYTES)
            magic, version, kind, received_sequence, size = _FRAME_HEADER.unpack(chunk_header)
            if (
                magic != FRAME_MAGIC
                or version != FRAME_VERSION
                or kind != 2
                or received_sequence != sequence
                or not 1 <= size <= MAX_CHUNK_BYTES
            ):
                raise ValueError
            # This shim deliberately treats the following payload as opaque
            # bytes.  It never decodes, formats, or logs a secret chunk.
            chunk = read_bounded(size)
            _write_all(sink, chunk_header)
            _write_all(sink, chunk)
    except ExecutorDaemonError:
        raise
    except Exception:
        raise ExecutorDaemonError("force_command") from None


def _force_command_forward_for_test(
    source: FrameByteReader,
    sink: FrameByteWriter,
    *,
    daemon_connector: Callable[[], _ForceCommandDaemonChannel],
    expected_uid: int,
) -> None:
    """Bounded byte relay for a forced command; it never parses secret chunks.

    The shim derives its effective UID locally; the UDS daemon independently
    obtains SO_PEERCRED.  It relays exactly the Hello/request/receipt dialogue
    and never interprets a secret chunk.
    """

    if (
        type(expected_uid) is not int
        or os.geteuid() != expected_uid
        or not callable(daemon_connector)
    ):
        raise ExecutorDaemonError("uds_peer")
    channel: _ForceCommandDaemonChannel | None = None
    try:
        channel = daemon_connector()
        _forward_group(source, channel)
        _forward_group(channel, sink)
        _forward_group(source, channel)
        finalizer = getattr(source, "require_eof", None)
        if callable(finalizer):
            finalizer()
        _write_relay_eof_frame(channel)
        channel.close_input()
        _forward_group(channel, sink)
        channel.close()
    except ExecutorDaemonError:
        raise
    except Exception:
        raise ExecutorDaemonError("force_command") from None
    finally:
        if channel is not None:
            with suppress(Exception):
                channel.close()


class ForceCommandRelay:
    """Signed-policy-bound ForceCommand relay for one restricted executor."""

    def __init__(self, artifacts: VerifiedExecutorTransportArtifactsV2) -> None:
        if type(artifacts) is not VerifiedExecutorTransportArtifactsV2:
            raise ExecutorDaemonError("force_command")
        self._artifacts = artifacts

    def forward(self) -> None:
        """Relay the one fixed stdio dialogue through a signed local UDS.

        There is intentionally no public reader/writer or connector injection:
        live ForceCommand execution always uses deadline-bounded inherited
        stdio, the signed UDS path, and an EOF-delimited nonmultiplexed
        dialogue. Offline tests exercise the underscored helper above.
        """

        policy = self._artifacts.policy
        try:
            group_ids = frozenset((*os.getgroups(), os.getegid()))
        except Exception:
            raise ExecutorDaemonError("uds_peer") from None
        if (
            os.geteuid() != policy.force_command_user_uid
            or policy.daemon_socket_group_gid not in group_ids
        ):
            raise ExecutorDaemonError("uds_peer")
        stdio = _DeadlineStandardStreams(timeout_seconds=policy.max_session_seconds)
        channel = _connect_force_command_uds(policy)
        try:
            _force_command_forward_for_test(
                stdio,
                stdio,
                daemon_connector=lambda: channel,
                expected_uid=policy.force_command_user_uid,
            )
        finally:
            channel.close()


__all__ = [
    "AllocationExecutorBackendContextV1",
    "BoundedExecutorDelivery",
    "ExecutorAllocationBackendEvidenceV1",
    "ExecutorAttestationSigner",
    "ExecutorBackendContextV2",
    "ExecutorBackendReceiptV2",
    "ExecutorDaemonError",
    "ExecutorDaemonSessionEngine",
    "ExecutorEngineOperationClaimV1",
    "ExecutorEngineOperationKindV1",
    "ExecutorEngineOperationRecorder",
    "ExecutorEngineOperationStateV1",
    "ExecutorMutationBackend",
    "ExecutorRecoveryReceiptV2",
    "ExecutorSecretSink",
    "ExecutorSessionJournal",
    "ExecutorSessionStateV2",
    "ForceCommandRelay",
    "LinuxMemorySafetyPreflight",
    "MemorySafetyLease",
    "MemorySafetyPreflight",
    "NoMutationBackend",
    "SystemdCredentialAttestationSigner",
    "serve_systemd_activated_allocation_session",
    "serve_systemd_activated_session",
    "unix_peer_uid",
    "verify_executor_recovery_receipt",
]
