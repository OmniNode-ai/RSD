"""Locked Phase-B verification and effect execution for lifecycle artifacts.

``authorize_and_execute`` is the sole public mutation-admission boundary. It
holds an owner-only artifact-root advisory lock, verifies signed artifacts and
leased provider provenance, durably records an operation, invokes one effect,
and durably records the terminal outcome. It never retrieves provider values
or invokes an external service itself.
"""

from __future__ import annotations

import argparse
import base64
import binascii
import copy
import fcntl
import hashlib
import json
import os
import re
import secrets
import sqlite3
import stat
from collections.abc import Callable, Mapping, Sequence
from contextlib import AbstractContextManager, suppress
from dataclasses import dataclass, field
from datetime import UTC, datetime
from enum import StrEnum
from pathlib import Path
from typing import Final, Literal, Protocol

import yaml
from cryptography.exceptions import InvalidSignature
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PublicKey
from pydantic import BaseModel, ConfigDict, Field, ValidationError, model_validator

from omninode_rsd.lifecycle.infisical_disposable import (
    ApprovalEvidenceV1,
    DisposablePreflightError,
    GovernedBaselineV1,
    PreflightPaths,
    PreflightReceiptV1,
    ProposalV1,
    ProviderDeclarationV1,
    ProviderReferenceV1,
    RegistryVerificationV1,
    RuntimeContractV1,
    TargetAttestationV1,
    _OwnerOnlyReader,
    _UniqueLoader,
    compile_preflight,
)

_SHA256: Final = r"^[0-9a-f]{64}$"
_IDENTIFIER: Final = r"^[A-Za-z][A-Za-z0-9_.-]{0,127}$"
_ARTIFACT_NAMES: Final[tuple[str, ...]] = (
    "proposal.yaml",
    "runtime-contract.yaml",
    "approval.yaml",
    "governed-baseline.yaml",
    "target-attestation.yaml",
    "provider-declaration.yaml",
    "registry-verification.yaml",
    "postgres-overlay.yaml",
)
_MARKED_EVIDENCE_NAMES: Final[frozenset[str]] = frozenset(_ARTIFACT_NAMES[2:-1])
_SIGNATURE_DOMAIN: Final = b"omninode-rsd.authorization.ed25519.v3\x00"
_IDEMPOTENCY_DOMAIN: Final = b"omninode-rsd.authorization.effect.v1\x00"
_ARTIFACT_LOCK_NAME: Final = ".rsd-authorization.lock"
_VERIFIED_CAPABILITY: Final = object()
_OPERATION_TABLE: Final = "authorization_operation_journal"
_OPERATION_SCHEMA: Final = f"""
CREATE TABLE IF NOT EXISTS {_OPERATION_TABLE} (
    operation_id TEXT PRIMARY KEY NOT NULL,
    nonce TEXT NOT NULL UNIQUE,
    proposal_sha256 TEXT NOT NULL,
    contract_sha256 TEXT NOT NULL,
    provider_provenance_sha256 TEXT NOT NULL,
    idempotency_key TEXT NOT NULL,
    state TEXT NOT NULL,
    effect_receipt_sha256 TEXT,
    failure_phase TEXT,
    created_at TEXT NOT NULL,
    updated_at TEXT NOT NULL,
    CHECK (state IN ('claimed', 'in_progress', 'committed', 'failed_recovery_required'))
) WITHOUT ROWID
"""


class _Model(BaseModel):
    model_config = ConfigDict(extra="forbid", frozen=True, strict=True, validate_default=True)


class AuthorizationError(RuntimeError):
    """Value-redacted fail-closed authorization error."""

    def __init__(self, phase: str) -> None:
        self.phase = phase
        super().__init__(f"authorization failed at phase: {phase}")


class AuthorizationOperationState(StrEnum):
    """Durable lifecycle states for one one-shot authorization operation."""

    CLAIMED = "claimed"
    IN_PROGRESS = "in_progress"
    COMMITTED = "committed"
    FAILED_RECOVERY_REQUIRED = "failed_recovery_required"


class DetachedAuthorizationSignatureV1(_Model):
    """Detached sidecar for one raw artifact and its canonical signed content."""

    schema_version: Literal["rsd.authorization-signature.v3"]
    artifact_name: str = Field(pattern=r"^[a-z][a-z0-9-]*[.]yaml$")
    artifact_sha256: str = Field(pattern=_SHA256)
    signed_content_sha256: str = Field(pattern=_SHA256)
    signer_key_id: str = Field(pattern=_IDENTIFIER)
    algorithm: Literal["ed25519"]
    signature_base64: str = Field(min_length=4, max_length=256)

    @model_validator(mode="after")
    def supported_artifact(self) -> DetachedAuthorizationSignatureV1:
        if self.artifact_name not in _ARTIFACT_NAMES:
            raise ValueError("artifact is not authorization material")
        if len(_canonical_base64(self.signature_base64)) != 64:
            raise ValueError("Ed25519 signature has wrong length")
        return self


class TrustedEd25519SignerV1(_Model):
    """Injected Ed25519 trust anchor; no configuration lookup occurs here."""

    key_id: str = Field(pattern=_IDENTIFIER)
    public_key_base64: str = Field(min_length=4, max_length=128)
    public_key_fingerprint_sha256: str = Field(pattern=_SHA256)

    @model_validator(mode="after")
    def fingerprint_binds_key(self) -> TrustedEd25519SignerV1:
        key = _canonical_base64(self.public_key_base64)
        if len(key) != 32 or hashlib.sha256(key).hexdigest() != self.public_key_fingerprint_sha256:
            raise ValueError("public key fingerprint does not bind key")
        return self

    def key(self) -> Ed25519PublicKey:
        return Ed25519PublicKey.from_public_bytes(_canonical_base64(self.public_key_base64))


@dataclass(frozen=True, slots=True)
class ProviderProvenance:
    """Value-free metadata supplied by one provider snapshot lease."""

    provider: str
    service: str
    account: str
    version: int
    reference_sha256: str
    fingerprint_sha256: str


class ProviderSnapshotLease(Protocol):
    """A lease that keeps referenced provider metadata stable through an effect.

    ``recheck`` must fail or return different metadata if the referenced item
    can no longer be proven to be the same version and fingerprint observed by
    ``inspect``. Implementations that retrieve values do so only inside their
    own lease and never expose those values through this package.
    """

    def inspect(self, reference: ProviderReferenceV1) -> ProviderProvenance | None: ...

    def recheck(self, reference: ProviderReferenceV1) -> ProviderProvenance | None: ...


class ProviderProvenanceAdapter(Protocol):
    """Acquire one leased provider snapshot for the supplied references."""

    def acquire(
        self, references: tuple[ProviderReferenceV1, ...]
    ) -> AbstractContextManager[ProviderSnapshotLease]: ...


class ProviderExpectationV1(_Model):
    """Exact value-free provider binding visible to the effect callback."""

    provider: str = Field(pattern=_IDENTIFIER)
    service: str = Field(pattern=_IDENTIFIER)
    account: str = Field(pattern=_IDENTIFIER)
    version: int = Field(ge=1)
    reference_sha256: str = Field(pattern=_SHA256)
    fingerprint_sha256: str = Field(pattern=_SHA256)


@dataclass(frozen=True, slots=True)
class VerifiedExecutionContext:
    """Immutable effect input with no artifact root, nonce, or journal handle."""

    operation_id: str
    idempotency_key: str
    proposal: ProposalV1
    final_contract: RuntimeContractV1
    provider_expectations: tuple[ProviderExpectationV1, ...]
    proposal_sha256: str
    contract_sha256: str
    provider_provenance_sha256: str


class EffectReceiptV1(_Model):
    """Effect-owned receipt explicitly bound to one execution context."""

    schema_version: Literal["rsd.lifecycle-effect-receipt.v1"]
    operation_id: str
    idempotency_key: str = Field(pattern=_SHA256)
    effect_receipt_sha256: str = Field(pattern=_SHA256)


class ExecutionReceiptV1(_Model):
    """Non-consumable audit result returned only after a committed effect."""

    schema_version: Literal["rsd.lifecycle-execution-receipt.v1"]
    status: Literal["committed"]
    operation_id: str
    idempotency_key: str = Field(pattern=_SHA256)
    effect_receipt_sha256: str = Field(pattern=_SHA256)
    proposal_sha256: str = Field(pattern=_SHA256)
    contract_sha256: str = Field(pattern=_SHA256)
    provider_provenance_sha256: str = Field(pattern=_SHA256)
    committed_at: str


@dataclass(frozen=True, slots=True)
class AuthorizationPaths:
    """Fixed artifact names prevent caller-selected substitution paths."""

    root: Path

    def preflight(self) -> PreflightPaths:
        return PreflightPaths(root=self.root)

    @staticmethod
    def signature_name(artifact_name: str) -> str:
        return f"{artifact_name}.authorization.yaml"


@dataclass(frozen=True, slots=True)
class _ArtifactVerification:
    receipt: PreflightReceiptV1
    proposal: ProposalV1
    final_contract: RuntimeContractV1


@dataclass(frozen=True, slots=True)
class _VerifiedExecution:
    """Opaque internal operation material that the public API never returns."""

    context: VerifiedExecutionContext
    nonce: str
    authorized_at: str
    capability: object = field(repr=False, compare=False)


def _digest(data: bytes) -> str:
    return hashlib.sha256(data).hexdigest()


def _canonical_base64(value: str) -> bytes:
    """Decode standard base64 only when its spelling is unique and canonical."""

    try:
        decoded = base64.b64decode(value, validate=True)
    except (binascii.Error, ValueError):
        raise ValueError("base64 is invalid") from None
    if base64.b64encode(decoded).decode("ascii") != value:
        raise ValueError("base64 is not canonical")
    return decoded


def _parse_document(raw: bytes, *, phase: str) -> dict[str, object]:
    try:
        document = yaml.load(raw.decode("utf-8"), Loader=_UniqueLoader)
        if type(document) is not dict or not all(type(key) is str for key in document):
            raise TypeError
        return document
    except (UnicodeDecodeError, TypeError, yaml.YAMLError):
        raise AuthorizationError(phase) from None


def _parse_signature(raw: bytes) -> DetachedAuthorizationSignatureV1:
    try:
        return DetachedAuthorizationSignatureV1.model_validate(
            _parse_document(raw, phase="signature_artifact")
        )
    except (AuthorizationError, ValidationError, ValueError):
        raise AuthorizationError("signature_artifact") from None


def _canonical_signed_content(artifact_name: str, artifact: bytes) -> bytes:
    """Canonical JSON with only the evidence signature digest omitted.

    The omitted marker is SHA-256 of the actual sidecar signature. The signer,
    key fingerprint, algorithm, and every other artifact field remain covered
    by Ed25519; raw hashes are independently checked against Phase-A bindings.
    """

    document = _parse_document(artifact, phase="artifact_content")
    normalized = copy.deepcopy(document)
    if artifact_name in _MARKED_EVIDENCE_NAMES:
        marker = normalized.get("signature")
        if type(marker) is not dict or set(marker) != {
            "algorithm",
            "detached_signature_sha256",
            "signer_key_id",
            "signer_public_key_fingerprint_sha256",
        }:
            raise AuthorizationError("signature_marker")
        digest = marker.pop("detached_signature_sha256")
        if type(digest) is not str or re.fullmatch(_SHA256, digest) is None:
            raise AuthorizationError("signature_marker")
    try:
        return json.dumps(normalized, sort_keys=True, separators=(",", ":")).encode("utf-8")
    except (TypeError, ValueError):
        raise AuthorizationError("artifact_content") from None


def _signature_message(artifact_name: str, signed_content_sha256: str) -> bytes:
    """Ed25519 input: fixed domain, artifact name, canonical-content digest."""

    return (
        _SIGNATURE_DOMAIN
        + artifact_name.encode("ascii")
        + b"\x00"
        + signed_content_sha256.encode("ascii")
    )


def _verify_signature(
    *,
    sidecar: DetachedAuthorizationSignatureV1,
    artifact_name: str,
    artifact: bytes,
    signer: TrustedEd25519SignerV1,
) -> bytes:
    if (
        sidecar.artifact_name != artifact_name
        or sidecar.artifact_sha256 != _digest(artifact)
        or sidecar.signer_key_id != signer.key_id
        or sidecar.signed_content_sha256
        != _digest(_canonical_signed_content(artifact_name, artifact))
    ):
        raise AuthorizationError("signature_binding")
    try:
        signature = _canonical_base64(sidecar.signature_base64)
        signer.key().verify(
            signature,
            _signature_message(artifact_name, sidecar.signed_content_sha256),
        )
        return signature
    except (InvalidSignature, ValueError, binascii.Error):
        raise AuthorizationError("signature_verification") from None


def _verify_embedded_marker(
    *, signature: bytes, model: object, signer: TrustedEd25519SignerV1
) -> None:
    marker = getattr(model, "signature", None)
    if marker is None or (
        marker.algorithm != "ed25519-detached-v1"
        or marker.signer_key_id != signer.key_id
        or marker.signer_public_key_fingerprint_sha256 != signer.public_key_fingerprint_sha256
        or marker.detached_signature_sha256 != _digest(signature)
    ):
        raise AuthorizationError("signature_marker")


def _receipt_snapshot(
    paths: AuthorizationPaths, *, now: datetime
) -> tuple[PreflightReceiptV1, dict[str, bytes]]:
    try:
        receipt = compile_preflight(paths.preflight(), now=now)
    except DisposablePreflightError as error:
        raise AuthorizationError(f"phase_a_{error.phase}") from None
    reader = _OwnerOnlyReader(paths.root)
    snapshot: dict[str, bytes] = {}
    try:
        for name in _ARTIFACT_NAMES:
            snapshot[name] = reader.read(name)
            snapshot[AuthorizationPaths.signature_name(name)] = reader.read(
                AuthorizationPaths.signature_name(name)
            )
    except DisposablePreflightError:
        raise AuthorizationError("artifact_snapshot") from None
    return receipt, snapshot


def _verify_artifact_snapshot(
    paths: AuthorizationPaths,
    *,
    signer: TrustedEd25519SignerV1,
    expected_disposal_owner: str,
    expected_approver_identity: str,
    now: datetime,
) -> tuple[_ArtifactVerification, dict[str, bytes]]:
    first, snapshot = _receipt_snapshot(paths, now=now)
    evidence_models: dict[str, BaseModel] = {}
    model_types: Mapping[str, type[BaseModel] | None] = {
        "approval.yaml": ApprovalEvidenceV1,
        "governed-baseline.yaml": GovernedBaselineV1,
        "target-attestation.yaml": TargetAttestationV1,
        "provider-declaration.yaml": ProviderDeclarationV1,
        "registry-verification.yaml": RegistryVerificationV1,
        "postgres-overlay.yaml": None,
    }
    for name in _ARTIFACT_NAMES:
        artifact = snapshot[name]
        sidecar = _parse_signature(snapshot[AuthorizationPaths.signature_name(name)])
        signature = _verify_signature(
            sidecar=sidecar, artifact_name=name, artifact=artifact, signer=signer
        )
        model_type = model_types.get(name)
        if model_type is not None:
            try:
                parsed = model_type.model_validate(
                    _parse_document(artifact, phase="evidence_model")
                )
            except (AuthorizationError, ValidationError):
                raise AuthorizationError("evidence_model") from None
            evidence_models[name] = parsed
            _verify_embedded_marker(signature=signature, model=parsed, signer=signer)
    try:
        proposal = ProposalV1.model_validate(
            _parse_document(snapshot["proposal.yaml"], phase="proposal")
        )
        final_contract = RuntimeContractV1.model_validate(
            _parse_document(snapshot["runtime-contract.yaml"], phase="contract")
        )
    except (AuthorizationError, ValidationError):
        raise AuthorizationError("proposal_contract") from None
    if datetime.fromisoformat(proposal.retention_expires_at.removesuffix("Z") + "+00:00") <= now:
        raise AuthorizationError("retention")
    approval = evidence_models.get("approval.yaml")
    if (
        type(expected_disposal_owner) is not str
        or type(expected_approver_identity) is not str
        or proposal.disposal_owner != expected_disposal_owner
        or not isinstance(approval, ApprovalEvidenceV1)
        or approval.approver_identity != expected_approver_identity
    ):
        raise AuthorizationError("owner_approval")
    return _ArtifactVerification(first, proposal, final_contract), snapshot


def _provider_commitment(
    *,
    references: tuple[ProviderReferenceV1, ...],
    lease: ProviderSnapshotLease,
    fingerprints: Mapping[str, str],
    recheck: bool,
) -> tuple[str, tuple[ProviderExpectationV1, ...]]:
    if set(fingerprints) != {reference.reference_sha256 for reference in references}:
        raise AuthorizationError("provider_policy")
    if any(
        type(value) is not str or re.fullmatch(_SHA256, value) is None
        for value in fingerprints.values()
    ):
        raise AuthorizationError("provider_policy")
    expected: list[ProviderExpectationV1] = []
    observed: list[dict[str, object]] = []
    inspect = lease.recheck if recheck else lease.inspect
    for reference in references:
        item = inspect(reference)
        expected_fingerprint = fingerprints[reference.reference_sha256]
        if item is None or (
            item.provider != reference.provider
            or item.service != reference.service
            or item.account != reference.account
            or item.version != reference.version
            or item.reference_sha256 != reference.reference_sha256
            or item.fingerprint_sha256 != expected_fingerprint
        ):
            raise AuthorizationError("provider_provenance")
        expected.append(
            ProviderExpectationV1(
                provider=item.provider,
                service=item.service,
                account=item.account,
                version=item.version,
                reference_sha256=item.reference_sha256,
                fingerprint_sha256=item.fingerprint_sha256,
            )
        )
        observed.append(expected[-1].model_dump(mode="json"))
    return (
        _digest(json.dumps(observed, sort_keys=True, separators=(",", ":")).encode()),
        tuple(expected),
    )


def _idempotency_key(
    *, operation_id: str, proposal_sha256: str, contract_sha256: str, provider_sha256: str
) -> str:
    material = "\x00".join(
        (operation_id, proposal_sha256, contract_sha256, provider_sha256)
    ).encode("ascii")
    return _digest(_IDEMPOTENCY_DOMAIN + material)


class ArtifactRootLease:
    """Exclusive advisory lock for an owner-only artifact root.

    Cooperating artifact writers use the same lease. Noncooperating changes are
    still fail-closed by the locked before/after artifact snapshots.
    """

    def __init__(self, root: Path) -> None:
        self._root = root
        self._lock_path = root / _ARTIFACT_LOCK_NAME
        self._file_descriptor: int | None = None

    @staticmethod
    def _validate_root(root: Path) -> tuple[int, int]:
        try:
            details = os.lstat(root)
        except OSError:
            raise AuthorizationError("artifact_lock_root") from None
        if (
            not stat.S_ISDIR(details.st_mode)
            or stat.S_ISLNK(details.st_mode)
            or details.st_uid != os.getuid()
            or stat.S_IMODE(details.st_mode) != 0o700
        ):
            raise AuthorizationError("artifact_lock_root")
        return (details.st_dev, details.st_ino)

    @staticmethod
    def _validate_file(path: Path) -> tuple[int, int]:
        try:
            details = os.lstat(path)
        except OSError:
            raise AuthorizationError("artifact_lock_file") from None
        if (
            not stat.S_ISREG(details.st_mode)
            or stat.S_ISLNK(details.st_mode)
            or details.st_uid != os.getuid()
            or stat.S_IMODE(details.st_mode) != 0o600
            or details.st_nlink != 1
        ):
            raise AuthorizationError("artifact_lock_file")
        return (details.st_dev, details.st_ino)

    def _open_file(self) -> int:
        self._validate_root(self._root)
        try:
            before = self._validate_file(self._lock_path)
        except AuthorizationError:
            flags = os.O_RDWR | os.O_CREAT | os.O_EXCL | getattr(os, "O_CLOEXEC", 0)
            flags |= getattr(os, "O_NOFOLLOW", 0)
            try:
                file_descriptor = os.open(self._lock_path, flags, 0o600)
            except FileExistsError:
                before = self._validate_file(self._lock_path)
            except OSError:
                raise AuthorizationError("artifact_lock_file") from None
            else:
                with suppress(OSError):
                    os.close(file_descriptor)
                before = self._validate_file(self._lock_path)
        try:
            file_descriptor = os.open(
                self._lock_path,
                os.O_RDWR | getattr(os, "O_CLOEXEC", 0) | getattr(os, "O_NOFOLLOW", 0),
            )
            after = os.fstat(file_descriptor)
        except OSError:
            raise AuthorizationError("artifact_lock_file") from None
        if before != (after.st_dev, after.st_ino):
            with suppress(OSError):
                os.close(file_descriptor)
            raise AuthorizationError("artifact_lock_file")
        return file_descriptor

    def __enter__(self) -> ArtifactRootLease:
        file_descriptor = self._open_file()
        try:
            fcntl.flock(file_descriptor, fcntl.LOCK_EX)
            self._validate_root(self._root)
            locked = os.fstat(file_descriptor)
            if (locked.st_dev, locked.st_ino) != self._validate_file(self._lock_path):
                raise AuthorizationError("artifact_lock_file")
        except AuthorizationError:
            with suppress(OSError):
                fcntl.flock(file_descriptor, fcntl.LOCK_UN)
            with suppress(OSError):
                os.close(file_descriptor)
            raise
        except OSError:
            with suppress(OSError):
                fcntl.flock(file_descriptor, fcntl.LOCK_UN)
            with suppress(OSError):
                os.close(file_descriptor)
            raise AuthorizationError("artifact_lock_file") from None
        self._file_descriptor = file_descriptor
        return self

    def __exit__(self, exception_type: object, exception: object, traceback: object) -> None:
        del exception_type, exception, traceback
        if self._file_descriptor is None:
            return
        with suppress(OSError):
            fcntl.flock(self._file_descriptor, fcntl.LOCK_UN)
        with suppress(OSError):
            os.close(self._file_descriptor)
        self._file_descriptor = None


class SQLiteAuthorizationJournal:
    """Owner-only SQLite store for one-shot operation state transitions."""

    def __init__(self, path: Path) -> None:
        self._path = path

    @staticmethod
    def _validate_owner_directory(path: Path) -> tuple[int, int]:
        try:
            details = os.lstat(path)
        except OSError:
            raise AuthorizationError("journal_directory") from None
        if (
            not stat.S_ISDIR(details.st_mode)
            or stat.S_ISLNK(details.st_mode)
            or details.st_uid != os.getuid()
            or stat.S_IMODE(details.st_mode) != 0o700
        ):
            raise AuthorizationError("journal_directory")
        return (details.st_dev, details.st_ino)

    @staticmethod
    def _validate_owner_file(path: Path) -> tuple[int, int]:
        try:
            details = os.lstat(path)
        except OSError:
            raise AuthorizationError("journal_path") from None
        if (
            not stat.S_ISREG(details.st_mode)
            or stat.S_ISLNK(details.st_mode)
            or details.st_uid != os.getuid()
            or stat.S_IMODE(details.st_mode) != 0o600
            or details.st_nlink != 1
        ):
            raise AuthorizationError("journal_path")
        return (details.st_dev, details.st_ino)

    def _ensure_owner_file(self) -> tuple[int, int]:
        if not self._path.is_absolute() or not self._path.name or self._path.name in {".", ".."}:
            raise AuthorizationError("journal_path")
        self._validate_owner_directory(self._path.parent)
        try:
            return self._validate_owner_file(self._path)
        except AuthorizationError:
            flags = os.O_RDWR | os.O_CREAT | os.O_EXCL | getattr(os, "O_CLOEXEC", 0)
            flags |= getattr(os, "O_NOFOLLOW", 0)
            try:
                file_descriptor = os.open(self._path, flags, 0o600)
            except FileExistsError:
                return self._validate_owner_file(self._path)
            except OSError:
                raise AuthorizationError("journal_path") from None
            try:
                created = os.fstat(file_descriptor)
                if (
                    not stat.S_ISREG(created.st_mode)
                    or created.st_uid != os.getuid()
                    or stat.S_IMODE(created.st_mode) != 0o600
                    or created.st_nlink != 1
                ):
                    raise AuthorizationError("journal_path")
            finally:
                with suppress(OSError):
                    os.close(file_descriptor)
            return self._validate_owner_file(self._path)

    def _validate_companions(self) -> None:
        for suffix in ("-journal", "-wal", "-shm"):
            candidate = self._path.with_name(f"{self._path.name}{suffix}")
            try:
                os.lstat(candidate)
            except FileNotFoundError:
                continue
            except OSError:
                raise AuthorizationError("journal_path") from None
            self._validate_owner_file(candidate)

    def _connect(self) -> sqlite3.Connection:
        before = self._ensure_owner_file()
        self._validate_companions()
        try:
            connection = sqlite3.connect(self._path, isolation_level=None, timeout=5.0)
        except sqlite3.Error:
            raise AuthorizationError("journal_open") from None
        try:
            if before != self._validate_owner_file(self._path):
                raise AuthorizationError("journal_path")
            connection.execute("PRAGMA trusted_schema = OFF")
            row = connection.execute("PRAGMA journal_mode = DELETE").fetchone()
            if row != ("delete",):
                raise AuthorizationError("journal_durability")
            connection.execute("PRAGMA synchronous = FULL")
            self._validate_companions()
            return connection
        except AuthorizationError:
            connection.close()
            raise
        except sqlite3.Error:
            connection.close()
            raise AuthorizationError("journal_open") from None

    @staticmethod
    def _validate_schema(connection: sqlite3.Connection) -> None:
        rows = connection.execute(f"PRAGMA table_info({_OPERATION_TABLE})").fetchall()
        expected = [
            (0, "operation_id", "TEXT", 1, None, 1),
            (1, "nonce", "TEXT", 1, None, 0),
            (2, "proposal_sha256", "TEXT", 1, None, 0),
            (3, "contract_sha256", "TEXT", 1, None, 0),
            (4, "provider_provenance_sha256", "TEXT", 1, None, 0),
            (5, "idempotency_key", "TEXT", 1, None, 0),
            (6, "state", "TEXT", 1, None, 0),
            (7, "effect_receipt_sha256", "TEXT", 0, None, 0),
            (8, "failure_phase", "TEXT", 0, None, 0),
            (9, "created_at", "TEXT", 1, None, 0),
            (10, "updated_at", "TEXT", 1, None, 0),
        ]
        if rows != expected:
            raise AuthorizationError("journal_schema")
        index_rows = connection.execute(f"PRAGMA index_list({_OPERATION_TABLE})").fetchall()
        indexes = {
            (
                bool(index[2]),
                index[3],
                tuple(
                    column[2]
                    for column in connection.execute(f"PRAGMA index_info({index[1]})").fetchall()
                ),
            )
            for index in index_rows
        }
        if indexes != {(True, "pk", ("operation_id",)), (True, "u", ("nonce",))}:
            raise AuthorizationError("journal_schema")
        schema = connection.execute(
            "SELECT sql FROM sqlite_master WHERE type = 'table' AND name = ?", (_OPERATION_TABLE,)
        ).fetchone()
        expected_sql = re.sub(r"\s+", "", _OPERATION_SCHEMA.replace("IF NOT EXISTS ", "").lower())
        if (
            schema is None
            or type(schema[0]) is not str
            or re.sub(r"\s+", "", schema[0].lower()) != expected_sql
        ):
            raise AuthorizationError("journal_schema")

    def _transaction(self, action: Callable[[sqlite3.Connection], str | None]) -> str | None:
        connection = self._connect()
        try:
            connection.execute("BEGIN IMMEDIATE")
            connection.execute(_OPERATION_SCHEMA)
            self._validate_schema(connection)
            result = action(connection)
            connection.execute("COMMIT")
            self._validate_owner_file(self._path)
            self._validate_companions()
            return result
        except AuthorizationError:
            with suppress(sqlite3.Error):
                connection.execute("ROLLBACK")
            raise
        except sqlite3.Error:
            with suppress(sqlite3.Error):
                connection.execute("ROLLBACK")
            raise AuthorizationError("journal_transaction") from None
        finally:
            connection.close()

    @staticmethod
    def _require_verified(verified: _VerifiedExecution) -> None:
        if (
            type(verified) is not _VerifiedExecution
            or verified.capability is not _VERIFIED_CAPABILITY
        ):
            raise AuthorizationError("journal")

    @staticmethod
    def _bindings(verified: _VerifiedExecution) -> tuple[str, str, str, str]:
        context = verified.context
        return (
            context.proposal_sha256,
            context.contract_sha256,
            context.provider_provenance_sha256,
            context.idempotency_key,
        )

    def _claim_verified(self, verified: _VerifiedExecution) -> None:
        self._require_verified(verified)
        proposal_sha256, contract_sha256, provider_sha256, idempotency_key = self._bindings(
            verified
        )

        def claim(connection: sqlite3.Connection) -> None:
            existing = connection.execute(
                f"SELECT state FROM {_OPERATION_TABLE} WHERE operation_id = ?",
                (verified.context.operation_id,),
            ).fetchone()
            if existing is not None:
                raise AuthorizationError("operation_replayed")
            nonce = connection.execute(
                f"SELECT operation_id FROM {_OPERATION_TABLE} WHERE nonce = ?", (verified.nonce,)
            ).fetchone()
            if nonce is not None:
                raise AuthorizationError("nonce_replayed")
            connection.execute(
                f"""
                INSERT INTO {_OPERATION_TABLE} (
                    operation_id, nonce, proposal_sha256, contract_sha256,
                    provider_provenance_sha256, idempotency_key, state,
                    effect_receipt_sha256, failure_phase, created_at, updated_at
                ) VALUES (?, ?, ?, ?, ?, ?, ?, NULL, NULL, ?, ?)
                """,
                (
                    verified.context.operation_id,
                    verified.nonce,
                    proposal_sha256,
                    contract_sha256,
                    provider_sha256,
                    idempotency_key,
                    AuthorizationOperationState.CLAIMED.value,
                    verified.authorized_at,
                    verified.authorized_at,
                ),
            )
            return None

        self._transaction(claim)

    def _begin_effect(self, verified: _VerifiedExecution) -> None:
        self._require_verified(verified)
        proposal_sha256, contract_sha256, provider_sha256, idempotency_key = self._bindings(
            verified
        )

        def begin(connection: sqlite3.Connection) -> None:
            result = connection.execute(
                f"""
                UPDATE {_OPERATION_TABLE}
                SET state = ?, updated_at = ?
                WHERE operation_id = ? AND nonce = ? AND proposal_sha256 = ?
                  AND contract_sha256 = ? AND provider_provenance_sha256 = ?
                  AND idempotency_key = ? AND state = ?
                """,
                (
                    AuthorizationOperationState.IN_PROGRESS.value,
                    verified.authorized_at,
                    verified.context.operation_id,
                    verified.nonce,
                    proposal_sha256,
                    contract_sha256,
                    provider_sha256,
                    idempotency_key,
                    AuthorizationOperationState.CLAIMED.value,
                ),
            )
            if result.rowcount != 1:
                raise AuthorizationError("operation_state")
            return None

        self._transaction(begin)

    def _commit_effect(self, verified: _VerifiedExecution, effect_receipt: EffectReceiptV1) -> None:
        self._require_verified(verified)
        proposal_sha256, contract_sha256, provider_sha256, idempotency_key = self._bindings(
            verified
        )

        def commit(connection: sqlite3.Connection) -> None:
            result = connection.execute(
                f"""
                UPDATE {_OPERATION_TABLE}
                SET state = ?, effect_receipt_sha256 = ?, failure_phase = NULL, updated_at = ?
                WHERE operation_id = ? AND nonce = ? AND proposal_sha256 = ?
                  AND contract_sha256 = ? AND provider_provenance_sha256 = ?
                  AND idempotency_key = ? AND state = ?
                """,
                (
                    AuthorizationOperationState.COMMITTED.value,
                    effect_receipt.effect_receipt_sha256,
                    verified.authorized_at,
                    verified.context.operation_id,
                    verified.nonce,
                    proposal_sha256,
                    contract_sha256,
                    provider_sha256,
                    idempotency_key,
                    AuthorizationOperationState.IN_PROGRESS.value,
                ),
            )
            if result.rowcount != 1:
                raise AuthorizationError("operation_state")
            return None

        self._transaction(commit)

    def _fail_effect(self, verified: _VerifiedExecution) -> None:
        self._require_verified(verified)

        def fail(connection: sqlite3.Connection) -> None:
            result = connection.execute(
                f"""
                UPDATE {_OPERATION_TABLE}
                SET state = ?, failure_phase = ?, updated_at = ?
                WHERE operation_id = ? AND nonce = ? AND state = ?
                """,
                (
                    AuthorizationOperationState.FAILED_RECOVERY_REQUIRED.value,
                    "effect",
                    verified.authorized_at,
                    verified.context.operation_id,
                    verified.nonce,
                    AuthorizationOperationState.IN_PROGRESS.value,
                ),
            )
            if result.rowcount != 1:
                raise AuthorizationError("operation_state")
            return None

        self._transaction(fail)

    def operation_state(self, operation_id: str) -> AuthorizationOperationState | None:
        if type(operation_id) is not str or not operation_id:
            raise AuthorizationError("operation_id")
        connection = self._connect()
        try:
            connection.execute("BEGIN IMMEDIATE")
            connection.execute(_OPERATION_SCHEMA)
            self._validate_schema(connection)
            row = connection.execute(
                f"SELECT state FROM {_OPERATION_TABLE} WHERE operation_id = ?", (operation_id,)
            ).fetchone()
            connection.execute("COMMIT")
        except AuthorizationError:
            with suppress(sqlite3.Error):
                connection.execute("ROLLBACK")
            raise
        except sqlite3.Error:
            with suppress(sqlite3.Error):
                connection.execute("ROLLBACK")
            raise AuthorizationError("journal_transaction") from None
        finally:
            connection.close()
        if row is None:
            return None
        try:
            return AuthorizationOperationState(row[0])
        except (TypeError, ValueError):
            raise AuthorizationError("journal_schema") from None

    def require_recovery(self, operation_id: str) -> AuthorizationOperationState:
        """Explicitly mark a stranded claimed/in-progress operation unretryable."""

        if type(operation_id) is not str or not operation_id:
            raise AuthorizationError("operation_id")

        def recover(connection: sqlite3.Connection) -> str:
            result = connection.execute(
                f"""
                UPDATE {_OPERATION_TABLE}
                SET state = ?, failure_phase = ?, updated_at = ?
                WHERE operation_id = ? AND state IN (?, ?)
                """,
                (
                    AuthorizationOperationState.FAILED_RECOVERY_REQUIRED.value,
                    "explicit_recovery",
                    datetime.now(UTC).isoformat(timespec="seconds").replace("+00:00", "Z"),
                    operation_id,
                    AuthorizationOperationState.CLAIMED.value,
                    AuthorizationOperationState.IN_PROGRESS.value,
                ),
            )
            if result.rowcount != 1:
                raise AuthorizationError("operation_state")
            return AuthorizationOperationState.FAILED_RECOVERY_REQUIRED.value

        result = self._transaction(recover)
        assert result is not None
        return AuthorizationOperationState(result)


def _validate_effect_receipt(context: VerifiedExecutionContext, value: object) -> EffectReceiptV1:
    if type(value) is not EffectReceiptV1:
        raise AuthorizationError("effect_receipt")
    receipt = value
    if (
        receipt.operation_id != context.operation_id
        or receipt.idempotency_key != context.idempotency_key
    ):
        raise AuthorizationError("effect_receipt")
    return receipt


def authorize_and_execute(
    paths: AuthorizationPaths,
    *,
    signer: TrustedEd25519SignerV1,
    provider: ProviderProvenanceAdapter,
    provider_fingerprints: Mapping[str, str],
    expected_disposal_owner: str,
    expected_approver_identity: str,
    journal: SQLiteAuthorizationJournal,
    effect: Callable[[VerifiedExecutionContext], EffectReceiptV1],
    now: datetime | None = None,
) -> ExecutionReceiptV1:
    """Lock, verify, claim, execute once, and commit an effect receipt.

    A failed callback and any process interruption after ``_begin_effect`` leave
    the operation in a non-retryable recovery-required state. The callback gets
    only immutable verified material and must use ``idempotency_key`` for its
    own side effect.
    """

    if type(journal) is not SQLiteAuthorizationJournal or not callable(effect):
        raise AuthorizationError("journal_effect")
    clock = datetime.now(UTC) if now is None else now
    if clock.tzinfo is None or clock.utcoffset() is None:
        raise AuthorizationError("clock")
    with ArtifactRootLease(paths.root):
        artifacts, snapshot = _verify_artifact_snapshot(
            paths,
            signer=signer,
            expected_disposal_owner=expected_disposal_owner,
            expected_approver_identity=expected_approver_identity,
            now=clock,
        )
        references = artifacts.proposal.provider_references.all()
        with provider.acquire(references) as lease:
            initial_provider_sha256, expectations = _provider_commitment(
                references=references,
                lease=lease,
                fingerprints=provider_fingerprints,
                recheck=False,
            )
            repeated_receipt, repeated_snapshot = _receipt_snapshot(paths, now=clock)
            if artifacts.receipt != repeated_receipt or snapshot != repeated_snapshot:
                raise AuthorizationError("artifact_race")
            final_provider_sha256, final_expectations = _provider_commitment(
                references=references,
                lease=lease,
                fingerprints=provider_fingerprints,
                recheck=True,
            )
            if (
                initial_provider_sha256 != final_provider_sha256
                or expectations != final_expectations
            ):
                raise AuthorizationError("provider_race")
            idempotency_key = _idempotency_key(
                operation_id=artifacts.receipt.operation_id,
                proposal_sha256=artifacts.receipt.proposal_sha256,
                contract_sha256=artifacts.receipt.contract_sha256,
                provider_sha256=final_provider_sha256,
            )
            context = VerifiedExecutionContext(
                operation_id=artifacts.receipt.operation_id,
                idempotency_key=idempotency_key,
                proposal=artifacts.proposal,
                final_contract=artifacts.final_contract,
                provider_expectations=final_expectations,
                proposal_sha256=artifacts.receipt.proposal_sha256,
                contract_sha256=artifacts.receipt.contract_sha256,
                provider_provenance_sha256=final_provider_sha256,
            )
            authorized_at = (
                clock.astimezone(UTC).isoformat(timespec="seconds").replace("+00:00", "Z")
            )
            verified = _VerifiedExecution(
                context=context,
                nonce=secrets.token_hex(16),
                authorized_at=authorized_at,
                capability=_VERIFIED_CAPABILITY,
            )
            journal._claim_verified(verified)
            journal._begin_effect(verified)
            try:
                effect_receipt = _validate_effect_receipt(context, effect(context))
            except Exception as error:
                try:
                    journal._fail_effect(verified)
                except AuthorizationError:
                    raise AuthorizationError("effect_failed_recovery_required") from error
                raise AuthorizationError("effect_failed_recovery_required") from error
            journal._commit_effect(verified, effect_receipt)
            return ExecutionReceiptV1(
                schema_version="rsd.lifecycle-execution-receipt.v1",
                status="committed",
                operation_id=context.operation_id,
                idempotency_key=context.idempotency_key,
                effect_receipt_sha256=effect_receipt.effect_receipt_sha256,
                proposal_sha256=context.proposal_sha256,
                contract_sha256=context.contract_sha256,
                provider_provenance_sha256=context.provider_provenance_sha256,
                committed_at=authorized_at,
            )


def main(argv: Sequence[str] | None = None) -> int:
    """Read-only command; embedding code must inject all trusted boundaries."""

    parser = argparse.ArgumentParser(prog="rsd-lifecycle-authorize")
    commands = parser.add_subparsers(dest="command", required=True)
    command = commands.add_parser(
        "authorize", help="verify authorization through injected boundaries"
    )
    command.add_argument("--root", type=Path, required=True)
    arguments = parser.parse_args(argv)
    del arguments
    print(
        json.dumps({"status": "blocked", "phase": "injected_trust_required"}, separators=(",", ":"))
    )
    return 2


if __name__ == "__main__":  # pragma: no cover
    raise SystemExit(main())
