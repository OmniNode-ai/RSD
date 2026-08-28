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
from typing import Final, Literal, Protocol, cast

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
_RECONCILIATION_DOMAIN: Final = b"omninode-rsd.authorization.reconciliation.v1\x00"
_ARTIFACT_LOCK_PREFIX: Final = ".rsd-authorization-root-"
_OPERATION_LEASE_PREFIX: Final = ".rsd-authorization-operation-"
_VERIFIED_CAPABILITY: Final = object()
_TEST_CLOCK_CAPABILITY: Final = object()
_SAFE_CALL_FAILURE: Final = object()
_OPERATION_TABLE: Final = "authorization_operation_journal"
_LEGACY_OPERATION_TABLE: Final = "authorization_nonce_journal"
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


class JournalMigrationStatus(StrEnum):
    """Read-only classification of a journal before it is used for an effect."""

    ABSENT = "absent"
    EMPTY = "empty"
    CURRENT = "current"
    LEGACY_DETECTED = "legacy_detected"
    UNKNOWN = "unknown"


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


class ReconciliationReceiptV1(_Model):
    """Signed operator evidence that an ambiguous effect committed exactly once."""

    schema_version: Literal["rsd.lifecycle-effect-reconciliation.v1"]
    outcome: Literal["effect_committed"]
    operation_id: str
    idempotency_key: str = Field(pattern=_SHA256)
    effect_receipt_sha256: str = Field(pattern=_SHA256)
    signer_key_id: str = Field(pattern=_IDENTIFIER)
    signature_base64: str = Field(min_length=4, max_length=256)

    @model_validator(mode="after")
    def canonical_signature(self) -> ReconciliationReceiptV1:
        if len(_canonical_base64(self.signature_base64)) != 64:
            raise ValueError("Ed25519 signature has wrong length")
        return self


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
    paths: AuthorizationPaths,
    *,
    now: datetime,
    reader: _OwnerOnlyReader,
) -> tuple[PreflightReceiptV1, dict[str, bytes]]:
    try:
        receipt = compile_preflight(paths.preflight(), now=now, _reader=reader)
    except DisposablePreflightError as error:
        raise AuthorizationError(f"phase_a_{error.phase}") from None
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


def _same_artifact_receipt(first: PreflightReceiptV1, second: PreflightReceiptV1) -> bool:
    """Compare Phase-A commitments without its local compilation timestamp."""

    return first.model_dump(exclude={"emitted_at"}) == second.model_dump(exclude={"emitted_at"})


def _verify_artifact_snapshot(
    paths: AuthorizationPaths,
    *,
    signer: TrustedEd25519SignerV1,
    expected_disposal_owner: str,
    expected_approver_identity: str,
    now: datetime,
    reader: _OwnerOnlyReader,
) -> tuple[_ArtifactVerification, dict[str, bytes]]:
    first, snapshot = _receipt_snapshot(paths, now=now, reader=reader)
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


def _safe_call(call: Callable[[], object]) -> object:
    """Discard arbitrary adapter or callback failures before they escape a boundary."""

    try:
        return call()
    except Exception:
        return _SAFE_CALL_FAILURE


def _provider_item(
    lease: ProviderSnapshotLease, reference: ProviderReferenceV1, *, recheck: bool
) -> ProviderProvenance | None:
    method_name = "recheck" if recheck else "inspect"
    method = _safe_call(lambda: getattr(lease, method_name))
    if method is _SAFE_CALL_FAILURE or not callable(method):
        raise AuthorizationError("provider_failure")
    item = _safe_call(lambda: method(reference))
    if item is _SAFE_CALL_FAILURE:
        raise AuthorizationError("provider_failure")
    if item is None:
        return None
    candidate = cast(ProviderProvenance, item)
    fields = _safe_call(
        lambda: (
            candidate.provider,
            candidate.service,
            candidate.account,
            candidate.version,
            candidate.reference_sha256,
            candidate.fingerprint_sha256,
        )
    )
    if fields is _SAFE_CALL_FAILURE or type(fields) is not tuple or len(fields) != 6:
        raise AuthorizationError("provider_failure")
    provider, service, account, version, reference_sha256, fingerprint_sha256 = fields
    if (
        type(provider) is not str
        or type(service) is not str
        or type(account) is not str
        or type(version) is not int
        or type(reference_sha256) is not str
        or type(fingerprint_sha256) is not str
    ):
        raise AuthorizationError("provider_provenance")
    return ProviderProvenance(
        provider=provider,
        service=service,
        account=account,
        version=version,
        reference_sha256=reference_sha256,
        fingerprint_sha256=fingerprint_sha256,
    )


def _provider_expectation(item: ProviderProvenance) -> ProviderExpectationV1:
    expected = _safe_call(
        lambda: ProviderExpectationV1(
            provider=item.provider,
            service=item.service,
            account=item.account,
            version=item.version,
            reference_sha256=item.reference_sha256,
            fingerprint_sha256=item.fingerprint_sha256,
        )
    )
    if type(expected) is not ProviderExpectationV1:
        raise AuthorizationError("provider_provenance")
    return expected


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
    for reference in references:
        item = _provider_item(lease, reference, recheck=recheck)
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
        expected.append(_provider_expectation(item))
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
    """A canonical-parent lock and stable directory descriptor for artifacts.

    The lock is placed beside the canonical root rather than inside it.  That
    makes root replacement, renaming, and lock-file replacement observable
    while the original directory descriptor remains the only read capability.
    """

    def __init__(self, root: Path) -> None:
        self._requested_root = root
        self._canonical_root: Path | None = None
        self._parent: Path | None = None
        self._lock_name: str | None = None
        self._parent_identity: tuple[int, int] | None = None
        self._root_identity: tuple[int, int] | None = None
        self._lock_identity: tuple[int, int] | None = None
        self._parent_descriptor: int | None = None
        self._root_descriptor: int | None = None
        self._lock_descriptor: int | None = None

    @staticmethod
    def _validate_directory_details(details: os.stat_result, phase: str) -> tuple[int, int]:
        if (
            not stat.S_ISDIR(details.st_mode)
            or stat.S_ISLNK(details.st_mode)
            or details.st_uid != os.getuid()
            or stat.S_IMODE(details.st_mode) != 0o700
        ):
            raise AuthorizationError(phase)
        return (details.st_dev, details.st_ino)

    @staticmethod
    def _validate_file_details(details: os.stat_result, phase: str) -> tuple[int, int]:
        if (
            not stat.S_ISREG(details.st_mode)
            or stat.S_ISLNK(details.st_mode)
            or details.st_uid != os.getuid()
            or stat.S_IMODE(details.st_mode) != 0o600
            or details.st_nlink != 1
        ):
            raise AuthorizationError(phase)
        return (details.st_dev, details.st_ino)

    @classmethod
    def _directory_identity(cls, path: Path, phase: str) -> tuple[int, int]:
        try:
            return cls._validate_directory_details(os.lstat(path), phase)
        except AuthorizationError:
            raise
        except OSError:
            raise AuthorizationError(phase) from None

    @classmethod
    def _file_identity_at(cls, descriptor: int, name: str, phase: str) -> tuple[int, int]:
        try:
            return cls._validate_file_details(os.lstat(name, dir_fd=descriptor), phase)
        except AuthorizationError:
            raise
        except OSError:
            raise AuthorizationError(phase) from None

    @classmethod
    def _open_directory(cls, path: Path, phase: str) -> tuple[int, tuple[int, int]]:
        before = cls._directory_identity(path, phase)
        descriptor: int | None = None
        try:
            descriptor = os.open(
                path,
                os.O_RDONLY
                | getattr(os, "O_DIRECTORY", 0)
                | getattr(os, "O_CLOEXEC", 0)
                | getattr(os, "O_NOFOLLOW", 0),
            )
            after = cls._validate_directory_details(os.fstat(descriptor), phase)
        except AuthorizationError:
            if descriptor is not None:
                with suppress(OSError):
                    os.close(descriptor)
            raise
        except OSError:
            if descriptor is not None:
                with suppress(OSError):
                    os.close(descriptor)
            raise AuthorizationError(phase) from None
        if before != after:
            with suppress(OSError):
                os.close(descriptor)
            raise AuthorizationError(phase)
        return descriptor, after

    @classmethod
    def _open_lock_file(cls, parent_descriptor: int, name: str) -> tuple[int, tuple[int, int]]:
        try:
            before = cls._file_identity_at(parent_descriptor, name, "artifact_lock_file")
        except AuthorizationError:
            try:
                os.lstat(name, dir_fd=parent_descriptor)
            except FileNotFoundError:
                flags = (
                    os.O_RDWR
                    | os.O_CREAT
                    | os.O_EXCL
                    | getattr(os, "O_CLOEXEC", 0)
                    | getattr(os, "O_NOFOLLOW", 0)
                )
                try:
                    created = os.open(name, flags, 0o600, dir_fd=parent_descriptor)
                except FileExistsError:
                    pass
                except OSError:
                    raise AuthorizationError("artifact_lock_file") from None
                else:
                    try:
                        cls._validate_file_details(os.fstat(created), "artifact_lock_file")
                    finally:
                        with suppress(OSError):
                            os.close(created)
            except OSError:
                raise AuthorizationError("artifact_lock_file") from None
            before = cls._file_identity_at(parent_descriptor, name, "artifact_lock_file")
        descriptor: int | None = None
        try:
            descriptor = os.open(
                name,
                os.O_RDWR | getattr(os, "O_CLOEXEC", 0) | getattr(os, "O_NOFOLLOW", 0),
                dir_fd=parent_descriptor,
            )
            after = cls._validate_file_details(os.fstat(descriptor), "artifact_lock_file")
        except AuthorizationError:
            if descriptor is not None:
                with suppress(OSError):
                    os.close(descriptor)
            raise
        except OSError:
            if descriptor is not None:
                with suppress(OSError):
                    os.close(descriptor)
            raise AuthorizationError("artifact_lock_file") from None
        assert descriptor is not None
        if before != after or before != cls._file_identity_at(
            parent_descriptor, name, "artifact_lock_file"
        ):
            with suppress(OSError):
                os.close(descriptor)
            raise AuthorizationError("artifact_lock_file")
        return descriptor, after

    @staticmethod
    def _canonicalize_root(root: Path) -> Path:
        try:
            details = os.lstat(root)
        except OSError:
            raise AuthorizationError("artifact_lock_root") from None
        if stat.S_ISLNK(details.st_mode):
            raise AuthorizationError("artifact_lock_root")
        canonical = Path(os.path.realpath(root))
        ArtifactRootLease._directory_identity(canonical, "artifact_lock_root")
        return canonical

    def __enter__(self) -> ArtifactRootLease:
        canonical = self._canonicalize_root(self._requested_root)
        parent = canonical.parent
        parent_descriptor: int | None = None
        root_descriptor: int | None = None
        lock_descriptor: int | None = None
        try:
            parent_descriptor, parent_identity = self._open_directory(parent, "artifact_lock_root")
            root_descriptor, root_identity = self._open_directory(canonical, "artifact_lock_root")
            lock_name = f"{_ARTIFACT_LOCK_PREFIX}{_digest(os.fsencode(str(canonical)))}.lock"
            lock_descriptor, lock_identity = self._open_lock_file(parent_descriptor, lock_name)
            fcntl.flock(lock_descriptor, fcntl.LOCK_EX)
            self._canonical_root = canonical
            self._parent = parent
            self._lock_name = lock_name
            self._parent_identity = parent_identity
            self._root_identity = root_identity
            self._lock_identity = lock_identity
            self._parent_descriptor = parent_descriptor
            self._root_descriptor = root_descriptor
            self._lock_descriptor = lock_descriptor
            self.assert_stable()
            return self
        except AuthorizationError:
            self._close_descriptors(lock_descriptor, root_descriptor, parent_descriptor)
            raise
        except OSError:
            self._close_descriptors(lock_descriptor, root_descriptor, parent_descriptor)
            raise AuthorizationError("artifact_lock_file") from None

    @staticmethod
    def _close_descriptors(
        lock_descriptor: int | None,
        root_descriptor: int | None,
        parent_descriptor: int | None,
    ) -> None:
        if lock_descriptor is not None:
            with suppress(OSError):
                fcntl.flock(lock_descriptor, fcntl.LOCK_UN)
            with suppress(OSError):
                os.close(lock_descriptor)
        for descriptor in (root_descriptor, parent_descriptor):
            if descriptor is not None:
                with suppress(OSError):
                    os.close(descriptor)

    def assert_stable(self) -> None:
        """Fail closed if any locked path or descriptor identity changed."""

        if (
            self._canonical_root is None
            or self._parent is None
            or self._lock_name is None
            or self._parent_identity is None
            or self._root_identity is None
            or self._lock_identity is None
            or self._parent_descriptor is None
            or self._root_descriptor is None
            or self._lock_descriptor is None
        ):
            raise AuthorizationError("artifact_lock_state")
        if self._directory_identity(self._parent, "artifact_lock_root") != self._parent_identity:
            raise AuthorizationError("artifact_lock_root")
        if (
            self._directory_identity(self._canonical_root, "artifact_lock_root")
            != self._root_identity
        ):
            raise AuthorizationError("artifact_lock_root")
        try:
            parent_identity = self._validate_directory_details(
                os.fstat(self._parent_descriptor), "artifact_lock_root"
            )
            root_identity = self._validate_directory_details(
                os.fstat(self._root_descriptor), "artifact_lock_root"
            )
            lock_identity = self._validate_file_details(
                os.fstat(self._lock_descriptor), "artifact_lock_file"
            )
        except AuthorizationError:
            raise
        except OSError:
            raise AuthorizationError("artifact_lock_state") from None
        if (
            parent_identity != self._parent_identity
            or root_identity != self._root_identity
            or lock_identity != self._lock_identity
            or self._file_identity_at(
                self._parent_descriptor, self._lock_name, "artifact_lock_file"
            )
            != self._lock_identity
        ):
            raise AuthorizationError("artifact_lock_state")

    def reader(self) -> _OwnerOnlyReader:
        """Return a reader bound to the locked root descriptor."""

        self.assert_stable()
        assert self._canonical_root is not None
        assert self._root_descriptor is not None
        return _OwnerOnlyReader(self._canonical_root, root_fd=self._root_descriptor)

    def __exit__(self, exception_type: object, exception: object, traceback: object) -> None:
        del exception_type, exception, traceback
        self._close_descriptors(
            self._lock_descriptor, self._root_descriptor, self._parent_descriptor
        )
        self._canonical_root = None
        self._parent = None
        self._lock_name = None
        self._parent_identity = None
        self._root_identity = None
        self._lock_identity = None
        self._parent_descriptor = None
        self._root_descriptor = None
        self._lock_descriptor = None


class _OperationLease:
    """One durable, owner-only advisory lease file per operation identifier."""

    def __init__(
        self, journal: SQLiteAuthorizationJournal, operation_id: str, *, nonblocking: bool
    ) -> None:
        self._journal = journal
        self._operation_id = operation_id
        self._nonblocking = nonblocking
        self._parent_descriptor: int | None = None
        self._file_descriptor: int | None = None
        self._parent_identity: tuple[int, int] | None = None
        self._file_identity: tuple[int, int] | None = None
        self._name = f"{_OPERATION_LEASE_PREFIX}{_digest(operation_id.encode())}.lock"

    @staticmethod
    def _open_file(parent_descriptor: int, name: str) -> tuple[int, tuple[int, int]]:
        try:
            before = ArtifactRootLease._file_identity_at(parent_descriptor, name, "operation_lease")
        except AuthorizationError:
            try:
                os.lstat(name, dir_fd=parent_descriptor)
            except FileNotFoundError:
                flags = (
                    os.O_RDWR
                    | os.O_CREAT
                    | os.O_EXCL
                    | getattr(os, "O_CLOEXEC", 0)
                    | getattr(os, "O_NOFOLLOW", 0)
                )
                try:
                    created = os.open(name, flags, 0o600, dir_fd=parent_descriptor)
                except FileExistsError:
                    pass
                except OSError:
                    raise AuthorizationError("operation_lease") from None
                else:
                    try:
                        ArtifactRootLease._validate_file_details(
                            os.fstat(created), "operation_lease"
                        )
                    finally:
                        with suppress(OSError):
                            os.close(created)
            except OSError:
                raise AuthorizationError("operation_lease") from None
            before = ArtifactRootLease._file_identity_at(parent_descriptor, name, "operation_lease")
        descriptor: int | None = None
        try:
            descriptor = os.open(
                name,
                os.O_RDWR | getattr(os, "O_CLOEXEC", 0) | getattr(os, "O_NOFOLLOW", 0),
                dir_fd=parent_descriptor,
            )
            after = ArtifactRootLease._validate_file_details(
                os.fstat(descriptor), "operation_lease"
            )
        except AuthorizationError:
            if descriptor is not None:
                with suppress(OSError):
                    os.close(descriptor)
            raise
        except OSError:
            if descriptor is not None:
                with suppress(OSError):
                    os.close(descriptor)
            raise AuthorizationError("operation_lease") from None
        assert descriptor is not None
        if before != after or before != ArtifactRootLease._file_identity_at(
            parent_descriptor, name, "operation_lease"
        ):
            with suppress(OSError):
                os.close(descriptor)
            raise AuthorizationError("operation_lease")
        return descriptor, after

    def __enter__(self) -> _OperationLease:
        if not self._journal._path.is_absolute():
            raise AuthorizationError("journal_path")
        parent_descriptor: int | None = None
        file_descriptor: int | None = None
        try:
            parent_descriptor, parent_identity = ArtifactRootLease._open_directory(
                self._journal._path.parent, "journal_directory"
            )
            file_descriptor, file_identity = self._open_file(parent_descriptor, self._name)
            lock_flags = fcntl.LOCK_EX | (fcntl.LOCK_NB if self._nonblocking else 0)
            try:
                fcntl.flock(file_descriptor, lock_flags)
            except BlockingIOError:
                raise AuthorizationError("operation_live") from None
            self._parent_descriptor = parent_descriptor
            self._file_descriptor = file_descriptor
            self._parent_identity = parent_identity
            self._file_identity = file_identity
            self.assert_stable()
            return self
        except AuthorizationError:
            self._close(file_descriptor, parent_descriptor)
            raise
        except OSError:
            self._close(file_descriptor, parent_descriptor)
            raise AuthorizationError("operation_lease") from None

    @staticmethod
    def _close(file_descriptor: int | None, parent_descriptor: int | None) -> None:
        if file_descriptor is not None:
            with suppress(OSError):
                fcntl.flock(file_descriptor, fcntl.LOCK_UN)
            with suppress(OSError):
                os.close(file_descriptor)
        if parent_descriptor is not None:
            with suppress(OSError):
                os.close(parent_descriptor)

    def assert_stable(self) -> None:
        if (
            self._parent_descriptor is None
            or self._file_descriptor is None
            or self._parent_identity is None
            or self._file_identity is None
        ):
            raise AuthorizationError("operation_lease")
        if (
            ArtifactRootLease._directory_identity(self._journal._path.parent, "journal_directory")
            != self._parent_identity
        ):
            raise AuthorizationError("operation_lease")
        try:
            parent_identity = ArtifactRootLease._validate_directory_details(
                os.fstat(self._parent_descriptor), "journal_directory"
            )
            file_identity = ArtifactRootLease._validate_file_details(
                os.fstat(self._file_descriptor), "operation_lease"
            )
        except AuthorizationError:
            raise
        except OSError:
            raise AuthorizationError("operation_lease") from None
        if (
            parent_identity != self._parent_identity
            or file_identity != self._file_identity
            or ArtifactRootLease._file_identity_at(
                self._parent_descriptor, self._name, "operation_lease"
            )
            != self._file_identity
        ):
            raise AuthorizationError("operation_lease")

    def __exit__(self, exception_type: object, exception: object, traceback: object) -> None:
        del exception_type, exception, traceback
        self._close(self._file_descriptor, self._parent_descriptor)
        self._parent_descriptor = None
        self._file_descriptor = None
        self._parent_identity = None
        self._file_identity = None


class SQLiteAuthorizationJournal:
    """Owner-only SQLite store for one-shot operation state transitions."""

    def __init__(self, path: Path) -> None:
        self._path = path

    @staticmethod
    def _table_names(connection: sqlite3.Connection) -> set[str]:
        rows = connection.execute(
            "SELECT name FROM sqlite_master WHERE type = 'table' ORDER BY name"
        ).fetchall()
        if not all(type(row[0]) is str for row in rows):
            raise AuthorizationError("journal_schema")
        return {row[0] for row in rows}

    @classmethod
    def _reject_incompatible_tables(cls, connection: sqlite3.Connection) -> None:
        names = cls._table_names(connection)
        if _LEGACY_OPERATION_TABLE in names:
            raise AuthorizationError("journal_legacy_detected")
        if names - {_OPERATION_TABLE}:
            raise AuthorizationError("journal_schema")

    def migration_status(self) -> JournalMigrationStatus:
        """Inspect journal format without creating or changing any file."""

        if not self._path.is_absolute() or not self._path.name or self._path.name in {".", ".."}:
            raise AuthorizationError("journal_path")
        self._validate_owner_directory(self._path.parent)
        try:
            os.lstat(self._path)
        except FileNotFoundError:
            return JournalMigrationStatus.ABSENT
        except OSError:
            raise AuthorizationError("journal_path") from None
        self._validate_owner_file(self._path)
        self._validate_companions()
        try:
            connection = sqlite3.connect(
                f"{self._path.as_uri()}?mode=ro",
                uri=True,
                isolation_level=None,
                timeout=5.0,
            )
        except sqlite3.Error:
            raise AuthorizationError("journal_open") from None
        try:
            connection.execute("PRAGMA trusted_schema = OFF")
            names = self._table_names(connection)
            if _LEGACY_OPERATION_TABLE in names:
                return JournalMigrationStatus.LEGACY_DETECTED
            if names == set():
                return JournalMigrationStatus.EMPTY
            if names != {_OPERATION_TABLE}:
                return JournalMigrationStatus.UNKNOWN
            try:
                self._validate_schema(connection)
            except AuthorizationError:
                return JournalMigrationStatus.UNKNOWN
            return JournalMigrationStatus.CURRENT
        except AuthorizationError:
            raise
        except sqlite3.Error:
            raise AuthorizationError("journal_open") from None
        finally:
            connection.close()

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
            self._reject_incompatible_tables(connection)
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
            self._reject_incompatible_tables(connection)
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

    def _operation_lease(self, operation_id: str, *, nonblocking: bool = False) -> _OperationLease:
        if type(operation_id) is not str or not operation_id:
            raise AuthorizationError("operation_id")
        return _OperationLease(self, operation_id, nonblocking=nonblocking)

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
            self._reject_incompatible_tables(connection)
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
        """Mark a released, ambiguous operation unretryable without retrying it."""

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

        with self._operation_lease(operation_id, nonblocking=True) as lease:
            lease.assert_stable()
            result = self._transaction(recover)
            lease.assert_stable()
        assert result is not None
        return AuthorizationOperationState(result)

    def reconcile_ambiguous_effect(
        self,
        receipt: ReconciliationReceiptV1,
        *,
        signer: TrustedEd25519SignerV1,
    ) -> AuthorizationOperationState:
        """Commit only a released ambiguous operation with signed outcome evidence.

        This operation never invokes an effect.  Without a verified typed
        receipt, callers must leave the journal in ``failed_recovery_required``
        and perform no automatic retry.
        """

        _verify_reconciliation_receipt(receipt, signer=signer)

        def reconcile(connection: sqlite3.Connection) -> str:
            row = connection.execute(
                f"""
                SELECT idempotency_key, state FROM {_OPERATION_TABLE}
                WHERE operation_id = ?
                """,
                (receipt.operation_id,),
            ).fetchone()
            if row is None or type(row[0]) is not str or type(row[1]) is not str:
                raise AuthorizationError("operation_state")
            if row[0] != receipt.idempotency_key or row[1] not in {
                AuthorizationOperationState.IN_PROGRESS.value,
                AuthorizationOperationState.FAILED_RECOVERY_REQUIRED.value,
            }:
                raise AuthorizationError("operation_state")
            result = connection.execute(
                f"""
                UPDATE {_OPERATION_TABLE}
                SET state = ?, effect_receipt_sha256 = ?, failure_phase = ?, updated_at = ?
                WHERE operation_id = ? AND idempotency_key = ?
                  AND state IN (?, ?)
                """,
                (
                    AuthorizationOperationState.COMMITTED.value,
                    receipt.effect_receipt_sha256,
                    "reconciled",
                    datetime.now(UTC).isoformat(timespec="seconds").replace("+00:00", "Z"),
                    receipt.operation_id,
                    receipt.idempotency_key,
                    AuthorizationOperationState.IN_PROGRESS.value,
                    AuthorizationOperationState.FAILED_RECOVERY_REQUIRED.value,
                ),
            )
            if result.rowcount != 1:
                raise AuthorizationError("operation_state")
            return AuthorizationOperationState.COMMITTED.value

        with self._operation_lease(receipt.operation_id, nonblocking=True) as lease:
            lease.assert_stable()
            result = self._transaction(reconcile)
            lease.assert_stable()
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


def _reconciliation_message(receipt: ReconciliationReceiptV1) -> bytes:
    material = {
        "effect_receipt_sha256": receipt.effect_receipt_sha256,
        "idempotency_key": receipt.idempotency_key,
        "operation_id": receipt.operation_id,
        "outcome": receipt.outcome,
        "schema_version": receipt.schema_version,
        "signer_key_id": receipt.signer_key_id,
    }
    return _RECONCILIATION_DOMAIN + json.dumps(
        material, sort_keys=True, separators=(",", ":")
    ).encode("ascii")


def _verify_reconciliation_receipt(
    receipt: ReconciliationReceiptV1, *, signer: TrustedEd25519SignerV1
) -> None:
    if (
        type(receipt) is not ReconciliationReceiptV1
        or type(signer) is not TrustedEd25519SignerV1
        or receipt.signer_key_id != signer.key_id
    ):
        raise AuthorizationError("reconciliation_signature")
    signature = _safe_call(lambda: _canonical_base64(receipt.signature_base64))
    if signature is _SAFE_CALL_FAILURE or type(signature) is not bytes:
        raise AuthorizationError("reconciliation_signature")
    verified = _safe_call(lambda: signer.key().verify(signature, _reconciliation_message(receipt)))
    if verified is _SAFE_CALL_FAILURE:
        raise AuthorizationError("reconciliation_signature")


def _read_clock(clock: Callable[[], datetime]) -> datetime:
    observed = _safe_call(clock)
    if type(observed) is not datetime or observed.tzinfo is None or observed.utcoffset() is None:
        raise AuthorizationError("clock")
    return observed.astimezone(UTC)


def _system_utc_clock() -> datetime:
    return datetime.now(UTC)


def _acquire_provider_lease(
    provider: ProviderProvenanceAdapter, references: tuple[ProviderReferenceV1, ...]
) -> tuple[object, ProviderSnapshotLease]:
    manager = _safe_call(lambda: provider.acquire(references))
    if manager is _SAFE_CALL_FAILURE:
        raise AuthorizationError("provider_failure")
    context_manager = cast(AbstractContextManager[ProviderSnapshotLease], manager)
    enter = _safe_call(lambda: context_manager.__enter__)
    exit_method = _safe_call(lambda: context_manager.__exit__)
    if (
        enter is _SAFE_CALL_FAILURE
        or exit_method is _SAFE_CALL_FAILURE
        or not callable(enter)
        or not callable(exit_method)
    ):
        raise AuthorizationError("provider_failure")
    lease = _safe_call(enter)
    if lease is _SAFE_CALL_FAILURE:
        raise AuthorizationError("provider_failure")
    return manager, cast(ProviderSnapshotLease, lease)


def _release_provider_lease(manager: object) -> bool:
    context_manager = cast(AbstractContextManager[ProviderSnapshotLease], manager)
    exit_method = _safe_call(lambda: context_manager.__exit__)
    if exit_method is _SAFE_CALL_FAILURE or not callable(exit_method):
        return False
    return _safe_call(lambda: exit_method(None, None, None)) is not _SAFE_CALL_FAILURE


def _normalized_fingerprints(fingerprints: Mapping[str, str]) -> dict[str, str]:
    normalized = _safe_call(lambda: dict(fingerprints))
    if type(normalized) is not dict or not all(
        type(key) is str and type(value) is str for key, value in normalized.items()
    ):
        raise AuthorizationError("provider_policy")
    return normalized


def _mark_effect_ambiguous(
    journal: SQLiteAuthorizationJournal, verified: _VerifiedExecution
) -> None:
    result = _safe_call(lambda: journal._fail_effect(verified))
    if result is _SAFE_CALL_FAILURE:
        raise AuthorizationError("effect_failed_recovery_required")


def _check_execution_stability(
    artifact_lease: ArtifactRootLease, operation_lease: _OperationLease
) -> None:
    artifact_lease.assert_stable()
    operation_lease.assert_stable()


def _authorize_and_execute_with_clock(
    paths: AuthorizationPaths,
    *,
    signer: TrustedEd25519SignerV1,
    provider: ProviderProvenanceAdapter,
    provider_fingerprints: Mapping[str, str],
    expected_disposal_owner: str,
    expected_approver_identity: str,
    journal: SQLiteAuthorizationJournal,
    effect: Callable[[VerifiedExecutionContext], EffectReceiptV1],
    clock: Callable[[], datetime],
) -> ExecutionReceiptV1:
    """Internal implementation with a capability-hidden test clock.

    The public entry point always supplies the system UTC clock.  A failed
    callback and any process interruption after ``_begin_effect`` leave an
    ambiguous operation that cannot be retried automatically.
    """

    if (
        type(paths) is not AuthorizationPaths
        or type(signer) is not TrustedEd25519SignerV1
        or type(journal) is not SQLiteAuthorizationJournal
        or not callable(effect)
    ):
        raise AuthorizationError("journal_effect")
    journal_status = journal.migration_status()
    if journal_status is JournalMigrationStatus.LEGACY_DETECTED:
        raise AuthorizationError("journal_legacy_detected")
    if journal_status is JournalMigrationStatus.UNKNOWN:
        raise AuthorizationError("journal_schema")
    fingerprints = _normalized_fingerprints(provider_fingerprints)
    with ArtifactRootLease(paths.root) as artifact_lease:
        artifact_lease.assert_stable()
        artifacts, snapshot = _verify_artifact_snapshot(
            paths,
            signer=signer,
            expected_disposal_owner=expected_disposal_owner,
            expected_approver_identity=expected_approver_identity,
            now=_read_clock(clock),
            reader=artifact_lease.reader(),
        )
        artifact_lease.assert_stable()
        references = artifacts.proposal.provider_references.all()
        manager, provider_lease = _acquire_provider_lease(provider, references)
        execution_receipt: ExecutionReceiptV1 | None = None
        provider_released = True
        try:
            initial_provider_sha256, expectations = _provider_commitment(
                references=references,
                lease=provider_lease,
                fingerprints=fingerprints,
                recheck=False,
            )
            artifact_lease.assert_stable()
            repeated_receipt, repeated_snapshot = _receipt_snapshot(
                paths,
                now=_read_clock(clock),
                reader=artifact_lease.reader(),
            )
            artifact_lease.assert_stable()
            if (
                not _same_artifact_receipt(artifacts.receipt, repeated_receipt)
                or snapshot != repeated_snapshot
            ):
                raise AuthorizationError("artifact_race")
            final_provider_sha256, final_expectations = _provider_commitment(
                references=references,
                lease=provider_lease,
                fingerprints=fingerprints,
                recheck=True,
            )
            artifact_lease.assert_stable()
            if (
                initial_provider_sha256 != final_provider_sha256
                or expectations != final_expectations
            ):
                raise AuthorizationError("provider_race")
            authorization_clock = _read_clock(clock)
            terminal_receipt, terminal_snapshot = _receipt_snapshot(
                paths,
                now=authorization_clock,
                reader=artifact_lease.reader(),
            )
            artifact_lease.assert_stable()
            if (
                not _same_artifact_receipt(artifacts.receipt, repeated_receipt)
                or not _same_artifact_receipt(artifacts.receipt, terminal_receipt)
                or snapshot != repeated_snapshot
                or snapshot != terminal_snapshot
            ):
                raise AuthorizationError("artifact_race")
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
            authorized_at = authorization_clock.isoformat(timespec="seconds").replace("+00:00", "Z")
            verified = _VerifiedExecution(
                context=context,
                nonce=secrets.token_hex(16),
                authorized_at=authorized_at,
                capability=_VERIFIED_CAPABILITY,
            )
            with journal._operation_lease(context.operation_id) as operation_lease:
                artifact_lease.assert_stable()
                operation_lease.assert_stable()
                journal._claim_verified(verified)
                journal._begin_effect(verified)
                artifact_lease.assert_stable()
                operation_lease.assert_stable()
                outcome = _safe_call(lambda: effect(context))
                if outcome is _SAFE_CALL_FAILURE:
                    _mark_effect_ambiguous(journal, verified)
                    raise AuthorizationError("effect_failed_recovery_required")
                effect_receipt = _safe_call(lambda: _validate_effect_receipt(context, outcome))
                if type(effect_receipt) is not EffectReceiptV1:
                    _mark_effect_ambiguous(journal, verified)
                    raise AuthorizationError("effect_failed_recovery_required")
                post_effect_stable = _safe_call(
                    lambda: _check_execution_stability(artifact_lease, operation_lease)
                )
                if post_effect_stable is _SAFE_CALL_FAILURE:
                    _mark_effect_ambiguous(journal, verified)
                    raise AuthorizationError("effect_failed_recovery_required")
                committed = _safe_call(lambda: journal._commit_effect(verified, effect_receipt))
                if committed is _SAFE_CALL_FAILURE:
                    _mark_effect_ambiguous(journal, verified)
                    raise AuthorizationError("effect_failed_recovery_required")
                terminal_stable = _safe_call(
                    lambda: _check_execution_stability(artifact_lease, operation_lease)
                )
                if terminal_stable is _SAFE_CALL_FAILURE:
                    raise AuthorizationError("terminal_stability")
                execution_receipt = ExecutionReceiptV1(
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
        finally:
            provider_released = _release_provider_lease(manager)
        assert execution_receipt is not None
        if not provider_released:
            raise AuthorizationError("provider_release")
        return execution_receipt


def _authorize_and_execute_for_test(
    paths: AuthorizationPaths,
    *,
    signer: TrustedEd25519SignerV1,
    provider: ProviderProvenanceAdapter,
    provider_fingerprints: Mapping[str, str],
    expected_disposal_owner: str,
    expected_approver_identity: str,
    journal: SQLiteAuthorizationJournal,
    effect: Callable[[VerifiedExecutionContext], EffectReceiptV1],
    _clock: Callable[[], datetime],
    _capability: object,
) -> ExecutionReceiptV1:
    """Test-only clock seam, inaccessible from the exported entry point."""

    if _capability is not _TEST_CLOCK_CAPABILITY:
        raise AuthorizationError("test_clock")
    return _authorize_and_execute_with_clock(
        paths,
        signer=signer,
        provider=provider,
        provider_fingerprints=provider_fingerprints,
        expected_disposal_owner=expected_disposal_owner,
        expected_approver_identity=expected_approver_identity,
        journal=journal,
        effect=effect,
        clock=_clock,
    )


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
) -> ExecutionReceiptV1:
    """Verify, lease, execute once, and commit using the trusted UTC clock."""

    return _authorize_and_execute_with_clock(
        paths,
        signer=signer,
        provider=provider,
        provider_fingerprints=provider_fingerprints,
        expected_disposal_owner=expected_disposal_owner,
        expected_approver_identity=expected_approver_identity,
        journal=journal,
        effect=effect,
        clock=_system_utc_clock,
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
