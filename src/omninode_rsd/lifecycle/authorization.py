"""Phase-B signature and provenance verification with durable nonce consumption.

The sole public mutation-admission operation is ``authorize_and_consume``.
It verifies the complete artifact set, then records a fresh nonce in an
owner-only SQLite journal before returning a non-consumable audit grant. This
module never retrieves provider values or invokes an external service.
"""

from __future__ import annotations

import argparse
import base64
import binascii
import copy
import hashlib
import json
import os
import re
import secrets
import sqlite3
import stat
from collections.abc import Mapping, Sequence
from contextlib import suppress
from dataclasses import dataclass, field
from datetime import UTC, datetime
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
_SIGNATURE_DOMAIN: Final = b"omninode-rsd.authorization.ed25519.v2\x00"
_VERIFIED_CAPABILITY: Final = object()
_JOURNAL_SCHEMA: Final = """
CREATE TABLE IF NOT EXISTS authorization_nonce_journal (
    nonce TEXT PRIMARY KEY NOT NULL,
    operation_id TEXT NOT NULL,
    receipt_sha256 TEXT NOT NULL,
    claimed_at TEXT NOT NULL
) WITHOUT ROWID
"""


class _Model(BaseModel):
    model_config = ConfigDict(extra="forbid", frozen=True, strict=True, validate_default=True)


class AuthorizationError(RuntimeError):
    """Value-redacted fail-closed authorization error."""

    def __init__(self, phase: str) -> None:
        self.phase = phase
        super().__init__(f"authorization failed at phase: {phase}")


class DetachedAuthorizationSignatureV1(_Model):
    """Detached sidecar for one raw artifact and its canonical signed content."""

    schema_version: Literal["rsd.authorization-signature.v2"]
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
    """Value-free metadata returned by a caller-supplied trusted boundary."""

    provider: str
    service: str
    account: str
    version: int
    reference_sha256: str
    fingerprint_sha256: str


class ProviderProvenanceAdapter(Protocol):
    """Inspect metadata only; provider values are outside this contract."""

    def inspect(self, reference: ProviderReferenceV1) -> ProviderProvenance | None: ...


class AuthorizationGrantV1(_Model):
    """Audit record only; it carries no journal-consumption capability."""

    schema_version: Literal["rsd.lifecycle-authorization-grant.v1"]
    status: Literal["consumed"]
    operation_id: str
    disposal_owner: str
    retention_expires_at: str
    proposal_sha256: str = Field(pattern=_SHA256)
    contract_sha256: str = Field(pattern=_SHA256)
    evidence_sha256: tuple[str, str, str, str, str, str]
    provider_provenance_sha256: str = Field(pattern=_SHA256)
    journal_entry_sha256: str = Field(pattern=_SHA256)
    consumed_at: str


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
class _VerifiedAuthorization:
    """Internal one-shot material that is never returned through the public API."""

    receipt: PreflightReceiptV1
    provider_provenance_sha256: str
    nonce: str
    authorized_at: str
    capability: object = field(repr=False, compare=False)

    def receipt_sha256(self) -> str:
        body = json.dumps(
            {
                "authorized_at": self.authorized_at,
                "contract_sha256": self.receipt.contract_sha256,
                "evidence_sha256": self.receipt.evidence_sha256,
                "nonce": self.nonce,
                "operation_id": self.receipt.operation_id,
                "proposal_sha256": self.receipt.proposal_sha256,
                "provider_provenance_sha256": self.provider_provenance_sha256,
            },
            sort_keys=True,
            separators=(",", ":"),
        )
        return _digest(body.encode())


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

    The omitted digest is derived from the real sidecar signature after that
    signature is calculated. All other marker fields remain covered by
    Ed25519. Raw artifact hashes remain checked against Phase-A bindings.
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
    """Domain-separated Ed25519 bytes: domain, artifact name, canonical digest."""

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


def _provider_commitment(
    *,
    references: tuple[ProviderReferenceV1, ...],
    adapter: ProviderProvenanceAdapter,
    fingerprints: Mapping[str, str],
) -> str:
    if set(fingerprints) != {reference.reference_sha256 for reference in references}:
        raise AuthorizationError("provider_policy")
    if any(
        type(value) is not str or re.fullmatch(_SHA256, value) is None
        for value in fingerprints.values()
    ):
        raise AuthorizationError("provider_policy")
    observed: list[dict[str, object]] = []
    for reference in references:
        item = adapter.inspect(reference)
        if item is None or (
            item.provider != reference.provider
            or item.service != reference.service
            or item.account != reference.account
            or item.version != reference.version
            or item.reference_sha256 != reference.reference_sha256
            or item.fingerprint_sha256 != fingerprints[reference.reference_sha256]
        ):
            raise AuthorizationError("provider_provenance")
        observed.append(
            {
                "account": item.account,
                "fingerprint_sha256": item.fingerprint_sha256,
                "provider": item.provider,
                "reference_sha256": item.reference_sha256,
                "service": item.service,
                "version": item.version,
            }
        )
    return _digest(json.dumps(observed, sort_keys=True, separators=(",", ":")).encode())


def _verify_authorization(
    paths: AuthorizationPaths,
    *,
    signer: TrustedEd25519SignerV1,
    provider: ProviderProvenanceAdapter,
    provider_fingerprints: Mapping[str, str],
    expected_disposal_owner: str,
    expected_approver_identity: str,
    now: datetime | None,
) -> _VerifiedAuthorization:
    clock = datetime.now(UTC) if now is None else now
    if clock.tzinfo is None or clock.utcoffset() is None:
        raise AuthorizationError("clock")
    first, snapshot = _receipt_snapshot(paths, now=clock)
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
    except (AuthorizationError, ValidationError):
        raise AuthorizationError("proposal") from None
    if datetime.fromisoformat(proposal.retention_expires_at.removesuffix("Z") + "+00:00") <= clock:
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
    provenance_sha256 = _provider_commitment(
        references=proposal.provider_references.all(),
        adapter=provider,
        fingerprints=provider_fingerprints,
    )
    second, repeated = _receipt_snapshot(paths, now=clock)
    if first != second or snapshot != repeated:
        raise AuthorizationError("artifact_race")
    authorized_at = clock.astimezone(UTC).isoformat(timespec="seconds").replace("+00:00", "Z")
    return _VerifiedAuthorization(
        receipt=first,
        provider_provenance_sha256=provenance_sha256,
        nonce=secrets.token_hex(16),
        authorized_at=authorized_at,
        capability=_VERIFIED_CAPABILITY,
    )


class SQLiteAuthorizationJournal:
    """Owner-only SQLite nonce ledger with durable, atomic single-use claims."""

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
        rows = connection.execute("PRAGMA table_info(authorization_nonce_journal)").fetchall()
        expected = [
            (0, "nonce", "TEXT", 1, None, 1),
            (1, "operation_id", "TEXT", 1, None, 0),
            (2, "receipt_sha256", "TEXT", 1, None, 0),
            (3, "claimed_at", "TEXT", 1, None, 0),
        ]
        if rows != expected:
            raise AuthorizationError("journal_schema")

    def _claim_verified(self, verified: _VerifiedAuthorization) -> str:
        """Internal-only claim; no public API accepts a decision object."""

        if (
            type(verified) is not _VerifiedAuthorization
            or verified.capability is not _VERIFIED_CAPABILITY
        ):
            raise AuthorizationError("journal")
        connection = self._connect()
        receipt_sha256 = verified.receipt_sha256()
        try:
            connection.execute("BEGIN IMMEDIATE")
            connection.execute(_JOURNAL_SCHEMA)
            self._validate_schema(connection)
            result = connection.execute(
                """
                INSERT INTO authorization_nonce_journal
                    (nonce, operation_id, receipt_sha256, claimed_at)
                VALUES (?, ?, ?, ?)
                ON CONFLICT(nonce) DO NOTHING
                """,
                (
                    verified.nonce,
                    verified.receipt.operation_id,
                    receipt_sha256,
                    verified.authorized_at,
                ),
            )
            if result.rowcount != 1:
                connection.execute("ROLLBACK")
                raise AuthorizationError("nonce_replayed")
            connection.execute("COMMIT")
            self._validate_owner_file(self._path)
            self._validate_companions()
        except AuthorizationError:
            with suppress(sqlite3.Error):
                connection.execute("ROLLBACK")
            raise
        except sqlite3.Error:
            with suppress(sqlite3.Error):
                connection.execute("ROLLBACK")
            raise AuthorizationError("journal_claim") from None
        finally:
            connection.close()
        return _digest(
            json.dumps(
                {
                    "nonce": verified.nonce,
                    "operation_id": verified.receipt.operation_id,
                    "receipt_sha256": receipt_sha256,
                },
                sort_keys=True,
                separators=(",", ":"),
            ).encode()
        )


def authorize_and_consume(
    paths: AuthorizationPaths,
    *,
    signer: TrustedEd25519SignerV1,
    provider: ProviderProvenanceAdapter,
    provider_fingerprints: Mapping[str, str],
    expected_disposal_owner: str,
    expected_approver_identity: str,
    journal: SQLiteAuthorizationJournal,
    now: datetime | None = None,
) -> AuthorizationGrantV1:
    """Verify then atomically consume one nonce before yielding an audit grant."""

    if type(journal) is not SQLiteAuthorizationJournal:
        raise AuthorizationError("journal")
    verified = _verify_authorization(
        paths,
        signer=signer,
        provider=provider,
        provider_fingerprints=provider_fingerprints,
        expected_disposal_owner=expected_disposal_owner,
        expected_approver_identity=expected_approver_identity,
        now=now,
    )
    journal_entry_sha256 = journal._claim_verified(verified)
    return AuthorizationGrantV1(
        schema_version="rsd.lifecycle-authorization-grant.v1",
        status="consumed",
        operation_id=verified.receipt.operation_id,
        disposal_owner=verified.receipt.disposal_owner,
        retention_expires_at=verified.receipt.retention_expires_at,
        proposal_sha256=verified.receipt.proposal_sha256,
        contract_sha256=verified.receipt.contract_sha256,
        evidence_sha256=verified.receipt.evidence_sha256,
        provider_provenance_sha256=verified.provider_provenance_sha256,
        journal_entry_sha256=journal_entry_sha256,
        consumed_at=verified.authorized_at,
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
