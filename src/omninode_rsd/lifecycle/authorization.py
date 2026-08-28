"""Read-only Phase-B authorization for signed lifecycle artifacts.

This module verifies signatures and provider metadata; it neither retrieves a
provider value nor performs a lifecycle mutation.  A runtime that can mutate
must consume a successful decision through an atomic, caller-owned journal.
"""

from __future__ import annotations

import argparse
import base64
import binascii
import hashlib
import json
import re
from collections.abc import Callable, Mapping, Sequence
from dataclasses import dataclass
from datetime import UTC, datetime
from pathlib import Path
from typing import Final, Literal, Protocol
from uuid import uuid4

import yaml
from cryptography.exceptions import InvalidSignature
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PublicKey
from pydantic import BaseModel, ConfigDict, Field, ValidationError, model_validator

from omninode_rsd.lifecycle.infisical_disposable import (
    ApprovalEvidenceV1,
    DisposablePreflightError,
    PreflightPaths,
    PreflightReceiptV1,
    ProviderReferenceV1,
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
_EVIDENCE_ARTIFACT_NAMES: Final[frozenset[str]] = frozenset(_ARTIFACT_NAMES[2:])
_SIGNATURE_DOMAIN: Final = b"omninode-rsd.authorization.ed25519.v1\x00"


class _Model(BaseModel):
    model_config = ConfigDict(extra="forbid", frozen=True, strict=True, validate_default=True)


class AuthorizationError(RuntimeError):
    """Value-redacted authorization failure."""

    def __init__(self, phase: str) -> None:
        self.phase = phase
        super().__init__(f"authorization failed at phase: {phase}")


class DetachedAuthorizationSignatureV1(_Model):
    """Portable sidecar containing an actual Ed25519 detached signature."""

    schema_version: Literal["rsd.authorization-signature.v1"]
    artifact_name: str = Field(pattern=r"^[a-z][a-z0-9-]*[.]yaml$")
    artifact_sha256: str = Field(pattern=_SHA256)
    signer_key_id: str = Field(pattern=_IDENTIFIER)
    algorithm: Literal["ed25519"]
    signature_base64: str = Field(min_length=4, max_length=256)

    @model_validator(mode="after")
    def supported_artifact(self) -> DetachedAuthorizationSignatureV1:
        if self.artifact_name not in _ARTIFACT_NAMES:
            raise ValueError("artifact is not authorization material")
        try:
            signature = base64.b64decode(self.signature_base64, validate=True)
        except (binascii.Error, ValueError):
            raise ValueError("signature is not canonical base64") from None
        if len(signature) != 64:
            raise ValueError("Ed25519 signature has wrong length")
        return self


class TrustedEd25519SignerV1(_Model):
    """An injected trust anchor; it is never loaded from configuration."""

    key_id: str = Field(pattern=_IDENTIFIER)
    public_key_base64: str = Field(min_length=4, max_length=128)
    public_key_fingerprint_sha256: str = Field(pattern=_SHA256)

    @model_validator(mode="after")
    def fingerprint_binds_key(self) -> TrustedEd25519SignerV1:
        try:
            key = base64.b64decode(self.public_key_base64, validate=True)
        except (binascii.Error, ValueError):
            raise ValueError("public key is not canonical base64") from None
        if len(key) != 32 or hashlib.sha256(key).hexdigest() != self.public_key_fingerprint_sha256:
            raise ValueError("public key fingerprint does not bind key")
        return self

    def key(self) -> Ed25519PublicKey:
        return Ed25519PublicKey.from_public_bytes(base64.b64decode(self.public_key_base64))


@dataclass(frozen=True, slots=True)
class ProviderProvenance:
    """Value-free provider metadata returned by a trusted boundary."""

    provider: str
    service: str
    account: str
    version: int
    reference_sha256: str
    fingerprint_sha256: str


class ProviderProvenanceAdapter(Protocol):
    """Read metadata only; implementations must not return provider values."""

    def inspect(self, reference: ProviderReferenceV1) -> ProviderProvenance | None: ...


class AuthorizationJournal(Protocol):
    """Durable atomic nonce claimer required by a mutating runtime."""

    def claim(self, *, operation_id: str, nonce: str, receipt_sha256: str) -> bool: ...


class AuthorizationDecisionV1(_Model):
    schema_version: Literal["rsd.lifecycle-authorization-decision.v1"]
    status: Literal["authorized"]
    operation_id: str
    disposal_owner: str
    retention_expires_at: str
    proposal_sha256: str = Field(pattern=_SHA256)
    contract_sha256: str = Field(pattern=_SHA256)
    evidence_sha256: tuple[str, str, str, str, str, str]
    provider_provenance_sha256: str = Field(pattern=_SHA256)
    authorization_nonce: str = Field(pattern=r"^[0-9a-f]{32}$")
    authorized_at: str

    def receipt_sha256(self) -> str:
        body = json.dumps(self.model_dump(mode="json"), sort_keys=True, separators=(",", ":"))
        return hashlib.sha256(body.encode()).hexdigest()


@dataclass(frozen=True, slots=True)
class AuthorizationPaths:
    """Fixed names keep artifact and sidecar substitution out of the API."""

    root: Path

    def preflight(self) -> PreflightPaths:
        return PreflightPaths(root=self.root)

    @staticmethod
    def signature_name(artifact_name: str) -> str:
        return f"{artifact_name}.authorization.yaml"


def _digest(data: bytes) -> str:
    return hashlib.sha256(data).hexdigest()


def _parse_signature(raw: bytes) -> DetachedAuthorizationSignatureV1:
    """Strictly parse one sidecar from a previously captured byte snapshot."""

    try:
        document = yaml.load(raw.decode("utf-8"), Loader=_UniqueLoader)
        if type(document) is not dict or not all(type(key) is str for key in document):
            raise TypeError
        return DetachedAuthorizationSignatureV1.model_validate(document)
    except (UnicodeDecodeError, TypeError, ValidationError, yaml.YAMLError):
        raise AuthorizationError("signature_artifact") from None


def _signature_message(artifact_name: str, artifact_sha256: str) -> bytes:
    return (
        _SIGNATURE_DOMAIN
        + artifact_name.encode("ascii")
        + b"\x00"
        + artifact_sha256.encode("ascii")
    )


def _verify_signature(
    *,
    sidecar: DetachedAuthorizationSignatureV1,
    artifact_name: str,
    artifact: bytes,
    signer: TrustedEd25519SignerV1,
) -> None:
    if (
        sidecar.artifact_name != artifact_name
        or sidecar.artifact_sha256 != _digest(artifact)
        or sidecar.signer_key_id != signer.key_id
    ):
        raise AuthorizationError("signature_binding")
    try:
        signer.key().verify(
            base64.b64decode(sidecar.signature_base64, validate=True),
            _signature_message(artifact_name, sidecar.artifact_sha256),
        )
    except (InvalidSignature, ValueError, binascii.Error):
        raise AuthorizationError("signature_verification") from None


def _verify_embedded_marker(
    *,
    sidecar: DetachedAuthorizationSignatureV1,
    artifact: bytes,
    model: object,
    signer: TrustedEd25519SignerV1,
) -> None:
    marker = getattr(model, "signature", None)
    if marker is None or (
        marker.algorithm != "ed25519-detached-v1"
        or marker.signer_key_id != signer.key_id
        or marker.signer_public_key_fingerprint_sha256 != signer.public_key_fingerprint_sha256
    ):
        raise AuthorizationError("signature_marker")
    _verify_signature(
        sidecar=sidecar,
        artifact_name=sidecar.artifact_name,
        artifact=artifact,
        signer=signer,
    )


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


def authorize(
    paths: AuthorizationPaths,
    *,
    signer: TrustedEd25519SignerV1,
    provider: ProviderProvenanceAdapter,
    provider_fingerprints: Mapping[str, str],
    expected_disposal_owner: str,
    expected_approver_identity: str,
    now: datetime | None = None,
    nonce_factory: Callable[[], str] | None = None,
) -> AuthorizationDecisionV1:
    """Verify all authorization material and return a single-use decision."""

    clock = datetime.now(UTC) if now is None else now
    if clock.tzinfo is None or clock.utcoffset() is None:
        raise AuthorizationError("clock")
    first, snapshot = _receipt_snapshot(paths, now=clock)
    evidence_models: dict[str, BaseModel] = {}
    for name in _ARTIFACT_NAMES:
        artifact = snapshot[name]
        sidecar = _parse_signature(snapshot[AuthorizationPaths.signature_name(name)])
        _verify_signature(sidecar=sidecar, artifact_name=name, artifact=artifact, signer=signer)
        if name in _EVIDENCE_ARTIFACT_NAMES:
            # Re-parse exact snapshot bytes to bind the in-document marker.
            document = yaml.load(artifact.decode("utf-8"), Loader=_UniqueLoader)
            if type(document) is not dict:
                raise AuthorizationError("evidence_model")
            from omninode_rsd.lifecycle.infisical_disposable import (
                GovernedBaselineV1,
                ProviderDeclarationV1,
                RegistryVerificationV1,
                TargetAttestationV1,
            )

            models: Mapping[str, type[BaseModel] | None] = {
                "approval.yaml": ApprovalEvidenceV1,
                "governed-baseline.yaml": GovernedBaselineV1,
                "target-attestation.yaml": TargetAttestationV1,
                "provider-declaration.yaml": ProviderDeclarationV1,
                "registry-verification.yaml": RegistryVerificationV1,
                "postgres-overlay.yaml": None,
            }
            model_type = models[name]
            if model_type is not None:
                try:
                    parsed = model_type.model_validate(document)
                except ValidationError:
                    raise AuthorizationError("evidence_model") from None
                evidence_models[name] = parsed
                _verify_embedded_marker(
                    sidecar=sidecar, artifact=artifact, model=parsed, signer=signer
                )
    proposal_model = yaml.load(snapshot["proposal.yaml"].decode("utf-8"), Loader=_UniqueLoader)
    if type(proposal_model) is not dict:
        raise AuthorizationError("proposal")
    from omninode_rsd.lifecycle.infisical_disposable import ProposalV1

    try:
        proposal = ProposalV1.model_validate(proposal_model)
    except ValidationError:
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
    nonce = uuid4().hex if nonce_factory is None else nonce_factory()
    if len(nonce) != 32 or any(character not in "0123456789abcdef" for character in nonce):
        raise AuthorizationError("nonce")
    return AuthorizationDecisionV1(
        schema_version="rsd.lifecycle-authorization-decision.v1",
        status="authorized",
        operation_id=first.operation_id,
        disposal_owner=first.disposal_owner,
        retention_expires_at=first.retention_expires_at,
        proposal_sha256=first.proposal_sha256,
        contract_sha256=first.contract_sha256,
        evidence_sha256=first.evidence_sha256,
        provider_provenance_sha256=provenance_sha256,
        authorization_nonce=nonce,
        authorized_at=clock.astimezone(UTC).isoformat(timespec="seconds").replace("+00:00", "Z"),
    )


def consume_authorization(decision: AuthorizationDecisionV1, journal: AuthorizationJournal) -> None:
    """Atomically bind a positive decision before a caller may mutate state."""

    if type(decision) is not AuthorizationDecisionV1 or decision.status != "authorized":
        raise AuthorizationError("decision")
    if not journal.claim(
        operation_id=decision.operation_id,
        nonce=decision.authorization_nonce,
        receipt_sha256=decision.receipt_sha256(),
    ):
        raise AuthorizationError("nonce_replayed")


class _UnavailableProvider:
    def inspect(self, reference: ProviderReferenceV1) -> ProviderProvenance | None:
        del reference
        return None


def main(argv: Sequence[str] | None = None) -> int:
    """Read-only command; without an injected provider it deliberately blocks."""

    parser = argparse.ArgumentParser(prog="rsd-lifecycle-authorize")
    commands = parser.add_subparsers(dest="command", required=True)
    command = commands.add_parser(
        "authorize", help="verify authorization through injected boundaries"
    )
    command.add_argument("--root", type=Path, required=True)
    arguments = parser.parse_args(argv)
    # The CLI intentionally exposes no signer or provider-value input surface.
    del arguments
    print(
        json.dumps({"status": "blocked", "phase": "injected_trust_required"}, separators=(",", ":"))
    )
    return 2


if __name__ == "__main__":  # pragma: no cover
    raise SystemExit(main())
