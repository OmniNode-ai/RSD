"""Public, fixed-anchor verification for signed executable grants v2.

This module is a data-contract verifier.  It has no ambient configuration,
network client, nonce database, publisher, or runtime adapter.  The only trust
anchor is a content-pinned package resource selected by this module.
"""

from __future__ import annotations

import json
from collections.abc import Mapping
from datetime import UTC, datetime
from hashlib import sha256
from importlib.resources import files
from typing import Annotated, Any, Final, Literal, Self
from uuid import UUID

from cryptography.exceptions import InvalidSignature
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PublicKey
from pydantic import BaseModel, ConfigDict, Field, ValidationError, model_validator

_SHA256 = r"^[0-9a-f]{64}$"
_IDENTIFIER = r"^[a-z][a-z0-9-]{1,63}$"
_MODEL_IDENTIFIER = r"^[a-z][a-z0-9._-]{1,127}$"
_TOPIC = r"^[a-z][a-z0-9-]*(?:[.][a-z][a-z0-9-]*)+$"
_EVENT_CLASS = r"^Model[A-Za-z0-9]*$"
_RESOURCE_ROOT: Final = "resources/"

PUBLIC_TRUST_ANCHOR_RESOURCE: Final = "resources/executable_grant_v2_trust_anchor.json"
SIGNED_EXECUTABLE_GRANT_V2_SCHEMA_RESOURCE: Final = (
    "resources/signed_executable_grant_v2.schema.json"
)
SIGNED_EXECUTABLE_GRANT_V2_VECTORS_RESOURCE: Final = (
    "resources/signed_executable_grant_v2.vectors.json"
)
PUBLIC_TRUST_ANCHOR_SHA256: Final = (
    "e8dcf17ac21033324f6aafd49495f1b84987c3ffac90932ffa82bbad5e769999"
)
SIGNED_EXECUTABLE_GRANT_V2_SCHEMA_SHA256: Final = (
    "4647fea4557e9e36b0e534d6c428cd9c9e3356818b523ac950e761033f9b8f8c"
)
SIGNED_EXECUTABLE_GRANT_V2_VECTORS_SHA256: Final = (
    "3059dcfc045867b5ffdc50ac2e6145b24db0a085c0423ec7b2998dea5f6b7f85"
)

_UUID_FIELDS: Final = frozenset({"grant_id", "envelope_id", "activation_id", "correlation_id"})
_DATETIME_FIELDS: Final = frozenset({"issued_at", "not_before", "expires_at"})
_OCTET_FIELDS: Final = frozenset({"public_key_octets", "signature_octets"})

Sha256 = Annotated[str, Field(pattern=_SHA256)]
Identifier = Annotated[str, Field(pattern=_IDENTIFIER)]
ModelIdentifier = Annotated[str, Field(pattern=_MODEL_IDENTIFIER)]
Octet = Annotated[int, Field(strict=True, ge=0, le=255)]
Ed25519PublicKeyOctets = Annotated[tuple[Octet, ...], Field(min_length=32, max_length=32)]
Ed25519SignatureOctets = Annotated[tuple[Octet, ...], Field(min_length=64, max_length=64)]


class ExecutableGrantVerificationError(ValueError):
    """Raised when a public executable-grant document fails closed."""


class _ContractModel(BaseModel):
    model_config = ConfigDict(extra="forbid", frozen=True, strict=True, validate_default=True)


def _require_utc(value: datetime, *, label: str) -> None:
    if value.tzinfo is None or value.utcoffset() != UTC.utcoffset(value):
        raise ValueError(f"{label} must be UTC timezone-aware")


def _normalize(value: object) -> object:
    if isinstance(value, BaseModel):
        return _normalize(value.model_dump(mode="python"))
    if isinstance(value, dict):
        return {
            str(key): _normalize(item)
            for key, item in sorted(value.items(), key=lambda item: str(item[0]))
        }
    if isinstance(value, tuple | list):
        return [_normalize(item) for item in value]
    if isinstance(value, UUID):
        return str(value)
    if isinstance(value, datetime):
        _require_utc(value, label="canonical datetime")
        return value.astimezone(UTC).isoformat(timespec="microseconds").replace("+00:00", "Z")
    if value is None or isinstance(value, str | int | bool):
        return value
    raise TypeError(f"unsupported canonical value: {type(value).__name__}")


def canonical_executable_grant_json(value: object) -> bytes:
    """Return the one deterministic JSON representation used by this contract."""

    return json.dumps(
        _normalize(value), sort_keys=True, separators=(",", ":"), ensure_ascii=True, allow_nan=False
    ).encode("utf-8")


class ArtifactPinsV2(_ContractModel):
    """Content-addressed artifact facts bound into one authorization."""

    artifact_sha256: Sha256
    rendered_contract_sha256: Sha256
    request_sha256: Sha256


class SingleAttemptPostureV2(_ContractModel):
    """The one-attempt posture signed into an executable authorization."""

    attempt_count: Literal[1]
    retry_disposition: Literal["forbidden"]
    fallback_used: Literal[False]
    recovery_disposition: Literal["report-only"]


class ExecutableGrantMaterialV2(_ContractModel):
    """All signed facts that authorize one bounded executable grant."""

    schema_version: Literal["omninode-rsd.executable-grant-material.v2"] = (
        "omninode-rsd.executable-grant-material.v2"
    )
    dispatch_policy: Literal["backend-pinned-single-attempt.v1"]
    grant_id: UUID
    envelope_id: UUID
    activation_id: UUID
    correlation_id: UUID
    nonce_sha256: Sha256
    pins: ArtifactPinsV2
    tenant_id: Identifier
    backend_id: Identifier
    served_model_id: ModelIdentifier
    posture: SingleAttemptPostureV2
    expected_output_topic: Annotated[str, Field(pattern=_TOPIC)]
    expected_output_event_class: Annotated[str, Field(pattern=_EVENT_CLASS)]
    expected_output_event_index: Literal[0]
    issued_at: datetime
    not_before: datetime
    expires_at: datetime

    @model_validator(mode="after")
    def _validate_lifetime_and_identities(self) -> Self:
        for label, value in (
            ("issued_at", self.issued_at),
            ("not_before", self.not_before),
            ("expires_at", self.expires_at),
        ):
            _require_utc(value, label=label)
        if len({self.grant_id, self.envelope_id, self.activation_id}) != 3:
            raise ValueError("grant, envelope, and activation IDs must be distinct")
        if self.not_before > self.issued_at:
            raise ValueError("not_before must not follow issued_at")
        if self.expires_at <= self.issued_at:
            raise ValueError("expires_at must follow issued_at")
        if (self.expires_at - self.not_before).total_seconds() > 300:
            raise ValueError("grant lifetime must not exceed 300 seconds")
        return self


class GrantAuthorizationMaterialV2(_ContractModel):
    """Canonical signed material and its non-circular authorization identity."""

    schema_version: Literal["omninode-rsd.grant-authorization-material.v2"] = (
        "omninode-rsd.grant-authorization-material.v2"
    )
    domain: Literal["omninode-rsd.signed-executable-grant.v2"] = (
        "omninode-rsd.signed-executable-grant.v2"
    )
    issuer_key_id: Identifier
    issuer_key_fingerprint_sha256: Sha256
    grant: ExecutableGrantMaterialV2

    def canonical_payload(self) -> bytes:
        return canonical_executable_grant_json(self.model_dump(mode="python"))

    def authorization_digest(self) -> str:
        return sha256(self.canonical_payload()).hexdigest()


class SignedExecutableGrantV2(_ContractModel):
    """One signature-bearing executable grant with no attached capability."""

    schema_version: Literal["omninode-rsd.signed-executable-grant.v2"] = (
        "omninode-rsd.signed-executable-grant.v2"
    )
    authorization_material: GrantAuthorizationMaterialV2
    authorization_digest: Sha256
    signature_octets: Ed25519SignatureOctets

    @model_validator(mode="after")
    def _validate_digest_and_signature_shape(self) -> Self:
        if self.authorization_digest != self.authorization_material.authorization_digest():
            raise ValueError("authorization_digest must bind canonical authorization material")
        if not any(self.signature_octets):
            raise ValueError("signature_octets must not be all zero")
        return self

    def signed_payload(self) -> bytes:
        return canonical_executable_grant_json(
            self.model_dump(mode="python", exclude={"signature_octets"})
        )


class PublicGrantTrustAnchorV1(_ContractModel):
    """Topology-free package trust anchor for public executable grants."""

    schema_version: Literal["omninode-rsd.executable-grant-trust-anchor.v1"]
    issuer_key_id: Identifier
    public_key_octets: Ed25519PublicKeyOctets
    public_key_fingerprint_sha256: Sha256

    @model_validator(mode="after")
    def _validate_public_key_fingerprint(self) -> Self:
        if sha256(bytes(self.public_key_octets)).hexdigest() != self.public_key_fingerprint_sha256:
            raise ValueError("trust anchor fingerprint does not bind public key")
        return self


def _reject_duplicate_keys(pairs: list[tuple[str, object]]) -> dict[str, object]:
    result: dict[str, object] = {}
    for key, value in pairs:
        if key in result:
            raise ValueError(f"duplicate JSON key: {key}")
        result[key] = value
    return result


def _decode_wire_value(name: str, value: object) -> object:
    if name in _UUID_FIELDS and type(value) is str:
        return UUID(value)
    if name in _DATETIME_FIELDS and type(value) is str:
        return datetime.fromisoformat(value.replace("Z", "+00:00"))
    if type(value) is dict:
        return {key: _decode_wire_value(key, item) for key, item in value.items()}
    if type(value) is list:
        decoded = [_decode_wire_value(name, item) for item in value]
        return tuple(decoded) if name in _OCTET_FIELDS else decoded
    return value


def _require_wire_versions(raw: dict[str, object]) -> None:
    if raw.get("schema_version") != "omninode-rsd.signed-executable-grant.v2":
        raise ExecutableGrantVerificationError("signed executable grant schema_version is invalid")
    material = raw.get("authorization_material")
    if type(material) is not dict or material.get("schema_version") != (
        "omninode-rsd.grant-authorization-material.v2"
    ):
        raise ExecutableGrantVerificationError(
            "grant authorization material schema_version is invalid"
        )
    if material.get("domain") != "omninode-rsd.signed-executable-grant.v2":
        raise ExecutableGrantVerificationError("grant authorization material domain is invalid")
    grant = material.get("grant")
    if type(grant) is not dict or grant.get("schema_version") != (
        "omninode-rsd.executable-grant-material.v2"
    ):
        raise ExecutableGrantVerificationError(
            "executable grant material schema_version is invalid"
        )


def _resource_bytes(name: str) -> bytes:
    expected = {
        PUBLIC_TRUST_ANCHOR_RESOURCE: PUBLIC_TRUST_ANCHOR_SHA256,
        SIGNED_EXECUTABLE_GRANT_V2_SCHEMA_RESOURCE: SIGNED_EXECUTABLE_GRANT_V2_SCHEMA_SHA256,
        SIGNED_EXECUTABLE_GRANT_V2_VECTORS_RESOURCE: SIGNED_EXECUTABLE_GRANT_V2_VECTORS_SHA256,
    }[name]
    value = files("omninode_grant_verifier").joinpath(name).read_bytes()
    if sha256(value).hexdigest() != expected:
        raise ExecutableGrantVerificationError("package resource digest is invalid")
    return value


def _load_resource_object(name: str) -> dict[str, object]:
    try:
        decoded: Any = json.loads(_resource_bytes(name), object_pairs_hook=_reject_duplicate_keys)
    except (OSError, TypeError, ValueError, json.JSONDecodeError) as exc:
        raise ExecutableGrantVerificationError("package resource is not strict JSON") from exc
    if type(decoded) is not dict:
        raise ExecutableGrantVerificationError("package resource root must be an object")
    return decoded


def public_grant_trust_anchor_v1() -> PublicGrantTrustAnchorV1:
    """Load the only package-selected public trust anchor."""

    raw = _load_resource_object(PUBLIC_TRUST_ANCHOR_RESOURCE)
    try:
        return PublicGrantTrustAnchorV1.model_validate(_decode_wire_value("", raw))
    except ValidationError as exc:
        raise ExecutableGrantVerificationError("public grant trust anchor is invalid") from exc


def signed_executable_grant_v2_json_schema() -> Mapping[str, object]:
    """Return the content-pinned v2 JSON Schema without a caller path."""

    raw = _load_resource_object(SIGNED_EXECUTABLE_GRANT_V2_SCHEMA_RESOURCE)
    if raw.get("$id") != "urn:omninode-rsd:signed-executable-grant:v2":
        raise ExecutableGrantVerificationError("signed executable grant schema identity is invalid")
    return raw


def _restore_vector_fingerprint(wire: object) -> None:
    """Restore a strictly encoded fingerprint from its scanner-safe resource form."""

    if type(wire) is not dict:
        raise ExecutableGrantVerificationError("signed executable grant vector wire is invalid")
    material = wire.get("authorization_material")
    if type(material) is not dict:
        raise ExecutableGrantVerificationError(
            "signed executable grant vector authorization material is invalid"
        )
    chunks = material.pop("issuer_key_fingerprint_sha256_chunks", None)
    if (
        "issuer_key_fingerprint_sha256" in material
        or type(chunks) is not list
        or len(chunks) != 4
        or not all(
            type(chunk) is str
            and len(chunk) == 16
            and all(character in "0123456789abcdef" for character in chunk)
            for chunk in chunks
        )
    ):
        raise ExecutableGrantVerificationError(
            "signed executable grant vector fingerprint chunks are invalid"
        )
    material["issuer_key_fingerprint_sha256"] = "".join(chunks)


def signed_executable_grant_v2_vectors() -> Mapping[str, object]:
    """Return deterministic public verifier vectors without a caller path."""

    raw = _load_resource_object(SIGNED_EXECUTABLE_GRANT_V2_VECTORS_RESOURCE)
    if raw.get("schema_version") != "omninode-rsd.signed-executable-grant-v2-vectors.v1":
        raise ExecutableGrantVerificationError(
            "signed executable grant vectors identity is invalid"
        )
    _restore_vector_fingerprint(raw.get("base_wire"))
    vectors = raw.get("vectors")
    if type(vectors) is not list:
        raise ExecutableGrantVerificationError("signed executable grant vector cases are invalid")
    for vector in vectors:
        if type(vector) is not dict or "wire" not in vector:
            continue
        _restore_vector_fingerprint(vector["wire"])
    return raw


def parse_signed_executable_grant_v2(wire: str | bytes | bytearray) -> SignedExecutableGrantV2:
    """Parse one strict JSON wire document into this canonical public DTO."""

    if type(wire) not in {str, bytes, bytearray}:
        raise ExecutableGrantVerificationError(
            "signed executable grant wire must be JSON text or bytes"
        )
    try:
        raw: Any = json.loads(wire, object_pairs_hook=_reject_duplicate_keys)
    except (TypeError, UnicodeDecodeError, ValueError, json.JSONDecodeError) as exc:
        raise ExecutableGrantVerificationError(
            "signed executable grant wire is not strict JSON"
        ) from exc
    if type(raw) is not dict:
        raise ExecutableGrantVerificationError(
            "signed executable grant wire root must be an object"
        )
    try:
        _require_wire_versions(raw)
        return SignedExecutableGrantV2.model_validate(_decode_wire_value("", raw))
    except (TypeError, ValueError, ValidationError) as exc:
        raise ExecutableGrantVerificationError(
            "signed executable grant wire does not match the fixed contract"
        ) from exc


def verify_signed_executable_grant_v2(
    wire: str | bytes | bytearray,
    *,
    now: datetime,
) -> SignedExecutableGrantV2:
    """Parse and verify a grant against the fixed package trust anchor."""

    if now.tzinfo is None or now.utcoffset() != UTC.utcoffset(now):
        raise ExecutableGrantVerificationError("verification timestamp must be UTC timezone-aware")
    grant = parse_signed_executable_grant_v2(wire)
    anchor = public_grant_trust_anchor_v1()
    material = grant.authorization_material
    if material.issuer_key_id != anchor.issuer_key_id:
        raise ExecutableGrantVerificationError(
            "grant issuer key ID does not match the public trust anchor"
        )
    if material.issuer_key_fingerprint_sha256 != anchor.public_key_fingerprint_sha256:
        raise ExecutableGrantVerificationError(
            "grant issuer fingerprint does not match the public trust anchor"
        )
    verified_at = now.astimezone(UTC)
    lifecycle = material.grant
    issued_at = lifecycle.issued_at.astimezone(UTC)
    not_before = lifecycle.not_before.astimezone(UTC)
    expires_at = lifecycle.expires_at.astimezone(UTC)
    if verified_at < issued_at:
        raise ExecutableGrantVerificationError("grant has not been issued yet")
    if not not_before <= verified_at <= expires_at:
        raise ExecutableGrantVerificationError("grant is stale or not yet valid")
    try:
        Ed25519PublicKey.from_public_bytes(bytes(anchor.public_key_octets)).verify(
            bytes(grant.signature_octets), grant.signed_payload()
        )
    except (InvalidSignature, ValueError) as exc:
        raise ExecutableGrantVerificationError("grant signature is invalid") from exc
    return grant


__all__ = [
    "PUBLIC_TRUST_ANCHOR_RESOURCE",
    "PUBLIC_TRUST_ANCHOR_SHA256",
    "SIGNED_EXECUTABLE_GRANT_V2_SCHEMA_RESOURCE",
    "SIGNED_EXECUTABLE_GRANT_V2_SCHEMA_SHA256",
    "SIGNED_EXECUTABLE_GRANT_V2_VECTORS_RESOURCE",
    "SIGNED_EXECUTABLE_GRANT_V2_VECTORS_SHA256",
    "ArtifactPinsV2",
    "ExecutableGrantMaterialV2",
    "ExecutableGrantVerificationError",
    "GrantAuthorizationMaterialV2",
    "PublicGrantTrustAnchorV1",
    "SignedExecutableGrantV2",
    "SingleAttemptPostureV2",
    "canonical_executable_grant_json",
    "parse_signed_executable_grant_v2",
    "public_grant_trust_anchor_v1",
    "signed_executable_grant_v2_json_schema",
    "signed_executable_grant_v2_vectors",
    "verify_signed_executable_grant_v2",
]
