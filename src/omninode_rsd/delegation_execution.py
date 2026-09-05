"""Offline verification of a narrowly scoped delegated execution activation.

The packaged delegation overlay remains the immutable disabled policy.  This
module verifies a separately signed, short-lived activation artifact; it does
not enable the existing ingress or resolve an endpoint, credential, or key.
"""

from __future__ import annotations

import base64
import binascii
import hmac
import json
from collections.abc import Callable
from datetime import UTC, datetime, timedelta
from hashlib import sha256
from re import fullmatch
from typing import Final, Literal
from uuid import UUID

import yaml
from cryptography.exceptions import InvalidSignature
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PublicKey
from pydantic import BaseModel, ConfigDict, Field, ValidationError, model_validator

from omninode_rsd.delegation import (
    DelegatedGrantClaim,
    DelegatedRequest,
    DelegationOverlay,
    VerifiedGrantFacts,
    load_canonical_delegation_overlay,
)
from omninode_rsd.lifecycle.hashing import canonical_json
from omninode_rsd.lifecycle.models import strict_model_values

_SHA256: Final = r"^[0-9a-f]{64}$"
_IDENTIFIER: Final = r"^[a-z][a-z0-9-]{1,63}$"
_MODEL_IDENTIFIER: Final = r"^[a-z][a-z0-9._/-]{2,127}$"
_REFERENCE_SEGMENT: Final = r"[a-z0-9][a-z0-9_-]*"
_ROUTE_REFERENCE: Final = r"^logical://[a-z0-9][a-z0-9_-]*(?:/[a-z0-9][a-z0-9._-]*[a-z0-9])*$"
_ENDPOINT_REFERENCE: Final = rf"^logical://endpoint/{_REFERENCE_SEGMENT}(?:/{_REFERENCE_SEGMENT})*$"
_CREDENTIAL_REFERENCE: Final = (
    rf"^logical://credential/{_REFERENCE_SEGMENT}(?:/{_REFERENCE_SEGMENT})*$"
)
_LOGICAL_REFERENCE: Final = _ROUTE_REFERENCE
_MAX_INPUT_BYTES: Final = 131_072
_MAX_ACTIVATION_LIFETIME: Final = timedelta(minutes=5)
_ACTIVATION_ID_DOMAIN: Final = b"omninode-rsd.delegation-execution-activation-id.v2\x00"
_SIGNATURE_DOMAIN: Final = b"omninode-rsd.delegation-execution-overlay.ed25519.v2\x00"
_ROUTE_AUTHORITY_SIGNATURE_DOMAIN: Final = b"omninode-rsd.delegation-route-authority.ed25519.v1\x00"


def _require_reference(value: object, *, namespace: str) -> None:
    """Reject aliases and traversal-like spellings at the reference boundary."""

    if type(value) is not str:
        raise ValueError("logical reference must be an exact string")
    pattern = {
        "delegation": _ROUTE_REFERENCE,
        "endpoint": _ENDPOINT_REFERENCE,
        "credential": _CREDENTIAL_REFERENCE,
    }.get(namespace)
    if pattern is None or fullmatch(pattern, value) is None:
        raise ValueError(f"logical {namespace} reference is not canonical")
    segments = value.removeprefix("logical://").split("/")
    if any(segment in {"", ".", ".."} for segment in segments):
        raise ValueError(f"logical {namespace} reference contains an invalid segment")


class DelegationExecutionError(ValueError):
    """Base error for invalid or unauthoritative activation material."""


class DelegationExecutionParseError(DelegationExecutionError):
    """Raised when activation input is not bounded, canonical, or typed."""


class DelegationExecutionSignatureError(DelegationExecutionError):
    """Raised when activation trust-anchor or detached signature checks fail."""


class DelegationRouteAuthorityParseError(DelegationExecutionError):
    """Raised when route-authority input is not bounded, canonical, or typed."""


class DelegationRouteAuthoritySignatureError(DelegationExecutionError):
    """Raised when route-authority trust-anchor or detached signature checks fail."""


class _Model(BaseModel):
    model_config = ConfigDict(extra="forbid", frozen=True, strict=True, validate_default=True)


class DelegationExecutionTrustAnchorV1(_Model):
    """Explicit caller-supplied Ed25519 public trust anchor."""

    schema_version: Literal["rsd.delegation-execution-trust-anchor.v1"]
    signer_key_id: str = Field(pattern=_IDENTIFIER)
    signer_public_key_base64: str = Field(min_length=44, max_length=44)
    signer_key_fingerprint_sha256: str = Field(pattern=_SHA256)


class DelegationRouteAuthorityTrustAnchorV1(_Model):
    """Explicit trust anchor for the independently signed route authority."""

    schema_version: Literal["rsd.delegation-route-authority-trust-anchor.v1"]
    signer_key_id: str = Field(pattern=_IDENTIFIER)
    signer_public_key_base64: str = Field(min_length=44, max_length=44)
    signer_key_fingerprint_sha256: str = Field(pattern=_SHA256)


def delegation_execution_activation_sha256(
    *, activation_id: UUID, activation_schema_version: str, activation_version: int
) -> str:
    """Hash the immutable activation identity without its self-referential hash."""

    if (
        type(activation_id) is not UUID
        or type(activation_schema_version) is not str
        or activation_schema_version != "rsd.delegation-execution-activation.v2"
        or type(activation_version) is not int
        or activation_version != 1
    ):
        raise DelegationExecutionError("activation identity is invalid")
    return sha256(
        _ACTIVATION_ID_DOMAIN
        + canonical_json(
            {
                "activation_id": activation_id,
                "activation_schema_version": activation_schema_version,
                "activation_version": activation_version,
            }
        )
    ).hexdigest()


class DelegationExecutionOverlayV1(_Model):
    """A signed, short-lived authorization to activate one exact delegation."""

    schema_version: Literal["rsd.delegation-execution-overlay.v2"]
    execute_enabled: Literal[True]
    authorization_digest: str = Field(pattern=_SHA256)
    request_envelope_sha256: str = Field(pattern=_SHA256)
    backend_id: str = Field(pattern=_IDENTIFIER)
    model_id: str = Field(pattern=_MODEL_IDENTIFIER)
    route_ref: str = Field(pattern=_LOGICAL_REFERENCE)
    disabled_overlay_sha256: str = Field(pattern=_SHA256)
    route_authority_sha256: str = Field(pattern=_SHA256)
    activation_id: UUID
    activation_schema_version: Literal["rsd.delegation-execution-activation.v2"]
    activation_version: Literal[1]
    activation_sha256: str = Field(pattern=_SHA256)
    issued_at: datetime
    expires_at: datetime
    endpoint_ref: str = Field(pattern=_LOGICAL_REFERENCE)
    credential_ref: str = Field(pattern=_LOGICAL_REFERENCE)
    signer_key_id: str = Field(pattern=_IDENTIFIER)
    signer_key_fingerprint_sha256: str = Field(pattern=_SHA256)
    signature_base64: str = Field(min_length=88, max_length=88)

    @model_validator(mode="after")
    def binds_activation_identity(self) -> DelegationExecutionOverlayV1:
        expected = delegation_execution_activation_sha256(
            activation_id=self.activation_id,
            activation_schema_version=self.activation_schema_version,
            activation_version=self.activation_version,
        )
        if not hmac.compare_digest(expected, self.activation_sha256):
            raise ValueError("activation identity hash is invalid")
        _require_reference(self.endpoint_ref, namespace="endpoint")
        _require_reference(self.credential_ref, namespace="credential")
        return self


class DelegationRouteAuthorityV1(_Model):
    """Signed route target facts under a trust root separate from activation."""

    schema_version: Literal["rsd.delegation-route-authority.v1"]
    authorization_digest: str = Field(pattern=_SHA256)
    request_envelope_sha256: str = Field(pattern=_SHA256)
    activation_id: UUID
    activation_sha256: str = Field(pattern=_SHA256)
    route_ref: str = Field(pattern=_ROUTE_REFERENCE)
    backend_id: str = Field(pattern=_IDENTIFIER)
    model_id: str = Field(pattern=_MODEL_IDENTIFIER)
    endpoint_ref: str = Field(pattern=_ENDPOINT_REFERENCE)
    credential_ref: str = Field(pattern=_CREDENTIAL_REFERENCE)
    route_policy_digest: str = Field(pattern=_SHA256)
    credential_provider_id: str = Field(pattern=_IDENTIFIER)
    credential_provider_fingerprint_sha256: str = Field(pattern=_SHA256)
    signer_key_id: str = Field(pattern=_IDENTIFIER)
    signer_key_fingerprint_sha256: str = Field(pattern=_SHA256)
    signature_base64: str = Field(min_length=88, max_length=88)

    @model_validator(mode="after")
    def binds_reference_namespaces(self) -> DelegationRouteAuthorityV1:
        _require_reference(self.route_ref, namespace="delegation")
        _require_reference(self.endpoint_ref, namespace="endpoint")
        _require_reference(self.credential_ref, namespace="credential")
        return self


_ACTIVATION_FIELDS = frozenset(DelegationExecutionOverlayV1.model_fields)
_ANCHOR_FIELDS = frozenset(DelegationExecutionTrustAnchorV1.model_fields)
_ROUTE_AUTHORITY_FIELDS = frozenset(DelegationRouteAuthorityV1.model_fields)
_ROUTE_ANCHOR_FIELDS = frozenset(DelegationRouteAuthorityTrustAnchorV1.model_fields)
_REQUEST_FIELDS = frozenset(DelegatedRequest.model_fields)
_GRANT_FIELDS = frozenset(VerifiedGrantFacts.model_fields)
_POLICY_FIELDS = frozenset(DelegationOverlay.model_fields)


class _UniqueLoader(yaml.SafeLoader):
    """Safe YAML loader rejecting duplicate mapping keys."""


def _mapping(
    loader: _UniqueLoader, node: yaml.MappingNode, deep: bool = False
) -> dict[object, object]:
    result: dict[object, object] = {}
    for key_node, value_node in node.value:
        key = loader.construct_object(key_node, deep=deep)
        if key in result:
            raise yaml.YAMLError("duplicate mapping key")
        result[key] = loader.construct_object(value_node, deep=deep)
    return result


_UniqueLoader.add_constructor(yaml.resolver.BaseResolver.DEFAULT_MAPPING_TAG, _mapping)


def _strict_model[T: BaseModel](
    value: object, expected_type: type[T], field_names: frozenset[str]
) -> T:
    if type(value) is not expected_type:
        raise DelegationExecutionParseError("activation model has an invalid type")
    values = strict_model_values(value, expected_type=expected_type, field_names=field_names)
    if values is None:
        raise DelegationExecutionParseError("activation model has an invalid shape")
    try:
        return expected_type.model_validate(values)
    except ValidationError as error:
        raise DelegationExecutionParseError("activation model is invalid") from error


def _strict_activation(value: object) -> DelegationExecutionOverlayV1:
    activation = _strict_model(value, DelegationExecutionOverlayV1, _ACTIVATION_FIELDS)
    _require_utc(activation.issued_at)
    _require_utc(activation.expires_at)
    return activation


def _strict_anchor(value: object) -> DelegationExecutionTrustAnchorV1:
    return _strict_model(value, DelegationExecutionTrustAnchorV1, _ANCHOR_FIELDS)


def _strict_route_authority(value: object) -> DelegationRouteAuthorityV1:
    return _strict_model(value, DelegationRouteAuthorityV1, _ROUTE_AUTHORITY_FIELDS)


def _strict_route_anchor(value: object) -> DelegationRouteAuthorityTrustAnchorV1:
    return _strict_model(value, DelegationRouteAuthorityTrustAnchorV1, _ROUTE_ANCHOR_FIELDS)


def _canonical_json_bytes(model: BaseModel) -> bytes:
    return canonical_json(model.model_dump(mode="json"))


def _normalize_parsed_activation_utc(
    activation: DelegationExecutionOverlayV1,
) -> DelegationExecutionOverlayV1:
    """Normalize the parser's zero-offset timezone wrapper to the UTC singleton."""

    updates: dict[str, datetime] = {}
    for field_name in ("issued_at", "expires_at"):
        value = getattr(activation, field_name)
        if value.tzinfo is not UTC and value.utcoffset() == timedelta(0):
            updates[field_name] = value.replace(tzinfo=UTC)
    return activation.model_copy(update=updates) if updates else activation


def canonical_delegation_execution_overlay_json_bytes(
    overlay: DelegationExecutionOverlayV1,
) -> bytes:
    """Serialize an activation as canonical JSON for signing or transport."""

    checked = _strict_activation(overlay)
    raw = _canonical_json_bytes(checked)
    if len(raw) > _MAX_INPUT_BYTES:
        raise DelegationExecutionParseError("activation exceeds the input bound")
    return raw


def canonical_delegation_execution_overlay_yaml_bytes(
    overlay: DelegationExecutionOverlayV1,
) -> bytes:
    """Serialize an activation as canonical block YAML for signing or transport."""

    checked = _strict_activation(overlay)
    try:
        raw = yaml.safe_dump(
            checked.model_dump(mode="json"),
            sort_keys=True,
            default_flow_style=False,
            allow_unicode=False,
            width=_MAX_INPUT_BYTES,
        ).encode("utf-8")
    except (TypeError, UnicodeError, yaml.YAMLError) as error:
        raise DelegationExecutionParseError("activation cannot be serialized") from error
    if len(raw) > _MAX_INPUT_BYTES:
        raise DelegationExecutionParseError("activation exceeds the input bound")
    return raw


def parse_delegation_execution_overlay(raw: bytes) -> DelegationExecutionOverlayV1:
    """Parse one exact bounded canonical JSON or block-YAML activation."""

    if type(raw) is not bytes or not raw or len(raw) > _MAX_INPUT_BYTES:
        raise DelegationExecutionParseError("activation bytes exceed the allowed bound")
    if raw.lstrip().startswith(b"{"):
        try:
            decoded = raw.decode("ascii")
            value = json.loads(decoded, object_pairs_hook=_reject_duplicate_keys)
        except (UnicodeDecodeError, json.JSONDecodeError, DelegationExecutionParseError):
            raise DelegationExecutionParseError("activation is not canonical JSON") from None
        if type(value) is not dict:
            raise DelegationExecutionParseError("activation JSON is not an object")
        try:
            activation = DelegationExecutionOverlayV1.model_validate_json(raw)
        except ValidationError as error:
            raise DelegationExecutionParseError("activation JSON is invalid") from error
        activation = _normalize_parsed_activation_utc(activation)
        activation = _strict_activation(activation)
        if canonical_delegation_execution_overlay_json_bytes(activation) != raw:
            raise DelegationExecutionParseError("activation JSON is not canonical")
        return activation
    try:
        value = yaml.load(raw.decode("utf-8"), Loader=_UniqueLoader)
    except (UnicodeDecodeError, TypeError, yaml.YAMLError):
        raise DelegationExecutionParseError("activation is not canonical YAML") from None
    if type(value) is not dict:
        raise DelegationExecutionParseError("activation YAML is not an object")
    try:
        activation = DelegationExecutionOverlayV1.model_validate_json(canonical_json(value))
    except ValidationError as error:
        raise DelegationExecutionParseError("activation YAML is invalid") from error
    activation = _normalize_parsed_activation_utc(activation)
    activation = _strict_activation(activation)
    if canonical_delegation_execution_overlay_yaml_bytes(activation) != raw:
        raise DelegationExecutionParseError("activation YAML is not canonical")
    return activation


def _reject_duplicate_keys(pairs: list[tuple[str, object]]) -> dict[str, object]:
    result: dict[str, object] = {}
    for key, value in pairs:
        if key in result:
            raise DelegationExecutionParseError("activation JSON contains duplicate keys")
        result[key] = value
    return result


def canonical_delegation_route_authority_json_bytes(
    authority: DelegationRouteAuthorityV1,
) -> bytes:
    """Serialize route authority as canonical JSON for signing or transport."""

    checked = _strict_route_authority(authority)
    raw = canonical_json(checked.model_dump(mode="python"))
    if len(raw) > _MAX_INPUT_BYTES:
        raise DelegationRouteAuthorityParseError("route authority exceeds the input bound")
    return raw


def canonical_delegation_route_authority_yaml_bytes(
    authority: DelegationRouteAuthorityV1,
) -> bytes:
    """Serialize route authority as canonical block YAML for signing or transport."""

    checked = _strict_route_authority(authority)
    try:
        raw = yaml.safe_dump(
            checked.model_dump(mode="json"),
            sort_keys=True,
            default_flow_style=False,
            allow_unicode=False,
            width=_MAX_INPUT_BYTES,
        ).encode("utf-8")
    except (TypeError, UnicodeError, yaml.YAMLError) as error:
        raise DelegationRouteAuthorityParseError("route authority cannot be serialized") from error
    if len(raw) > _MAX_INPUT_BYTES:
        raise DelegationRouteAuthorityParseError("route authority exceeds the input bound")
    return raw


def parse_delegation_route_authority(raw: bytes) -> DelegationRouteAuthorityV1:
    """Parse one exact bounded canonical JSON or block-YAML route authority."""

    if type(raw) is not bytes or not raw or len(raw) > _MAX_INPUT_BYTES:
        raise DelegationRouteAuthorityParseError("route authority bytes exceed the allowed bound")
    if raw.lstrip().startswith(b"{"):
        try:
            decoded = raw.decode("ascii")
            value = json.loads(decoded, object_pairs_hook=_reject_duplicate_keys)
        except (
            UnicodeDecodeError,
            json.JSONDecodeError,
            DelegationExecutionParseError,
            DelegationRouteAuthorityParseError,
        ):
            raise DelegationRouteAuthorityParseError(
                "route authority is not canonical JSON"
            ) from None
        if type(value) is not dict:
            raise DelegationRouteAuthorityParseError("route authority JSON is not an object")
        try:
            authority = DelegationRouteAuthorityV1.model_validate_json(raw)
        except ValidationError as error:
            raise DelegationRouteAuthorityParseError("route authority JSON is invalid") from error
        authority = _strict_route_authority(authority)
        if canonical_delegation_route_authority_json_bytes(authority) != raw:
            raise DelegationRouteAuthorityParseError("route authority JSON is not canonical")
        return authority
    try:
        value = yaml.load(raw.decode("utf-8"), Loader=_UniqueLoader)
    except (UnicodeDecodeError, TypeError, yaml.YAMLError):
        raise DelegationRouteAuthorityParseError("route authority is not canonical YAML") from None
    if type(value) is not dict:
        raise DelegationRouteAuthorityParseError("route authority YAML is not an object")
    try:
        authority = DelegationRouteAuthorityV1.model_validate_json(canonical_json(value))
    except ValidationError as error:
        raise DelegationRouteAuthorityParseError("route authority YAML is invalid") from error
    authority = _strict_route_authority(authority)
    if canonical_delegation_route_authority_yaml_bytes(authority) != raw:
        raise DelegationRouteAuthorityParseError("route authority YAML is not canonical")
    return authority


def delegation_route_authority_message(authority: DelegationRouteAuthorityV1) -> bytes:
    """Return the domain-separated canonical route-authority signature payload."""

    checked = _strict_route_authority(authority)
    return _ROUTE_AUTHORITY_SIGNATURE_DOMAIN + canonical_json(
        checked.model_dump(mode="python", exclude={"signature_base64"})
    )


def delegation_route_authority_sha256(authority: DelegationRouteAuthorityV1) -> str:
    """Hash the exact signed route-target material without its detached signature."""

    checked = _strict_route_authority(authority)
    return sha256(delegation_route_authority_message(checked)).hexdigest()


def verify_delegation_route_authority(
    raw: bytes,
    *,
    trust_anchor: DelegationRouteAuthorityTrustAnchorV1,
) -> DelegationRouteAuthorityV1:
    """Verify a route target under its independent trust anchor and domain."""

    authority = parse_delegation_route_authority(raw)
    anchor = _strict_route_anchor(trust_anchor)
    if (
        authority.signer_key_id != anchor.signer_key_id
        or authority.signer_key_fingerprint_sha256 != anchor.signer_key_fingerprint_sha256
    ):
        raise DelegationRouteAuthoritySignatureError("route authority signer is invalid")
    try:
        signature = _canonical_base64(authority.signature_base64, expected_bytes=64)
        public_key = _trusted_route_public_key(anchor)
        Ed25519PublicKey.from_public_bytes(public_key).verify(
            signature, delegation_route_authority_message(authority)
        )
    except (InvalidSignature, ValueError, TypeError, DelegationExecutionError):
        raise DelegationRouteAuthoritySignatureError(
            "route authority signature is invalid"
        ) from None
    return authority


def delegation_execution_overlay_message(overlay: DelegationExecutionOverlayV1) -> bytes:
    """Return the domain-separated canonical message covered by its signature."""

    checked = _strict_activation(overlay)
    return _SIGNATURE_DOMAIN + canonical_json(
        checked.model_dump(mode="json", exclude={"signature_base64"})
    )


def canonical_disabled_delegation_overlay_sha256() -> str:
    """Commit the packaged disabled policy as typed canonical model material."""

    overlay = load_canonical_delegation_overlay()
    if type(overlay) is not DelegationOverlay or overlay.execute_enabled is not False:
        raise DelegationExecutionError("packaged delegation overlay is not disabled")
    return sha256(canonical_json(overlay.model_dump(mode="python"))).hexdigest()


def _canonical_base64(value: str, *, expected_bytes: int) -> bytes:
    if type(value) is not str:
        raise DelegationExecutionSignatureError("activation key encoding is invalid")
    try:
        decoded = base64.b64decode(value.encode("ascii"), validate=True)
    except (UnicodeEncodeError, binascii.Error):
        raise DelegationExecutionSignatureError("activation key encoding is invalid") from None
    if len(decoded) != expected_bytes or base64.b64encode(decoded).decode("ascii") != value:
        raise DelegationExecutionSignatureError("activation key encoding is invalid")
    return decoded


def _trusted_public_key(anchor: DelegationExecutionTrustAnchorV1) -> bytes:
    key = _canonical_base64(anchor.signer_public_key_base64, expected_bytes=32)
    if not hmac.compare_digest(sha256(key).hexdigest(), anchor.signer_key_fingerprint_sha256):
        raise DelegationExecutionSignatureError("activation trust-anchor fingerprint is invalid")
    return key


def _trusted_route_public_key(
    anchor: DelegationRouteAuthorityTrustAnchorV1,
) -> bytes:
    try:
        key = _canonical_base64(anchor.signer_public_key_base64, expected_bytes=32)
    except DelegationExecutionError:
        raise DelegationRouteAuthoritySignatureError(
            "route-authority trust-anchor is invalid"
        ) from None
    if not hmac.compare_digest(sha256(key).hexdigest(), anchor.signer_key_fingerprint_sha256):
        raise DelegationRouteAuthoritySignatureError(
            "route-authority trust-anchor fingerprint is invalid"
        )
    return key


def _require_utc(value: object) -> datetime:
    if type(value) is not datetime or value.tzinfo is not UTC:
        raise DelegationExecutionError("activation timestamp must be exact UTC")
    return value


def _validate_claim(
    claim: DelegatedGrantClaim,
) -> tuple[DelegatedRequest, VerifiedGrantFacts, DelegationOverlay]:
    if type(claim) is not DelegatedGrantClaim:
        raise DelegationExecutionError("delegation claim has an invalid type")
    request = _strict_model(claim.request, DelegatedRequest, _REQUEST_FIELDS)
    grant = _strict_model(claim.grant, VerifiedGrantFacts, _GRANT_FIELDS)
    policy = _strict_model(claim.policy, DelegationOverlay, _POLICY_FIELDS)
    packaged_policy = load_canonical_delegation_overlay()
    if (
        request.run_id != grant.correlation_id
        or request.request_sha256 != grant.request_sha256
        or request.artifact_sha256 != grant.artifact_sha256
        or request.rendered_contract_sha256 != grant.rendered_contract_sha256
        or request.tenant_id != grant.tenant_id
        or request.backend_id != grant.backend_id
        or request.model_id != grant.model_id
        or request.expected_output_topic != grant.expected_output_topic
        or request.expected_output_event_class != grant.expected_output_event_class
        or request.expected_output_event_index != grant.expected_output_event_index
        or policy != packaged_policy
        or policy.execute_enabled is not False
        or policy.route_ref != request.route_ref
        or policy.model_ref != request.model_id
    ):
        raise DelegationExecutionError("delegation claim is not coherent")
    _require_utc(grant.not_before)
    _require_utc(grant.expires_at)
    return request, grant, policy


type TrustedClock = Callable[[], datetime]


def verify_delegation_execution_overlay(
    raw: bytes,
    *,
    claim: DelegatedGrantClaim,
    trust_anchor: DelegationExecutionTrustAnchorV1,
    route_authority: bytes,
    route_authority_trust_anchor: DelegationRouteAuthorityTrustAnchorV1,
    trusted_clock: TrustedClock,
) -> DelegationExecutionOverlayV1:
    """Verify one signed activation against an exact disabled-policy claim."""

    activation = parse_delegation_execution_overlay(raw)
    anchor = _strict_anchor(trust_anchor)
    request, grant, _policy = _validate_claim(claim)
    activation_public_key = _trusted_public_key(anchor)
    route_anchor = _strict_route_anchor(route_authority_trust_anchor)
    route_public_key = _trusted_route_public_key(route_anchor)
    if hmac.compare_digest(activation_public_key, route_public_key) or hmac.compare_digest(
        anchor.signer_key_fingerprint_sha256,
        route_anchor.signer_key_fingerprint_sha256,
    ):
        raise DelegationExecutionSignatureError(
            "activation and route authority trust anchors must be distinct"
        )
    authority = verify_delegation_route_authority(
        route_authority,
        trust_anchor=route_anchor,
    )
    _require_utc(activation.issued_at)
    _require_utc(activation.expires_at)
    try:
        now = _require_utc(trusted_clock())
    except DelegationExecutionError:
        raise
    except Exception as error:
        raise DelegationExecutionError("trusted activation clock failed") from error
    try:
        disabled_overlay_sha256 = canonical_disabled_delegation_overlay_sha256()
    except Exception as error:
        raise DelegationExecutionError("packaged delegation overlay is unavailable") from error
    if (
        activation.authorization_digest != grant.authorization_digest
        or activation.request_envelope_sha256 != request.request_sha256
        or activation.backend_id != request.backend_id
        or activation.backend_id != grant.backend_id
        or activation.model_id != request.model_id
        or activation.model_id != grant.model_id
        or activation.route_ref != request.route_ref
        or activation.route_authority_sha256 != delegation_route_authority_sha256(authority)
        or authority.authorization_digest != grant.authorization_digest
        or authority.request_envelope_sha256 != request.request_sha256
        or authority.activation_id != grant.activation_id
        or authority.activation_sha256 != activation.activation_sha256
        or authority.route_ref != activation.route_ref
        or authority.backend_id != activation.backend_id
        or authority.model_id != activation.model_id
        or authority.endpoint_ref != activation.endpoint_ref
        or authority.credential_ref != activation.credential_ref
        or activation.disabled_overlay_sha256 != disabled_overlay_sha256
        or activation.activation_id != grant.activation_id
        or activation.issued_at < grant.not_before
        or activation.expires_at > grant.expires_at
        or activation.issued_at > now
        or activation.expires_at <= now
        or activation.expires_at <= activation.issued_at
        or activation.expires_at - activation.issued_at > _MAX_ACTIVATION_LIFETIME
        or activation.signer_key_id != anchor.signer_key_id
        or activation.signer_key_fingerprint_sha256 != anchor.signer_key_fingerprint_sha256
    ):
        raise DelegationExecutionError("activation does not match its authority")
    try:
        signature = _canonical_base64(activation.signature_base64, expected_bytes=64)
        Ed25519PublicKey.from_public_bytes(activation_public_key).verify(
            signature, delegation_execution_overlay_message(activation)
        )
    except (InvalidSignature, ValueError, TypeError, DelegationExecutionError):
        raise DelegationExecutionSignatureError("activation signature is invalid") from None
    return activation


__all__ = [
    "DelegationExecutionError",
    "DelegationExecutionOverlayV1",
    "DelegationExecutionParseError",
    "DelegationExecutionSignatureError",
    "DelegationExecutionTrustAnchorV1",
    "DelegationRouteAuthorityParseError",
    "DelegationRouteAuthoritySignatureError",
    "DelegationRouteAuthorityTrustAnchorV1",
    "DelegationRouteAuthorityV1",
    "canonical_delegation_execution_overlay_json_bytes",
    "canonical_delegation_execution_overlay_yaml_bytes",
    "canonical_delegation_route_authority_json_bytes",
    "canonical_delegation_route_authority_yaml_bytes",
    "canonical_disabled_delegation_overlay_sha256",
    "delegation_execution_activation_sha256",
    "delegation_execution_overlay_message",
    "delegation_route_authority_message",
    "delegation_route_authority_sha256",
    "parse_delegation_execution_overlay",
    "parse_delegation_route_authority",
    "verify_delegation_execution_overlay",
    "verify_delegation_route_authority",
]
