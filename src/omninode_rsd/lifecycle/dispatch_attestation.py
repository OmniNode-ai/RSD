"""Pure, bounded verification for delegated OpenAI-compatible dispatch data.

This module defines only canonical request and authenticated-result material.
It does not resolve a target, open a connection, load a key, or perform a
dispatch.  Runtime composition must supply the separately governed request
bytes, trust anchor, clock, and replay authority.
"""

from __future__ import annotations

import base64
import binascii
import json
from collections.abc import Callable
from datetime import UTC, datetime
from enum import StrEnum
from hashlib import sha256
from typing import Final, Literal, Protocol
from uuid import UUID

from cryptography.exceptions import InvalidSignature
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PublicKey
from pydantic import BaseModel, ConfigDict, Field, ValidationError

from omninode_rsd.delegation import (
    DelegatedGrantClaim,
    DelegatedRequest,
    DelegationOverlay,
    VerifiedGrantFacts,
    delegation_claim_binding_sha256,
)
from omninode_rsd.lifecycle.hashing import canonical_json
from omninode_rsd.lifecycle.models import strict_model_values

_SHA256 = r"^[0-9a-f]{64}$"
_IDENTIFIER = r"^[a-z][a-z0-9-]{1,63}$"
_MODEL_IDENTIFIER = r"^[a-z][a-z0-9._/-]{2,127}$"
_ROUTE_REF = r"^logical://[a-z0-9./-]+$"
_OUTCOME_DOMAIN: Final[bytes] = b"omninode-rsd.dispatch-outcome-attestation.ed25519.v1\x00"
_RESPONSE_HASH_DOMAIN: Final[bytes] = b"omninode-rsd.dispatch-response-preimage.sha256.v1\x00"
_OUTPUT_HASH_DOMAIN: Final[bytes] = b"omninode-rsd.dispatch-output-payload.sha256.v1\x00"
_MAX_REQUEST_ENVELOPE_BYTES: Final[int] = 131_072
_MAX_OUTCOME_ATTESTATION_BYTES: Final[int] = 32_768
_MAX_RESPONSE_PREIMAGE_BYTES: Final[int] = 8_192
_MAX_OUTPUT_PAYLOAD_BYTES: Final[int] = 65_536
_MAX_MESSAGE_BYTES: Final[int] = 16_384
_MAX_MESSAGES: Final[int] = 32


class DispatchAttestationError(ValueError):
    """Base error for invalid or untrustworthy dispatch contract material."""


class DispatchRequestEnvelopeError(DispatchAttestationError):
    """Raised when a bounded dispatch request envelope is not authoritative."""


class DispatchOutcomeSignatureError(DispatchAttestationError):
    """Raised when an outcome attestation cannot be authenticated."""


class DispatchOutcomeReplayError(DispatchAttestationError):
    """Raised when a verified outcome receipt was already consumed."""


class DispatchOutcomeReplayAmbiguousError(DispatchAttestationError):
    """Raised when replay authority cannot give a definitive single-use result."""


class _DispatchModel(BaseModel):
    """Strict immutable values at the public dispatch contract boundary."""

    model_config = ConfigDict(extra="forbid", frozen=True, strict=True)


class OpenAIChatMessageV1(_DispatchModel):
    """One bounded message in the fixed chat-completions request shape."""

    role: Literal["system", "user", "assistant"]
    content: str = Field(min_length=0, max_length=_MAX_MESSAGE_BYTES)


class OpenAIChatCompletionRequestV1(_DispatchModel):
    """Topology-free, bounded request material for one chat completion."""

    schema_version: Literal["rsd.openai-chat-completion-request.v1"]
    model_id: str = Field(pattern=_MODEL_IDENTIFIER)
    messages: tuple[OpenAIChatMessageV1, ...] = Field(min_length=1, max_length=_MAX_MESSAGES)
    max_output_tokens: int = Field(ge=1, le=8_192)
    stream: Literal[False]


class DispatchRequestEnvelopeV1(_DispatchModel):
    """Canonical preimage whose bytes must equal the signed request pin."""

    schema_version: Literal["rsd.dispatch-request-envelope.v1"]
    authorization_digest: str = Field(pattern=_SHA256)
    backend_id: str = Field(pattern=_IDENTIFIER)
    model_id: str = Field(pattern=_MODEL_IDENTIFIER)
    route_ref: str = Field(pattern=_ROUTE_REF)
    request: OpenAIChatCompletionRequestV1


class DispatchOutcomeTrustAnchorV1(_DispatchModel):
    """Explicit public verification facts for one outcome-attesting authority."""

    schema_version: Literal["rsd.dispatch-outcome-trust-anchor.v1"]
    trust_domain: Literal["omninode-rsd.dispatch-outcome-attestation.v1"]
    signer_key_id: str = Field(pattern=_IDENTIFIER)
    signer_public_key_base64: str = Field(min_length=44, max_length=44)
    signer_key_fingerprint_sha256: str = Field(pattern=_SHA256)


class DispatchResponsePreimageV1(_DispatchModel):
    """Canonical, topology-free response metadata for one terminal outcome."""

    schema_version: Literal["rsd.dispatch-response-preimage.v1"]
    outcome_status: Literal["completed", "failed"]
    output_payload_sha256: str = Field(pattern=_SHA256)


class DispatchCompletedOutputPayloadV1(_DispatchModel):
    """The complete bounded text payload for a definitive completed result."""

    schema_version: Literal["rsd.dispatch-completed-output-payload.v1"]
    content: str = Field(min_length=0, max_length=65_536)


class DispatchFailedOutputPayloadV1(_DispatchModel):
    """A finite, redacted classification for a definitive failed result."""

    schema_version: Literal["rsd.dispatch-failed-output-payload.v1"]
    failure_code: Literal[
        "backend_rejected",
        "invalid_response",
        "model_unavailable",
        "service_failed",
    ]


type DispatchOutputPayloadV1 = DispatchCompletedOutputPayloadV1 | DispatchFailedOutputPayloadV1


class DispatchOutcomeAttestationV1(_DispatchModel):
    """Detached-signature evidence for one definitive dispatch outcome."""

    schema_version: Literal["rsd.dispatch-outcome-attestation.v1"]
    attestation_id: UUID
    authorization_digest: str = Field(pattern=_SHA256)
    claim_binding_sha256: str = Field(pattern=_SHA256)
    backend_id: str = Field(pattern=_IDENTIFIER)
    model_id: str = Field(pattern=_MODEL_IDENTIFIER)
    route_ref: str = Field(pattern=_ROUTE_REF)
    request_sha256: str = Field(pattern=_SHA256)
    response_sha256: str = Field(pattern=_SHA256)
    output_payload_sha256: str = Field(pattern=_SHA256)
    outcome_status: Literal["completed", "failed"]
    issued_at: datetime
    signer_key_id: str = Field(pattern=_IDENTIFIER)
    trust_anchor_key_id: str = Field(pattern=_IDENTIFIER)
    trust_anchor_key_fingerprint_sha256: str = Field(pattern=_SHA256)
    signature_base64: str = Field(min_length=88, max_length=88)


class DispatchOutcomeReplayClaimV1(_DispatchModel):
    """The complete identity a durable authority needs to consume one receipt."""

    schema_version: Literal["rsd.dispatch-outcome-replay-claim.v1"]
    attestation_id: UUID
    attestation_sha256: str = Field(pattern=_SHA256)
    authorization_digest: str = Field(pattern=_SHA256)


class DispatchOutcomeReplayDisposition(StrEnum):
    """Definitive results from an external receipt single-use authority."""

    CLAIMED = "claimed"
    REPLAYED = "replayed"
    CONFLICT = "conflict"


class DispatchOutcomeReplayAuthority(Protocol):
    """Consumes a verified attestation identity exactly once."""

    def claim(self, claim: DispatchOutcomeReplayClaimV1) -> DispatchOutcomeReplayDisposition: ...


type TrustedClock = Callable[[], datetime]

_MESSAGE_FIELDS = frozenset(OpenAIChatMessageV1.model_fields)
_REQUEST_FIELDS = frozenset(OpenAIChatCompletionRequestV1.model_fields)
_ENVELOPE_FIELDS = frozenset(DispatchRequestEnvelopeV1.model_fields)
_ANCHOR_FIELDS = frozenset(DispatchOutcomeTrustAnchorV1.model_fields)
_RESPONSE_PREIMAGE_FIELDS = frozenset(DispatchResponsePreimageV1.model_fields)
_COMPLETED_OUTPUT_FIELDS = frozenset(DispatchCompletedOutputPayloadV1.model_fields)
_FAILED_OUTPUT_FIELDS = frozenset(DispatchFailedOutputPayloadV1.model_fields)
_ATTESTATION_FIELDS = frozenset(DispatchOutcomeAttestationV1.model_fields)
_CLAIM_FIELDS = frozenset(DispatchOutcomeReplayClaimV1.model_fields)
_DELEGATED_REQUEST_FIELDS = frozenset(DelegatedRequest.model_fields)
_GRANT_FIELDS = frozenset(VerifiedGrantFacts.model_fields)
_POLICY_FIELDS = frozenset(DelegationOverlay.model_fields)
_DELEGATED_CLAIM_FIELDS = frozenset(DelegatedGrantClaim.model_fields)


def _strict_model_values[ModelT: BaseModel](
    value: object, expected_type: type[ModelT], field_names: frozenset[str]
) -> dict[str, object]:
    if type(value) is not expected_type:
        raise DispatchAttestationError("dispatch contract model has an invalid type")
    values = strict_model_values(value, expected_type=expected_type, field_names=field_names)
    if values is None:
        raise DispatchAttestationError("dispatch contract model has an invalid shape")
    return values


def _strict_model[ModelT: BaseModel](
    value: object, expected_type: type[ModelT], field_names: frozenset[str]
) -> ModelT:
    values = _strict_model_values(value, expected_type, field_names)
    try:
        return expected_type.model_validate(values)
    except ValidationError as error:
        raise DispatchAttestationError("dispatch contract model is invalid") from error


def _strict_message(value: object) -> OpenAIChatMessageV1:
    values = _strict_model_values(value, OpenAIChatMessageV1, _MESSAGE_FIELDS)
    if type(values["role"]) is not str or type(values["content"]) is not str:
        raise DispatchAttestationError("dispatch message uses a non-exact scalar")
    message = _strict_model(value, OpenAIChatMessageV1, _MESSAGE_FIELDS)
    return message


def _strict_request(value: object) -> OpenAIChatCompletionRequestV1:
    values = _strict_model_values(value, OpenAIChatCompletionRequestV1, _REQUEST_FIELDS)
    messages = values["messages"]
    if (
        type(values["schema_version"]) is not str
        or type(values["model_id"]) is not str
        or type(messages) is not tuple
        or type(values["max_output_tokens"]) is not int
        or type(values["stream"]) is not bool
    ):
        raise DispatchAttestationError("dispatch request uses a non-exact scalar")
    for message in messages:
        _strict_message(message)
    return _strict_model(value, OpenAIChatCompletionRequestV1, _REQUEST_FIELDS)


def _strict_envelope(value: object) -> DispatchRequestEnvelopeV1:
    values = _strict_model_values(value, DispatchRequestEnvelopeV1, _ENVELOPE_FIELDS)
    scalar_values = (
        values["schema_version"],
        values["authorization_digest"],
        values["backend_id"],
        values["model_id"],
        values["route_ref"],
    )
    if any(type(item) is not str for item in scalar_values):
        raise DispatchRequestEnvelopeError("dispatch request envelope uses a non-exact scalar")
    _strict_request(values["request"])
    return _strict_model(value, DispatchRequestEnvelopeV1, _ENVELOPE_FIELDS)


def _strict_anchor(value: object) -> DispatchOutcomeTrustAnchorV1:
    values = _strict_model_values(value, DispatchOutcomeTrustAnchorV1, _ANCHOR_FIELDS)
    if any(type(item) is not str for item in values.values()):
        raise DispatchOutcomeSignatureError("dispatch outcome trust anchor uses a non-exact scalar")
    return _strict_model(value, DispatchOutcomeTrustAnchorV1, _ANCHOR_FIELDS)


def _strict_response_preimage(value: object) -> DispatchResponsePreimageV1:
    values = _strict_model_values(value, DispatchResponsePreimageV1, _RESPONSE_PREIMAGE_FIELDS)
    if any(type(item) is not str for item in values.values()):
        raise DispatchOutcomeSignatureError("dispatch response preimage uses a non-exact scalar")
    return _strict_model(value, DispatchResponsePreimageV1, _RESPONSE_PREIMAGE_FIELDS)


def _strict_completed_output(value: object) -> DispatchCompletedOutputPayloadV1:
    values = _strict_model_values(value, DispatchCompletedOutputPayloadV1, _COMPLETED_OUTPUT_FIELDS)
    if any(type(item) is not str for item in values.values()):
        raise DispatchOutcomeSignatureError("completed output payload uses a non-exact scalar")
    return _strict_model(value, DispatchCompletedOutputPayloadV1, _COMPLETED_OUTPUT_FIELDS)


def _strict_failed_output(value: object) -> DispatchFailedOutputPayloadV1:
    values = _strict_model_values(value, DispatchFailedOutputPayloadV1, _FAILED_OUTPUT_FIELDS)
    if any(type(item) is not str for item in values.values()):
        raise DispatchOutcomeSignatureError("failed output payload uses a non-exact scalar")
    return _strict_model(value, DispatchFailedOutputPayloadV1, _FAILED_OUTPUT_FIELDS)


def _strict_attestation(value: object) -> DispatchOutcomeAttestationV1:
    values = _strict_model_values(value, DispatchOutcomeAttestationV1, _ATTESTATION_FIELDS)
    for value_item in values.values():
        if type(value_item) not in {str, UUID, datetime}:
            raise DispatchOutcomeSignatureError(
                "dispatch outcome attestation uses a non-exact scalar"
            )
    _require_utc(values["issued_at"], error_type=DispatchOutcomeSignatureError)
    return _strict_model(value, DispatchOutcomeAttestationV1, _ATTESTATION_FIELDS)


def _strict_replay_claim(value: object) -> DispatchOutcomeReplayClaimV1:
    values = _strict_model_values(value, DispatchOutcomeReplayClaimV1, _CLAIM_FIELDS)
    if any(type(item) not in {str, UUID} for item in values.values()):
        raise DispatchAttestationError("dispatch replay claim uses a non-exact scalar")
    return _strict_model(value, DispatchOutcomeReplayClaimV1, _CLAIM_FIELDS)


def _strict_claim(value: object) -> tuple[DelegatedRequest, VerifiedGrantFacts, DelegationOverlay]:
    claim_values = _strict_model_values(value, DelegatedGrantClaim, _DELEGATED_CLAIM_FIELDS)
    request_values = _strict_model_values(
        claim_values["request"], DelegatedRequest, _DELEGATED_REQUEST_FIELDS
    )
    grant_values = _strict_model_values(claim_values["grant"], VerifiedGrantFacts, _GRANT_FIELDS)
    policy_values = _strict_model_values(claim_values["policy"], DelegationOverlay, _POLICY_FIELDS)
    if any(type(item) not in {str, UUID, int} for item in request_values.values()):
        raise DispatchAttestationError("delegated request uses a non-exact scalar")
    if any(type(item) not in {str, UUID, int, bool, datetime} for item in grant_values.values()):
        raise DispatchAttestationError("verified grant uses a non-exact scalar")
    if any(type(item) not in {str, bool} for item in policy_values.values()):
        raise DispatchAttestationError("delegation policy uses a non-exact scalar")
    for moment in (
        grant_values["issued_at"],
        grant_values["not_before"],
        grant_values["expires_at"],
    ):
        _require_utc(moment, error_type=DispatchAttestationError)
    request = _strict_model(claim_values["request"], DelegatedRequest, _DELEGATED_REQUEST_FIELDS)
    grant = _strict_model(claim_values["grant"], VerifiedGrantFacts, _GRANT_FIELDS)
    policy = _strict_model(claim_values["policy"], DelegationOverlay, _POLICY_FIELDS)
    return request, grant, policy


def _require_coherent_claim(
    request: DelegatedRequest,
    grant: VerifiedGrantFacts,
    policy: DelegationOverlay,
    *,
    error_type: type[DispatchAttestationError],
) -> None:
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
        or policy.execute_enabled is not False
        or policy.route_ref != request.route_ref
        or policy.model_ref != request.model_id
    ):
        raise error_type("delegated claim is not coherent with its authority")


def _require_utc(value: object, *, error_type: type[DispatchAttestationError]) -> datetime:
    if (
        type(value) is not datetime
        or value.tzinfo is None
        or value.utcoffset() != UTC.utcoffset(value)
    ):
        raise error_type("dispatch timestamp must be an exact UTC datetime")
    return value


def _reject_duplicate_keys(pairs: list[tuple[str, object]]) -> dict[str, object]:
    result: dict[str, object] = {}
    for key, value in pairs:
        if key in result:
            raise DispatchAttestationError("dispatch JSON contains duplicate keys")
        result[key] = value
    return result


def _parse_canonical_json(
    raw: bytes, *, maximum: int, error_type: type[DispatchAttestationError]
) -> dict[str, object]:
    if type(raw) is not bytes or not raw or len(raw) > maximum:
        raise error_type("dispatch contract bytes exceed the allowed bound")
    try:
        decoded = raw.decode("ascii")
        value = json.loads(decoded, object_pairs_hook=_reject_duplicate_keys)
    except (UnicodeDecodeError, json.JSONDecodeError, DispatchAttestationError):
        raise error_type("dispatch contract bytes are not canonical JSON") from None
    if type(value) is not dict:
        raise error_type("dispatch contract bytes are not a JSON object")
    return value


def _canonical_bytes(model: BaseModel) -> bytes:
    return canonical_json(model.model_dump(mode="python"))


def _bounded_canonical_bytes(
    model: BaseModel,
    *,
    maximum: int,
    error_type: type[DispatchAttestationError],
    label: str,
) -> bytes:
    raw = _canonical_bytes(model)
    if len(raw) > maximum:
        raise error_type(f"{label} exceeds the allowed bound")
    return raw


def _domain_hash(domain: bytes, raw: bytes) -> str:
    return sha256(domain + raw).hexdigest()


def canonical_dispatch_request_envelope_bytes(envelope: DispatchRequestEnvelopeV1) -> bytes:
    """Return the only accepted preimage for the signed request hash."""

    return _bounded_canonical_bytes(
        _strict_envelope(envelope),
        maximum=_MAX_REQUEST_ENVELOPE_BYTES,
        error_type=DispatchRequestEnvelopeError,
        label="dispatch request envelope",
    )


def parse_dispatch_request_envelope(raw: bytes) -> DispatchRequestEnvelopeV1:
    """Parse one bounded canonical request envelope without any transport action."""

    _parse_canonical_json(
        raw, maximum=_MAX_REQUEST_ENVELOPE_BYTES, error_type=DispatchRequestEnvelopeError
    )
    try:
        envelope = DispatchRequestEnvelopeV1.model_validate_json(raw)
    except ValidationError as error:
        raise DispatchRequestEnvelopeError("dispatch request envelope is invalid") from error
    envelope = _strict_envelope(envelope)
    if _canonical_bytes(envelope) != raw:
        raise DispatchRequestEnvelopeError("dispatch request envelope is not canonically encoded")
    return envelope


def validate_dispatch_request_envelope(
    raw: bytes, claim: DelegatedGrantClaim
) -> DispatchRequestEnvelopeV1:
    """Verify that exact canonical envelope bytes are authorized by ``claim``."""

    envelope = parse_dispatch_request_envelope(raw)
    request, grant, policy = _strict_claim(claim)
    _require_coherent_claim(
        request,
        grant,
        policy,
        error_type=DispatchRequestEnvelopeError,
    )
    if (
        sha256(raw).hexdigest() != request.request_sha256
        or envelope.authorization_digest != grant.authorization_digest
        or envelope.backend_id != request.backend_id
        or envelope.model_id != request.model_id
        or envelope.route_ref != request.route_ref
        or envelope.request.model_id != request.model_id
        or envelope.request.model_id != grant.model_id
        or envelope.request.model_id != policy.model_ref
    ):
        raise DispatchRequestEnvelopeError(
            "dispatch request envelope does not match its authorization"
        )
    return envelope


def canonical_dispatch_response_preimage_bytes(response: DispatchResponsePreimageV1) -> bytes:
    """Return the one bounded canonical metadata preimage for ``response_sha256``."""

    return _bounded_canonical_bytes(
        _strict_response_preimage(response),
        maximum=_MAX_RESPONSE_PREIMAGE_BYTES,
        error_type=DispatchOutcomeSignatureError,
        label="dispatch response preimage",
    )


def dispatch_response_sha256(response: DispatchResponsePreimageV1) -> str:
    """Domain-separate and hash the canonical response metadata preimage."""

    return _domain_hash(_RESPONSE_HASH_DOMAIN, canonical_dispatch_response_preimage_bytes(response))


def parse_dispatch_response_preimage(raw: bytes) -> DispatchResponsePreimageV1:
    """Parse one exact bounded response metadata preimage."""

    _parse_canonical_json(
        raw, maximum=_MAX_RESPONSE_PREIMAGE_BYTES, error_type=DispatchOutcomeSignatureError
    )
    try:
        response = DispatchResponsePreimageV1.model_validate_json(raw)
    except ValidationError as error:
        raise DispatchOutcomeSignatureError("dispatch response preimage is invalid") from error
    response = _strict_response_preimage(response)
    if canonical_dispatch_response_preimage_bytes(response) != raw:
        raise DispatchOutcomeSignatureError("dispatch response preimage is not canonically encoded")
    return response


def canonical_dispatch_output_payload_bytes(payload: DispatchOutputPayloadV1) -> bytes:
    """Return the one bounded canonical terminal payload preimage.

    A completed payload has only bounded output content. A failed payload has
    only a finite redacted failure code, so it cannot carry endpoint details,
    credentials, provider errors, or a free-form diagnostic.
    """

    if type(payload) is DispatchCompletedOutputPayloadV1:
        checked: DispatchOutputPayloadV1 = _strict_completed_output(payload)
    elif type(payload) is DispatchFailedOutputPayloadV1:
        checked = _strict_failed_output(payload)
    else:
        raise DispatchOutcomeSignatureError("dispatch output payload has an invalid type")
    return _bounded_canonical_bytes(
        checked,
        maximum=_MAX_OUTPUT_PAYLOAD_BYTES,
        error_type=DispatchOutcomeSignatureError,
        label="dispatch output payload",
    )


def dispatch_output_payload_sha256(payload: DispatchOutputPayloadV1) -> str:
    """Domain-separate and hash the canonical terminal payload preimage."""

    return _domain_hash(_OUTPUT_HASH_DOMAIN, canonical_dispatch_output_payload_bytes(payload))


def parse_dispatch_output_payload(raw: bytes) -> DispatchOutputPayloadV1:
    """Parse one exact bounded completed or redacted-failure payload."""

    value = _parse_canonical_json(
        raw, maximum=_MAX_OUTPUT_PAYLOAD_BYTES, error_type=DispatchOutcomeSignatureError
    )
    schema_version = value.get("schema_version")
    if schema_version == "rsd.dispatch-completed-output-payload.v1":
        try:
            completed_payload = DispatchCompletedOutputPayloadV1.model_validate_json(raw)
        except ValidationError as error:
            raise DispatchOutcomeSignatureError("dispatch output payload is invalid") from error
        completed = _strict_completed_output(completed_payload)
        if canonical_dispatch_output_payload_bytes(completed) != raw:
            raise DispatchOutcomeSignatureError(
                "dispatch output payload is not canonically encoded"
            )
        return completed
    elif schema_version == "rsd.dispatch-failed-output-payload.v1":
        try:
            failed_payload = DispatchFailedOutputPayloadV1.model_validate_json(raw)
        except ValidationError as error:
            raise DispatchOutcomeSignatureError("dispatch output payload is invalid") from error
        failed = _strict_failed_output(failed_payload)
        if canonical_dispatch_output_payload_bytes(failed) != raw:
            raise DispatchOutcomeSignatureError(
                "dispatch output payload is not canonically encoded"
            )
        return failed
    else:
        raise DispatchOutcomeSignatureError("dispatch output payload schema is invalid")


def _verify_outcome_preimages(
    attestation: DispatchOutcomeAttestationV1,
    *,
    response_preimage: bytes,
    output_payload: bytes,
) -> None:
    response = parse_dispatch_response_preimage(response_preimage)
    payload = parse_dispatch_output_payload(output_payload)
    completed = type(payload) is DispatchCompletedOutputPayloadV1
    if (
        response.outcome_status != attestation.outcome_status
        or (attestation.outcome_status == "completed") != completed
        or response.output_payload_sha256 != dispatch_output_payload_sha256(payload)
        or attestation.output_payload_sha256 != dispatch_output_payload_sha256(payload)
        or attestation.response_sha256 != dispatch_response_sha256(response)
    ):
        raise DispatchOutcomeSignatureError("dispatch outcome preimages do not match the receipt")


def _canonical_base64(value: str, *, expected_bytes: int) -> bytes:
    if type(value) is not str:
        raise DispatchOutcomeSignatureError("dispatch signature encoding is invalid")
    try:
        decoded = base64.b64decode(value.encode("ascii"), validate=True)
    except (UnicodeEncodeError, binascii.Error):
        raise DispatchOutcomeSignatureError("dispatch signature encoding is invalid") from None
    if len(decoded) != expected_bytes or base64.b64encode(decoded).decode("ascii") != value:
        raise DispatchOutcomeSignatureError("dispatch signature encoding is invalid")
    return decoded


def _anchor_public_key(anchor: DispatchOutcomeTrustAnchorV1) -> bytes:
    key = _canonical_base64(anchor.signer_public_key_base64, expected_bytes=32)
    if sha256(key).hexdigest() != anchor.signer_key_fingerprint_sha256:
        raise DispatchOutcomeSignatureError("dispatch outcome trust anchor fingerprint is invalid")
    return key


def dispatch_outcome_attestation_message(attestation: DispatchOutcomeAttestationV1) -> bytes:
    """Return canonical domain-separated bytes covered by an outcome signature."""

    checked = _strict_attestation(attestation)
    return _OUTCOME_DOMAIN + canonical_json(
        checked.model_dump(mode="python", exclude={"signature_base64"})
    )


def parse_dispatch_outcome_attestation(raw: bytes) -> DispatchOutcomeAttestationV1:
    """Parse one bounded canonical detached-signature outcome receipt."""

    _parse_canonical_json(
        raw, maximum=_MAX_OUTCOME_ATTESTATION_BYTES, error_type=DispatchOutcomeSignatureError
    )
    try:
        attestation = DispatchOutcomeAttestationV1.model_validate_json(raw)
    except ValidationError as error:
        raise DispatchOutcomeSignatureError("dispatch outcome attestation is invalid") from error
    attestation = _strict_attestation(attestation)
    if _canonical_bytes(attestation) != raw:
        raise DispatchOutcomeSignatureError(
            "dispatch outcome attestation is not canonically encoded"
        )
    return attestation


def verify_dispatch_outcome_attestation(
    raw: bytes,
    *,
    claim: DelegatedGrantClaim,
    trust_anchor: DispatchOutcomeTrustAnchorV1,
    trusted_clock: TrustedClock,
    replay_authority: DispatchOutcomeReplayAuthority,
    response_preimage: bytes,
    output_payload: bytes,
) -> DispatchOutcomeAttestationV1:
    """Authenticate one complete, reproducible, single-use definitive outcome."""

    attestation = parse_dispatch_outcome_attestation(raw)
    request, grant, policy = _strict_claim(claim)
    _require_coherent_claim(
        request,
        grant,
        policy,
        error_type=DispatchOutcomeSignatureError,
    )
    anchor = _strict_anchor(trust_anchor)
    now = _require_utc(trusted_clock(), error_type=DispatchOutcomeSignatureError)
    if (
        attestation.authorization_digest != grant.authorization_digest
        or attestation.claim_binding_sha256
        != delegation_claim_binding_sha256(request=request, grant=grant, policy=policy)
        or attestation.backend_id != request.backend_id
        or attestation.model_id != request.model_id
        or attestation.route_ref != request.route_ref
        or attestation.request_sha256 != request.request_sha256
        or attestation.signer_key_id != anchor.signer_key_id
        or attestation.trust_anchor_key_id != anchor.signer_key_id
        or attestation.trust_anchor_key_fingerprint_sha256 != anchor.signer_key_fingerprint_sha256
        or attestation.issued_at < grant.not_before
        or attestation.issued_at > grant.expires_at
        or attestation.issued_at > now
    ):
        raise DispatchOutcomeSignatureError(
            "dispatch outcome attestation does not match its authority"
        )
    try:
        Ed25519PublicKey.from_public_bytes(_anchor_public_key(anchor)).verify(
            _canonical_base64(attestation.signature_base64, expected_bytes=64),
            dispatch_outcome_attestation_message(attestation),
        )
    except (InvalidSignature, ValueError, TypeError):
        raise DispatchOutcomeSignatureError("dispatch outcome signature is invalid") from None
    _verify_outcome_preimages(
        attestation,
        response_preimage=response_preimage,
        output_payload=output_payload,
    )
    replay_claim = _strict_replay_claim(
        DispatchOutcomeReplayClaimV1(
            schema_version="rsd.dispatch-outcome-replay-claim.v1",
            attestation_id=attestation.attestation_id,
            attestation_sha256=sha256(raw).hexdigest(),
            authorization_digest=attestation.authorization_digest,
        )
    )
    try:
        disposition = replay_authority.claim(replay_claim)
    except Exception:
        raise DispatchOutcomeReplayAmbiguousError(
            "dispatch outcome replay authority was not definitive"
        ) from None
    if type(disposition) is not DispatchOutcomeReplayDisposition:
        raise DispatchOutcomeReplayAmbiguousError(
            "dispatch outcome replay authority was not definitive"
        )
    if disposition is DispatchOutcomeReplayDisposition.REPLAYED:
        raise DispatchOutcomeReplayError("dispatch outcome attestation was already consumed")
    if disposition is not DispatchOutcomeReplayDisposition.CLAIMED:
        raise DispatchOutcomeReplayAmbiguousError(
            "dispatch outcome replay authority was not definitive"
        )
    return attestation
