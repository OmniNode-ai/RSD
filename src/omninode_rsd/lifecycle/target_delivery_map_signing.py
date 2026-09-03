"""Pure V1 TargetDeliveryMap signature primitives.

This module deliberately preserves the historical V1 message byte sequence.
It owns no authorization, configuration, provider, or filesystem boundary.
"""

from __future__ import annotations

import base64
import binascii
import hashlib
import json
from typing import Literal, NoReturn, Self

from cryptography.exceptions import InvalidSignature
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PublicKey
from pydantic import BaseModel, ConfigDict, Field, ValidationError, model_validator

from omninode_rsd.lifecycle.infisical_disposable import TargetDeliveryMapV1, _strict_canonical_model

_IDENTIFIER = r"^[A-Za-z][A-Za-z0-9_.-]{0,127}$"
_SHA256 = r"^[0-9a-f]{64}$"
_DOMAIN = b"omninode-rsd.target-delivery-map.ed25519.v1\x00"


class TargetDeliveryMapSigningError(ValueError):
    """Fixed failure for a V1 map signature or its pinned public root."""


class _Model(BaseModel):
    model_config = ConfigDict(extra="forbid", frozen=True, strict=True, validate_default=True)


class TargetDeliveryMapSignerTrustAnchorV1(_Model):
    """The externally pinned, exact public signer root for a V1 map."""

    schema_version: Literal["rsd.target-delivery-map-signer-trust-anchor.v1"]
    key_id: str = Field(pattern=_IDENTIFIER)
    public_key_base64: str = Field(min_length=4, max_length=128)
    public_key_fingerprint_sha256: str = Field(pattern=_SHA256)
    algorithm: Literal["ed25519"]

    @model_validator(mode="after")
    def exact_public_key(self) -> Self:
        key = _base64(self.public_key_base64)
        if len(key) != 32 or hashlib.sha256(key).hexdigest() != self.public_key_fingerprint_sha256:
            raise ValueError("target delivery map signer anchor is invalid")
        return self


def _base64(value: str) -> bytes:
    if type(value) is not str:
        raise ValueError("base64 is invalid")
    try:
        result = base64.b64decode(value, validate=True)
    except (binascii.Error, ValueError):
        raise ValueError("base64 is invalid") from None
    if base64.b64encode(result).decode("ascii") != value:
        raise ValueError("base64 is invalid")
    return result


def _canonical(model: BaseModel, *, exclude: set[str] | None = None) -> bytes:
    try:
        return json.dumps(
            model.model_dump(mode="json", exclude=exclude or set(), warnings="error"),
            ensure_ascii=True,
            sort_keys=True,
            separators=(",", ":"),
            allow_nan=False,
        ).encode("utf-8")
    except (TypeError, ValueError):
        raise ValueError("model is invalid") from None


def _fail() -> NoReturn:
    raise TargetDeliveryMapSigningError("target delivery map signature validation failed")


def strict_canonical_target_delivery_map_signer_trust_anchor_v1(
    anchor: TargetDeliveryMapSignerTrustAnchorV1,
) -> TargetDeliveryMapSignerTrustAnchorV1:
    try:
        return _strict_canonical_model(anchor, TargetDeliveryMapSignerTrustAnchorV1)
    except (TypeError, ValidationError, ValueError):
        _fail()


def target_delivery_map_v1_canonical_message(delivery_map: TargetDeliveryMapV1) -> bytes:
    """Return the unchanged historical V1 Ed25519 message bytes."""

    if type(delivery_map) is not TargetDeliveryMapV1:
        _fail()
    try:
        canonical = _strict_canonical_model(delivery_map, TargetDeliveryMapV1)
        return _DOMAIN + _canonical(canonical, exclude={"signature_base64"})
    except (TypeError, ValidationError, ValueError):
        _fail()


def verify_target_delivery_map_v1_signature(
    *,
    delivery_map: TargetDeliveryMapV1,
    signer_trust_anchor: TargetDeliveryMapSignerTrustAnchorV1,
) -> TargetDeliveryMapV1:
    """Verify one complete, canonical V1 map under its external anchor."""

    try:
        canonical_map = _strict_canonical_model(delivery_map, TargetDeliveryMapV1)
        anchor = strict_canonical_target_delivery_map_signer_trust_anchor_v1(signer_trust_anchor)
        if canonical_map.signer_key_id != anchor.key_id:
            raise ValueError("signer mismatch")
        Ed25519PublicKey.from_public_bytes(_base64(anchor.public_key_base64)).verify(
            _base64(canonical_map.signature_base64),
            target_delivery_map_v1_canonical_message(canonical_map),
        )
        return canonical_map
    except (InvalidSignature, TargetDeliveryMapSigningError, TypeError, ValueError):
        _fail()
