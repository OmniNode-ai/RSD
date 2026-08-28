"""Public, value-safe provider-material bootstrap primitives.

This module deliberately has no ambient configuration, subprocess, network,
or service integration.  Callers supply typed, signed artifacts and a
create-only provider adapter.  The macOS adapter uses Security.framework
directly; it never invokes the ``security`` command-line tool.

The material boundary is intentionally narrower than a runtime secret
delivery system.  It can attest immutable Keychain items and expose only
value-free provenance.  It does not inject a value into a process, create a
backup, or contact an external service.
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
import re
import stat
import sys
from collections.abc import Callable, Iterator, Mapping, Sequence
from contextlib import contextmanager, suppress
from dataclasses import dataclass
from datetime import UTC, datetime, timedelta
from enum import StrEnum
from pathlib import Path
from typing import Any, Final, Literal, Protocol, cast

import yaml
from cryptography import x509
from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric.ed25519 import (
    Ed25519PrivateKey,
    Ed25519PublicKey,
)
from pydantic import (
    BaseModel,
    ConfigDict,
    Field,
    ValidationError,
    field_validator,
    model_validator,
)

from omninode_rsd.lifecycle.infisical_disposable import (
    DisposableTransportProfile,
    InitialProvisioningIntentV1,
    ProviderReferenceV1,
    _strict_canonical_model,
    _UniqueLoader,
    initial_provisioning_intent_sha256,
    strict_canonical_initial_provisioning_intent,
)

_SHA256: Final = r"^[0-9a-f]{64}$"
_IDENTIFIER: Final = r"^[A-Za-z][A-Za-z0-9_.-]{0,127}$"
_UUID: Final = (
    r"^[0-9a-f]{8}-[0-9a-f]{4}-[1-5][0-9a-f]{3}-[89ab][0-9a-f]{3}-"
    r"[0-9a-f]{12}$"
)
_MAX_ARTIFACT_BYTES: Final = 131_072
_MATERIAL_ATTESTATION_FRESHNESS: Final = timedelta(minutes=15)
_SIGNER_GENESIS_DOMAIN: Final = b"omninode-rsd.provider-crypto.signer-genesis.v1\x00"
_REPLAY_POLICY_DOMAIN: Final = b"omninode-rsd.provider-crypto.replay-policy.v1\x00"
_MATERIAL_POLICY_DOMAIN: Final = b"omninode-rsd.provider-crypto.material-policy.v1\x00"
_FINGERPRINT_ATTESTATION_DOMAIN: Final = (
    b"omninode-rsd.provider-crypto.fingerprint-attestation.v1\x00"
)
_MATERIAL_GENESIS_DOMAIN: Final = b"omninode-rsd.provider-crypto.material-genesis.v1\x00"
_INITIAL_INTENT_SIGNATURE_DOMAIN: Final = b"omninode-rsd.initial-provisioning-intent.ed25519.v1\x00"
_MATERIAL_POLICY_NAME: Final = "provider-material-policy.yaml"
_MATERIAL_GENESIS_NAME: Final = "provider-material-genesis.yaml"
_FINGERPRINT_ATTESTATION_NAME: Final = "provider-fingerprint-attestation.yaml"
_REPLAY_POLICY_NAME: Final = "replay-authority-policy.yaml"
_SIGNER_GENESIS_NAME: Final = "signer-genesis.yaml"
_TRANSPORT_FAILURE: Final = object()


class ProviderCryptoError(RuntimeError):
    """Value-redacted failure from the provider-material boundary."""

    def __init__(self, phase: str) -> None:
        self.phase = phase
        super().__init__(f"provider crypto failed at phase: {phase}")


class _Model(BaseModel):
    model_config = ConfigDict(extra="forbid", frozen=True, strict=True, validate_default=True)


class _TrustedSigner(Protocol):
    @property
    def key_id(self) -> str: ...

    @property
    def public_key_fingerprint_sha256(self) -> str: ...

    def key(self) -> Ed25519PublicKey: ...


class ProviderMaterialPurpose(StrEnum):
    """Purposes are pairwise distinct and cannot be substituted."""

    COMMITMENT_HMAC = "commitment_hmac"
    BACKUP_ENCRYPTION = "backup_encryption"
    INFISICAL_ENCRYPTION_KEY = "encryption_key"
    INFISICAL_AUTH_SECRET = "auth_secret"
    PRIMARY_VALKEY_PASSWORD = "primary_valkey_password"
    RESTORE_VALKEY_PASSWORD = "restore_valkey_password"
    TLS_TRUST_ANCHOR = "tls_trust_anchor"


class ProviderMaterialFormat(StrEnum):
    """Strict serializations allowed by the public bootstrap contract.

    ``infisical_hex_16_v1`` represents the normal self-hosted
    Infisical form: 16 random bytes encoded as 32 lower-case hexadecimal ASCII
    characters. ``infisical_auth_secret_base64_32_v1`` represents 32 random
    bytes in canonical standard Base64. FIPS deployments are intentionally not
    represented by this policy and therefore fail closed.

    The Valkey password spelling is a policy-owned portable encoding: 32 random
    bytes encoded as unpadded Base64URL ASCII. It is a conservative generated
    credential contract, not an assertion that Valkey imposes a fixed length.
    The TLS representation is one PEM-encoded X.509 CA certificate; SPKI pins
    and bundles require a separate, explicitly reviewed policy version.
    """

    HMAC_SHA256_RAW_32_V1 = "hmac_sha256_raw_32_v1"
    AES_256_GCM_RAW_32_V1 = "aes_256_gcm_raw_32_v1"
    INFISICAL_HEX_16_V1 = "infisical_hex_16_v1"
    INFISICAL_AUTH_SECRET_BASE64_32_V1 = "infisical_auth_secret_base64_32_v1"
    VALKEY_PASSWORD_BASE64URL_32_V1 = "valkey_password_base64url_32_v1"
    X509_CA_PEM_V1 = "x509_ca_pem_v1"


_PURPOSE_FORMATS: Final[Mapping[ProviderMaterialPurpose, ProviderMaterialFormat]] = {
    ProviderMaterialPurpose.COMMITMENT_HMAC: ProviderMaterialFormat.HMAC_SHA256_RAW_32_V1,
    ProviderMaterialPurpose.BACKUP_ENCRYPTION: ProviderMaterialFormat.AES_256_GCM_RAW_32_V1,
    ProviderMaterialPurpose.INFISICAL_ENCRYPTION_KEY: (ProviderMaterialFormat.INFISICAL_HEX_16_V1),
    ProviderMaterialPurpose.INFISICAL_AUTH_SECRET: (
        ProviderMaterialFormat.INFISICAL_AUTH_SECRET_BASE64_32_V1
    ),
    ProviderMaterialPurpose.PRIMARY_VALKEY_PASSWORD: (
        ProviderMaterialFormat.VALKEY_PASSWORD_BASE64URL_32_V1
    ),
    ProviderMaterialPurpose.RESTORE_VALKEY_PASSWORD: (
        ProviderMaterialFormat.VALKEY_PASSWORD_BASE64URL_32_V1
    ),
    ProviderMaterialPurpose.TLS_TRUST_ANCHOR: ProviderMaterialFormat.X509_CA_PEM_V1,
}
_FORMAT_LENGTHS: Final[Mapping[ProviderMaterialFormat, tuple[int, int]]] = {
    ProviderMaterialFormat.HMAC_SHA256_RAW_32_V1: (32, 32),
    ProviderMaterialFormat.AES_256_GCM_RAW_32_V1: (32, 32),
    ProviderMaterialFormat.INFISICAL_HEX_16_V1: (32, 32),
    ProviderMaterialFormat.INFISICAL_AUTH_SECRET_BASE64_32_V1: (44, 44),
    ProviderMaterialFormat.VALKEY_PASSWORD_BASE64URL_32_V1: (43, 43),
    ProviderMaterialFormat.X509_CA_PEM_V1: (1, _MAX_ARTIFACT_BYTES),
}


class KeychainItemReferenceV1(_Model):
    """Non-secret identity for one immutable generic-password item."""

    provider: Literal["macos_keychain"]
    service: str = Field(pattern=_IDENTIFIER)
    account: str = Field(pattern=_IDENTIFIER)
    version: int = Field(ge=1, le=1_000_000)
    reference_sha256: str = Field(pattern=_SHA256)

    @model_validator(mode="after")
    def binds_metadata(self) -> KeychainItemReferenceV1:
        expected = _sha256(
            _canonical_json(
                {
                    "account": self.account,
                    "provider": self.provider,
                    "service": self.service,
                    "version": self.version,
                }
            )
        )
        if not hmac.compare_digest(expected, self.reference_sha256) or not self.account.endswith(
            f".v{self.version}"
        ):
            raise ValueError("keychain reference does not bind metadata")
        return self


class SignerGenesisV1(_Model):
    """A signed trust-anchor artifact for one Keychain-held Ed25519 seed.

    The artifact is signed by an already trusted issuer.  Loading or
    provisioning the seed independently proves both its recorded digest and
    its derived public key, so a matching item cannot be replaced with an
    unrelated Keychain value.
    """

    schema_version: Literal["rsd.provider-crypto.signer-genesis.v1"]
    initial_intent_sha256: str = Field(pattern=_SHA256)
    issuer_key_id: str = Field(pattern=_IDENTIFIER)
    key_id: str = Field(pattern=_IDENTIFIER)
    public_key_base64: str = Field(min_length=4, max_length=128)
    public_key_fingerprint_sha256: str = Field(pattern=_SHA256)
    seed_fingerprint_sha256: str = Field(pattern=_SHA256)
    keychain_reference: KeychainItemReferenceV1
    created_at: str = Field(min_length=20, max_length=40)
    signature_base64: str = Field(min_length=4, max_length=256)

    @model_validator(mode="after")
    def binds_subject_key(self) -> SignerGenesisV1:
        try:
            created = _parse_timestamp(self.created_at)
            public_key = _canonical_base64(self.public_key_base64)
        except ValueError:
            raise ValueError("signer genesis fields are invalid") from None
        if (
            created is None
            or self.issuer_key_id == self.key_id
            or len(public_key) != 32
            or not hmac.compare_digest(_sha256(public_key), self.public_key_fingerprint_sha256)
            or len(_canonical_base64(self.signature_base64)) != 64
        ):
            raise ValueError("signer genesis fields are invalid")
        return self


class ReplayAuthorityPolicyArtifactV1(_Model):
    """Signed replay namespace preimage pinned to the initial intent."""

    schema_version: Literal["rsd.provider-crypto.replay-authority-policy.v1"]
    initial_intent_sha256: str = Field(pattern=_SHA256)
    service: str = Field(pattern=_IDENTIFIER, min_length=1, max_length=128)
    account_prefix: str = Field(pattern=_IDENTIFIER, min_length=1, max_length=48)
    replay_policy_sha256: str = Field(pattern=_SHA256)
    created_at: str = Field(min_length=20, max_length=40)
    signer_key_id: str = Field(pattern=_IDENTIFIER)
    signature_base64: str = Field(min_length=4, max_length=256)

    @model_validator(mode="after")
    def binds_policy(self) -> ReplayAuthorityPolicyArtifactV1:
        if (
            _parse_timestamp(self.created_at) is None
            or not hmac.compare_digest(
                self.replay_policy_sha256,
                replay_authority_policy_sha256(self.service, self.account_prefix),
            )
            or len(_canonical_base64(self.signature_base64)) != 64
        ):
            raise ValueError("replay authority policy fields are invalid")
        return self


class ProviderMaterialSpecV1(_Model):
    """One purpose-bound Keychain reference and exact material encoding."""

    purpose: ProviderMaterialPurpose
    reference: ProviderReferenceV1
    format: ProviderMaterialFormat
    value_min_bytes: int = Field(ge=1, le=_MAX_ARTIFACT_BYTES)
    value_max_bytes: int = Field(ge=1, le=_MAX_ARTIFACT_BYTES)

    @field_validator("purpose", mode="before")
    @classmethod
    def parse_purpose(cls, value: object) -> ProviderMaterialPurpose:
        if type(value) is ProviderMaterialPurpose:
            return value
        if type(value) is str:
            try:
                return ProviderMaterialPurpose(value)
            except ValueError:
                pass
        raise ValueError("provider material specification is invalid")

    @field_validator("format", mode="before")
    @classmethod
    def parse_format(cls, value: object) -> ProviderMaterialFormat:
        if type(value) is ProviderMaterialFormat:
            return value
        if type(value) is str:
            try:
                return ProviderMaterialFormat(value)
            except ValueError:
                pass
        raise ValueError("provider material specification is invalid")

    @model_validator(mode="after")
    def uses_exact_purpose_contract(self) -> ProviderMaterialSpecV1:
        if (
            type(self.purpose) is not ProviderMaterialPurpose
            or type(self.format) is not ProviderMaterialFormat
        ):
            raise ValueError("provider material specification is invalid")
        expected_format = _PURPOSE_FORMATS[self.purpose]
        expected_lengths = _FORMAT_LENGTHS[expected_format]
        if (
            self.format.value != expected_format.value
            or (self.value_min_bytes, self.value_max_bytes) != expected_lengths
            or (
                self.reference.provider == "macos_keychain"
                and not self.reference.account.endswith(f".v{self.reference.version}")
            )
        ):
            raise ValueError("provider material specification is invalid")
        return self


class ProviderMaterialPolicyV1(_Model):
    """Signed policy that binds all material purposes to the initial intent."""

    schema_version: Literal["rsd.provider-crypto.material-policy.v1"]
    initial_intent_sha256: str = Field(pattern=_SHA256)
    disposal_owner: str = Field(pattern=_IDENTIFIER)
    approver_identity: str = Field(pattern=_IDENTIFIER)
    policy_id: str = Field(pattern=_UUID)
    signer_keychain_reference: KeychainItemReferenceV1
    signer_seed_fingerprint_sha256: str = Field(pattern=_SHA256)
    created_at: str = Field(min_length=20, max_length=40)
    retention_expires_at: str = Field(min_length=20, max_length=40)
    materials: tuple[ProviderMaterialSpecV1, ...] = Field(min_length=6, max_length=7)
    signer_key_id: str = Field(pattern=_IDENTIFIER)
    signature_base64: str = Field(min_length=4, max_length=256)

    @field_validator("materials", mode="before")
    @classmethod
    def material_items(cls, value: object) -> tuple[object, ...]:
        if type(value) not in {list, tuple}:
            raise ValueError("provider material policy fields are invalid")
        return tuple(cast(list[object] | tuple[object, ...], value))

    @model_validator(mode="after")
    def complete_distinct_material_set(self) -> ProviderMaterialPolicyV1:
        try:
            created = _parse_timestamp(self.created_at)
            expires = _parse_timestamp(self.retention_expires_at)
        except ValueError:
            raise ValueError("provider material policy fields are invalid") from None
        purposes = tuple(item.purpose for item in self.materials)
        identities = tuple(item.reference.identity for item in self.materials)
        references = tuple(item.reference.reference_sha256 for item in self.materials)
        signer_identity = (
            self.signer_keychain_reference.provider,
            self.signer_keychain_reference.service,
            self.signer_keychain_reference.account,
        )
        if (
            created is None
            or expires is None
            or expires <= created
            or len(set(purposes)) != len(purposes)
            or len(set(identities)) != len(identities)
            or len(set(references)) != len(references)
            or signer_identity in identities
            or self.signer_keychain_reference.reference_sha256 in references
            or set(purposes)
            not in (
                set(ProviderMaterialPurpose),
                set(ProviderMaterialPurpose) - {ProviderMaterialPurpose.TLS_TRUST_ANCHOR},
            )
            or len(_canonical_base64(self.signature_base64)) != 64
        ):
            raise ValueError("provider material policy fields are invalid")
        return self

    def policy_sha256(self) -> str:
        return _sha256(_canonical_json(self.model_dump(mode="json", exclude={"signature_base64"})))

    def by_reference(self) -> dict[str, ProviderMaterialSpecV1]:
        return {item.reference.reference_sha256: item for item in self.materials}


class ProviderMaterialFingerprintV1(_Model):
    """Value-free fingerprint for one policy-bound material item."""

    purpose: ProviderMaterialPurpose
    reference_sha256: str = Field(pattern=_SHA256)
    fingerprint_sha256: str = Field(pattern=_SHA256)

    @field_validator("purpose", mode="before")
    @classmethod
    def parse_purpose(cls, value: object) -> ProviderMaterialPurpose:
        if type(value) is ProviderMaterialPurpose:
            return value
        if type(value) is str:
            try:
                return ProviderMaterialPurpose(value)
            except ValueError:
                pass
        raise ValueError("provider fingerprint attestation fields are invalid")


class ProviderFingerprintAttestationV1(_Model):
    """Signed, value-free observed fingerprints for one material policy."""

    schema_version: Literal["rsd.provider-crypto.fingerprint-attestation.v1"]
    initial_intent_sha256: str = Field(pattern=_SHA256)
    provider_material_policy_sha256: str = Field(pattern=_SHA256)
    attestation_id: str = Field(pattern=_UUID)
    observed_at: str = Field(min_length=20, max_length=40)
    materials: tuple[ProviderMaterialFingerprintV1, ...] = Field(min_length=6, max_length=7)
    signer_key_id: str = Field(pattern=_IDENTIFIER)
    signature_base64: str = Field(min_length=4, max_length=256)

    @field_validator("materials", mode="before")
    @classmethod
    def material_items(cls, value: object) -> tuple[object, ...]:
        if type(value) not in {list, tuple}:
            raise ValueError("provider fingerprint attestation fields are invalid")
        return tuple(cast(list[object] | tuple[object, ...], value))

    @model_validator(mode="after")
    def distinct_materials(self) -> ProviderFingerprintAttestationV1:
        try:
            observed = _parse_timestamp(self.observed_at)
        except ValueError:
            raise ValueError("provider fingerprint attestation fields are invalid") from None
        purposes = tuple(item.purpose for item in self.materials)
        references = tuple(item.reference_sha256 for item in self.materials)
        fingerprints = tuple(item.fingerprint_sha256 for item in self.materials)
        if (
            observed is None
            or len(set(purposes)) != len(purposes)
            or len(set(references)) != len(references)
            or len(set(fingerprints)) != len(fingerprints)
            or len(_canonical_base64(self.signature_base64)) != 64
        ):
            raise ValueError("provider fingerprint attestation fields are invalid")
        return self

    def fingerprint_by_reference(self) -> dict[str, str]:
        return {item.reference_sha256: item.fingerprint_sha256 for item in self.materials}


class ProviderMaterialGenesisV1(_Model):
    """Signed pending manifest persisted before the first Keychain write."""

    schema_version: Literal["rsd.provider-crypto.material-genesis.v1"]
    status: Literal["pending"]
    genesis_id: str = Field(pattern=_UUID)
    initial_intent_sha256: str = Field(pattern=_SHA256)
    provider_material_policy_sha256: str = Field(pattern=_SHA256)
    provider_fingerprint_attestation_sha256: str = Field(pattern=_SHA256)
    created_at: str = Field(min_length=20, max_length=40)
    signer_key_id: str = Field(pattern=_IDENTIFIER)
    signature_base64: str = Field(min_length=4, max_length=256)

    @model_validator(mode="after")
    def canonical_fields(self) -> ProviderMaterialGenesisV1:
        if (
            _parse_timestamp(self.created_at) is None
            or len(_canonical_base64(self.signature_base64)) != 64
        ):
            raise ValueError("provider material genesis fields are invalid")
        return self


class ProviderMaterialGenesisStatus(StrEnum):
    """Structural read-only status; it never proves authorization completeness."""

    ABSENT = "absent"
    PENDING = "pending"
    STRUCTURALLY_COMPLETE_UNVERIFIED = "structurally_complete_unverified"
    PARTIAL_OR_RECONCILIATION_REQUIRED = "partial_or_reconciliation_required"
    INVALID = "invalid"


@dataclass(frozen=True, slots=True)
class KeychainProviderProvenance:
    """Value-free provenance compatible with the authorization provider lease."""

    provider: str
    service: str
    account: str
    version: int
    reference_sha256: str
    fingerprint_sha256: str


class _KeychainTransport(Protocol):
    """Create-only generic-password transport.  Values never leave this API."""

    def add_if_absent(self, service: str, account: str, value: bytearray) -> bool: ...

    def read_if_present(self, service: str, account: str) -> bytearray | None: ...


class _ArtifactReader(Protocol):
    """Already-pinned descriptor-relative artifact reader used by authorization."""

    def read(self, name: str) -> bytes: ...


def _sha256(value: bytes | bytearray) -> str:
    return hashlib.sha256(value).hexdigest()


def _read_keychain_value(
    store: _KeychainTransport, service: str, account: str
) -> bytearray | object | None:
    """Read through the transport without retaining a provider exception."""

    try:
        return store.read_if_present(service, account)
    except Exception:
        return _TRANSPORT_FAILURE


def _create_keychain_value(
    store: _KeychainTransport, service: str, account: str, value: bytearray
) -> bool | object:
    """Create one value through the transport without retaining its error."""

    try:
        return store.add_if_absent(service, account, value)
    except Exception:
        return _TRANSPORT_FAILURE


def _canonical_json(value: object) -> bytes:
    try:
        return json.dumps(value, sort_keys=True, separators=(",", ":")).encode("utf-8")
    except (TypeError, ValueError):
        raise ProviderCryptoError("canonical_encoding") from None


def _canonical_base64(value: str) -> bytes:
    if type(value) is not str:
        raise ValueError("base64 is invalid")
    try:
        decoded = base64.b64decode(value, validate=True)
    except (binascii.Error, ValueError):
        raise ValueError("base64 is invalid") from None
    if base64.b64encode(decoded).decode("ascii") != value:
        raise ValueError("base64 is not canonical")
    return decoded


def _parse_timestamp(value: str) -> datetime | None:
    if type(value) is not str or not value.endswith("Z"):
        return None
    try:
        parsed = datetime.fromisoformat(value.removesuffix("Z") + "+00:00")
    except ValueError:
        return None
    if parsed.tzinfo is None or parsed.utcoffset() is None:
        return None
    return parsed.astimezone(UTC)


def _system_utc_clock() -> datetime:
    """Return the process-local UTC clock used at each mutation boundary."""

    return datetime.now(UTC)


def _canonical_initial_intent(intent: InitialProvisioningIntentV1) -> InitialProvisioningIntentV1:
    """Reject all construction/copy type drift before a bootstrap operation."""

    try:
        return strict_canonical_initial_provisioning_intent(intent)
    except ValueError:
        raise ProviderCryptoError("initial_intent") from None


def _reject_unsupported_tls_termination(
    intent: InitialProvisioningIntentV1,
) -> InitialProvisioningIntentV1:
    """Return canonical non-TLS intent, blocking every current TLS bootstrap write."""

    canonical = _canonical_initial_intent(intent)
    profile = canonical.plan.transport.profile
    if (
        type(profile) is not DisposableTransportProfile
        or profile.value == DisposableTransportProfile.TLS_VERIFIED.value
    ):
        raise ProviderCryptoError("tls_termination_amendment_required")
    return canonical


def _canonical_artifact(model: object, model_type: type[_Model], *, phase: str) -> _Model:
    """Revalidate a caller model before it can select an artifact or Keychain row."""

    try:
        return _strict_canonical_model(model, model_type)
    except ValueError:
        raise ProviderCryptoError(phase) from None


def _signature_message(domain: bytes, model: BaseModel) -> bytes:
    try:
        payload = model.model_dump(mode="json", exclude={"signature_base64"})
    except (TypeError, ValueError):
        raise ProviderCryptoError("artifact_signature") from None
    return domain + _canonical_json(payload)


def _initial_intent_message(intent: InitialProvisioningIntentV1) -> bytes:
    if type(intent) is not InitialProvisioningIntentV1:
        raise ProviderCryptoError("initial_intent_signature")
    return _INITIAL_INTENT_SIGNATURE_DOMAIN + _canonical_json(
        intent.model_dump(mode="json", exclude={"signature_base64"})
    )


def _verify_initial_intent_signature(
    intent: InitialProvisioningIntentV1, *, issuer: _TrustedSigner
) -> None:
    """Require the original intent signature before any bootstrap artifact use."""

    valid = False
    try:
        if (
            type(intent) is not InitialProvisioningIntentV1
            or type(issuer.key_id) is not str
            or intent.signer_key_id != issuer.key_id
        ):
            raise ValueError("initial intent signer is invalid")
        issuer.key().verify(
            _canonical_base64(intent.signature_base64), _initial_intent_message(intent)
        )
        valid = True
    except Exception:
        valid = False
    if not valid:
        raise ProviderCryptoError("initial_intent_signature")


def _verify_signed(
    model: BaseModel,
    *,
    domain: bytes,
    signer: _TrustedSigner,
    expected_signer_key_id: str | None = None,
) -> None:
    valid = False
    try:
        signer_key_id = getattr(model, "signer_key_id", None)
        if signer_key_id is None:
            signer_key_id = getattr(model, "issuer_key_id", None)
        signature_base64 = getattr(model, "signature_base64", None)
        if (
            type(signer.key_id) is not str
            or type(signer.public_key_fingerprint_sha256) is not str
            or type(signer_key_id) is not str
            or signer_key_id != signer.key_id
            or (expected_signer_key_id is not None and signer_key_id != expected_signer_key_id)
            or type(signature_base64) is not str
        ):
            raise ValueError("artifact signer is invalid")
        signer.key().verify(_canonical_base64(signature_base64), _signature_message(domain, model))
        valid = True
    except Exception:
        valid = False
    if not valid:
        raise ProviderCryptoError("artifact_signature")


def signer_genesis_message(genesis: SignerGenesisV1) -> bytes:
    """Canonical bytes to sign for a ``SignerGenesisV1`` artifact."""

    if type(genesis) is not SignerGenesisV1:
        raise ProviderCryptoError("signer_genesis")
    return _signature_message(_SIGNER_GENESIS_DOMAIN, genesis)


def replay_authority_policy_message(artifact: ReplayAuthorityPolicyArtifactV1) -> bytes:
    """Canonical bytes to sign for a replay-policy artifact."""

    if type(artifact) is not ReplayAuthorityPolicyArtifactV1:
        raise ProviderCryptoError("replay_policy")
    return _signature_message(_REPLAY_POLICY_DOMAIN, artifact)


def provider_material_policy_message(policy: ProviderMaterialPolicyV1) -> bytes:
    """Canonical bytes to sign for a material-policy artifact."""

    if type(policy) is not ProviderMaterialPolicyV1:
        raise ProviderCryptoError("material_policy")
    return _signature_message(_MATERIAL_POLICY_DOMAIN, policy)


def provider_fingerprint_attestation_message(
    attestation: ProviderFingerprintAttestationV1,
) -> bytes:
    """Canonical bytes to sign for an observed fingerprint attestation."""

    if type(attestation) is not ProviderFingerprintAttestationV1:
        raise ProviderCryptoError("fingerprint_attestation")
    return _signature_message(_FINGERPRINT_ATTESTATION_DOMAIN, attestation)


def provider_material_genesis_message(genesis: ProviderMaterialGenesisV1) -> bytes:
    """Canonical bytes to sign for a pending material-genesis artifact."""

    if type(genesis) is not ProviderMaterialGenesisV1:
        raise ProviderCryptoError("material_genesis")
    return _signature_message(_MATERIAL_GENESIS_DOMAIN, genesis)


def replay_authority_policy_sha256(service: str, account_prefix: str) -> str:
    """Digest compatible with ``ReplayAuthorityPolicyV1.sha256``.

    Keeping the preimage here avoids a runtime import cycle with the lifecycle
    authorization module while preserving one exact typed policy representation.
    """

    if (
        type(service) is not str
        or type(account_prefix) is not str
        or re.fullmatch(_IDENTIFIER, service) is None
        or re.fullmatch(_IDENTIFIER, account_prefix) is None
    ):
        raise ProviderCryptoError("replay_policy")
    return _sha256(
        _canonical_json(
            {
                "account_prefix": account_prefix,
                "schema_version": "rsd.replay-authority-policy.v1",
                "service": service,
            }
        )
    )


def verify_signer_genesis(
    genesis: SignerGenesisV1,
    *,
    issuer: _TrustedSigner,
    initial_intent: InitialProvisioningIntentV1,
) -> None:
    """Verify issuer approval and exact initial-intent binding for a key seed."""

    genesis = cast(
        SignerGenesisV1,
        _canonical_artifact(genesis, SignerGenesisV1, phase="signer_genesis"),
    )
    initial_intent = _reject_unsupported_tls_termination(initial_intent)
    _verify_initial_intent_signature(initial_intent, issuer=issuer)
    _verify_signed(genesis, domain=_SIGNER_GENESIS_DOMAIN, signer=issuer)
    if genesis.initial_intent_sha256 != initial_provisioning_intent_sha256(initial_intent):
        raise ProviderCryptoError("signer_genesis_binding")


def trusted_signer_from_genesis(
    genesis: SignerGenesisV1,
    *,
    issuer: _TrustedSigner,
    initial_intent: InitialProvisioningIntentV1,
) -> tuple[str, bytes, str]:
    """Return a public trust anchor only after issuer and intent verification."""

    genesis = cast(
        SignerGenesisV1,
        _canonical_artifact(genesis, SignerGenesisV1, phase="signer_genesis"),
    )
    initial_intent = _reject_unsupported_tls_termination(initial_intent)
    verify_signer_genesis(genesis, issuer=issuer, initial_intent=initial_intent)
    try:
        public_key = _canonical_base64(genesis.public_key_base64)
    except ValueError:
        raise ProviderCryptoError("signer_genesis") from None
    return genesis.key_id, public_key, genesis.public_key_fingerprint_sha256


def verify_replay_authority_policy_artifact(
    artifact: ReplayAuthorityPolicyArtifactV1,
    *,
    signer: _TrustedSigner,
    initial_intent: InitialProvisioningIntentV1,
    expected_policy_sha256: str,
) -> None:
    """Verify a signed replay namespace cannot be caller-substituted."""

    artifact = cast(
        ReplayAuthorityPolicyArtifactV1,
        _canonical_artifact(artifact, ReplayAuthorityPolicyArtifactV1, phase="replay_policy"),
    )
    initial_intent = _reject_unsupported_tls_termination(initial_intent)
    if type(expected_policy_sha256) is not str:
        raise ProviderCryptoError("replay_policy")
    _verify_initial_intent_signature(initial_intent, issuer=signer)
    _verify_signed(artifact, domain=_REPLAY_POLICY_DOMAIN, signer=signer)
    intent_sha256 = initial_provisioning_intent_sha256(initial_intent)
    if (
        artifact.initial_intent_sha256 != intent_sha256
        or artifact.replay_policy_sha256 != expected_policy_sha256
        or initial_intent.replay_policy_sha256 != expected_policy_sha256
    ):
        raise ProviderCryptoError("replay_policy_binding")


def _reference_map(
    intent: InitialProvisioningIntentV1,
) -> dict[ProviderMaterialPurpose, ProviderReferenceV1]:
    references = intent.provider_references
    result: dict[ProviderMaterialPurpose, ProviderReferenceV1] = {
        ProviderMaterialPurpose.COMMITMENT_HMAC: references.commitment_hmac,
        ProviderMaterialPurpose.BACKUP_ENCRYPTION: references.backup_encryption,
        ProviderMaterialPurpose.INFISICAL_ENCRYPTION_KEY: references.encryption_key,
        ProviderMaterialPurpose.INFISICAL_AUTH_SECRET: references.auth_secret,
        ProviderMaterialPurpose.PRIMARY_VALKEY_PASSWORD: references.primary_valkey_password,
        ProviderMaterialPurpose.RESTORE_VALKEY_PASSWORD: references.restore_valkey_password,
    }
    if references.tls_trust_anchor is not None:
        result[ProviderMaterialPurpose.TLS_TRUST_ANCHOR] = references.tls_trust_anchor
    return result


def _verify_material_signer(
    *,
    signer: _TrustedSigner,
    signer_genesis: SignerGenesisV1,
    issuer: _TrustedSigner,
    initial_intent: InitialProvisioningIntentV1,
) -> None:
    """Bind every material signature to one issuer-approved intent signer."""

    signer_genesis = cast(
        SignerGenesisV1,
        _canonical_artifact(signer_genesis, SignerGenesisV1, phase="signer_genesis"),
    )
    initial_intent = _reject_unsupported_tls_termination(initial_intent)
    verify_signer_genesis(signer_genesis, issuer=issuer, initial_intent=initial_intent)
    valid = False
    try:
        if (
            type(signer.key_id) is not str
            or type(signer.public_key_fingerprint_sha256) is not str
            or signer.key_id != signer_genesis.key_id
            or signer.public_key_fingerprint_sha256 != signer_genesis.public_key_fingerprint_sha256
        ):
            raise ValueError("material signer is invalid")
        public_key = signer.key().public_bytes(
            serialization.Encoding.Raw,
            serialization.PublicFormat.Raw,
        )
        if not hmac.compare_digest(public_key, _canonical_base64(signer_genesis.public_key_base64)):
            raise ValueError("material signer is invalid")
        valid = True
    except Exception:
        valid = False
    if not valid:
        raise ProviderCryptoError("material_signer")


def _verify_provider_material_policy_at(
    policy: ProviderMaterialPolicyV1,
    *,
    signer: _TrustedSigner,
    signer_genesis: SignerGenesisV1,
    issuer: _TrustedSigner,
    initial_intent: InitialProvisioningIntentV1,
    expected_disposal_owner: str,
    expected_approver_identity: str,
    now: datetime,
) -> None:
    """Verify all policy references, purposes, and retention before use."""

    policy = cast(
        ProviderMaterialPolicyV1,
        _canonical_artifact(policy, ProviderMaterialPolicyV1, phase="material_policy"),
    )
    signer_genesis = cast(
        SignerGenesisV1,
        _canonical_artifact(signer_genesis, SignerGenesisV1, phase="signer_genesis"),
    )
    initial_intent = _reject_unsupported_tls_termination(initial_intent)
    if (
        type(expected_disposal_owner) is not str
        or type(expected_approver_identity) is not str
        or type(now) is not datetime
        or now.tzinfo is None
        or now.utcoffset() is None
    ):
        raise ProviderCryptoError("material_policy")
    _verify_material_signer(
        signer=signer,
        signer_genesis=signer_genesis,
        issuer=issuer,
        initial_intent=initial_intent,
    )
    _verify_signed(policy, domain=_MATERIAL_POLICY_DOMAIN, signer=signer)
    expected_references = _reference_map(initial_intent)
    policy_references = {item.purpose: item.reference for item in policy.materials}
    try:
        expires = _parse_timestamp(policy.retention_expires_at)
        created = _parse_timestamp(policy.created_at)
    except ValueError:
        raise ProviderCryptoError("material_policy") from None
    normalized_now = now.astimezone(UTC)
    if (
        expires is None
        or created is None
        or created > normalized_now
        or expires <= normalized_now
        or policy.initial_intent_sha256 != initial_provisioning_intent_sha256(initial_intent)
        or policy.disposal_owner != expected_disposal_owner
        or policy.approver_identity != expected_approver_identity
        or policy_references != expected_references
        or policy.signer_keychain_reference != signer_genesis.keychain_reference
        or policy.signer_seed_fingerprint_sha256 != signer_genesis.seed_fingerprint_sha256
    ):
        raise ProviderCryptoError("material_policy_binding")


def verify_provider_material_policy(
    policy: ProviderMaterialPolicyV1,
    *,
    signer: _TrustedSigner,
    signer_genesis: SignerGenesisV1,
    issuer: _TrustedSigner,
    initial_intent: InitialProvisioningIntentV1,
    expected_disposal_owner: str,
    expected_approver_identity: str,
) -> None:
    """Verify a material policy against the trusted production UTC clock."""

    _verify_provider_material_policy_at(
        policy,
        signer=signer,
        signer_genesis=signer_genesis,
        issuer=issuer,
        initial_intent=initial_intent,
        expected_disposal_owner=expected_disposal_owner,
        expected_approver_identity=expected_approver_identity,
        now=_system_utc_clock(),
    )


def _verify_provider_fingerprint_attestation_at(
    attestation: ProviderFingerprintAttestationV1,
    *,
    policy: ProviderMaterialPolicyV1,
    signer: _TrustedSigner,
    signer_genesis: SignerGenesisV1,
    issuer: _TrustedSigner,
    initial_intent: InitialProvisioningIntentV1,
    now: datetime,
) -> dict[str, str]:
    """Return trusted reference-to-fingerprint bindings after strict verification."""

    attestation = cast(
        ProviderFingerprintAttestationV1,
        _canonical_artifact(
            attestation,
            ProviderFingerprintAttestationV1,
            phase="fingerprint_attestation",
        ),
    )
    policy = cast(
        ProviderMaterialPolicyV1,
        _canonical_artifact(policy, ProviderMaterialPolicyV1, phase="material_policy"),
    )
    signer_genesis = cast(
        SignerGenesisV1,
        _canonical_artifact(signer_genesis, SignerGenesisV1, phase="signer_genesis"),
    )
    initial_intent = _reject_unsupported_tls_termination(initial_intent)
    if type(now) is not datetime or now.tzinfo is None or now.utcoffset() is None:
        raise ProviderCryptoError("fingerprint_attestation")
    _verify_material_signer(
        signer=signer,
        signer_genesis=signer_genesis,
        issuer=issuer,
        initial_intent=initial_intent,
    )
    _verify_signed(attestation, domain=_FINGERPRINT_ATTESTATION_DOMAIN, signer=signer)
    observed_at = _parse_timestamp(attestation.observed_at)
    normalized_now = now.astimezone(UTC)
    if (
        observed_at is None
        or observed_at > normalized_now
        or normalized_now - observed_at > _MATERIAL_ATTESTATION_FRESHNESS
    ):
        raise ProviderCryptoError("fingerprint_attestation")
    expected = {item.purpose: item.reference.reference_sha256 for item in policy.materials}
    supplied = {item.purpose: item.reference_sha256 for item in attestation.materials}
    if (
        attestation.initial_intent_sha256 != initial_provisioning_intent_sha256(initial_intent)
        or attestation.provider_material_policy_sha256 != policy.policy_sha256()
        or supplied != expected
    ):
        raise ProviderCryptoError("fingerprint_attestation_binding")
    fingerprints = attestation.fingerprint_by_reference()
    if (
        len(fingerprints) != len(policy.materials)
        or len(set(fingerprints.values())) != len(fingerprints)
        or policy.signer_seed_fingerprint_sha256 in fingerprints.values()
    ):
        raise ProviderCryptoError("fingerprint_attestation_binding")
    return fingerprints


def verify_provider_fingerprint_attestation(
    attestation: ProviderFingerprintAttestationV1,
    *,
    policy: ProviderMaterialPolicyV1,
    signer: _TrustedSigner,
    signer_genesis: SignerGenesisV1,
    issuer: _TrustedSigner,
    initial_intent: InitialProvisioningIntentV1,
) -> dict[str, str]:
    """Verify a fingerprint attestation against the production UTC clock."""

    return _verify_provider_fingerprint_attestation_at(
        attestation,
        policy=policy,
        signer=signer,
        signer_genesis=signer_genesis,
        issuer=issuer,
        initial_intent=initial_intent,
        now=_system_utc_clock(),
    )


def _verify_provider_material_bundle_at(
    policy: ProviderMaterialPolicyV1,
    attestation: ProviderFingerprintAttestationV1,
    *,
    signer: _TrustedSigner,
    signer_genesis: SignerGenesisV1,
    issuer: _TrustedSigner,
    initial_intent: InitialProvisioningIntentV1,
    expected_disposal_owner: str,
    expected_approver_identity: str,
    now: datetime,
) -> dict[str, str]:
    """Verify a signed policy and its signed fingerprint attestation together."""

    _verify_provider_material_policy_at(
        policy,
        signer=signer,
        signer_genesis=signer_genesis,
        issuer=issuer,
        initial_intent=initial_intent,
        expected_disposal_owner=expected_disposal_owner,
        expected_approver_identity=expected_approver_identity,
        now=now,
    )
    return _verify_provider_fingerprint_attestation_at(
        attestation,
        policy=policy,
        signer=signer,
        signer_genesis=signer_genesis,
        issuer=issuer,
        initial_intent=initial_intent,
        now=now,
    )


def verify_provider_material_bundle(
    policy: ProviderMaterialPolicyV1,
    attestation: ProviderFingerprintAttestationV1,
    *,
    signer: _TrustedSigner,
    signer_genesis: SignerGenesisV1,
    issuer: _TrustedSigner,
    initial_intent: InitialProvisioningIntentV1,
    expected_disposal_owner: str,
    expected_approver_identity: str,
) -> dict[str, str]:
    """Verify a material bundle against the trusted production UTC clock."""

    return _verify_provider_material_bundle_at(
        policy,
        attestation,
        signer=signer,
        signer_genesis=signer_genesis,
        issuer=issuer,
        initial_intent=initial_intent,
        expected_disposal_owner=expected_disposal_owner,
        expected_approver_identity=expected_approver_identity,
        now=_system_utc_clock(),
    )


def verify_provider_material_genesis(
    genesis: ProviderMaterialGenesisV1,
    *,
    policy: ProviderMaterialPolicyV1,
    attestation: ProviderFingerprintAttestationV1,
    signer: _TrustedSigner,
    signer_genesis: SignerGenesisV1,
    issuer: _TrustedSigner,
    initial_intent: InitialProvisioningIntentV1,
) -> None:
    """Verify the pending manifest binds the exact policy and attestation.

    A valid manifest proves the only supported provisioning sequence was
    declared before a Keychain write. It is not a bearer capability and cannot
    create or modify any provider item by itself.
    """

    genesis = cast(
        ProviderMaterialGenesisV1,
        _canonical_artifact(genesis, ProviderMaterialGenesisV1, phase="material_genesis"),
    )
    policy = cast(
        ProviderMaterialPolicyV1,
        _canonical_artifact(policy, ProviderMaterialPolicyV1, phase="material_policy"),
    )
    attestation = cast(
        ProviderFingerprintAttestationV1,
        _canonical_artifact(
            attestation,
            ProviderFingerprintAttestationV1,
            phase="fingerprint_attestation",
        ),
    )
    signer_genesis = cast(
        SignerGenesisV1,
        _canonical_artifact(signer_genesis, SignerGenesisV1, phase="signer_genesis"),
    )
    initial_intent = _reject_unsupported_tls_termination(initial_intent)
    _verify_material_signer(
        signer=signer,
        signer_genesis=signer_genesis,
        issuer=issuer,
        initial_intent=initial_intent,
    )
    _verify_signed(genesis, domain=_MATERIAL_GENESIS_DOMAIN, signer=signer)
    if (
        genesis.initial_intent_sha256 != initial_provisioning_intent_sha256(initial_intent)
        or genesis.provider_material_policy_sha256 != policy.policy_sha256()
        or genesis.provider_fingerprint_attestation_sha256
        != _sha256(_canonical_json(attestation.model_dump(mode="json")))
    ):
        raise ProviderCryptoError("material_genesis_binding")


def _zeroize(value: bytearray) -> None:
    """Best-effort overwrite for mutable copies held by this module."""

    for index in range(len(value)):
        value[index] = 0


_STANDARD_BASE64_ALPHABET: Final = (
    b"ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/"
)
_URLSAFE_BASE64_ALPHABET: Final = (
    b"ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789-_"
)


def _alphabet_index(value: int, alphabet: bytes) -> int:
    """Find one encoded byte without allocating a secret-bearing copy."""

    for index, candidate in enumerate(alphabet):
        if value == candidate:
            return index
    return -1


def _is_lower_hex_16(raw: bytearray) -> bool:
    return len(raw) == 32 and all(48 <= value <= 57 or 97 <= value <= 102 for value in raw)


def _is_canonical_standard_base64_32(raw: bytearray) -> bool:
    """Recognize the only canonical 44-char Base64 representation of 32 bytes."""

    if len(raw) != 44 or raw[-1] != ord("="):
        return False
    last_index = -1
    for index in range(len(raw) - 1):
        last_index = _alphabet_index(raw[index], _STANDARD_BASE64_ALPHABET)
        if last_index < 0:
            return False
    return last_index & 0b11 == 0


def _is_canonical_base64url_32(raw: bytearray) -> bool:
    """Recognize the only canonical unpadded Base64URL spelling of 32 bytes."""

    if len(raw) != 43:
        return False
    last_index = -1
    for value in raw:
        last_index = _alphabet_index(value, _URLSAFE_BASE64_ALPHABET)
        if last_index < 0:
            return False
    return last_index & 0b11 == 0


def _validate_value(spec: ProviderMaterialSpecV1, value: bytearray) -> None:
    """Validate format without returning or serializing the material value."""

    if (
        type(spec) is not ProviderMaterialSpecV1
        or type(spec.format) is not ProviderMaterialFormat
        or type(value) is not bytearray
        or not (spec.value_min_bytes <= len(value) <= spec.value_max_bytes)
    ):
        raise ProviderCryptoError("material_format")
    raw = value
    format_value = spec.format.value
    if format_value in {
        ProviderMaterialFormat.HMAC_SHA256_RAW_32_V1.value,
        ProviderMaterialFormat.AES_256_GCM_RAW_32_V1.value,
    }:
        return
    if format_value == ProviderMaterialFormat.INFISICAL_HEX_16_V1.value:
        if not _is_lower_hex_16(raw):
            raise ProviderCryptoError("material_format")
        return
    if format_value == ProviderMaterialFormat.INFISICAL_AUTH_SECRET_BASE64_32_V1.value:
        if not _is_canonical_standard_base64_32(raw):
            raise ProviderCryptoError("material_format")
        return
    if format_value == ProviderMaterialFormat.VALKEY_PASSWORD_BASE64URL_32_V1.value:
        if not _is_canonical_base64url_32(raw):
            raise ProviderCryptoError("material_format")
        return
    if format_value == ProviderMaterialFormat.X509_CA_PEM_V1.value:
        try:
            # cryptography accepts immutable input here. This isolated parser
            # boundary therefore makes one unavoidable transient copy; the
            # encoded secret formats above never decode or copy their buffers.
            certificate = x509.load_pem_x509_certificate(bytes(raw))
            canonical = certificate.public_bytes(serialization.Encoding.PEM)
            basic_constraints = certificate.extensions.get_extension_for_class(
                x509.BasicConstraints
            ).value
        except (ValueError, x509.ExtensionNotFound):
            raise ProviderCryptoError("material_format") from None
        if not basic_constraints.ca or not hmac.compare_digest(canonical, raw):
            raise ProviderCryptoError("material_format")
        return
    raise ProviderCryptoError("material_format")


class _MacOSGenericPasswordStore:
    """Direct Security.framework generic-password bridge with no update/delete path."""

    _ERR_SEC_SUCCESS: Final = 0
    _ERR_SEC_DUPLICATE_ITEM: Final = -25299
    _ERR_SEC_ITEM_NOT_FOUND: Final = -25300
    _UTF8: Final = 0x08000100

    def __init__(self) -> None:
        if sys.platform != "darwin":
            raise RuntimeError("Security.framework is unavailable")
        self._security: Any = ctypes.CDLL("/System/Library/Frameworks/Security.framework/Security")
        self._core: Any = ctypes.CDLL(
            "/System/Library/Frameworks/CoreFoundation.framework/CoreFoundation"
        )
        self._configure_symbols()
        self._class = self._symbol(self._security, "kSecClass")
        self._generic_password = self._symbol(self._security, "kSecClassGenericPassword")
        self._service = self._symbol(self._security, "kSecAttrService")
        self._account = self._symbol(self._security, "kSecAttrAccount")
        self._value_data = self._symbol(self._security, "kSecValueData")
        self._return_data = self._symbol(self._security, "kSecReturnData")
        self._match_limit = self._symbol(self._security, "kSecMatchLimit")
        self._match_limit_one = self._symbol(self._security, "kSecMatchLimitOne")
        self._boolean_true = self._symbol(self._core, "kCFBooleanTrue")

    def _configure_symbols(self) -> None:
        pointer = ctypes.c_void_p
        self._security.SecItemAdd.argtypes = [pointer, pointer]
        self._security.SecItemAdd.restype = ctypes.c_int32
        self._security.SecItemCopyMatching.argtypes = [pointer, ctypes.POINTER(pointer)]
        self._security.SecItemCopyMatching.restype = ctypes.c_int32
        self._core.CFStringCreateWithCString.argtypes = [pointer, ctypes.c_char_p, ctypes.c_uint32]
        self._core.CFStringCreateWithCString.restype = pointer
        self._core.CFDataCreate.argtypes = [pointer, ctypes.POINTER(ctypes.c_ubyte), ctypes.c_long]
        self._core.CFDataCreate.restype = pointer
        self._core.CFDataGetLength.argtypes = [pointer]
        self._core.CFDataGetLength.restype = ctypes.c_long
        self._core.CFDataGetBytePtr.argtypes = [pointer]
        self._core.CFDataGetBytePtr.restype = ctypes.POINTER(ctypes.c_ubyte)
        self._core.CFDictionaryCreateMutable.argtypes = [pointer, ctypes.c_long, pointer, pointer]
        self._core.CFDictionaryCreateMutable.restype = pointer
        self._core.CFDictionarySetValue.argtypes = [pointer, pointer, pointer]
        self._core.CFDictionarySetValue.restype = None
        self._core.CFRelease.argtypes = [pointer]
        self._core.CFRelease.restype = None

    @staticmethod
    def _symbol(library: Any, name: str) -> int:
        pointer = ctypes.c_void_p.in_dll(library, name).value
        if pointer is None:
            raise RuntimeError("Security.framework symbol is unavailable")
        return int(pointer)

    def _release(self, value: Any) -> None:
        if value:
            self._core.CFRelease(ctypes.c_void_p(value))

    def _string(self, value: str) -> Any:
        result = self._core.CFStringCreateWithCString(None, value.encode("utf-8"), self._UTF8)
        if not result:
            raise RuntimeError("Security.framework allocation failed")
        return result

    def _data(self, value: bytearray) -> Any:
        buffer = (ctypes.c_ubyte * len(value)).from_buffer(value)
        result = self._core.CFDataCreate(None, buffer, len(value))
        if not result:
            raise RuntimeError("Security.framework allocation failed")
        return result

    def _dictionary(self, entries: list[tuple[int, Any]]) -> Any:
        result = self._core.CFDictionaryCreateMutable(None, 0, None, None)
        if not result:
            raise RuntimeError("Security.framework allocation failed")
        for key, value in entries:
            self._core.CFDictionarySetValue(result, ctypes.c_void_p(key), ctypes.c_void_p(value))
        return result

    def read_if_present(self, service: str, account: str) -> bytearray | None:
        service_value = self._string(service)
        account_value = self._string(account)
        query: Any = None
        result = ctypes.c_void_p()
        try:
            query = self._dictionary(
                [
                    (self._class, self._generic_password),
                    (self._service, service_value),
                    (self._account, account_value),
                    (self._return_data, self._boolean_true),
                    (self._match_limit, self._match_limit_one),
                ]
            )
            status = self._security.SecItemCopyMatching(query, ctypes.byref(result))
            if status == self._ERR_SEC_ITEM_NOT_FOUND:
                return None
            if status != self._ERR_SEC_SUCCESS or not result.value:
                raise RuntimeError("Security.framework lookup failed")
            length = self._core.CFDataGetLength(result)
            pointer = self._core.CFDataGetBytePtr(result)
            if length < 0 or not pointer:
                raise RuntimeError("Security.framework lookup failed")
            value = bytearray(length)
            if length:
                ctypes.memmove((ctypes.c_ubyte * length).from_buffer(value), pointer, length)
            return value
        finally:
            if result.value:
                self._release(result.value)
            if query:
                self._release(query)
            self._release(account_value)
            self._release(service_value)

    def add_if_absent(self, service: str, account: str, value: bytearray) -> bool:
        service_value = self._string(service)
        account_value = self._string(account)
        data_value = self._data(value)
        attributes: Any = None
        try:
            attributes = self._dictionary(
                [
                    (self._class, self._generic_password),
                    (self._service, service_value),
                    (self._account, account_value),
                    (self._value_data, data_value),
                ]
            )
            status = self._security.SecItemAdd(attributes, None)
            if status == self._ERR_SEC_SUCCESS:
                return True
            if status == self._ERR_SEC_DUPLICATE_ITEM:
                return False
            raise RuntimeError("Security.framework create failed")
        finally:
            if attributes:
                self._release(attributes)
            self._release(data_value)
            self._release(account_value)
            self._release(service_value)


def _default_keychain_store() -> _KeychainTransport:
    """Construct the direct framework adapter without exposing platform errors."""

    try:
        return _MacOSGenericPasswordStore()
    except Exception:
        pass
    raise ProviderCryptoError("keychain_store")


class KeychainEd25519Signer:
    """Ed25519 signer whose seed stays in a generic Keychain item.

    Signing necessarily materializes a short-lived mutable copy in this process
    because ``cryptography`` accepts raw Ed25519 seed bytes. The source copy is
    overwritten in a ``finally`` block; copies held by the OS or cryptography
    cannot be guaranteed to be erased by Python.
    """

    def __init__(
        self,
        genesis: SignerGenesisV1,
        *,
        issuer: _TrustedSigner,
        initial_intent: InitialProvisioningIntentV1,
        _store: _KeychainTransport | None = None,
    ) -> None:
        initial_intent = _reject_unsupported_tls_termination(initial_intent)
        genesis = cast(
            SignerGenesisV1,
            _canonical_artifact(genesis, SignerGenesisV1, phase="signer_genesis"),
        )
        verify_signer_genesis(genesis, issuer=issuer, initial_intent=initial_intent)
        self._genesis = genesis
        self._store = _default_keychain_store() if _store is None else _store
        try:
            self._public_key = Ed25519PublicKey.from_public_bytes(
                _canonical_base64(genesis.public_key_base64)
            )
        except ValueError:
            raise ProviderCryptoError("signer_genesis") from None

    @property
    def key_id(self) -> str:
        return self._genesis.key_id

    @property
    def public_key_fingerprint_sha256(self) -> str:
        return self._genesis.public_key_fingerprint_sha256

    def key(self) -> Ed25519PublicKey:
        return self._public_key

    def _seed(self) -> bytearray:
        reference = self._genesis.keychain_reference
        stored = _read_keychain_value(self._store, reference.service, reference.account)
        if type(stored) is not bytearray:
            raise ProviderCryptoError("keychain_signer")
        seed = stored
        try:
            derived = (
                Ed25519PrivateKey.from_private_bytes(seed)
                .public_key()
                .public_bytes(
                    serialization.Encoding.Raw,
                    serialization.PublicFormat.Raw,
                )
            )
        except ValueError:
            _zeroize(seed)
            raise ProviderCryptoError("keychain_signer") from None
        if (
            len(seed) != 32
            or not hmac.compare_digest(_sha256(seed), self._genesis.seed_fingerprint_sha256)
            or not hmac.compare_digest(
                derived,
                _canonical_base64(self._genesis.public_key_base64),
            )
        ):
            _zeroize(seed)
            raise ProviderCryptoError("keychain_signer")
        return seed

    def sign_artifact(
        self,
        artifact: (
            ReplayAuthorityPolicyArtifactV1
            | ProviderMaterialPolicyV1
            | ProviderFingerprintAttestationV1
            | ProviderMaterialGenesisV1
        ),
    ) -> bytes:
        """Sign only one exact, intent-bound provider bootstrap artifact.

        This intentionally does not offer a generic ``sign(bytes)`` method.
        The Keychain seed may not become an ambient signing oracle for another
        intent or an unrelated Ed25519 domain.
        """

        messages: tuple[tuple[type[BaseModel], Callable[[Any], bytes]], ...] = (
            (ReplayAuthorityPolicyArtifactV1, replay_authority_policy_message),
            (ProviderMaterialPolicyV1, provider_material_policy_message),
            (ProviderFingerprintAttestationV1, provider_fingerprint_attestation_message),
            (ProviderMaterialGenesisV1, provider_material_genesis_message),
        )
        message: bytes | None = None
        for model_type, build_message in messages:
            if type(artifact) is model_type:
                canonical_artifact = _canonical_artifact(
                    artifact,
                    model_type,
                    phase="keychain_signer_scope",
                )
                candidate_intent = getattr(canonical_artifact, "initial_intent_sha256", None)
                candidate_key_id = getattr(canonical_artifact, "signer_key_id", None)
                if (
                    type(candidate_intent) is not str
                    or type(candidate_key_id) is not str
                    or candidate_intent != self._genesis.initial_intent_sha256
                    or candidate_key_id != self._genesis.key_id
                ):
                    raise ProviderCryptoError("keychain_signer_scope")
                message = build_message(canonical_artifact)
                break
        if message is None:
            raise ProviderCryptoError("keychain_signer_scope")
        seed = self._seed()
        try:
            return Ed25519PrivateKey.from_private_bytes(seed).sign(message)
        except ValueError:
            raise ProviderCryptoError("keychain_signer") from None
        finally:
            _zeroize(seed)


def provision_keychain_ed25519_signer(
    paths: ProviderMaterialArtifactPaths,
    genesis: SignerGenesisV1,
    *,
    issuer: _TrustedSigner,
    initial_intent: InitialProvisioningIntentV1,
    seed: bytearray,
    _store: _KeychainTransport | None = None,
) -> KeychainEd25519Signer:
    """Create one Keychain seed only after a signed genesis is durable.

    The caller must supply the seed through an in-memory trusted boundary.  This
    API accepts no path, environment-variable name, or command-line value.
    Duplicate items always fail closed, including byte-identical duplicates.
    """

    if type(seed) is not bytearray:
        raise ProviderCryptoError("keychain_signer")
    try:
        initial_intent = _reject_unsupported_tls_termination(initial_intent)
        with _OwnerOnlyArtifactDirectory(paths.root) as directory:
            genesis = _persist_verified_signer_genesis_in_directory(
                directory,
                signer_genesis_name=paths.signer_genesis_name(),
                genesis=genesis,
                issuer=issuer,
                initial_intent=initial_intent,
            )
            # Keep the same owner-only root descriptor open through the
            # one-way Keychain write, and re-open/reverify the durable name
            # immediately before it.  A path replacement cannot select a
            # different root between the durable trust-anchor check and
            # ``SecItemAdd``.
            genesis = _require_persisted_signer_genesis_in_directory(
                directory,
                signer_genesis_name=paths.signer_genesis_name(),
                genesis=genesis,
                issuer=issuer,
                initial_intent=initial_intent,
            )
            try:
                derived = (
                    Ed25519PrivateKey.from_private_bytes(seed)
                    .public_key()
                    .public_bytes(
                        serialization.Encoding.Raw,
                        serialization.PublicFormat.Raw,
                    )
                )
            except ValueError:
                raise ProviderCryptoError("keychain_signer") from None
            try:
                expected_public = _canonical_base64(genesis.public_key_base64)
            except ValueError:
                raise ProviderCryptoError("signer_genesis") from None
            if (
                len(seed) != 32
                or not hmac.compare_digest(_sha256(seed), genesis.seed_fingerprint_sha256)
                or not hmac.compare_digest(derived, expected_public)
            ):
                raise ProviderCryptoError("keychain_signer")
            store = _default_keychain_store() if _store is None else _store
            reference = genesis.keychain_reference
            with directory.pin_exact_signer_genesis(
                paths.signer_genesis_name(),
                _yaml_bytes(genesis),
            ):
                created = _create_keychain_value(store, reference.service, reference.account, seed)
            if type(created) is not bool:
                raise ProviderCryptoError("keychain_signer")
            if not created:
                raise ProviderCryptoError("keychain_signer_replayed")
            return KeychainEd25519Signer(
                genesis,
                issuer=issuer,
                initial_intent=initial_intent,
                _store=store,
            )
    finally:
        _zeroize(seed)


def load_keychain_ed25519_signer(
    paths: ProviderMaterialArtifactPaths,
    *,
    issuer: _TrustedSigner,
    initial_intent: InitialProvisioningIntentV1,
    _store: _KeychainTransport | None = None,
) -> KeychainEd25519Signer:
    """Load only an issuer-verified persistent signer genesis and Keychain seed."""

    initial_intent = _reject_unsupported_tls_termination(initial_intent)
    genesis = load_verified_signer_genesis(
        paths,
        issuer=issuer,
        initial_intent=initial_intent,
    )
    return KeychainEd25519Signer(
        genesis,
        issuer=issuer,
        initial_intent=initial_intent,
        _store=_store,
    )


class _KeychainLease:
    def __init__(
        self,
        *,
        specs: Mapping[str, ProviderMaterialSpecV1],
        store: _KeychainTransport,
    ) -> None:
        self._specs = dict(specs)
        self._store = store

    def _inspect(self, reference: ProviderReferenceV1) -> KeychainProviderProvenance | None:
        spec = self._specs.get(reference.reference_sha256)
        if spec is None or spec.reference != reference or reference.provider != "macos_keychain":
            return None
        stored = _read_keychain_value(self._store, reference.service, reference.account)
        if type(stored) is not bytearray:
            return None
        value = stored
        try:
            _validate_value(spec, value)
            fingerprint = _sha256(value)
        finally:
            _zeroize(value)
        return KeychainProviderProvenance(
            provider=reference.provider,
            service=reference.service,
            account=reference.account,
            version=reference.version,
            reference_sha256=reference.reference_sha256,
            fingerprint_sha256=fingerprint,
        )

    def inspect(self, reference: ProviderReferenceV1) -> KeychainProviderProvenance | None:
        return self._inspect(reference)

    def recheck(self, reference: ProviderReferenceV1) -> KeychainProviderProvenance | None:
        return self._inspect(reference)


class MacOSKeychainProviderProvenanceAdapter:
    """Security.framework provenance adapter with no provider-value output."""

    def __init__(
        self,
        policy: ProviderMaterialPolicyV1,
        *,
        _store: _KeychainTransport | None = None,
    ) -> None:
        policy = cast(
            ProviderMaterialPolicyV1,
            _canonical_artifact(policy, ProviderMaterialPolicyV1, phase="material_policy"),
        )
        self._specs = policy.by_reference()
        self._store = _default_keychain_store() if _store is None else _store

    @contextmanager
    def acquire(self, references: tuple[ProviderReferenceV1, ...]) -> Iterator[_KeychainLease]:
        expected = tuple(self._specs)
        supplied = tuple(reference.reference_sha256 for reference in references)
        if len(supplied) != len(expected) or set(supplied) != set(expected):
            raise ProviderCryptoError("provider_keychain")
        yield _KeychainLease(specs=self._specs, store=self._store)


@dataclass(frozen=True, slots=True)
class ProviderMaterialArtifactPaths:
    """Fixed owner-only filenames for signed non-secret provider artifacts."""

    root: Path

    @staticmethod
    def policy_name() -> str:
        return _MATERIAL_POLICY_NAME

    @staticmethod
    def genesis_name() -> str:
        return _MATERIAL_GENESIS_NAME

    @staticmethod
    def attestation_name() -> str:
        return _FINGERPRINT_ATTESTATION_NAME

    @staticmethod
    def replay_policy_name() -> str:
        return _REPLAY_POLICY_NAME

    @staticmethod
    def signer_genesis_name() -> str:
        return _SIGNER_GENESIS_NAME


class _OwnerOnlyArtifactDirectory:
    """Descriptor-relative no-follow reader/writer for bounded public artifacts."""

    def __init__(self, root: Path) -> None:
        self._root = root
        self._fd: int | None = None

    def __enter__(self) -> _OwnerOnlyArtifactDirectory:
        flags = os.O_RDONLY | os.O_DIRECTORY | getattr(os, "O_NOFOLLOW", 0)
        try:
            descriptor = os.open(self._root, flags)
            details = os.fstat(descriptor)
        except OSError:
            raise ProviderCryptoError("artifact_root") from None
        if (
            not stat.S_ISDIR(details.st_mode)
            or details.st_uid != os.getuid()
            or stat.S_IMODE(details.st_mode) != 0o700
            or details.st_nlink < 2
        ):
            os.close(descriptor)
            raise ProviderCryptoError("artifact_root")
        self._fd = descriptor
        return self

    def __exit__(self, exc_type: object, exc: object, traceback: object) -> None:
        del exc_type, exc, traceback
        if self._fd is not None:
            os.close(self._fd)
            self._fd = None

    def _descriptor(self) -> int:
        if self._fd is None:
            raise ProviderCryptoError("artifact_root")
        return self._fd

    def read(self, name: str) -> bytes:
        if name not in {
            _MATERIAL_POLICY_NAME,
            _MATERIAL_GENESIS_NAME,
            _FINGERPRINT_ATTESTATION_NAME,
            _REPLAY_POLICY_NAME,
            _SIGNER_GENESIS_NAME,
        }:
            raise ProviderCryptoError("artifact_name")
        try:
            descriptor = os.open(
                name,
                os.O_RDONLY | getattr(os, "O_NOFOLLOW", 0),
                dir_fd=self._descriptor(),
            )
        except OSError:
            raise ProviderCryptoError("artifact_read") from None
        try:
            details = os.fstat(descriptor)
            if (
                not stat.S_ISREG(details.st_mode)
                or details.st_uid != os.getuid()
                or stat.S_IMODE(details.st_mode) != 0o600
                or details.st_nlink != 1
                or details.st_size < 1
                or details.st_size > _MAX_ARTIFACT_BYTES
            ):
                raise ProviderCryptoError("artifact_read")
            chunks: list[bytes] = []
            remaining = details.st_size
            while remaining:
                chunk = os.read(descriptor, remaining)
                if not chunk:
                    raise ProviderCryptoError("artifact_read")
                chunks.append(chunk)
                remaining -= len(chunk)
            if os.read(descriptor, 1):
                raise ProviderCryptoError("artifact_read")
            return b"".join(chunks)
        except OSError:
            raise ProviderCryptoError("artifact_read") from None
        finally:
            os.close(descriptor)

    def read_optional(self, name: str) -> bytes | None:
        """Return ``None`` only for absence; unsafe files remain hard failures."""

        if name not in {
            _MATERIAL_POLICY_NAME,
            _MATERIAL_GENESIS_NAME,
            _FINGERPRINT_ATTESTATION_NAME,
            _REPLAY_POLICY_NAME,
            _SIGNER_GENESIS_NAME,
        }:
            raise ProviderCryptoError("artifact_name")
        try:
            descriptor = os.open(
                name,
                os.O_RDONLY | getattr(os, "O_NOFOLLOW", 0),
                dir_fd=self._descriptor(),
            )
        except FileNotFoundError:
            return None
        except OSError:
            raise ProviderCryptoError("artifact_read") from None
        try:
            details = os.fstat(descriptor)
            if (
                not stat.S_ISREG(details.st_mode)
                or details.st_uid != os.getuid()
                or stat.S_IMODE(details.st_mode) != 0o600
                or details.st_nlink != 1
                or details.st_size < 1
                or details.st_size > _MAX_ARTIFACT_BYTES
            ):
                raise ProviderCryptoError("artifact_read")
            chunks: list[bytes] = []
            remaining = details.st_size
            while remaining:
                chunk = os.read(descriptor, remaining)
                if not chunk:
                    raise ProviderCryptoError("artifact_read")
                chunks.append(chunk)
                remaining -= len(chunk)
            if os.read(descriptor, 1):
                raise ProviderCryptoError("artifact_read")
            return b"".join(chunks)
        except OSError:
            raise ProviderCryptoError("artifact_read") from None
        finally:
            os.close(descriptor)

    def fsync_existing(self, name: str) -> None:
        """Durably pin one already-validated immutable artifact before a write."""

        if name not in {
            _MATERIAL_POLICY_NAME,
            _MATERIAL_GENESIS_NAME,
            _FINGERPRINT_ATTESTATION_NAME,
            _REPLAY_POLICY_NAME,
            _SIGNER_GENESIS_NAME,
        }:
            raise ProviderCryptoError("artifact_name")
        try:
            descriptor = os.open(
                name,
                os.O_RDONLY | getattr(os, "O_NOFOLLOW", 0),
                dir_fd=self._descriptor(),
            )
        except OSError:
            raise ProviderCryptoError("artifact_read") from None
        try:
            details = os.fstat(descriptor)
            if (
                not stat.S_ISREG(details.st_mode)
                or details.st_uid != os.getuid()
                or stat.S_IMODE(details.st_mode) != 0o600
                or details.st_nlink != 1
                or details.st_size < 1
                or details.st_size > _MAX_ARTIFACT_BYTES
            ):
                raise ProviderCryptoError("artifact_read")
            os.fsync(descriptor)
            os.fsync(self._descriptor())
        except OSError:
            raise ProviderCryptoError("artifact_write") from None
        finally:
            os.close(descriptor)

    @staticmethod
    def _exact_file_details(
        details: os.stat_result,
    ) -> tuple[int, int, int, int, int, int, int, int]:
        """Return the immutable identity/timestamp tuple for a pinned artifact."""

        return (
            details.st_dev,
            details.st_ino,
            details.st_nlink,
            details.st_uid,
            stat.S_IMODE(details.st_mode),
            details.st_size,
            details.st_mtime_ns,
            details.st_ctime_ns,
        )

    @staticmethod
    def _read_descriptor_exact(descriptor: int, expected: bytes) -> None:
        """Compare an open immutable-artifact FD without reopening its name."""

        try:
            os.lseek(descriptor, 0, os.SEEK_SET)
            chunks: list[bytes] = []
            remaining = len(expected)
            while remaining:
                chunk = os.read(descriptor, remaining)
                if not chunk:
                    raise ProviderCryptoError("signer_genesis")
                chunks.append(chunk)
                remaining -= len(chunk)
            if os.read(descriptor, 1) or not hmac.compare_digest(b"".join(chunks), expected):
                raise ProviderCryptoError("signer_genesis")
        except OSError:
            raise ProviderCryptoError("signer_genesis") from None

    @contextmanager
    def pin_exact_signer_genesis(self, name: str, expected: bytes) -> Iterator[None]:
        """Hold one signer artifact stable through an irreversible Keychain write.

        The exclusive advisory lease coordinates same-owner RSD processes.  The
        descriptor is re-read and its identity/timestamps are compared when the
        lease releases, so a non-cooperating in-place replacement also turns
        the bootstrap into a fail-closed orphan state rather than a successful
        completed provisioning.
        """

        if name != _SIGNER_GENESIS_NAME or type(expected) is not bytes or not expected:
            raise ProviderCryptoError("signer_genesis")
        try:
            descriptor = os.open(
                name,
                os.O_RDONLY | getattr(os, "O_NOFOLLOW", 0),
                dir_fd=self._descriptor(),
            )
        except OSError:
            raise ProviderCryptoError("signer_genesis") from None
        locked = False
        try:
            details = os.fstat(descriptor)
            if (
                not stat.S_ISREG(details.st_mode)
                or details.st_uid != os.getuid()
                or stat.S_IMODE(details.st_mode) != 0o600
                or details.st_nlink != 1
                or details.st_size != len(expected)
            ):
                raise ProviderCryptoError("signer_genesis")
            try:
                fcntl.flock(descriptor, fcntl.LOCK_EX | fcntl.LOCK_NB)
                locked = True
            except OSError:
                raise ProviderCryptoError("signer_genesis_busy") from None
            self._read_descriptor_exact(descriptor, expected)
            try:
                os.fsync(descriptor)
                os.fsync(self._descriptor())
            except OSError:
                raise ProviderCryptoError("signer_genesis") from None
            original_details = self._exact_file_details(details)
            try:
                yield
            finally:
                final_details = os.fstat(descriptor)
                if self._exact_file_details(
                    final_details
                ) != original_details or final_details.st_size != len(expected):
                    raise ProviderCryptoError("signer_genesis")
                self._read_descriptor_exact(descriptor, expected)
                try:
                    os.fsync(descriptor)
                    os.fsync(self._descriptor())
                except OSError:
                    raise ProviderCryptoError("signer_genesis") from None
        except OSError:
            raise ProviderCryptoError("signer_genesis") from None
        finally:
            if locked:
                with suppress(OSError):
                    fcntl.flock(descriptor, fcntl.LOCK_UN)
            os.close(descriptor)

    def write_once(self, name: str, value: bytes) -> None:
        if (
            name
            not in {
                _MATERIAL_POLICY_NAME,
                _MATERIAL_GENESIS_NAME,
                _FINGERPRINT_ATTESTATION_NAME,
                _REPLAY_POLICY_NAME,
                _SIGNER_GENESIS_NAME,
            }
            or type(value) is not bytes
            or not value
            or len(value) > _MAX_ARTIFACT_BYTES
        ):
            raise ProviderCryptoError("artifact_write")
        flags = os.O_WRONLY | os.O_CREAT | os.O_EXCL | getattr(os, "O_NOFOLLOW", 0)
        try:
            descriptor = os.open(name, flags, 0o600, dir_fd=self._descriptor())
        except FileExistsError:
            raise ProviderCryptoError("artifact_replayed") from None
        except OSError:
            raise ProviderCryptoError("artifact_write") from None
        try:
            offset = 0
            while offset < len(value):
                written = os.write(descriptor, value[offset:])
                if written <= 0:
                    raise ProviderCryptoError("artifact_write")
                offset += written
            os.fsync(descriptor)
        except OSError:
            raise ProviderCryptoError("artifact_write") from None
        finally:
            os.close(descriptor)
        try:
            os.fsync(self._descriptor())
        except OSError:
            raise ProviderCryptoError("artifact_write") from None

    def write_once_or_require_exact(self, name: str, value: bytes) -> None:
        """Create one durable artifact or admit only exact crash recovery bytes."""

        existing = self.read_optional(name)
        if existing is None:
            self.write_once(name, value)
        elif not hmac.compare_digest(existing, value):
            raise ProviderCryptoError("artifact_replayed")
        self.fsync_existing(name)


def _yaml_bytes(model: BaseModel) -> bytes:
    try:
        return yaml.safe_dump(model.model_dump(mode="json"), sort_keys=True).encode("utf-8")
    except (TypeError, ValueError, yaml.YAMLError):
        raise ProviderCryptoError("artifact_encoding") from None


def _load_model(raw: bytes, model_type: type[_Model], *, phase: str) -> _Model:
    try:
        document = yaml.load(raw.decode("utf-8"), Loader=_UniqueLoader)
        if type(document) is not dict or not all(type(key) is str for key in document):
            raise TypeError
        return model_type.model_validate(document)
    except (TypeError, UnicodeDecodeError, ValidationError, ValueError, yaml.YAMLError):
        raise ProviderCryptoError(phase) from None


def persist_replay_authority_policy_artifact(
    paths: ProviderMaterialArtifactPaths,
    artifact: ReplayAuthorityPolicyArtifactV1,
    *,
    signer: _TrustedSigner,
    initial_intent: InitialProvisioningIntentV1,
    expected_policy_sha256: str,
) -> None:
    """Explicitly persist one signed replay-policy preimage before use."""

    initial_intent = _reject_unsupported_tls_termination(initial_intent)
    artifact = cast(
        ReplayAuthorityPolicyArtifactV1,
        _canonical_artifact(artifact, ReplayAuthorityPolicyArtifactV1, phase="replay_policy"),
    )
    verify_replay_authority_policy_artifact(
        artifact,
        signer=signer,
        initial_intent=initial_intent,
        expected_policy_sha256=expected_policy_sha256,
    )
    with _OwnerOnlyArtifactDirectory(paths.root) as directory:
        directory.write_once(paths.replay_policy_name(), _yaml_bytes(artifact))


def _persist_verified_signer_genesis_in_directory(
    directory: _OwnerOnlyArtifactDirectory,
    *,
    signer_genesis_name: str,
    genesis: SignerGenesisV1,
    issuer: _TrustedSigner,
    initial_intent: InitialProvisioningIntentV1,
) -> SignerGenesisV1:
    """Durably create and reverify signer genesis through one held root FD."""

    canonical_genesis = cast(
        SignerGenesisV1,
        _canonical_artifact(genesis, SignerGenesisV1, phase="signer_genesis"),
    )
    verify_signer_genesis(canonical_genesis, issuer=issuer, initial_intent=initial_intent)
    expected = _yaml_bytes(canonical_genesis)
    directory.write_once_or_require_exact(signer_genesis_name, expected)
    # ``write_once`` fsyncs both the file and containing descriptor.  The
    # reopen below is still mandatory: it proves that the durable name now
    # resolves to the exact signed bytes bound to this input.
    persisted_raw = directory.read(signer_genesis_name)
    if not hmac.compare_digest(persisted_raw, expected):
        raise ProviderCryptoError("signer_genesis")
    persisted = cast(
        SignerGenesisV1,
        _load_model(persisted_raw, SignerGenesisV1, phase="signer_genesis"),
    )
    persisted = cast(
        SignerGenesisV1,
        _canonical_artifact(persisted, SignerGenesisV1, phase="signer_genesis"),
    )
    verify_signer_genesis(persisted, issuer=issuer, initial_intent=initial_intent)
    if persisted != canonical_genesis:
        raise ProviderCryptoError("signer_genesis")
    return persisted


def _persist_verified_signer_genesis(
    paths: ProviderMaterialArtifactPaths,
    genesis: SignerGenesisV1,
    *,
    issuer: _TrustedSigner,
    initial_intent: InitialProvisioningIntentV1,
) -> SignerGenesisV1:
    """Durably create or prove one exact signer genesis before a SecItemAdd."""

    with _OwnerOnlyArtifactDirectory(paths.root) as directory:
        return _persist_verified_signer_genesis_in_directory(
            directory,
            signer_genesis_name=paths.signer_genesis_name(),
            genesis=genesis,
            issuer=issuer,
            initial_intent=initial_intent,
        )


def _require_persisted_signer_genesis_in_directory(
    directory: _OwnerOnlyArtifactDirectory,
    *,
    signer_genesis_name: str,
    genesis: SignerGenesisV1,
    issuer: _TrustedSigner,
    initial_intent: InitialProvisioningIntentV1,
) -> SignerGenesisV1:
    """Require an exact durable signer genesis through the held root FD."""

    # This helper is also reached by material readiness paths.  Reject an
    # unsupported TLS intent before the descriptor performs even a read so a
    # pre-populated artifact directory cannot make TLS look ready.
    initial_intent = _reject_unsupported_tls_termination(initial_intent)
    canonical_genesis = cast(
        SignerGenesisV1,
        _canonical_artifact(genesis, SignerGenesisV1, phase="signer_genesis"),
    )
    expected = _yaml_bytes(canonical_genesis)
    persisted_raw = directory.read(signer_genesis_name)
    if not hmac.compare_digest(persisted_raw, expected):
        raise ProviderCryptoError("signer_genesis")
    directory.fsync_existing(signer_genesis_name)
    persisted = cast(
        SignerGenesisV1,
        _load_model(persisted_raw, SignerGenesisV1, phase="signer_genesis"),
    )
    persisted = cast(
        SignerGenesisV1,
        _canonical_artifact(persisted, SignerGenesisV1, phase="signer_genesis"),
    )
    verify_signer_genesis(persisted, issuer=issuer, initial_intent=initial_intent)
    if persisted != canonical_genesis:
        raise ProviderCryptoError("signer_genesis")
    return persisted


def _require_persisted_signer_genesis(
    paths: ProviderMaterialArtifactPaths,
    genesis: SignerGenesisV1,
    *,
    issuer: _TrustedSigner,
    initial_intent: InitialProvisioningIntentV1,
) -> SignerGenesisV1:
    """Require an already durable, exact signer genesis before material writes."""

    with _OwnerOnlyArtifactDirectory(paths.root) as directory:
        return _require_persisted_signer_genesis_in_directory(
            directory,
            signer_genesis_name=paths.signer_genesis_name(),
            genesis=genesis,
            issuer=issuer,
            initial_intent=initial_intent,
        )


def persist_signer_genesis(
    paths: ProviderMaterialArtifactPaths,
    genesis: SignerGenesisV1,
    *,
    issuer: _TrustedSigner,
    initial_intent: InitialProvisioningIntentV1,
) -> None:
    """Persist one issuer-signed Keychain signer trust anchor without mutation."""

    initial_intent = _reject_unsupported_tls_termination(initial_intent)
    _persist_verified_signer_genesis(
        paths,
        genesis,
        issuer=issuer,
        initial_intent=initial_intent,
    )


def load_verified_signer_genesis(
    paths: ProviderMaterialArtifactPaths,
    *,
    issuer: _TrustedSigner,
    initial_intent: InitialProvisioningIntentV1,
) -> SignerGenesisV1:
    """Load a persisted signer genesis through the owner-only descriptor boundary."""

    initial_intent = _reject_unsupported_tls_termination(initial_intent)
    with _OwnerOnlyArtifactDirectory(paths.root) as directory:
        raw = directory.read(paths.signer_genesis_name())
        genesis = cast(
            SignerGenesisV1,
            _load_model(raw, SignerGenesisV1, phase="signer_genesis"),
        )
    genesis = cast(
        SignerGenesisV1,
        _canonical_artifact(genesis, SignerGenesisV1, phase="signer_genesis"),
    )
    if not hmac.compare_digest(raw, _yaml_bytes(genesis)):
        raise ProviderCryptoError("signer_genesis")
    verify_signer_genesis(genesis, issuer=issuer, initial_intent=initial_intent)
    return genesis


def _load_verified_signer_genesis_from_reader(
    reader: _ArtifactReader,
    *,
    issuer: _TrustedSigner,
    initial_intent: InitialProvisioningIntentV1,
) -> tuple[SignerGenesisV1, str]:
    """Load the trust anchor from an authorization-pinned root descriptor."""

    initial_intent = _reject_unsupported_tls_termination(initial_intent)
    try:
        raw = reader.read(_SIGNER_GENESIS_NAME)
    except Exception:
        raise ProviderCryptoError("signer_genesis") from None
    genesis = cast(
        SignerGenesisV1,
        _load_model(raw, SignerGenesisV1, phase="signer_genesis"),
    )
    genesis = cast(
        SignerGenesisV1,
        _canonical_artifact(genesis, SignerGenesisV1, phase="signer_genesis"),
    )
    if not hmac.compare_digest(raw, _yaml_bytes(genesis)):
        raise ProviderCryptoError("signer_genesis")
    verify_signer_genesis(genesis, issuer=issuer, initial_intent=initial_intent)
    return genesis, _sha256(raw)


def persist_provider_material_policy(
    paths: ProviderMaterialArtifactPaths,
    policy: ProviderMaterialPolicyV1,
    *,
    signer: _TrustedSigner,
    signer_genesis: SignerGenesisV1,
    issuer: _TrustedSigner,
    initial_intent: InitialProvisioningIntentV1,
    expected_disposal_owner: str,
    expected_approver_identity: str,
) -> None:
    """Persist a signed material policy once using the trusted UTC clock."""

    initial_intent = _reject_unsupported_tls_termination(initial_intent)
    policy = cast(
        ProviderMaterialPolicyV1,
        _canonical_artifact(policy, ProviderMaterialPolicyV1, phase="material_policy"),
    )
    signer_genesis = _require_persisted_signer_genesis(
        paths,
        signer_genesis,
        issuer=issuer,
        initial_intent=initial_intent,
    )
    _verify_provider_material_policy_at(
        policy,
        signer=signer,
        signer_genesis=signer_genesis,
        issuer=issuer,
        initial_intent=initial_intent,
        expected_disposal_owner=expected_disposal_owner,
        expected_approver_identity=expected_approver_identity,
        now=_system_utc_clock(),
    )
    with _OwnerOnlyArtifactDirectory(paths.root) as directory:
        directory.write_once(paths.policy_name(), _yaml_bytes(policy))


def persist_provider_material_genesis(
    paths: ProviderMaterialArtifactPaths,
    genesis: ProviderMaterialGenesisV1,
    *,
    policy: ProviderMaterialPolicyV1,
    attestation: ProviderFingerprintAttestationV1,
    signer: _TrustedSigner,
    signer_genesis: SignerGenesisV1,
    issuer: _TrustedSigner,
    initial_intent: InitialProvisioningIntentV1,
    expected_disposal_owner: str,
    expected_approver_identity: str,
) -> None:
    """Persist a signed pending manifest using the trusted UTC clock."""

    initial_intent = _reject_unsupported_tls_termination(initial_intent)
    policy = cast(
        ProviderMaterialPolicyV1,
        _canonical_artifact(policy, ProviderMaterialPolicyV1, phase="material_policy"),
    )
    genesis = cast(
        ProviderMaterialGenesisV1,
        _canonical_artifact(genesis, ProviderMaterialGenesisV1, phase="material_genesis"),
    )
    attestation = cast(
        ProviderFingerprintAttestationV1,
        _canonical_artifact(
            attestation,
            ProviderFingerprintAttestationV1,
            phase="fingerprint_attestation",
        ),
    )
    signer_genesis = _require_persisted_signer_genesis(
        paths,
        signer_genesis,
        issuer=issuer,
        initial_intent=initial_intent,
    )
    _verify_provider_material_bundle_at(
        policy,
        attestation,
        signer=signer,
        signer_genesis=signer_genesis,
        issuer=issuer,
        initial_intent=initial_intent,
        expected_disposal_owner=expected_disposal_owner,
        expected_approver_identity=expected_approver_identity,
        now=_system_utc_clock(),
    )
    verify_provider_material_genesis(
        genesis,
        policy=policy,
        attestation=attestation,
        signer=signer,
        signer_genesis=signer_genesis,
        issuer=issuer,
        initial_intent=initial_intent,
    )
    with _OwnerOnlyArtifactDirectory(paths.root) as directory:
        persisted_policy = cast(
            ProviderMaterialPolicyV1,
            _load_model(
                directory.read(paths.policy_name()),
                ProviderMaterialPolicyV1,
                phase="material_policy",
            ),
        )
        if (
            persisted_policy != policy
            or directory.read_optional(paths.attestation_name()) is not None
        ):
            raise ProviderCryptoError("material_genesis_state")
        directory.write_once(paths.genesis_name(), _yaml_bytes(genesis))


def _read_material_artifacts_from_directory(
    directory: _OwnerOnlyArtifactDirectory,
    *,
    policy_name: str,
    genesis_name: str,
    attestation_name: str,
) -> tuple[
    ProviderMaterialPolicyV1, ProviderMaterialGenesisV1, ProviderFingerprintAttestationV1 | None
]:
    """Read material state only through a caller-held artifact-root descriptor."""

    policy = cast(
        ProviderMaterialPolicyV1,
        _load_model(
            directory.read(policy_name),
            ProviderMaterialPolicyV1,
            phase="material_policy",
        ),
    )
    genesis = cast(
        ProviderMaterialGenesisV1,
        _load_model(
            directory.read(genesis_name),
            ProviderMaterialGenesisV1,
            phase="material_genesis",
        ),
    )
    raw_attestation = directory.read_optional(attestation_name)
    if raw_attestation is None:
        return policy, genesis, None
    attestation = cast(
        ProviderFingerprintAttestationV1,
        _load_model(
            raw_attestation, ProviderFingerprintAttestationV1, phase="fingerprint_attestation"
        ),
    )
    return policy, genesis, attestation


def _read_material_artifacts(
    paths: ProviderMaterialArtifactPaths,
) -> tuple[
    ProviderMaterialPolicyV1, ProviderMaterialGenesisV1, ProviderFingerprintAttestationV1 | None
]:
    with _OwnerOnlyArtifactDirectory(paths.root) as directory:
        return _read_material_artifacts_from_directory(
            directory,
            policy_name=paths.policy_name(),
            genesis_name=paths.genesis_name(),
            attestation_name=paths.attestation_name(),
        )


def provider_material_genesis_status(
    paths: ProviderMaterialArtifactPaths,
    *,
    _store: _KeychainTransport,
) -> ProviderMaterialGenesisStatus:
    """Classify a pending manifest without writing or retrying anything."""

    try:
        with _OwnerOnlyArtifactDirectory(paths.root) as directory:
            raw_signer_genesis = directory.read_optional(paths.signer_genesis_name())
            raw_policy = directory.read_optional(paths.policy_name())
            raw_genesis = directory.read_optional(paths.genesis_name())
            raw_attestation = directory.read_optional(paths.attestation_name())
    except ProviderCryptoError:
        return ProviderMaterialGenesisStatus.INVALID
    if (
        raw_signer_genesis is None
        and raw_policy is None
        and raw_genesis is None
        and raw_attestation is None
    ):
        return ProviderMaterialGenesisStatus.ABSENT
    if raw_signer_genesis is None or raw_policy is None or raw_genesis is None:
        return ProviderMaterialGenesisStatus.INVALID
    try:
        _load_model(raw_signer_genesis, SignerGenesisV1, phase="signer_genesis")
        policy = cast(
            ProviderMaterialPolicyV1,
            _load_model(raw_policy, ProviderMaterialPolicyV1, phase="material_policy"),
        )
        _load_model(raw_genesis, ProviderMaterialGenesisV1, phase="material_genesis")
        attestation = (
            None
            if raw_attestation is None
            else cast(
                ProviderFingerprintAttestationV1,
                _load_model(
                    raw_attestation,
                    ProviderFingerprintAttestationV1,
                    phase="fingerprint_attestation",
                ),
            )
        )
    except ProviderCryptoError:
        return ProviderMaterialGenesisStatus.INVALID
    existing: list[bool] = []
    try:
        for spec in policy.materials:
            value = _read_keychain_value(_store, spec.reference.service, spec.reference.account)
            if value is _TRANSPORT_FAILURE:
                return ProviderMaterialGenesisStatus.INVALID
            if type(value) is bytearray:
                _zeroize(value)
                existing.append(True)
            elif value is None:
                existing.append(False)
            else:
                return ProviderMaterialGenesisStatus.INVALID
    except Exception:
        return ProviderMaterialGenesisStatus.INVALID
    if attestation is not None:
        return (
            ProviderMaterialGenesisStatus.STRUCTURALLY_COMPLETE_UNVERIFIED
            if all(existing)
            else ProviderMaterialGenesisStatus.PARTIAL_OR_RECONCILIATION_REQUIRED
        )
    if not any(existing):
        return ProviderMaterialGenesisStatus.PENDING
    return ProviderMaterialGenesisStatus.PARTIAL_OR_RECONCILIATION_REQUIRED


def _provision_keychain_materials(
    paths: ProviderMaterialArtifactPaths,
    *,
    policy: ProviderMaterialPolicyV1,
    genesis: ProviderMaterialGenesisV1,
    attestation: ProviderFingerprintAttestationV1,
    signer: _TrustedSigner,
    signer_genesis: SignerGenesisV1,
    issuer: _TrustedSigner,
    initial_intent: InitialProvisioningIntentV1,
    expected_disposal_owner: str,
    expected_approver_identity: str,
    materials: Mapping[ProviderMaterialPurpose, bytearray],
    _store: _KeychainTransport | None = None,
) -> None:
    """Perform the one-way, create-only Keychain material write sequence.

    A matching signed pending manifest must already exist.  Any duplicate,
    missing item after a partial write, malformed value, or crash leaves the
    state blocked for signed operator reconciliation; this function never
    updates, deletes, or retries a material row.
    """

    supplied: dict[ProviderMaterialPurpose, bytearray] = {}
    material_mapping_failed = False
    try:
        supplied = dict(materials)
    except Exception:
        material_mapping_failed = True
    try:
        if material_mapping_failed or not all(
            type(purpose) is ProviderMaterialPurpose and type(value) is bytearray
            for purpose, value in supplied.items()
        ):
            raise ProviderCryptoError("material_values")
        initial_intent = _reject_unsupported_tls_termination(initial_intent)
        policy = cast(
            ProviderMaterialPolicyV1,
            _canonical_artifact(policy, ProviderMaterialPolicyV1, phase="material_policy"),
        )
        genesis = cast(
            ProviderMaterialGenesisV1,
            _canonical_artifact(genesis, ProviderMaterialGenesisV1, phase="material_genesis"),
        )
        attestation = cast(
            ProviderFingerprintAttestationV1,
            _canonical_artifact(
                attestation,
                ProviderFingerprintAttestationV1,
                phase="fingerprint_attestation",
            ),
        )
        with _OwnerOnlyArtifactDirectory(paths.root) as directory:
            # Hold one descriptor-relative root for every revalidation and
            # every create-only Keychain write.  A root rename/replacement
            # cannot select a different signer genesis between checks.
            signer_genesis = _require_persisted_signer_genesis_in_directory(
                directory,
                signer_genesis_name=paths.signer_genesis_name(),
                genesis=signer_genesis,
                issuer=issuer,
                initial_intent=initial_intent,
            )
            now = _system_utc_clock()
            _verify_provider_material_bundle_at(
                policy,
                attestation,
                signer=signer,
                signer_genesis=signer_genesis,
                issuer=issuer,
                initial_intent=initial_intent,
                expected_disposal_owner=expected_disposal_owner,
                expected_approver_identity=expected_approver_identity,
                now=now,
            )
            verify_provider_material_genesis(
                genesis,
                policy=policy,
                attestation=attestation,
                signer=signer,
                signer_genesis=signer_genesis,
                issuer=issuer,
                initial_intent=initial_intent,
            )
            if set(supplied) != {spec.purpose for spec in policy.materials}:
                raise ProviderCryptoError("material_values")
            if any(spec.reference.provider != "macos_keychain" for spec in policy.materials):
                raise ProviderCryptoError("material_provider")
            persisted_policy, persisted_genesis, persisted_attestation = (
                _read_material_artifacts_from_directory(
                    directory,
                    policy_name=paths.policy_name(),
                    genesis_name=paths.genesis_name(),
                    attestation_name=paths.attestation_name(),
                )
            )
            if (
                persisted_policy != policy
                or persisted_genesis != genesis
                or persisted_attestation is not None
            ):
                raise ProviderCryptoError("material_genesis_state")
            store = _default_keychain_store() if _store is None else _store
            expected_fingerprints = attestation.fingerprint_by_reference()
            for spec in policy.materials:
                # Reopen and verify the durable signer immediately before each
                # irreversible ``SecItemAdd``.  This rejects a same-owner
                # artifact replacement rather than using stale in-memory
                # signer authority.
                _require_persisted_signer_genesis_in_directory(
                    directory,
                    signer_genesis_name=paths.signer_genesis_name(),
                    genesis=signer_genesis,
                    issuer=issuer,
                    initial_intent=initial_intent,
                )
                current_policy, current_genesis, current_attestation = (
                    _read_material_artifacts_from_directory(
                        directory,
                        policy_name=paths.policy_name(),
                        genesis_name=paths.genesis_name(),
                        attestation_name=paths.attestation_name(),
                    )
                )
                if (
                    current_policy != policy
                    or current_genesis != genesis
                    or current_attestation is not None
                ):
                    raise ProviderCryptoError("material_genesis_state")
                value = supplied[spec.purpose]
                _validate_value(spec, value)
                fingerprint = _sha256(value)
                expected_fingerprint = expected_fingerprints.get(spec.reference.reference_sha256)
                if expected_fingerprint is None or not hmac.compare_digest(
                    fingerprint, expected_fingerprint
                ):
                    raise ProviderCryptoError("material_fingerprint")
                with directory.pin_exact_signer_genesis(
                    paths.signer_genesis_name(),
                    _yaml_bytes(signer_genesis),
                ):
                    created = _create_keychain_value(
                        store, spec.reference.service, spec.reference.account, value
                    )
                if type(created) is not bool:
                    raise ProviderCryptoError("material_provider")
                if not created:
                    raise ProviderCryptoError("material_duplicate_or_partial")
            terminal_policy, terminal_genesis, terminal_attestation = (
                _read_material_artifacts_from_directory(
                    directory,
                    policy_name=paths.policy_name(),
                    genesis_name=paths.genesis_name(),
                    attestation_name=paths.attestation_name(),
                )
            )
            if (
                terminal_policy != policy
                or terminal_genesis != genesis
                or terminal_attestation is not None
            ):
                raise ProviderCryptoError("material_genesis_state")
            directory.write_once(paths.attestation_name(), _yaml_bytes(attestation))
    finally:
        for value in supplied.values():
            _zeroize(value)


def provision_keychain_materials(
    paths: ProviderMaterialArtifactPaths,
    *,
    policy: ProviderMaterialPolicyV1,
    genesis: ProviderMaterialGenesisV1,
    attestation: ProviderFingerprintAttestationV1,
    signer: _TrustedSigner,
    signer_genesis: SignerGenesisV1,
    issuer: _TrustedSigner,
    initial_intent: InitialProvisioningIntentV1,
    expected_disposal_owner: str,
    expected_approver_identity: str,
    materials: Mapping[ProviderMaterialPurpose, bytearray],
    _store: _KeychainTransport | None = None,
) -> None:
    """Create material rows only once using the trusted production UTC clock."""

    _provision_keychain_materials(
        paths,
        policy=policy,
        genesis=genesis,
        attestation=attestation,
        signer=signer,
        signer_genesis=signer_genesis,
        issuer=issuer,
        initial_intent=initial_intent,
        expected_disposal_owner=expected_disposal_owner,
        expected_approver_identity=expected_approver_identity,
        materials=materials,
        _store=_store,
    )


def _load_verified_provider_material_bundle_at(
    paths: ProviderMaterialArtifactPaths,
    *,
    signer: _TrustedSigner,
    signer_genesis: SignerGenesisV1,
    issuer: _TrustedSigner,
    initial_intent: InitialProvisioningIntentV1,
    expected_disposal_owner: str,
    expected_approver_identity: str,
    now: datetime,
) -> tuple[ProviderMaterialPolicyV1, ProviderMaterialGenesisV1, ProviderFingerprintAttestationV1]:
    """Load and verify only completed material artifacts through one root fd."""

    initial_intent = _reject_unsupported_tls_termination(initial_intent)
    policy, genesis, attestation = _read_material_artifacts(paths)
    if attestation is None:
        raise ProviderCryptoError("material_genesis_pending")
    _verify_provider_material_bundle_at(
        policy,
        attestation,
        signer=signer,
        signer_genesis=signer_genesis,
        issuer=issuer,
        initial_intent=initial_intent,
        expected_disposal_owner=expected_disposal_owner,
        expected_approver_identity=expected_approver_identity,
        now=now,
    )
    verify_provider_material_genesis(
        genesis,
        policy=policy,
        attestation=attestation,
        signer=signer,
        signer_genesis=signer_genesis,
        issuer=issuer,
        initial_intent=initial_intent,
    )
    return policy, genesis, attestation


def load_verified_provider_material_bundle(
    paths: ProviderMaterialArtifactPaths,
    *,
    signer: _TrustedSigner,
    signer_genesis: SignerGenesisV1,
    issuer: _TrustedSigner,
    initial_intent: InitialProvisioningIntentV1,
    expected_disposal_owner: str,
    expected_approver_identity: str,
) -> tuple[ProviderMaterialPolicyV1, ProviderMaterialGenesisV1, ProviderFingerprintAttestationV1]:
    """Load only a cryptographically verified terminal material state."""

    initial_intent = _reject_unsupported_tls_termination(initial_intent)
    signer_genesis = _require_persisted_signer_genesis(
        paths,
        signer_genesis,
        issuer=issuer,
        initial_intent=initial_intent,
    )
    return _load_verified_provider_material_bundle_at(
        paths,
        signer=signer,
        signer_genesis=signer_genesis,
        issuer=issuer,
        initial_intent=initial_intent,
        expected_disposal_owner=expected_disposal_owner,
        expected_approver_identity=expected_approver_identity,
        now=_system_utc_clock(),
    )


def _load_verified_provider_material_bundle_from_reader_at(
    reader: _ArtifactReader,
    *,
    signer: _TrustedSigner,
    signer_genesis: SignerGenesisV1,
    issuer: _TrustedSigner,
    initial_intent: InitialProvisioningIntentV1,
    expected_disposal_owner: str,
    expected_approver_identity: str,
    now: datetime,
) -> tuple[
    ProviderMaterialPolicyV1,
    ProviderMaterialGenesisV1,
    ProviderFingerprintAttestationV1,
    tuple[str, str, str],
]:
    """Verify terminal artifacts from an authorization-pinned directory FD.

    Authorization uses this internal helper rather than reopening the root by
    path, then compares the returned raw-file hashes at each snapshot. The
    terminal fingerprint-attestation artifact is the durable completion marker;
    a manually populated provider without these three artifacts cannot enter an
    effect path.
    """

    initial_intent = _reject_unsupported_tls_termination(initial_intent)
    try:
        raw_signer_genesis = reader.read(_SIGNER_GENESIS_NAME)
        raw_policy = reader.read(_MATERIAL_POLICY_NAME)
        raw_genesis = reader.read(_MATERIAL_GENESIS_NAME)
        raw_attestation = reader.read(_FINGERPRINT_ATTESTATION_NAME)
    except Exception:
        raise ProviderCryptoError("material_artifact") from None
    persisted_signer_genesis = cast(
        SignerGenesisV1,
        _load_model(raw_signer_genesis, SignerGenesisV1, phase="signer_genesis"),
    )
    persisted_signer_genesis = cast(
        SignerGenesisV1,
        _canonical_artifact(
            persisted_signer_genesis,
            SignerGenesisV1,
            phase="signer_genesis",
        ),
    )
    if not hmac.compare_digest(raw_signer_genesis, _yaml_bytes(persisted_signer_genesis)):
        raise ProviderCryptoError("signer_genesis")
    verify_signer_genesis(
        persisted_signer_genesis,
        issuer=issuer,
        initial_intent=initial_intent,
    )
    signer_genesis = cast(
        SignerGenesisV1,
        _canonical_artifact(signer_genesis, SignerGenesisV1, phase="signer_genesis"),
    )
    if persisted_signer_genesis != signer_genesis:
        raise ProviderCryptoError("signer_genesis")
    policy = cast(
        ProviderMaterialPolicyV1,
        _load_model(raw_policy, ProviderMaterialPolicyV1, phase="material_policy"),
    )
    genesis = cast(
        ProviderMaterialGenesisV1,
        _load_model(raw_genesis, ProviderMaterialGenesisV1, phase="material_genesis"),
    )
    attestation = cast(
        ProviderFingerprintAttestationV1,
        _load_model(
            raw_attestation,
            ProviderFingerprintAttestationV1,
            phase="fingerprint_attestation",
        ),
    )
    _verify_provider_material_bundle_at(
        policy,
        attestation,
        signer=signer,
        signer_genesis=signer_genesis,
        issuer=issuer,
        initial_intent=initial_intent,
        expected_disposal_owner=expected_disposal_owner,
        expected_approver_identity=expected_approver_identity,
        now=now,
    )
    verify_provider_material_genesis(
        genesis,
        policy=policy,
        attestation=attestation,
        signer=signer,
        signer_genesis=signer_genesis,
        issuer=issuer,
        initial_intent=initial_intent,
    )
    return (
        policy,
        genesis,
        attestation,
        (
            _sha256(raw_policy),
            _sha256(raw_genesis),
            _sha256(raw_attestation),
        ),
    )


__all__: Sequence[str] = (
    "KeychainEd25519Signer",
    "KeychainItemReferenceV1",
    "KeychainProviderProvenance",
    "MacOSKeychainProviderProvenanceAdapter",
    "ProviderCryptoError",
    "ProviderFingerprintAttestationV1",
    "ProviderMaterialArtifactPaths",
    "ProviderMaterialFingerprintV1",
    "ProviderMaterialFormat",
    "ProviderMaterialGenesisStatus",
    "ProviderMaterialGenesisV1",
    "ProviderMaterialPolicyV1",
    "ProviderMaterialPurpose",
    "ProviderMaterialSpecV1",
    "ReplayAuthorityPolicyArtifactV1",
    "SignerGenesisV1",
    "load_keychain_ed25519_signer",
    "load_verified_provider_material_bundle",
    "load_verified_signer_genesis",
    "persist_provider_material_genesis",
    "persist_provider_material_policy",
    "persist_replay_authority_policy_artifact",
    "persist_signer_genesis",
    "provider_fingerprint_attestation_message",
    "provider_material_genesis_message",
    "provider_material_genesis_status",
    "provider_material_policy_message",
    "provision_keychain_ed25519_signer",
    "provision_keychain_materials",
    "replay_authority_policy_message",
    "replay_authority_policy_sha256",
    "signer_genesis_message",
    "trusted_signer_from_genesis",
    "verify_provider_fingerprint_attestation",
    "verify_provider_material_bundle",
    "verify_provider_material_genesis",
    "verify_provider_material_policy",
    "verify_replay_authority_policy_artifact",
    "verify_signer_genesis",
)
