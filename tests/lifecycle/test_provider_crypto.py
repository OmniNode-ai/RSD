"""Adversarial tests for public provider-crypto bootstrap primitives."""

from __future__ import annotations

import base64
import hashlib
import json

import pytest

from omninode_rsd.lifecycle.infisical_disposable import ProviderReferenceV1
from omninode_rsd.lifecycle.provider_crypto import (
    KeychainItemReferenceV1,
    MacOSKeychainProviderProvenanceAdapter,
    ProviderCryptoError,
    ProviderMaterialFormat,
    ProviderMaterialPolicyV1,
    ProviderMaterialPurpose,
    ProviderMaterialSpecV1,
)


def _sha256(value: bytes) -> str:
    return hashlib.sha256(value).hexdigest()


def _reference(name: str, version: int = 1) -> ProviderReferenceV1:
    fields = {
        "account": f"account-{name}.v{version}",
        "provider": "macos_keychain",
        "service": f"service-{name}",
        "version": version,
    }
    return ProviderReferenceV1(
        **fields,
        reference_sha256=_sha256(
            json.dumps(fields, sort_keys=True, separators=(",", ":")).encode()
        ),
    )


def _policy() -> ProviderMaterialPolicyV1:
    definitions: tuple[
        tuple[ProviderMaterialPurpose, ProviderMaterialFormat, int, int, ProviderReferenceV1], ...
    ] = (
        (
            ProviderMaterialPurpose.COMMITMENT_HMAC,
            ProviderMaterialFormat.HMAC_SHA256_RAW_32_V1,
            32,
            32,
            _reference("commitment"),
        ),
        (
            ProviderMaterialPurpose.BACKUP_ENCRYPTION,
            ProviderMaterialFormat.AES_256_GCM_RAW_32_V1,
            32,
            32,
            _reference("backup"),
        ),
        (
            ProviderMaterialPurpose.INFISICAL_ENCRYPTION_KEY,
            ProviderMaterialFormat.INFISICAL_HEX_16_V1,
            32,
            32,
            _reference("encryption"),
        ),
        (
            ProviderMaterialPurpose.INFISICAL_AUTH_SECRET,
            ProviderMaterialFormat.INFISICAL_AUTH_SECRET_BASE64_32_V1,
            44,
            44,
            _reference("auth"),
        ),
        (
            ProviderMaterialPurpose.PRIMARY_VALKEY_PASSWORD,
            ProviderMaterialFormat.VALKEY_PASSWORD_BASE64URL_32_V1,
            43,
            43,
            _reference("primary"),
        ),
        (
            ProviderMaterialPurpose.RESTORE_VALKEY_PASSWORD,
            ProviderMaterialFormat.VALKEY_PASSWORD_BASE64URL_32_V1,
            43,
            43,
            _reference("restore"),
        ),
    )
    signer_fields = {
        "account": "account-provider-signer.v1",
        "provider": "macos_keychain",
        "service": "service-provider-signer",
        "version": 1,
    }
    return ProviderMaterialPolicyV1(
        schema_version="rsd.provider-crypto.material-policy.v1",
        initial_intent_sha256="a" * 64,
        disposal_owner="owner",
        approver_identity="approver",
        policy_id="123e4567-e89b-42d3-a456-426614174011",
        signer_keychain_reference=KeychainItemReferenceV1(
            **signer_fields,
            reference_sha256=_sha256(
                json.dumps(signer_fields, sort_keys=True, separators=(",", ":")).encode()
            ),
        ),
        signer_seed_fingerprint_sha256="f" * 64,
        created_at="2026-08-27T12:00:00Z",
        retention_expires_at="2026-08-27T12:10:00Z",
        materials=tuple(
            ProviderMaterialSpecV1(
                purpose=purpose,
                reference=reference,
                format=material_format,
                value_min_bytes=minimum,
                value_max_bytes=maximum,
            )
            for purpose, material_format, minimum, maximum, reference in definitions
        ),
        signer_key_id="test-signer",
        signature_base64=base64.b64encode(b"0" * 64).decode(),
    )


def _values(policy: ProviderMaterialPolicyV1) -> dict[str, bytes]:
    values = (
        b"c" * 32,
        b"b" * 32,
        b"0123456789abcdef0123456789abcdef",
        base64.b64encode(b"a" * 32),
        base64.urlsafe_b64encode(b"p" * 32).rstrip(b"="),
        base64.urlsafe_b64encode(b"r" * 32).rstrip(b"="),
    )
    return {
        spec.reference.reference_sha256: value
        for spec, value in zip(policy.materials, values, strict=True)
    }


class _Store:
    def __init__(self) -> None:
        self.records: dict[tuple[str, str], bytes] = {}
        self.add_calls: list[tuple[str, str]] = []

    def add_if_absent(self, service: str, account: str, value: bytearray) -> bool:
        self.add_calls.append((service, account))
        key = (service, account)
        if key in self.records:
            return False
        self.records[key] = bytes(value)
        return True

    def read_if_present(self, service: str, account: str) -> bytearray | None:
        stored = self.records.get((service, account))
        return None if stored is None else bytearray(stored)


def test_keychain_provenance_adapter_exposes_no_material_value() -> None:
    policy = _policy()
    values = _values(policy)
    store = _Store()
    for spec in policy.materials:
        store.records[(spec.reference.service, spec.reference.account)] = values[
            spec.reference.reference_sha256
        ]

    adapter = MacOSKeychainProviderProvenanceAdapter(policy, _store=store)
    references = tuple(spec.reference for spec in policy.materials)
    with adapter.acquire(references) as lease:
        provenances = tuple(lease.inspect(reference) for reference in references)
        assert tuple(lease.recheck(reference) for reference in references) == provenances

    assert all(item is not None for item in provenances)
    for provenance in provenances:
        assert provenance is not None
        assert not hasattr(provenance, "value")
        assert provenance.fingerprint_sha256 == _sha256(values[provenance.reference_sha256])


def test_keychain_provenance_rejects_malformed_value_without_leaking_it() -> None:
    policy = _policy()
    values = _values(policy)
    target = policy.materials[2]
    malformed = values[target.reference.reference_sha256] + b"!"
    store = _Store()
    for spec in policy.materials:
        value = malformed if spec == target else values[spec.reference.reference_sha256]
        store.records[(spec.reference.service, spec.reference.account)] = value

    adapter = MacOSKeychainProviderProvenanceAdapter(policy, _store=store)
    with (
        adapter.acquire(tuple(spec.reference for spec in policy.materials)) as lease,
        pytest.raises(ProviderCryptoError, match="material_format") as caught,
    ):
        lease.inspect(target.reference)

    error = caught.value
    assert malformed.decode("ascii") not in str(error)
    assert error.__cause__ is None
    assert error.__context__ is None


def test_material_policy_rejects_duplicate_purpose_and_reference() -> None:
    policy = _policy()
    raw = policy.model_dump(mode="python")
    materials = list(raw["materials"])
    materials[1] = materials[0]
    raw["materials"] = tuple(materials)

    with pytest.raises(ValueError, match="provider material policy fields"):
        ProviderMaterialPolicyV1.model_validate(raw)


def test_material_policy_rejects_reusing_the_signer_keychain_item() -> None:
    policy = _policy()
    raw = policy.model_dump(mode="python")
    materials = list(raw["materials"])
    materials[0] = {
        **materials[0],
        "reference": raw["signer_keychain_reference"],
    }
    raw["materials"] = tuple(materials)

    with pytest.raises(ValueError, match="provider material policy fields"):
        ProviderMaterialPolicyV1.model_validate(raw)


@pytest.mark.parametrize(
    ("purpose", "alphabet", "last_offset"),
    (
        (
            ProviderMaterialPurpose.INFISICAL_AUTH_SECRET,
            b"ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/",
            -2,
        ),
        (
            ProviderMaterialPurpose.PRIMARY_VALKEY_PASSWORD,
            b"ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789-_",
            -1,
        ),
    ),
)
def test_keychain_provenance_rejects_noncanonical_trailing_bit_aliases(
    purpose: ProviderMaterialPurpose,
    alphabet: bytes,
    last_offset: int,
) -> None:
    policy = _policy()
    values = _values(policy)
    target = next(spec for spec in policy.materials if spec.purpose is purpose)
    alias = bytearray(values[target.reference.reference_sha256])
    position = len(alias) + last_offset
    index = alphabet.index(alias[position])
    alias[position] = alphabet[(index & ~0b11) | ((index + 1) & 0b11)]
    store = _Store()
    for spec in policy.materials:
        value = alias if spec is target else values[spec.reference.reference_sha256]
        store.records[(spec.reference.service, spec.reference.account)] = bytes(value)

    adapter = MacOSKeychainProviderProvenanceAdapter(policy, _store=store)
    with (
        pytest.raises(ProviderCryptoError, match="material_format"),
        adapter.acquire(tuple(spec.reference for spec in policy.materials)) as lease,
    ):
        lease.inspect(target.reference)


def test_keychain_reference_requires_an_immutable_versioned_account_name() -> None:
    fields = {
        "account": "account-without-version",
        "provider": "macos_keychain",
        "service": "service-versioned",
        "version": 1,
    }
    with pytest.raises(ValueError, match="keychain reference does not bind metadata"):
        KeychainItemReferenceV1(
            **fields,
            reference_sha256=_sha256(
                json.dumps(fields, sort_keys=True, separators=(",", ":")).encode()
            ),
        )
