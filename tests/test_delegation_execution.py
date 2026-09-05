from __future__ import annotations

import base64
import json
from datetime import UTC, datetime, timedelta, timezone
from hashlib import sha256
from typing import Literal
from uuid import UUID, uuid4

import pytest
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey
from omninode_grant_verifier import signed_executable_grant_v2_vectors

from omninode_rsd.delegation import (
    AtomicClaimPort,
    ClaimDisposition,
    DelegatedGrantClaim,
    DelegatedRequest,
    DelegatedRequestIngress,
    DelegationSubmissionState,
    PublicGrantVerifierAdapter,
    VerifiedGrantFacts,
    load_canonical_delegation_overlay,
)
from omninode_rsd.delegation_execution import (
    DelegationExecutionError,
    DelegationExecutionOverlayV1,
    DelegationExecutionParseError,
    DelegationExecutionSignatureError,
    DelegationExecutionTrustAnchorV1,
    canonical_delegation_execution_overlay_json_bytes,
    canonical_delegation_execution_overlay_yaml_bytes,
    canonical_disabled_delegation_overlay_sha256,
    delegation_execution_activation_sha256,
    delegation_execution_overlay_message,
    parse_delegation_execution_overlay,
    verify_delegation_execution_overlay,
)
from omninode_rsd.lifecycle import InMemoryEventLog, LifecycleEventIngress

_NOW = datetime(2030, 1, 1, tzinfo=UTC)
_ACTIVATION_SCHEMA: Literal["rsd.delegation-execution-activation.v1"] = (
    "rsd.delegation-execution-activation.v1"
)


class _UnusedClaim(AtomicClaimPort):
    def claim(self, claim: DelegatedGrantClaim) -> ClaimDisposition:
        raise AssertionError(f"disabled ingress invoked claim: {claim}")


class _UnusedDispatch:
    def dispatch(self, claim: DelegatedGrantClaim) -> None:
        raise AssertionError(f"disabled ingress invoked dispatch: {claim}")


def _facts() -> VerifiedGrantFacts:
    vector = signed_executable_grant_v2_vectors()["base_wire"]
    assert type(vector) is dict
    wire = json.dumps(vector, separators=(",", ":")).encode("utf-8")
    return PublicGrantVerifierAdapter(trusted_clock=lambda: _NOW)(wire)


def _claim() -> DelegatedGrantClaim:
    policy = load_canonical_delegation_overlay()
    base_facts = _facts()
    facts = base_facts.model_copy(update={"model_id": policy.model_ref})
    request = DelegatedRequest(
        run_id=facts.correlation_id,
        request_sha256=facts.request_sha256,
        artifact_sha256=facts.artifact_sha256,
        rendered_contract_sha256=facts.rendered_contract_sha256,
        tenant_id=facts.tenant_id,
        backend_id=facts.backend_id,
        model_id=facts.model_id,
        route_ref=policy.route_ref,
        expected_output_topic=facts.expected_output_topic,
        expected_output_event_class=facts.expected_output_event_class,
        expected_output_event_index=facts.expected_output_event_index,
    )
    return DelegatedGrantClaim(request=request, grant=facts, policy=policy)


def _anchor(private_key: Ed25519PrivateKey) -> DelegationExecutionTrustAnchorV1:
    public_key = private_key.public_key().public_bytes_raw()
    return DelegationExecutionTrustAnchorV1(
        schema_version="rsd.delegation-execution-trust-anchor.v1",
        signer_key_id="execution-authority",
        signer_public_key_base64=base64.b64encode(public_key).decode("ascii"),
        signer_key_fingerprint_sha256=sha256(public_key).hexdigest(),
    )


def _unsigned_activation(
    claim: DelegatedGrantClaim,
    *,
    issued_at: datetime = _NOW,
    expires_at: datetime = _NOW + timedelta(seconds=30),
) -> DelegationExecutionOverlayV1:
    activation_id = claim.grant.activation_id
    return DelegationExecutionOverlayV1(
        schema_version="rsd.delegation-execution-overlay.v1",
        execute_enabled=True,
        authorization_digest=claim.grant.authorization_digest,
        request_envelope_sha256=claim.request.request_sha256,
        backend_id=claim.request.backend_id,
        model_id=claim.request.model_id,
        route_ref=claim.request.route_ref,
        disabled_overlay_sha256=canonical_disabled_delegation_overlay_sha256(),
        activation_id=activation_id,
        activation_schema_version=_ACTIVATION_SCHEMA,
        activation_version=1,
        activation_sha256=delegation_execution_activation_sha256(
            activation_id=activation_id,
            activation_schema_version=_ACTIVATION_SCHEMA,
            activation_version=1,
        ),
        issued_at=issued_at,
        expires_at=expires_at,
        endpoint_ref="logical://endpoint/provider-alpha",
        credential_ref="logical://credential/provider-alpha-v1",
        signer_key_id="execution-authority",
        signer_key_fingerprint_sha256="0" * 64,
        signature_base64=base64.b64encode(b"\0" * 64).decode("ascii"),
    )


def _signed_activation(
    claim: DelegatedGrantClaim,
    private_key: Ed25519PrivateKey,
    **updates: object,
) -> DelegationExecutionOverlayV1:
    unsigned = _unsigned_activation(claim).model_copy(update=updates)
    signature = private_key.sign(delegation_execution_overlay_message(unsigned))
    return unsigned.model_copy(
        update={"signature_base64": base64.b64encode(signature).decode("ascii")}
    )


def _verified(
    raw: bytes,
    claim: DelegatedGrantClaim,
    anchor: DelegationExecutionTrustAnchorV1,
) -> DelegationExecutionOverlayV1:
    return verify_delegation_execution_overlay(
        raw,
        claim=claim,
        trust_anchor=anchor,
        trusted_clock=lambda: _NOW,
    )


def test_valid_json_activation_binds_every_execution_fact() -> None:
    claim = _claim()
    private_key = Ed25519PrivateKey.generate()
    anchor = _anchor(private_key)
    activation = _signed_activation(
        claim,
        private_key,
        signer_key_fingerprint_sha256=anchor.signer_key_fingerprint_sha256,
    )

    result = _verified(canonical_delegation_execution_overlay_json_bytes(activation), claim, anchor)

    assert result == activation
    assert result.execute_enabled is True
    assert result.authorization_digest == claim.grant.authorization_digest
    assert result.request_envelope_sha256 == claim.request.request_sha256
    assert result.activation_id == claim.grant.activation_id
    assert result.endpoint_ref.startswith("logical://")
    assert result.credential_ref.startswith("logical://")


def test_canonical_yaml_round_trip_is_deterministic() -> None:
    claim = _claim()
    private_key = Ed25519PrivateKey.generate()
    anchor = _anchor(private_key)
    activation = _signed_activation(
        claim,
        private_key,
        signer_key_fingerprint_sha256=anchor.signer_key_fingerprint_sha256,
    )
    raw = canonical_delegation_execution_overlay_yaml_bytes(activation)

    assert raw == canonical_delegation_execution_overlay_yaml_bytes(activation)
    assert parse_delegation_execution_overlay(raw) == activation
    assert _verified(raw, claim, anchor) == activation


def test_packaged_disabled_overlay_and_old_ingress_remain_non_bypassable() -> None:
    claim = _claim()
    assert load_canonical_delegation_overlay().execute_enabled is False

    result = DelegatedRequestIngress(
        trusted_clock=lambda: _NOW,
        claim_port=_UnusedClaim(),
        dispatch_port=_UnusedDispatch(),
        event_log=InMemoryEventLog(),
        event_ingress=LifecycleEventIngress(),
    ).submit(claim.request, b"activation-is-not-an-ingress-substitution")

    assert result.state is DelegationSubmissionState.REJECTED_NOT_CLAIMED


@pytest.mark.parametrize(
    ("field", "value"),
    [
        ("authorization_digest", "0" * 64),
        ("request_envelope_sha256", "0" * 64),
        ("backend_id", "provider-beta"),
        ("model_id", "different/model-v1"),
        ("route_ref", "logical://route/other"),
        ("disabled_overlay_sha256", "0" * 64),
        ("signer_key_id", "other-authority"),
    ],
)
def test_binding_or_reference_mismatch_fails_closed(field: str, value: object) -> None:
    claim = _claim()
    private_key = Ed25519PrivateKey.generate()
    anchor = _anchor(private_key)
    updates: dict[str, object] = {
        "signer_key_fingerprint_sha256": anchor.signer_key_fingerprint_sha256
    }
    updates[field] = value
    activation = _signed_activation(claim, private_key, **updates)

    with pytest.raises(DelegationExecutionError):
        _verified(canonical_delegation_execution_overlay_json_bytes(activation), claim, anchor)


def test_activation_identity_mismatch_fails_closed() -> None:
    claim = _claim()
    private_key = Ed25519PrivateKey.generate()
    anchor = _anchor(private_key)
    activation_id = uuid4()
    activation = _signed_activation(
        claim,
        private_key,
        activation_id=activation_id,
        activation_sha256=delegation_execution_activation_sha256(
            activation_id=activation_id,
            activation_schema_version=_ACTIVATION_SCHEMA,
            activation_version=1,
        ),
        signer_key_fingerprint_sha256=anchor.signer_key_fingerprint_sha256,
    )

    with pytest.raises(DelegationExecutionError):
        _verified(canonical_delegation_execution_overlay_json_bytes(activation), claim, anchor)


@pytest.mark.parametrize(
    "issued_at,expires_at",
    [
        (_NOW + timedelta(seconds=1), _NOW + timedelta(seconds=30)),
        (_NOW - timedelta(minutes=2), _NOW - timedelta(seconds=1)),
        (_NOW - timedelta(seconds=1), _NOW + timedelta(minutes=6)),
    ],
)
def test_expiry_and_lifetime_are_bounded(issued_at: datetime, expires_at: datetime) -> None:
    claim = _claim()
    private_key = Ed25519PrivateKey.generate()
    anchor = _anchor(private_key)
    activation = _signed_activation(
        claim,
        private_key,
        issued_at=issued_at,
        expires_at=expires_at,
        signer_key_fingerprint_sha256=anchor.signer_key_fingerprint_sha256,
    )

    with pytest.raises(DelegationExecutionError):
        _verified(canonical_delegation_execution_overlay_json_bytes(activation), claim, anchor)


def test_signature_and_trust_anchor_mismatch_fail_closed() -> None:
    claim = _claim()
    private_key = Ed25519PrivateKey.generate()
    wrong_key = Ed25519PrivateKey.generate()
    anchor = _anchor(private_key)
    activation = _signed_activation(
        claim,
        wrong_key,
        signer_key_fingerprint_sha256=anchor.signer_key_fingerprint_sha256,
    )

    with pytest.raises(DelegationExecutionSignatureError):
        _verified(canonical_delegation_execution_overlay_json_bytes(activation), claim, anchor)

    wrong_anchor = anchor.model_copy(update={"signer_key_fingerprint_sha256": "0" * 64})
    with pytest.raises(DelegationExecutionError):
        _verified(
            canonical_delegation_execution_overlay_json_bytes(activation), claim, wrong_anchor
        )


def test_endpoint_and_credential_references_are_signature_bound() -> None:
    claim = _claim()
    private_key = Ed25519PrivateKey.generate()
    anchor = _anchor(private_key)
    activation = _signed_activation(
        claim,
        private_key,
        signer_key_fingerprint_sha256=anchor.signer_key_fingerprint_sha256,
    )
    raw = canonical_delegation_execution_overlay_json_bytes(activation)
    tampered = raw.replace(
        b"logical://endpoint/provider-alpha", b"logical://endpoint/provider-beta"
    )
    tampered = tampered.replace(
        b"logical://credential/provider-alpha-v1", b"logical://credential/provider-beta-v1"
    )

    with pytest.raises(DelegationExecutionSignatureError):
        _verified(tampered, claim, anchor)


def test_invalid_endpoint_and_credential_references_are_rejected() -> None:
    claim = _claim()
    private_key = Ed25519PrivateKey.generate()
    anchor = _anchor(private_key)
    activation = _signed_activation(
        claim,
        private_key,
        signer_key_fingerprint_sha256=anchor.signer_key_fingerprint_sha256,
    )
    raw = canonical_delegation_execution_overlay_json_bytes(activation)

    for marker, replacement in (
        (b"logical://endpoint/provider-alpha", b"provider://endpoint"),
        (b"logical://credential/provider-alpha-v1", b"secret-value"),
    ):
        with pytest.raises(DelegationExecutionParseError):
            parse_delegation_execution_overlay(raw.replace(marker, replacement))


def test_unknown_duplicate_and_noncanonical_input_is_rejected() -> None:
    claim = _claim()
    private_key = Ed25519PrivateKey.generate()
    anchor = _anchor(private_key)
    activation = _signed_activation(
        claim,
        private_key,
        signer_key_fingerprint_sha256=anchor.signer_key_fingerprint_sha256,
    )
    raw = canonical_delegation_execution_overlay_json_bytes(activation)
    value = json.loads(raw)

    unknown = json.dumps({**value, "unknown": "reject"}, separators=(",", ":")).encode("ascii")
    with pytest.raises(DelegationExecutionParseError):
        parse_delegation_execution_overlay(unknown)
    with pytest.raises(DelegationExecutionParseError):
        parse_delegation_execution_overlay(raw + b" ")

    duplicate = raw.replace(b'"schema_version":', b'"schema_version":"other", "schema_version":', 1)
    with pytest.raises(DelegationExecutionParseError):
        parse_delegation_execution_overlay(duplicate)

    yaml_raw = canonical_delegation_execution_overlay_yaml_bytes(activation)
    with pytest.raises(DelegationExecutionParseError):
        parse_delegation_execution_overlay(yaml_raw + b"unknown: reject\n")


def test_oversized_and_non_utc_clock_material_fails_closed() -> None:
    claim = _claim()
    private_key = Ed25519PrivateKey.generate()
    anchor = _anchor(private_key)
    activation = _signed_activation(
        claim,
        private_key,
        signer_key_fingerprint_sha256=anchor.signer_key_fingerprint_sha256,
    )
    raw = canonical_delegation_execution_overlay_json_bytes(activation)

    with pytest.raises(DelegationExecutionParseError):
        parse_delegation_execution_overlay(raw + b"\n" + b" " * 131_072)
    with pytest.raises(DelegationExecutionError):
        verify_delegation_execution_overlay(
            raw,
            claim=claim,
            trust_anchor=anchor,
            trusted_clock=lambda: datetime(2030, 1, 1),
        )


def test_activation_timestamps_must_be_utc() -> None:
    claim = _claim()
    private_key = Ed25519PrivateKey.generate()
    anchor = _anchor(private_key)
    non_utc = _NOW.astimezone(timezone(timedelta(hours=-5)))
    activation = _signed_activation(
        claim,
        private_key,
        issued_at=non_utc,
        expires_at=non_utc + timedelta(seconds=30),
        signer_key_fingerprint_sha256=anchor.signer_key_fingerprint_sha256,
    )

    with pytest.raises(DelegationExecutionError):
        _verified(canonical_delegation_execution_overlay_json_bytes(activation), claim, anchor)


def test_activation_hash_is_deterministic_and_domain_separated() -> None:
    activation_id = UUID("40000000-0000-4000-8000-000000000003")
    first = delegation_execution_activation_sha256(
        activation_id=activation_id,
        activation_schema_version=_ACTIVATION_SCHEMA,
        activation_version=1,
    )
    second = delegation_execution_activation_sha256(
        activation_id=activation_id,
        activation_schema_version=_ACTIVATION_SCHEMA,
        activation_version=1,
    )

    assert first == second
    assert len(first) == 64
    with pytest.raises(DelegationExecutionError):
        delegation_execution_activation_sha256(
            activation_id=activation_id,
            activation_schema_version="rsd.other.v1",
            activation_version=1,
        )
