from __future__ import annotations

import base64
import inspect
import json
from datetime import UTC, datetime, timedelta, timezone
from hashlib import sha256
from typing import Literal
from uuid import UUID, uuid4

import pytest
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey
from omninode_grant_verifier import signed_executable_grant_v2_vectors
from pydantic import ValidationError

import omninode_rsd.delegation_execution as delegation_execution
from omninode_rsd.delegation import (
    AtomicClaimPort,
    ClaimDisposition,
    DelegatedGrantClaim,
    DelegatedRequest,
    DelegatedRequestIngress,
    DelegationSubmissionState,
    PublicGrantVerifierAdapter,
    VerifiedGrantFacts,
    delegation_claim_binding_sha256,
    load_canonical_delegation_overlay,
)
from omninode_rsd.delegation_execution import (
    DelegationExecutionAuthorityProjectionV1,
    DelegationExecutionAuthorityProjectionV2,
    DelegationExecutionError,
    DelegationExecutionOverlayV1,
    DelegationExecutionParseError,
    DelegationExecutionSignatureError,
    DelegationExecutionTrustAnchorV1,
    DelegationRouteAuthorityParseError,
    DelegationRouteAuthoritySignatureError,
    DelegationRouteAuthorityTrustAnchorV1,
    DelegationRouteAuthorityV1,
    DelegationRouteAuthorityV2,
    VerifiedDispatchOutcomeV2,
    canonical_delegation_execution_authority_projection_json_bytes,
    canonical_delegation_execution_authority_projection_v2_json_bytes,
    canonical_delegation_execution_overlay_json_bytes,
    canonical_delegation_execution_overlay_yaml_bytes,
    canonical_delegation_route_authority_json_bytes,
    canonical_delegation_route_authority_v2_json_bytes,
    canonical_delegation_route_authority_v2_yaml_bytes,
    canonical_disabled_delegation_overlay_sha256,
    delegation_execution_activation_sha256,
    delegation_execution_overlay_message,
    delegation_logical_reference_sha256,
    delegation_route_authority_message,
    delegation_route_authority_sha256,
    delegation_route_authority_v2_message,
    delegation_route_authority_v2_sha256,
    parse_delegation_execution_overlay,
    parse_delegation_route_authority,
    parse_delegation_route_authority_v2,
    verify_delegation_execution_authority,
    verify_delegation_execution_overlay,
    verify_delegation_route_authority,
    verify_delegation_route_authority_v2,
    verify_raw_delegation_execution_authority_v2,
    verify_raw_dispatch_outcome_attestation_v2,
)
from omninode_rsd.lifecycle import InMemoryEventLog, LifecycleEventIngress
from omninode_rsd.lifecycle.dispatch_attestation import (
    DispatchCompletedOutputPayloadV1,
    DispatchOutcomeAttestationV1,
    DispatchOutcomeAttestationV2,
    DispatchOutcomeSignatureError,
    DispatchOutcomeTrustAnchorV1,
    DispatchResponsePreimageV1,
    dispatch_outcome_attestation_message,
    dispatch_outcome_attestation_v2_message,
    dispatch_outcome_trust_anchor_sha256,
    dispatch_output_payload_sha256,
    dispatch_response_sha256,
    parse_dispatch_outcome_attestation_v2,
)
from omninode_rsd.lifecycle.hashing import canonical_json

_NOW = datetime(2030, 1, 1, tzinfo=UTC)
_ACTIVATION_SCHEMA: Literal["rsd.delegation-execution-activation.v2"] = (
    "rsd.delegation-execution-activation.v2"
)
_ROUTE_AUTHORITY_SCHEMA: Literal["rsd.delegation-route-authority.v1"] = (
    "rsd.delegation-route-authority.v1"
)
_ROUTE_PRIVATE_KEY = Ed25519PrivateKey.generate()
_OUTCOME_PRIVATE_KEY = Ed25519PrivateKey.generate()


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


def _route_anchor(private_key: Ed25519PrivateKey) -> DelegationRouteAuthorityTrustAnchorV1:
    public_key = private_key.public_key().public_bytes_raw()
    return DelegationRouteAuthorityTrustAnchorV1(
        schema_version="rsd.delegation-route-authority-trust-anchor.v1",
        signer_key_id="route-authority",
        signer_public_key_base64=base64.b64encode(public_key).decode("ascii"),
        signer_key_fingerprint_sha256=sha256(public_key).hexdigest(),
    )


def _outcome_anchor(private_key: Ed25519PrivateKey) -> DispatchOutcomeTrustAnchorV1:
    public_key = private_key.public_key().public_bytes_raw()
    return DispatchOutcomeTrustAnchorV1(
        schema_version="rsd.dispatch-outcome-trust-anchor.v1",
        trust_domain="omninode-rsd.dispatch-outcome-attestation.v1",
        signer_key_id="outcome-attester",
        signer_public_key_base64=base64.b64encode(public_key).decode("ascii"),
        signer_key_fingerprint_sha256=sha256(public_key).hexdigest(),
    )


def _unsigned_route_authority(
    claim: DelegatedGrantClaim,
    *,
    route_ref: str | None = None,
    backend_id: str | None = None,
    model_id: str | None = None,
    endpoint_ref: str = "logical://endpoint/provider-alpha",
    credential_ref: str = "logical://credential/provider-alpha-v1",
    route_policy_digest: str = "5" * 64,
    target_configuration_sha256: str = "7" * 64,
    credential_provider_id: str = "provider-alpha",
    credential_provider_fingerprint_sha256: str = "6" * 64,
    activation_sha256: str | None = None,
) -> DelegationRouteAuthorityV1:
    if activation_sha256 is None:
        activation_sha256 = delegation_execution_activation_sha256(
            activation_id=claim.grant.activation_id,
            activation_schema_version=_ACTIVATION_SCHEMA,
            activation_version=1,
        )
    return DelegationRouteAuthorityV1(
        schema_version=_ROUTE_AUTHORITY_SCHEMA,
        authorization_digest=claim.grant.authorization_digest,
        request_envelope_sha256=claim.request.request_sha256,
        activation_id=claim.grant.activation_id,
        activation_sha256=activation_sha256,
        route_ref=route_ref or claim.request.route_ref,
        backend_id=backend_id or claim.request.backend_id,
        model_id=model_id or claim.request.model_id,
        endpoint_ref=endpoint_ref,
        credential_ref=credential_ref,
        route_policy_digest=route_policy_digest,
        target_configuration_sha256=target_configuration_sha256,
        credential_provider_id=credential_provider_id,
        credential_provider_fingerprint_sha256=credential_provider_fingerprint_sha256,
        signer_key_id="route-authority",
        signer_key_fingerprint_sha256="0" * 64,
        signature_base64=base64.b64encode(b"\0" * 64).decode("ascii"),
    )


def _signed_route_authority(
    claim: DelegatedGrantClaim,
    activation: DelegationExecutionOverlayV1,
    private_key: Ed25519PrivateKey,
    **updates: object,
) -> DelegationRouteAuthorityV1:
    unsigned = _unsigned_route_authority(
        claim,
        route_ref=activation.route_ref,
        backend_id=activation.backend_id,
        model_id=activation.model_id,
        endpoint_ref=activation.endpoint_ref,
        credential_ref=activation.credential_ref,
        activation_sha256=activation.activation_sha256,
    ).model_copy(update=updates)
    anchor = _route_anchor(private_key)
    unsigned = unsigned.model_copy(
        update={"signer_key_fingerprint_sha256": anchor.signer_key_fingerprint_sha256}
    )
    signature = private_key.sign(delegation_route_authority_message(unsigned))
    return unsigned.model_copy(
        update={"signature_base64": base64.b64encode(signature).decode("ascii")}
    )


def _unsigned_route_authority_v2(
    claim: DelegatedGrantClaim,
    *,
    route_ref: str | None = None,
    backend_id: str | None = None,
    model_id: str | None = None,
    endpoint_ref: str = "logical://endpoint/provider-alpha",
    credential_ref: str = "logical://credential/provider-alpha-v1",
    route_policy_digest: str = "5" * 64,
    target_configuration_sha256: str = "7" * 64,
    credential_provider_id: str = "provider-alpha",
    credential_provider_fingerprint_sha256: str = "6" * 64,
    activation_sha256: str | None = None,
    outcome_trust_anchor: DispatchOutcomeTrustAnchorV1 | None = None,
) -> DelegationRouteAuthorityV2:
    if activation_sha256 is None:
        activation_sha256 = delegation_execution_activation_sha256(
            activation_id=claim.grant.activation_id,
            activation_schema_version=_ACTIVATION_SCHEMA,
            activation_version=1,
        )
    return DelegationRouteAuthorityV2(
        schema_version="rsd.delegation-route-authority.v2",
        authorization_digest=claim.grant.authorization_digest,
        request_envelope_sha256=claim.request.request_sha256,
        activation_id=claim.grant.activation_id,
        activation_sha256=activation_sha256,
        route_ref=route_ref or claim.request.route_ref,
        backend_id=backend_id or claim.request.backend_id,
        model_id=model_id or claim.request.model_id,
        endpoint_ref=endpoint_ref,
        credential_ref=credential_ref,
        route_policy_digest=route_policy_digest,
        target_configuration_sha256=target_configuration_sha256,
        credential_provider_id=credential_provider_id,
        credential_provider_fingerprint_sha256=credential_provider_fingerprint_sha256,
        outcome_trust_anchor=outcome_trust_anchor or _outcome_anchor(_OUTCOME_PRIVATE_KEY),
        signer_key_id="route-authority",
        signer_key_fingerprint_sha256="0" * 64,
        signature_base64=base64.b64encode(b"\0" * 64).decode("ascii"),
    )


def _signed_route_authority_v2(
    claim: DelegatedGrantClaim,
    activation: DelegationExecutionOverlayV1,
    private_key: Ed25519PrivateKey,
    **updates: object,
) -> DelegationRouteAuthorityV2:
    unsigned = _unsigned_route_authority_v2(
        claim,
        route_ref=activation.route_ref,
        backend_id=activation.backend_id,
        model_id=activation.model_id,
        endpoint_ref=activation.endpoint_ref,
        credential_ref=activation.credential_ref,
        activation_sha256=activation.activation_sha256,
    ).model_copy(update=updates)
    anchor = _route_anchor(private_key)
    unsigned = unsigned.model_copy(
        update={"signer_key_fingerprint_sha256": anchor.signer_key_fingerprint_sha256}
    )
    signature = private_key.sign(delegation_route_authority_v2_message(unsigned))
    return unsigned.model_copy(
        update={"signature_base64": base64.b64encode(signature).decode("ascii")}
    )


def _signed_pair(
    claim: DelegatedGrantClaim,
    activation_private_key: Ed25519PrivateKey,
    route_private_key: Ed25519PrivateKey,
    **target: object,
) -> tuple[DelegationExecutionOverlayV1, DelegationRouteAuthorityV1]:
    route_anchor = _route_anchor(route_private_key)
    route_ref = str(target.get("route_ref", claim.request.route_ref))
    backend_id = str(target.get("backend_id", claim.request.backend_id))
    model_id = str(target.get("model_id", claim.request.model_id))
    endpoint_ref = str(target.get("endpoint_ref", "logical://endpoint/provider-alpha"))
    credential_ref = str(target.get("credential_ref", "logical://credential/provider-alpha-v1"))
    route_policy_digest = str(target.get("route_policy_digest", "5" * 64))
    target_configuration_sha256 = str(target.get("target_configuration_sha256", "7" * 64))
    credential_provider_id = str(target.get("credential_provider_id", "provider-alpha"))
    credential_provider_fingerprint_sha256 = str(
        target.get("credential_provider_fingerprint_sha256", "6" * 64)
    )
    authority = _unsigned_route_authority(
        claim,
        route_ref=route_ref,
        backend_id=backend_id,
        model_id=model_id,
        endpoint_ref=endpoint_ref,
        credential_ref=credential_ref,
        route_policy_digest=route_policy_digest,
        target_configuration_sha256=target_configuration_sha256,
        credential_provider_id=credential_provider_id,
        credential_provider_fingerprint_sha256=credential_provider_fingerprint_sha256,
    ).model_copy(
        update={"signer_key_fingerprint_sha256": route_anchor.signer_key_fingerprint_sha256}
    )
    activation = _unsigned_activation(
        claim,
    ).model_copy(
        update={
            "route_ref": route_ref,
            "backend_id": backend_id,
            "model_id": model_id,
            "endpoint_ref": endpoint_ref,
            "credential_ref": credential_ref,
            "route_authority_sha256": delegation_route_authority_sha256(authority),
        }
    )
    activation_anchor = _anchor(activation_private_key)
    activation = activation.model_copy(
        update={"signer_key_fingerprint_sha256": activation_anchor.signer_key_fingerprint_sha256}
    )
    activation_signature = activation_private_key.sign(
        delegation_execution_overlay_message(activation)
    )
    activation = activation.model_copy(
        update={"signature_base64": base64.b64encode(activation_signature).decode("ascii")}
    )
    authority = _signed_route_authority(claim, activation, route_private_key, **target)
    return activation, authority


def _signed_pair_v2(
    claim: DelegatedGrantClaim,
    activation_private_key: Ed25519PrivateKey,
    route_private_key: Ed25519PrivateKey,
    **target: object,
) -> tuple[DelegationExecutionOverlayV1, DelegationRouteAuthorityV2]:
    route_anchor = _route_anchor(route_private_key)
    route_ref = str(target.get("route_ref", claim.request.route_ref))
    backend_id = str(target.get("backend_id", claim.request.backend_id))
    model_id = str(target.get("model_id", claim.request.model_id))
    endpoint_ref = str(target.get("endpoint_ref", "logical://endpoint/provider-alpha"))
    credential_ref = str(target.get("credential_ref", "logical://credential/provider-alpha-v1"))
    authority = _unsigned_route_authority_v2(
        claim,
        route_ref=route_ref,
        backend_id=backend_id,
        model_id=model_id,
        endpoint_ref=endpoint_ref,
        credential_ref=credential_ref,
    ).model_copy(
        update={"signer_key_fingerprint_sha256": route_anchor.signer_key_fingerprint_sha256}
    )
    activation = _unsigned_activation(claim).model_copy(
        update={
            "route_ref": route_ref,
            "backend_id": backend_id,
            "model_id": model_id,
            "endpoint_ref": endpoint_ref,
            "credential_ref": credential_ref,
            "route_authority_sha256": delegation_route_authority_v2_sha256(authority),
        }
    )
    activation_anchor = _anchor(activation_private_key)
    activation = activation.model_copy(
        update={"signer_key_fingerprint_sha256": activation_anchor.signer_key_fingerprint_sha256}
    )
    activation = activation.model_copy(
        update={
            "signature_base64": base64.b64encode(
                activation_private_key.sign(delegation_execution_overlay_message(activation))
            ).decode("ascii")
        }
    )
    authority = _signed_route_authority_v2(claim, activation, route_private_key, **target)
    return activation, authority


def _unsigned_activation(
    claim: DelegatedGrantClaim,
    *,
    issued_at: datetime = _NOW,
    expires_at: datetime = _NOW + timedelta(seconds=30),
) -> DelegationExecutionOverlayV1:
    activation_id = claim.grant.activation_id
    route_anchor = _route_anchor(_ROUTE_PRIVATE_KEY)
    authority = _unsigned_route_authority(claim).model_copy(
        update={"signer_key_fingerprint_sha256": route_anchor.signer_key_fingerprint_sha256}
    )
    return DelegationExecutionOverlayV1(
        schema_version="rsd.delegation-execution-overlay.v2",
        execute_enabled=True,
        authorization_digest=claim.grant.authorization_digest,
        request_envelope_sha256=claim.request.request_sha256,
        backend_id=claim.request.backend_id,
        model_id=claim.request.model_id,
        route_ref=claim.request.route_ref,
        disabled_overlay_sha256=canonical_disabled_delegation_overlay_sha256(),
        route_authority_sha256=delegation_route_authority_sha256(authority),
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
    *,
    route_authority: DelegationRouteAuthorityV1 | None = None,
    route_anchor: DelegationRouteAuthorityTrustAnchorV1 | None = None,
    trusted_clock: datetime = _NOW,
) -> DelegationExecutionOverlayV1:
    activation = parse_delegation_execution_overlay(raw)
    route_private_key = _ROUTE_PRIVATE_KEY
    authority = route_authority or _signed_route_authority(claim, activation, route_private_key)
    authority_anchor = route_anchor or _route_anchor(route_private_key)
    return verify_delegation_execution_overlay(
        raw,
        claim=claim,
        trust_anchor=anchor,
        route_authority=canonical_delegation_route_authority_json_bytes(authority),
        route_authority_trust_anchor=authority_anchor,
        trusted_clock=lambda: trusted_clock,
    )


def test_valid_json_activation_binds_every_execution_fact() -> None:
    claim = _claim()
    private_key = Ed25519PrivateKey.generate()
    anchor = _anchor(private_key)
    activation, authority = _signed_pair(
        claim,
        private_key,
        _ROUTE_PRIVATE_KEY,
    )

    result = _verified(
        canonical_delegation_execution_overlay_json_bytes(activation),
        claim,
        anchor,
        route_authority=authority,
    )

    assert result == activation
    assert result.execute_enabled is True
    assert result.authorization_digest == claim.grant.authorization_digest
    assert result.request_envelope_sha256 == claim.request.request_sha256
    assert result.activation_id == claim.grant.activation_id
    assert result.endpoint_ref.startswith("logical://")
    assert result.credential_ref.startswith("logical://")


def test_independent_route_authority_allows_only_its_resigned_target() -> None:
    claim = _claim()
    activation_key = Ed25519PrivateKey.generate()
    route_key = Ed25519PrivateKey.generate()
    activation, authority = _signed_pair(
        claim,
        activation_key,
        route_key,
        endpoint_ref="logical://endpoint/provider-beta",
        credential_ref="logical://credential/provider-beta-v2",
        route_policy_digest="7" * 64,
        credential_provider_id="provider-beta",
        credential_provider_fingerprint_sha256="8" * 64,
    )
    assert (
        _anchor(activation_key).signer_key_fingerprint_sha256
        != _route_anchor(route_key).signer_key_fingerprint_sha256
    )
    result = _verified(
        canonical_delegation_execution_overlay_json_bytes(activation),
        claim,
        _anchor(activation_key),
        route_authority=authority,
        route_anchor=_route_anchor(route_key),
    )

    assert result.endpoint_ref == "logical://endpoint/provider-beta"
    assert result.credential_ref == "logical://credential/provider-beta-v2"
    assert authority.route_policy_digest == "7" * 64
    assert authority.credential_provider_id == "provider-beta"


def test_resigned_route_authority_target_configuration_cannot_redirect_activation() -> None:
    claim = _claim()
    activation_key = Ed25519PrivateKey.generate()
    route_key = Ed25519PrivateKey.generate()
    activation, _authority = _signed_pair(claim, activation_key, route_key)
    redirected_authority = _signed_route_authority(
        claim,
        activation,
        route_key,
        target_configuration_sha256="8" * 64,
    )

    assert (
        verify_delegation_route_authority(
            canonical_delegation_route_authority_json_bytes(redirected_authority),
            trust_anchor=_route_anchor(route_key),
        )
        == redirected_authority
    )
    with pytest.raises(DelegationExecutionError):
        _verified(
            canonical_delegation_execution_overlay_json_bytes(activation),
            claim,
            _anchor(activation_key),
            route_authority=redirected_authority,
            route_anchor=_route_anchor(route_key),
        )


def test_verified_authority_projection_is_redacted_exact_and_deterministic() -> None:
    claim = _claim()
    activation_key = Ed25519PrivateKey.generate()
    route_key = Ed25519PrivateKey.generate()
    activation, authority = _signed_pair(claim, activation_key, route_key)
    raw_activation = canonical_delegation_execution_overlay_json_bytes(activation)
    raw_authority = canonical_delegation_route_authority_json_bytes(authority)
    projection = verify_delegation_execution_authority(
        raw_activation,
        claim=claim,
        trust_anchor=_anchor(activation_key),
        route_authority=raw_authority,
        route_authority_trust_anchor=_route_anchor(route_key),
        trusted_clock=lambda: _NOW,
    )

    assert type(projection) is DelegationExecutionAuthorityProjectionV1
    assert projection.activation_id == activation.activation_id
    assert projection.activation_sha256 == activation.activation_sha256
    assert projection.claim_binding_sha256 == delegation_claim_binding_sha256(
        request=claim.request,
        grant=claim.grant,
        policy=claim.policy,
    )
    assert projection.route_authority_sha256 == delegation_route_authority_sha256(authority)
    assert projection.target_configuration_sha256 == authority.target_configuration_sha256
    assert projection.endpoint_ref_sha256 == delegation_logical_reference_sha256(
        authority.endpoint_ref,
        namespace="endpoint",
    )
    assert projection.credential_ref_sha256 == delegation_logical_reference_sha256(
        authority.credential_ref,
        namespace="credential",
    )
    assert (
        projection.activation_trust_anchor_fingerprint_sha256
        == _anchor(activation_key).signer_key_fingerprint_sha256
    )
    assert (
        projection.route_authority_trust_anchor_fingerprint_sha256
        == _route_anchor(route_key).signer_key_fingerprint_sha256
    )
    assert (
        b"logical://endpoint/"
        not in canonical_delegation_execution_authority_projection_json_bytes(projection)
    )
    assert set(DelegationExecutionAuthorityProjectionV1.model_fields) == {
        "schema_version",
        "execute_enabled",
        "activation_id",
        "activation_schema_version",
        "activation_version",
        "activation_sha256",
        "issued_at",
        "expires_at",
        "authorization_digest",
        "claim_binding_sha256",
        "request_envelope_sha256",
        "disabled_overlay_sha256",
        "backend_id",
        "model_id",
        "route_ref",
        "route_authority_sha256",
        "route_policy_digest",
        "target_configuration_sha256",
        "endpoint_ref_sha256",
        "credential_ref_sha256",
        "activation_trust_anchor_fingerprint_sha256",
        "route_authority_trust_anchor_fingerprint_sha256",
        "credential_provider_id",
        "credential_provider_fingerprint_sha256",
    }
    assert canonical_delegation_execution_authority_projection_json_bytes(
        projection
    ) == canonical_delegation_execution_authority_projection_json_bytes(projection)


def test_same_trust_key_is_rejected_after_valid_independent_signatures() -> None:
    claim = _claim()
    shared_key = Ed25519PrivateKey.generate()
    activation, authority = _signed_pair(claim, shared_key, shared_key)
    route_anchor = _route_anchor(shared_key)

    assert (
        verify_delegation_route_authority(
            canonical_delegation_route_authority_json_bytes(authority),
            trust_anchor=route_anchor,
        )
        == authority
    )
    with pytest.raises(
        DelegationExecutionSignatureError,
        match="trust anchors must be distinct",
    ) as error:
        _verified(
            canonical_delegation_execution_overlay_json_bytes(activation),
            claim,
            _anchor(shared_key),
            route_authority=authority,
            route_anchor=route_anchor,
        )
    assert str(error.value) == "activation and route authority trust anchors must be distinct"


def test_validly_resigned_route_authority_cannot_redirect_activation() -> None:
    claim = _claim()
    activation_key = Ed25519PrivateKey.generate()
    route_key = Ed25519PrivateKey.generate()
    activation, _authority = _signed_pair(claim, activation_key, route_key)
    redirected_authority = _signed_route_authority(
        claim,
        activation,
        route_key,
        endpoint_ref="logical://endpoint/provider-beta",
        credential_ref="logical://credential/provider-beta-v2",
        route_policy_digest="7" * 64,
        credential_provider_id="provider-beta",
        credential_provider_fingerprint_sha256="8" * 64,
    )

    with pytest.raises(DelegationExecutionError):
        _verified(
            canonical_delegation_execution_overlay_json_bytes(activation),
            claim,
            _anchor(activation_key),
            route_authority=redirected_authority,
            route_anchor=_route_anchor(route_key),
        )


def test_route_authority_wrong_trust_root_fails_closed() -> None:
    claim = _claim()
    activation_key = Ed25519PrivateKey.generate()
    route_key = Ed25519PrivateKey.generate()
    wrong_route_key = Ed25519PrivateKey.generate()
    activation, _authority = _signed_pair(claim, activation_key, route_key)
    wrong_authority = _signed_route_authority(claim, activation, wrong_route_key)

    with pytest.raises(DelegationRouteAuthoritySignatureError):
        _verified(
            canonical_delegation_execution_overlay_json_bytes(activation),
            claim,
            _anchor(activation_key),
            route_authority=wrong_authority,
            route_anchor=_route_anchor(route_key),
        )


def test_alternate_disabled_policy_is_rejected_even_when_resigned() -> None:
    claim = _claim()
    alternate_route = "logical://delegation/alternate"
    alternate_policy = claim.policy.model_copy(update={"route_ref": alternate_route})
    alternate_request = claim.request.model_copy(update={"route_ref": alternate_route})
    alternate_claim = DelegatedGrantClaim(
        request=alternate_request,
        grant=claim.grant,
        policy=alternate_policy,
    )
    activation_key = Ed25519PrivateKey.generate()
    route_key = Ed25519PrivateKey.generate()
    activation, authority = _signed_pair(
        alternate_claim,
        activation_key,
        route_key,
        route_ref=alternate_route,
    )

    with pytest.raises(DelegationExecutionError):
        _verified(
            canonical_delegation_execution_overlay_json_bytes(activation),
            alternate_claim,
            _anchor(activation_key),
            route_authority=authority,
            route_anchor=_route_anchor(route_key),
        )


@pytest.mark.parametrize(
    "endpoint_ref",
    [
        "logical://credential/provider-alpha",
        "logical://endpoint//provider-alpha",
        "logical://endpoint/../provider-alpha",
        "logical://endpoint/./provider-alpha",
        "logical://endpoint/provider.alpha",
    ],
)
def test_route_authority_references_reject_aliases_and_namespace_confusion(
    endpoint_ref: str,
) -> None:
    with pytest.raises(ValidationError):
        _unsigned_route_authority(_claim(), endpoint_ref=endpoint_ref)


def test_canonical_yaml_round_trip_is_deterministic() -> None:
    claim = _claim()
    private_key = Ed25519PrivateKey.generate()
    anchor = _anchor(private_key)
    activation, authority = _signed_pair(
        claim,
        private_key,
        _ROUTE_PRIVATE_KEY,
    )
    raw = canonical_delegation_execution_overlay_yaml_bytes(activation)

    assert raw == canonical_delegation_execution_overlay_yaml_bytes(activation)
    assert parse_delegation_execution_overlay(raw) == activation
    assert _verified(raw, claim, anchor, route_authority=authority) == activation


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

    with pytest.raises(DelegationExecutionSignatureError, match="activation signature is invalid"):
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

    with pytest.raises(DelegationExecutionError):
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


def test_route_authority_unknown_duplicate_and_noncanonical_input_is_rejected() -> None:
    claim = _claim()
    activation_key = Ed25519PrivateKey.generate()
    route_key = Ed25519PrivateKey.generate()
    _activation, authority = _signed_pair(claim, activation_key, route_key)
    raw = canonical_delegation_route_authority_json_bytes(authority)
    value = json.loads(raw)

    unknown = json.dumps({**value, "unknown": "reject"}, separators=(",", ":")).encode("ascii")
    with pytest.raises(DelegationRouteAuthorityParseError):
        parse_delegation_route_authority(unknown)
    duplicate = raw.replace(b'"schema_version":', b'"schema_version":"other", "schema_version":', 1)
    with pytest.raises(DelegationRouteAuthorityParseError):
        parse_delegation_route_authority(duplicate)
    with pytest.raises(DelegationRouteAuthorityParseError):
        parse_delegation_route_authority(raw + b" ")


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
        authority = _signed_route_authority(claim, activation, _ROUTE_PRIVATE_KEY)
        verify_delegation_execution_overlay(
            raw,
            claim=claim,
            trust_anchor=anchor,
            route_authority=canonical_delegation_route_authority_json_bytes(authority),
            route_authority_trust_anchor=_route_anchor(_ROUTE_PRIVATE_KEY),
            trusted_clock=lambda: datetime(2030, 1, 1),
        )


def test_activation_timestamps_must_be_utc() -> None:
    claim = _claim()
    private_key = Ed25519PrivateKey.generate()
    anchor = _anchor(private_key)
    non_utc = _NOW.astimezone(timezone(timedelta(hours=-5)))
    with pytest.raises(DelegationExecutionError):
        activation = _signed_activation(
            claim,
            private_key,
            issued_at=non_utc,
            expires_at=non_utc + timedelta(seconds=30),
            signer_key_fingerprint_sha256=anchor.signer_key_fingerprint_sha256,
        )
        _verified(canonical_delegation_execution_overlay_json_bytes(activation), claim, anchor)


def test_custom_zero_offset_timezone_is_not_utc() -> None:
    claim = _claim()
    private_key = Ed25519PrivateKey.generate()
    anchor = _anchor(private_key)
    custom_utc = timezone(timedelta(0), name="custom-utc")

    with pytest.raises(DelegationExecutionError):
        activation = _signed_activation(
            claim,
            private_key,
            issued_at=datetime(2030, 1, 1, tzinfo=custom_utc),
            expires_at=datetime(2030, 1, 1, 0, 0, 30, tzinfo=custom_utc),
            signer_key_fingerprint_sha256=anchor.signer_key_fingerprint_sha256,
        )
        canonical_delegation_execution_overlay_json_bytes(activation)


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


def test_v2_route_authority_signs_the_complete_outcome_anchor() -> None:
    claim = _claim()
    activation_key = Ed25519PrivateKey.generate()
    route_key = Ed25519PrivateKey.generate()
    _activation, authority = _signed_pair_v2(claim, activation_key, route_key)
    raw = canonical_delegation_route_authority_v2_json_bytes(authority)

    verified = verify_delegation_route_authority_v2(
        raw,
        trust_anchor=_route_anchor(route_key),
    )

    assert verified == authority
    assert (
        delegation_route_authority_v2_sha256(verified)
        == sha256(delegation_route_authority_v2_message(verified)).hexdigest()
    )
    assert dispatch_outcome_trust_anchor_sha256(verified.outcome_trust_anchor) != "0" * 64
    with pytest.raises(DelegationRouteAuthorityParseError):
        parse_delegation_route_authority(raw)


def test_v2_anchor_divergence_and_noncanonical_shapes_fail_before_verification() -> None:
    claim = _claim()
    activation_key = Ed25519PrivateKey.generate()
    route_key = Ed25519PrivateKey.generate()
    _activation, authority = _signed_pair_v2(claim, activation_key, route_key)
    raw = canonical_delegation_route_authority_v2_json_bytes(authority)
    value = json.loads(raw)
    anchor = value["outcome_trust_anchor"]
    assert type(anchor) is dict
    anchor["signer_key_id"] = "substituted-attester"
    tampered = json.dumps(value, separators=(",", ":")).encode("ascii")

    with pytest.raises(DelegationRouteAuthoritySignatureError):
        verify_delegation_route_authority_v2(
            tampered,
            trust_anchor=_route_anchor(route_key),
        )
    with pytest.raises(DelegationRouteAuthorityParseError):
        parse_delegation_route_authority_v2(raw + b" ")
    with pytest.raises(DelegationRouteAuthorityParseError):
        parse_delegation_route_authority_v2(
            raw.replace(b'"schema_version":', b'"schema_version":"other","schema_version":', 1)
        )
    with pytest.raises(DelegationRouteAuthorityParseError):
        parse_delegation_route_authority_v2(b"anchor: &same {x: value}\ncopy: *same\n")
    with pytest.raises(DelegationRouteAuthorityParseError):
        parse_delegation_route_authority_v2(
            b"x:\n  y:\n    z:\n      a:\n        b:\n          c:\n            d:\n"
            b"              e:\n                f: 1\n"
        )
    with pytest.raises(ValidationError):
        _unsigned_route_authority_v2(
            claim,
            outcome_trust_anchor=_outcome_anchor(_OUTCOME_PRIVATE_KEY).model_copy(
                update={"signer_key_fingerprint_sha256": "0" * 64}
            ),
        )


def test_v2_yaml_is_canonical_and_embeds_the_strict_anchor() -> None:
    claim = _claim()
    activation_key = Ed25519PrivateKey.generate()
    route_key = Ed25519PrivateKey.generate()
    _activation, authority = _signed_pair_v2(claim, activation_key, route_key)
    raw = canonical_delegation_route_authority_v2_yaml_bytes(authority)

    assert parse_delegation_route_authority_v2(raw) == authority
    assert b"outcome_trust_anchor:" in raw
    assert b"outcome_trust_anchor_sha256" not in raw


def test_raw_v2_chain_derives_projection_without_claim_or_projection_inputs(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    policy = load_canonical_delegation_overlay()
    facts = _facts().model_copy(update={"model_id": policy.model_ref})
    claim = DelegatedGrantClaim(
        request=DelegatedRequest(
            run_id=facts.correlation_id,
            request_sha256=facts.request_sha256,
            artifact_sha256=facts.artifact_sha256,
            rendered_contract_sha256=facts.rendered_contract_sha256,
            tenant_id=facts.tenant_id,
            backend_id=facts.backend_id,
            model_id=policy.model_ref,
            route_ref=policy.route_ref,
            expected_output_topic=facts.expected_output_topic,
            expected_output_event_class=facts.expected_output_event_class,
            expected_output_event_index=facts.expected_output_event_index,
        ),
        grant=facts,
        policy=policy,
    )
    activation_key = Ed25519PrivateKey.generate()
    route_key = Ed25519PrivateKey.generate()
    activation, authority = _signed_pair_v2(claim, activation_key, route_key)

    class _FixedVerifier:
        def __init__(self, *, trusted_clock: object) -> None:
            assert callable(trusted_clock)

        def __call__(self, raw_signed_grant: bytes) -> VerifiedGrantFacts:
            assert raw_signed_grant == b"raw-signed-grant"
            return facts

    monkeypatch.setattr(delegation_execution, "PublicGrantVerifierAdapter", _FixedVerifier)
    projection = verify_raw_delegation_execution_authority_v2(
        b"raw-signed-grant",
        canonical_delegation_execution_overlay_json_bytes(activation),
        activation_trust_anchor=_anchor(activation_key),
        raw_route_authority=canonical_delegation_route_authority_v2_json_bytes(authority),
        route_authority_trust_anchor=_route_anchor(route_key),
        trusted_clock=lambda: _NOW,
    )

    assert type(projection) is DelegationExecutionAuthorityProjectionV2
    assert projection.schema_version == "rsd.delegation-execution-authority-projection.v2"
    assert projection.grant_correlation_id == facts.correlation_id == claim.request.run_id
    assert projection.grant_not_before == facts.not_before
    assert projection.grant_expires_at == facts.expires_at
    assert projection.outcome_trust_anchor_sha256 == dispatch_outcome_trust_anchor_sha256(
        authority.outcome_trust_anchor
    )
    assert projection.outcome_trust_anchor_key_id == authority.outcome_trust_anchor.signer_key_id
    assert (
        projection.outcome_trust_anchor_key_fingerprint_sha256
        == authority.outcome_trust_anchor.signer_key_fingerprint_sha256
    )
    projection_bytes = canonical_delegation_execution_authority_projection_v2_json_bytes(projection)
    assert json.loads(projection_bytes)["grant_correlation_id"] == str(facts.correlation_id)
    assert b"logical://endpoint/" not in projection_bytes

    invalid_lifetime = projection.model_dump(mode="python")
    invalid_lifetime["grant_not_before"] = projection.issued_at + timedelta(microseconds=1)
    with pytest.raises(ValidationError, match="lifetime is not within"):
        DelegationExecutionAuthorityProjectionV2.model_validate(invalid_lifetime)

    non_singleton_utc = timezone(timedelta(0), "UTC")
    invalid_timezone = projection.model_dump(mode="python")
    invalid_timezone["grant_not_before"] = projection.grant_not_before.replace(
        tzinfo=non_singleton_utc
    )
    with pytest.raises(ValidationError, match="exact UTC"):
        DelegationExecutionAuthorityProjectionV2.model_validate(invalid_timezone)


def test_raw_v2_chain_rejects_grant_lifetime_divergence(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    claim = _claim()
    facts = claim.grant
    activation_key = Ed25519PrivateKey.generate()
    route_key = Ed25519PrivateKey.generate()
    activation, authority = _signed_pair_v2(claim, activation_key, route_key)
    raw_activation = canonical_delegation_execution_overlay_json_bytes(activation)
    raw_route_authority = canonical_delegation_route_authority_v2_json_bytes(authority)

    for divergent in (
        facts.model_copy(update={"not_before": activation.issued_at + timedelta(microseconds=1)}),
        facts.model_copy(update={"expires_at": activation.expires_at - timedelta(microseconds=1)}),
    ):

        class _FixedVerifier:
            def __init__(self, *, trusted_clock: object) -> None:
                assert callable(trusted_clock)

            def __call__(
                self,
                raw_signed_grant: bytes,
                _facts: VerifiedGrantFacts = divergent,
            ) -> VerifiedGrantFacts:
                assert raw_signed_grant == b"raw-signed-grant"
                return _facts

        monkeypatch.setattr(delegation_execution, "PublicGrantVerifierAdapter", _FixedVerifier)
        with pytest.raises(DelegationExecutionError):
            verify_raw_delegation_execution_authority_v2(
                b"raw-signed-grant",
                raw_activation,
                activation_trust_anchor=_anchor(activation_key),
                raw_route_authority=raw_route_authority,
                route_authority_trust_anchor=_route_anchor(route_key),
                trusted_clock=lambda: _NOW,
            )


def test_raw_v2_chain_refuses_fixed_public_grant_that_conflicts_with_packaged_policy() -> None:
    vector = signed_executable_grant_v2_vectors()["base_wire"]
    assert type(vector) is dict
    raw_grant = json.dumps(vector, separators=(",", ":")).encode("utf-8")
    claim = _claim()
    activation_key = Ed25519PrivateKey.generate()
    route_key = Ed25519PrivateKey.generate()
    activation, authority = _signed_pair_v2(claim, activation_key, route_key)

    with pytest.raises(DelegationExecutionError):
        verify_raw_delegation_execution_authority_v2(
            raw_grant,
            canonical_delegation_execution_overlay_json_bytes(activation),
            activation_trust_anchor=_anchor(activation_key),
            raw_route_authority=canonical_delegation_route_authority_v2_json_bytes(authority),
            route_authority_trust_anchor=_route_anchor(route_key),
            trusted_clock=lambda: _NOW,
        )


@pytest.mark.parametrize(
    ("field", "value"),
    (
        ("correlation_id", "40000000-0000-4000-8000-000000000099"),
        ("not_before", "2030-01-01T00:00:01Z"),
        ("expires_at", "2030-01-01T00:00:00Z"),
    ),
)
def test_raw_v2_chain_refuses_tampered_signed_grant_identity_or_lifetime(
    field: str,
    value: str,
) -> None:
    vector = signed_executable_grant_v2_vectors()["base_wire"]
    assert type(vector) is dict
    material = vector["authorization_material"]
    assert type(material) is dict
    grant = material["grant"]
    assert type(grant) is dict
    grant[field] = value
    claim = _claim()
    activation_key = Ed25519PrivateKey.generate()
    route_key = Ed25519PrivateKey.generate()
    activation, authority = _signed_pair_v2(claim, activation_key, route_key)

    with pytest.raises(DelegationExecutionError):
        verify_raw_delegation_execution_authority_v2(
            json.dumps(vector, separators=(",", ":")).encode("utf-8"),
            canonical_delegation_execution_overlay_json_bytes(activation),
            activation_trust_anchor=_anchor(activation_key),
            raw_route_authority=canonical_delegation_route_authority_v2_json_bytes(authority),
            route_authority_trust_anchor=_route_anchor(route_key),
            trusted_clock=lambda: _NOW,
        )


def test_v2_outcome_attestation_preimage_binds_v2_authority_facts() -> None:
    attestation = DispatchOutcomeAttestationV2(
        schema_version="rsd.dispatch-outcome-attestation.v2",
        attestation_id=UUID("40000000-0000-4000-8000-000000000004"),
        attempt_id=UUID("40000000-0000-4000-8000-000000000005"),
        authorization_digest="1" * 64,
        claim_binding_sha256="2" * 64,
        backend_id="backend-alpha",
        model_id="qwen/qwen3.8-27b",
        route_ref="logical://delegation/qwen3.8-27b",
        request_sha256="3" * 64,
        response_sha256="4" * 64,
        output_payload_sha256="5" * 64,
        outcome_status="completed",
        issued_at=_NOW,
        activation_id=UUID("40000000-0000-4000-8000-000000000003"),
        activation_sha256="6" * 64,
        route_authority_sha256="7" * 64,
        target_configuration_sha256="8" * 64,
        outcome_trust_anchor_sha256="9" * 64,
        signer_key_id="outcome-attester",
        trust_anchor_key_id="outcome-attester",
        trust_anchor_key_fingerprint_sha256="a" * 64,
        signature_base64=base64.b64encode(b"\0" * 64).decode("ascii"),
    )
    signed = attestation.model_copy(
        update={
            "signature_base64": base64.b64encode(
                _OUTCOME_PRIVATE_KEY.sign(dispatch_outcome_attestation_v2_message(attestation))
            ).decode("ascii")
        }
    )
    raw = canonical_json(signed.model_dump(mode="python"))

    assert parse_dispatch_outcome_attestation_v2(raw) == signed
    assert b"dispatch-outcome-attestation.ed25519.v2" in dispatch_outcome_attestation_v2_message(
        signed
    )
    assert b"target_configuration_sha256" in dispatch_outcome_attestation_v2_message(signed)


def test_raw_v2_outcome_verifier_derives_anchor_and_rejects_bound_fact_divergence(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    claim = _claim()
    facts = claim.grant
    activation_key = Ed25519PrivateKey.generate()
    route_key = Ed25519PrivateKey.generate()
    activation, authority = _signed_pair_v2(claim, activation_key, route_key)

    class _FixedVerifier:
        def __init__(self, *, trusted_clock: object) -> None:
            assert callable(trusted_clock)

        def __call__(self, raw_signed_grant: bytes) -> VerifiedGrantFacts:
            assert raw_signed_grant == b"raw-signed-grant"
            return facts

    monkeypatch.setattr(delegation_execution, "PublicGrantVerifierAdapter", _FixedVerifier)
    raw_activation = canonical_delegation_execution_overlay_json_bytes(activation)
    activation_anchor = _anchor(activation_key)
    raw_route_authority = canonical_delegation_route_authority_v2_json_bytes(authority)
    route_anchor = _route_anchor(route_key)
    projection = verify_raw_delegation_execution_authority_v2(
        b"raw-signed-grant",
        raw_activation,
        activation_trust_anchor=activation_anchor,
        raw_route_authority=raw_route_authority,
        route_authority_trust_anchor=route_anchor,
        trusted_clock=lambda: _NOW,
    )
    payload = DispatchCompletedOutputPayloadV1(
        schema_version="rsd.dispatch-completed-output-payload.v1", content="bounded output"
    )
    response = DispatchResponsePreimageV1(
        schema_version="rsd.dispatch-response-preimage.v1",
        outcome_status="completed",
        output_payload_sha256=dispatch_output_payload_sha256(payload),
    )
    unsigned = DispatchOutcomeAttestationV2(
        schema_version="rsd.dispatch-outcome-attestation.v2",
        attestation_id=UUID("40000000-0000-4000-8000-000000000005"),
        attempt_id=UUID("40000000-0000-4000-8000-000000000006"),
        authorization_digest=projection.authorization_digest,
        claim_binding_sha256=projection.claim_binding_sha256,
        backend_id=projection.backend_id,
        model_id=projection.model_id,
        route_ref=projection.route_ref,
        request_sha256=projection.request_envelope_sha256,
        response_sha256=dispatch_response_sha256(response),
        output_payload_sha256=dispatch_output_payload_sha256(payload),
        outcome_status="completed",
        issued_at=_NOW,
        activation_id=projection.activation_id,
        activation_sha256=projection.activation_sha256,
        route_authority_sha256=projection.route_authority_sha256,
        target_configuration_sha256=projection.target_configuration_sha256,
        outcome_trust_anchor_sha256=projection.outcome_trust_anchor_sha256,
        signer_key_id=projection.outcome_trust_anchor_key_id,
        trust_anchor_key_id=projection.outcome_trust_anchor_key_id,
        trust_anchor_key_fingerprint_sha256=(
            projection.outcome_trust_anchor_key_fingerprint_sha256
        ),
        signature_base64=base64.b64encode(b"\0" * 64).decode("ascii"),
    )
    signed = unsigned.model_copy(
        update={
            "signature_base64": base64.b64encode(
                _OUTCOME_PRIVATE_KEY.sign(dispatch_outcome_attestation_v2_message(unsigned))
            ).decode("ascii")
        }
    )
    raw = canonical_json(signed.model_dump(mode="python"))
    verified = verify_raw_dispatch_outcome_attestation_v2(
        raw,
        raw_signed_grant=b"raw-signed-grant",
        raw_activation=raw_activation,
        activation_trust_anchor=activation_anchor,
        raw_route_authority=raw_route_authority,
        route_authority_trust_anchor=route_anchor,
        expected_attempt_id=signed.attempt_id,
        trusted_clock=lambda: _NOW,
        response_preimage=canonical_json(response.model_dump(mode="python")),
        output_payload=canonical_json(payload.model_dump(mode="python")),
    )
    assert verified.attestation_sha256 == sha256(raw).hexdigest()
    assert verified.attempt_id == signed.attempt_id
    assert verified.grant_correlation_id == projection.grant_correlation_id == facts.correlation_id
    assert verified.grant_not_before == projection.grant_not_before == facts.not_before
    assert verified.grant_expires_at == projection.grant_expires_at == facts.expires_at
    assert verified.outcome_trust_anchor_sha256 == projection.outcome_trust_anchor_sha256
    assert {"projection", "claim", "outcome_trust_anchor", "execute_enabled"}.isdisjoint(
        inspect.signature(verify_raw_dispatch_outcome_attestation_v2).parameters
    )

    at_grant_expiry = verified.model_dump(mode="python")
    at_grant_expiry["issued_at"] = verified.grant_expires_at
    with pytest.raises(ValidationError, match="outside the verified grant"):
        VerifiedDispatchOutcomeV2.model_validate(at_grant_expiry)

    mismatched = signed.model_copy(update={"target_configuration_sha256": "f" * 64})
    mismatched = mismatched.model_copy(
        update={
            "signature_base64": base64.b64encode(
                _OUTCOME_PRIVATE_KEY.sign(dispatch_outcome_attestation_v2_message(mismatched))
            ).decode("ascii")
        }
    )
    with pytest.raises(DelegationExecutionSignatureError, match="does not match authority"):
        verify_raw_dispatch_outcome_attestation_v2(
            canonical_json(mismatched.model_dump(mode="python")),
            raw_signed_grant=b"raw-signed-grant",
            raw_activation=raw_activation,
            activation_trust_anchor=activation_anchor,
            raw_route_authority=raw_route_authority,
            route_authority_trust_anchor=route_anchor,
            expected_attempt_id=signed.attempt_id,
            trusted_clock=lambda: _NOW,
            response_preimage=canonical_json(response.model_dump(mode="python")),
            output_payload=canonical_json(payload.model_dump(mode="python")),
        )

    for field, value in (
        ("attempt_id", UUID("40000000-0000-4000-8000-000000000007")),
        ("authorization_digest", "0" * 64),
        ("claim_binding_sha256", "0" * 64),
        ("request_sha256", "0" * 64),
        ("backend_id", "backend-beta"),
        ("model_id", "qwen/qwen3.8-27b-alt"),
        ("route_ref", "logical://delegation/qwen3.8-27b-alt"),
        ("activation_id", UUID("40000000-0000-4000-8000-000000000006")),
        ("activation_sha256", "0" * 64),
        ("route_authority_sha256", "0" * 64),
        ("outcome_trust_anchor_sha256", "0" * 64),
        ("signer_key_id", "other-attester"),
        ("trust_anchor_key_id", "other-attester"),
        ("trust_anchor_key_fingerprint_sha256", "0" * 64),
    ):
        divergent = signed.model_copy(update={field: value})
        divergent = divergent.model_copy(
            update={
                "signature_base64": base64.b64encode(
                    _OUTCOME_PRIVATE_KEY.sign(dispatch_outcome_attestation_v2_message(divergent))
                ).decode("ascii")
            }
        )
        with pytest.raises(DelegationExecutionSignatureError, match="does not match authority"):
            verify_raw_dispatch_outcome_attestation_v2(
                canonical_json(divergent.model_dump(mode="python")),
                raw_signed_grant=b"raw-signed-grant",
                raw_activation=raw_activation,
                activation_trust_anchor=activation_anchor,
                raw_route_authority=raw_route_authority,
                route_authority_trust_anchor=route_anchor,
                expected_attempt_id=signed.attempt_id,
                trusted_clock=lambda: _NOW,
                response_preimage=canonical_json(response.model_dump(mode="python")),
                output_payload=canonical_json(payload.model_dump(mode="python")),
            )

    invalid_signature = signed.model_copy(
        update={"signature_base64": base64.b64encode(b"\0" * 64).decode("ascii")}
    )
    with pytest.raises(DelegationExecutionSignatureError, match="signature is invalid"):
        verify_raw_dispatch_outcome_attestation_v2(
            canonical_json(invalid_signature.model_dump(mode="python")),
            raw_signed_grant=b"raw-signed-grant",
            raw_activation=raw_activation,
            activation_trust_anchor=activation_anchor,
            raw_route_authority=raw_route_authority,
            route_authority_trust_anchor=route_anchor,
            expected_attempt_id=signed.attempt_id,
            trusted_clock=lambda: _NOW,
            response_preimage=canonical_json(response.model_dump(mode="python")),
            output_payload=canonical_json(payload.model_dump(mode="python")),
        )

    v1 = DispatchOutcomeAttestationV1(
        schema_version="rsd.dispatch-outcome-attestation.v1",
        attestation_id=signed.attestation_id,
        authorization_digest=signed.authorization_digest,
        claim_binding_sha256=signed.claim_binding_sha256,
        backend_id=signed.backend_id,
        model_id=signed.model_id,
        route_ref=signed.route_ref,
        request_sha256=signed.request_sha256,
        response_sha256=signed.response_sha256,
        output_payload_sha256=signed.output_payload_sha256,
        outcome_status=signed.outcome_status,
        issued_at=signed.issued_at,
        signer_key_id=signed.signer_key_id,
        trust_anchor_key_id=signed.trust_anchor_key_id,
        trust_anchor_key_fingerprint_sha256=signed.trust_anchor_key_fingerprint_sha256,
        signature_base64=base64.b64encode(b"\0" * 64).decode("ascii"),
    )
    v1 = v1.model_copy(
        update={
            "signature_base64": base64.b64encode(
                _OUTCOME_PRIVATE_KEY.sign(dispatch_outcome_attestation_message(v1))
            ).decode("ascii")
        }
    )
    for raw_invalid in (
        canonical_json(v1.model_dump(mode="python")),
        b'{"schema_version":"rsd.dispatch-outcome-attestation.v2","schema_version":"x"}',
        b"{" + (b" " * 32_768) + b"}",
    ):
        with pytest.raises(DispatchOutcomeSignatureError):
            verify_raw_dispatch_outcome_attestation_v2(
                raw_invalid,
                raw_signed_grant=b"raw-signed-grant",
                raw_activation=raw_activation,
                activation_trust_anchor=activation_anchor,
                raw_route_authority=raw_route_authority,
                route_authority_trust_anchor=route_anchor,
                expected_attempt_id=signed.attempt_id,
                trusted_clock=lambda: _NOW,
                response_preimage=canonical_json(response.model_dump(mode="python")),
                output_payload=canonical_json(payload.model_dump(mode="python")),
            )

    for issued_at, trusted_clock in (
        (projection.issued_at - timedelta(microseconds=1), lambda: _NOW),
        (projection.expires_at, lambda: _NOW),
        (projection.expires_at + timedelta(microseconds=1), lambda: _NOW),
        (_NOW + timedelta(microseconds=1), lambda: _NOW),
    ):
        outside_window = unsigned.model_copy(update={"issued_at": issued_at})
        outside_window = outside_window.model_copy(
            update={
                "signature_base64": base64.b64encode(
                    _OUTCOME_PRIVATE_KEY.sign(
                        dispatch_outcome_attestation_v2_message(outside_window)
                    )
                ).decode("ascii")
            }
        )
        with pytest.raises(DelegationExecutionSignatureError, match="does not match authority"):
            verify_raw_dispatch_outcome_attestation_v2(
                canonical_json(outside_window.model_dump(mode="python")),
                raw_signed_grant=b"raw-signed-grant",
                raw_activation=raw_activation,
                activation_trust_anchor=activation_anchor,
                raw_route_authority=raw_route_authority,
                route_authority_trust_anchor=route_anchor,
                expected_attempt_id=signed.attempt_id,
                trusted_clock=trusted_clock,
                response_preimage=canonical_json(response.model_dump(mode="python")),
                output_payload=canonical_json(payload.model_dump(mode="python")),
            )

    at_expiry = unsigned.model_copy(update={"issued_at": projection.expires_at})
    at_expiry = at_expiry.model_copy(
        update={
            "signature_base64": base64.b64encode(
                _OUTCOME_PRIVATE_KEY.sign(dispatch_outcome_attestation_v2_message(at_expiry))
            ).decode("ascii")
        }
    )
    with pytest.raises(DelegationExecutionError, match="activation does not match its authority"):
        verify_raw_dispatch_outcome_attestation_v2(
            canonical_json(at_expiry.model_dump(mode="python")),
            raw_signed_grant=b"raw-signed-grant",
            raw_activation=raw_activation,
            activation_trust_anchor=activation_anchor,
            raw_route_authority=raw_route_authority,
            route_authority_trust_anchor=route_anchor,
            expected_attempt_id=signed.attempt_id,
            trusted_clock=lambda: projection.expires_at,
            response_preimage=canonical_json(response.model_dump(mode="python")),
            output_payload=canonical_json(payload.model_dump(mode="python")),
        )

    for alternate_outcome_anchor in (
        _outcome_anchor(Ed25519PrivateKey.generate()).model_copy(
            update={"signer_key_id": "unrelated-attester"}
        ),
        _outcome_anchor(Ed25519PrivateKey.generate()),
    ):
        alternate_authority = _signed_route_authority_v2(
            claim,
            activation,
            route_key,
            outcome_trust_anchor=alternate_outcome_anchor,
        )
        alternate_raw_authority = canonical_delegation_route_authority_v2_json_bytes(
            alternate_authority
        )
        alternate_activation = activation.model_copy(
            update={
                "route_authority_sha256": delegation_route_authority_v2_sha256(alternate_authority),
                "signature_base64": base64.b64encode(b"\0" * 64).decode("ascii"),
            }
        )
        alternate_activation = alternate_activation.model_copy(
            update={
                "signature_base64": base64.b64encode(
                    activation_key.sign(delegation_execution_overlay_message(alternate_activation))
                ).decode("ascii")
            }
        )
        alternate_raw_activation = canonical_delegation_execution_overlay_json_bytes(
            alternate_activation
        )
        alternate_projection = verify_raw_delegation_execution_authority_v2(
            b"raw-signed-grant",
            alternate_raw_activation,
            activation_trust_anchor=activation_anchor,
            raw_route_authority=alternate_raw_authority,
            route_authority_trust_anchor=route_anchor,
            trusted_clock=lambda: _NOW,
        )
        alternate_unsigned = unsigned.model_copy(
            update={
                "route_authority_sha256": alternate_projection.route_authority_sha256,
                "outcome_trust_anchor_sha256": alternate_projection.outcome_trust_anchor_sha256,
                "signer_key_id": alternate_projection.outcome_trust_anchor_key_id,
                "trust_anchor_key_id": alternate_projection.outcome_trust_anchor_key_id,
                "trust_anchor_key_fingerprint_sha256": (
                    alternate_projection.outcome_trust_anchor_key_fingerprint_sha256
                ),
            }
        )
        alternate_signed = alternate_unsigned.model_copy(
            update={
                "signature_base64": base64.b64encode(
                    _OUTCOME_PRIVATE_KEY.sign(
                        dispatch_outcome_attestation_v2_message(alternate_unsigned)
                    )
                ).decode("ascii")
            }
        )
        with pytest.raises(DelegationExecutionSignatureError, match="signature is invalid"):
            verify_raw_dispatch_outcome_attestation_v2(
                canonical_json(alternate_signed.model_dump(mode="python")),
                raw_signed_grant=b"raw-signed-grant",
                raw_activation=alternate_raw_activation,
                activation_trust_anchor=activation_anchor,
                raw_route_authority=alternate_raw_authority,
                route_authority_trust_anchor=route_anchor,
                expected_attempt_id=alternate_signed.attempt_id,
                trusted_clock=lambda: _NOW,
                response_preimage=canonical_json(response.model_dump(mode="python")),
                output_payload=canonical_json(payload.model_dump(mode="python")),
            )
    with pytest.raises(DelegationExecutionSignatureError, match="preimages do not match"):
        verify_raw_dispatch_outcome_attestation_v2(
            raw,
            raw_signed_grant=b"raw-signed-grant",
            raw_activation=raw_activation,
            activation_trust_anchor=activation_anchor,
            raw_route_authority=raw_route_authority,
            route_authority_trust_anchor=route_anchor,
            expected_attempt_id=signed.attempt_id,
            trusted_clock=lambda: _NOW,
            response_preimage=canonical_json(response.model_dump(mode="python")),
            output_payload=canonical_json(
                payload.model_copy(update={"content": "different"}).model_dump(mode="python")
            ),
        )
    with pytest.raises(DelegationExecutionSignatureError, match="preimages do not match"):
        verify_raw_dispatch_outcome_attestation_v2(
            raw,
            raw_signed_grant=b"raw-signed-grant",
            raw_activation=raw_activation,
            activation_trust_anchor=activation_anchor,
            raw_route_authority=raw_route_authority,
            route_authority_trust_anchor=route_anchor,
            expected_attempt_id=signed.attempt_id,
            trusted_clock=lambda: _NOW,
            response_preimage=canonical_json(
                response.model_copy(update={"output_payload_sha256": "0" * 64}).model_dump(
                    mode="python"
                )
            ),
            output_payload=canonical_json(payload.model_dump(mode="python")),
        )
