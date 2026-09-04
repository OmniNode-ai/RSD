"""Tests for the pure bounded delegated-dispatch contract layer."""

from __future__ import annotations

import base64
import json
from datetime import UTC, datetime
from hashlib import sha256
from pathlib import Path
from uuid import UUID, uuid4

import pytest
import yaml
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey

from omninode_rsd.delegation import (
    DelegatedGrantClaim,
    DelegatedRequest,
    DelegationOverlay,
    VerifiedGrantFacts,
    delegation_claim_binding_sha256,
)
from omninode_rsd.lifecycle.dispatch_attestation import (
    DispatchCompletedOutputPayloadV1,
    DispatchFailedOutputPayloadV1,
    DispatchOutcomeAttestationV1,
    DispatchOutcomeReplayAmbiguousError,
    DispatchOutcomeReplayAuthority,
    DispatchOutcomeReplayClaimV1,
    DispatchOutcomeReplayDisposition,
    DispatchOutcomeReplayError,
    DispatchOutcomeSignatureError,
    DispatchOutcomeTrustAnchorV1,
    DispatchRequestEnvelopeError,
    DispatchRequestEnvelopeV1,
    DispatchResponsePreimageV1,
    OpenAIChatCompletionRequestV1,
    OpenAIChatMessageV1,
    canonical_dispatch_output_payload_bytes,
    canonical_dispatch_request_envelope_bytes,
    canonical_dispatch_response_preimage_bytes,
    dispatch_outcome_attestation_message,
    dispatch_output_payload_sha256,
    dispatch_response_sha256,
    parse_dispatch_outcome_attestation,
    parse_dispatch_output_payload,
    parse_dispatch_request_envelope,
    parse_dispatch_response_preimage,
    validate_dispatch_request_envelope,
    verify_dispatch_outcome_attestation,
)
from omninode_rsd.lifecycle.hashing import canonical_json

_NOW = datetime(2030, 1, 1, tzinfo=UTC)
_VECTOR = (
    Path(__file__).parents[2] / "src/omninode_rsd/lifecycle/dispatch_attestation_public_vector.yaml"
)
_VECTOR_SHA256 = "f1f903e219136f61c15529583117f53caa0d026bec4dd24bbad8765360186b35"


class _ReplayAuthority(DispatchOutcomeReplayAuthority):
    def __init__(self) -> None:
        self._claims: dict[UUID, str] = {}
        self.calls = 0

    def claim(self, claim: DispatchOutcomeReplayClaimV1) -> DispatchOutcomeReplayDisposition:
        self.calls += 1
        existing = self._claims.get(claim.attestation_id)
        if existing is None:
            self._claims[claim.attestation_id] = claim.attestation_sha256
            return DispatchOutcomeReplayDisposition.CLAIMED
        if existing == claim.attestation_sha256:
            return DispatchOutcomeReplayDisposition.REPLAYED
        return DispatchOutcomeReplayDisposition.CONFLICT


class _AmbiguousReplayAuthority(DispatchOutcomeReplayAuthority):
    def claim(self, claim: DispatchOutcomeReplayClaimV1) -> DispatchOutcomeReplayDisposition:
        del claim
        raise OSError("replay authority unavailable")


def _synthetic_facts(*, request_sha256: str) -> VerifiedGrantFacts:
    """Return explicit unsigned facts for the synthetic public vector only."""

    return VerifiedGrantFacts.model_construct(
        signed_schema_version="omninode-rsd.signed-executable-grant.v2",
        authorization_schema_version="omninode-rsd.grant-authorization-material.v2",
        authorization_domain="omninode-rsd.signed-executable-grant.v2",
        authorization_digest="1" * 64,
        signature_sha256="2" * 64,
        issuer_key_id="synthetic-issuer",
        issuer_key_fingerprint_sha256="3" * 64,
        grant_id=UUID("10000000-0000-4000-8000-000000000001"),
        envelope_id=UUID("10000000-0000-4000-8000-000000000002"),
        activation_id=UUID("10000000-0000-4000-8000-000000000003"),
        correlation_id=UUID("10000000-0000-4000-8000-000000000004"),
        nonce_sha256="4" * 64,
        request_sha256=request_sha256,
        artifact_sha256="5" * 64,
        rendered_contract_sha256="6" * 64,
        tenant_id="synthetic-tenant",
        backend_id="synthetic-backend",
        model_id="synthetic-model-v1",
        dispatch_policy="backend-pinned-single-attempt.v1",
        attempt_count=1,
        retry_disposition="forbidden",
        fallback_used=False,
        recovery_disposition="report-only",
        expected_output_topic="events.synthetic.completed.v1",
        expected_output_event_class="ModelSyntheticCompleted",
        expected_output_event_index=0,
        issued_at=datetime(2029, 1, 1, tzinfo=UTC),
        not_before=datetime(2029, 1, 1, tzinfo=UTC),
        expires_at=datetime(2031, 1, 1, tzinfo=UTC),
    )


def _request(facts: VerifiedGrantFacts, *, request_sha256: str) -> DelegatedRequest:
    return DelegatedRequest(
        run_id=facts.correlation_id,
        request_sha256=request_sha256,
        artifact_sha256=facts.artifact_sha256,
        rendered_contract_sha256=facts.rendered_contract_sha256,
        tenant_id=facts.tenant_id,
        backend_id=facts.backend_id,
        model_id=facts.model_id,
        route_ref="logical://delegation/public-demo",
        expected_output_topic=facts.expected_output_topic,
        expected_output_event_class=facts.expected_output_event_class,
        expected_output_event_index=facts.expected_output_event_index,
    )


def _policy(facts: VerifiedGrantFacts) -> DelegationOverlay:
    return DelegationOverlay(
        schema_version="rsd.delegation-overlay.v1",
        execute_enabled=False,
        route_ref="logical://delegation/public-demo",
        model_ref=facts.model_id,
    )


def _claim_and_envelope() -> tuple[DelegatedGrantClaim, bytes]:
    facts = _synthetic_facts(request_sha256="0" * 64)
    initial_request = _request(facts, request_sha256=facts.request_sha256)
    envelope = DispatchRequestEnvelopeV1(
        schema_version="rsd.dispatch-request-envelope.v1",
        authorization_digest=facts.authorization_digest,
        backend_id=facts.backend_id,
        model_id=facts.model_id,
        route_ref=initial_request.route_ref,
        request=OpenAIChatCompletionRequestV1(
            schema_version="rsd.openai-chat-completion-request.v1",
            model_id=facts.model_id,
            messages=(OpenAIChatMessageV1(role="user", content="bounded test request"),),
            max_output_tokens=64,
            stream=False,
        ),
    )
    raw = canonical_dispatch_request_envelope_bytes(envelope)
    final_facts = _synthetic_facts(request_sha256=sha256(raw).hexdigest())
    final_request = _request(final_facts, request_sha256=final_facts.request_sha256)
    final_claim = DelegatedGrantClaim(
        request=final_request,
        grant=final_facts,
        policy=_policy(final_facts),
    )
    return final_claim, raw


def _claim_binding(claim: DelegatedGrantClaim) -> str:
    return delegation_claim_binding_sha256(
        request=claim.request,
        grant=claim.grant,
        policy=claim.policy,
    )


def _anchor(private_key: Ed25519PrivateKey) -> DispatchOutcomeTrustAnchorV1:
    public_key = private_key.public_key().public_bytes_raw()
    return DispatchOutcomeTrustAnchorV1(
        schema_version="rsd.dispatch-outcome-trust-anchor.v1",
        trust_domain="omninode-rsd.dispatch-outcome-attestation.v1",
        signer_key_id="dispatch-attestor",
        signer_public_key_base64=base64.b64encode(public_key).decode("ascii"),
        signer_key_fingerprint_sha256=sha256(public_key).hexdigest(),
    )


def _attestation_bytes(
    claim: DelegatedGrantClaim,
    private_key: Ed25519PrivateKey,
    *,
    attestation_id: UUID | None = None,
    outcome_status: str = "completed",
) -> tuple[bytes, DispatchOutcomeTrustAnchorV1, bytes, bytes]:
    anchor = _anchor(private_key)
    if outcome_status == "completed":
        payload = DispatchCompletedOutputPayloadV1(
            schema_version="rsd.dispatch-completed-output-payload.v1",
            content="bounded test response",
        )
    else:
        payload = DispatchFailedOutputPayloadV1(
            schema_version="rsd.dispatch-failed-output-payload.v1",
            failure_code="service_failed",
        )
    output_payload = canonical_dispatch_output_payload_bytes(payload)
    response = DispatchResponsePreimageV1(
        schema_version="rsd.dispatch-response-preimage.v1",
        outcome_status=outcome_status,  # type: ignore[arg-type]
        output_payload_sha256=dispatch_output_payload_sha256(payload),
    )
    response_preimage = canonical_dispatch_response_preimage_bytes(response)
    unsigned = DispatchOutcomeAttestationV1(
        schema_version="rsd.dispatch-outcome-attestation.v1",
        attestation_id=uuid4() if attestation_id is None else attestation_id,
        authorization_digest=claim.grant.authorization_digest,
        claim_binding_sha256=_claim_binding(claim),
        backend_id=claim.request.backend_id,
        model_id=claim.request.model_id,
        route_ref=claim.request.route_ref,
        request_sha256=claim.request.request_sha256,
        response_sha256=dispatch_response_sha256(response),
        output_payload_sha256=dispatch_output_payload_sha256(payload),
        outcome_status=outcome_status,  # type: ignore[arg-type]
        issued_at=_NOW,
        signer_key_id=anchor.signer_key_id,
        trust_anchor_key_id=anchor.signer_key_id,
        trust_anchor_key_fingerprint_sha256=anchor.signer_key_fingerprint_sha256,
        signature_base64=base64.b64encode(b"\x00" * 64).decode("ascii"),
    )
    signed = unsigned.model_copy(
        update={
            "signature_base64": base64.b64encode(
                private_key.sign(dispatch_outcome_attestation_message(unsigned))
            ).decode("ascii")
        }
    )
    return (
        canonical_json(signed.model_dump(mode="python")),
        anchor,
        response_preimage,
        output_payload,
    )


def test_canonical_request_envelope_is_the_exact_signed_request_preimage() -> None:
    claim, raw = _claim_and_envelope()

    result = validate_dispatch_request_envelope(raw, claim)

    assert result.request.model_id == claim.request.model_id
    assert sha256(raw).hexdigest() == claim.request.request_sha256
    assert _claim_binding(claim) != ""


def test_public_vector_verifies_the_complete_request_and_outcome_contract() -> None:
    raw_vector = _VECTOR.read_bytes()
    assert sha256(raw_vector).hexdigest() == _VECTOR_SHA256
    loaded = yaml.safe_load(raw_vector)
    assert type(loaded) is dict
    assert set(loaded) == {
        "schema_version",
        "purpose",
        "request_envelope_base64",
        "request_envelope_sha256",
        "response_preimage_base64",
        "response_preimage_sha256",
        "output_payload_base64",
        "output_payload_sha256",
        "outcome_attestation_base64_segments",
        "outcome_attestation_sha256",
        "trust_anchor",
    }
    assert loaded["schema_version"] == "rsd.dispatch-attestation-public-vector.v1"
    assert loaded["purpose"] == "synthetic_unsigned_claim_facts_request_and_authenticated_outcome"
    assert type(loaded["request_envelope_base64"]) is str
    assert type(loaded["request_envelope_sha256"]) is str
    assert type(loaded["response_preimage_base64"]) is str
    assert type(loaded["response_preimage_sha256"]) is str
    assert type(loaded["output_payload_base64"]) is str
    assert type(loaded["output_payload_sha256"]) is str
    assert type(loaded["outcome_attestation_base64_segments"]) is list
    assert type(loaded["outcome_attestation_sha256"]) is str
    assert type(loaded["trust_anchor"]) is dict
    request_raw = base64.b64decode(loaded["request_envelope_base64"], validate=True)
    response_preimage = base64.b64decode(loaded["response_preimage_base64"], validate=True)
    output_payload = base64.b64decode(loaded["output_payload_base64"], validate=True)
    encoded_segments = loaded["outcome_attestation_base64_segments"]
    assert all(type(segment) is str for segment in encoded_segments)
    outcome_raw = base64.b64decode("".join(encoded_segments), validate=True)
    assert sha256(request_raw).hexdigest() == loaded["request_envelope_sha256"]
    assert sha256(response_preimage).hexdigest() == loaded["response_preimage_sha256"]
    assert sha256(output_payload).hexdigest() == loaded["output_payload_sha256"]
    assert sha256(outcome_raw).hexdigest() == loaded["outcome_attestation_sha256"]
    claim, expected_request_raw = _claim_and_envelope()
    assert request_raw == expected_request_raw
    assert validate_dispatch_request_envelope(request_raw, claim).model_id == claim.request.model_id
    anchor = DispatchOutcomeTrustAnchorV1.model_validate(loaded["trust_anchor"])
    assert (
        verify_dispatch_outcome_attestation(
            outcome_raw,
            claim=claim,
            trust_anchor=anchor,
            trusted_clock=lambda: _NOW,
            replay_authority=_ReplayAuthority(),
            response_preimage=response_preimage,
            output_payload=output_payload,
        ).outcome_status
        == "completed"
    )


@pytest.mark.parametrize(
    "raw",
    (
        b'{"schema_version":"rsd.dispatch-request-envelope.v1"}',
        b"{ }",
        b"x" * 131_073,
    ),
)
def test_request_envelope_rejects_invalid_or_oversize_bytes(raw: bytes) -> None:
    with pytest.raises(DispatchRequestEnvelopeError):
        parse_dispatch_request_envelope(raw)


def test_canonical_request_serializer_rejects_an_aggregate_oversize_envelope() -> None:
    claim, _ = _claim_and_envelope()
    envelope = DispatchRequestEnvelopeV1(
        schema_version="rsd.dispatch-request-envelope.v1",
        authorization_digest=claim.grant.authorization_digest,
        backend_id=claim.request.backend_id,
        model_id=claim.request.model_id,
        route_ref=claim.request.route_ref,
        request=OpenAIChatCompletionRequestV1(
            schema_version="rsd.openai-chat-completion-request.v1",
            model_id=claim.request.model_id,
            messages=(OpenAIChatMessageV1(role="user", content="x" * 16_384),) * 32,
            max_output_tokens=64,
            stream=False,
        ),
    )

    with pytest.raises(DispatchRequestEnvelopeError, match="allowed bound"):
        canonical_dispatch_request_envelope_bytes(envelope)


def test_request_envelope_rejects_noncanonical_and_unknown_shapes() -> None:
    _, raw = _claim_and_envelope()
    decoded = json.loads(raw)
    decoded["unexpected"] = "value"
    unknown = json.dumps(decoded, separators=(",", ":"), sort_keys=True).encode("ascii")

    with pytest.raises(DispatchRequestEnvelopeError, match="invalid"):
        parse_dispatch_request_envelope(unknown)
    with pytest.raises(DispatchRequestEnvelopeError, match="canonically encoded"):
        parse_dispatch_request_envelope(b" " + raw)


def test_request_envelope_rejects_every_authorization_mismatch() -> None:
    claim, raw = _claim_and_envelope()
    changed = claim.model_copy(
        update={"request": claim.request.model_copy(update={"backend_id": "other-backend"})}
    )

    with pytest.raises(DispatchRequestEnvelopeError, match="coherent"):
        validate_dispatch_request_envelope(raw, changed)


def test_request_envelope_rejects_a_forged_request_pin_that_disagrees_with_grant() -> None:
    claim, raw = _claim_and_envelope()
    forged = DelegatedGrantClaim.model_construct(
        request=claim.request.model_copy(update={"request_sha256": "0" * 64}),
        grant=claim.grant,
        policy=claim.policy,
    )

    with pytest.raises(DispatchRequestEnvelopeError, match="coherent"):
        validate_dispatch_request_envelope(raw, forged)


def test_result_preimages_are_canonical_domain_separated_and_redact_failure() -> None:
    completed = DispatchCompletedOutputPayloadV1(
        schema_version="rsd.dispatch-completed-output-payload.v1",
        content="bounded completed output",
    )
    completed_raw = canonical_dispatch_output_payload_bytes(completed)
    response = DispatchResponsePreimageV1(
        schema_version="rsd.dispatch-response-preimage.v1",
        outcome_status="completed",
        output_payload_sha256=dispatch_output_payload_sha256(completed),
    )
    response_raw = canonical_dispatch_response_preimage_bytes(response)

    assert parse_dispatch_output_payload(completed_raw) == completed
    assert parse_dispatch_response_preimage(response_raw) == response
    assert dispatch_output_payload_sha256(completed) != sha256(completed_raw).hexdigest()
    assert dispatch_response_sha256(response) != sha256(response_raw).hexdigest()

    failed = DispatchFailedOutputPayloadV1(
        schema_version="rsd.dispatch-failed-output-payload.v1",
        failure_code="model_unavailable",
    )
    assert parse_dispatch_output_payload(canonical_dispatch_output_payload_bytes(failed)) == failed
    assert failed.model_dump() == {
        "schema_version": "rsd.dispatch-failed-output-payload.v1",
        "failure_code": "model_unavailable",
    }


def test_result_preimages_reject_noncanonical_or_oversize_bytes() -> None:
    payload = DispatchCompletedOutputPayloadV1(
        schema_version="rsd.dispatch-completed-output-payload.v1",
        content="bounded output",
    )
    raw = canonical_dispatch_output_payload_bytes(payload)
    response = DispatchResponsePreimageV1(
        schema_version="rsd.dispatch-response-preimage.v1",
        outcome_status="completed",
        output_payload_sha256=dispatch_output_payload_sha256(payload),
    )

    with pytest.raises(DispatchOutcomeSignatureError, match="not canonically encoded"):
        parse_dispatch_output_payload(b" " + raw)
    with pytest.raises(DispatchOutcomeSignatureError, match="allowed bound"):
        parse_dispatch_output_payload(b"x" * 65_537)
    with pytest.raises(DispatchOutcomeSignatureError, match="allowed bound"):
        canonical_dispatch_output_payload_bytes(
            DispatchCompletedOutputPayloadV1(
                schema_version="rsd.dispatch-completed-output-payload.v1",
                content="x" * 65_536,
            )
        )
    with pytest.raises(DispatchOutcomeSignatureError, match="not canonically encoded"):
        parse_dispatch_response_preimage(
            b" " + canonical_dispatch_response_preimage_bytes(response)
        )


def test_outcome_attestation_rejects_tampered_preimages_before_replay_and_accepts_failure() -> None:
    claim, _ = _claim_and_envelope()
    private_key = Ed25519PrivateKey.generate()
    raw, anchor, response_preimage, output_payload = _attestation_bytes(claim, private_key)
    replay = _ReplayAuthority()
    tampered_payload = canonical_dispatch_output_payload_bytes(
        DispatchCompletedOutputPayloadV1(
            schema_version="rsd.dispatch-completed-output-payload.v1",
            content="different bounded output",
        )
    )

    with pytest.raises(DispatchOutcomeSignatureError, match="preimages do not match"):
        verify_dispatch_outcome_attestation(
            raw,
            claim=claim,
            trust_anchor=anchor,
            trusted_clock=lambda: _NOW,
            replay_authority=replay,
            response_preimage=response_preimage,
            output_payload=tampered_payload,
        )
    assert replay.calls == 0

    tampered_response = canonical_dispatch_response_preimage_bytes(
        DispatchResponsePreimageV1(
            schema_version="rsd.dispatch-response-preimage.v1",
            outcome_status="completed",
            output_payload_sha256="0" * 64,
        )
    )
    with pytest.raises(DispatchOutcomeSignatureError, match="preimages do not match"):
        verify_dispatch_outcome_attestation(
            raw,
            claim=claim,
            trust_anchor=anchor,
            trusted_clock=lambda: _NOW,
            replay_authority=replay,
            response_preimage=tampered_response,
            output_payload=output_payload,
        )
    assert replay.calls == 0

    with pytest.raises(DispatchOutcomeSignatureError, match="allowed bound"):
        verify_dispatch_outcome_attestation(
            raw,
            claim=claim,
            trust_anchor=anchor,
            trusted_clock=lambda: _NOW,
            replay_authority=replay,
            response_preimage=b"x" * 8_193,
            output_payload=output_payload,
        )
    assert replay.calls == 0

    failed_raw, failed_anchor, failed_response, failed_payload = _attestation_bytes(
        claim,
        private_key,
        outcome_status="failed",
    )
    assert (
        verify_dispatch_outcome_attestation(
            failed_raw,
            claim=claim,
            trust_anchor=failed_anchor,
            trusted_clock=lambda: _NOW,
            replay_authority=_ReplayAuthority(),
            response_preimage=failed_response,
            output_payload=failed_payload,
        ).outcome_status
        == "failed"
    )


def test_outcome_attestation_verifies_complete_binding_signature_and_single_use() -> None:
    claim, _ = _claim_and_envelope()
    private_key = Ed25519PrivateKey.generate()
    raw, anchor, response_preimage, output_payload = _attestation_bytes(claim, private_key)
    replay = _ReplayAuthority()

    verified = verify_dispatch_outcome_attestation(
        raw,
        claim=claim,
        trust_anchor=anchor,
        trusted_clock=lambda: _NOW,
        replay_authority=replay,
        response_preimage=response_preimage,
        output_payload=output_payload,
    )

    assert verified.outcome_status == "completed"
    assert replay.calls == 1
    with pytest.raises(DispatchOutcomeReplayError):
        verify_dispatch_outcome_attestation(
            raw,
            claim=claim,
            trust_anchor=anchor,
            trusted_clock=lambda: _NOW,
            replay_authority=replay,
            response_preimage=response_preimage,
            output_payload=output_payload,
        )
    assert replay.calls == 2


def test_outcome_attestation_rejects_signature_mismatch_before_replay_claim() -> None:
    claim, _ = _claim_and_envelope()
    private_key = Ed25519PrivateKey.generate()
    raw, anchor, response_preimage, output_payload = _attestation_bytes(claim, private_key)
    decoded = json.loads(raw)
    decoded["model_id"] = "model-other-v2"
    tampered = json.dumps(decoded, separators=(",", ":"), sort_keys=True).encode("ascii")
    replay = _ReplayAuthority()

    with pytest.raises(DispatchOutcomeSignatureError):
        verify_dispatch_outcome_attestation(
            tampered,
            claim=claim,
            trust_anchor=anchor,
            trusted_clock=lambda: _NOW,
            replay_authority=replay,
            response_preimage=response_preimage,
            output_payload=output_payload,
        )
    assert replay.calls == 0


def test_outcome_attestation_rejects_noncanonical_bytes_and_forged_anchor_scalar() -> None:
    class EvilString(str):
        pass

    claim, _ = _claim_and_envelope()
    private_key = Ed25519PrivateKey.generate()
    raw, anchor, response_preimage, output_payload = _attestation_bytes(claim, private_key)
    forged_anchor = anchor.model_copy(update={"signer_key_id": EvilString(anchor.signer_key_id)})

    with pytest.raises(DispatchOutcomeSignatureError, match="not canonically encoded"):
        parse_dispatch_outcome_attestation(b" " + raw)
    with pytest.raises(DispatchOutcomeSignatureError, match="non-exact scalar"):
        verify_dispatch_outcome_attestation(
            raw,
            claim=claim,
            trust_anchor=forged_anchor,
            trusted_clock=lambda: _NOW,
            replay_authority=_ReplayAuthority(),
            response_preimage=response_preimage,
            output_payload=output_payload,
        )


def test_outcome_attestation_rejects_conflicting_replay_identity_and_authority_ambiguity() -> None:
    claim, _ = _claim_and_envelope()
    private_key = Ed25519PrivateKey.generate()
    attestation_id = uuid4()
    first, anchor, first_response, first_payload = _attestation_bytes(
        claim, private_key, attestation_id=attestation_id
    )
    second, _, second_response, second_payload = _attestation_bytes(
        claim,
        private_key,
        attestation_id=attestation_id,
        outcome_status="failed",
    )
    replay = _ReplayAuthority()

    verify_dispatch_outcome_attestation(
        first,
        claim=claim,
        trust_anchor=anchor,
        trusted_clock=lambda: _NOW,
        replay_authority=replay,
        response_preimage=first_response,
        output_payload=first_payload,
    )
    with pytest.raises(DispatchOutcomeReplayAmbiguousError):
        verify_dispatch_outcome_attestation(
            second,
            claim=claim,
            trust_anchor=anchor,
            trusted_clock=lambda: _NOW,
            replay_authority=replay,
            response_preimage=second_response,
            output_payload=second_payload,
        )
    with pytest.raises(DispatchOutcomeReplayAmbiguousError):
        verify_dispatch_outcome_attestation(
            first,
            claim=claim,
            trust_anchor=anchor,
            trusted_clock=lambda: _NOW,
            replay_authority=_AmbiguousReplayAuthority(),
            response_preimage=first_response,
            output_payload=first_payload,
        )


def test_outcome_attestation_rejects_a_claim_forged_after_verification() -> None:
    claim, _ = _claim_and_envelope()
    private_key = Ed25519PrivateKey.generate()
    raw, anchor, response_preimage, output_payload = _attestation_bytes(claim, private_key)
    forged = DelegatedGrantClaim.model_construct(
        request=claim.request.model_copy(update={"tenant_id": "other-tenant"}),
        grant=claim.grant,
        policy=claim.policy,
    )

    with pytest.raises(DispatchOutcomeSignatureError):
        verify_dispatch_outcome_attestation(
            raw,
            claim=forged,
            trust_anchor=anchor,
            trusted_clock=lambda: _NOW,
            replay_authority=_ReplayAuthority(),
            response_preimage=response_preimage,
            output_payload=output_payload,
        )
