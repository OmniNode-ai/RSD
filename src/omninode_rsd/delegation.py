"""Fail-closed delegated-request orchestration with packaged authority."""

from __future__ import annotations

from collections.abc import Callable
from dataclasses import dataclass
from datetime import datetime
from enum import StrEnum
from hashlib import sha256
from importlib.resources import files
from typing import Literal, Protocol
from uuid import UUID

import yaml
from omninode_grant_verifier import SignedExecutableGrantV2, verify_signed_executable_grant_v2
from pydantic import BaseModel, ConfigDict, Field, ValidationError

from omninode_rsd.lifecycle import LifecycleEventIngress, LifecycleEventIntent, LifecycleEventType
from omninode_rsd.lifecycle.event_log import LifecycleEventLog
from omninode_rsd.lifecycle.hashing import canonical_hash
from omninode_rsd.lifecycle.models import strict_model_values

_SHA256 = r"^[0-9a-f]{64}$"
_IDENTIFIER = r"^[a-z][a-z0-9-]{1,63}$"
_MODEL_IDENTIFIER = r"^[a-z][a-z0-9._/-]{2,127}$"
_ROUTE_REF = r"^logical://[a-z0-9./-]+$"
_TOPIC = r"^[a-z][a-z0-9-]*(?:[.][a-z][a-z0-9-]*)+$"
_EVENT_CLASS = r"^Model[A-Za-z0-9]*$"


class _DelegationModel(BaseModel):
    """Strict immutable values that cross the delegation trust boundary."""

    model_config = ConfigDict(extra="forbid", frozen=True, strict=True)


class DelegatedRequest(_DelegationModel):
    """Exact caller facts that must be bound into the signed authorization."""

    run_id: UUID
    request_sha256: str = Field(pattern=_SHA256)
    artifact_sha256: str = Field(pattern=_SHA256)
    rendered_contract_sha256: str = Field(pattern=_SHA256)
    tenant_id: str = Field(pattern=_IDENTIFIER)
    backend_id: str = Field(pattern=_IDENTIFIER)
    model_id: str = Field(pattern=_MODEL_IDENTIFIER)
    route_ref: str = Field(pattern=_ROUTE_REF)
    expected_output_topic: str = Field(pattern=_TOPIC)
    expected_output_event_class: str = Field(pattern=_EVENT_CLASS)
    expected_output_event_index: Literal[0]


class DelegationOverlay(_DelegationModel):
    """Canonical topology-free policy selected by the package composition path."""

    schema_version: Literal["rsd.delegation-overlay.v1"]
    execute_enabled: bool = False
    route_ref: str = Field(pattern=_ROUTE_REF)
    model_ref: str = Field(pattern=_MODEL_IDENTIFIER)


def _canonical_delegation_overlay_bytes() -> bytes:
    """Read the one authority artifact shipped with this package."""

    try:
        return files("omninode_rsd").joinpath("delegation-overlay.yaml").read_bytes()
    except (ModuleNotFoundError, OSError) as error:
        raise ValueError("delegation overlay is unavailable") from error


def load_canonical_delegation_overlay() -> DelegationOverlay:
    """Load the immutable policy authoritative for the production ingress."""

    try:
        value = yaml.safe_load(_canonical_delegation_overlay_bytes())
    except yaml.YAMLError as error:
        raise ValueError("delegation overlay is unavailable") from error
    try:
        return DelegationOverlay.model_validate(value)
    except (TypeError, ValidationError) as error:
        raise ValueError("delegation overlay is invalid") from error


class VerifiedGrantFacts(_DelegationModel):
    """Complete normalized identity and authorization facts from a verified grant."""

    signed_schema_version: Literal["omninode-rsd.signed-executable-grant.v2"]
    authorization_schema_version: Literal["omninode-rsd.grant-authorization-material.v2"]
    authorization_domain: Literal["omninode-rsd.signed-executable-grant.v2"]
    authorization_digest: str = Field(pattern=_SHA256)
    signature_sha256: str = Field(pattern=_SHA256)
    issuer_key_id: str = Field(pattern=_IDENTIFIER)
    issuer_key_fingerprint_sha256: str = Field(pattern=_SHA256)
    grant_id: UUID
    envelope_id: UUID
    activation_id: UUID
    correlation_id: UUID
    nonce_sha256: str = Field(pattern=_SHA256)
    request_sha256: str = Field(pattern=_SHA256)
    artifact_sha256: str = Field(pattern=_SHA256)
    rendered_contract_sha256: str = Field(pattern=_SHA256)
    tenant_id: str = Field(pattern=_IDENTIFIER)
    backend_id: str = Field(pattern=_IDENTIFIER)
    model_id: str = Field(pattern=_MODEL_IDENTIFIER)
    dispatch_policy: Literal["backend-pinned-single-attempt.v1"]
    attempt_count: Literal[1]
    retry_disposition: Literal["forbidden"]
    fallback_used: Literal[False]
    recovery_disposition: Literal["report-only"]
    expected_output_topic: str = Field(pattern=_TOPIC)
    expected_output_event_class: str = Field(pattern=_EVENT_CLASS)
    expected_output_event_index: Literal[0]
    issued_at: datetime
    not_before: datetime
    expires_at: datetime

    @classmethod
    def from_signed_executable_grant(cls, grant: SignedExecutableGrantV2) -> VerifiedGrantFacts:
        """Project every dispatch-relevant signed fact from the public DTO."""

        authorization = grant.authorization_material
        material = authorization.grant
        posture = material.posture
        return cls(
            signed_schema_version=grant.schema_version,
            authorization_schema_version=authorization.schema_version,
            authorization_domain=authorization.domain,
            authorization_digest=grant.authorization_digest,
            signature_sha256=sha256(bytes(grant.signature_octets)).hexdigest(),
            issuer_key_id=authorization.issuer_key_id,
            issuer_key_fingerprint_sha256=authorization.issuer_key_fingerprint_sha256,
            grant_id=material.grant_id,
            envelope_id=material.envelope_id,
            activation_id=material.activation_id,
            correlation_id=material.correlation_id,
            nonce_sha256=material.nonce_sha256,
            request_sha256=material.pins.request_sha256,
            artifact_sha256=material.pins.artifact_sha256,
            rendered_contract_sha256=material.pins.rendered_contract_sha256,
            tenant_id=material.tenant_id,
            backend_id=material.backend_id,
            model_id=material.served_model_id,
            dispatch_policy=material.dispatch_policy,
            attempt_count=posture.attempt_count,
            retry_disposition=posture.retry_disposition,
            fallback_used=posture.fallback_used,
            recovery_disposition=posture.recovery_disposition,
            expected_output_topic=material.expected_output_topic,
            expected_output_event_class=material.expected_output_event_class,
            expected_output_event_index=material.expected_output_event_index,
            issued_at=material.issued_at,
            not_before=material.not_before,
            expires_at=material.expires_at,
        )


type TrustedClock = Callable[[], datetime]


class PublicGrantVerifierAdapter:
    """Typed adapter from the fixed-anchor public verifier to ingress facts."""

    def __init__(self, *, trusted_clock: TrustedClock) -> None:
        self._trusted_clock = trusted_clock

    def __call__(self, grant_wire: bytes) -> VerifiedGrantFacts:
        signed_grant = verify_signed_executable_grant_v2(
            grant_wire,
            now=self._trusted_clock(),
        )
        return VerifiedGrantFacts.from_signed_executable_grant(signed_grant)


class DelegatedGrantClaim(_DelegationModel):
    """The full grant identity consumed by the atomic single-attempt claim."""

    request: DelegatedRequest
    grant: VerifiedGrantFacts
    policy: DelegationOverlay


def delegation_claim_binding_sha256(
    *,
    request: DelegatedRequest,
    grant: VerifiedGrantFacts,
    policy: DelegationOverlay,
) -> str:
    """Return the one durable identity binding for a verified delegation claim.

    Callers must first enforce exact public model types. The complete signed
    request pin is deliberately part of this durable binding. A dispatch
    envelope therefore never embeds this digest: it validates separately as
    the exact preimage of that pin, avoiding a self-referential hash cycle.
    """

    return canonical_hash(
        {
            "schema_version": "rsd.delegation-claim-binding.v1",
            "authorization_domain": grant.authorization_domain,
            "request": request,
            "grant": grant.model_dump(mode="python", exclude={"signature_sha256"}),
            "policy": policy,
        }
    )


class ClaimDisposition(StrEnum):
    """Known results from the durable atomic claim authority."""

    CLAIMED = "claimed"
    NOT_CLAIMED = "not_claimed"


class AtomicClaimPort(Protocol):
    """Consumes the full normalized identity of one signed authorization."""

    def claim(self, claim: DelegatedGrantClaim) -> ClaimDisposition: ...


class DispatchPort(Protocol):
    """Performs the one side effect authorized by an atomically claimed grant."""

    def dispatch(self, claim: DelegatedGrantClaim) -> None: ...


class DelegationSubmissionState(StrEnum):
    """Terminal outcomes; callers must never convert these into an automatic retry."""

    REJECTED_NOT_CLAIMED = "rejected_not_claimed"
    PRECLAIM_PERSISTENCE_FAILED = "preclaim_persistence_failed"
    CLAIM_UNCERTAIN = "claim_uncertain"
    NOT_CLAIMED = "not_claimed"
    CLAIMED_PERSISTENCE_UNCERTAIN = "claimed_persistence_uncertain"
    DISPATCH_UNCERTAIN = "dispatch_uncertain"
    SUCCEEDED = "succeeded"


@dataclass(frozen=True, slots=True)
class DelegationSubmissionResult:
    """A terminal, typed result that does not imply cross-system atomicity."""

    state: DelegationSubmissionState


_REQUEST_FIELD_NAMES = frozenset(DelegatedRequest.model_fields)
_FACT_FIELD_NAMES = frozenset(VerifiedGrantFacts.model_fields)


def _validated_request(value: object) -> DelegatedRequest | None:
    values = strict_model_values(
        value,
        expected_type=DelegatedRequest,
        field_names=_REQUEST_FIELD_NAMES,
    )
    if values is None:
        return None
    try:
        return DelegatedRequest.model_validate(values)
    except ValidationError:
        return None


def _validated_facts(value: object) -> VerifiedGrantFacts | None:
    values = strict_model_values(
        value,
        expected_type=VerifiedGrantFacts,
        field_names=_FACT_FIELD_NAMES,
    )
    if values is None:
        return None
    try:
        return VerifiedGrantFacts.model_validate(values)
    except ValidationError:
        return None


class DelegatedRequestIngress:
    """Use packaged authority, then persist, claim, and attempt one dispatch."""

    def __init__(
        self,
        *,
        trusted_clock: TrustedClock,
        claim_port: AtomicClaimPort,
        dispatch_port: DispatchPort,
        event_log: LifecycleEventLog,
        event_ingress: LifecycleEventIngress,
    ) -> None:
        self._policy = load_canonical_delegation_overlay()
        self._verify_grant = PublicGrantVerifierAdapter(trusted_clock=trusted_clock)
        self._claim_port = claim_port
        self._dispatch_port = dispatch_port
        self._event_log = event_log
        self._event_ingress = event_ingress

    def submit(
        self, request: DelegatedRequest, grant_wire: bytes | None
    ) -> DelegationSubmissionResult:
        """Return one terminal state and never retry claim, persistence, or dispatch."""

        if not self._policy.execute_enabled:
            return self._result(DelegationSubmissionState.REJECTED_NOT_CLAIMED)
        validated_request = _validated_request(request)
        if validated_request is None or type(grant_wire) is not bytes:
            return self._result(DelegationSubmissionState.REJECTED_NOT_CLAIMED)
        try:
            facts = _validated_facts(self._verify_grant(grant_wire))
        except Exception:
            return self._result(DelegationSubmissionState.REJECTED_NOT_CLAIMED)
        if facts is None:
            return self._result(DelegationSubmissionState.REJECTED_NOT_CLAIMED)
        claim = self._claim_for(validated_request, facts)
        if claim is None:
            return self._result(DelegationSubmissionState.REJECTED_NOT_CLAIMED)
        try:
            self._event_log.ingest(
                LifecycleEventIntent(
                    run_id=validated_request.run_id,
                    event_type=LifecycleEventType.RUN_CREATED,
                    detail=(
                        f"delegated claim intent for authorization {facts.authorization_digest}"
                    ),
                ),
                self._event_ingress,
            )
        except Exception:
            return self._result(DelegationSubmissionState.PRECLAIM_PERSISTENCE_FAILED)
        try:
            disposition = self._claim_port.claim(claim)
        except Exception:
            return self._result(DelegationSubmissionState.CLAIM_UNCERTAIN)
        if type(disposition) is not ClaimDisposition:
            return self._result(DelegationSubmissionState.CLAIM_UNCERTAIN)
        if disposition is ClaimDisposition.NOT_CLAIMED:
            return self._result(DelegationSubmissionState.NOT_CLAIMED)
        postclaim_detail = f"delegated grant {facts.grant_id} claimed; authorization recorded"
        try:
            self._event_log.ingest(
                LifecycleEventIntent(
                    run_id=validated_request.run_id,
                    event_type=LifecycleEventType.WORK_STARTED,
                    detail=postclaim_detail,
                ),
                self._event_ingress,
            )
        except Exception:
            return self._result(DelegationSubmissionState.CLAIMED_PERSISTENCE_UNCERTAIN)
        try:
            self._dispatch_port.dispatch(claim)
        except Exception:
            return self._result(DelegationSubmissionState.DISPATCH_UNCERTAIN)
        return self._result(DelegationSubmissionState.SUCCEEDED)

    def _claim_for(
        self, request: DelegatedRequest, facts: VerifiedGrantFacts
    ) -> DelegatedGrantClaim | None:
        if (
            request.run_id != facts.correlation_id
            or request.request_sha256 != facts.request_sha256
            or request.artifact_sha256 != facts.artifact_sha256
            or request.rendered_contract_sha256 != facts.rendered_contract_sha256
            or request.tenant_id != facts.tenant_id
            or request.backend_id != facts.backend_id
            or request.model_id != facts.model_id
            or request.model_id != self._policy.model_ref
            or request.route_ref != self._policy.route_ref
            or request.expected_output_topic != facts.expected_output_topic
            or request.expected_output_event_class != facts.expected_output_event_class
            or request.expected_output_event_index != facts.expected_output_event_index
        ):
            return None
        return DelegatedGrantClaim(request=request, grant=facts, policy=self._policy)

    @staticmethod
    def _result(state: DelegationSubmissionState) -> DelegationSubmissionResult:
        return DelegationSubmissionResult(state=state)
