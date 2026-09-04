from __future__ import annotations

import inspect
import json
from datetime import UTC, datetime
from typing import cast
from uuid import UUID, uuid4

import pytest
from omninode_grant_verifier import signed_executable_grant_v2_vectors
from pydantic import ValidationError

import omninode_rsd.delegation as delegation
from omninode_rsd.delegation import (
    AtomicClaimPort,
    ClaimDisposition,
    DelegatedGrantClaim,
    DelegatedRequest,
    DelegatedRequestIngress,
    DelegationSubmissionState,
    DispatchPort,
    PublicGrantVerifierAdapter,
    VerifiedGrantFacts,
    delegation_claim_binding_sha256,
    load_canonical_delegation_overlay,
)
from omninode_rsd.lifecycle import (
    InMemoryEventLog,
    LifecycleEvent,
    LifecycleEventIngress,
    LifecycleEventIntent,
    LifecycleEventType,
)
from omninode_rsd.lifecycle.postgres import (
    DelegationClaimIdentityV1,
    DelegationClaimResult,
    PostgresDelegationClaimStore,
)
from omninode_rsd.lifecycle.postgres.delegation_claim_port import PostgresAtomicClaimPort

_NOW = datetime(2030, 1, 1, tzinfo=UTC)


def _valid_wire() -> bytes:
    vectors = signed_executable_grant_v2_vectors()
    base = vectors["base_wire"]
    assert type(base) is dict
    return json.dumps(base, separators=(",", ":")).encode("utf-8")


def _facts() -> VerifiedGrantFacts:
    return PublicGrantVerifierAdapter(trusted_clock=lambda: _NOW)(_valid_wire())


def _request(facts: VerifiedGrantFacts | None = None) -> DelegatedRequest:
    facts = _facts() if facts is None else facts
    return DelegatedRequest(
        run_id=facts.correlation_id,
        request_sha256=facts.request_sha256,
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


def _enabled_overlay_bytes(facts: VerifiedGrantFacts) -> bytes:
    return (
        "\n".join(
            (
                'schema_version: "rsd.delegation-overlay.v1"',
                "execute_enabled: true",
                'route_ref: "logical://delegation/public-demo"',
                f'model_ref: "{facts.model_id}"',
            )
        )
        + "\n"
    ).encode("utf-8")


def _enable_canonical_overlay(monkeypatch: pytest.MonkeyPatch, facts: VerifiedGrantFacts) -> None:
    monkeypatch.setattr(
        delegation,
        "_canonical_delegation_overlay_bytes",
        lambda: _enabled_overlay_bytes(facts),
    )


class _Claim(AtomicClaimPort):
    def __init__(
        self,
        disposition: ClaimDisposition = ClaimDisposition.CLAIMED,
        *,
        order: list[str] | None = None,
        error: Exception | None = None,
    ) -> None:
        self.disposition = disposition
        self.order = order
        self.error = error
        self.calls = 0
        self.claims: list[DelegatedGrantClaim] = []

    def claim(self, claim: DelegatedGrantClaim) -> ClaimDisposition:
        self.calls += 1
        self.claims.append(claim)
        if self.order is not None:
            self.order.append("claim")
        if self.error is not None:
            raise self.error
        return self.disposition


class _Dispatch(DispatchPort):
    def __init__(self, *, order: list[str] | None = None, error: Exception | None = None) -> None:
        self.order = order
        self.error = error
        self.calls = 0
        self.claims: list[DelegatedGrantClaim] = []

    def dispatch(self, claim: DelegatedGrantClaim) -> None:
        self.calls += 1
        self.claims.append(claim)
        if self.order is not None:
            self.order.append("dispatch")
        if self.error is not None:
            raise self.error


class _PostgresClaimStore:
    def __init__(self) -> None:
        self.identities: list[DelegationClaimIdentityV1] = []

    def claim(self, identity: DelegationClaimIdentityV1) -> DelegationClaimResult:
        self.identities.append(identity)
        return DelegationClaimResult.CLAIMED


class _RecordingLog:
    def __init__(
        self, *, order: list[str] | None = None, fail_on_ingest: int | None = None
    ) -> None:
        self._log = InMemoryEventLog()
        self._order = order
        self._fail_on_ingest = fail_on_ingest
        self.ingest_calls = 0

    def append(self, event: LifecycleEvent) -> None:
        self._log.append(event)

    def ingest(
        self,
        intent: LifecycleEventIntent | dict[str, object],
        builder: LifecycleEventIngress,
    ) -> LifecycleEvent:
        self.ingest_calls += 1
        if self._order is not None:
            event_type = intent.event_type if type(intent) is LifecycleEventIntent else "unknown"
            self._order.append(f"ingest:{event_type}")
        if self._fail_on_ingest == self.ingest_calls:
            raise OSError("durable lifecycle store is unavailable")
        return self._log.ingest(intent, builder)

    def events_for(self, run_id: UUID) -> tuple[LifecycleEvent, ...]:
        return self._log.events_for(run_id)


def _ingress(
    claim: AtomicClaimPort,
    dispatch: DispatchPort,
    log: _RecordingLog | None = None,
) -> DelegatedRequestIngress:
    return DelegatedRequestIngress(
        trusted_clock=lambda: _NOW,
        claim_port=claim,
        dispatch_port=dispatch,
        event_log=_RecordingLog() if log is None else log,
        event_ingress=LifecycleEventIngress(),
    )


def test_public_ingress_has_no_policy_or_verifier_substitution_surface() -> None:
    parameters = inspect.signature(DelegatedRequestIngress).parameters

    assert {"policy", "verify_grant", "verifier", "overlay"}.isdisjoint(parameters)
    assert not hasattr(DelegatedRequestIngress, "from_canonical_public_verifier")
    assert not hasattr(delegation, "load_delegation_overlay")
    assert not hasattr(delegation, "canonical_delegation_overlay_path")


def test_canonical_overlay_is_immutable_packaged_authority() -> None:
    overlay = load_canonical_delegation_overlay()

    assert not overlay.execute_enabled
    with pytest.raises(ValidationError):
        overlay.execute_enabled = True


def test_disabled_canonical_policy_rejects_before_every_dependency(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    facts = _facts()

    def fail_verifier(_: PublicGrantVerifierAdapter, __: bytes) -> VerifiedGrantFacts:
        raise AssertionError("disabled policy must reject before verification")

    monkeypatch.setattr(PublicGrantVerifierAdapter, "__call__", fail_verifier)
    claim, dispatch, log = _Claim(), _Dispatch(), _RecordingLog()

    result = _ingress(claim, dispatch, log).submit(_request(facts), _valid_wire())

    assert result.state is DelegationSubmissionState.REJECTED_NOT_CLAIMED
    assert claim.calls == dispatch.calls == log.ingest_calls == 0


def test_public_verifier_adapter_projects_full_identity() -> None:
    facts = _facts()

    assert (
        facts.authorization_digest
        == "e03cc6144006dafba4e7bc085ca5511e3f40b5ab9b73f3c28b0dbb3a60368d2d"
    )
    assert facts.grant_id == UUID("40000000-0000-4000-8000-000000000001")
    assert facts.nonce_sha256 == "1" * 64
    assert facts.tenant_id == "public-demo" and facts.backend_id == "provider-alpha"
    assert facts.model_id == "model-public-v2"
    assert facts.dispatch_policy == "backend-pinned-single-attempt.v1"
    assert facts.expected_output_topic == "events.public.grant.completed.v2"
    assert facts.expected_output_event_class == "ModelPublicGrantCompleted"
    assert facts.attempt_count == 1
    assert facts.retry_disposition == "forbidden"
    assert not facts.fallback_used and facts.recovery_disposition == "report-only"


def test_postgres_claim_adapter_binds_all_semantic_claim_material_not_transport_signature() -> None:
    facts = _facts()
    request = _request(facts)
    claim = DelegatedGrantClaim(
        request=request,
        grant=facts,
        policy=load_canonical_delegation_overlay(),
    )
    store = _PostgresClaimStore()
    adapter = PostgresAtomicClaimPort(cast(PostgresDelegationClaimStore, store))

    assert adapter.claim(claim) is ClaimDisposition.CLAIMED
    signature_changed = claim.model_copy(
        update={"grant": facts.model_copy(update={"signature_sha256": "f" * 64})}
    )
    assert adapter.claim(signature_changed) is ClaimDisposition.CLAIMED
    semantic_change = claim.model_copy(
        update={"request": request.model_copy(update={"tenant_id": "other-tenant"})}
    )
    assert adapter.claim(semantic_change) is ClaimDisposition.CLAIMED
    request_pin_changed = claim.model_copy(
        update={"request": request.model_copy(update={"request_sha256": "a" * 64})}
    )
    assert adapter.claim(request_pin_changed) is ClaimDisposition.CLAIMED

    assert store.identities[0].authorization_digest == facts.authorization_digest
    assert store.identities[0].claim_binding_sha256 == delegation_claim_binding_sha256(
        request=request,
        grant=facts,
        policy=load_canonical_delegation_overlay(),
    )
    assert store.identities[0].claim_binding_sha256 == store.identities[1].claim_binding_sha256
    assert store.identities[0].claim_binding_sha256 != store.identities[2].claim_binding_sha256
    assert store.identities[0].claim_binding_sha256 != store.identities[3].claim_binding_sha256


def test_postgres_claim_adapter_rejects_constructed_scalar_subclass_before_store() -> None:
    class EvilString(str):
        pass

    facts = _facts()
    request = _request(facts).model_copy(update={"tenant_id": EvilString(facts.tenant_id)})
    claim = DelegatedGrantClaim.model_construct(
        request=request,
        grant=facts,
        policy=load_canonical_delegation_overlay(),
    )
    store = _PostgresClaimStore()

    with pytest.raises(ValueError, match="non-exact public values"):
        PostgresAtomicClaimPort(cast(PostgresDelegationClaimStore, store)).claim(claim)
    assert store.identities == []


@pytest.mark.parametrize(
    ("field", "replacement"),
    (
        ("run_id", uuid4()),
        ("request_sha256", "a" * 64),
        ("artifact_sha256", "b" * 64),
        ("rendered_contract_sha256", "c" * 64),
        ("tenant_id", "other-tenant"),
        ("backend_id", "other-backend"),
        ("model_id", "model-other-v2"),
        ("route_ref", "logical://delegation/other"),
        ("expected_output_topic", "events.public.other.v2"),
        ("expected_output_event_class", "ModelOtherCompleted"),
        ("expected_output_event_index", 1),
    ),
)
def test_every_request_fact_mismatch_rejects_before_lifecycle_claim_or_dispatch(
    monkeypatch: pytest.MonkeyPatch, field: str, replacement: object
) -> None:
    facts = _facts()
    _enable_canonical_overlay(monkeypatch, facts)
    request = _request(facts).model_copy(update={field: replacement})
    claim, dispatch, log = _Claim(), _Dispatch(), _RecordingLog()

    result = _ingress(claim, dispatch, log).submit(request, _valid_wire())

    assert result.state is DelegationSubmissionState.REJECTED_NOT_CLAIMED
    assert claim.calls == dispatch.calls == log.ingest_calls == 0


def test_claim_receives_full_verified_identity_and_lifecycle_ingest_orders_all_boundaries(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    facts = _facts()
    _enable_canonical_overlay(monkeypatch, facts)
    request = _request(facts)
    order: list[str] = []
    claim, dispatch, log = _Claim(order=order), _Dispatch(order=order), _RecordingLog(order=order)

    result = _ingress(claim, dispatch, log).submit(request, _valid_wire())

    assert result.state is DelegationSubmissionState.SUCCEEDED
    assert order == [
        "ingest:RUN_CREATED",
        "claim",
        "ingest:WORK_STARTED",
        "dispatch",
    ]
    assert claim.calls == dispatch.calls == 1
    assert claim.claims == dispatch.claims
    submitted = claim.claims[0]
    assert submitted.grant == facts
    assert submitted.grant.grant_id == facts.grant_id
    assert submitted.grant.nonce_sha256 == facts.nonce_sha256
    assert submitted.grant.authorization_digest == facts.authorization_digest
    assert submitted.grant.signature_sha256 == facts.signature_sha256
    assert submitted.request == request and submitted.policy.route_ref == request.route_ref
    events = log.events_for(request.run_id)
    assert [(event.sequence, event.event_type) for event in events] == [
        (1, LifecycleEventType.RUN_CREATED),
        (2, LifecycleEventType.WORK_STARTED),
    ]
    assert events[1].prior_event_hash == events[0].event_hash


def test_preclaim_persistence_failure_is_terminal_without_claim_or_dispatch(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    facts = _facts()
    _enable_canonical_overlay(monkeypatch, facts)
    claim, dispatch, log = _Claim(), _Dispatch(), _RecordingLog(fail_on_ingest=1)

    result = _ingress(claim, dispatch, log).submit(_request(facts), _valid_wire())

    assert result.state is DelegationSubmissionState.PRECLAIM_PERSISTENCE_FAILED
    assert claim.calls == dispatch.calls == 0


def test_claim_uncertainty_is_terminal_without_postclaim_persistence_or_dispatch(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    facts = _facts()
    _enable_canonical_overlay(monkeypatch, facts)
    claim = _Claim(error=OSError("claim connection outcome is unknown"))
    dispatch, log = _Dispatch(), _RecordingLog()

    result = _ingress(claim, dispatch, log).submit(_request(facts), _valid_wire())

    assert result.state is DelegationSubmissionState.CLAIM_UNCERTAIN
    assert claim.calls == 1 and dispatch.calls == 0 and log.ingest_calls == 1


def test_claimed_persistence_uncertainty_is_terminal_and_never_dispatches(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    facts = _facts()
    _enable_canonical_overlay(monkeypatch, facts)
    claim, dispatch, log = _Claim(), _Dispatch(), _RecordingLog(fail_on_ingest=2)

    result = _ingress(claim, dispatch, log).submit(_request(facts), _valid_wire())

    assert result.state is DelegationSubmissionState.CLAIMED_PERSISTENCE_UNCERTAIN
    assert claim.calls == 1 and dispatch.calls == 0 and log.ingest_calls == 2


def test_not_claimed_has_an_explicit_outcome_and_leaves_the_lifecycle_unadvanced(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    facts = _facts()
    _enable_canonical_overlay(monkeypatch, facts)
    claim, dispatch, log = _Claim(ClaimDisposition.NOT_CLAIMED), _Dispatch(), _RecordingLog()

    result = _ingress(claim, dispatch, log).submit(_request(facts), _valid_wire())

    assert result.state is DelegationSubmissionState.NOT_CLAIMED
    assert claim.calls == 1 and dispatch.calls == 0
    assert [event.event_type for event in log.events_for(facts.correlation_id)] == [
        LifecycleEventType.RUN_CREATED,
    ]


def test_dispatch_failure_reports_uncertainty_and_never_retries_the_same_run(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    facts = _facts()
    _enable_canonical_overlay(monkeypatch, facts)
    claim, dispatch, log = _Claim(), _Dispatch(error=OSError("dispatch timed out")), _RecordingLog()
    ingress = _ingress(claim, dispatch, log)

    first = ingress.submit(_request(facts), _valid_wire())
    second = ingress.submit(_request(facts), _valid_wire())

    assert first.state is DelegationSubmissionState.DISPATCH_UNCERTAIN
    assert second.state is DelegationSubmissionState.PRECLAIM_PERSISTENCE_FAILED
    assert claim.calls == dispatch.calls == 1


def test_absent_or_invalid_grant_never_persists_claims_or_dispatches(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    facts = _facts()
    _enable_canonical_overlay(monkeypatch, facts)
    claim, dispatch, log = _Claim(), _Dispatch(), _RecordingLog()
    ingress = _ingress(claim, dispatch, log)

    absent = ingress.submit(_request(facts), None)
    invalid = ingress.submit(_request(facts), b"grant")

    assert absent.state is invalid.state is DelegationSubmissionState.REJECTED_NOT_CLAIMED
    assert claim.calls == dispatch.calls == log.ingest_calls == 0
