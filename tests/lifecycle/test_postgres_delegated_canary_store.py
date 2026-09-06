"""Protocol-fake coverage for the async delegated-canary PostgreSQL C0 store."""

from __future__ import annotations

import asyncio
from collections.abc import Callable, Mapping
from contextlib import AbstractAsyncContextManager
from datetime import UTC, datetime, timedelta
from pathlib import Path
from uuid import UUID

import pytest

import omninode_rsd.lifecycle.postgres.delegated_canary_store as store_module
from omninode_rsd.delegation_execution import (
    DelegationExecutionAuthorityProjectionV2,
    DelegationExecutionReconciliationEvidenceV2,
    DelegationExecutionTrustAnchorV1,
    DelegationRouteAuthorityTrustAnchorV1,
    VerifiedDispatchOutcomeV2,
)
from omninode_rsd.lifecycle.postgres.delegated_canary_store import (
    AsyncPostgresDelegatedCanaryStore,
    DelegatedCanaryAttemptIdentityV2,
    DelegatedCanaryDispatchDisposition,
    DelegatedCanaryPrepareDisposition,
    DelegatedCanaryReconciliationDisposition,
    DelegatedCanaryReconciliationIdentityV1,
    DelegatedCanaryStoreAmbiguousCommitError,
    DelegatedCanaryStoreConflictError,
    DelegatedCanaryTerminalDisposition,
    RawDelegationExecutionAuthorityV2,
)

NOW = datetime(2026, 9, 5, tzinfo=UTC)
RUN_ID = UUID("10000000-0000-4000-8000-000000000001")
ATTEMPT_ID = UUID("20000000-0000-4000-8000-000000000002")
ATTESTATION_ID = UUID("30000000-0000-4000-8000-000000000003")
RECONCILIATION_ID = UUID("40000000-0000-4000-8000-000000000004")


class _Result:
    def __init__(self, row: Mapping[str, object] | None = None) -> None:
        self._row = row

    async def fetchone(self) -> Mapping[str, object] | None:
        return self._row


class _Transaction(AbstractAsyncContextManager[object]):
    def __init__(self, database: _Database) -> None:
        self._database = database

    async def __aenter__(self) -> object:
        self._database.transactions.append("begin")
        return self

    async def __aexit__(
        self,
        exc_type: object,
        exc: object,
        traceback: object,
    ) -> None:
        self._database.transactions.append("rollback" if exc_type is not None else "commit")
        if exc_type is None and self._database.commit_error_once:
            self._database.commit_error_once = False
            raise OSError("connection ended after commit")


class _Database:
    def __init__(self) -> None:
        self.attempts: dict[UUID, dict[str, object]] = {}
        self.dispatches: dict[str, dict[str, object]] = {}
        self.terminals: dict[str, dict[str, object]] = {}
        self.reconciliations: dict[UUID, dict[str, object]] = {}
        self.calls: list[str] = []
        self.transactions: list[str] = []
        self.commit_error_once = False


class _Connection(AbstractAsyncContextManager["_Connection"]):
    def __init__(self, database: _Database) -> None:
        self._database = database

    async def __aenter__(self) -> _Connection:
        return self

    async def __aexit__(self, exc_type: object, exc: object, traceback: object) -> None:
        return None

    def transaction(self) -> _Transaction:
        return _Transaction(self._database)

    async def execute(self, query: str, params: tuple[object, ...] = ()) -> _Result:
        normalized = " ".join(query.split())
        self._database.calls.append(normalized)
        if normalized == "SET TRANSACTION ISOLATION LEVEL READ COMMITTED;":
            return _Result()
        if normalized.startswith("SELECT pg_advisory_xact_lock"):
            return _Result()
        if normalized.startswith("SELECT run_id, authorization_digest"):
            attempt_id = _uuid(params[0])
            return _Result(self._database.attempts.get(attempt_id))
        if normalized.startswith(
            "SELECT authorization_digest, attestation_id, attempt_id_v2, outcome"
        ):
            digest = _digest(params[0])
            return _Result(self._database.terminals.get(digest))
        if normalized.startswith("SELECT authorization_digest, attestation_id, attempt_id_v2"):
            digest = _digest(params[0])
            row = self._database.dispatches.get(digest)
            return _Result(row)
        if normalized.startswith("SELECT attempt_id_v2, authorization_digest"):
            reconciliation_id = _uuid(params[0])
            return _Result(self._database.reconciliations.get(reconciliation_id))
        if normalized.startswith("INSERT INTO rsd_canary.delegated_canary_attempts"):
            attempt_id = _uuid(params[27])
            if attempt_id in self._database.attempts:
                return _Result()
            self._database.attempts[attempt_id] = {
                "run_id": params[0],
                "authorization_digest": params[1],
                "attestation_id": params[3],
                "claim_binding_sha256": params[2],
                "grant_not_before": params[28],
                "grant_expires_at": params[29],
            }
            return _Result({"attempt_id_v2": attempt_id})
        if normalized.startswith("INSERT INTO rsd_canary.delegated_canary_dispatches"):
            digest = _digest(params[0])
            if digest in self._database.dispatches:
                return _Result()
            self._database.dispatches[digest] = {
                "authorization_digest": digest,
                "attestation_id": params[1],
                "attempt_id_v2": params[3],
                "grant_not_before": params[4],
                "grant_expires_at": params[5],
            }
            return _Result({"authorization_digest": digest})
        if normalized.startswith("INSERT INTO rsd_canary.delegated_canary_terminal_receipts"):
            digest = _digest(params[0])
            if digest in self._database.terminals:
                return _Result()
            self._database.terminals[digest] = {
                "authorization_digest": digest,
                "attestation_id": params[1],
                "attempt_id_v2": params[8],
                "outcome_attestation_id_v2": params[11],
                "outcome_attestation_sha256": params[13],
                "grant_not_before": params[9],
                "grant_expires_at": params[10],
            }
            return _Result({"authorization_digest": digest})
        if normalized.startswith("INSERT INTO rsd_canary.delegated_canary_reconciliations"):
            reconciliation_id = _uuid(params[0])
            if reconciliation_id in self._database.reconciliations:
                return _Result()
            self._database.reconciliations[reconciliation_id] = {
                "attempt_id_v2": params[1],
                "authorization_digest": params[2],
                "attestation_id": params[3],
                "grant_not_before": params[4],
                "grant_expires_at": params[5],
                "reconciliation_state": params[6],
                "observation_sha256": params[7],
                "observed_at": params[8],
            }
            return _Result({"reconciliation_id": reconciliation_id})
        raise AssertionError(f"unexpected query: {normalized}")


class _Factory:
    def __init__(self, database: _Database) -> None:
        self._database = database

    def __call__(self) -> _Connection:
        return _Connection(self._database)


def _uuid(value: object) -> UUID:
    assert type(value) is UUID
    return value


def _digest(value: object) -> str:
    assert type(value) is str
    return value


def _authority() -> RawDelegationExecutionAuthorityV2:
    return RawDelegationExecutionAuthorityV2.model_construct(
        schema_version="rsd.raw-delegation-execution-authority.v2",
        raw_signed_grant=b"grant",
        raw_activation=b"activation",
        activation_trust_anchor=DelegationExecutionTrustAnchorV1.model_construct(),
        raw_route_authority=b"route",
        route_authority_trust_anchor=DelegationRouteAuthorityTrustAnchorV1.model_construct(),
    )


def _identity() -> DelegatedCanaryAttemptIdentityV2:
    return DelegatedCanaryAttemptIdentityV2(
        schema_version="rsd.delegated-canary-attempt-identity.v2",
        attempt_id=ATTEMPT_ID,
        outcome_attestation_id=ATTESTATION_ID,
    )


def _projection(
    *, expires_at: datetime = NOW + timedelta(minutes=1)
) -> DelegationExecutionAuthorityProjectionV2:
    return DelegationExecutionAuthorityProjectionV2.model_construct(
        schema_version="rsd.delegation-execution-authority-projection.v2",
        execute_enabled=True,
        activation_id=UUID("50000000-0000-4000-8000-000000000005"),
        activation_schema_version="rsd.delegation-execution-activation.v2",
        activation_version=1,
        activation_sha256="a" * 64,
        issued_at=NOW - timedelta(minutes=1),
        expires_at=expires_at,
        grant_correlation_id=RUN_ID,
        grant_not_before=NOW - timedelta(minutes=2),
        grant_expires_at=NOW + timedelta(minutes=2),
        authorization_digest="b" * 64,
        claim_binding_sha256="c" * 64,
        request_envelope_sha256="d" * 64,
        disabled_overlay_sha256="e" * 64,
        backend_id="qwen",
        model_id="qwen/qwen3.8-27b",
        route_ref="logical://delegation/qwen3.8-27b",
        route_authority_sha256="f" * 64,
        route_policy_digest="0" * 64,
        target_configuration_sha256="1" * 64,
        endpoint_ref_sha256="2" * 64,
        credential_ref_sha256="3" * 64,
        activation_trust_anchor_fingerprint_sha256="4" * 64,
        route_authority_trust_anchor_fingerprint_sha256="5" * 64,
        credential_provider_id="infisical",
        credential_provider_fingerprint_sha256="6" * 64,
        outcome_trust_anchor_sha256="7" * 64,
        outcome_trust_anchor_key_id="outcome-key",
        outcome_trust_anchor_key_fingerprint_sha256="8" * 64,
    )


def _outcome() -> VerifiedDispatchOutcomeV2:
    projection = _projection()
    return VerifiedDispatchOutcomeV2.model_construct(
        schema_version="rsd.verified-dispatch-outcome.v2",
        attestation_id=ATTESTATION_ID,
        attempt_id=ATTEMPT_ID,
        attestation_sha256="9" * 64,
        grant_correlation_id=projection.grant_correlation_id,
        grant_not_before=projection.grant_not_before,
        grant_expires_at=projection.grant_expires_at,
        authorization_digest=projection.authorization_digest,
        claim_binding_sha256=projection.claim_binding_sha256,
        request_envelope_sha256=projection.request_envelope_sha256,
        backend_id=projection.backend_id,
        model_id=projection.model_id,
        route_ref=projection.route_ref,
        activation_id=projection.activation_id,
        activation_sha256=projection.activation_sha256,
        route_authority_sha256=projection.route_authority_sha256,
        target_configuration_sha256=projection.target_configuration_sha256,
        outcome_trust_anchor_sha256=projection.outcome_trust_anchor_sha256,
        outcome_trust_anchor_key_id=projection.outcome_trust_anchor_key_id,
        outcome_trust_anchor_key_fingerprint_sha256=(
            projection.outcome_trust_anchor_key_fingerprint_sha256
        ),
        response_sha256="a" * 64,
        output_payload_sha256="b" * 64,
        outcome_status="completed",
        issued_at=NOW,
    )


def _store(
    database: _Database,
    *,
    trusted_clock: Callable[[], datetime] = lambda: NOW,
) -> AsyncPostgresDelegatedCanaryStore:
    return AsyncPostgresDelegatedCanaryStore(_Factory(database), trusted_clock=trusted_clock)


def _patch_verifiers(
    monkeypatch: pytest.MonkeyPatch,
    *,
    projection: DelegationExecutionAuthorityProjectionV2 | None = None,
    outcome: VerifiedDispatchOutcomeV2 | None = None,
) -> None:
    monkeypatch.setattr(
        store_module,
        "verify_raw_delegation_execution_authority_v2",
        lambda raw_signed_grant, raw_activation, **kwargs: projection or _projection(),
    )
    monkeypatch.setattr(
        store_module,
        "verify_raw_delegation_execution_authority_v2_for_reconciliation",
        lambda raw_signed_grant, raw_activation, **kwargs: (
            DelegationExecutionReconciliationEvidenceV2.model_construct(
                schema_version="rsd.delegation-execution-reconciliation-evidence.v2",
                grant_correlation_id=(projection or _projection()).grant_correlation_id,
                grant_not_before=(projection or _projection()).grant_not_before,
                grant_expires_at=(projection or _projection()).grant_expires_at,
                authorization_digest=(projection or _projection()).authorization_digest,
                claim_binding_sha256=(projection or _projection()).claim_binding_sha256,
            )
        ),
    )
    monkeypatch.setattr(
        store_module,
        "verify_raw_dispatch_outcome_attestation_v2",
        lambda raw_attestation, **kwargs: outcome or _outcome(),
    )


def test_async_store_appends_prepare_dispatch_terminal_idempotently(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    database = _Database()
    _patch_verifiers(monkeypatch)
    store = _store(database)

    async def exercise() -> tuple[object, ...]:
        prepared = await store.prepare(_authority(), _identity())
        prepared_again = await store.prepare(_authority(), _identity())
        dispatched = await store.record_dispatch_started(_authority(), _identity())
        dispatched_again = await store.record_dispatch_started(_authority(), _identity())
        terminal = await store.record_terminal(
            _authority(),
            expected_attempt_id=ATTEMPT_ID,
            raw_attestation=b"attestation",
            response_preimage=b"response",
            output_payload=b"payload",
        )
        terminal_again = await store.record_terminal(
            _authority(),
            expected_attempt_id=ATTEMPT_ID,
            raw_attestation=b"attestation",
            response_preimage=b"response",
            output_payload=b"payload",
        )
        return (
            prepared,
            prepared_again,
            dispatched,
            dispatched_again,
            terminal,
            terminal_again,
        )

    assert asyncio.run(exercise()) == (
        DelegatedCanaryPrepareDisposition.PREPARED,
        DelegatedCanaryPrepareDisposition.ALREADY_PREPARED,
        DelegatedCanaryDispatchDisposition.DISPATCH_STARTED,
        DelegatedCanaryDispatchDisposition.ALREADY_DISPATCH_STARTED,
        DelegatedCanaryTerminalDisposition.TERMINAL_RECORDED,
        DelegatedCanaryTerminalDisposition.ALREADY_TERMINAL,
    )
    assert database.transactions == ["begin", "commit"] * 6
    assert len(database.attempts) == len(database.dispatches) == len(database.terminals) == 1


def test_terminal_out_of_order_and_expired_authority_fail_before_writes(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    database = _Database()
    _patch_verifiers(monkeypatch)
    store = _store(database)

    async def missing_dispatch() -> None:
        await store.record_terminal(
            _authority(),
            expected_attempt_id=ATTEMPT_ID,
            raw_attestation=b"attestation",
            response_preimage=b"response",
            output_payload=b"payload",
        )

    with pytest.raises(DelegatedCanaryStoreConflictError, match="prepared attempt"):
        asyncio.run(missing_dispatch())
    assert database.terminals == {}

    _patch_verifiers(monkeypatch, projection=_projection(expires_at=NOW))
    with pytest.raises(DelegatedCanaryStoreConflictError, match="expired"):
        asyncio.run(store.prepare(_authority(), _identity()))
    assert database.attempts == {}


def test_commit_ambiguity_requires_append_only_reconciliation(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    database = _Database()
    database.commit_error_once = True
    _patch_verifiers(monkeypatch)
    store = _store(database)

    with pytest.raises(DelegatedCanaryStoreAmbiguousCommitError, match="reconcile"):
        asyncio.run(store.prepare(_authority(), _identity()))
    assert ATTEMPT_ID in database.attempts

    result = asyncio.run(
        store.reconcile_ambiguous_commit(
            _authority(),
            _identity(),
            DelegatedCanaryReconciliationIdentityV1(
                schema_version="rsd.delegated-canary-reconciliation-identity.v1",
                reconciliation_id=RECONCILIATION_ID,
            ),
        )
    )
    assert result is DelegatedCanaryReconciliationDisposition.PREPARED
    assert database.reconciliations[RECONCILIATION_ID]["reconciliation_state"] == "prepared"

    restarted = _store(database)
    assert (
        asyncio.run(
            restarted.reconcile_ambiguous_commit(
                _authority(),
                _identity(),
                DelegatedCanaryReconciliationIdentityV1(
                    schema_version="rsd.delegated-canary-reconciliation-identity.v1",
                    reconciliation_id=RECONCILIATION_ID,
                ),
            )
        )
        is DelegatedCanaryReconciliationDisposition.PREPARED
    )


def test_reconciliation_uses_historical_evidence_after_live_expiry(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    database = _Database()
    _patch_verifiers(monkeypatch)
    expired_now = NOW + timedelta(minutes=10)
    store = _store(database, trusted_clock=lambda: expired_now)

    result = asyncio.run(
        store.reconcile_ambiguous_commit(
            _authority(),
            _identity(),
            DelegatedCanaryReconciliationIdentityV1(
                schema_version="rsd.delegated-canary-reconciliation-identity.v1",
                reconciliation_id=RECONCILIATION_ID,
            ),
        )
    )

    assert result is DelegatedCanaryReconciliationDisposition.UNKNOWN_COMMIT
    assert database.reconciliations[RECONCILIATION_ID]["grant_expires_at"] < expired_now


def test_missing_attempt_is_recorded_as_unknown_commit_without_history_mutation(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    database = _Database()
    _patch_verifiers(monkeypatch)
    store = _store(database)

    result = asyncio.run(
        store.reconcile_ambiguous_commit(
            _authority(),
            _identity(),
            DelegatedCanaryReconciliationIdentityV1(
                schema_version="rsd.delegated-canary-reconciliation-identity.v1",
                reconciliation_id=RECONCILIATION_ID,
            ),
        )
    )

    assert result is DelegatedCanaryReconciliationDisposition.UNKNOWN_COMMIT
    assert database.attempts == database.dispatches == database.terminals == {}
    assert database.reconciliations[RECONCILIATION_ID]["reconciliation_state"] == "unknown_commit"


def test_conflicting_prepared_binding_fails_closed(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    database = _Database()
    _patch_verifiers(monkeypatch)
    store = _store(database)
    asyncio.run(store.prepare(_authority(), _identity()))
    database.attempts[ATTEMPT_ID]["claim_binding_sha256"] = "f" * 64

    with pytest.raises(DelegatedCanaryStoreConflictError, match="different binding"):
        asyncio.run(store.prepare(_authority(), _identity()))


def test_store_has_no_driver_or_runtime_configuration_dependency() -> None:
    source = store_module.__file__
    assert type(source) is str
    text = Path(source).read_text(encoding="utf-8")
    assert "psycopg" not in text
    assert "os.environ" not in text
    assert "httpx" not in text


def test_store_rejects_model_construct_wrong_schema_versions(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    authority = RawDelegationExecutionAuthorityV2.model_construct(
        schema_version="wrong",
        raw_signed_grant=b"grant",
        raw_activation=b"activation",
        activation_trust_anchor=DelegationExecutionTrustAnchorV1.model_construct(),
        raw_route_authority=b"route",
        route_authority_trust_anchor=DelegationRouteAuthorityTrustAnchorV1.model_construct(),
    )
    identity = DelegatedCanaryAttemptIdentityV2.model_construct(
        schema_version="wrong",
        attempt_id=ATTEMPT_ID,
        outcome_attestation_id=ATTESTATION_ID,
    )
    reconciliation = DelegatedCanaryReconciliationIdentityV1.model_construct(
        schema_version="wrong",
        reconciliation_id=RECONCILIATION_ID,
    )

    with pytest.raises(ValueError, match="exact public type"):
        AsyncPostgresDelegatedCanaryStore._validate_raw_authority(authority)
    with pytest.raises(ValueError, match="invalid"):
        AsyncPostgresDelegatedCanaryStore._validate_attempt_identity(identity)
    store = _store(_Database())
    _patch_verifiers(monkeypatch)

    with pytest.raises(ValueError, match="exact public type"):
        asyncio.run(store.reconcile_ambiguous_commit(_authority(), _identity(), reconciliation))

    projection_values = _projection().model_dump()
    projection_values["schema_version"] = "wrong"
    invalid_projection = DelegationExecutionAuthorityProjectionV2.model_construct(
        **projection_values
    )
    _patch_verifiers(monkeypatch, projection=invalid_projection)
    with pytest.raises(ValueError, match="invalid authority projection"):
        asyncio.run(store.prepare(_authority(), _identity()))


def test_delegated_canary_symbols_are_exported_from_canonical_postgres_package() -> None:
    from omninode_rsd.lifecycle.postgres import (
        AsyncPostgresDelegatedCanaryStore as CanonicalStore,
    )
    from omninode_rsd.lifecycle.postgres import (
        DelegatedCanaryAttemptIdentityV2 as CanonicalAttemptIdentity,
    )
    from omninode_rsd.lifecycle.postgres import (
        DelegatedCanaryPrepareDisposition as CanonicalPrepareDisposition,
    )
    from omninode_rsd.lifecycle.postgres import (
        DelegatedCanaryStoreError as CanonicalStoreError,
    )
    from omninode_rsd.lifecycle.postgres import (
        RawDelegationExecutionAuthorityV2 as CanonicalAuthority,
    )

    assert CanonicalStore is AsyncPostgresDelegatedCanaryStore
    assert CanonicalAttemptIdentity is DelegatedCanaryAttemptIdentityV2
    assert CanonicalPrepareDisposition is DelegatedCanaryPrepareDisposition
    assert CanonicalStoreError is store_module.DelegatedCanaryStoreError
    assert CanonicalAuthority is RawDelegationExecutionAuthorityV2
