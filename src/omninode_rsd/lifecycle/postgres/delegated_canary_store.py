"""Async, append-only PostgreSQL evidence storage for delegated canaries.

The caller owns connection setup and the trusted clock.  This module neither
looks up configuration nor opens a network connection, and it never performs
the delegated effect.  It derives every durable authority fact from the raw
V2 verifier immediately before a write; a caller-provided projection is never
accepted as authority.
"""

from __future__ import annotations

from collections.abc import Awaitable, Callable, Mapping
from contextlib import AbstractAsyncContextManager
from dataclasses import dataclass
from datetime import UTC, datetime
from enum import StrEnum
from typing import Literal, Protocol, TypeVar
from uuid import UUID

from pydantic import BaseModel, ConfigDict, Field

from omninode_rsd.delegation_execution import (
    DelegationExecutionAuthorityProjectionV2,
    DelegationExecutionTrustAnchorV1,
    DelegationRouteAuthorityTrustAnchorV1,
    HistoricalDelegationExecutionEvidenceV2,
    VerifiedDispatchOutcomeV2,
    delegation_logical_reference_sha256,
    verify_raw_delegation_execution_authority_v2,
    verify_raw_delegation_execution_chain_v2_for_historical_reconciliation,
    verify_raw_dispatch_outcome_attestation_v2,
)
from omninode_rsd.lifecycle.hashing import canonical_hash

_SHA256 = r"^[0-9a-f]{64}$"
_READ_COMMITTED_SQL = "SET TRANSACTION ISOLATION LEVEL READ COMMITTED;"
_LOCK_ATTEMPT_SQL = "SELECT pg_advisory_xact_lock(hashtextextended(%s::text, 0));"
_SELECT_ATTEMPT_SQL = """
SELECT run_id, authorization_digest, attestation_id, claim_binding_sha256,
       grant_not_before, grant_expires_at
FROM rsd_canary.delegated_canary_attempts
WHERE attempt_id_v2 = %s
FOR UPDATE
"""
_SELECT_DISPATCH_SQL = """
SELECT authorization_digest, attestation_id, attempt_id_v2, grant_not_before, grant_expires_at
FROM rsd_canary.delegated_canary_dispatches
WHERE authorization_digest = %s
FOR UPDATE
"""
_SELECT_TERMINAL_SQL = """
SELECT authorization_digest, attestation_id, attempt_id_v2, outcome_attestation_id_v2,
       outcome_attestation_sha256, grant_not_before, grant_expires_at
FROM rsd_canary.delegated_canary_terminal_receipts
WHERE authorization_digest = %s
FOR UPDATE
"""
_INSERT_ATTEMPT_SQL = """
INSERT INTO rsd_canary.delegated_canary_attempts (
    run_id, authorization_digest, claim_binding_sha256, attestation_id,
    activation_id, activation_schema_version, activation_version, activation_sha256,
    activation_issued_at, activation_expires_at, request_envelope_sha256,
    disabled_overlay_sha256, backend_id, model_id, route_ref_sha256,
    route_authority_sha256, route_policy_digest, target_configuration_sha256,
    endpoint_ref_sha256, credential_ref_sha256,
    activation_trust_anchor_fingerprint_sha256,
    route_authority_trust_anchor_fingerprint_sha256, credential_provider_id,
    credential_provider_fingerprint_sha256, state, prepared_at,
    attempt_schema_version, attempt_id_v2, grant_not_before, grant_expires_at
) VALUES (
    %s, %s, %s, %s, %s, %s, %s, %s, %s, %s, %s, %s, %s, %s, %s, %s,
    %s, %s, %s, %s, %s, %s, %s, %s, %s, %s, %s, %s, %s, %s
)
ON CONFLICT (attempt_id_v2) DO NOTHING
RETURNING attempt_id_v2
"""
_INSERT_DISPATCH_SQL = """
INSERT INTO rsd_canary.delegated_canary_dispatches (
    authorization_digest, attestation_id, state, dispatch_started_at,
    attempt_id_v2, grant_not_before, grant_expires_at
) VALUES (%s, %s, 'dispatch_started', %s, %s, %s, %s)
ON CONFLICT (authorization_digest) DO NOTHING
RETURNING authorization_digest
"""
_INSERT_TERMINAL_SQL = """
INSERT INTO rsd_canary.delegated_canary_terminal_receipts (
    authorization_digest, attestation_id, terminal_state, response_sha256,
    output_payload_sha256, attestation_sha256, outcome_issued_at, recorded_at,
    attempt_id_v2, grant_not_before, grant_expires_at,
    outcome_attestation_id_v2, outcome_attestation_schema_version,
    outcome_attestation_sha256, outcome_trust_anchor_sha256,
    outcome_trust_anchor_key_id, outcome_trust_anchor_key_fingerprint_sha256,
    outcome_issued_at_v2
) VALUES (
    %s, %s, %s, %s, %s, %s, %s, %s, %s, %s, %s, %s, %s, %s, %s, %s, %s, %s
)
ON CONFLICT (authorization_digest) DO NOTHING
RETURNING authorization_digest
"""
_SELECT_RECONCILIATION_SQL = """
SELECT attempt_id_v2, authorization_digest, attestation_id, grant_not_before,
       grant_expires_at, reconciliation_state, observation_sha256, observed_at
FROM rsd_canary.delegated_canary_reconciliations
WHERE reconciliation_id = %s
FOR UPDATE
"""
_INSERT_RECONCILIATION_SQL = """
INSERT INTO rsd_canary.delegated_canary_reconciliations (
    reconciliation_id, attempt_id_v2, authorization_digest, attestation_id,
    grant_not_before, grant_expires_at, reconciliation_state, observation_sha256, observed_at
) VALUES (%s, %s, %s, %s, %s, %s, %s, %s, %s)
ON CONFLICT (reconciliation_id) DO NOTHING
RETURNING reconciliation_id
"""


class AsyncPostgresResult(Protocol):
    """Minimal awaited result surface required by the C0 adapter."""

    async def fetchone(self) -> Mapping[str, object] | tuple[object, ...] | None: ...


class AsyncPostgresConnection(Protocol):
    """Caller-owned async PostgreSQL connection surface."""

    async def execute(self, query: str, params: tuple[object, ...] = ()) -> AsyncPostgresResult: ...

    def transaction(self) -> AbstractAsyncContextManager[object]: ...


type AsyncPostgresConnectionFactory = Callable[
    [], AbstractAsyncContextManager[AsyncPostgresConnection]
]
type TrustedClock = Callable[[], datetime]
_Result = TypeVar("_Result")
_VerifiedAuthority = (
    DelegationExecutionAuthorityProjectionV2 | HistoricalDelegationExecutionEvidenceV2
)


class DelegatedCanaryStoreError(RuntimeError):
    """Base class for a durable delegated-canary evidence failure."""


class DelegatedCanaryStoreConflictError(DelegatedCanaryStoreError):
    """A durable row conflicts with the verified attempt identity."""


class DelegatedCanaryStoreCorruptionError(DelegatedCanaryStoreError):
    """A returned durable row is not the exact expected record."""


class DelegatedCanaryStoreUnavailableError(DelegatedCanaryStoreError):
    """A read could not return a definitive durable state."""


class DelegatedCanaryStoreAmbiguousCommitError(DelegatedCanaryStoreError):
    """A write may have committed; callers must reconcile before any effect."""


class _StoreModel(BaseModel):
    model_config = ConfigDict(extra="forbid", frozen=True, strict=True)


class RawDelegationExecutionAuthorityV2(_StoreModel):
    """Raw authority inputs; the store derives its own redacted projection."""

    schema_version: Literal["rsd.raw-delegation-execution-authority.v2"]
    raw_signed_grant: bytes = Field(min_length=1, max_length=131_072)
    raw_activation: bytes = Field(min_length=1, max_length=131_072)
    activation_trust_anchor: DelegationExecutionTrustAnchorV1
    raw_route_authority: bytes = Field(min_length=1, max_length=131_072)
    route_authority_trust_anchor: DelegationRouteAuthorityTrustAnchorV1


class DelegatedCanaryAttemptIdentityV2(_StoreModel):
    """Caller-selected, non-authorizing identities for one single attempt."""

    schema_version: Literal["rsd.delegated-canary-attempt-identity.v2"]
    attempt_id: UUID
    outcome_attestation_id: UUID


class DelegatedCanaryReconciliationIdentityV1(_StoreModel):
    """One append-only observation of an ambiguous write."""

    schema_version: Literal["rsd.delegated-canary-reconciliation-identity.v1"]
    reconciliation_id: UUID


class DelegatedCanaryPrepareDisposition(StrEnum):
    PREPARED = "prepared"
    ALREADY_PREPARED = "already_prepared"


class DelegatedCanaryDispatchDisposition(StrEnum):
    DISPATCH_STARTED = "dispatch_started"
    ALREADY_DISPATCH_STARTED = "already_dispatch_started"


class DelegatedCanaryTerminalDisposition(StrEnum):
    TERMINAL_RECORDED = "terminal_recorded"
    ALREADY_TERMINAL = "already_terminal"


class DelegatedCanaryReconciliationDisposition(StrEnum):
    UNKNOWN_COMMIT = "unknown_commit"
    PREPARED = "prepared"
    DISPATCH_STARTED = "dispatch_started"
    TERMINAL = "terminal"


@dataclass(frozen=True, slots=True)
class _AttemptRow:
    run_id: UUID
    authorization_digest: str
    attestation_id: UUID
    claim_binding_sha256: str
    grant_not_before: datetime
    grant_expires_at: datetime


@dataclass(frozen=True, slots=True)
class _DispatchRow:
    authorization_digest: str
    attestation_id: UUID
    attempt_id: UUID
    grant_not_before: datetime
    grant_expires_at: datetime


@dataclass(frozen=True, slots=True)
class _TerminalRow:
    authorization_digest: str
    attestation_id: UUID
    attempt_id: UUID
    outcome_attestation_id: UUID
    outcome_attestation_sha256: str
    grant_not_before: datetime
    grant_expires_at: datetime


@dataclass(frozen=True, slots=True)
class _ReconciliationRow:
    attempt_id: UUID
    authorization_digest: str
    attestation_id: UUID
    grant_not_before: datetime
    grant_expires_at: datetime
    state: DelegatedCanaryReconciliationDisposition
    observation_sha256: str
    observed_at: datetime


class AsyncPostgresDelegatedCanaryStore:
    """C0 evidence persistence with no transport, provider, or execute path."""

    def __init__(
        self,
        connection_factory: AsyncPostgresConnectionFactory,
        *,
        trusted_clock: TrustedClock,
    ) -> None:
        self._connection_factory = connection_factory
        self._trusted_clock = trusted_clock

    async def prepare(
        self,
        authority: RawDelegationExecutionAuthorityV2,
        identity: DelegatedCanaryAttemptIdentityV2,
    ) -> DelegatedCanaryPrepareDisposition:
        projection, now = self._verified_authority(authority)
        self._validate_attempt_identity(identity)
        self._require_live(projection, now)

        async def operation(
            connection: AsyncPostgresConnection,
        ) -> DelegatedCanaryPrepareDisposition:
            existing = await self._attempt(connection, identity.attempt_id)
            if existing is not None:
                self._require_attempt_matches(existing, projection, identity)
                return DelegatedCanaryPrepareDisposition.ALREADY_PREPARED
            inserted = await connection.execute(
                _INSERT_ATTEMPT_SQL,
                self._attempt_parameters(projection, identity, now),
            )
            if await inserted.fetchone() is None:
                existing = await self._attempt(connection, identity.attempt_id)
                if existing is None:
                    raise DelegatedCanaryStoreCorruptionError("attempt conflict row is absent")
                self._require_attempt_matches(existing, projection, identity)
                return DelegatedCanaryPrepareDisposition.ALREADY_PREPARED
            return DelegatedCanaryPrepareDisposition.PREPARED

        return await self._write(identity.attempt_id, operation)

    async def record_dispatch_started(
        self,
        authority: RawDelegationExecutionAuthorityV2,
        identity: DelegatedCanaryAttemptIdentityV2,
    ) -> DelegatedCanaryDispatchDisposition:
        projection, now = self._verified_authority(authority)
        self._validate_attempt_identity(identity)
        self._require_live(projection, now)

        async def operation(
            connection: AsyncPostgresConnection,
        ) -> DelegatedCanaryDispatchDisposition:
            attempt = await self._attempt(connection, identity.attempt_id)
            if attempt is None:
                raise DelegatedCanaryStoreConflictError("dispatch has no prepared attempt")
            self._require_attempt_matches(attempt, projection, identity)
            existing = await self._dispatch(connection, projection.authorization_digest)
            if existing is not None:
                self._require_dispatch_matches(existing, projection, identity)
                return DelegatedCanaryDispatchDisposition.ALREADY_DISPATCH_STARTED
            inserted = await connection.execute(
                _INSERT_DISPATCH_SQL,
                (
                    projection.authorization_digest,
                    identity.outcome_attestation_id,
                    now,
                    identity.attempt_id,
                    projection.grant_not_before,
                    projection.grant_expires_at,
                ),
            )
            if await inserted.fetchone() is None:
                existing = await self._dispatch(connection, projection.authorization_digest)
                if existing is None:
                    raise DelegatedCanaryStoreCorruptionError("dispatch conflict row is absent")
                self._require_dispatch_matches(existing, projection, identity)
                return DelegatedCanaryDispatchDisposition.ALREADY_DISPATCH_STARTED
            return DelegatedCanaryDispatchDisposition.DISPATCH_STARTED

        return await self._write(identity.attempt_id, operation)

    async def record_terminal(
        self,
        authority: RawDelegationExecutionAuthorityV2,
        *,
        expected_attempt_id: UUID,
        raw_attestation: bytes,
        response_preimage: bytes,
        output_payload: bytes,
    ) -> DelegatedCanaryTerminalDisposition:
        outcome, now = self._verified_outcome(
            authority,
            expected_attempt_id=expected_attempt_id,
            raw_attestation=raw_attestation,
            response_preimage=response_preimage,
            output_payload=output_payload,
        )
        self._require_live_outcome(outcome, now)

        async def operation(
            connection: AsyncPostgresConnection,
        ) -> DelegatedCanaryTerminalDisposition:
            attempt = await self._attempt(connection, expected_attempt_id)
            if attempt is None:
                raise DelegatedCanaryStoreConflictError("terminal receipt has no prepared attempt")
            self._require_outcome_matches_attempt(attempt, outcome)
            dispatch = await self._dispatch(connection, outcome.authorization_digest)
            if dispatch is None:
                raise DelegatedCanaryStoreConflictError("terminal receipt has no dispatch start")
            self._require_outcome_matches_dispatch(dispatch, outcome)
            existing = await self._terminal(connection, outcome.authorization_digest)
            if existing is not None:
                self._require_terminal_matches(existing, outcome)
                return DelegatedCanaryTerminalDisposition.ALREADY_TERMINAL
            inserted = await connection.execute(
                _INSERT_TERMINAL_SQL,
                self._terminal_parameters(outcome, now),
            )
            if await inserted.fetchone() is None:
                existing = await self._terminal(connection, outcome.authorization_digest)
                if existing is None:
                    raise DelegatedCanaryStoreCorruptionError("terminal conflict row is absent")
                self._require_terminal_matches(existing, outcome)
                return DelegatedCanaryTerminalDisposition.ALREADY_TERMINAL
            return DelegatedCanaryTerminalDisposition.TERMINAL_RECORDED

        return await self._write(expected_attempt_id, operation)

    async def reconcile_ambiguous_commit(
        self,
        authority: RawDelegationExecutionAuthorityV2,
        identity: DelegatedCanaryAttemptIdentityV2,
        reconciliation: DelegatedCanaryReconciliationIdentityV1,
    ) -> DelegatedCanaryReconciliationDisposition:
        """Append or reuse one durable observation; this never changes history."""

        evidence = self._verified_historical_evidence(authority)
        self._validate_attempt_identity(identity)
        if (
            type(reconciliation) is not DelegatedCanaryReconciliationIdentityV1
            or reconciliation.schema_version != "rsd.delegated-canary-reconciliation-identity.v1"
        ):
            raise ValueError("reconciliation identity must use the exact public type")

        async def operation(
            connection: AsyncPostgresConnection,
        ) -> DelegatedCanaryReconciliationDisposition:
            existing = await self._reconciliation(connection, reconciliation.reconciliation_id)
            if existing is not None:
                self._require_reconciliation_identity_matches(existing, evidence, identity)
            state = await self._observed_state(connection, evidence, identity)
            if existing is not None:
                self._require_reconciliation_state_matches(existing, state)
                return state
            now = self._now()
            observation_sha256 = canonical_hash(
                {
                    "schema_version": "rsd.delegated-canary-reconciliation-observation.v1",
                    "attempt_id": identity.attempt_id,
                    "outcome_attestation_id": identity.outcome_attestation_id,
                    "authorization_digest": evidence.authorization_digest,
                    "grant_not_before": evidence.grant_not_before,
                    "grant_expires_at": evidence.grant_expires_at,
                    "state": state.value,
                    "observed_at": now,
                }
            )
            inserted = await connection.execute(
                _INSERT_RECONCILIATION_SQL,
                (
                    reconciliation.reconciliation_id,
                    identity.attempt_id,
                    evidence.authorization_digest,
                    identity.outcome_attestation_id,
                    evidence.grant_not_before,
                    evidence.grant_expires_at,
                    state.value,
                    observation_sha256,
                    now,
                ),
            )
            if await inserted.fetchone() is None:
                existing = await self._reconciliation(connection, reconciliation.reconciliation_id)
                if existing is None:
                    raise DelegatedCanaryStoreCorruptionError(
                        "reconciliation conflict row is absent"
                    )
                self._require_reconciliation_identity_matches(existing, evidence, identity)
                self._require_reconciliation_state_matches(existing, state)
            return state

        return await self._write(identity.attempt_id, operation)

    def _verified_historical_evidence(
        self, authority: RawDelegationExecutionAuthorityV2
    ) -> HistoricalDelegationExecutionEvidenceV2:
        self._validate_raw_authority(authority)
        evidence = verify_raw_delegation_execution_chain_v2_for_historical_reconciliation(
            authority.raw_signed_grant,
            authority.raw_activation,
            activation_trust_anchor=authority.activation_trust_anchor,
            raw_route_authority=authority.raw_route_authority,
            route_authority_trust_anchor=authority.route_authority_trust_anchor,
        )
        if (
            type(evidence) is not HistoricalDelegationExecutionEvidenceV2
            or evidence.schema_version != "rsd.delegation-execution-reconciliation-evidence.v2"
        ):
            raise ValueError("raw verifier returned invalid historical evidence")
        return evidence

    def _verified_authority(
        self, authority: RawDelegationExecutionAuthorityV2
    ) -> tuple[DelegationExecutionAuthorityProjectionV2, datetime]:
        self._validate_raw_authority(authority)
        now = self._now()
        projection = verify_raw_delegation_execution_authority_v2(
            authority.raw_signed_grant,
            authority.raw_activation,
            activation_trust_anchor=authority.activation_trust_anchor,
            raw_route_authority=authority.raw_route_authority,
            route_authority_trust_anchor=authority.route_authority_trust_anchor,
            trusted_clock=lambda: now,
        )
        if (
            type(projection) is not DelegationExecutionAuthorityProjectionV2
            or projection.schema_version != "rsd.delegation-execution-authority-projection.v2"
        ):
            raise ValueError("raw verifier returned an invalid authority projection")
        return projection, now

    def _verified_outcome(
        self,
        authority: RawDelegationExecutionAuthorityV2,
        *,
        expected_attempt_id: UUID,
        raw_attestation: bytes,
        response_preimage: bytes,
        output_payload: bytes,
    ) -> tuple[VerifiedDispatchOutcomeV2, datetime]:
        self._validate_raw_authority(authority)
        if type(expected_attempt_id) is not UUID:
            raise ValueError("expected attempt identity must be a UUID")
        if any(
            type(value) is not bytes or not value
            for value in (raw_attestation, response_preimage, output_payload)
        ):
            raise ValueError("terminal receipt inputs must be non-empty bytes")
        now = self._now()
        outcome = verify_raw_dispatch_outcome_attestation_v2(
            raw_attestation,
            raw_signed_grant=authority.raw_signed_grant,
            raw_activation=authority.raw_activation,
            activation_trust_anchor=authority.activation_trust_anchor,
            raw_route_authority=authority.raw_route_authority,
            route_authority_trust_anchor=authority.route_authority_trust_anchor,
            expected_attempt_id=expected_attempt_id,
            trusted_clock=lambda: now,
            response_preimage=response_preimage,
            output_payload=output_payload,
        )
        if (
            type(outcome) is not VerifiedDispatchOutcomeV2
            or outcome.schema_version != "rsd.verified-dispatch-outcome.v2"
        ):
            raise ValueError("raw verifier returned an invalid terminal receipt")
        return outcome, now

    async def _write(
        self,
        attempt_id: UUID,
        operation: Callable[[AsyncPostgresConnection], Awaitable[_Result]],
    ) -> _Result:
        try:
            async with self._connection_factory() as connection, connection.transaction():
                await connection.execute(_READ_COMMITTED_SQL)
                await connection.execute(_LOCK_ATTEMPT_SQL, (str(attempt_id),))
                return await operation(connection)
        except DelegatedCanaryStoreError:
            raise
        except (TypeError, ValueError):
            raise
        except Exception as error:
            if _sqlstate(error).startswith("23"):
                raise DelegatedCanaryStoreConflictError(
                    "delegated-canary write conflicts"
                ) from None
            raise DelegatedCanaryStoreAmbiguousCommitError(
                "delegated-canary write may have committed; reconcile before any effect"
            ) from None

    async def _attempt(
        self, connection: AsyncPostgresConnection, attempt_id: UUID
    ) -> _AttemptRow | None:
        row = await (await connection.execute(_SELECT_ATTEMPT_SQL, (attempt_id,))).fetchone()
        return None if row is None else _attempt_row(row)

    async def _dispatch(
        self, connection: AsyncPostgresConnection, authorization_digest: str
    ) -> _DispatchRow | None:
        row = await (
            await connection.execute(_SELECT_DISPATCH_SQL, (authorization_digest,))
        ).fetchone()
        return None if row is None else _dispatch_row(row)

    async def _terminal(
        self, connection: AsyncPostgresConnection, authorization_digest: str
    ) -> _TerminalRow | None:
        row = await (
            await connection.execute(_SELECT_TERMINAL_SQL, (authorization_digest,))
        ).fetchone()
        return None if row is None else _terminal_row(row)

    async def _reconciliation(
        self, connection: AsyncPostgresConnection, reconciliation_id: UUID
    ) -> _ReconciliationRow | None:
        row = await (
            await connection.execute(_SELECT_RECONCILIATION_SQL, (reconciliation_id,))
        ).fetchone()
        if row is None:
            return None
        values = _row_values(
            row,
            (
                "attempt_id_v2",
                "authorization_digest",
                "attestation_id",
                "grant_not_before",
                "grant_expires_at",
                "reconciliation_state",
                "observation_sha256",
                "observed_at",
            ),
        )
        state_value = values["reconciliation_state"]
        if type(state_value) is not str:
            raise DelegatedCanaryStoreCorruptionError("stored reconciliation state is invalid")
        try:
            state = DelegatedCanaryReconciliationDisposition(state_value)
        except ValueError:
            raise DelegatedCanaryStoreCorruptionError(
                "stored reconciliation state is invalid"
            ) from None
        return _ReconciliationRow(
            attempt_id=_uuid(values["attempt_id_v2"]),
            authorization_digest=_digest(values["authorization_digest"]),
            attestation_id=_uuid(values["attestation_id"]),
            grant_not_before=_utc(values["grant_not_before"]),
            grant_expires_at=_utc(values["grant_expires_at"]),
            state=state,
            observation_sha256=_digest(values["observation_sha256"]),
            observed_at=_utc(values["observed_at"]),
        )

    async def _observed_state(
        self,
        connection: AsyncPostgresConnection,
        evidence: _VerifiedAuthority,
        identity: DelegatedCanaryAttemptIdentityV2,
    ) -> DelegatedCanaryReconciliationDisposition:
        attempt = await self._attempt(connection, identity.attempt_id)
        if attempt is None:
            return DelegatedCanaryReconciliationDisposition.UNKNOWN_COMMIT
        self._require_attempt_matches(attempt, evidence, identity)
        terminal = await self._terminal(connection, evidence.authorization_digest)
        if terminal is not None:
            self._require_terminal_identity_matches(terminal, evidence, identity)
            return DelegatedCanaryReconciliationDisposition.TERMINAL
        dispatch = await self._dispatch(connection, evidence.authorization_digest)
        if dispatch is not None:
            self._require_dispatch_matches(dispatch, evidence, identity)
            return DelegatedCanaryReconciliationDisposition.DISPATCH_STARTED
        return DelegatedCanaryReconciliationDisposition.PREPARED

    @staticmethod
    def _attempt_parameters(
        projection: DelegationExecutionAuthorityProjectionV2,
        identity: DelegatedCanaryAttemptIdentityV2,
        now: datetime,
    ) -> tuple[object, ...]:
        return (
            projection.grant_correlation_id,
            projection.authorization_digest,
            projection.claim_binding_sha256,
            identity.outcome_attestation_id,
            projection.activation_id,
            projection.activation_schema_version,
            projection.activation_version,
            projection.activation_sha256,
            projection.issued_at,
            projection.expires_at,
            projection.request_envelope_sha256,
            projection.disabled_overlay_sha256,
            projection.backend_id,
            projection.model_id,
            delegation_logical_reference_sha256(projection.route_ref, namespace="delegation"),
            projection.route_authority_sha256,
            projection.route_policy_digest,
            projection.target_configuration_sha256,
            projection.endpoint_ref_sha256,
            projection.credential_ref_sha256,
            projection.activation_trust_anchor_fingerprint_sha256,
            projection.route_authority_trust_anchor_fingerprint_sha256,
            projection.credential_provider_id,
            projection.credential_provider_fingerprint_sha256,
            "prepared",
            now,
            "rsd.delegated-canary-attempt.v2",
            identity.attempt_id,
            projection.grant_not_before,
            projection.grant_expires_at,
        )

    @staticmethod
    def _terminal_parameters(
        outcome: VerifiedDispatchOutcomeV2, now: datetime
    ) -> tuple[object, ...]:
        return (
            outcome.authorization_digest,
            outcome.attestation_id,
            outcome.outcome_status,
            outcome.response_sha256,
            outcome.output_payload_sha256,
            outcome.attestation_sha256,
            outcome.issued_at,
            now,
            outcome.attempt_id,
            outcome.grant_not_before,
            outcome.grant_expires_at,
            outcome.attestation_id,
            "rsd.dispatch-outcome-attestation.v2",
            outcome.attestation_sha256,
            outcome.outcome_trust_anchor_sha256,
            outcome.outcome_trust_anchor_key_id,
            outcome.outcome_trust_anchor_key_fingerprint_sha256,
            outcome.issued_at,
        )

    @staticmethod
    def _validate_raw_authority(authority: RawDelegationExecutionAuthorityV2) -> None:
        if (
            type(authority) is not RawDelegationExecutionAuthorityV2
            or authority.schema_version != "rsd.raw-delegation-execution-authority.v2"
        ):
            raise ValueError("raw authority must use the exact public type")
        if (
            type(authority.raw_signed_grant) is not bytes
            or type(authority.raw_activation) is not bytes
            or type(authority.raw_route_authority) is not bytes
            or type(authority.activation_trust_anchor) is not DelegationExecutionTrustAnchorV1
            or type(authority.route_authority_trust_anchor)
            is not DelegationRouteAuthorityTrustAnchorV1
        ):
            raise ValueError("raw authority fields are not exact public values")

    @staticmethod
    def _validate_attempt_identity(identity: DelegatedCanaryAttemptIdentityV2) -> None:
        if (
            type(identity) is not DelegatedCanaryAttemptIdentityV2
            or identity.schema_version != "rsd.delegated-canary-attempt-identity.v2"
            or type(identity.attempt_id) is not UUID
            or type(identity.outcome_attestation_id) is not UUID
            or identity.attempt_id == identity.outcome_attestation_id
        ):
            raise ValueError("delegated-canary attempt identity is invalid")

    def _now(self) -> datetime:
        now = self._trusted_clock()
        if type(now) is not datetime or now.tzinfo is not UTC:
            raise ValueError("trusted clock must return an exact UTC datetime")
        return now

    @staticmethod
    def _require_live(projection: DelegationExecutionAuthorityProjectionV2, now: datetime) -> None:
        if not (projection.grant_not_before <= now < projection.grant_expires_at):
            raise DelegatedCanaryStoreConflictError(
                "verified authority is expired or not yet valid"
            )
        if not (projection.issued_at <= now < projection.expires_at):
            raise DelegatedCanaryStoreConflictError(
                "verified activation is expired or not yet valid"
            )

    @staticmethod
    def _require_live_outcome(outcome: VerifiedDispatchOutcomeV2, now: datetime) -> None:
        if not (outcome.grant_not_before <= now < outcome.grant_expires_at):
            raise DelegatedCanaryStoreConflictError("verified terminal receipt is expired")

    @staticmethod
    def _require_attempt_matches(
        row: _AttemptRow,
        evidence: _VerifiedAuthority,
        identity: DelegatedCanaryAttemptIdentityV2,
    ) -> None:
        if (
            row.run_id != evidence.grant_correlation_id
            or row.authorization_digest != evidence.authorization_digest
            or row.attestation_id != identity.outcome_attestation_id
            or row.claim_binding_sha256 != evidence.claim_binding_sha256
            or row.grant_not_before != evidence.grant_not_before
            or row.grant_expires_at != evidence.grant_expires_at
        ):
            raise DelegatedCanaryStoreConflictError("prepared attempt has a different binding")

    @staticmethod
    def _require_dispatch_matches(
        row: _DispatchRow,
        evidence: _VerifiedAuthority,
        identity: DelegatedCanaryAttemptIdentityV2,
    ) -> None:
        if (
            row.authorization_digest != evidence.authorization_digest
            or row.attestation_id != identity.outcome_attestation_id
            or row.attempt_id != identity.attempt_id
            or row.grant_not_before != evidence.grant_not_before
            or row.grant_expires_at != evidence.grant_expires_at
        ):
            raise DelegatedCanaryStoreConflictError("dispatch start has a different binding")

    @staticmethod
    def _require_outcome_matches_attempt(
        row: _AttemptRow, outcome: VerifiedDispatchOutcomeV2
    ) -> None:
        if (
            row.run_id != outcome.grant_correlation_id
            or row.authorization_digest != outcome.authorization_digest
            or row.attestation_id != outcome.attestation_id
            or row.claim_binding_sha256 != outcome.claim_binding_sha256
            or row.grant_not_before != outcome.grant_not_before
            or row.grant_expires_at != outcome.grant_expires_at
        ):
            raise DelegatedCanaryStoreConflictError(
                "terminal receipt has a different attempt binding"
            )

    @staticmethod
    def _require_outcome_matches_dispatch(
        row: _DispatchRow, outcome: VerifiedDispatchOutcomeV2
    ) -> None:
        if (
            row.authorization_digest != outcome.authorization_digest
            or row.attestation_id != outcome.attestation_id
            or row.attempt_id != outcome.attempt_id
            or row.grant_not_before != outcome.grant_not_before
            or row.grant_expires_at != outcome.grant_expires_at
        ):
            raise DelegatedCanaryStoreConflictError(
                "terminal receipt has a different dispatch binding"
            )

    @staticmethod
    def _require_terminal_matches(row: _TerminalRow, outcome: VerifiedDispatchOutcomeV2) -> None:
        if (
            row.authorization_digest != outcome.authorization_digest
            or row.attestation_id != outcome.attestation_id
            or row.attempt_id != outcome.attempt_id
            or row.outcome_attestation_id != outcome.attestation_id
            or row.outcome_attestation_sha256 != outcome.attestation_sha256
            or row.grant_not_before != outcome.grant_not_before
            or row.grant_expires_at != outcome.grant_expires_at
        ):
            raise DelegatedCanaryStoreConflictError("terminal receipt has a different binding")

    @staticmethod
    def _require_terminal_identity_matches(
        row: _TerminalRow,
        evidence: _VerifiedAuthority,
        identity: DelegatedCanaryAttemptIdentityV2,
    ) -> None:
        if (
            row.authorization_digest != evidence.authorization_digest
            or row.attestation_id != identity.outcome_attestation_id
            or row.attempt_id != identity.attempt_id
            or row.outcome_attestation_id != identity.outcome_attestation_id
            or row.grant_not_before != evidence.grant_not_before
            or row.grant_expires_at != evidence.grant_expires_at
        ):
            raise DelegatedCanaryStoreCorruptionError(
                "stored terminal record has a different binding"
            )

    @staticmethod
    def _require_reconciliation_identity_matches(
        row: _ReconciliationRow,
        evidence: _VerifiedAuthority,
        identity: DelegatedCanaryAttemptIdentityV2,
    ) -> None:
        if (
            row.attempt_id != identity.attempt_id
            or row.authorization_digest != evidence.authorization_digest
            or row.attestation_id != identity.outcome_attestation_id
            or row.grant_not_before != evidence.grant_not_before
            or row.grant_expires_at != evidence.grant_expires_at
        ):
            raise DelegatedCanaryStoreConflictError("reconciliation has a different binding")

    @staticmethod
    def _require_reconciliation_state_matches(
        row: _ReconciliationRow,
        state: DelegatedCanaryReconciliationDisposition,
    ) -> None:
        if row.state is not state:
            raise DelegatedCanaryStoreConflictError("reconciliation has a different state")


def _row_values(
    row: Mapping[str, object] | tuple[object, ...], columns: tuple[str, ...]
) -> dict[str, object]:
    if type(row) is tuple:
        if len(row) != len(columns):
            raise DelegatedCanaryStoreCorruptionError("stored row has an unexpected shape")
        return dict(zip(columns, row, strict=True))
    if isinstance(row, Mapping) and set(row) == set(columns):
        return {column: row[column] for column in columns}
    raise DelegatedCanaryStoreCorruptionError("stored row has an unexpected shape")


def _attempt_row(row: Mapping[str, object] | tuple[object, ...]) -> _AttemptRow:
    values = _row_values(
        row,
        (
            "run_id",
            "authorization_digest",
            "attestation_id",
            "claim_binding_sha256",
            "grant_not_before",
            "grant_expires_at",
        ),
    )
    return _AttemptRow(
        run_id=_uuid(values["run_id"]),
        authorization_digest=_digest(values["authorization_digest"]),
        attestation_id=_uuid(values["attestation_id"]),
        claim_binding_sha256=_digest(values["claim_binding_sha256"]),
        grant_not_before=_utc(values["grant_not_before"]),
        grant_expires_at=_utc(values["grant_expires_at"]),
    )


def _dispatch_row(row: Mapping[str, object] | tuple[object, ...]) -> _DispatchRow:
    values = _row_values(
        row,
        (
            "authorization_digest",
            "attestation_id",
            "attempt_id_v2",
            "grant_not_before",
            "grant_expires_at",
        ),
    )
    return _DispatchRow(
        authorization_digest=_digest(values["authorization_digest"]),
        attestation_id=_uuid(values["attestation_id"]),
        attempt_id=_uuid(values["attempt_id_v2"]),
        grant_not_before=_utc(values["grant_not_before"]),
        grant_expires_at=_utc(values["grant_expires_at"]),
    )


def _terminal_row(row: Mapping[str, object] | tuple[object, ...]) -> _TerminalRow:
    values = _row_values(
        row,
        (
            "authorization_digest",
            "attestation_id",
            "attempt_id_v2",
            "outcome_attestation_id_v2",
            "outcome_attestation_sha256",
            "grant_not_before",
            "grant_expires_at",
        ),
    )
    return _TerminalRow(
        authorization_digest=_digest(values["authorization_digest"]),
        attestation_id=_uuid(values["attestation_id"]),
        attempt_id=_uuid(values["attempt_id_v2"]),
        outcome_attestation_id=_uuid(values["outcome_attestation_id_v2"]),
        outcome_attestation_sha256=_digest(values["outcome_attestation_sha256"]),
        grant_not_before=_utc(values["grant_not_before"]),
        grant_expires_at=_utc(values["grant_expires_at"]),
    )


def _uuid(value: object) -> UUID:
    if type(value) is not UUID:
        raise DelegatedCanaryStoreCorruptionError("stored UUID is invalid")
    return value


def _digest(value: object) -> str:
    if (
        type(value) is not str
        or len(value) != 64
        or any(char not in "0123456789abcdef" for char in value)
    ):
        raise DelegatedCanaryStoreCorruptionError("stored digest is invalid")
    return value


def _utc(value: object) -> datetime:
    if type(value) is not datetime or value.tzinfo is not UTC:
        raise DelegatedCanaryStoreCorruptionError("stored timestamp is not exact UTC")
    return value


def _sqlstate(error: Exception) -> str:
    value = getattr(error, "sqlstate", "")
    return value if type(value) is str else ""


__all__ = [
    "AsyncPostgresConnection",
    "AsyncPostgresConnectionFactory",
    "AsyncPostgresDelegatedCanaryStore",
    "AsyncPostgresResult",
    "DelegatedCanaryAttemptIdentityV2",
    "DelegatedCanaryDispatchDisposition",
    "DelegatedCanaryPrepareDisposition",
    "DelegatedCanaryReconciliationDisposition",
    "DelegatedCanaryReconciliationIdentityV1",
    "DelegatedCanaryStoreAmbiguousCommitError",
    "DelegatedCanaryStoreConflictError",
    "DelegatedCanaryStoreCorruptionError",
    "DelegatedCanaryStoreError",
    "DelegatedCanaryStoreUnavailableError",
    "DelegatedCanaryTerminalDisposition",
    "RawDelegationExecutionAuthorityV2",
]
