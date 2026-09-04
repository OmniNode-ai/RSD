"""Concrete PostgreSQL implementation of the generic delegation claim port."""

from __future__ import annotations

from datetime import datetime
from uuid import UUID

from pydantic import BaseModel

from omninode_rsd.delegation import (
    AtomicClaimPort,
    ClaimDisposition,
    DelegatedGrantClaim,
    DelegatedRequest,
    DelegationOverlay,
    VerifiedGrantFacts,
)
from omninode_rsd.lifecycle.hashing import canonical_hash
from omninode_rsd.lifecycle.models import strict_model_values
from omninode_rsd.lifecycle.postgres.claim_store import (
    DelegationClaimIdentityV1,
    DelegationClaimResult,
    DelegationClaimStoreCorruptionError,
    PostgresDelegationClaimStore,
)


class PostgresAtomicClaimPort(AtomicClaimPort):
    """Strictly revalidate a public claim before one durable PostgreSQL claim."""

    def __init__(self, store: PostgresDelegationClaimStore) -> None:
        self._store = store

    def claim(self, claim: DelegatedGrantClaim) -> ClaimDisposition:
        if type(claim) is not DelegatedGrantClaim:
            raise ValueError("delegation claim must have the exact public type")
        request = _strict_model(claim.request, DelegatedRequest)
        grant = _strict_model(claim.grant, VerifiedGrantFacts)
        policy = _strict_model(claim.policy, DelegationOverlay)
        identity = DelegationClaimIdentityV1(
            schema_version="rsd.delegation-claim-identity.v1",
            authorization_digest=grant.authorization_digest,
            claim_binding_sha256=canonical_hash(
                {
                    "schema_version": "rsd.delegation-claim-binding.v1",
                    "authorization_domain": grant.authorization_domain,
                    "request": request,
                    "grant": grant.model_dump(mode="python", exclude={"signature_sha256"}),
                    "policy": policy,
                }
            ),
        )
        result = self._store.claim(identity)
        if result is DelegationClaimResult.CLAIMED:
            return ClaimDisposition.CLAIMED
        if result is DelegationClaimResult.NOT_CLAIMED:
            return ClaimDisposition.NOT_CLAIMED
        raise DelegationClaimStoreCorruptionError(
            "delegation claim store returned an unknown result"
        )


def _strict_model[ModelT: BaseModel](value: object, expected_type: type[ModelT]) -> ModelT:
    if type(value) is not expected_type or not _exact_public_values(value):
        raise ValueError("delegation claim contains non-exact public values")
    values = strict_model_values(
        value, expected_type=expected_type, field_names=frozenset(expected_type.model_fields)
    )
    if values is None:
        raise ValueError("delegation claim contains an invalid public model")
    return expected_type.model_validate(values)


def _exact_public_values(model: BaseModel) -> bool:
    exact_types = {str, bool, int, datetime, UUID}
    return all(type(value) in exact_types for value in model.__dict__.values())
