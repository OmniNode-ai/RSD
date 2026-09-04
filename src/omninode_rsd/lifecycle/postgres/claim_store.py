"""Endpoint-agnostic durable delegation-claim storage."""

from __future__ import annotations

from collections.abc import Mapping
from enum import StrEnum
from typing import Literal

from pydantic import BaseModel, ConfigDict, Field

from omninode_rsd.lifecycle.models import strict_model_values
from omninode_rsd.lifecycle.postgres.store import PostgresConnection, PostgresConnectionFactory

_SHA256 = r"^[0-9a-f]{64}$"
_READ_COMMITTED_SQL = "SET TRANSACTION ISOLATION LEVEL READ COMMITTED;"
_INSERT_CLAIM_SQL = """
INSERT INTO rsd_canary.delegation_claims (authorization_digest, claim_binding_sha256)
VALUES (%s, %s)
ON CONFLICT (authorization_digest) DO NOTHING
RETURNING authorization_digest
"""
_SELECT_CLAIM_SQL = """
SELECT claim_binding_sha256
FROM rsd_canary.delegation_claims
WHERE authorization_digest = %s
"""


class _ClaimModel(BaseModel):
    model_config = ConfigDict(extra="forbid", frozen=True, strict=True)


class DelegationClaimIdentityV1(_ClaimModel):
    """Minimal immutable identity required by the durable claim boundary."""

    schema_version: Literal["rsd.delegation-claim-identity.v1"]
    authorization_digest: str = Field(pattern=_SHA256)
    claim_binding_sha256: str = Field(pattern=_SHA256)


class DelegationClaimResult(StrEnum):
    CLAIMED = "claimed"
    NOT_CLAIMED = "not_claimed"


class DelegationClaimStoreError(RuntimeError):
    """Base error for a durable delegation claim that was not definitive."""


class DelegationClaimStoreCorruptionError(DelegationClaimStoreError):
    """Stored claim data cannot prove it is the requested semantic claim."""


class DelegationClaimStoreUnavailableError(DelegationClaimStoreError):
    """The injected database boundary could not complete a definitive claim."""


class PostgresDelegationClaimStore:
    """Claim one verified authorization before its single external effect.

    The caller owns driver choice, credentials, pool, and connection setup. This
    adapter creates no configuration surface and never retries: a transaction or
    commit exception has an ambiguous outcome and must remain fail-closed.
    """

    def __init__(self, connection_factory: PostgresConnectionFactory) -> None:
        self._connection_factory = connection_factory

    def claim(self, identity: DelegationClaimIdentityV1) -> DelegationClaimResult:
        identity = _validated_identity(identity)
        try:
            with self._connection_factory() as connection, connection.transaction():
                connection.execute(_READ_COMMITTED_SQL)
                inserted = connection.execute(
                    _INSERT_CLAIM_SQL,
                    (identity.authorization_digest, identity.claim_binding_sha256),
                ).fetchone()
                if inserted is not None:
                    return DelegationClaimResult.CLAIMED
                return self._existing_claim_result(connection, identity)
        except DelegationClaimStoreError:
            raise
        except Exception:
            raise DelegationClaimStoreUnavailableError(
                "delegation claim transaction did not complete definitively"
            ) from None

    @staticmethod
    def _existing_claim_result(
        connection: PostgresConnection, identity: DelegationClaimIdentityV1
    ) -> DelegationClaimResult:
        row = connection.execute(_SELECT_CLAIM_SQL, (identity.authorization_digest,)).fetchone()
        if row is None:
            raise DelegationClaimStoreCorruptionError("conflicting claim row is absent")
        binding = _claim_binding_from_row(row)
        if binding != identity.claim_binding_sha256:
            raise DelegationClaimStoreCorruptionError("conflicting claim has a different binding")
        return DelegationClaimResult.NOT_CLAIMED


def _claim_binding_from_row(row: Mapping[str, object] | tuple[object, ...]) -> str:
    if type(row) is tuple:
        if len(row) != 1:
            raise DelegationClaimStoreCorruptionError("stored claim row has an unexpected shape")
        value = row[0]
    elif isinstance(row, Mapping) and set(row) == {"claim_binding_sha256"}:
        value = row["claim_binding_sha256"]
    else:
        raise DelegationClaimStoreCorruptionError("stored claim row has an unexpected shape")
    if (
        type(value) is not str
        or len(value) != 64
        or any(char not in "0123456789abcdef" for char in value)
    ):
        raise DelegationClaimStoreCorruptionError("stored claim binding is not valid")
    return value


def _validated_identity(identity: DelegationClaimIdentityV1) -> DelegationClaimIdentityV1:
    if type(identity) is not DelegationClaimIdentityV1 or not _exact_scalars(identity):
        raise ValueError("delegation claim identity must use exact public values")
    values = strict_model_values(
        identity,
        expected_type=DelegationClaimIdentityV1,
        field_names=frozenset(DelegationClaimIdentityV1.model_fields),
    )
    if values is None:
        raise ValueError("delegation claim identity is not valid")
    return DelegationClaimIdentityV1.model_validate(values)


def _exact_scalars(model: BaseModel) -> bool:
    return all(type(value) is str for value in model.__dict__.values())
