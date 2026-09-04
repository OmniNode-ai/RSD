"""Protocol-fake tests for the topology-neutral PostgreSQL claim store."""

from __future__ import annotations

from contextlib import AbstractContextManager
from pathlib import Path

import pytest

from omninode_rsd.lifecycle.postgres import (
    DelegationClaimIdentityV1,
    DelegationClaimResult,
    DelegationClaimStoreCorruptionError,
    DelegationClaimStoreUnavailableError,
    PostgresDelegationClaimStore,
)


class _Result:
    def __init__(self, row: dict[str, object] | None = None) -> None:
        self._row = row

    def fetchone(self) -> dict[str, object] | None:
        return self._row

    def fetchall(self) -> list[dict[str, object]]:
        return []


class _Transaction(AbstractContextManager[object]):
    def __init__(self, database: _Database) -> None:
        self._database = database

    def __enter__(self) -> object:
        self._database.transactions.append("begin")
        return self

    def __exit__(self, exc_type: object, exc: object, traceback: object) -> None:
        self._database.transactions.append("rollback" if exc_type is not None else "commit")
        if exc_type is None and self._database.commit_error:
            raise OSError("commit ambiguous")


class _Database:
    def __init__(self) -> None:
        self.claims: dict[str, str] = {}
        self.calls: list[str] = []
        self.transactions: list[str] = []
        self.fail = False
        self.commit_error = False
        self.force_conflict = False


class _Connection(AbstractContextManager["_Connection"]):
    def __init__(self, database: _Database) -> None:
        self._database = database

    def __enter__(self) -> _Connection:
        return self

    def __exit__(self, exc_type: object, exc: object, traceback: object) -> None:
        return None

    def transaction(self) -> _Transaction:
        return _Transaction(self._database)

    def execute(self, query: str, params: tuple[object, ...] = ()) -> _Result:
        normalized = " ".join(query.split())
        self._database.calls.append(normalized)
        if self._database.fail:
            raise OSError("connection failed")
        if normalized == "SET TRANSACTION ISOLATION LEVEL READ COMMITTED;":
            return _Result()
        if normalized.startswith("INSERT INTO rsd_canary.delegation_claims"):
            digest, binding = params
            assert type(digest) is str and type(binding) is str
            if self._database.force_conflict or digest in self._database.claims:
                return _Result()
            self._database.claims[digest] = binding
            return _Result({"authorization_digest": digest})
        if normalized.startswith("SELECT claim_binding_sha256"):
            digest = params[0]
            assert type(digest) is str
            binding = self._database.claims.get(digest)
            return _Result(None if binding is None else {"claim_binding_sha256": binding})
        raise AssertionError(f"unexpected query: {normalized}")


class _Factory:
    def __init__(self, database: _Database) -> None:
        self._database = database

    def __call__(self) -> _Connection:
        return _Connection(self._database)


def _identity(*, digest: str = "a" * 64, binding: str = "b" * 64) -> DelegationClaimIdentityV1:
    return DelegationClaimIdentityV1(
        schema_version="rsd.delegation-claim-identity.v1",
        authorization_digest=digest,
        claim_binding_sha256=binding,
    )


def _store(database: _Database) -> PostgresDelegationClaimStore:
    return PostgresDelegationClaimStore(_Factory(database))


def test_atomic_insert_claims_once_and_identical_repeat_is_not_claimed() -> None:
    database = _Database()
    store = _store(database)

    assert store.claim(_identity()) is DelegationClaimResult.CLAIMED
    assert store.claim(_identity()) is DelegationClaimResult.NOT_CLAIMED

    assert database.transactions == ["begin", "commit", "begin", "commit"]
    assert database.calls[0] == "SET TRANSACTION ISOLATION LEVEL READ COMMITTED;"
    assert "ON CONFLICT (authorization_digest) DO NOTHING" in database.calls[1]
    assert len(database.claims) == 1


def test_conflicting_binding_or_missing_conflict_row_fails_closed() -> None:
    database = _Database()
    store = _store(database)
    assert store.claim(_identity()) is DelegationClaimResult.CLAIMED

    with pytest.raises(DelegationClaimStoreCorruptionError, match="different binding"):
        store.claim(_identity(binding="c" * 64))
    database.claims.clear()
    database.force_conflict = True
    with pytest.raises(DelegationClaimStoreCorruptionError, match="absent"):
        store.claim(_identity())


@pytest.mark.parametrize("commit_error", [False, True])
def test_driver_or_commit_errors_are_unavailable_and_never_retried(commit_error: bool) -> None:
    database = _Database()
    database.fail = not commit_error
    database.commit_error = commit_error

    with pytest.raises(DelegationClaimStoreUnavailableError) as raised:
        _store(database).claim(_identity())

    assert raised.value.__cause__ is None
    assert database.calls.count("SET TRANSACTION ISOLATION LEVEL READ COMMITTED;") == 1


def test_claim_store_has_no_configuration_or_driver_dependency() -> None:
    import omninode_rsd.lifecycle.postgres.claim_store as claim_store

    source = Path(claim_store.__file__).read_text(encoding="utf-8")
    assert "psycopg" not in source
    assert "os.environ" not in source


def test_constructed_or_scalar_subclass_identity_is_rejected_before_database_access() -> None:
    class EvilString(str):
        pass

    database = _Database()
    forged = DelegationClaimIdentityV1.model_construct(
        schema_version="rsd.delegation-claim-identity.v1",
        authorization_digest=EvilString("a" * 64),
        claim_binding_sha256="b" * 64,
    )

    with pytest.raises(ValueError, match="exact public values"):
        _store(database).claim(forged)
    assert database.calls == []
