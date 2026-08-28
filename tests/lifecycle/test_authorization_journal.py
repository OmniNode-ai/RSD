"""Durability, replay, and recovery tests for the SQLite operation journal."""

from __future__ import annotations

import base64
import hashlib
import multiprocessing
import os
import sqlite3
from concurrent.futures import ThreadPoolExecutor
from pathlib import Path
from typing import Protocol

import pytest
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey

from omninode_rsd.lifecycle.authorization import (
    _VERIFIED_CAPABILITY,
    AuthorizationError,
    AuthorizationOperationState,
    JournalMigrationStatus,
    ReconciliationReceiptV1,
    SQLiteAuthorizationJournal,
    TrustedEd25519SignerV1,
    VerifiedExecutionContext,
    _reconciliation_message,
    _VerifiedExecution,
)
from omninode_rsd.lifecycle.infisical_disposable import ProposalV1, RuntimeContractV1


class _StartGate(Protocol):
    def wait(self) -> bool: ...


class _ResultQueue(Protocol):
    def put(self, value: str) -> None: ...


def _verified(nonce: str, operation_id: str = "operation-one") -> _VerifiedExecution:
    context = VerifiedExecutionContext(
        operation_id=operation_id,
        idempotency_key="a" * 64,
        proposal=ProposalV1.model_construct(),
        final_contract=RuntimeContractV1.model_construct(),
        provider_expectations=(),
        proposal_sha256="b" * 64,
        contract_sha256="c" * 64,
        provider_provenance_sha256="d" * 64,
    )
    return _VerifiedExecution(
        context=context,
        nonce=nonce,
        authorized_at="2026-08-27T12:00:00Z",
        capability=_VERIFIED_CAPABILITY,
    )


def _journal(tmp_path: Path) -> SQLiteAuthorizationJournal:
    root = tmp_path / "journal"
    root.mkdir(mode=0o700)
    root.chmod(0o700)
    return SQLiteAuthorizationJournal(root / "authorization.sqlite3")


def _digest(value: bytes) -> str:
    return hashlib.sha256(value).hexdigest()


def _signed_reconciliation(
    operation_id: str, *, idempotency_key: str = "a" * 64
) -> tuple[TrustedEd25519SignerV1, ReconciliationReceiptV1]:
    key = Ed25519PrivateKey.generate()
    public = key.public_key().public_bytes_raw()
    signer = TrustedEd25519SignerV1(
        key_id="reconciliation-signer",
        public_key_base64=base64.b64encode(public).decode(),
        public_key_fingerprint_sha256=_digest(public),
    )
    unsigned = ReconciliationReceiptV1(
        schema_version="rsd.lifecycle-effect-reconciliation.v1",
        outcome="effect_committed",
        operation_id=operation_id,
        idempotency_key=idempotency_key,
        effect_receipt_sha256="e" * 64,
        signer_key_id=signer.key_id,
        signature_base64=base64.b64encode(b"0" * 64).decode(),
    )
    return (
        signer,
        unsigned.model_copy(
            update={
                "signature_base64": base64.b64encode(
                    key.sign(_reconciliation_message(unsigned))
                ).decode()
            }
        ),
    )


def _claim_worker(
    path: str,
    nonce: str,
    operation_id: str,
    start: _StartGate,
    queue: _ResultQueue,
) -> None:
    start.wait()
    try:
        SQLiteAuthorizationJournal(Path(path))._claim_verified(_verified(nonce, operation_id))
    except AuthorizationError as error:
        queue.put(error.phase)
    else:
        queue.put("claimed")


def _crash_worker(path: str, nonce: str, operation_id: str) -> None:
    journal = SQLiteAuthorizationJournal(Path(path))
    verified = _verified(nonce, operation_id)
    with journal._operation_lease(operation_id):
        journal._claim_verified(verified)
        journal._begin_effect(verified)
        os._exit(0)


def test_claim_is_durable_and_same_operation_rejects_fresh_nonce(tmp_path: Path) -> None:
    journal = _journal(tmp_path)
    journal._claim_verified(_verified("a" * 32))

    with pytest.raises(AuthorizationError, match="operation_replayed"):
        SQLiteAuthorizationJournal(journal._path)._claim_verified(_verified("b" * 32))


def test_migration_status_is_read_only_and_classifies_current_journal(tmp_path: Path) -> None:
    journal = _journal(tmp_path)

    assert journal.migration_status() is JournalMigrationStatus.ABSENT
    assert not journal._path.exists()
    journal._claim_verified(_verified("a" * 32))
    assert journal.migration_status() is JournalMigrationStatus.CURRENT


def test_journal_rejects_a_caller_constructed_verified_shape(tmp_path: Path) -> None:
    verified = _verified("9" * 32)
    forged = _VerifiedExecution(
        context=verified.context,
        nonce=verified.nonce,
        authorized_at=verified.authorized_at,
        capability=object(),
    )

    with pytest.raises(AuthorizationError, match="journal"):
        _journal(tmp_path)._claim_verified(forged)


def test_claim_is_atomic_for_threads_and_processes(tmp_path: Path) -> None:
    journal = _journal(tmp_path)
    nonce = "b" * 32

    with ThreadPoolExecutor(max_workers=2) as executor:
        futures = [
            executor.submit(journal._claim_verified, _verified(nonce, f"thread-{index}"))
            for index in range(2)
        ]
    results = []
    for future in futures:
        try:
            future.result()
        except AuthorizationError as error:
            results.append(error.phase)
        else:
            results.append("claimed")
    assert sorted(results) == ["claimed", "nonce_replayed"]

    context = multiprocessing.get_context("spawn")
    start = context.Event()
    queue = context.Queue()
    operation_id = "shared-operation"
    workers = [
        context.Process(
            target=_claim_worker,
            args=(str(journal._path), f"{index + 3}" * 32, operation_id, start, queue),
        )
        for index in range(2)
    ]
    for worker in workers:
        worker.start()
    start.set()
    observed = [queue.get(timeout=10) for _ in workers]
    for worker in workers:
        worker.join(timeout=10)
        assert worker.exitcode == 0
    assert sorted(observed) == ["claimed", "operation_replayed"]


def test_crash_restart_leaves_in_progress_and_requires_explicit_recovery(tmp_path: Path) -> None:
    journal = _journal(tmp_path)
    context = multiprocessing.get_context("spawn")
    worker = context.Process(
        target=_crash_worker,
        args=(str(journal._path), "d" * 32, "crash-operation"),
    )

    worker.start()
    worker.join(timeout=10)

    assert worker.exitcode == 0
    restarted = SQLiteAuthorizationJournal(journal._path)
    assert restarted.operation_state("crash-operation") is AuthorizationOperationState.IN_PROGRESS
    with pytest.raises(AuthorizationError, match="operation_replayed"):
        restarted._claim_verified(_verified("e" * 32, "crash-operation"))
    assert (
        restarted.require_recovery("crash-operation")
        is AuthorizationOperationState.FAILED_RECOVERY_REQUIRED
    )
    assert (
        restarted.operation_state("crash-operation")
        is AuthorizationOperationState.FAILED_RECOVERY_REQUIRED
    )


def test_signed_reconciliation_is_the_only_ambiguous_effect_resolution(tmp_path: Path) -> None:
    journal = _journal(tmp_path)
    verified = _verified("c" * 32, "ambiguous-operation")
    with journal._operation_lease(verified.context.operation_id):
        journal._claim_verified(verified)
        journal._begin_effect(verified)
    assert (
        journal.require_recovery(verified.context.operation_id)
        is AuthorizationOperationState.FAILED_RECOVERY_REQUIRED
    )
    signer, receipt = _signed_reconciliation(verified.context.operation_id)

    assert (
        journal.reconcile_ambiguous_effect(receipt, signer=signer)
        is AuthorizationOperationState.COMMITTED
    )
    assert (
        journal.operation_state(verified.context.operation_id)
        is AuthorizationOperationState.COMMITTED
    )
    with pytest.raises(AuthorizationError, match="operation_state"):
        journal.reconcile_ambiguous_effect(receipt, signer=signer)


def test_reconciliation_rejects_unsigned_or_live_operations(tmp_path: Path) -> None:
    journal = _journal(tmp_path)
    verified = _verified("f" * 32, "live-ambiguous-operation")
    signer, receipt = _signed_reconciliation(verified.context.operation_id)
    invalid = receipt.model_copy(update={"signature_base64": base64.b64encode(b"1" * 64).decode()})

    with pytest.raises(AuthorizationError, match="reconciliation_signature"):
        journal.reconcile_ambiguous_effect(invalid, signer=signer)

    with journal._operation_lease(verified.context.operation_id):
        journal._claim_verified(verified)
        journal._begin_effect(verified)
        with pytest.raises(AuthorizationError, match="operation_live"):
            journal.reconcile_ambiguous_effect(receipt, signer=signer)


def test_journal_rejects_non_owner_mode_symlink_and_wrong_schema(tmp_path: Path) -> None:
    insecure = tmp_path / "insecure"
    insecure.mkdir(mode=0o755)
    insecure.chmod(0o755)
    with pytest.raises(AuthorizationError, match="journal_directory"):
        SQLiteAuthorizationJournal(insecure / "authorization.sqlite3")._claim_verified(
            _verified("e" * 32)
        )

    journal = _journal(tmp_path)
    target = tmp_path / "target.sqlite3"
    target.write_bytes(b"not-a-journal")
    target.chmod(0o600)
    journal._path.symlink_to(target)
    with pytest.raises(AuthorizationError, match="journal_path"):
        journal._claim_verified(_verified("f" * 32))

    schema_root = tmp_path / "schema"
    schema_root.mkdir(mode=0o700)
    schema_root.chmod(0o700)
    schema_path = schema_root / "authorization.sqlite3"
    connection = sqlite3.connect(schema_path)
    connection.execute("CREATE TABLE authorization_operation_journal (wrong TEXT)")
    connection.commit()
    connection.close()
    schema_path.chmod(0o600)
    with pytest.raises(AuthorizationError, match="journal_schema"):
        SQLiteAuthorizationJournal(schema_path)._claim_verified(_verified("0" * 32))


def test_journal_rejects_relaxed_database_mode(tmp_path: Path) -> None:
    journal = _journal(tmp_path)
    journal._claim_verified(_verified("1" * 32))
    journal._path.chmod(0o644)

    with pytest.raises(AuthorizationError, match="journal_path"):
        journal._claim_verified(_verified("2" * 32, "operation-two"))
