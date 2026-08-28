"""Durability, replay, and recovery tests for the SQLite operation journal."""

from __future__ import annotations

import base64
import hashlib
import multiprocessing
import os
import shutil
import sqlite3
import uuid
from concurrent.futures import ThreadPoolExecutor
from pathlib import Path
from threading import Event
from typing import Protocol

import pytest
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey

from omninode_rsd.lifecycle.authorization import (
    _GENESIS_CAPABILITY,
    _VERIFIED_CAPABILITY,
    AuthorizationError,
    AuthorizationOperationState,
    JournalGenesisReceiptV1,
    JournalMigrationStatus,
    ReconciliationReceiptV1,
    SQLiteAuthorizationJournal,
    TrustedEd25519SignerV1,
    VerifiedExecutionContext,
    _journal_genesis_artifact_bytes,
    _journal_genesis_message,
    _reconciliation_message,
    _VerifiedExecution,
    _VerifiedGenesis,
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


def _seed_current_journal(journal: SQLiteAuthorizationJournal) -> None:
    """Create a genuinely signed test genesis before exercising journal internals."""

    key = Ed25519PrivateKey.generate()
    public = key.public_key().public_bytes_raw()
    signer = TrustedEd25519SignerV1(
        key_id="journal-genesis-signer",
        public_key_base64=base64.b64encode(public).decode(),
        public_key_fingerprint_sha256=_digest(public),
    )
    unsigned = JournalGenesisReceiptV1(
        schema_version="rsd.authorization-journal-genesis.v1",
        operation_domain="rsd.disposable-acceptance-operation.v1",
        operation_id="operation-one",
        proposal_sha256="b" * 64,
        contract_sha256="c" * 64,
        disposal_owner="journal-owner",
        approver_identity="journal-approver",
        journal_path=str(journal._path),
        journal_path_sha256=journal._path_sha256(),
        journal_uuid=str(uuid.uuid4()),
        journal_schema_sha256=journal.journal_schema_sha256(),
        created_at="2026-08-27T12:00:00Z",
        signer_key_id=signer.key_id,
        signature_base64=base64.b64encode(b"0" * 64).decode(),
    )
    receipt = unsigned.model_copy(
        update={
            "signature_base64": base64.b64encode(
                key.sign(_journal_genesis_message(unsigned))
            ).decode()
        }
    )
    raw = _journal_genesis_artifact_bytes(receipt)
    verified = _VerifiedGenesis(
        receipt=receipt,
        artifact_sha256=_digest(raw),
        capability=_GENESIS_CAPABILITY,
    )
    journal._begin_verified_genesis(verified)
    journal._complete_verified_genesis(verified)


def _journal(tmp_path: Path, *, seeded: bool = True) -> SQLiteAuthorizationJournal:
    root = tmp_path / "journal"
    root.mkdir(mode=0o700)
    root.chmod(0o700)
    journal = SQLiteAuthorizationJournal(root / "authorization.sqlite3")
    if seeded:
        _seed_current_journal(journal)
    return journal


def _journal_at(root: Path, *, seeded: bool = True) -> SQLiteAuthorizationJournal:
    root.mkdir(mode=0o700)
    root.chmod(0o700)
    journal = SQLiteAuthorizationJournal(root / "authorization.sqlite3")
    if seeded:
        _seed_current_journal(journal)
    return journal


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
    journal = _journal(tmp_path, seeded=False)

    assert journal.migration_status() is JournalMigrationStatus.ABSENT
    assert not journal._path.exists()
    with pytest.raises(AuthorizationError, match="journal_absent"):
        journal._claim_verified(_verified("a" * 32))
    assert not journal._path.exists()
    _seed_current_journal(journal)
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

    journal = _journal(tmp_path, seeded=False)
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
    with pytest.raises(AuthorizationError, match="journal_genesis_missing"):
        SQLiteAuthorizationJournal(schema_path)._claim_verified(_verified("0" * 32))


def test_journal_rejects_relaxed_database_mode(tmp_path: Path) -> None:
    journal = _journal(tmp_path)
    journal._claim_verified(_verified("1" * 32))
    journal._path.chmod(0o644)

    with pytest.raises(AuthorizationError, match="journal_path"):
        journal._claim_verified(_verified("2" * 32, "operation-two"))


def test_journal_rejects_replacement_with_fresh_database_and_preserves_replay_guard(
    tmp_path: Path,
) -> None:
    journal = _journal(tmp_path)
    journal._claim_verified(_verified("3" * 32))
    archived = journal._path.with_name("authorization-before-replacement.sqlite3")
    os.replace(journal._path, archived)
    connection = sqlite3.connect(journal._path)
    connection.close()
    journal._path.chmod(0o600)

    assert journal.migration_status() is JournalMigrationStatus.IDENTITY_MISMATCH
    with pytest.raises(AuthorizationError, match="journal_identity_mismatch"):
        SQLiteAuthorizationJournal(journal._path)._claim_verified(_verified("4" * 32))


def test_journal_rejects_database_deletion_without_recreating_it(tmp_path: Path) -> None:
    journal = _journal(tmp_path)
    journal._claim_verified(_verified("5" * 32))
    journal._path.unlink()

    assert journal.migration_status() is JournalMigrationStatus.JOURNAL_MISSING
    with pytest.raises(AuthorizationError, match="journal_missing"):
        SQLiteAuthorizationJournal(journal._path)._claim_verified(_verified("6" * 32))
    assert not journal._path.exists()


def test_journal_rejects_anchor_deletion_without_recreating_it(tmp_path: Path) -> None:
    journal = _journal(tmp_path)
    journal._claim_verified(_verified("7" * 32))
    journal._anchor_path().unlink()

    assert journal.migration_status() is JournalMigrationStatus.ANCHOR_MISSING
    with pytest.raises(AuthorizationError, match="journal_anchor_missing"):
        SQLiteAuthorizationJournal(journal._path)._claim_verified(_verified("8" * 32))
    assert not journal._anchor_path().exists()


def test_journal_rejects_byte_identical_anchor_replacement(tmp_path: Path) -> None:
    journal = _journal(tmp_path)
    journal._claim_verified(_verified("9" * 32))
    replacement = tmp_path / "same-anchor-content.json"
    shutil.copy2(journal._anchor_path(), replacement)
    replacement.chmod(0o600)
    os.replace(replacement, journal._anchor_path())

    assert journal.migration_status() is JournalMigrationStatus.IDENTITY_MISMATCH
    with pytest.raises(AuthorizationError, match="journal_identity_mismatch"):
        SQLiteAuthorizationJournal(journal._path)._claim_verified(_verified("a" * 32))


def test_journal_rejects_anchor_swap_and_copied_journal(tmp_path: Path) -> None:
    first = _journal_at(tmp_path / "first")
    second = _journal_at(tmp_path / "second")
    first._claim_verified(_verified("b" * 32, "first-operation"))
    second._claim_verified(_verified("c" * 32, "second-operation"))

    first_anchor = first._anchor_path()
    first_anchor.unlink()
    shutil.copy2(second._anchor_path(), first_anchor)
    first_anchor.chmod(0o600)
    assert first.migration_status() is JournalMigrationStatus.IDENTITY_MISMATCH
    with pytest.raises(AuthorizationError, match=r"journal_anchor|journal_identity_mismatch"):
        SQLiteAuthorizationJournal(first._path)._claim_verified(
            _verified("d" * 32, "first-operation")
        )

    copied = _journal_at(tmp_path / "copied")
    shutil.copy2(second._path, copied._path)
    copied._path.chmod(0o600)
    shutil.copy2(second._anchor_path(), copied._anchor_path())
    copied._anchor_path().chmod(0o600)
    shutil.copy2(second._genesis_marker_path(), copied._genesis_marker_path())
    copied._genesis_marker_path().chmod(0o600)
    assert copied.migration_status() is JournalMigrationStatus.IDENTITY_MISMATCH
    with pytest.raises(
        AuthorizationError, match=r"journal_anchor|journal_genesis_marker|journal_identity_mismatch"
    ):
        copied._claim_verified(_verified("e" * 32, "copied-operation"))


def test_journal_replacement_racing_a_waiting_claim_fails_closed(tmp_path: Path) -> None:
    journal = _journal(tmp_path)
    journal._claim_verified(_verified("f" * 32, "anchored-operation"))
    entered = Event()

    def claim_after_lease() -> str:
        entered.set()
        try:
            SQLiteAuthorizationJournal(journal._path)._claim_verified(
                _verified("0" * 32, "new-operation")
            )
        except AuthorizationError as error:
            return error.phase
        return "claimed"

    with ThreadPoolExecutor(max_workers=1) as executor:
        with journal._identity_lease():
            pending = executor.submit(claim_after_lease)
            assert entered.wait(timeout=5)
            archived = journal._path.with_name("authorization-raced.sqlite3")
            os.replace(journal._path, archived)
            connection = sqlite3.connect(journal._path)
            connection.close()
            journal._path.chmod(0o600)
        outcome = pending.result(timeout=5)

    assert outcome == "journal_identity_mismatch"
