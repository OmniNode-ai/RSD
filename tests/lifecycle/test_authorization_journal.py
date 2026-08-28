"""Durability and replay tests for the owner-only SQLite authorization journal."""

from __future__ import annotations

import multiprocessing
import os
import sqlite3
from concurrent.futures import ThreadPoolExecutor
from pathlib import Path
from typing import Protocol

import pytest

from omninode_rsd.lifecycle.authorization import (
    _VERIFIED_CAPABILITY,
    AuthorizationError,
    SQLiteAuthorizationJournal,
    _VerifiedAuthorization,
)
from omninode_rsd.lifecycle.infisical_disposable import PreflightReceiptV1


class _StartGate(Protocol):
    def wait(self) -> bool: ...


class _ResultQueue(Protocol):
    def put(self, value: str) -> None: ...


def _verified(nonce: str) -> _VerifiedAuthorization:
    return _VerifiedAuthorization(
        receipt=PreflightReceiptV1(
            schema_version="rsd.disposable-preflight-receipt.v1",
            status="compiled",
            authorization_state="not_authorized_pending_live_provenance",
            operation_id="123e4567-e89b-42d3-a456-426614174000",
            contract_sha256="a" * 64,
            proposal_sha256="b" * 64,
            candidate_composite_sha256="c" * 64,
            retention_expires_at="2030-01-01T00:00:00Z",
            disposal_owner="acceptance-owner",
            emitted_at="2026-08-27T12:00:00Z",
            evidence_sha256=("d" * 64,) * 6,
        ),
        provider_provenance_sha256="e" * 64,
        nonce=nonce,
        authorized_at="2026-08-27T12:00:00Z",
        capability=_VERIFIED_CAPABILITY,
    )


def _journal(tmp_path: Path) -> SQLiteAuthorizationJournal:
    root = tmp_path / "journal"
    root.mkdir(mode=0o700)
    root.chmod(0o700)
    return SQLiteAuthorizationJournal(root / "authorization.sqlite3")


def _claim_worker(path: str, nonce: str, start: _StartGate, queue: _ResultQueue) -> None:
    start.wait()
    try:
        SQLiteAuthorizationJournal(Path(path))._claim_verified(_verified(nonce))
    except AuthorizationError as error:
        queue.put(error.phase)
    else:
        queue.put("claimed")


def _crash_worker(path: str, nonce: str) -> None:
    journal = SQLiteAuthorizationJournal(Path(path))
    connection = journal._connect()
    connection.execute("BEGIN IMMEDIATE")
    connection.execute(
        """
        CREATE TABLE IF NOT EXISTS authorization_nonce_journal (
            nonce TEXT PRIMARY KEY NOT NULL,
            operation_id TEXT NOT NULL,
            receipt_sha256 TEXT NOT NULL,
            claimed_at TEXT NOT NULL
        ) WITHOUT ROWID
        """
    )
    connection.execute(
        """
        INSERT INTO authorization_nonce_journal (nonce, operation_id, receipt_sha256, claimed_at)
        VALUES (?, ?, ?, ?)
        """,
        (nonce, "crash-operation", "a" * 64, "2026-08-27T12:00:00Z"),
    )
    os._exit(0)


def test_claim_is_durable_and_replayed_across_new_instances(tmp_path: Path) -> None:
    journal = _journal(tmp_path)
    verified = _verified("a" * 32)

    journal._claim_verified(verified)
    with pytest.raises(AuthorizationError, match="nonce_replayed"):
        SQLiteAuthorizationJournal(journal._path)._claim_verified(verified)


def test_journal_rejects_a_caller_constructed_verified_shape(tmp_path: Path) -> None:
    verified = _verified("9" * 32)
    forged = _VerifiedAuthorization(
        receipt=verified.receipt,
        provider_provenance_sha256=verified.provider_provenance_sha256,
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
        futures = [executor.submit(journal._claim_verified, _verified(nonce)) for _ in range(2)]
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
    process_nonce = "c" * 32
    workers = [
        context.Process(
            target=_claim_worker, args=(str(journal._path), process_nonce, start, queue)
        )
        for _ in range(2)
    ]
    for worker in workers:
        worker.start()
    start.set()
    observed = [queue.get(timeout=10) for _ in workers]
    for worker in workers:
        worker.join(timeout=10)
        assert worker.exitcode == 0
    assert sorted(observed) == ["claimed", "nonce_replayed"]


def test_uncommitted_crash_is_recovered_without_false_claim(tmp_path: Path) -> None:
    journal = _journal(tmp_path)
    context = multiprocessing.get_context("spawn")
    worker = context.Process(target=_crash_worker, args=(str(journal._path), "d" * 32))

    worker.start()
    worker.join(timeout=10)

    assert worker.exitcode == 0
    journal._claim_verified(_verified("d" * 32))


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
    connection.execute("CREATE TABLE authorization_nonce_journal (wrong TEXT)")
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
        journal._claim_verified(_verified("2" * 32))
