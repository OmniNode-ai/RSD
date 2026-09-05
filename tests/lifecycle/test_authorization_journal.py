"""Durability, replay, and recovery tests for the SQLite operation journal."""

from __future__ import annotations

import base64
import hashlib
import multiprocessing
import os
import queue
import shutil
import sqlite3
import stat
import time
import uuid
from concurrent.futures import ThreadPoolExecutor
from contextlib import suppress
from pathlib import Path
from threading import Event, Lock, get_ident
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


_MAX_DIAGNOSTIC_EVENTS = 32
_DIAGNOSTIC_TIMEOUT_SECONDS = 10.0
_DIAGNOSTIC_COMPANION_KINDS = {
    "missing",
    "regular",
    "lstat_error",
    "symlink",
    "nonregular",
    "uid_mismatch",
    "mode_mismatch",
    "nlink_mismatch",
}
_DIAGNOSTIC_IDENTITY_RESULTS = {
    "database_stat",
    "anchor",
    "metadata",
    "schema",
    "durability_mismatch",
}
_DiagnosticEvent = tuple[
    int,
    int,
    int,
    int,
    int | None,
    int | None,
    str,
    str | None,
    tuple[tuple[str, str], ...],
]


class _DiagnosticEventQueue(Protocol):
    def put(self, value: tuple[tuple[_DiagnosticEvent, ...], bool]) -> None: ...


class _RecordingJournalObserver:
    """Test-only ordered event sink with opaque stable local identities."""

    def __init__(self, *, process_ordinal: int, journal_ordinal: int) -> None:
        self._process_ordinal = process_ordinal
        self._journal_ordinal = journal_ordinal
        self._lock = Lock()
        self._next_sequence = 0
        self._thread_ordinals: dict[int, int] = {}
        self._events: list[_DiagnosticEvent] = []
        self._overflowed = False

    def record(
        self,
        *,
        phase: str,
        connection_ordinal: int | None,
        transaction_ordinal: int | None,
        result: str | None,
        companions: tuple[tuple[str, str], ...],
    ) -> None:
        with self._lock:
            if len(self._events) == _MAX_DIAGNOSTIC_EVENTS:
                self._overflowed = True
                return
            thread_id = get_ident()
            thread_ordinal = self._thread_ordinals.setdefault(
                thread_id, len(self._thread_ordinals) + 1
            )
            self._next_sequence += 1
            self._events.append(
                (
                    self._next_sequence,
                    self._process_ordinal,
                    self._journal_ordinal,
                    thread_ordinal,
                    connection_ordinal,
                    transaction_ordinal,
                    phase,
                    result,
                    companions,
                )
            )

    def receipt(self) -> tuple[tuple[_DiagnosticEvent, ...], bool]:
        with self._lock:
            return tuple(self._events), self._overflowed


class _FailingJournalObserver:
    def record(
        self,
        *,
        phase: str,
        connection_ordinal: int | None,
        transaction_ordinal: int | None,
        result: str | None,
        companions: tuple[tuple[str, str], ...],
    ) -> None:
        del phase, connection_ordinal, transaction_ordinal, result, companions
        raise RuntimeError("diagnostic observer failure")


def _verified(nonce: str, operation_id: str = "operation-one") -> _VerifiedExecution:
    context = VerifiedExecutionContext(
        operation_kind="observed_lifecycle_v1",
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
        operation_domain="rsd.observed-lifecycle-operation.v1",
        operation_kind="observed_lifecycle_v1",
        operation_id="operation-one",
        proposal_sha256="b" * 64,
        contract_sha256="c" * 64,
        disposal_owner="journal-owner",
        approver_identity="journal-approver",
        journal_path=str(journal._path),
        journal_path_sha256=journal._path_sha256(),
        journal_uuid=str(uuid.uuid4()),
        journal_schema_sha256=journal.journal_schema_sha256(),
        replay_policy_sha256="e" * 64,
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


def _diagnostic_claim_worker(
    path: str,
    nonce: str,
    operation_id: str,
    start: _StartGate,
    result_queue: _ResultQueue,
    event_queue: _DiagnosticEventQueue,
    process_ordinal: int,
    fail_before_receipt: bool = False,
) -> None:
    observer = _RecordingJournalObserver(
        process_ordinal=process_ordinal, journal_ordinal=process_ordinal
    )
    start.wait()
    if fail_before_receipt:
        raise RuntimeError("diagnostic worker failure")
    try:
        SQLiteAuthorizationJournal(Path(path), diagnostic_observer=observer)._claim_verified(
            _verified(nonce, operation_id)
        )
    except AuthorizationError as error:
        result_queue.put(error.phase)
    else:
        result_queue.put("claimed")
    finally:
        event_queue.put(observer.receipt())


def _cleanup_diagnostic_workers(workers: list[multiprocessing.Process]) -> None:
    """Terminate, reap, and finally kill only workers started by this case."""

    deadline = time.monotonic() + _DIAGNOSTIC_TIMEOUT_SECONDS
    for worker in workers:
        if worker.is_alive():
            worker.terminate()
    for worker in workers:
        worker.join(timeout=max(0.0, deadline - time.monotonic()))
    for worker in workers:
        if worker.is_alive():
            worker.kill()
    for worker in workers:
        worker.join(timeout=max(0.0, deadline - time.monotonic()))
        assert not worker.is_alive(), worker.pid


def _close_diagnostic_queues(*queues: object) -> None:
    for event_queue in queues:
        close = getattr(event_queue, "close", None)
        cancel_join_thread = getattr(event_queue, "cancel_join_thread", None)
        if callable(close):
            with suppress(OSError, ValueError):
                close()
        if callable(cancel_join_thread):
            with suppress(OSError, ValueError):
                cancel_join_thread()


def _run_process_claim_control(root: Path, *, operation_id: str) -> None:
    """Run the identical process race with the observer disabled."""

    journal = _journal_at(root)
    context = multiprocessing.get_context("spawn")
    start = context.Event()
    result_queue = context.Queue()
    workers = [
        context.Process(
            target=_claim_worker,
            args=(str(journal._path), f"{index + 3}" * 32, operation_id, start, result_queue),
        )
        for index in range(2)
    ]
    started_workers: list[multiprocessing.Process] = []
    try:
        for worker in workers:
            worker.start()
            started_workers.append(worker)
        start.set()
        deadline = time.monotonic() + _DIAGNOSTIC_TIMEOUT_SECONDS
        observed = [
            result_queue.get(timeout=max(0.001, deadline - time.monotonic())) for _ in workers
        ]
        for worker in started_workers:
            worker.join(timeout=max(0.0, deadline - time.monotonic()))
            assert worker.exitcode == 0
        assert sorted(observed) == ["claimed", "operation_replayed"]
    finally:
        _cleanup_diagnostic_workers(started_workers)
        _close_diagnostic_queues(result_queue)


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

    _run_process_claim_control(tmp_path / "process-control", operation_id="shared-operation")


def _assert_redacted_diagnostic_events(
    receipt: tuple[tuple[_DiagnosticEvent, ...], bool], *, journal: SQLiteAuthorizationJournal
) -> None:
    """Reject regressions that leak journal inputs into a test failure receipt."""

    events, overflowed = receipt
    assert not overflowed, events
    assert events
    assert all(event[1] >= 1 and event[2] >= 1 and event[3] >= 1 for event in events), events
    assert any(event[4] == 1 for event in events), events
    assert any(event[5] == 1 for event in events), events
    serialized = repr(events)
    assert str(journal._path) not in serialized
    assert "diagnostic-thread-" not in serialized
    assert "diagnostic-process-operation" not in serialized
    assert "cccc" not in serialized
    for event in events:
        if event[7] is not None:
            assert event[7] in _DIAGNOSTIC_IDENTITY_RESULTS | {
                "claimed",
                "operation_replayed",
                "nonce_replayed",
                "committed",
                "authorization",
                "journal_transaction",
                "missing",
                "lstat_error",
                "symlink",
                "nonregular",
                "uid_mismatch",
                "mode_mismatch",
                "nlink_mismatch",
            }
        for suffix, kind in event[8]:
            assert suffix in {"-journal", "-wal", "-shm"}
            assert kind in _DIAGNOSTIC_COMPANION_KINDS


def _assert_claim_phase_coverage(events: tuple[_DiagnosticEvent, ...]) -> None:
    assert {event[6] for event in events} >= {
        "claim_started",
        "claim_operation_read",
        "claim_nonce_read",
        "claim_insert_enter",
        "transaction_begin_enter",
        "transaction_begin_return",
    }, events


def _require_claim_results(
    observed: list[str], expected: list[str], events: tuple[_DiagnosticEvent, ...]
) -> None:
    if sorted(observed) != expected:
        pytest.fail(f"redacted journal diagnostic receipt: {events!r}")


def _journal_diagnostic_runs(request: pytest.FixtureRequest) -> int:
    runs = request.config.getoption("--journal-diagnostic-runs")
    if type(runs) is not int or not 1 <= runs <= 100:
        raise pytest.UsageError("--journal-diagnostic-runs must be in [1, 100]")
    return runs


def _run_thread_claim_diagnostic(root: Path) -> None:
    """The opt-in observer exposes causal phases, never journal input values."""

    journal = _journal_at(root)
    thread_observers = [
        _RecordingJournalObserver(process_ordinal=1, journal_ordinal=index + 1)
        for index in range(2)
    ]
    thread_journals = [
        SQLiteAuthorizationJournal(journal._path, diagnostic_observer=observer)
        for observer in thread_observers
    ]
    with ThreadPoolExecutor(max_workers=2) as executor:
        futures = [
            executor.submit(
                thread_journals[index]._claim_verified,
                _verified("c" * 32, f"diagnostic-thread-{index}"),
            )
            for index in range(2)
        ]
    thread_results = []
    for future in futures:
        try:
            future.result()
        except AuthorizationError as error:
            thread_results.append(error.phase)
        else:
            thread_results.append("claimed")
    receipts = [observer.receipt() for observer in thread_observers]
    events = tuple(event for receipt, _ in receipts for event in receipt)
    _require_claim_results(thread_results, ["claimed", "nonce_replayed"], events)
    _assert_claim_phase_coverage(events)
    for receipt in receipts:
        _assert_redacted_diagnostic_events(receipt, journal=journal)
    for observer in thread_observers:
        observer_events, overflowed = observer.receipt()
        assert not overflowed, observer_events
        sequences = [event[0] for event in observer_events]
        assert sequences == list(range(1, len(sequences) + 1)), observer_events


def _run_thread_claim_control(root: Path) -> None:
    """Run the identical thread race with the observer disabled."""

    journal = _journal_at(root)
    with ThreadPoolExecutor(max_workers=2) as executor:
        futures = [
            executor.submit(
                journal._claim_verified,
                _verified("c" * 32, f"control-thread-{index}"),
            )
            for index in range(2)
        ]
    observed: list[str] = []
    for future in futures:
        try:
            future.result()
        except AuthorizationError as error:
            observed.append(error.phase)
        else:
            observed.append("claimed")
    assert sorted(observed) == ["claimed", "nonce_replayed"]


def test_claim_diagnostic_observer_for_threads_is_redacted_and_ordered(
    tmp_path: Path, request: pytest.FixtureRequest
) -> None:
    for run_ordinal in range(_journal_diagnostic_runs(request)):
        _run_thread_claim_diagnostic(tmp_path / f"thread-{run_ordinal}")
        _run_thread_claim_control(tmp_path / f"thread-control-{run_ordinal}")


def _run_process_claim_diagnostic(
    root: Path,
    *,
    fail_worker: int | None = None,
    timeout_seconds: float = _DIAGNOSTIC_TIMEOUT_SECONDS,
) -> None:
    """Process event receipts retain only opaque local ordinals and phase labels."""

    journal = _journal_at(root)

    context = multiprocessing.get_context("spawn")
    start = context.Event()
    result_queue = context.Queue()
    event_queue = context.Queue()
    workers = [
        context.Process(
            target=_diagnostic_claim_worker,
            args=(
                str(journal._path),
                f"{index + 5}" * 32,
                "diagnostic-process-operation",
                start,
                result_queue,
                event_queue,
                index + 2,
                fail_worker == index,
            ),
        )
        for index in range(2)
    ]
    started_workers: list[multiprocessing.Process] = []
    try:
        for worker in workers:
            worker.start()
            started_workers.append(worker)
        start.set()
        deadline = time.monotonic() + timeout_seconds
        process_results = [
            result_queue.get(timeout=max(0.001, deadline - time.monotonic())) for _ in workers
        ]
        process_receipts = [
            event_queue.get(timeout=max(0.001, deadline - time.monotonic())) for _ in workers
        ]
        for worker in started_workers:
            worker.join(timeout=max(0.0, deadline - time.monotonic()))
            assert worker.exitcode == 0
        events = tuple(event for receipt, _ in process_receipts for event in receipt)
        _require_claim_results(process_results, ["claimed", "operation_replayed"], events)
        _assert_claim_phase_coverage(events)
        for receipt in process_receipts:
            _assert_redacted_diagnostic_events(receipt, journal=journal)
        for worker_events, overflowed in process_receipts:
            assert not overflowed, worker_events
            sequences = [event[0] for event in worker_events]
            assert sequences == list(range(1, len(sequences) + 1)), worker_events
    finally:
        _cleanup_diagnostic_workers(started_workers)
        _close_diagnostic_queues(result_queue, event_queue)


def test_claim_diagnostic_observer_for_processes_is_redacted_and_ordered(
    tmp_path: Path, request: pytest.FixtureRequest
) -> None:
    for run_ordinal in range(_journal_diagnostic_runs(request)):
        _run_process_claim_diagnostic(tmp_path / f"process-{run_ordinal}")
        _run_process_claim_control(
            tmp_path / f"process-control-{run_ordinal}", operation_id="control-process-operation"
        )


def test_claim_diagnostic_worker_failure_reaps_started_peers(tmp_path: Path) -> None:
    before = {worker.pid for worker in multiprocessing.active_children()}
    with pytest.raises(queue.Empty):
        _run_process_claim_diagnostic(
            tmp_path / "process-failure",
            fail_worker=0,
            timeout_seconds=0.5,
        )
    after = {worker.pid for worker in multiprocessing.active_children()}
    assert after <= before


def test_claim_diagnostic_observer_failure_is_not_silenced(tmp_path: Path) -> None:
    journal = _journal(tmp_path)

    with pytest.raises(RuntimeError, match="diagnostic observer failure"):
        SQLiteAuthorizationJournal(
            journal._path, diagnostic_observer=_FailingJournalObserver()
        )._claim_verified(_verified("d" * 32, "diagnostic-observer-failure"))


def _companion_stat_result(*, mode: int, uid: int, nlink: int) -> os.stat_result:
    return os.stat_result((mode, 0, 0, nlink, uid, 0, 0, 0, 0, 0))


@pytest.mark.parametrize(
    ("mode", "uid", "nlink", "expected"),
    [
        (stat.S_IFLNK | 0o777, os.getuid(), 1, "symlink"),
        (stat.S_IFDIR | 0o700, os.getuid(), 1, "nonregular"),
        (stat.S_IFREG | 0o600, os.getuid() + 1, 1, "uid_mismatch"),
        (stat.S_IFREG | 0o644, os.getuid(), 1, "mode_mismatch"),
        (stat.S_IFREG | 0o600, os.getuid(), 2, "nlink_mismatch"),
    ],
)
def test_diagnostic_companion_snapshot_precedence_is_redacted(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch, mode: int, uid: int, nlink: int, expected: str
) -> None:
    journal = _journal(tmp_path)
    observer = _RecordingJournalObserver(process_ordinal=1, journal_ordinal=1)
    diagnostic = SQLiteAuthorizationJournal(journal._path, diagnostic_observer=observer)
    candidate = journal._path.with_name(f"{journal._path.name}-wal")
    real_lstat = os.lstat
    calls = 0

    def snapshot_lstat(path: str | os.PathLike[str]) -> os.stat_result:
        nonlocal calls
        if Path(path) == candidate:
            calls += 1
            return _companion_stat_result(mode=mode, uid=uid, nlink=nlink)
        return real_lstat(path)

    monkeypatch.setattr(os, "lstat", snapshot_lstat)
    with pytest.raises(AuthorizationError, match="journal_path"):
        diagnostic._validate_companions()
    events, overflowed = observer.receipt()
    assert not overflowed
    assert calls == 2
    assert any(
        event[6] == "companions_failed"
        and event[7] == expected
        and event[8] == (("-wal", expected),)
        for event in events
    ), events


@pytest.mark.parametrize("failure", ["missing", "lstat_error"])
def test_diagnostic_companion_snapshot_acquisition_is_redacted(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch, failure: str
) -> None:
    journal = _journal(tmp_path)
    observer = _RecordingJournalObserver(process_ordinal=1, journal_ordinal=1)
    diagnostic = SQLiteAuthorizationJournal(journal._path, diagnostic_observer=observer)
    candidate = journal._path.with_name(f"{journal._path.name}-wal")
    candidate.touch(mode=0o600)
    real_lstat = os.lstat
    calls = 0

    def fail_second_lstat(path: str | os.PathLike[str]) -> os.stat_result:
        nonlocal calls
        if Path(path) == candidate:
            calls += 1
            if calls == 2:
                if failure == "missing":
                    raise FileNotFoundError
                raise OSError("redacted test fault")
        return real_lstat(path)

    monkeypatch.setattr(os, "lstat", fail_second_lstat)
    with pytest.raises(AuthorizationError, match="journal_path"):
        diagnostic._validate_companions()
    events, overflowed = observer.receipt()
    assert not overflowed
    assert calls == 2
    assert any(
        event[6] == "companions_failed" and event[7] == failure and event[8] == (("-wal", failure),)
        for event in events
    ), events


def test_diagnostic_companion_regular_snapshot_is_redacted(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    journal = _journal(tmp_path)
    observer = _RecordingJournalObserver(process_ordinal=1, journal_ordinal=1)
    diagnostic = SQLiteAuthorizationJournal(journal._path, diagnostic_observer=observer)
    candidate = journal._path.with_name(f"{journal._path.name}-wal")
    real_lstat = os.lstat
    calls = 0

    def regular_lstat(path: str | os.PathLike[str]) -> os.stat_result:
        nonlocal calls
        if Path(path) == candidate:
            calls += 1
            return _companion_stat_result(mode=stat.S_IFREG | 0o600, uid=os.getuid(), nlink=1)
        return real_lstat(path)

    monkeypatch.setattr(os, "lstat", regular_lstat)
    diagnostic._validate_companions()
    events, overflowed = observer.receipt()
    assert not overflowed
    assert calls == 2
    assert any(
        event[8] == (("-journal", "missing"), ("-wal", "regular"), ("-shm", "missing"))
        for event in events
    ), events


def test_diagnostic_identity_failures_are_redacted_and_classified(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    journal = _journal(tmp_path)
    observer = _RecordingJournalObserver(process_ordinal=1, journal_ordinal=1)
    diagnostic = SQLiteAuthorizationJournal(journal._path, diagnostic_observer=observer)

    def fail_anchor() -> object:
        raise AuthorizationError("journal_anchor")

    monkeypatch.setattr(diagnostic, "_read_anchor", fail_anchor)
    with pytest.raises(AuthorizationError, match="journal_anchor"):
        diagnostic.assert_identity()
    events, overflowed = observer.receipt()
    assert not overflowed
    assert any(event[6] == "identity_failed" and event[7] == "anchor" for event in events), events
    assert str(journal._path) not in repr(events)


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


@pytest.mark.parametrize("target", ("database", "anchor", "marker"))
def test_execution_pin_rejects_exact_pre_effect_object_replacement(
    tmp_path: Path, target: str
) -> None:
    journal = _journal(tmp_path)
    pin = journal._pin_execution_identity()
    source = {
        "database": journal._path,
        "anchor": journal._anchor_path(),
        "marker": journal._genesis_marker_path(),
    }[target]
    replacement = tmp_path / f"replacement-{target}"
    shutil.copy2(source, replacement)
    replacement.chmod(0o600)
    os.replace(replacement, source)

    with pytest.raises(AuthorizationError, match="journal_identity_pinned"):
        journal._assert_pinned_execution_identity(pin)


@pytest.mark.parametrize(
    "statement",
    (
        "CREATE VIEW authorization_unexpected_view AS SELECT operation_id "
        "FROM authorization_operation_journal",
        """
        CREATE TRIGGER authorization_unexpected_trigger
        AFTER INSERT ON authorization_operation_journal
        BEGIN
            SELECT 1;
        END
        """,
    ),
)
def test_journal_rejects_unexpected_sqlite_views_or_triggers(
    tmp_path: Path, statement: str
) -> None:
    journal = _journal(tmp_path)
    connection = sqlite3.connect(journal._path)
    try:
        connection.execute(statement)
        connection.commit()
    finally:
        connection.close()

    assert journal.migration_status() is JournalMigrationStatus.IDENTITY_MISMATCH
    with pytest.raises(AuthorizationError, match="journal_schema"):
        journal._claim_verified(_verified("a" * 32, "schema-object-operation"))


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
