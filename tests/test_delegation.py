from __future__ import annotations

from pathlib import Path
from uuid import uuid4

import pytest

from omninode_rsd.delegation import (
    DelegatedRequest,
    DelegatedRequestIngress,
    VerifiedGrantFacts,
    load_delegation_overlay,
)
from omninode_rsd.lifecycle import InMemoryEventLog, LifecycleEventIngress


def _request() -> DelegatedRequest:
    return DelegatedRequest(
        run_id=uuid4(),
        request_sha256="a" * 64,
        artifact_sha256="b" * 64,
        model_id="Qwen/Qwen3.8-27B",
    )


class _Claim:
    def __init__(self, result: bool = True) -> None:
        self.result, self.calls = result, 0

    def claim(self, request: DelegatedRequest, facts: VerifiedGrantFacts) -> bool:
        self.calls += 1
        return self.result


class _Dispatch:
    def __init__(self) -> None:
        self.calls = 0

    def dispatch(self, request: DelegatedRequest) -> None:
        self.calls += 1


def _ingress(
    verifier: object,
    claim: _Claim,
    dispatch: _Dispatch,
    log: InMemoryEventLog | object | None = None,
) -> DelegatedRequestIngress:
    return DelegatedRequestIngress(
        verify_grant=verifier,
        claim_port=claim,
        dispatch_port=dispatch,
        event_log=log or InMemoryEventLog(),
        event_ingress=LifecycleEventIngress(),
    )  # type: ignore[arg-type]


@pytest.mark.parametrize(
    "wire, facts",
    [
        (None, None),
        (b"x", VerifiedGrantFacts("x" * 64, "b" * 64, "Qwen/Qwen3.8-27B")),
        (b"x", VerifiedGrantFacts("a" * 64, "b" * 64, "other")),
        (b"x", VerifiedGrantFacts("a" * 64, "b" * 64, "Qwen/Qwen3.8-27B", True)),
    ],
)
def test_grant_absence_or_mismatch_never_claims_or_dispatches(
    wire: bytes | None, facts: VerifiedGrantFacts | None
) -> None:
    claim, dispatch = _Claim(), _Dispatch()
    verifier = (
        (lambda _: facts)
        if facts is not None
        else (lambda _: (_ for _ in ()).throw(ValueError("bad")))
    )
    assert not _ingress(verifier, claim, dispatch).submit(_request(), wire)
    assert claim.calls == dispatch.calls == 0


def test_claim_failure_or_persistence_failure_never_dispatches() -> None:
    request, dispatch = _request(), _Dispatch()
    facts = VerifiedGrantFacts(request.request_sha256, request.artifact_sha256, request.model_id)
    assert not _ingress(lambda _: facts, _Claim(False), dispatch).submit(request, b"grant")

    class _FailLog:
        def append(self, event: object) -> None:
            raise OSError("unavailable")

    assert not _ingress(lambda _: facts, _Claim(), dispatch, _FailLog()).submit(request, b"grant")
    assert dispatch.calls == 0


def test_success_claims_persists_then_dispatches_once() -> None:
    request, claim, dispatch = _request(), _Claim(), _Dispatch()
    facts = VerifiedGrantFacts(request.request_sha256, request.artifact_sha256, request.model_id)
    assert _ingress(lambda _: facts, claim, dispatch).submit(request, b"grant")
    assert claim.calls == dispatch.calls == 1


def test_canonical_overlay_is_disabled_and_topology_free() -> None:
    overlay = load_delegation_overlay(Path("config/delegation-overlay.yaml"))
    assert not overlay.execute_enabled and overlay.route_ref == "logical://delegation/qwen3.8-27b"
