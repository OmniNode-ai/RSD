"""Fail-closed delegated-request orchestration with injected authority seams."""

from __future__ import annotations

from dataclasses import dataclass
from pathlib import Path
from typing import Protocol
from uuid import UUID

import yaml
from pydantic import BaseModel, ConfigDict, Field

from omninode_rsd.lifecycle import LifecycleEventIngress, LifecycleEventIntent, LifecycleEventType
from omninode_rsd.lifecycle.event_log import LifecycleEventLog


class DelegatedRequest(BaseModel):
    """Exact facts the caller asks to delegate; execution is always disabled here."""

    model_config = ConfigDict(extra="forbid", frozen=True)
    run_id: UUID
    request_sha256: str = Field(pattern=r"^[0-9a-f]{64}$")
    artifact_sha256: str = Field(pattern=r"^[0-9a-f]{64}$")
    model_id: str = Field(pattern=r"^[A-Za-z0-9._/-]{3,128}$")


class DelegationOverlay(BaseModel):
    """Topology-free, canonical route selection for the disabled seam."""

    model_config = ConfigDict(extra="forbid", frozen=True)
    schema_version: str
    execute_enabled: bool = False
    route_ref: str = Field(pattern=r"^logical://[a-z0-9./-]+$")
    model_ref: str = Field(pattern=r"^[A-Za-z0-9._/-]{3,128}$")


def load_delegation_overlay(path: Path) -> DelegationOverlay:
    """Parse only the tracked canonical overlay; it cannot enable dispatch."""
    try:
        value = yaml.safe_load(path.read_bytes())
    except (OSError, yaml.YAMLError) as error:
        raise ValueError("delegation overlay is unavailable") from error
    try:
        overlay = DelegationOverlay.model_validate(value)
    except Exception as error:
        raise ValueError("delegation overlay is invalid") from error
    if overlay.schema_version != "rsd.delegation-overlay.v1" or overlay.execute_enabled:
        raise ValueError("delegation overlay must remain execute-disabled")
    return overlay


@dataclass(frozen=True)
class VerifiedGrantFacts:
    request_sha256: str
    artifact_sha256: str
    model_id: str
    execute_enabled: bool = False


class GrantVerifier(Protocol):
    def __call__(self, grant_wire: bytes) -> VerifiedGrantFacts: ...


class AtomicClaimPort(Protocol):
    def claim(self, request: DelegatedRequest, facts: VerifiedGrantFacts) -> bool: ...


class DispatchPort(Protocol):
    def dispatch(self, request: DelegatedRequest) -> None: ...


class DelegatedRequestIngress:
    """Compose verified grant, atomic claim, durable lifecycle, then dispatch.

    The caller injects the public signed-grant verifier and later infrastructure
    ports. A missing/invalid grant, any mismatch, uncertain claim, lifecycle
    failure, or execute-enabled grant fails before dispatch.
    """

    def __init__(
        self,
        *,
        verify_grant: GrantVerifier,
        claim_port: AtomicClaimPort,
        dispatch_port: DispatchPort,
        event_log: LifecycleEventLog,
        event_ingress: LifecycleEventIngress,
    ) -> None:
        self._verify_grant = verify_grant
        self._claim_port = claim_port
        self._dispatch_port = dispatch_port
        self._event_log = event_log
        self._event_ingress = event_ingress

    def submit(self, request: DelegatedRequest, grant_wire: bytes | None) -> bool:
        """Return false on every unavailable authority path; never retry or dispatch."""
        if grant_wire is None:
            return False
        try:
            facts = self._verify_grant(grant_wire)
            if facts.execute_enabled or (
                facts.request_sha256 != request.request_sha256
                or facts.artifact_sha256 != request.artifact_sha256
                or facts.model_id != request.model_id
            ):
                return False
            if self._claim_port.claim(request, facts) is not True:
                return False
            event = self._event_ingress.build(
                LifecycleEventIntent(
                    run_id=request.run_id,
                    event_type=LifecycleEventType.RUN_CREATED,
                    detail="delegated request atomically claimed",
                ),
                sequence=1,
            )
            self._event_log.append(event)
            self._dispatch_port.dispatch(request)
        except Exception:
            return False
        return True
