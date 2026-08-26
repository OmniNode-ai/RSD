"""Tests for lifecycle models and event creation."""

from __future__ import annotations

from datetime import UTC, datetime
from uuid import UUID

import pytest
from pydantic import ValidationError

from rsd_canary.lifecycle.ingress import InMemorySequenceAllocator, LifecycleEventIngress
from rsd_canary.lifecycle.models import LifecycleEventIntent, LifecycleEventType


def test_ingress_assigns_order_and_chains_hashes() -> None:
    event_ids = iter(
        [
            UUID("00000000-0000-0000-0000-000000000011"),
            UUID("00000000-0000-0000-0000-000000000012"),
        ]
    )
    ingress = LifecycleEventIngress(
        InMemorySequenceAllocator(),
        event_id_factory=lambda: next(event_ids),
        clock=lambda: datetime(2026, 1, 1, tzinfo=UTC),
    )
    intent = LifecycleEventIntent(
        run_id=UUID("00000000-0000-0000-0000-000000000001"),
        event_type=LifecycleEventType.RUN_CREATED,
        detail="created",
    )

    first = ingress.ingest(intent)
    second = ingress.ingest(
        intent.model_copy(update={"event_type": LifecycleEventType.WORK_STARTED})
    )

    assert first.sequence == 1
    assert second.sequence == 2
    assert second.prior_event_hash == first.event_hash


def test_intent_rejects_empty_detail() -> None:
    with pytest.raises(ValidationError):
        LifecycleEventIntent(
            run_id=UUID("00000000-0000-0000-0000-000000000001"),
            event_type=LifecycleEventType.RUN_CREATED,
            detail="",
        )
