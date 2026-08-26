"""Canonical hashing rules shared by ingestion, reduction, and replay."""

from __future__ import annotations

import json
from datetime import date, datetime
from decimal import Decimal
from enum import Enum
from hashlib import sha256
from typing import cast
from uuid import UUID

from pydantic import BaseModel

from omninode_rsd.lifecycle.models import LifecycleEvent, LifecycleRunProjection


def _normalize(value: object) -> object:
    """Convert supported typed values into canonical JSON-compatible values."""

    if isinstance(value, BaseModel):
        return _normalize(value.model_dump(mode="python"))
    if isinstance(value, dict):
        pairs = sorted(value.items(), key=lambda item: str(item[0]))
        return {str(key): _normalize(item) for key, item in pairs}
    if isinstance(value, list | tuple):
        return [_normalize(item) for item in value]
    if isinstance(value, set | frozenset):
        normalized = [_normalize(item) for item in value]
        return sorted(
            normalized,
            key=lambda item: json.dumps(item, sort_keys=True, separators=(",", ":")),
        )
    if isinstance(value, Enum):
        return _normalize(value.value)
    if isinstance(value, UUID):
        return str(value)
    if isinstance(value, datetime):
        return value.isoformat(timespec="microseconds")
    if isinstance(value, date):
        return value.isoformat()
    if isinstance(value, Decimal):
        return format(value.normalize(), "f")
    if value is None or isinstance(value, str | int | float | bool):
        return value
    raise TypeError(f"unsupported canonical JSON value: {type(value).__name__}")


def canonical_json(value: object) -> bytes:
    """Serialize a value with stable ordering and no insignificant whitespace."""

    normalized = _normalize(value)
    return json.dumps(
        normalized,
        sort_keys=True,
        separators=(",", ":"),
        ensure_ascii=True,
        allow_nan=False,
    ).encode("utf-8")


def canonical_hash(value: object) -> str:
    """Return the SHA-256 digest of canonical JSON."""

    return sha256(canonical_json(value)).hexdigest()


def compute_event_hash(event: LifecycleEvent) -> str:
    """Hash the exact persisted event, excluding only its self-referential hash."""

    return canonical_hash(event.model_dump(mode="python", exclude={"event_hash"}))


def advance_event_stream_hash(previous_hash: str, event: LifecycleEvent) -> str:
    """Extend the canonical persisted-event stream hash by one event."""

    return canonical_hash(
        {
            "schema_version": "rsd.lifecycle-event-stream-hash.v1",
            "prior_event_stream_hash": previous_hash,
            "event": event,
        }
    )


def compute_event_stream_hash(events: tuple[LifecycleEvent, ...]) -> str:
    """Hash an ordered authoritative event tuple using the projection's chain rule."""

    stream_hash = "0" * 64
    for event in events:
        stream_hash = advance_event_stream_hash(stream_hash, event)
    return stream_hash


def event_replay_material(event: LifecycleEvent) -> dict[str, object]:
    """Return deterministic transition material, excluding observations of time."""

    return cast(
        dict[str, object],
        event.model_dump(mode="python", exclude={"occurred_at", "event_hash"}),
    )


def advance_transition_checksum(previous_checksum: str, event: LifecycleEvent) -> str:
    """Extend the replay checksum chain with one canonical transition."""

    material = event_replay_material(event)
    # The persisted prior-event field belongs to the observed stream.  Replay uses
    # its own chain so checksums remain independent of wall-clock observations.
    material["prior_event_hash"] = previous_checksum
    return canonical_hash(material)


def compute_projection_checksum(projection: LifecycleRunProjection) -> str:
    """Hash canonical reducer state without its self-referential checksum."""

    return canonical_hash(projection.model_dump(mode="python", exclude={"projection_checksum"}))
