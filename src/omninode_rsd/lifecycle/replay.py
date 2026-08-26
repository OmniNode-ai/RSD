"""Replay ordered lifecycle events into a verified projection."""

from __future__ import annotations

import re
from dataclasses import dataclass

from omninode_rsd.lifecycle.models import LifecycleEvent, LifecycleRunProjection
from omninode_rsd.lifecycle.projection import project_events
from omninode_rsd.lifecycle.reducer import (
    LifecycleReductionError,
    transition_checksum,
    validate_lifecycle_event,
    validate_lifecycle_projection,
)

_LOWERCASE_SHA256_RE = re.compile(r"^[0-9a-f]{64}$")


class LifecycleReplayVerificationError(ValueError):
    """Base error raised when replay verification cannot succeed."""


class LifecycleReplayInputError(LifecycleReplayVerificationError):
    """Raised when the supplied event stream cannot be replayed."""


class LifecycleReplayArtifactError(LifecycleReplayVerificationError):
    """Raised when a supplied replay artifact is malformed or incoherent."""


class LifecycleReplayMismatchError(LifecycleReplayVerificationError):
    """Raised when a valid artifact does not match the canonical replay."""


class LifecycleReplayRunMismatchError(LifecycleReplayMismatchError):
    """Raised when an artifact projection belongs to a different run."""


@dataclass(frozen=True)
class LifecycleReplay:
    """Projection and checksum produced from one event stream."""

    projection: LifecycleRunProjection
    replay_checksum: str


def replay_lifecycle(events: tuple[LifecycleEvent, ...]) -> LifecycleReplay:
    """Reduce a non-empty event stream and return its deterministic checksum."""

    projection = project_events(events)
    return LifecycleReplay(projection=projection, replay_checksum=transition_checksum(events))


def verify_lifecycle_replay(
    events: tuple[LifecycleEvent, ...] | list[LifecycleEvent], replay: LifecycleReplay
) -> None:
    """Verify a replay artifact against the canonical replay of an event snapshot.

    This verifies the supplied artifact and event stream but does not retain or
    mutate either input. The event-stream hash and replay checksum intentionally
    use their existing separate canonical hash domains.
    """

    if type(replay) is not LifecycleReplay:
        raise LifecycleReplayArtifactError("replay artifact is not valid")
    if type(events) is not tuple and type(events) is not list:
        raise LifecycleReplayInputError("replay input must be a tuple or list")
    event_snapshot = tuple(events)
    if not event_snapshot:
        raise LifecycleReplayInputError("replay input must not be empty")

    validated_events: list[LifecycleEvent] = []
    event_ids = set()
    for event in event_snapshot:
        try:
            validated_event = validate_lifecycle_event(event)
        except LifecycleReductionError as error:
            raise LifecycleReplayInputError(f"replay input is not valid: {error}") from error
        if validated_event.event_id in event_ids:
            raise LifecycleReplayInputError("replay input is not valid: event_id is duplicated")
        event_ids.add(validated_event.event_id)
        validated_events.append(validated_event)
    canonical_events = tuple(validated_events)

    try:
        canonical_projection = project_events(canonical_events)
    except LifecycleReductionError as error:
        raise LifecycleReplayInputError(f"replay input is not valid: {error}") from error

    try:
        artifact_projection = validate_lifecycle_projection(replay.projection)
    except LifecycleReductionError as error:
        raise LifecycleReplayArtifactError(f"replay artifact is not valid: {error}") from error
    if type(replay.replay_checksum) is not str or not _LOWERCASE_SHA256_RE.fullmatch(
        replay.replay_checksum
    ):
        raise LifecycleReplayArtifactError(
            "replay artifact checksum is not a lowercase SHA-256 digest"
        )
    if artifact_projection.run_id != canonical_projection.run_id:
        raise LifecycleReplayRunMismatchError(
            "replay artifact run_id does not match the event stream"
        )
    if artifact_projection != canonical_projection:
        raise LifecycleReplayMismatchError("replay projection does not match the event stream")
    if replay.replay_checksum != transition_checksum(canonical_events):
        raise LifecycleReplayMismatchError("replay checksum does not match the event stream")
