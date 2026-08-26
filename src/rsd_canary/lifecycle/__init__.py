"""Event creation, reduction, projection, and replay primitives."""

from rsd_canary.lifecycle.event_log import InMemoryEventLog
from rsd_canary.lifecycle.ingress import LifecycleEventIngress
from rsd_canary.lifecycle.models import (
    LifecycleDescription,
    LifecycleEvent,
    LifecycleEventIntent,
    LifecycleEventType,
    LifecycleRunProjection,
    LifecycleState,
    LifecycleTransition,
)
from rsd_canary.lifecycle.reducer import reduce_lifecycle_event
from rsd_canary.lifecycle.replay import (
    LifecycleReplay,
    LifecycleReplayArtifactError,
    LifecycleReplayInputError,
    LifecycleReplayMismatchError,
    LifecycleReplayRunMismatchError,
    LifecycleReplayVerificationError,
    replay_lifecycle,
    verify_lifecycle_replay,
)
from rsd_canary.lifecycle.validation import load_lifecycle_description, parse_lifecycle_description

__all__ = [
    "InMemoryEventLog",
    "LifecycleDescription",
    "LifecycleEvent",
    "LifecycleEventIngress",
    "LifecycleEventIntent",
    "LifecycleEventType",
    "LifecycleReplay",
    "LifecycleReplayArtifactError",
    "LifecycleReplayInputError",
    "LifecycleReplayMismatchError",
    "LifecycleReplayRunMismatchError",
    "LifecycleReplayVerificationError",
    "LifecycleRunProjection",
    "LifecycleState",
    "LifecycleTransition",
    "load_lifecycle_description",
    "parse_lifecycle_description",
    "reduce_lifecycle_event",
    "replay_lifecycle",
    "verify_lifecycle_replay",
]
