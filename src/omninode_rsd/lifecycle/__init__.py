"""Event creation, reduction, projection, and replay primitives."""

from omninode_rsd.lifecycle.event_log import InMemoryEventLog
from omninode_rsd.lifecycle.ingress import LifecycleEventIngress
from omninode_rsd.lifecycle.models import (
    LifecycleDescription,
    LifecycleEvent,
    LifecycleEventIntent,
    LifecycleEventType,
    LifecycleRunProjection,
    LifecycleState,
    LifecycleTransition,
)
from omninode_rsd.lifecycle.reducer import reduce_lifecycle_event
from omninode_rsd.lifecycle.replay import (
    LifecycleReplay,
    LifecycleReplayArtifactError,
    LifecycleReplayInputError,
    LifecycleReplayMismatchError,
    LifecycleReplayRunMismatchError,
    LifecycleReplayVerificationError,
    replay_lifecycle,
    verify_lifecycle_replay,
)
from omninode_rsd.lifecycle.validation import (
    load_lifecycle_description,
    parse_lifecycle_description,
)

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
