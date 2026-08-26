"""Validation for the bundled lifecycle description."""

from __future__ import annotations

from pathlib import Path
from typing import Any

import yaml

from rsd_canary.lifecycle.models import LifecycleEventType, LifecycleState


class LifecycleDescriptionError(ValueError):
    """Raised when the bundled lifecycle description is malformed."""


def load_lifecycle_description(path: Path) -> dict[str, Any]:
    """Load and validate a public lifecycle description file."""

    raw = yaml.safe_load(path.read_text(encoding="utf-8"))
    if not isinstance(raw, dict):
        raise LifecycleDescriptionError("description must be a mapping")
    expected_states = {state.value for state in LifecycleState}
    expected_events = {event.value for event in LifecycleEventType}
    if set(raw.get("states", [])) != expected_states:
        raise LifecycleDescriptionError("states do not match the supported lifecycle")
    transitions = raw.get("transitions")
    if not isinstance(transitions, list) or not transitions:
        raise LifecycleDescriptionError("transitions must be a non-empty list")
    for transition in transitions:
        if not isinstance(transition, dict):
            raise LifecycleDescriptionError("each transition must be a mapping")
        if transition.get("event_type") not in expected_events:
            raise LifecycleDescriptionError("transition has an unknown event type")
        if transition.get("source_state") not in expected_states:
            raise LifecycleDescriptionError("transition has an unknown source state")
        if transition.get("target_state") not in expected_states:
            raise LifecycleDescriptionError("transition has an unknown target state")
    return raw
