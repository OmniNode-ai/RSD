"""Tests for the bundled lifecycle description."""

from __future__ import annotations

from pathlib import Path
from typing import cast

import pytest

from omninode_rsd.lifecycle.models import LifecycleEventType
from omninode_rsd.lifecycle.projection import empty_projection
from omninode_rsd.lifecycle.reducer import reduce_lifecycle_event
from omninode_rsd.lifecycle.validation import (
    LifecycleDescriptionError,
    load_lifecycle_description,
)

from .support import event_stream


def test_bundled_description_matches_models() -> None:
    path = Path(__file__).parents[2] / "src/omninode_rsd/lifecycle/lifecycle_contract.yaml"
    description = load_lifecycle_description(path)

    assert type(description) is dict
    assert description["schema_version"] == "rsd.lifecycle-description.v1"
    assert len(cast(list[object], description["transitions"])) == 5
    assert description["states"] == ["INITIAL", "CREATED", "ACTIVE", "COMPLETED", "FAILED"]
    assert list(description) == ["schema_version", "states", "transitions"]
    assert len(description) == 3
    description["states"].append("MUTATED")
    assert description["states"][-1] == "MUTATED"


def test_description_accepts_reordered_valid_yaml(tmp_path: Path) -> None:
    path = tmp_path / "lifecycle.yaml"
    path.write_text(
        """schema_version: rsd.lifecycle-description.v1
states: [FAILED, COMPLETED, ACTIVE, CREATED, INITIAL]
transitions:
  - {event_type: WORK_FAILED, source_state: ACTIVE, target_state: FAILED}
  - {event_type: WORK_COMPLETED, source_state: ACTIVE, target_state: COMPLETED}
  - {event_type: WORK_STARTED, source_state: CREATED, target_state: ACTIVE}
  - {event_type: WORK_FAILED, source_state: CREATED, target_state: FAILED}
  - {event_type: RUN_CREATED, source_state: INITIAL, target_state: CREATED}
""",
        encoding="utf-8",
    )

    description = load_lifecycle_description(path)

    transitions = cast(list[dict[str, str]], description["transitions"])
    assert transitions[0]["event_type"] == "WORK_FAILED"


@pytest.mark.parametrize(
    "body",
    (
        "schema_version: rsd.lifecycle-description.v1\n"
        "schema_version: rsd.lifecycle-description.v1\n",
        "schema_version: [\n",
    ),
)
def test_description_rejects_duplicate_keys_and_invalid_yaml(tmp_path: Path, body: str) -> None:
    path = tmp_path / "lifecycle.yaml"
    path.write_text(body, encoding="utf-8")

    with pytest.raises(LifecycleDescriptionError, match=r"^description is not valid YAML$"):
        load_lifecycle_description(path)


def test_description_rejects_unknown_keys(tmp_path: Path) -> None:
    path = tmp_path / "lifecycle.yaml"
    path.write_text(
        """schema_version: rsd.lifecycle-description.v1
states: [INITIAL, CREATED, ACTIVE, COMPLETED, FAILED]
transitions: []
unknown: value
""",
        encoding="utf-8",
    )

    with pytest.raises(LifecycleDescriptionError, match="description is not valid"):
        load_lifecycle_description(path)


def test_description_preserves_resource_errors(tmp_path: Path) -> None:
    with pytest.raises(FileNotFoundError):
        load_lifecycle_description(tmp_path / "missing.yaml")


def test_description_rejects_invalid_utf8(tmp_path: Path) -> None:
    path = tmp_path / "invalid.yaml"
    path.write_bytes(b"\xff")

    with pytest.raises(LifecycleDescriptionError, match=r"^description is not valid YAML$"):
        load_lifecycle_description(path)


@pytest.mark.parametrize(
    "body",
    (
        "states: []\ntransitions: []\n",
        "schema_version: rsd.lifecycle-description.v2\nstates: []\ntransitions: []\n",
    ),
)
def test_description_rejects_missing_or_wrong_schema(tmp_path: Path, body: str) -> None:
    path = tmp_path / "lifecycle.yaml"
    path.write_text(body, encoding="utf-8")

    with pytest.raises(LifecycleDescriptionError, match="schema_version"):
        load_lifecycle_description(path)


@pytest.mark.parametrize(
    ("replacement", "message"),
    (
        ("  - INITIAL\n", "duplicates"),
        ("", "every supported state"),
        ("  - UNKNOWN\n", "description is not valid"),
    ),
)
def test_description_rejects_duplicate_missing_or_extra_states(
    tmp_path: Path, replacement: str, message: str
) -> None:
    path = tmp_path / "lifecycle.yaml"
    path.write_text(
        """schema_version: rsd.lifecycle-description.v1
states:
  - INITIAL
  - CREATED
  - ACTIVE
  - COMPLETED
  - FAILED
""".replace("  - FAILED\n", replacement)
        + """transitions:
  - event_type: RUN_CREATED
    source_state: INITIAL
    target_state: CREATED
  - event_type: WORK_STARTED
    source_state: CREATED
    target_state: ACTIVE
  - event_type: WORK_COMPLETED
    source_state: ACTIVE
    target_state: COMPLETED
  - event_type: WORK_FAILED
    source_state: ACTIVE
    target_state: FAILED
""",
        encoding="utf-8",
    )

    with pytest.raises(LifecycleDescriptionError, match=message):
        load_lifecycle_description(path)


@pytest.mark.parametrize(
    ("replacement", "message"),
    (
        (
            "  - event_type: WORK_FAILED\n    source_state: ACTIVE\n    target_state: FAILED\n"
            "  - event_type: WORK_FAILED\n    source_state: ACTIVE\n    target_state: FAILED\n",
            "duplicates",
        ),
        ("", "topology exactly once"),
        (
            "  - event_type: WORK_FAILED\n    source_state: ACTIVE\n    target_state: COMPLETED\n",
            "topology exactly once",
        ),
    ),
)
def test_description_rejects_duplicate_missing_or_drifted_transitions(
    tmp_path: Path, replacement: str, message: str
) -> None:
    path = tmp_path / "lifecycle.yaml"
    path.write_text(
        """schema_version: rsd.lifecycle-description.v1
states:
  - INITIAL
  - CREATED
  - ACTIVE
  - COMPLETED
  - FAILED
transitions:
  - event_type: RUN_CREATED
    source_state: INITIAL
    target_state: CREATED
  - event_type: WORK_STARTED
    source_state: CREATED
    target_state: ACTIVE
  - event_type: WORK_COMPLETED
    source_state: ACTIVE
    target_state: COMPLETED
"""
        + replacement,
        encoding="utf-8",
    )

    with pytest.raises(LifecycleDescriptionError, match=message):
        load_lifecycle_description(path)


def test_every_declared_transition_reduces() -> None:
    reduced_transitions = set[tuple[str, str, str]]()
    for events in (
        event_stream(),
        event_stream(LifecycleEventType.WORK_FAILED),
        event_stream(fail_before_start=True),
    ):
        projection = empty_projection(events[0].run_id)
        for event in events:
            source_state = projection.state
            projection = reduce_lifecycle_event(projection, event)
            reduced_transitions.add(
                (source_state.value, event.event_type.value, projection.state.value)
            )

    path = Path(__file__).parents[2] / "src/omninode_rsd/lifecycle/lifecycle_contract.yaml"
    description = load_lifecycle_description(path)
    transitions = cast(list[dict[str, str]], description["transitions"])
    expected_transitions = {
        (transition["source_state"], transition["event_type"], transition["target_state"])
        for transition in transitions
    }
    assert reduced_transitions == expected_transitions
