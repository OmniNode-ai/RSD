"""Validation for the bundled lifecycle description."""

from __future__ import annotations

from pathlib import Path
from typing import cast

import yaml
from pydantic import ValidationError

from rsd_canary.lifecycle.models import (
    ALLOWED_LIFECYCLE_TRANSITIONS,
    LifecycleDescription,
    LifecycleState,
)


class LifecycleDescriptionError(ValueError):
    """Raised when the bundled lifecycle description is malformed."""


class _UniqueKeyLoader(yaml.SafeLoader):
    """Safe YAML loader that rejects duplicate mapping keys."""


def _construct_unique_mapping(
    loader: _UniqueKeyLoader, node: yaml.MappingNode, deep: bool = False
) -> dict[object, object]:
    mapping: dict[object, object] = {}
    for key_node, value_node in node.value:
        key = loader.construct_object(key_node, deep=deep)
        try:
            duplicate_key = key in mapping
        except TypeError as error:
            raise yaml.constructor.ConstructorError(
                "while constructing a mapping",
                node.start_mark,
                "found an unhashable mapping key",
                key_node.start_mark,
            ) from error
        if duplicate_key:
            raise yaml.constructor.ConstructorError(
                "while constructing a mapping",
                node.start_mark,
                f"found duplicate key {key!r}",
                key_node.start_mark,
            )
        mapping[key] = loader.construct_object(value_node, deep=deep)
    return mapping


_UniqueKeyLoader.add_constructor(
    yaml.resolver.BaseResolver.DEFAULT_MAPPING_TAG, _construct_unique_mapping
)


def parse_lifecycle_description(path: Path) -> LifecycleDescription:
    """Load and validate a lifecycle description as a typed model."""

    try:
        contents = path.read_text(encoding="utf-8")
    except UnicodeDecodeError as error:
        raise LifecycleDescriptionError("description is not valid YAML") from error
    try:
        raw = yaml.load(contents, Loader=_UniqueKeyLoader)
    except yaml.YAMLError as error:
        raise LifecycleDescriptionError("description is not valid YAML") from error
    if not isinstance(raw, dict):
        raise LifecycleDescriptionError("description must be a mapping")
    if raw.get("schema_version") != "rsd.lifecycle-description.v1":
        raise LifecycleDescriptionError("schema_version must be 'rsd.lifecycle-description.v1'")
    try:
        description = LifecycleDescription.model_validate(raw)
    except ValidationError as error:
        raise LifecycleDescriptionError(f"description is not valid: {error}") from error

    expected_states = frozenset(LifecycleState)
    if len(description.states) != len(set(description.states)):
        raise LifecycleDescriptionError("states must not contain duplicates")
    if frozenset(description.states) != expected_states:
        raise LifecycleDescriptionError("states must contain every supported state exactly once")

    topology = tuple(
        (transition.source_state, transition.event_type, transition.target_state)
        for transition in description.transitions
    )
    expected_topology = frozenset(
        (source_state, event_type, target_state)
        for (source_state, event_type), target_state in ALLOWED_LIFECYCLE_TRANSITIONS.items()
    )
    if len(topology) != len(set(topology)):
        raise LifecycleDescriptionError("transitions must not contain duplicates")
    if frozenset(topology) != expected_topology:
        raise LifecycleDescriptionError(
            "transitions must contain the supported lifecycle topology exactly once"
        )
    return description


def load_lifecycle_description(path: Path) -> dict[str, object]:
    """Load a validated lifecycle description with the original dict API."""

    return cast(dict[str, object], parse_lifecycle_description(path).model_dump(mode="json"))
