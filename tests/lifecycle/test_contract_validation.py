"""Tests for the bundled lifecycle description."""

from __future__ import annotations

from pathlib import Path

from rsd_canary.lifecycle.validation import load_lifecycle_description


def test_bundled_description_matches_models() -> None:
    path = Path(__file__).parents[2] / "src/rsd_canary/lifecycle/lifecycle_contract.yaml"
    description = load_lifecycle_description(path)

    assert description["schema_version"] == "rsd.lifecycle-description.v1"
    assert len(description["transitions"]) == 4
