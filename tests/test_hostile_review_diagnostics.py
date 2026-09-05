from __future__ import annotations

import importlib.util
import sys
from pathlib import Path
from typing import Any, cast

import pytest

ROOT = Path(__file__).parents[1]
_DIAGNOSTICS_PATH = ROOT / "scripts" / "ci" / "hostile_review_diagnostics.py"
_DIAGNOSTICS_SPEC = importlib.util.spec_from_file_location(
    "hostile_review_diagnostics", _DIAGNOSTICS_PATH
)
assert _DIAGNOSTICS_SPEC is not None and _DIAGNOSTICS_SPEC.loader is not None
_DIAGNOSTICS = importlib.util.module_from_spec(_DIAGNOSTICS_SPEC)
sys.modules[_DIAGNOSTICS_SPEC.name] = _DIAGNOSTICS
_DIAGNOSTICS_SPEC.loader.exec_module(_DIAGNOSTICS)


def _configured_environment() -> dict[str, str]:
    return {
        "LOCAL_LLM_SHARED_SECRET": "configured",
        "LLM_QWEN3_REVIEW_URL": "configured",
        "LLM_QWEN3_REVIEW_B_URL": "configured",
    }


def test_preflight_reports_missing_slots_without_retaining_values() -> None:
    preflight = _DIAGNOSTICS.preflight_reviewer_configuration({})

    assert not preflight.ready
    assert preflight.missing_fields == (
        _DIAGNOSTICS.ConfigurationField.AUTHENTICATION,
        _DIAGNOSTICS.ConfigurationField.PRIMARY_ENDPOINT,
        _DIAGNOSTICS.ConfigurationField.SECONDARY_ENDPOINT,
    )
    assert _DIAGNOSTICS.preflight_reviewer_configuration(_configured_environment()).ready


@pytest.mark.parametrize(
    ("diagnostic", "expected"),
    [
        ("request timed out after 30 seconds", "TIMEOUT"),
        ("Connection refused while contacting review service", "CONNECTION"),
        ("JSONDecodeError while parsing response", "PARSER"),
        ("model qwen-review not found", "MODEL"),
        ("progress completed=4 timeout=30", "ERROR"),
    ],
)
def test_diagnostics_use_fixed_categories_and_do_not_retain_text(
    diagnostic: str,
    expected: str,
) -> None:
    report = _DIAGNOSTICS.classify_reviewer_diagnostics(diagnostic)

    assert report.category is getattr(_DIAGNOSTICS.DiagnosticCategory, expected)
    assert report.captured_bytes == len(diagnostic.encode("utf-8"))
    assert diagnostic not in repr(report)
    assert not hasattr(report, "raw_diagnostics")


def test_diagnostics_reject_oversize_input_without_echoing_it() -> None:
    diagnostic = "x" * (_DIAGNOSTICS.MAX_DIAGNOSTIC_BYTES + 1)

    report = _DIAGNOSTICS.classify_reviewer_diagnostics(diagnostic)

    assert report.category is _DIAGNOSTICS.DiagnosticCategory.ERROR
    assert report.captured_bytes == _DIAGNOSTICS.MAX_DIAGNOSTIC_BYTES


def test_diagnostics_reject_non_text_input() -> None:
    with pytest.raises(TypeError, match="bytes or text"):
        _DIAGNOSTICS.classify_reviewer_diagnostics(cast(Any, object()))
