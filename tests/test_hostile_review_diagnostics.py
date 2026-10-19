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


def _configured_environment(tmp_path: Path) -> dict[str, str]:
    overlay = tmp_path / "voters-overlay.yaml"
    overlay.write_text("roster data", encoding="utf-8")
    return {
        "LOCAL_LLM_SHARED_SECRET": "fixture-signing-key",
        "REVIEW_VOTERS_OVERLAY": str(overlay),
    }


def test_preflight_reports_missing_slots_without_retaining_values() -> None:
    preflight = _DIAGNOSTICS.preflight_reviewer_configuration({})

    assert not preflight.ready
    assert preflight.missing_fields == (
        _DIAGNOSTICS.ConfigurationField.AUTHENTICATION,
        _DIAGNOSTICS.ConfigurationField.VOTERS_OVERLAY,
    )
    assert preflight.malformed_fields == ()


@pytest.mark.parametrize("invalid", ("relative", "missing", "empty", "directory", "nul"))
def test_preflight_rejects_invalid_overlay_without_retaining_path(
    tmp_path: Path,
    invalid: str,
) -> None:
    environment = _configured_environment(tmp_path)
    overlay = Path(environment["REVIEW_VOTERS_OVERLAY"])
    if invalid == "relative":
        environment["REVIEW_VOTERS_OVERLAY"] = "relative-overlay.yaml"
    elif invalid == "missing":
        overlay.unlink()
    elif invalid == "empty":
        overlay.write_text("", encoding="utf-8")
    elif invalid == "nul":
        environment["REVIEW_VOTERS_OVERLAY"] += "\x00"
    else:
        overlay.unlink()
        overlay.mkdir()

    preflight = _DIAGNOSTICS.preflight_reviewer_configuration(environment)

    assert not preflight.ready
    assert preflight.missing_fields == ()
    assert preflight.malformed_fields == (_DIAGNOSTICS.ConfigurationField.VOTERS_OVERLAY,)
    for value in environment.values():
        assert value not in repr(preflight)
    assert not hasattr(preflight, "values")


@pytest.mark.parametrize("key", ("signing\nkey", "signing\rkey"))
def test_preflight_rejects_multiline_authentication(tmp_path: Path, key: str) -> None:
    environment = _configured_environment(tmp_path)
    environment["LOCAL_LLM_SHARED_SECRET"] = key

    preflight = _DIAGNOSTICS.preflight_reviewer_configuration(environment)

    assert not preflight.ready
    assert preflight.malformed_fields == (_DIAGNOSTICS.ConfigurationField.AUTHENTICATION,)
    assert key not in repr(preflight)


@pytest.mark.parametrize("state", ("missing-overlay", "missing-key", "ready"))
def test_preflight_cli_emits_only_category(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
    capsys: pytest.CaptureFixture[str],
    state: str,
) -> None:
    environment = _configured_environment(tmp_path)
    if state == "missing-overlay":
        Path(environment["REVIEW_VOTERS_OVERLAY"]).unlink()
    elif state == "missing-key":
        environment.pop("LOCAL_LLM_SHARED_SECRET")
    for slot in ("REVIEW_VOTERS_OVERLAY", "LOCAL_LLM_SHARED_SECRET"):
        monkeypatch.delenv(slot, raising=False)
    for slot, value in environment.items():
        monkeypatch.setenv(slot, value)

    assert _DIAGNOSTICS.preflight_reviewer_configuration(environment).ready == (state == "ready")
    assert _DIAGNOSTICS.main(["preflight"]) == (0 if state == "ready" else 1)
    captured = capsys.readouterr()
    assert captured.out == ("reviewer-ready\n" if state == "ready" else "reviewer-configuration\n")
    assert captured.err == ""
    for value in environment.values():
        assert value not in captured.out + captured.err


@pytest.mark.parametrize(
    ("diagnostic", "expected"),
    [
        ("request timed out after 30 seconds", "TIMEOUT"),
        ("Connection refused while contacting review service", "CONNECTION"),
        ("server unavailable after connection reset", "CONNECTION"),
        ("failed JSON response", "PARSER"),
        ("HTTP 404 endpoint not found", "CONNECTION"),
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
