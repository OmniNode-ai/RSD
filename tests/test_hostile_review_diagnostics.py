from __future__ import annotations

import importlib.util
import json
import os
import subprocess
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


def _failed_review_result() -> dict[str, object]:
    return {
        "models_attempted": ["correctness", "sonnet"],
        "models_succeeded": ["correctness"],
        "models_failed": ["sonnet"],
        "results": [
            {"model": "correctness", "success": True, "error": None},
            {"model": "sonnet", "success": False, "error": "request timed out"},
        ],
    }


def test_failed_voter_cli_names_only_failed_voter_and_safe_category(tmp_path: Path) -> None:
    result = _failed_review_result()
    result["results"][1]["error"] = (  # type: ignore[index]
        "HTTP 401 authentication failed at https://review.example.invalid with bearer secret-value"
    )
    result_path = tmp_path / "result.json"
    result_path.write_text(json.dumps(result), encoding="utf-8")
    completed = subprocess.run(
        [sys.executable, str(_DIAGNOSTICS_PATH), "failures", "--result", str(result_path)],
        capture_output=True,
        text=True,
        check=False,
    )
    assert completed.returncode == 0
    assert completed.stdout == "review voter sonnet failed (category reviewer-authentication)\n"
    assert completed.stderr == ""
    for sensitive_text in ("review.example.invalid", "secret-value", "HTTP 401"):
        assert sensitive_text not in completed.stdout + completed.stderr


def test_failed_voters_keep_their_own_error_categories(tmp_path: Path) -> None:
    result = _failed_review_result()
    result["models_succeeded"] = []
    result["models_failed"] = ["correctness", "sonnet"]
    result["results"][0].update(success=False, error="request timed out")  # type: ignore[index]
    result["results"][1]["error"] = "HTTP 403 forbidden"  # type: ignore[index]
    result_path = tmp_path / "result.json"
    result_path.write_text(json.dumps(result), encoding="utf-8")
    completed = subprocess.run(
        [sys.executable, str(_DIAGNOSTICS_PATH), "failures", "--result", str(result_path)],
        capture_output=True,
        text=True,
        check=False,
    )
    assert completed.returncode == 0
    assert completed.stdout.splitlines() == [
        "review voter correctness failed (category reviewer-timeout)",
        "review voter sonnet failed (category reviewer-authentication)",
    ]
    assert completed.stderr == ""


@pytest.mark.parametrize("invalid", ["identity", "lists", "success", "empty", "oversize"])
def test_failed_voter_cli_rejects_invalid_results_without_echo(
    tmp_path: Path, invalid: str
) -> None:
    result = _failed_review_result()
    if invalid == "identity":
        result["results"][1]["model"] = "sonnet\n::error::secret-value"  # type: ignore[index]
    elif invalid == "lists":
        result["models_failed"] = ["correctness"]
    elif invalid == "success":
        result["results"][1]["success"] = "false"  # type: ignore[index]
    elif invalid == "empty":
        result["results"] = []
    result_path = tmp_path / "result.json"
    result_path.write_text(
        "secret-value" * 120000 if invalid == "oversize" else json.dumps(result),
        encoding="utf-8",
    )
    completed = subprocess.run(
        [sys.executable, str(_DIAGNOSTICS_PATH), "failures", "--result", str(result_path)],
        capture_output=True,
        text=True,
        check=False,
    )
    assert completed.returncode == 1
    assert completed.stdout == "reviewer-error\n"
    assert completed.stderr == ""


@pytest.mark.parametrize("result_state", ["valid", "malformed"])
def test_workflow_failed_review_reports_voter_and_preserves_exit(
    tmp_path: Path, result_state: str
) -> None:
    # Exercise the deployed shell path with only uv/model invocation replaced.
    workflow = (ROOT / ".github/workflows/hostile-reviewer.yml").read_text(encoding="utf-8")
    block = workflow.split("      - name: Run adversarial review\n", 1)[1]
    block = block.split("        run: |\n", 1)[1].split("\n  hostile-review-gate:", 1)[0]
    script = "\n".join(line[10:] for line in block.splitlines())
    fake_bin = tmp_path / "bin"
    fake_bin.mkdir()
    fake_uv = fake_bin / "uv"
    fake_uv.write_text(
        "#!/bin/bash\n"
        "if [[ \" $* \" == *' -m omniintelligence.review_pairing.cli_review '* ]]; then\n"
        '  cat "$FIXTURE_RESULT"\n'
        "  echo 'request timed out; secret-value' >&2\n"
        "  exit 2\n"
        "fi\n"
        "while [[ $1 != python ]]; do shift; done\n"
        "shift\n"
        'exec "$FIXTURE_PYTHON" "$@"\n',
        encoding="utf-8",
    )
    fake_uv.chmod(0o755)
    result_path = tmp_path / "result.json"
    result_path.write_text(json.dumps(_failed_review_result()), encoding="utf-8")
    if result_state == "malformed":
        result_path.write_text("secret-value", encoding="utf-8")
    workspace = tmp_path / "workspace"
    base_scripts = workspace / "base/scripts/ci"
    base_scripts.mkdir(parents=True)
    (base_scripts / "hostile_review_diagnostics.py").symlink_to(_DIAGNOSTICS_PATH)
    overlay = tmp_path / "overlay.yaml"
    overlay.write_text("roster data", encoding="utf-8")
    review_input = tmp_path / "input.diff"
    review_input.write_text("bounded test input", encoding="utf-8")
    env = {
        **os.environ,
        "PATH": f"{fake_bin}:{os.environ['PATH']}",
        "FIXTURE_RESULT": str(result_path),
        "FIXTURE_PYTHON": sys.executable,
        "GITHUB_WORKSPACE": str(workspace),
        "REVIEW_INPUT": str(review_input),
        "REVIEW_VOTERS_OVERLAY": str(overlay),
        "LOCAL_LLM_SHARED_SECRET": "fixture-key",
        "GITHUB_OUTPUT": str(tmp_path / "github-output"),
    }
    completed = subprocess.run(
        ["bash", "-c", script], env=env, capture_output=True, text=True, check=False, timeout=15
    )
    assert completed.returncode == 2, completed.stdout + completed.stderr
    if result_state == "valid":
        assert "review voter sonnet failed (category reviewer-timeout)" in completed.stdout
    else:
        assert "per-voter reviewer diagnostics unavailable" in completed.stdout
    assert "category reviewer-timeout, exit 2" in completed.stdout
    assert "secret-value" not in completed.stdout + completed.stderr
    assert "verdict=passed" not in completed.stdout
