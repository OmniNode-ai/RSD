from __future__ import annotations

import importlib.util
import json
import re
import sys
from pathlib import Path
from typing import Any, cast

import pytest

ROOT = Path(__file__).parents[1]


def _load(name: str, path: Path) -> Any:
    spec = importlib.util.spec_from_file_location(name, path)
    assert spec is not None and spec.loader is not None
    module = importlib.util.module_from_spec(spec)
    sys.modules[name] = module
    spec.loader.exec_module(module)
    return module


_FETCH = _load("fetch_hostile_review_input", ROOT / "scripts/ci/fetch_hostile_review_input.py")
_PARSER = _load("parse_hostile_review", ROOT / "scripts/ci/parse_hostile_review.py")


def test_workflow_uses_trusted_base_and_immutable_actions() -> None:
    text = (ROOT / ".github/workflows/hostile-reviewer.yml").read_text(encoding="utf-8")
    assert re.search(r"^  pull_request_target:\s*$", text, re.MULTILINE)
    assert not re.search(r"^  pull_request:\s*$", text, re.MULTILINE)
    assert "ref: ${{ github.sha }}" in text
    assert "path: base" in text
    assert "persist-credentials: false" in text
    assert "--no-fallback" in text
    reviewer = text.split("  hostile-review:\n", 1)[1].split("    timeout-minutes:", 1)[0]
    gate = text.split("  hostile-review-gate:\n", 1)[1]
    assert "github.event.pull_request.head.repo.full_name != github.repository" in reviewer
    assert "'ubuntu-latest'" in reviewer
    assert "fromJSON(vars.OMNI_REVIEW_RUNS_ON_JSON" in reviewer
    assert '["self-hosted","omnibase-ci"]' in reviewer
    assert "runs-on: ubuntu-latest" in gate
    assert "if: always()" in gate
    assert "github.event.pull_request.head.repo.full_name" in reviewer
    assert "github.event.pull_request.head.sha" not in text
    assert "LOCAL_LLM_SHARED_SECRET:" in text
    assert "LLM_QWEN3_REVIEW_URL:" in text
    assert "LLM_QWEN3_REVIEW_B_URL:" in text
    assert text.count("github.event.pull_request.head.repo.full_name == github.repository") == 3
    assert "capture_bounded_stderr" in text
    assert "hostile_review_diagnostics.py" in text
    assert "classify_diagnostic" not in text
    assert not re.search(r"\b(?:\d{1,3}\.){3}\d{1,3}\b", text)
    for line in text.splitlines():
        if "uses:" in line:
            assert re.search(r"@[0-9a-f]{40}(?:\s+#.*)?$", line)


def test_fetch_input_bounds_and_validates_identity() -> None:
    assert _FETCH.validate_repository("OmniNode-ai/RSD") == "OmniNode-ai/RSD"
    assert _FETCH.parse_pull_request_number("9") == 9
    with pytest.raises(ValueError):
        _FETCH.validate_repository("not a repository")
    with pytest.raises(ValueError):
        _FETCH.parse_pull_request_number("0")


def test_parser_requires_two_successful_models() -> None:
    finding: dict[str, object] = {
        "finding_id": "00000000-0000-4000-8000-000000000001",
        "repo": "OmniNode-ai/RSD",
        "pr_id": 9,
        "rule_id": "review:example",
        "severity": "info",
        "file_path": "README.md",
        "line_start": 1,
        "line_end": None,
        "tool_name": "reviewer",
        "tool_version": "1",
        "normalized_message": "informational",
        "raw_message": "informational",
        "commit_sha_observed": "9d8c6f0",
        "observed_at": "2026-09-03T00:00:00Z",
        "code_snippet": None,
        "category": "informational",
        "confidence": "low",
        "source_model": "reviewer",
        "detection_method": "model",
    }
    model = {
        "model": "qwen3-review",
        "prompt_version": "v1",
        "success": True,
        "error": None,
        "findings": [finding],
        "result_count": 1,
    }
    payload = {
        "models_attempted": ["qwen3-review"],
        "models_succeeded": ["qwen3-review"],
        "models_failed": [],
        "results": [model],
        "total_findings": 1,
    }
    with pytest.raises(ValueError, match="at least two models"):
        cast(Any, _PARSER).parse_review_result(json.dumps(payload))
