from __future__ import annotations

import re
from pathlib import Path

import pytest
import yaml

_WORKFLOW_DIR = Path(__file__).parents[1] / ".github" / "workflows"
_HOSTILE_REVIEWER = _WORKFLOW_DIR / "hostile-reviewer.yml"
_SHA_RE = re.compile(r"^\s*(?:-\s*)?uses:\s*(?P<action>[^@\s]+)@(?P<sha>[0-9a-f]{40})(?:\s+#.*)?$")


def test_workflows_parse_as_yaml() -> None:
    for workflow in _WORKFLOW_DIR.glob("*.yml"):
        assert isinstance(yaml.safe_load(workflow.read_text(encoding="utf-8")), dict)


def test_all_workflow_actions_are_immutable_and_verified() -> None:
    expected = {
        "actions/checkout@11d5960a326750d5838078e36cf38b85af677262",
        "actions/checkout@3d3c42e5aac5ba805825da76410c181273ba90b1",
        "astral-sh/setup-uv@d4b2f3b6ecc6e67c4457f6d3e41ec42d3d0fcb86",
        "astral-sh/setup-uv@37802adc94f370d6bfd71619e3f0bf239e1f3b78",
    }
    seen: set[str] = set()
    for workflow in _WORKFLOW_DIR.glob("*.yml"):
        for line in workflow.read_text(encoding="utf-8").splitlines():
            if "uses:" not in line:
                continue
            match = _SHA_RE.match(line)
            assert match is not None, f"mutable or malformed action reference in {workflow}: {line}"
            seen.add(f"{match.group('action')}@{match.group('sha')}")
    assert seen == expected


def test_hostile_reviewer_is_fork_safe_and_minimal() -> None:
    text = _HOSTILE_REVIEWER.read_text(encoding="utf-8")
    config = yaml.safe_load(text)

    assert isinstance(config, dict)
    assert "pull_request:" in text
    assert "branches: [main]" in text
    assert "types: [opened, synchronize, reopened]" in text
    assert "contents: read" in text
    assert "pull-requests: read" in text
    assert "pull-requests: write" not in text
    assert "pull_request_target" not in text
    assert "occ-preflight" not in text
    assert "CodeRabbit" not in text
    assert "github-script" not in text
    assert text.count("${{ secrets.GITHUB_TOKEN }}") == 1
    assert text.count("${{ secrets.LOCAL_LLM_SHARED_SECRET }}") == 1
    assert not re.search(r"\b(?:\d{1,3}\.){3}\d{1,3}\b", text)


def test_hostile_reviewer_uses_canonical_runner_policy() -> None:
    text = _HOSTILE_REVIEWER.read_text(encoding="utf-8")

    assert text.count("github.event.pull_request.head.repo.full_name != github.repository") == 3
    assert text.count("github.event.pull_request.head.repo.full_name == github.repository") >= 1
    assert "vars.OMNI_PUBLIC_PR_RUNS_ON_JSON" in text
    assert "vars.OMNI_TRUSTED_CI_RUNS_ON_JSON" in text
    assert '["ubuntu-latest"]' in text
    assert '["self-hosted","omnibase-ci"]' in text


def test_hostile_reviewer_has_explicit_degraded_fork_and_default_deny_gate() -> None:
    text = _HOSTILE_REVIEWER.read_text(encoding="utf-8")

    assert "Hostile Reviewer (adversarial gate)" in text
    assert "Hostile Review Gate" in text
    assert "verdict=degraded" in text
    assert "if: always()" in text
    assert 'case "$RESULT" in' in text
    assert "success)" in text
    assert "failure)" in text
    assert "cancelled|skipped)" in text
    assert "*)" in text
    assert "--model qwen3-review" in text
    assert "--model qwen3-review-b" in text


@pytest.mark.parametrize("forbidden", ["onex-allow-internal-ip", "192.", "201:"])
def test_hostile_reviewer_does_not_encode_lab_topology(forbidden: str) -> None:
    assert forbidden not in _HOSTILE_REVIEWER.read_text(encoding="utf-8")
