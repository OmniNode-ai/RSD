from __future__ import annotations

import copy
import importlib.util
import json
import re
import sys
from collections.abc import Callable
from pathlib import Path

import pytest
import yaml

_WORKFLOW_DIR = Path(__file__).parents[1] / ".github" / "workflows"
_HOSTILE_REVIEWER = _WORKFLOW_DIR / "hostile-reviewer.yml"
_SHA_RE = re.compile(r"^\s*(?:-\s*)?uses:\s*(?P<action>[^@\s]+)@(?P<sha>[0-9a-f]{40})(?:\s+#.*)?$")
_PARSER_PATH = Path(__file__).parents[1] / "scripts" / "ci" / "parse_hostile_review.py"
_PARSER_SPEC = importlib.util.spec_from_file_location("parse_hostile_review", _PARSER_PATH)
assert _PARSER_SPEC is not None and _PARSER_SPEC.loader is not None
_PARSER = importlib.util.module_from_spec(_PARSER_SPEC)
sys.modules[_PARSER_SPEC.name] = _PARSER
_PARSER_SPEC.loader.exec_module(_PARSER)
parse_review_result = _PARSER.parse_review_result
_FETCH_PATH = Path(__file__).parents[1] / "scripts" / "ci" / "fetch_hostile_review_input.py"
_FETCH_SPEC = importlib.util.spec_from_file_location("fetch_hostile_review_input", _FETCH_PATH)
assert _FETCH_SPEC is not None and _FETCH_SPEC.loader is not None
_FETCH = importlib.util.module_from_spec(_FETCH_SPEC)
sys.modules[_FETCH_SPEC.name] = _FETCH
_FETCH_SPEC.loader.exec_module(_FETCH)


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
    assert re.search(r"^  pull_request_target:\s*$", text, re.MULTILINE)
    assert not re.search(r"^  pull_request:\s*$", text, re.MULTILINE)
    assert "branches: [main]" in text
    assert "types: [opened, synchronize, reopened]" in text
    assert "contents: read" in text
    assert "pull-requests: read" in text
    assert "pull-requests: write" not in text
    assert text.count("runs-on: ubuntu-latest") == 2
    assert "OMNI_PUBLIC_PR_RUNS_ON_JSON" not in text
    assert "OMNI_TRUSTED_CI_RUNS_ON_JSON" not in text
    assert "self-hosted" not in text
    assert "occ-preflight" not in text
    assert "CodeRabbit" not in text
    assert "github-script" not in text
    assert "upload-artifact" not in text
    assert "actions/cache" not in text
    assert "artifact" not in text.lower()
    assert "reviewer-stderr.log" not in text
    assert "tee " not in text
    assert "--with pyyaml" not in text.lower()
    assert "${{ secrets.GITHUB_TOKEN }}" not in text
    assert text.count("${{ github.token }}") == 1
    assert text.count("${{ secrets.LOCAL_LLM_SHARED_SECRET }}") == 1
    assert text.count("${{ secrets.LLM_QWEN3_REVIEW_URL }}") == 1
    assert text.count("${{ secrets.LLM_QWEN3_REVIEW_B_URL }}") == 1
    assert '--file "$REVIEW_INPUT"' in text
    assert "--no-fallback" in text
    assert "--python 3.12.14" in text
    assert "Hosted runners cannot reach the configured reviewer defaults" in text
    assert "${{ github.event.pull_request.head" not in text
    assert "head.sha" not in text
    assert "/merge" not in text
    assert "gh pr checkout" not in text
    assert "--pr " not in text
    assert not re.search(r"\b(?:\d{1,3}\.){3}\d{1,3}\b", text)


def test_hostile_reviewer_uses_canonical_runner_policy() -> None:
    text = _HOSTILE_REVIEWER.read_text(encoding="utf-8")

    assert text.count("runs-on: ubuntu-latest") == 2
    assert "runs-on: >-" not in text
    assert "fromJSON(" not in text
    assert "github.event.pull_request.head" not in text
    assert "self-hosted" not in text


def test_pull_request_workflows_never_select_self_hosted_runners() -> None:
    for workflow in _WORKFLOW_DIR.glob("*.yml"):
        text = workflow.read_text(encoding="utf-8")
        if not re.search(r"^\s+pull_request(?:_target)?\s*:", text, re.MULTILINE):
            continue
        assert "self-hosted" not in text, workflow
        assert "OMNI_PUBLIC_PR_RUNS_ON_JSON" not in text, workflow
        assert "OMNI_TRUSTED_CI_RUNS_ON_JSON" not in text, workflow


def test_hostile_reviewer_pins_dependencies_and_verifies_checkout() -> None:
    text = _HOSTILE_REVIEWER.read_text(encoding="utf-8")
    expected_pins = {
        "omniintelligence": "dec976b1177cd1338d0d79335d30bebff687d997",
        "omnibase_core": "872beef0397e81064e1212ad5d9d73f173ea3f84",
        "omnibase_compat": "039df62a695f0498821dfd76d44363872c8f6b22",
    }

    assert "git ls-remote" not in text
    assert 'git -C "${target_dir}" rev-parse HEAD' in text
    assert 'git -C "${target_dir}" fetch --no-tags --depth=1 origin "${expected_sha}"' in text
    assert 'git -C "${target_dir}" checkout --detach "${expected_sha}"' in text
    assert "github.event.pull_request.head" not in text
    assert 'git fetch origin "${{ github' not in text
    for repo, sha in expected_pins.items():
        assert sha in text
        assert f"clone_with_retry {repo} ../{repo} {sha}" in text


def test_hostile_reviewer_has_explicit_degraded_fork_and_default_deny_gate() -> None:
    text = _HOSTILE_REVIEWER.read_text(encoding="utf-8")

    assert "Hostile Reviewer (adversarial gate)" in text
    assert "Hostile Review Gate" in text
    assert "verdict=degraded" not in text
    assert "if: always()" in text
    assert 'case "$RESULT" in' in text
    assert "success)" in text
    assert "failure)" in text
    assert "degraded)" in text
    assert "cancelled|skipped)" in text
    assert "*)" in text
    assert '--file "$REVIEW_INPUT"' in text
    assert "--no-fallback" in text
    assert "--python 3.12.14" in text
    assert "--model qwen3-review" in text
    assert "--model qwen3-review-b" in text


def _run_scripts(value: object) -> list[str]:
    if isinstance(value, dict):
        scripts: list[str] = []
        for key, child in value.items():
            if key == "run" and isinstance(child, str):
                scripts.append(child)
            scripts.extend(_run_scripts(child))
        return scripts
    if isinstance(value, list):
        scripts = []
        for child in value:
            scripts.extend(_run_scripts(child))
        return scripts
    return []


def test_workflow_run_blocks_do_not_interpolate_event_data() -> None:
    for workflow in _WORKFLOW_DIR.glob("*.yml"):
        config = yaml.safe_load(workflow.read_text(encoding="utf-8"))
        for script in _run_scripts(config):
            assert "${{" not in script, f"shell interpolation in {workflow}: {script}"
            assert "github.event.pull_request.head" not in script
            assert "head.sha" not in script


def test_hostile_reviewer_pins_toolchain_and_disables_cache() -> None:
    for workflow in (_HOSTILE_REVIEWER, _WORKFLOW_DIR / "test.yml"):
        text = workflow.read_text(encoding="utf-8")
        assert 'version: "0.11.31"' in text
        assert "enable-cache: false" in text

    assert 'python-version: "3.12"' in (_WORKFLOW_DIR / "test.yml").read_text(encoding="utf-8")
    assert "uv python install 3.12.14" in _HOSTILE_REVIEWER.read_text(encoding="utf-8")


def test_hostile_reviewer_uses_only_trusted_base_files() -> None:
    text = _HOSTILE_REVIEWER.read_text(encoding="utf-8")

    assert "ref: ${{ github.sha }}" in text
    assert "path: base" in text
    assert "persist-credentials: false" in text
    assert '"$GITHUB_WORKSPACE/base/scripts/ci/fetch_hostile_review_input.py"' in text
    assert '"$GITHUB_WORKSPACE/base/scripts/ci/parse_hostile_review.py"' in text
    assert "pull_request.head" not in text
    assert "git clone" not in text


def test_hostile_review_gate_is_default_deny_and_fork_fail_closed() -> None:
    text = _HOSTILE_REVIEWER.read_text(encoding="utf-8")
    gate = text.split("  hostile-review-gate:", 1)[1]

    assert "needs: [hostile-review]" in gate
    assert "if: always()" in gate
    assert "REVIEWER_RESULT: ${{ needs.hostile-review.result }}" in gate
    assert 'case "$RESULT" in' in gate
    assert "success)" in gate
    for branch in ("failure)", "degraded)", "cancelled|skipped)", "*)"):
        clause = gate.split(branch, 1)[1].split(";;", 1)[0]
        assert "exit 1" in clause


def test_hostile_reviewer_has_no_fork_skip_or_degraded_success_path() -> None:
    text = _HOSTILE_REVIEWER.read_text(encoding="utf-8")

    assert "if: github.event" not in text
    assert "verdict=degraded" not in text
    assert "continue-on-error" not in text
    assert "failure" in text
    assert "unavailable" in text


def test_hostile_reviewer_parses_actual_model_multi_review_fields() -> None:
    text = _HOSTILE_REVIEWER.read_text(encoding="utf-8")
    parser = (Path(__file__).parents[1] / "scripts" / "ci" / "parse_hostile_review.py").read_text(
        encoding="utf-8"
    )

    assert "parse_hostile_review.py" in text
    assert '"results"' in parser
    assert '"total_findings"' in parser
    assert '"result_count"' in parser
    assert "merged_findings" not in parser
    assert "total_input_findings" not in parser


def test_hostile_review_gate_rejects_every_non_success_result() -> None:
    gate = _HOSTILE_REVIEWER.read_text(encoding="utf-8").split("  hostile-review-gate:", 1)[1]

    for branch in ("failure)", "degraded)", "cancelled|skipped)", "*)"):
        clause = gate.split(branch, 1)[1].split(";;", 1)[0]
        assert "exit 1" in clause


def _finding(severity: str = "warning") -> dict[str, object]:
    return {
        "finding_id": "00000000-0000-0000-0000-000000000001",
        "repo": "OmniNode-ai/RSD",
        "pr_id": 1,
        "rule_id": "review:example",
        "severity": severity,
        "file_path": "src/example.py",
        "line_start": 1,
        "line_end": None,
        "tool_name": "reviewer",
        "tool_version": "1",
        "normalized_message": "example finding",
        "raw_message": "example finding",
        "commit_sha_observed": "abcdef0",
        "observed_at": "2026-08-29T00:00:00+00:00",
        "code_snippet": None,
        "category": None,
        "confidence": None,
        "source_model": "qwen3-review",
        "detection_method": "llm_review",
    }


def _review_envelope(
    first_findings: list[dict[str, object]] | None = None,
) -> dict[str, object]:
    first_findings = first_findings or []
    results = [
        {
            "model": "qwen3-review",
            "prompt_version": "v1",
            "success": True,
            "error": None,
            "findings": first_findings,
            "result_count": len(first_findings),
        },
        {
            "model": "qwen3-review-b",
            "prompt_version": "v1",
            "success": True,
            "error": None,
            "findings": [],
            "result_count": 0,
        },
    ]
    return {
        "models_attempted": ["qwen3-review", "qwen3-review-b"],
        "models_succeeded": ["qwen3-review", "qwen3-review-b"],
        "models_failed": [],
        "results": results,
        "total_findings": len(first_findings),
    }


def test_review_parser_accepts_actual_envelope_and_counts_nested_findings() -> None:
    summary = parse_review_result(json.dumps(_review_envelope([_finding("error")])))

    assert summary.verdict == "blocked"
    assert summary.blocking_count == 1
    assert summary.total_findings == 1
    assert summary.models_succeeded == ("qwen3-review", "qwen3-review-b")


def test_review_parser_accepts_empty_successful_finding_lists() -> None:
    summary = parse_review_result(json.dumps(_review_envelope()))

    assert summary.verdict == "passed"
    assert summary.blocking_count == 0
    assert summary.total_findings == 0


@pytest.mark.parametrize(
    "mutate",
    [
        lambda result: result.pop("results"),
        lambda result: result.__setitem__("merged_findings", []),
        lambda result: result.__setitem__("results", []),
        lambda result: result.__setitem__("total_findings", "0"),
        lambda result: result["results"][0].__setitem__("result_count", 1),
        lambda result: result["results"][0].__setitem__("success", "true"),
        lambda result: result["results"][0].__setitem__("findings", {}),
        lambda result: result["models_attempted"].__setitem__(0, "qwen3\nreview"),
        lambda result: result["results"][0].__setitem__("model", "qwen3\nreview"),
    ],
)
def test_review_parser_rejects_malformed_or_empty_envelopes(
    mutate: Callable[[dict[str, object]], object],
) -> None:
    result = _review_envelope()
    mutate(result)

    with pytest.raises(ValueError):
        parse_review_result(json.dumps(result))


def test_review_parser_rejects_inconsistent_model_lists_and_totals() -> None:
    result = _review_envelope([_finding()])
    result["models_succeeded"] = ["qwen3-review"]
    with pytest.raises(ValueError):
        parse_review_result(json.dumps(result))

    result = _review_envelope([_finding()])
    result["total_findings"] = 0
    with pytest.raises(ValueError):
        parse_review_result(json.dumps(result))


def test_review_parser_rejects_malformed_nested_finding() -> None:
    result = _review_envelope([_finding()])
    finding = copy.deepcopy(result["results"][0]["findings"][0])
    finding["severity"] = "unknown"
    result["results"][0]["findings"][0] = finding

    with pytest.raises(ValueError):
        parse_review_result(json.dumps(result))


@pytest.mark.parametrize("forbidden", ["onex-allow-internal-ip", "192.", "201:"])
def test_hostile_reviewer_does_not_encode_lab_topology(forbidden: str) -> None:
    assert forbidden not in _HOSTILE_REVIEWER.read_text(encoding="utf-8")


@pytest.mark.parametrize(
    ("repository", "expected"),
    [
        ("OmniNode-ai/RSD", "OmniNode-ai/RSD"),
        ("owner.with-dash/repo_name", "owner.with-dash/repo_name"),
    ],
)
def test_review_input_validates_repository_slug(repository: str, expected: str) -> None:
    assert _FETCH.validate_repository(repository) == expected


@pytest.mark.parametrize("repository", ["", "owner", "owner/name/extra", "$(touch pwned)/repo"])
def test_review_input_rejects_malformed_repository_slug(repository: str) -> None:
    with pytest.raises(ValueError):
        _FETCH.validate_repository(repository)


@pytest.mark.parametrize(
    ("raw_number", "expected"),
    [("1", 1), ("0007", 7), (str(_FETCH.MAX_PR_NUMBER), _FETCH.MAX_PR_NUMBER)],
)
def test_review_input_validates_pull_request_number(raw_number: str, expected: int) -> None:
    assert _FETCH.parse_pull_request_number(raw_number) == expected


@pytest.mark.parametrize("raw_number", ["0", "-1", "+1", "1.0", "", "100000000"])
def test_review_input_rejects_malformed_pull_request_number(raw_number: str) -> None:
    with pytest.raises(ValueError):
        _FETCH.parse_pull_request_number(raw_number)


class _FakeResponse:
    def __init__(self, payload: object) -> None:
        self.payload = payload
        self.read_once = False

    def read(self, size: int) -> object:
        del size
        if self.read_once:
            return b""
        self.read_once = True
        return self.payload


@pytest.mark.parametrize("payload", [b"diff --git a/a b/a\n", "not bytes"])
def test_review_input_bounded_reader_accepts_only_utf8_bytes(payload: object) -> None:
    if isinstance(payload, bytes):
        assert _FETCH._read_bounded(_FakeResponse(payload), 100) == payload
    else:
        with pytest.raises(ValueError):
            _FETCH._read_bounded(_FakeResponse(payload), 100)


@pytest.mark.parametrize(
    "payload",
    [b"", b" \n", b"x" * 11, b"\xff"],
)
def test_review_input_bounded_reader_rejects_empty_oversized_or_invalid_data(
    payload: bytes,
) -> None:
    with pytest.raises(ValueError):
        _FETCH._read_bounded(_FakeResponse(payload), 10)


def test_review_input_writer_exposes_only_a_trusted_absolute_path(tmp_path: Path) -> None:
    output_path = tmp_path / "review.diff"
    github_output = tmp_path / "github-output"

    _FETCH.write_review_input(b"diff --git a/a b/a\n", output_path, github_output)

    assert output_path.read_bytes() == b"diff --git a/a b/a\n"
    assert github_output.read_text(encoding="utf-8") == f"path={output_path}\n"


def test_review_input_writer_rejects_relative_paths(tmp_path: Path) -> None:
    with pytest.raises(ValueError):
        _FETCH.write_review_input(b"diff\n", Path("review.diff"), tmp_path / "output")


def test_review_input_writer_rejects_non_utf8_data(tmp_path: Path) -> None:
    with pytest.raises(ValueError):
        _FETCH.write_review_input(b"\xff", tmp_path / "review.diff", tmp_path / "output")


def test_review_input_fetch_uses_read_only_github_diff_endpoint(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    captured: dict[str, object] = {}

    class ContextResponse(_FakeResponse):
        def __enter__(self) -> ContextResponse:
            return self

        def __exit__(self, *_args: object) -> None:
            return None

    def fake_urlopen(request: object, timeout: int) -> ContextResponse:
        captured["request"] = request
        captured["timeout"] = timeout
        return ContextResponse(b"diff --git a/a b/a\n")

    monkeypatch.setattr(_FETCH, "urlopen", fake_urlopen)
    assert _FETCH.fetch_pull_request_diff("owner/repo", 7, "token") == b"diff --git a/a b/a\n"

    request = captured["request"]
    assert isinstance(request, _FETCH.Request)
    assert request.full_url == "https://api.github.com/repos/owner/repo/pulls/7"
    assert request.get_header("Accept") == "application/vnd.github.diff"
    assert request.get_header("Authorization") == "Bearer token"
    assert captured["timeout"] == 60
