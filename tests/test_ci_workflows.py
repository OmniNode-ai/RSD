from __future__ import annotations

import copy
import importlib.util
import json
import re
import subprocess
import sys
from collections.abc import Callable
from pathlib import Path

import pytest
import yaml

_WORKFLOW_DIR = Path(__file__).parents[1] / ".github" / "workflows"
_HOSTILE_REVIEWER = _WORKFLOW_DIR / "hostile-reviewer.yml"
_RELEASE_WORKFLOW = _WORKFLOW_DIR / "release.yml"
_TEST_WORKFLOW = _WORKFLOW_DIR / "test.yml"
_PRE_COMMIT_CONFIG = Path(__file__).parents[1] / ".pre-commit-config.yaml"
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
        "actions/create-github-app-token@bcd2ba49218906704ab6c1aa796996da409d3eb1",
        "actions/upload-artifact@65c4c4a1ddee5b72f698fdd19549f0f0fb45cf08",
        "astral-sh/setup-uv@d4b2f3b6ecc6e67c4457f6d3e41ec42d3d0fcb86",
        "astral-sh/setup-uv@37802adc94f370d6bfd71619e3f0bf239e1f3b78",
        "OmniNode-ai/omniclaude/.github/workflows/public-repo-hygiene-reusable.yml@6ccd525e2b6390869d18f8e00d1b36294aa5550a",
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


def test_paired_release_workflow_is_build_only() -> None:
    text = _RELEASE_WORKFLOW.read_text(encoding="utf-8")

    assert "workflow_dispatch:" in text
    assert "push:" not in text
    assert "uv publish" not in text
    assert "PYPI_TOKEN" not in text
    assert "secrets." not in text
    assert "contents: read" in text
    assert "actions/upload-artifact@65c4c4a1ddee5b72f698fdd19549f0f0fb45cf08" in text


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
    assert text.count("runs-on: ubuntu-latest") == 1
    assert "OMNI_PUBLIC_PR_RUNS_ON_JSON" not in text
    assert "OMNI_TRUSTED_CI_RUNS_ON_JSON" not in text
    assert "OMNI_REVIEW_RUNS_ON_JSON" in text
    assert "self-hosted" in text
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
    assert "LOCAL_LLM_SHARED_SECRET:" not in text
    assert "LLM_QWEN3_" not in text
    assert "LLM_ENDPOINT_CIDR_ALLOWLIST:" not in text
    assert '--voters-overlay "$REVIEW_VOTERS_OVERLAY"' in text
    assert "--model" not in text
    assert '--file "$REVIEW_INPUT"' in text
    assert "--no-fallback" in text
    assert "--python 3.12" in text
    assert "trusted, base-controlled" in text
    assert "github.event.pull_request.head.repo.full_name" in text
    assert "head.sha" not in text
    assert "/merge" not in text
    assert "gh pr checkout" not in text
    assert "--pr " not in text
    assert not re.search(r"\b(?:\d{1,3}\.){3}\d{1,3}\b", text)


def test_hostile_reviewer_uses_canonical_runner_policy() -> None:
    text = _HOSTILE_REVIEWER.read_text(encoding="utf-8")
    reviewer = text.split("  hostile-review:\n", 1)[1].split("    timeout-minutes:", 1)[0]
    gate = text.split("  hostile-review-gate:\n", 1)[1]

    assert "runs-on: >-" in reviewer
    assert "github.event.pull_request.head.repo.full_name != github.repository" in reviewer
    assert "'ubuntu-latest'" in reviewer
    assert "fromJSON(vars.OMNI_REVIEW_RUNS_ON_JSON" in reviewer
    assert '["self-hosted","omnibase-ci"]' in reviewer
    assert "runs-on: ubuntu-latest" in gate
    assert "github.event.pull_request.head.repo.full_name" in reviewer
    assert "github.event.pull_request.head.sha" not in text
    assert "self-hosted" in reviewer
    assert "LOCAL_LLM_SHARED_SECRET:" not in text
    assert "LLM_QWEN3_" not in text
    assert text.count("github.event.pull_request.head.repo.full_name == github.repository") == 4
    for value in (
        "vars.OMNI_CI_OVERLAY_REPO",
        "vars.OMNI_CI_OVERLAY_REF",
        "secrets.ONEXBOT_APP_ID",
        "secrets.ONEXBOT_APP_PRIVATE_KEY",
    ):
        assert (
            "${{ github.event.pull_request.head.repo.full_name == github.repository && "
            + value
            + " || '' }}"
        ) in text


def test_hostile_reviewer_fetches_pinned_overlay_outside_workspace() -> None:
    config = yaml.safe_load(_HOSTILE_REVIEWER.read_text(encoding="utf-8"))
    job = config["jobs"]["hostile-review"]
    assert job["env"] == {
        "REVIEW_VOTERS_OVERLAY": "${{ github.workspace }}/../ci-overlay/config/onex/overlays/"
        "node_review_voters_overlay_compute/overlay.yaml"
    }
    steps = {step["name"]: step for step in job["steps"]}
    token = steps["Mint a read-only CI overlay token"]
    assert (
        token["uses"] == "actions/create-github-app-token@bcd2ba49218906704ab6c1aa796996da409d3eb1"
    )
    assert token["with"]["permission-contents"] == "read"
    assert token["with"]["repositories"] == "${{ steps.ci-overlay.outputs.name }}"
    overlay = steps["Fetch the CI overlay"]["with"]
    assert overlay["ref"] == "${{ steps.ci-overlay.outputs.ref }}"
    assert overlay["token"] == "${{ steps.ci-overlay-token.outputs.token }}"
    assert overlay["persist-credentials"] is False
    assert (
        overlay["sparse-checkout"].strip()
        == "config/onex/overlays/node_review_voters_overlay_compute"
    )
    assert overlay["sparse-checkout-cone-mode"] is False
    place = steps["Place the CI overlay outside the workspace"]
    assert place["env"]["EXPECTED_OVERLAY_REF"] == "${{ steps.ci-overlay.outputs.ref }}"
    assert "mv .ci-overlay-checkout ../ci-overlay" in place["run"]
    assert 'FETCHED_REF="$(git -C ../ci-overlay rev-parse HEAD)"' in place["run"]
    assert 'if [ "${FETCHED_REF}" != "${EXPECTED_OVERLAY_REF}" ]; then' in place["run"]
    review = steps["Run adversarial review"]
    assert review["env"] == {
        "REVIEW_INPUT": "${{ steps.fetch-diff.outputs.path }}",
        "REVIEW_REPOSITORY": "${{ github.repository }}",
    }
    assert list(steps).index("Resolve the CI overlay") < list(steps).index("Run adversarial review")


@pytest.mark.parametrize(
    ("repo", "ref", "expected"),
    [
        ("", "", "no review voters configured"),
        ("bad\n::warning::injected", "a" * 40, "must be a bare repository name"),
        ("owner/repo", "a" * 40, "must be a bare repository name"),
        ("overlay", "", "OMNI_CI_OVERLAY_REF is unset"),
        ("overlay", "dev", "full 40-hex lowercase commit sha"),
        ("overlay", "A" * 40, "full 40-hex lowercase commit sha"),
        ("overlay", "a" * 40 + "\n::warning::injected", "full 40-hex lowercase commit sha"),
    ],
)
def test_overlay_resolver_fails_closed_without_echoing_rejected_values(
    tmp_path: Path,
    repo: str,
    ref: str,
    expected: str,
) -> None:
    config = yaml.safe_load(_HOSTILE_REVIEWER.read_text(encoding="utf-8"))
    resolve = next(
        step
        for step in config["jobs"]["hostile-review"]["steps"]
        if step["name"] == "Resolve the CI overlay"
    )
    output = tmp_path / "output"
    result = subprocess.run(
        ["bash", "-c", resolve["run"]],
        env={"CI_OVERLAY_REPO": repo, "CI_OVERLAY_REF": ref, "GITHUB_OUTPUT": str(output)},
        capture_output=True,
        text=True,
        check=False,
    )
    assert result.returncode == 1
    assert expected in result.stdout
    assert "::warning::injected" not in result.stdout + result.stderr
    assert not output.exists()


def test_pull_request_workflows_never_select_self_hosted_runners() -> None:
    for workflow in _WORKFLOW_DIR.glob("*.yml"):
        text = workflow.read_text(encoding="utf-8")
        if not re.search(r"^\s+pull_request(?:_target)?\s*:", text, re.MULTILINE):
            continue
        if workflow == _HOSTILE_REVIEWER:
            reviewer = text.split("  hostile-review:\n", 1)[1].split("    timeout-minutes:", 1)[0]
            gate = text.split("  hostile-review-gate:\n", 1)[1]
            assert "OMNI_REVIEW_RUNS_ON_JSON" in reviewer
            assert "github.event.pull_request.head.repo.full_name != github.repository" in reviewer
            assert "'ubuntu-latest'" in reviewer
            assert "self-hosted" in reviewer
            assert "runs-on: ubuntu-latest" in gate
            continue
        assert "self-hosted" not in text, workflow
        assert "OMNI_PUBLIC_PR_RUNS_ON_JSON" not in text, workflow
        assert "OMNI_TRUSTED_CI_RUNS_ON_JSON" not in text, workflow


def test_hostile_reviewer_pins_dependencies_and_verifies_checkout() -> None:
    text = _HOSTILE_REVIEWER.read_text(encoding="utf-8")
    expected_pins = {
        "omniintelligence": "475b99d47ef553ada207699178935dbe35b9ebf9",
    }

    assert "omnibase_core" not in text
    assert "omnibase_compat" not in text
    assert "git ls-remote" not in text
    assert 'git -C "${target_dir}" rev-parse HEAD' in text
    assert 'git -C "${target_dir}" fetch --no-tags --depth=1 origin "${expected_sha}"' in text
    assert 'git -C "${target_dir}" checkout --detach "${expected_sha}"' in text
    assert "github.event.pull_request.head.repo.full_name" in text
    assert "github.event.pull_request.head.sha" not in text
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
    assert "--python 3.12" in text
    assert '--voters-overlay "$REVIEW_VOTERS_OVERLAY"' in text
    assert "--model" not in text


def test_hostile_reviewer_bounds_and_normalizes_diagnostics() -> None:
    text = _HOSTILE_REVIEWER.read_text(encoding="utf-8")
    reviewer = text.split("  hostile-review:\n", 1)[1]
    diagnostics = (
        Path(__file__).parents[1] / "scripts" / "ci" / "hostile_review_diagnostics.py"
    ).read_text(encoding="utf-8")

    assert 'REVIEW_TMPDIR="$(mktemp -d)"' in reviewer
    assert "trap 'rm -rf \"$REVIEW_TMPDIR\"' EXIT" in reviewer
    assert 'mkfifo "$REVIEW_FIFO"' in reviewer
    assert "capture_bounded_stderr" in reviewer
    assert "head -c 16384" in reviewer
    assert "cat >/dev/null" in reviewer
    assert '2>"$REVIEW_FIFO"' in reviewer
    assert "2>/dev/null" not in reviewer
    assert '"$REVIEW_STDERR"' in reviewer
    assert "hostile_review_diagnostics.py" in reviewer
    assert "classify_diagnostic" not in reviewer
    for category in (
        "reviewer-timeout",
        "reviewer-authentication",
        "reviewer-model-unavailable",
        "reviewer-rate-limited",
        "reviewer-endpoint-unavailable",
        "reviewer-malformed-response",
        "reviewer-error",
    ):
        assert category in diagnostics
    assert 'echo "$REVIEW_STDERR"' not in reviewer
    assert 'cat "$REVIEW_STDERR"' not in reviewer
    assert "--no-fallback" in reviewer
    assert 'REVIEW_JSON="$(cat "$REVIEW_STDOUT")"' in reviewer


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
    assert "uv python install 3.12" in _HOSTILE_REVIEWER.read_text(encoding="utf-8")


def test_hostile_reviewer_uses_only_trusted_base_files() -> None:
    text = _HOSTILE_REVIEWER.read_text(encoding="utf-8")

    assert "ref: ${{ github.sha }}" in text
    assert "path: base" in text
    assert "persist-credentials: false" in text
    assert '"$GITHUB_WORKSPACE/base/scripts/ci/fetch_hostile_review_input.py"' in text
    assert '"$GITHUB_WORKSPACE/base/scripts/ci/parse_hostile_review.py"' in text
    assert "github.event.pull_request.head.repo.full_name" in text
    assert "github.event.pull_request.head.sha" not in text
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


def test_authored_contract_set_validation_is_wired_as_a_gate() -> None:
    """The authored contract set is re-validated by CI and by pre-commit.

    The unit tests around the harness prove the harness; only running the
    console script against the committed YAML proves the committed contract
    set itself still validates. Wiring it in both places is what stops a
    change to the YAML from landing on the strength of a green unit suite.
    """
    command = "uv run rsd-validate-lab-delegation-contracts"

    workflow = yaml.safe_load(_TEST_WORKFLOW.read_text(encoding="utf-8"))
    assert isinstance(workflow, dict)
    steps = workflow["jobs"]["full-suite"]["steps"]
    assert any(step.get("run") == command for step in steps), (
        "the authored contract set validation is not a step in the test workflow"
    )

    pre_commit = yaml.safe_load(_PRE_COMMIT_CONFIG.read_text(encoding="utf-8"))
    assert isinstance(pre_commit, dict)
    hooks = [hook for repo in pre_commit["repos"] for hook in repo["hooks"]]
    hook = next(
        (item for item in hooks if item["id"] == "validate-lab-delegation-contracts"),
        None,
    )
    assert hook is not None, "the authored contract set validation is not a pre-commit hook"
    assert hook["entry"] == command
    assert hook["pass_filenames"] is False


def _quorum_finding(agreement: int, *, blocking: bool) -> dict[str, object]:
    return {
        "file_path": "src/example.py",
        "line_start": 1,
        "severity": "error" if blocking else "warning",
        "rule": "review:example",
        "message": "example finding",
        "agreeing_models": ["qwen3-review", "qwen3-review-b"][:agreement],
        "agreement_count": agreement,
        "blocking": blocking,
        "finding_ids": ["00000000-0000-0000-0000-000000000001"],
        "standing_rule_id": None,
    }


def _quorum(
    *,
    verdict: str = "passed",
    blocking: int = 0,
    warnings: int = 1,
    threshold: int = 2,
    agreement: int = 1,
) -> dict[str, object]:
    blocking_findings = [
        _quorum_finding(max(agreement, threshold), blocking=True) for _ in range(blocking)
    ]
    warning_findings = [_quorum_finding(agreement, blocking=False) for _ in range(warnings)]
    return {
        "verdict": verdict,
        "quorum_threshold": threshold,
        "models_succeeded": ["qwen3-review", "qwen3-review-b"],
        "quorum_met": True,
        "blocking_count": blocking,
        "warning_count": warnings,
        "blocking_findings": blocking_findings,
        "warning_findings": warning_findings,
    }


def test_review_parser_does_not_block_on_a_single_model_finding() -> None:
    """OMN-18479: one model's error finding is a warning, not a block."""
    envelope = _review_envelope([_finding("error")])
    envelope["quorum"] = _quorum(verdict="passed", blocking=0, warnings=1)

    summary = parse_review_result(json.dumps(envelope))

    assert summary.verdict == "passed"
    assert summary.blocking_count == 0


def test_review_parser_blocks_when_two_models_agree() -> None:
    """Positive control for the zero above, same envelope, agreement of two."""
    envelope = _review_envelope([_finding("error")])
    envelope["quorum"] = _quorum(verdict="blocked", blocking=1, warnings=0, agreement=2)

    summary = parse_review_result(json.dumps(envelope))

    assert summary.verdict == "blocked"
    assert summary.blocking_count == 1


def test_review_parser_refuses_a_verdictless_quorum() -> None:
    envelope = _review_envelope()
    envelope["quorum"] = _quorum(verdict="degraded_quorum", blocking=0, warnings=0)

    with pytest.raises(ValueError):
        parse_review_result(json.dumps(envelope))


def test_review_parser_refuses_a_quorum_threshold_below_two() -> None:
    envelope = _review_envelope()
    envelope["quorum"] = _quorum(threshold=1, warnings=0)

    with pytest.raises(ValueError):
        parse_review_result(json.dumps(envelope))


@pytest.mark.parametrize(
    "mutate",
    [
        lambda quorum: quorum.__setitem__("blocking_count", 1),
        lambda quorum: quorum.__setitem__("verdict", "invented"),
        lambda quorum: quorum.pop("warning_findings"),
        lambda quorum: quorum.__setitem__("unexpected", 1),
        lambda quorum: quorum.__setitem__("quorum_met", "yes"),
        lambda quorum: quorum.__setitem__("models_succeeded", ["qwen3-review"]),
    ],
)
def test_review_parser_rejects_a_malformed_quorum(
    mutate: Callable[[dict[str, object]], object],
) -> None:
    envelope = _review_envelope()
    quorum = _quorum(warnings=0)
    mutate(quorum)
    envelope["quorum"] = quorum

    with pytest.raises(ValueError):
        parse_review_result(json.dumps(envelope))


def test_review_parser_still_rejects_unknown_top_level_keys() -> None:
    """Accepting `quorum` must not have opened the envelope to anything."""
    envelope = _review_envelope()
    envelope["merged_findings"] = []

    with pytest.raises(ValueError):
        parse_review_result(json.dumps(envelope))


def _pinned_review_envelope() -> dict[str, object]:
    """Include every defaulted addition emitted by the pinned CLI."""
    finding = _finding()
    finding["standing_rule_id"] = None
    envelope = _review_envelope([finding])
    envelope.update(
        {
            "total_dropped": 1,
            "skipped_reason": None,
            "standing_rules": None,
            "substitute_votes": [],
            "quorum": _quorum(),
        }
    )
    envelope["quorum"]["distinct_reviewers_succeeded"] = ["identity-a", "identity-b"]
    for model in envelope["results"]:
        model.update(
            {
                "input_tokens": 10,
                "output_tokens": 5,
                "parse_failed": False,
                "raw_reply_length": None,
                "dropped_findings": [],
                "reviewer_identity": None,
            }
        )
    envelope["results"][0]["dropped_findings"] = [
        {
            "title": "No defect",
            "severity": "info",
            "category": "informational",
            "location": None,
            "reason": "The model said the code was correct.",
        }
    ]
    return envelope


def test_review_parser_accepts_pinned_cli_defaults_and_overlay_voter_names() -> None:
    envelope = _pinned_review_envelope()
    names = ["voter-a", "v" + "a" * 62]
    envelope["models_attempted"] = names
    envelope["models_succeeded"] = names
    envelope["quorum"]["models_succeeded"] = names
    envelope["quorum"]["warning_findings"][0]["agreeing_models"] = names[:1]
    for model, name in zip(envelope["results"], names, strict=True):
        model["model"] = name

    summary = parse_review_result(json.dumps(envelope))

    assert summary.verdict == "passed"
    assert summary.total_findings == 1
    assert summary.models_succeeded == tuple(names)


def test_review_parser_accepts_nested_standing_rules_and_substitute_votes() -> None:
    envelope = _pinned_review_envelope()
    envelope["standing_rules"] = {
        "version": "v1",
        "digest": "a" * 64,
        "rule_ids": ["rule-a"],
        "mandatory_rule_ids": ["rule-a"],
        "source": "rules.yaml",
        "gated": False,
        "violations": [{"rule_id": "rule-a", "reason": "removed"}],
        "candidate_errors": [],
    }
    envelope["substitute_votes"] = [
        {
            "voter_id": "voter-a",
            "failure": "timed out",
            "replaced_error": "request timed out",
            "reviewer_ids": ["reviewer-a", "reviewer-b"],
            "head_sha": "a" * 40,
            "review_authors": ["author-a", "author-b"],
        }
    ]

    assert parse_review_result(json.dumps(envelope)).verdict == "passed"


@pytest.mark.parametrize(
    "mutate",
    [
        lambda result: result.__setitem__("truly_unknown", None),
        lambda result: result["results"][0].__setitem__("truly_unknown", None),
        lambda result: result["results"][0]["findings"][0].__setitem__("truly_unknown", None),
        lambda result: result["results"][0]["dropped_findings"][0].__setitem__(
            "truly_unknown", None
        ),
        lambda result: result["quorum"].__setitem__("truly_unknown", None),
        lambda result: result["quorum"]["warning_findings"][0].__setitem__("truly_unknown", None),
        lambda result: result.__setitem__("total_dropped", "1"),
        lambda result: result["results"][0].__setitem__("input_tokens", -1),
        lambda result: result["results"][0].__setitem__("parse_failed", "false"),
        lambda result: result["results"][0]["findings"][0].__setitem__("standing_rule_id", []),
    ],
)
def test_review_parser_rejects_unknown_keys_and_malformed_new_fields(
    mutate: Callable[[dict[str, object]], object],
) -> None:
    envelope = _pinned_review_envelope()
    mutate(envelope)

    with pytest.raises(ValueError):
        parse_review_result(json.dumps(envelope))
