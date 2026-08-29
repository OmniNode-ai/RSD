#!/usr/bin/env python3
"""Validate and summarize the omniintelligence hostile-review JSON envelope.

The field sets mirror the pinned ``omniintelligence``
``ModelMultiReviewResult``, ``ModelExternalReviewResult``, and
``ModelReviewFindingObserved`` models at commit
``dec976b1177cd1338d0d79335d30bebff687d997``.  This parser is deliberately
strict: a model result must not be allowed to become a passing check merely
because an unexpected, empty, or renamed field was ignored.
"""

from __future__ import annotations

import json
import sys
from dataclasses import dataclass
from datetime import datetime
from typing import Final
from uuid import UUID

MULTI_RESULT_FIELDS: Final[frozenset[str]] = frozenset(
    {
        "models_attempted",
        "models_succeeded",
        "models_failed",
        "results",
        "total_findings",
    }
)
PER_MODEL_RESULT_FIELDS: Final[frozenset[str]] = frozenset(
    {
        "model",
        "prompt_version",
        "success",
        "error",
        "findings",
        "result_count",
    }
)
FINDING_FIELDS: Final[frozenset[str]] = frozenset(
    {
        "finding_id",
        "repo",
        "pr_id",
        "rule_id",
        "severity",
        "file_path",
        "line_start",
        "line_end",
        "tool_name",
        "tool_version",
        "normalized_message",
        "raw_message",
        "commit_sha_observed",
        "observed_at",
        "code_snippet",
        "category",
        "confidence",
        "source_model",
        "detection_method",
    }
)
SEVERITIES: Final[frozenset[str]] = frozenset({"critical", "error", "warning", "info", "hint"})
CATEGORIES: Final[frozenset[str]] = frozenset(
    {
        "security",
        "logic_error",
        "integration",
        "scope_violation",
        "contract_breach",
        "style",
        "informational",
    }
)
CONFIDENCES: Final[frozenset[str]] = frozenset({"high", "medium", "low"})


@dataclass(frozen=True, slots=True)
class ReviewSummary:
    """Validated review outcome used by the workflow step."""

    verdict: str
    blocking_count: int
    total_findings: int
    models_succeeded: tuple[str, ...]


def _require_keys(value: object, expected: frozenset[str], label: str) -> dict[str, object]:
    if not isinstance(value, dict) or set(value) != expected:
        raise ValueError(f"{label} schema is malformed")
    return value


def _require_nonempty_string(value: object, label: str) -> str:
    if not isinstance(value, str) or not value:
        raise ValueError(f"{label} must be a non-empty string")
    return value


def _require_nonnegative_integer(value: object, label: str) -> int:
    if not isinstance(value, int) or isinstance(value, bool) or value < 0:
        raise ValueError(f"{label} must be a non-negative integer")
    return value


def _validate_finding(raw_finding: object) -> dict[str, object]:
    finding = _require_keys(raw_finding, FINDING_FIELDS, "review finding")
    try:
        UUID(_require_nonempty_string(finding["finding_id"], "finding_id"))
    except ValueError as error:
        raise ValueError("finding_id must be a UUID") from error
    repo = _require_nonempty_string(finding["repo"], "repo")
    if len(repo) < 3:
        raise ValueError("repo must contain at least three characters")
    pr_id = finding["pr_id"]
    if not isinstance(pr_id, int) or isinstance(pr_id, bool) or pr_id <= 0:
        raise ValueError("pr_id must be a positive integer")
    _require_nonempty_string(finding["rule_id"], "rule_id")
    severity = _require_nonempty_string(finding["severity"], "severity")
    if severity not in SEVERITIES:
        raise ValueError("severity is not a recognized finding severity")
    _require_nonempty_string(finding["file_path"], "file_path")
    line_start = finding["line_start"]
    if not isinstance(line_start, int) or isinstance(line_start, bool) or line_start <= 0:
        raise ValueError("line_start must be a positive integer")
    line_end = finding["line_end"]
    if line_end is not None and (
        not isinstance(line_end, int) or isinstance(line_end, bool) or line_end <= 0
    ):
        raise ValueError("line_end must be null or a positive integer")
    for field in (
        "tool_name",
        "tool_version",
        "normalized_message",
        "raw_message",
    ):
        _require_nonempty_string(finding[field], field)
    commit_sha = _require_nonempty_string(finding["commit_sha_observed"], "commit_sha_observed")
    if not 7 <= len(commit_sha) <= 40:
        raise ValueError("commit_sha_observed has an invalid length")
    observed_at = _require_nonempty_string(finding["observed_at"], "observed_at")
    try:
        datetime.fromisoformat(observed_at.replace("Z", "+00:00"))
    except ValueError as error:
        raise ValueError("observed_at must be an ISO-8601 datetime") from error
    for field in ("code_snippet", "source_model", "detection_method"):
        value = finding[field]
        if value is not None and not isinstance(value, str):
            raise ValueError(f"{field} must be null or a string")
    category = finding["category"]
    if category is not None and (not isinstance(category, str) or category not in CATEGORIES):
        raise ValueError("category is not a recognized finding category")
    confidence = finding["confidence"]
    if confidence is not None and (
        not isinstance(confidence, str) or confidence not in CONFIDENCES
    ):
        raise ValueError("confidence is not a recognized finding confidence")
    return finding


def parse_review_result(raw_json: str) -> ReviewSummary:
    """Parse one exact ``ModelMultiReviewResult`` JSON document."""

    try:
        raw_result = json.loads(raw_json)
    except json.JSONDecodeError as error:
        raise ValueError("review result is not valid JSON") from error
    result = _require_keys(raw_result, MULTI_RESULT_FIELDS, "multi-model result")

    attempted = result["models_attempted"]
    succeeded = result["models_succeeded"]
    failed = result["models_failed"]
    for field, value in (
        ("models_attempted", attempted),
        ("models_succeeded", succeeded),
        ("models_failed", failed),
    ):
        if not isinstance(value, list) or not all(isinstance(item, str) and item for item in value):
            raise ValueError(f"{field} must be a list of non-empty strings")
    if not attempted:
        raise ValueError("models_attempted must not be empty")
    if len(set(attempted)) != len(attempted):
        raise ValueError("models_attempted must not contain duplicates")
    if len(set(succeeded)) != len(succeeded) or len(set(failed)) != len(failed):
        raise ValueError("model success lists must not contain duplicates")
    if set(succeeded) & set(failed):
        raise ValueError("a model cannot be both succeeded and failed")

    raw_results = result["results"]
    if not isinstance(raw_results, list) or not raw_results:
        raise ValueError("results must be a non-empty list")
    parsed_results: list[tuple[str, bool, int, list[dict[str, object]]]] = []
    for raw_model_result in raw_results:
        model_result = _require_keys(
            raw_model_result,
            PER_MODEL_RESULT_FIELDS,
            "per-model result",
        )
        model = _require_nonempty_string(model_result["model"], "model")
        _require_nonempty_string(model_result["prompt_version"], "prompt_version")
        success = model_result["success"]
        if not isinstance(success, bool):
            raise ValueError("success must be boolean")
        error = model_result["error"]
        if error is not None and not isinstance(error, str):
            raise ValueError("error must be null or a string")
        if success and error is not None:
            raise ValueError("successful result cannot contain an error")
        if not success and not error:
            raise ValueError("failed result must contain an error")
        raw_findings = model_result["findings"]
        if not isinstance(raw_findings, list):
            raise ValueError("findings must be a list")
        findings = [_validate_finding(finding) for finding in raw_findings]
        result_count = _require_nonnegative_integer(model_result["result_count"], "result_count")
        if result_count != len(findings):
            raise ValueError("result_count disagrees with findings")
        parsed_results.append((model, success, result_count, findings))

    result_models = [model for model, _, _, _ in parsed_results]
    if len(set(result_models)) != len(result_models):
        raise ValueError("results must contain unique models")
    if result_models != attempted:
        raise ValueError("models_attempted disagrees with results")
    expected_succeeded = [model for model, success, _, _ in parsed_results if success]
    expected_failed = [model for model, success, _, _ in parsed_results if not success]
    if succeeded != expected_succeeded or failed != expected_failed:
        raise ValueError("model success lists disagree with results")
    if len(succeeded) < 2:
        raise ValueError("at least two models must succeed for a full review")

    total_findings = _require_nonnegative_integer(result["total_findings"], "total_findings")
    expected_total = sum(count for _, success, count, _ in parsed_results if success)
    if total_findings != expected_total:
        raise ValueError("total_findings disagrees with successful per-model results")
    blocking_count = sum(
        1
        for _, success, _, findings in parsed_results
        if success
        for finding in findings
        if finding["severity"] in {"critical", "error"}
    )
    return ReviewSummary(
        verdict="blocked" if blocking_count else "passed",
        blocking_count=blocking_count,
        total_findings=total_findings,
        models_succeeded=tuple(succeeded),
    )


def main() -> int:
    try:
        summary = parse_review_result(sys.stdin.read())
    except ValueError as error:
        print(f"review result rejected: {error}", file=sys.stderr)
        return 1
    print(f"verdict={summary.verdict}")
    print(f"blocking_count={summary.blocking_count}")
    print(f"total_findings={summary.total_findings}")
    print(f"models_succeeded={','.join(summary.models_succeeded)}")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
