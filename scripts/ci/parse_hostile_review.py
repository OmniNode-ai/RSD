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
import re
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
# OMN-18479: the reviewer resolves cross-model agreement and ships the result
# in ``quorum``.  It is OPTIONAL here only because this repository pins the
# reviewer by sha: a pin predating that change emits no such key.  Every other
# unexpected key is still refused -- an envelope that grew a field this parser
# does not understand must not become a passing check by being ignored.
OPTIONAL_MULTI_RESULT_FIELDS: Final[frozenset[str]] = frozenset({"quorum"})
QUORUM_FIELDS: Final[frozenset[str]] = frozenset(
    {
        "verdict",
        "quorum_threshold",
        "models_succeeded",
        "quorum_met",
        "blocking_count",
        "warning_count",
        "blocking_findings",
        "warning_findings",
    }
)
QUORUM_VERDICTS: Final[frozenset[str]] = frozenset(
    {"passed", "blocked", "degraded_quorum", "no_models"}
)
# A quorum verdict that is not one of these two means no verdict was
# established at all, and the absence of a verdict is never a passing one.
QUORUM_DECIDED_VERDICTS: Final[frozenset[str]] = frozenset({"passed", "blocked"})
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
MODEL_NAME_RE: Final[re.Pattern[str]] = re.compile(r"^[A-Za-z0-9][A-Za-z0-9_.-]{0,63}$")


@dataclass(frozen=True, slots=True)
class ReviewSummary:
    """Validated review outcome used by the workflow step."""

    verdict: str
    blocking_count: int
    total_findings: int
    models_succeeded: tuple[str, ...]


def _require_keys(
    value: object,
    expected: frozenset[str],
    label: str,
    optional: frozenset[str] = frozenset(),
) -> dict[str, object]:
    if not isinstance(value, dict):
        raise ValueError(f"{label} schema is malformed")
    keys = set(value)
    if not expected <= keys or not keys <= (expected | optional):
        raise ValueError(f"{label} schema is malformed")
    return value


def _require_nonempty_string(value: object, label: str) -> str:
    if not isinstance(value, str) or not value:
        raise ValueError(f"{label} must be a non-empty string")
    return value


def _require_model_name(value: object, label: str) -> str:
    model = _require_nonempty_string(value, label)
    if MODEL_NAME_RE.fullmatch(model) is None:
        raise ValueError(f"{label} is not a safe model name")
    return model


def _require_model_names(value: object, label: str) -> list[str]:
    if not isinstance(value, list):
        raise ValueError(f"{label} must be a list of non-empty strings")
    models: list[str] = []
    for index, item in enumerate(value):
        models.append(_require_model_name(item, f"{label}[{index}]"))
    return models


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


def _validate_quorum(raw_quorum: object, succeeded: list[str]) -> tuple[int, str]:
    """Validate the reviewer quorum block and return (blocking_count, verdict).

    OMN-18479: blocking is the count of findings at least two DISTINCT
    models raised, computed by the reviewer.  It is deliberately NOT a
    severity sum across models here: that sum is what let a single model's
    finding block a merge, and re-deriving it in this repository would
    reinstate the defect one repository at a time.
    """
    quorum = _require_keys(raw_quorum, QUORUM_FIELDS, "review quorum")
    verdict = _require_nonempty_string(quorum["verdict"], "quorum verdict")
    if verdict not in QUORUM_VERDICTS:
        raise ValueError("quorum verdict is not a recognized verdict")
    threshold = _require_nonnegative_integer(quorum["quorum_threshold"], "quorum_threshold")
    if threshold < 2:
        raise ValueError("quorum threshold must require at least two models")
    if not isinstance(quorum["quorum_met"], bool):
        raise ValueError("quorum_met must be boolean")
    blocking_count = _require_nonnegative_integer(quorum["blocking_count"], "quorum blocking_count")
    _require_nonnegative_integer(quorum["warning_count"], "quorum warning_count")
    quorum_models = _require_model_names(quorum["models_succeeded"], "quorum models_succeeded")
    if quorum_models != succeeded:
        raise ValueError("quorum models_succeeded disagrees with the review result")
    for field in ("blocking_findings", "warning_findings"):
        entries = quorum[field]
        if not isinstance(entries, list):
            raise ValueError(f"quorum {field} must be a list")
        for entry in entries:
            if not isinstance(entry, dict):
                raise ValueError(f"quorum {field} entries must be objects")
            agreement = _require_nonnegative_integer(
                entry.get("agreement_count"), "quorum agreement_count"
            )
            if field == "blocking_findings" and agreement < threshold:
                raise ValueError("a blocking quorum finding must meet the agreement threshold")
    if len(quorum["blocking_findings"]) != blocking_count:
        raise ValueError("quorum blocking_count disagrees with blocking_findings")
    if verdict not in QUORUM_DECIDED_VERDICTS:
        raise ValueError(
            f"the reviewer established no verdict (quorum {verdict}); this is not a pass"
        )
    if (verdict == "blocked") != (blocking_count > 0):
        raise ValueError("quorum verdict disagrees with its own blocking count")
    return blocking_count, verdict


def parse_review_result(raw_json: str) -> ReviewSummary:
    """Parse one exact ``ModelMultiReviewResult`` JSON document."""

    try:
        raw_result = json.loads(raw_json)
    except json.JSONDecodeError as json_error:
        raise ValueError("review result is not valid JSON") from json_error
    result = _require_keys(
        raw_result,
        MULTI_RESULT_FIELDS,
        "multi-model result",
        optional=OPTIONAL_MULTI_RESULT_FIELDS,
    )

    attempted = _require_model_names(result["models_attempted"], "models_attempted")
    succeeded = _require_model_names(result["models_succeeded"], "models_succeeded")
    failed = _require_model_names(result["models_failed"], "models_failed")
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
        model = _require_model_name(model_result["model"], "model")
        _require_nonempty_string(model_result["prompt_version"], "prompt_version")
        success = model_result["success"]
        if not isinstance(success, bool):
            raise ValueError("success must be boolean")
        model_error = model_result["error"]
        if model_error is not None and not isinstance(model_error, str):
            raise ValueError("error must be null or a string")
        if success and model_error is not None:
            raise ValueError("successful result cannot contain an error")
        if not success and not model_error:
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
    if "quorum" in result:
        blocking_count, _ = _validate_quorum(result["quorum"], succeeded)
    else:
        # Reviewer pin predating OMN-18479: no agreement data exists, so the
        # only available rule is the per-model sum.  It is kept solely so a
        # pin bump and this parser can land separately; it goes away with the
        # pin.
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
