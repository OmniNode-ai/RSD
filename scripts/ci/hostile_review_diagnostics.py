#!/usr/bin/env python3
"""Fail-closed, nonprinting diagnostics for the hostile-review workflow.

This module deliberately knows only configuration *slots*, not providers or
configuration values.  Its public result types retain fixed categories and a
bounded byte count; they never retain or render an endpoint, credential, or
reviewer stderr text.
"""

from __future__ import annotations

import argparse
import os
import re
from collections.abc import Mapping, Sequence
from dataclasses import dataclass
from enum import StrEnum
from pathlib import Path
from typing import Final
from urllib.parse import urlsplit

MAX_DIAGNOSTIC_BYTES: Final[int] = 16 * 1024


class ConfigurationField(StrEnum):
    """Provider-neutral configuration slots required for paired review."""

    AUTHENTICATION = "authentication"
    PRIMARY_ENDPOINT = "primary_endpoint"
    SECONDARY_ENDPOINT = "secondary_endpoint"


class DiagnosticCategory(StrEnum):
    """Allowlisted public categories for a failed adversarial review."""

    CONFIGURATION = "reviewer-configuration"
    TIMEOUT = "reviewer-timeout"
    AUTHENTICATION = "reviewer-authentication"
    MODEL = "reviewer-model-unavailable"
    RATE_LIMIT = "reviewer-rate-limited"
    CONNECTION = "reviewer-endpoint-unavailable"
    PARSER = "reviewer-malformed-response"
    ERROR = "reviewer-error"


@dataclass(frozen=True, slots=True)
class ConfigurationPreflight:
    """Presence-only configuration result that cannot disclose values."""

    missing_fields: tuple[ConfigurationField, ...]
    malformed_fields: tuple[ConfigurationField, ...]

    @property
    def ready(self) -> bool:
        """Whether all required configuration slots have safe nonempty values."""
        return not self.missing_fields and not self.malformed_fields


@dataclass(frozen=True, slots=True)
class DiagnosticReport:
    """Bounded diagnostic classification without raw diagnostic retention."""

    category: DiagnosticCategory
    captured_bytes: int


_CONFIGURATION_ENVIRONMENT_KEYS: Final[tuple[tuple[ConfigurationField, str], ...]] = (
    (ConfigurationField.AUTHENTICATION, "LOCAL_LLM_SHARED_SECRET"),
    (ConfigurationField.PRIMARY_ENDPOINT, "LLM_QWEN3_REVIEW_URL"),
    (ConfigurationField.SECONDARY_ENDPOINT, "LLM_QWEN3_REVIEW_B_URL"),
)
_PROGRESS_TIMEOUT_MARKER: Final[re.Pattern[str]] = re.compile(
    r"\btimeout\s*=\s*[^\s]+", re.IGNORECASE
)
_TIMEOUT: Final[re.Pattern[str]] = re.compile(
    r"(?:\btimed\s*out\b|\bdeadline\s+exceeded\b|\btimeouterror\b|\betimedout\b|"
    r"\btimeout\s+(?:after|while|error|expired)\b|\btimeout\s*:)",
    re.IGNORECASE,
)
_AUTHENTICATION: Final[re.Pattern[str]] = re.compile(
    r"(?:\b401\b|\b403\b|\bunauthori[sz]ed\b|\bforbidden\b|\bauthentication failed\b)",
    re.IGNORECASE,
)
_MODEL: Final[re.Pattern[str]] = re.compile(
    r"(?:\bmodel\b.*\b(?:not found|does not exist|unavailable)\b|"
    r"\b(?:unknown|unsupported)\s+model\b)",
    re.IGNORECASE,
)
_ENDPOINT_NOT_FOUND: Final[re.Pattern[str]] = re.compile(
    r"(?:\b(?:http\s+)?404\b|\bendpoint\b.*\b(?:not found|unavailable)\b|"
    r"\b(?:not found|unavailable)\b.*\bendpoint\b)",
    re.IGNORECASE,
)
_RATE_LIMIT: Final[re.Pattern[str]] = re.compile(
    r"(?:\b429\b|\brate limit\b|\btoo many requests\b)", re.IGNORECASE
)
_CONNECTION: Final[re.Pattern[str]] = re.compile(
    r"(?:\bconnection refused\b|\bfailed to connect\b|\bcould not connect\b|"
    r"\bnetwork is unreachable\b|\bname or service not known\b|\beconnrefused\b|"
    r"\benetunreach\b|\bconnecterror\b|\bconnection (?:reset|aborted|closed|failed)\b|"
    r"\bserver unavailable\b|\bserver disconnected\b|\bno route to host\b|"
    r"\btemporary failure in name resolution\b)",
    re.IGNORECASE,
)
_PARSER: Final[re.Pattern[str]] = re.compile(
    r"(?:\bjsondecodeerror\b|\bjson\s+(?:parse|decode|decoding)\s+(?:error|failed)\b|"
    r"\bfailed\s+(?:to\s+parse\s+)?json(?:\s+response)?\b|\bparse error\b|"
    r"\bmalformed\s+(?:json|response)\b|\binvalid\s+json(?:\s+response)?\b|"
    r"\bdecode error\b)",
    re.IGNORECASE,
)


def is_valid_review_endpoint_shape(value: object) -> bool:
    """Accept only a syntactically strict HTTP(S) endpoint without resolving it."""
    if not isinstance(value, str) or not value or value != value.strip():
        return False
    if any(
        character.isspace() or ord(character) < 32 or ord(character) == 127 for character in value
    ):
        return False
    if "#" in value:
        return False
    try:
        parsed = urlsplit(value)
        port = parsed.port
    except ValueError:
        return False
    if parsed.scheme.lower() not in {"http", "https"} or not parsed.netloc:
        return False
    if "@" in parsed.netloc or parsed.username is not None or parsed.password is not None:
        return False
    if parsed.hostname is None:
        return False
    return parsed.hostname.isascii() and (port is None or port >= 1)


def preflight_reviewer_configuration(
    environment: Mapping[str, object],
) -> ConfigurationPreflight:
    """Inspect only required-slot presence without retaining their values."""
    missing: list[ConfigurationField] = []
    malformed: list[ConfigurationField] = []
    for field, environment_key in _CONFIGURATION_ENVIRONMENT_KEYS:
        value = environment.get(environment_key)
        if not isinstance(value, str) or not value.strip() or "\r" in value or "\n" in value:
            missing.append(field)
        elif field is not ConfigurationField.AUTHENTICATION and not is_valid_review_endpoint_shape(
            value
        ):
            malformed.append(field)
    return ConfigurationPreflight(tuple(missing), tuple(malformed))


def classify_reviewer_diagnostics(raw: bytes | str) -> DiagnosticReport:
    """Classify bounded diagnostics without including them in the result."""
    if isinstance(raw, str):
        encoded = raw.encode("utf-8")
    elif isinstance(raw, bytes):
        encoded = raw
    else:
        raise TypeError("reviewer diagnostics must be bytes or text")
    if len(encoded) > MAX_DIAGNOSTIC_BYTES:
        return DiagnosticReport(DiagnosticCategory.ERROR, MAX_DIAGNOSTIC_BYTES)
    try:
        text = encoded.decode("utf-8")
    except UnicodeDecodeError:
        return DiagnosticReport(DiagnosticCategory.ERROR, len(encoded))

    # CLI progress messages commonly report the configured client budget as
    # ``timeout=<seconds>``. Remove that value-shaped marker before matching
    # operational failures, while still accepting an independent timeout error
    # on the same line.
    searchable = _PROGRESS_TIMEOUT_MARKER.sub("", text)
    category = DiagnosticCategory.ERROR
    for pattern, candidate in (
        (_TIMEOUT, DiagnosticCategory.TIMEOUT),
        (_AUTHENTICATION, DiagnosticCategory.AUTHENTICATION),
        (_MODEL, DiagnosticCategory.MODEL),
        (_RATE_LIMIT, DiagnosticCategory.RATE_LIMIT),
        (_ENDPOINT_NOT_FOUND, DiagnosticCategory.CONNECTION),
        (_CONNECTION, DiagnosticCategory.CONNECTION),
        (_PARSER, DiagnosticCategory.PARSER),
    ):
        if pattern.search(searchable) is not None:
            category = candidate
            break
    return DiagnosticReport(category, len(encoded))


def read_bounded_diagnostics(path: Path) -> bytes:
    """Read one workflow-owned diagnostic file with a hard input limit."""
    if not path.is_absolute() or not path.is_file():
        raise ValueError("reviewer diagnostics are unavailable")
    with path.open("rb") as handle:
        raw = handle.read(MAX_DIAGNOSTIC_BYTES + 1)
    if len(raw) > MAX_DIAGNOSTIC_BYTES:
        raise ValueError("reviewer diagnostics exceed the bound")
    return raw


def _argument_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(description="classify hostile-review diagnostics")
    commands = parser.add_subparsers(dest="command", required=True)
    commands.add_parser("preflight")
    classify = commands.add_parser("classify")
    classify.add_argument("--diagnostics", required=True, type=Path)
    return parser


def main(arguments: Sequence[str] | None = None) -> int:
    """Emit only one allowlisted category, never an input or configuration value."""
    parsed = _argument_parser().parse_args(arguments)
    if parsed.command == "preflight":
        preflight = preflight_reviewer_configuration(os.environ)
        if preflight.ready:
            print("reviewer-ready")
            return 0
        print(DiagnosticCategory.CONFIGURATION.value)
        return 1

    try:
        diagnostics = read_bounded_diagnostics(parsed.diagnostics)
    except (OSError, ValueError):
        print(DiagnosticCategory.ERROR.value)
        return 1
    print(classify_reviewer_diagnostics(diagnostics).category.value)
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
