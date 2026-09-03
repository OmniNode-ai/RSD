#!/usr/bin/env python3
"""Fetch a pull request diff as bounded, untrusted data for hostile review."""

from __future__ import annotations

import os
import re
import sys
from pathlib import Path
from typing import Final, Protocol
from urllib.error import HTTPError, URLError
from urllib.request import Request, urlopen

GITHUB_API_ROOT: Final[str] = "https://api.github.com"
MAX_DIFF_BYTES: Final[int] = 1_200_000
MAX_PR_NUMBER: Final[int] = 99_999_999
READ_CHUNK_BYTES: Final[int] = 64 * 1024
REPOSITORY_RE: Final[re.Pattern[str]] = re.compile(
    r"^[A-Za-z0-9][A-Za-z0-9_.-]{0,99}/[A-Za-z0-9][A-Za-z0-9_.-]{0,99}$"
)


class _ReadableResponse(Protocol):
    """Small protocol for the bounded response reader."""

    def read(self, size: int) -> bytes:
        """Read at most ``size`` bytes."""


def validate_repository(raw_repository: str) -> str:
    """Validate a GitHub ``owner/name`` repository slug."""
    if not isinstance(raw_repository, str) or REPOSITORY_RE.fullmatch(raw_repository) is None:
        raise ValueError("repository slug is malformed")
    return raw_repository


def parse_pull_request_number(raw_number: str) -> int:
    """Validate and bound a pull request number."""
    if not isinstance(raw_number, str) or not raw_number.isdecimal():
        raise ValueError("pull request number is malformed")
    number = int(raw_number)
    if not 1 <= number <= MAX_PR_NUMBER:
        raise ValueError("pull request number is out of bounds")
    return number


def _read_bounded(response: _ReadableResponse, max_bytes: int) -> bytes:
    if not isinstance(max_bytes, int) or isinstance(max_bytes, bool) or max_bytes <= 0:
        raise ValueError("maximum diff size is invalid")

    chunks = bytearray()
    while len(chunks) <= max_bytes:
        read_size = min(READ_CHUNK_BYTES, max_bytes + 1 - len(chunks))
        chunk = response.read(read_size)
        if not isinstance(chunk, bytes):
            raise ValueError("GitHub diff response is not bytes")
        if not chunk:
            break
        chunks.extend(chunk)

    if len(chunks) > max_bytes:
        raise ValueError("pull request diff exceeds the review input bound")
    if not chunks.strip():
        raise ValueError("pull request diff is empty")
    try:
        bytes(chunks).decode("utf-8")
    except UnicodeDecodeError as error:
        raise ValueError("pull request diff is not UTF-8") from error
    return bytes(chunks)


def fetch_pull_request_diff(
    repository: str,
    pull_request_number: int,
    token: str,
    *,
    max_bytes: int = MAX_DIFF_BYTES,
) -> bytes:
    """Fetch one base-repository PR diff without checking out its head."""
    repository = validate_repository(repository)
    if isinstance(pull_request_number, bool) or not 1 <= pull_request_number <= MAX_PR_NUMBER:
        raise ValueError("pull request number is out of bounds")
    if not isinstance(token, str) or not token or any(character in token for character in "\r\n"):
        raise ValueError("GitHub token is unavailable")

    request = Request(
        f"{GITHUB_API_ROOT}/repos/{repository}/pulls/{pull_request_number}",
        headers={
            "Accept": "application/vnd.github.diff",
            "Authorization": f"Bearer {token}",
            "User-Agent": "RSD-hostile-review",
            "X-GitHub-Api-Version": "2022-11-28",
        },
    )
    try:
        with urlopen(request, timeout=60) as response:
            return _read_bounded(response, max_bytes)
    except (HTTPError, URLError, TimeoutError, OSError) as error:
        raise ValueError("GitHub pull request diff fetch failed") from error


def write_review_input(data: bytes, output_path: Path, github_output: Path) -> None:
    """Write bounded UTF-8 diff data and expose only its trusted path."""
    if not isinstance(data, bytes):
        raise ValueError("review input is not bytes")
    if not output_path.is_absolute() or not github_output.is_absolute():
        raise ValueError("workflow output paths must be absolute")
    if len(data) > MAX_DIFF_BYTES or not data.strip():
        raise ValueError("review input is missing or exceeds the bound")
    try:
        data.decode("utf-8")
    except UnicodeDecodeError as error:
        raise ValueError("review input is not UTF-8") from error
    with output_path.open("xb") as handle:
        handle.write(data)
    with github_output.open("a", encoding="utf-8") as handle:
        handle.write(f"path={output_path}\n")


def main() -> int:
    try:
        repository = validate_repository(os.environ["REPO"])
        pull_request_number = parse_pull_request_number(os.environ["PR_NUMBER"])
        data = fetch_pull_request_diff(
            repository,
            pull_request_number,
            os.environ["GH_TOKEN"],
        )
        write_review_input(
            data,
            Path(os.environ["OUTPUT_PATH"]),
            Path(os.environ["GITHUB_OUTPUT"]),
        )
    except (KeyError, OSError, ValueError):
        print("::error::unable to fetch a bounded pull request review input", file=sys.stderr)
        return 1
    print("bounded pull request review input is ready")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
