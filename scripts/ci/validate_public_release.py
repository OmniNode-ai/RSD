#!/usr/bin/env python3
"""Validate that this repository is safe to publish.

The validator intentionally uses only the Python standard library so it can run
before dependencies are installed.  It is conservative around network-looking
configuration, while allowing loopback, documentation-only addresses, and
public dependency URLs in the lockfile.
"""

from __future__ import annotations

import argparse
import os
import re
import sys
from dataclasses import dataclass
from ipaddress import IPv4Address, IPv6Address, ip_address
from pathlib import Path
from typing import Final
from urllib.parse import urlsplit

IGNORED_DIRECTORIES: Final[frozenset[str]] = frozenset(
    {".venv", "dist", "build", ".mypy_cache", ".pytest_cache", ".ruff_cache", "__pycache__"}
)
ARCHIVE_SUFFIXES: Final[tuple[str, ...]] = (
    ".7z",
    ".bz2",
    ".gz",
    ".rar",
    ".tar",
    ".tgz",
    ".xz",
    ".zip",
)
ALLOWED_TOP_LEVEL: Final[frozenset[str]] = frozenset(
    {
        ".dockerignore",
        ".github",
        ".gitignore",
        ".pre-commit-config.yaml",
        "LICENSE",
        "README.md",
        "pyproject.toml",
        "public_verifier",
        "scripts",
        "src",
        "tests",
        "uv.lock",
    }
)
PUBLIC_VERIFIER_FILES: Final[frozenset[tuple[str, ...]]] = frozenset(
    {
        ("public_verifier", "pyproject.toml"),
        ("public_verifier", "uv.lock"),
        ("public_verifier", "src", "omninode_grant_verifier", "__init__.py"),
        (
            "public_verifier",
            "src",
            "omninode_grant_verifier",
            "resources",
            "executable_grant_v2_trust_anchor.json",
        ),
        (
            "public_verifier",
            "src",
            "omninode_grant_verifier",
            "resources",
            "signed_executable_grant_v2.schema.json",
        ),
        (
            "public_verifier",
            "src",
            "omninode_grant_verifier",
            "resources",
            "signed_executable_grant_v2.vectors.json",
        ),
        ("public_verifier", "tests", "test_signed_executable_grant_v2.py"),
        ("public_verifier", "tests", "test_signed_executable_grant_v2_release.py"),
    }
)
ALLOWED_SOURCE_SUBSYSTEM: Final[str] = "lifecycle"
PUBLIC_GRANT_RESOURCES: Final[frozenset[str]] = frozenset(
    {
        "executable_grant_v2_trust_anchor.json",
        "signed_executable_grant_v2.schema.json",
        "signed_executable_grant_v2.vectors.json",
    }
)
DELEGATED_REQUEST_SAFE_SLICE_FILES: Final[frozenset[tuple[str, ...]]] = frozenset(
    {
        ("src", "omninode_rsd", "delegation.py"),
        ("src", "omninode_rsd", "delegation-overlay.yaml"),
        ("tests", "test_delegation.py"),
    }
)
VALIDATOR_PATH: Final[Path] = Path("scripts/ci/validate_public_release.py")

MARKER_RE = re.compile(
    r"(?i)(?<![a-z0-9_])(?:patent|private|pre[-_ ]?provisional|confidential)(?![a-z0-9_])"
)
ENV_REFERENCE_RE = re.compile(r"(?<![a-z0-9_])\.env(?:[.][a-z0-9_-]+)?(?![a-z0-9_])", re.IGNORECASE)
OLD_IDENTIFIER_RE = re.compile(r"(?<![a-z0-9_])rsd_new(?![a-z0-9_])", re.IGNORECASE)
ABSOLUTE_WORKSPACE_RE = re.compile(r"(?<![a-z0-9_])/(?:Users|Volumes|private)(?:/|$)")
IPV4_RE = re.compile(r"(?<![a-z0-9])(?:\d{1,3}[.]){3}\d{1,3}(?![a-z0-9])", re.IGNORECASE)
IPV6_RE = re.compile(
    r"(?<![a-z0-9:])(?=(?:[0-9a-f:.%]*:){2})(?:[0-9a-f]{0,4}:){2,}[0-9a-f:.%]*(?![a-z0-9:])",
    re.IGNORECASE,
)
URL_RE = re.compile(
    r"(?i)\b(?:https?|wss?|grpc|tcp|udp|redis|rediss|postgres(?:ql)?|mysql|amqps?)://[^\s'\"<>]+"
)
INTERNAL_HOST_RE = re.compile(
    r"(?i)(?<![a-z0-9-])(?:[a-z0-9-]+[.])+(?:local|lan|internal|corp|home|intranet)(?![a-z0-9-])"
)
GITHUB_SECRET_REFERENCE_RE = re.compile(r"\$\{\{\s*secrets\.[a-z0-9_]+\s*\}\}", re.IGNORECASE)
SHORTHAND_HOST_RE = re.compile(
    r"(?i)(?<![a-z0-9-])(?:[a-z0-9_-]+[.])+(?:200|201)(?::\d{1,5})?(?![a-z0-9-])"
)
SSH_URL_RE = re.compile(r"(?i)(?<![a-z0-9])(?:ssh|scp)://[^\s'\"<>]+")
SSH_COMMAND_RE = re.compile(
    r"(?i)(?<![a-z0-9])(?:ssh|scp)(?:\s+-[^\s]+)*\s+(?:[a-z0-9_.-]+@)?(?:\[[^\]]+\]|[a-z0-9_.-]+)(?::\d+)?"
)
HOST_PORT_RE = re.compile(
    r"(?i)(?<![a-z0-9_.:-])(?:\[[^\]]+\]|[a-z][a-z0-9_.-]*|(?:\d{1,3}[.]\d{1,3}[.]\d{1,3}[.]\d{1,3])):\d{1,5}(?!\d)"
)
DOCKER_MAPPING_RE = re.compile(
    r"(?<![a-z0-9])(?:(?:localhost|127[.]0[.]0[.]1):)?\d{2,5}:\d{2,5}(?::\d{2,5})?(?![a-z0-9])",
    re.IGNORECASE,
)
WILDCARD_BIND_RE = re.compile(
    r"(?ix)(?:\b(?:bind|host|listen|address|addr|interface|endpoint)\b\s*[:=]\s*[\"']?(?:0[.]0[.]0[.]0|\[?::\]?)(?:[\"']|\s|$)|--(?:host|bind|listen)\s+(?:0[.]0[.]0[.]0|::))"
)

DOCUMENTATION_NETWORKS: Final[tuple[tuple[IPv4Address | IPv6Address, int], ...]] = (
    # IPv4 documentation ranges.
    (IPv4Address("192.0.2.0"), 24),
    (IPv4Address("198.51.100.0"), 24),
    (IPv4Address("203.0.113.0"), 24),
    # IPv6 documentation range.
    (IPv6Address("2001:db8::"), 32),
)
SAFE_HOSTS: Final[frozenset[str]] = frozenset({"localhost", "127.0.0.1", "::1"})
SAFE_PUBLIC_HOSTS: Final[frozenset[str]] = frozenset(
    {"api.github.com", "github.com", "img.shields.io"}
)
SAFE_DOCUMENTATION_SUFFIXES: Final[tuple[str, ...]] = (
    ".example.com",
    ".example.invalid",
    ".example.test",
)
SOURCE_LOCATION_SUFFIXES: Final[tuple[str, ...]] = (
    ".c",
    ".cc",
    ".cpp",
    ".go",
    ".java",
    ".js",
    ".json",
    ".md",
    ".py",
    ".rs",
    ".toml",
    ".ts",
    ".txt",
    ".yaml",
    ".yml",
)


@dataclass(frozen=True, slots=True)
class Finding:
    """One policy violation, suitable for both humans and tests."""

    path: str
    line: int
    column: int
    rule: str
    detail: str

    def __str__(self) -> str:
        return f"{self.path}:{self.line}:{self.column}: {self.rule}: {self.detail}"


def _within_documentation_range(value: IPv4Address | IPv6Address) -> bool:
    for network_address, prefix_length in DOCUMENTATION_NETWORKS:
        if value.version != network_address.version:
            continue
        if int(value) >> (value.max_prefixlen - prefix_length) == int(network_address) >> (
            value.max_prefixlen - prefix_length
        ):
            return True
    return False


def _classify_ip(raw: str) -> str | None:
    try:
        value = ip_address(raw.split("%", 1)[0])
    except ValueError:
        return None
    if str(value) in SAFE_HOSTS or _within_documentation_range(value):
        return None
    if isinstance(value, IPv4Address):
        octets = value.packed
        first, second = octets[0], octets[1]
        if first == 10 or (first == 172 and 16 <= second <= 31) or (first == 192 and second == 168):
            return "private_ipv4"
        if first == 100 and 64 <= second <= 127:
            return "cgnat_ipv4"
        if first == 169 and second == 254:
            return "link_local_ipv4"
        # Unspecified is a wildcard bind, handled with contextual evidence below.
        if value == IPv4Address("0.0.0.0"):
            return None
    else:
        if value == IPv6Address("::"):
            return None
        if value.is_private or value.is_link_local:
            return "private_ipv6"
    return None


def _is_allowed_directory(path: Path) -> bool:
    parts = path.parts
    if not parts:
        return True
    if parts[0] == "public_verifier":
        return any(entry[: len(parts)] == parts for entry in PUBLIC_VERIFIER_FILES)
    if len(parts) == 1:
        return parts[0] in {".github", "scripts", "src", "tests"}
    if parts[:2] == (".github", "workflows"):
        return len(parts) == 2
    if parts[:2] == ("scripts", "ci"):
        return len(parts) == 2
    if parts == ("src", "omninode_rsd"):
        return True
    if parts[:3] == ("src", "omninode_rsd", ALLOWED_SOURCE_SUBSYSTEM):
        return len(parts) == 3 or parts[3:] in {
            ("postgres",),
            ("postgres", "migrations"),
            ("resources",),
        }
    if parts[:2] == ("tests", "lifecycle"):
        return len(parts) == 2
    return False


def _is_allowed_file(path: Path) -> bool:
    parts = path.parts
    if parts and parts[0] == "public_verifier":
        return parts in PUBLIC_VERIFIER_FILES
    if parts in DELEGATED_REQUEST_SAFE_SLICE_FILES:
        return True
    if len(parts) == 1:
        return parts[0] in ALLOWED_TOP_LEVEL - {".github", "scripts", "src", "tests"}
    if parts in {
        (".github", "workflows", "test.yml"),
        (".github", "workflows", "hostile-reviewer.yml"),
    }:
        return True
    if parts in {
        VALIDATOR_PATH.parts,
        ("scripts", "ci", "parse_hostile_review.py"),
        ("scripts", "ci", "fetch_hostile_review_input.py"),
    }:
        return True
    if parts[:2] == ("src", "omninode_rsd"):
        return (
            (len(parts) == 3 and parts[2] == "__init__.py")
            or (
                len(parts) == 4
                and parts[2] == ALLOWED_SOURCE_SUBSYSTEM
                and path.suffix in {".py", ".json", ".yaml"}
            )
            or (
                len(parts) == 5
                and parts[2:4] == (ALLOWED_SOURCE_SUBSYSTEM, "postgres")
                and path.suffix == ".py"
            )
            or (
                len(parts) == 6
                and parts[2:5] == (ALLOWED_SOURCE_SUBSYSTEM, "postgres", "migrations")
                and path.suffix in {".py", ".sql"}
            )
            or (
                len(parts) == 5
                and parts[2:4] == (ALLOWED_SOURCE_SUBSYSTEM, "resources")
                and parts[4] in PUBLIC_GRANT_RESOURCES
            )
        )
    if parts[:2] == ("tests", "lifecycle"):
        return len(parts) == 3 and path.suffix == ".py"
    return parts in {
        ("tests", "test_public_release.py"),
        ("tests", "test_ci_workflows.py"),
        ("tests", "test_hostile_review_bootstrap.py"),
    }


def _is_safe_host(host: str) -> bool:
    normalized = host.strip("[]").rstrip(".").lower()
    if normalized in SAFE_HOSTS | SAFE_PUBLIC_HOSTS or normalized in {
        "example.com",
        "example.invalid",
        "example.test",
    }:
        return True
    if normalized.endswith(SAFE_DOCUMENTATION_SUFFIXES):
        return True
    try:
        value = ip_address(normalized)
    except ValueError:
        return False
    return _classify_ip(str(value)) is None


def _looks_like_source_location(line: str, match: re.Match[str]) -> bool:
    host = match.group(0).rsplit(":", 1)[0].lower()
    port = int(match.group(0).rsplit(":", 1)[1])
    return host in {"sha256", "sha512"} or (host.endswith(SOURCE_LOCATION_SUFFIXES) and port <= 999)


def _finding(path: Path, line_number: int, column: int, rule: str, detail: str) -> Finding:
    return Finding(path.as_posix(), line_number, column, rule, detail)


def _is_archive(path: Path) -> bool:
    return path.name.lower().endswith(ARCHIVE_SUFFIXES)


def _scan_line(
    path: Path, line_number: int, line: str, *, is_lockfile: bool = False
) -> list[Finding]:
    findings: list[Finding] = []

    def add_matches(pattern: re.Pattern[str], rule: str, detail: str | None = None) -> None:
        for match in pattern.finditer(line):
            findings.append(
                _finding(path, line_number, match.start() + 1, rule, detail or match.group(0))
            )

    add_matches(MARKER_RE, "sensitive_marker", "restricted publication marker")
    add_matches(ENV_REFERENCE_RE, "environment_reference", "environment file reference")
    add_matches(OLD_IDENTIFIER_RE, "legacy_identifier", "legacy private-project identifier")
    add_matches(ABSOLUTE_WORKSPACE_RE, "absolute_workspace_path", "absolute local workspace path")
    # GitHub Actions secret references contain a dotted identifier such as
    # ``secrets.LOCAL_LLM_SHARED_SECRET``.  The scanner must not misclassify
    # that syntax as an internal hostname; the secret value is never present
    # in the checked-in workflow.
    without_secret_references = GITHUB_SECRET_REFERENCE_RE.sub("SECRET_REFERENCE", line)
    for match in INTERNAL_HOST_RE.finditer(without_secret_references):
        findings.append(
            _finding(
                path,
                line_number,
                match.start() + 1,
                "internal_hostname",
                "internal or mDNS hostname suffix",
            )
        )
    for match in SHORTHAND_HOST_RE.finditer(line):
        token = match.group(0).split(":", 1)[0]
        try:
            is_documentation_ip = _within_documentation_range(ip_address(token))
        except ValueError:
            is_documentation_ip = False
        if not is_documentation_ip:
            findings.append(
                _finding(
                    path, line_number, match.start() + 1, "lab_host_shorthand", "lab host shorthand"
                )
            )
    add_matches(SSH_URL_RE, "ssh_target", "SSH/SCP target")
    add_matches(SSH_COMMAND_RE, "ssh_target", "SSH/SCP command target")
    add_matches(WILDCARD_BIND_RE, "wildcard_bind", "non-loopback wildcard bind")

    for pattern in (IPV4_RE, IPV6_RE):
        for match in pattern.finditer(line):
            rule = _classify_ip(match.group(0))
            if rule is not None:
                findings.append(
                    _finding(path, line_number, match.start() + 1, rule, match.group(0))
                )

    for match in URL_RE.finditer(line):
        raw_url = match.group(0).rstrip(".,;)")
        try:
            parsed = urlsplit(raw_url)
            host = parsed.hostname
        except ValueError:
            host = None
        if host is None:
            continue
        if _is_safe_host(host):
            continue
        if is_lockfile and "." in host and not INTERNAL_HOST_RE.search(host):
            # uv.lock contains public package indexes and artifact URLs.  IP
            # literals remain covered by the address scan above.
            continue
        findings.append(_finding(path, line_number, match.start() + 1, "service_endpoint", raw_url))

    # URLs are handled above; removing them avoids reporting their port twice.
    without_urls = URL_RE.sub(" " * 8, line)
    for match in HOST_PORT_RE.finditer(without_urls):
        if is_lockfile:
            continue
        if _looks_like_source_location(without_urls, match):
            continue
        host = match.group(0).rsplit(":", 1)[0].strip("[]")
        if _is_safe_host(host):
            continue
        findings.append(
            _finding(path, line_number, match.start() + 1, "service_endpoint", match.group(0))
        )

    if re.search(r"(?i)\b(?:ports?|publish|published|docker\s+run|--publish|-p)\b", line):
        add_matches(DOCKER_MAPPING_RE, "docker_port_mapping", "Docker published-port mapping")
    return findings


def _iter_paths(root: Path) -> tuple[list[Path], list[Finding]]:
    files: list[Path] = []
    findings: list[Finding] = []
    for current, directories, names in os.walk(root, topdown=True):
        current_path = Path(current)
        kept_directories: list[str] = []
        for name in sorted(directories):
            candidate = current_path / name
            if name == ".git":
                # A standard checkout's real root control directory is
                # operational metadata. Nested control directories and all
                # symlinks are publishable-path violations and are never
                # traversed.
                if candidate == root / ".git" and not candidate.is_symlink() and candidate.is_dir():
                    continue
                relative = candidate.relative_to(root)
                findings.append(
                    _finding(
                        relative,
                        1,
                        1,
                        "path_allowlist",
                        "directory is not public-release allowlisted",
                    )
                )
                continue
            if name in IGNORED_DIRECTORIES:
                continue
            relative = candidate.relative_to(root)
            if ENV_REFERENCE_RE.fullmatch(name):
                findings.append(
                    _finding(relative, 1, 1, "environment_file", "environment file is prohibited")
                )
            if not _is_allowed_directory(relative):
                findings.append(
                    _finding(
                        relative,
                        1,
                        1,
                        "path_allowlist",
                        "directory is not public-release allowlisted",
                    )
                )
            kept_directories.append(name)
        directories[:] = kept_directories
        for name in sorted(names):
            candidate = current_path / name
            # Linked Git worktrees represent only the root control directory as
            # a regular ``.git`` file. Preserve normal ignored-directory
            # behavior, but do not exempt nested paths or symlinks.
            if candidate == root / ".git" and candidate.is_file() and not candidate.is_symlink():
                continue
            relative = candidate.relative_to(root)
            files.append(relative)
            if _is_archive(relative):
                findings.append(
                    _finding(relative, 1, 1, "archive_file", "archive files are prohibited")
                )
            if not _is_allowed_file(relative):
                findings.append(
                    _finding(
                        relative, 1, 1, "path_allowlist", "file is not public-release allowlisted"
                    )
                )
    return files, findings


def scan_tree(root: Path) -> list[Finding]:
    """Return deterministic policy findings for *root*."""
    root = root.resolve()
    files, findings = _iter_paths(root)
    for relative in files:
        normalized = relative.as_posix()
        for part in relative.parts:
            if ENV_REFERENCE_RE.fullmatch(part):
                findings.append(
                    _finding(relative, 1, 1, "environment_file", "environment file is prohibited")
                )
            if OLD_IDENTIFIER_RE.search(part):
                findings.append(
                    _finding(
                        relative, 1, 1, "legacy_identifier", "legacy private-project identifier"
                    )
                )
            if MARKER_RE.search(part):
                findings.append(
                    _finding(relative, 1, 1, "sensitive_marker", "restricted publication marker")
                )
        if normalized == VALIDATOR_PATH.as_posix() or not _is_allowed_file(relative):
            continue
        try:
            content = (root / relative).read_bytes()
        except OSError as exc:
            findings.append(_finding(relative, 1, 1, "read_error", str(exc)))
            continue
        if b"\0" in content:
            continue
        try:
            text = content.decode("utf-8")
        except UnicodeDecodeError:
            continue
        previous_line = ""
        for line_number, line in enumerate(text.splitlines(), 1):
            findings.extend(
                _scan_line(relative, line_number, line, is_lockfile=relative.name == "uv.lock")
            )
            if re.search(r"(?i)^\s*ports?\s*:\s*$", previous_line):
                for match in DOCKER_MAPPING_RE.finditer(line):
                    findings.append(
                        _finding(
                            relative,
                            line_number,
                            match.start() + 1,
                            "docker_port_mapping",
                            "Docker published-port mapping",
                        )
                    )
            previous_line = line
    return sorted(
        findings, key=lambda item: (item.path, item.line, item.column, item.rule, item.detail)
    )


def validate_tree(root: Path) -> None:
    """Raise ``ValueError`` with all findings when the tree is not publishable."""
    findings = scan_tree(root)
    if findings:
        raise ValueError(
            "public-release validation failed:\n" + "\n".join(str(item) for item in findings)
        )


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("root", nargs="?", type=Path, default=Path(__file__).resolve().parents[2])
    args = parser.parse_args(argv)
    findings = scan_tree(args.root)
    if findings:
        print("public-release validation failed:", file=sys.stderr)
        for item in findings:
            print(item, file=sys.stderr)
        return 1
    print(f"public-release validation passed: {args.root.resolve()}")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
