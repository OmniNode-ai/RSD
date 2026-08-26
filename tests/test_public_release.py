from __future__ import annotations

import importlib.util
import sys
from pathlib import Path

import pytest

_VALIDATOR_PATH = Path(__file__).parents[1] / "scripts" / "ci" / "validate_public_release.py"
_SPEC = importlib.util.spec_from_file_location("public_release_validator", _VALIDATOR_PATH)
assert _SPEC is not None and _SPEC.loader is not None
_VALIDATOR = importlib.util.module_from_spec(_SPEC)
sys.modules[_SPEC.name] = _VALIDATOR
_SPEC.loader.exec_module(_VALIDATOR)
scan_tree = _VALIDATOR.scan_tree
validate_tree = _VALIDATOR.validate_tree

_MIT_LICENSE = """\\
MIT License

Copyright (c) 2026 OmniNode.ai Inc.

Permission is hereby granted, free of charge, to any person obtaining a copy
of this software and associated documentation files (the \"Software\"), to deal
in the Software without restriction, including without limitation the rights
to use, copy, modify, merge, publish, distribute, sublicense, and/or sell
copies of the Software, and to permit persons to whom the Software is
furnished to do so, subject to the following conditions:

The above copyright notice and this permission notice shall be included in all
copies or substantial portions of the Software.

THE SOFTWARE IS PROVIDED \"AS IS\", WITHOUT WARRANTY OF ANY KIND, EXPRESS OR
IMPLIED, INCLUDING BUT NOT LIMITED TO THE WARRANTIES OF MERCHANTABILITY,
FITNESS FOR A PARTICULAR PURPOSE AND NONINFRINGEMENT. IN NO EVENT SHALL THE
AUTHORS OR COPYRIGHT HOLDERS BE LIABLE FOR ANY CLAIM, DAMAGES OR OTHER
LIABILITY, WHETHER IN AN ACTION OF CONTRACT, TORT OR OTHERWISE, ARISING FROM,
OUT OF OR IN CONNECTION WITH THE SOFTWARE OR THE USE OR OTHER DEALINGS IN THE
SOFTWARE.
"""


def _write(tmp_path: Path, relative: str, content: str) -> list:
    target = tmp_path / relative
    target.parent.mkdir(parents=True, exist_ok=True)
    target.write_text(content, encoding="utf-8")
    return scan_tree(tmp_path)


def _marker(name: str) -> str:
    # Keep policy fixtures assembled so this test file passes its own scan.
    return {
        "restricted": "pri" + "vate",
        "legacy": "rsd" + "_new",
        "env": "." + "env",
        "pat" + "ent": "pat" + "ent",
        "pre" + "provisional": "pre" + "-provisional",
        "confi" + "dential": "confi" + "dential",
    }[name]


def _address(*parts: str) -> str:
    return "".join(parts)


@pytest.mark.parametrize(
    ("content", "rule"),
    [
        (lambda: "address = '" + _address("10", ".24.3.8") + "'", "private_ipv4"),
        (lambda: "address = '" + _address("100", ".64.4.8") + "'", "cgnat_ipv4"),
        (lambda: "address = '" + _address("fd12", "::8") + "'", "private_ipv6"),
        (lambda: "address = '" + _address("fe80", "::8") + "'", "private_ipv6"),
        (lambda: "url = 'ht" + "tps://node.lab" + ".local/api'", "internal_hostname"),
        (lambda: "url = 'http" + "s://worker." + "200" + ":8443'", "lab_host_shorthand"),
        (lambda: "command = 'ss" + "h analyst@node.lab" + ".local'", "internal_hostname"),
        (lambda: "command = 'ss" + "h analyst@node.lab" + ".local'", "ssh_target"),
        (lambda: "bind = '0.0.0" + ".0'", "wildcard_bind"),
        (lambda: "ports = ['8080" + ":" + "80']", "docker_port_mapping"),
        (lambda: "endpoint = 'htt" + "p://service:" + "8123'", "service_endpoint"),
        (lambda: "endpoint = 'htt" + "ps://service.example" + ".net/api'", "service_endpoint"),
        (lambda: "note = '/" + "Users/name/work'", "absolute_workspace_path"),
    ],
)
def test_detects_prohibited_values(tmp_path: Path, content: str, rule: str) -> None:
    if callable(content):
        content = content()
    findings = _write(tmp_path, "src/omninode_rsd/lifecycle/config.py", content)
    assert any(item.rule == rule for item in findings)


def test_detects_restricted_markers_and_environment_references(tmp_path: Path) -> None:
    content = (
        f"{_marker('restricted')} record\nconfig={_marker('env')}.prod\nname={_marker('legacy')}\n"
    )
    findings = _write(tmp_path, "README.md", content)
    rules = {item.rule for item in findings}
    assert {"sensitive_marker", "environment_reference", "legacy_identifier"} <= rules


@pytest.mark.parametrize("name", ["pat" + "ent", "pre" + "provisional", "confi" + "dential"])
def test_detects_other_restricted_markers(tmp_path: Path, name: str) -> None:
    findings = _write(tmp_path, "README.md", _marker(name))
    assert any(item.rule == "sensitive_marker" for item in findings)


def test_allows_loopback_documentation_and_public_dependency_values(tmp_path: Path) -> None:
    content = "\n".join(
        [
            "a = 'localhost:8080'",
            "b = '127.0.0.1:9000'",
            "c = '[::1]:9000'",
            "d = '" + _address("192", ".0.2.7") + "'",
            "e = '" + _address("2001:db8", "::7") + "'",
            "f = 'https://example.com:443/docs'",
        ]
    )
    findings = _write(tmp_path, "README.md", content)
    assert findings == []


def test_allows_source_locations_and_uid_gid_notation(tmp_path: Path) -> None:
    findings = _write(tmp_path, "README.md", "error in module.py:12; owner 1000:1000\n")
    assert findings == []


def test_allows_public_dependency_url_with_port_in_lockfile(tmp_path: Path) -> None:
    url = "htt" + "ps://pypi.org:" + "443/packages/pkg.tar.gz"
    findings = _write(tmp_path, "uv.lock", f"sdist = '{url}'\n")
    assert findings == []


def test_allows_mit_license_and_badge_without_sensitive_marker_findings(tmp_path: Path) -> None:
    (tmp_path / "LICENSE").write_text(_MIT_LICENSE, encoding="utf-8")
    (tmp_path / "README.md").write_text(
        "[![License: MIT](https://img.shields.io/badge/License-MIT-yellow.svg)](LICENSE)\n",
        encoding="utf-8",
    )
    assert scan_tree(tmp_path) == []


@pytest.mark.parametrize("filename", ["license", "LICENSE.txt"])
def test_requires_exact_uppercase_root_license_filename(tmp_path: Path, filename: str) -> None:
    findings = _write(tmp_path, filename, _MIT_LICENSE)
    assert any(item.path == filename and item.rule == "path_allowlist" for item in findings)


def test_rejects_unallowlisted_top_level_and_source_subsystem(tmp_path: Path) -> None:
    (tmp_path / "infra").mkdir()
    (tmp_path / "infra" / "notes.txt").write_text("nothing", encoding="utf-8")
    (tmp_path / "src" / "omninode_rsd" / "transport").mkdir(parents=True)
    findings = scan_tree(tmp_path)
    paths = {item.path for item in findings if item.rule == "path_allowlist"}
    assert "infra" in paths
    assert "src/omninode_rsd/transport" in paths


def test_allows_postgres_lifecycle_package_paths(tmp_path: Path) -> None:
    _write(tmp_path, "src/omninode_rsd/lifecycle/postgres/__init__.py", "")
    findings = _write(
        tmp_path,
        "src/omninode_rsd/lifecycle/postgres/migrations/001_lifecycle.sql",
        "SELECT 1;\n",
    )
    assert findings == []


def test_rejects_archives_environment_directories_and_multiline_port_maps(tmp_path: Path) -> None:
    (tmp_path / "release.tar.gz").write_text("placeholder", encoding="utf-8")
    (tmp_path / _marker("env")).mkdir()
    content = "ports:\n  - '" + _address("8080", ":80") + "'\n"
    findings = _write(tmp_path, "README.md", content)
    rules = {item.rule for item in findings}
    assert {"archive_file", "docker_port_mapping", "environment_file"} <= rules


def test_ignored_build_and_runtime_directories_are_not_scanned(tmp_path: Path) -> None:
    for directory in (
        ".venv",
        "dist",
        "build",
        ".mypy_cache",
        ".pytest_cache",
        ".ruff_cache",
    ):
        target = tmp_path / directory / "leak.txt"
        target.parent.mkdir(parents=True)
        target.write_text(_address("10", ".0.0.1"), encoding="utf-8")
    assert scan_tree(tmp_path) == []


def test_allows_root_git_directory_as_operational_metadata(tmp_path: Path) -> None:
    target = tmp_path / ".git" / "leak.txt"
    target.parent.mkdir(parents=True)
    target.write_text(_address("10", ".0.0.1"), encoding="utf-8")

    assert scan_tree(tmp_path) == []


def test_allows_root_linked_worktree_gitfile(tmp_path: Path) -> None:
    (tmp_path / ".git").write_text("gitdir: linked-worktree", encoding="utf-8")
    assert scan_tree(tmp_path) == []


def test_rejects_nested_gitfile_in_an_allowlisted_tree(tmp_path: Path) -> None:
    findings = _write(
        tmp_path,
        "src/omninode_rsd/lifecycle/.git",
        "gitdir: nested-worktree",
    )
    assert any(
        item.path == "src/omninode_rsd/lifecycle/.git" and item.rule == "path_allowlist"
        for item in findings
    )


def test_rejects_nested_git_directory_without_scanning_its_contents(tmp_path: Path) -> None:
    target = tmp_path / "src" / "omninode_rsd" / "lifecycle" / ".git" / "leak.txt"
    target.parent.mkdir(parents=True)
    target.write_text(_address("10", ".0.0.1"), encoding="utf-8")

    findings = scan_tree(tmp_path)

    assert {(item.path, item.rule) for item in findings} == {
        ("src/omninode_rsd/lifecycle/.git", "path_allowlist")
    }


def test_rejects_root_gitfile_symlink(tmp_path: Path) -> None:
    target = tmp_path / "linked-git-control"
    target.write_text("gitdir: nested-worktree", encoding="utf-8")
    (tmp_path / ".git").symlink_to(target)

    findings = scan_tree(tmp_path)

    assert any(item.path == ".git" and item.rule == "path_allowlist" for item in findings)


def test_rejects_root_git_directory_symlink_without_traversal(tmp_path: Path) -> None:
    target = tmp_path.with_name(f"{tmp_path.name}-external-git")
    target.mkdir()
    (target / "leak.txt").write_text(_address("10", ".0.0.1"), encoding="utf-8")
    (tmp_path / ".git").symlink_to(target, target_is_directory=True)

    findings = scan_tree(tmp_path)

    assert {(item.path, item.rule) for item in findings} == {(".git", "path_allowlist")}


def test_validate_tree_raises_with_actionable_findings(tmp_path: Path) -> None:
    _write(tmp_path, "README.md", "endpoint='http://" + _address("10", ".0.0.5") + ":8000'")
    with pytest.raises(ValueError, match="private_ipv4"):
        validate_tree(tmp_path)
