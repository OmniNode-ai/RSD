from __future__ import annotations

import importlib.util
import json
import shutil
import subprocess
import sys
import tarfile
import zipfile
from pathlib import Path
from typing import Any, cast

import pytest

_VALIDATOR_PATH = Path(__file__).parents[1] / "scripts" / "ci" / "validate_public_release.py"
_SPEC = importlib.util.spec_from_file_location("public_release_validator", _VALIDATOR_PATH)
assert _SPEC is not None and _SPEC.loader is not None
_VALIDATOR = importlib.util.module_from_spec(_SPEC)
sys.modules[_SPEC.name] = _VALIDATOR
_SPEC.loader.exec_module(_VALIDATOR)
scan_tree = _VALIDATOR.scan_tree
validate_tree = _VALIDATOR.validate_tree

_ROOT = Path(__file__).parents[1]
_VERIFIER_ROOT = _ROOT / "public_verifier"
_VERIFIER_VERSION = "0.1.0"
_VERIFIER_RESOURCES = (
    "executable_grant_v2_trust_anchor.json",
    "signed_executable_grant_v2.schema.json",
    "signed_executable_grant_v2.vectors.json",
)

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


def _write(tmp_path: Path, relative: str, content: str) -> list[Any]:
    target = tmp_path / relative
    target.parent.mkdir(parents=True, exist_ok=True)
    target.write_text(content, encoding="utf-8")
    return cast(list[Any], scan_tree(tmp_path))


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


def _run_command(cwd: Path, *command: str) -> str:
    completed = subprocess.run(command, cwd=cwd, capture_output=True, text=True)
    if completed.returncode:
        raise AssertionError(
            f"command failed: {command!r}\nstdout:\n{completed.stdout}\nstderr:\n{completed.stderr}"
        )
    return completed.stdout


def _single_artifact(directory: Path, suffix: str) -> Path:
    artifacts = tuple(directory.glob(f"*{suffix}"))
    assert len(artifacts) == 1
    return artifacts[0]


def _installed_records(interpreter: Path) -> dict[str, list[str]]:
    code = """
import csv
import json
from importlib.metadata import distribution

records = {}
for name in ("omninode-rsd", "omninode-grant-verifier"):
    record = distribution(name).read_text("RECORD")
    assert record is not None
    records[name] = [row[0] for row in csv.reader(record.splitlines())]
print(json.dumps(records, sort_keys=True))
"""
    output = _run_command(_ROOT, str(interpreter), "-c", code)
    return cast(dict[str, list[str]], json.loads(output))


def _installed_smoke(interpreter: Path) -> None:
    code = f"""
import json
from datetime import UTC, datetime
from importlib.resources import files

from omninode_grant_verifier import signed_executable_grant_v2_vectors
from omninode_rsd.delegation import PublicGrantVerifierAdapter, load_canonical_delegation_overlay
from omninode_rsd.lifecycle.postgres import discover_lifecycle_migrations

resources = files("omninode_grant_verifier").joinpath("resources")
for resource_name in {_VERIFIER_RESOURCES!r}:
    assert resources.joinpath(resource_name).read_bytes()
vectors = signed_executable_grant_v2_vectors()
base_wire = vectors["base_wire"]
assert type(base_wire) is dict
facts = PublicGrantVerifierAdapter(
    trusted_clock=lambda: datetime(2030, 1, 1, tzinfo=UTC)
)(json.dumps(base_wire, separators=(",", ":")).encode())
assert facts.tenant_id == "public-demo"
assert not load_canonical_delegation_overlay().execute_enabled
assert discover_lifecycle_migrations()[0].version == 1
"""
    _run_command(_ROOT, str(interpreter), "-c", code)


def _installed_verifier_smoke(interpreter: Path) -> None:
    code = """
from importlib.metadata import PackageNotFoundError, distribution
from importlib.resources import files

from omninode_grant_verifier import signed_executable_grant_v2_vectors

try:
    distribution("omninode-rsd")
except PackageNotFoundError:
    pass
else:
    raise AssertionError("root distribution remained installed")
assert files("omninode_grant_verifier").joinpath(
    "resources", "signed_executable_grant_v2.vectors.json"
).read_bytes()
assert type(signed_executable_grant_v2_vectors()["base_wire"]) is dict
"""
    _run_command(_ROOT, str(interpreter), "-c", code)


def test_offline_release_bundle_owns_disjoint_distribution_files(tmp_path: Path) -> None:
    """Build and exercise the paired public artifacts without an index."""
    uv = shutil.which("uv")
    assert uv is not None
    root_sdist_dir = tmp_path / "root-sdist"
    root_wheel_dir = tmp_path / "root-wheel"
    verifier_sdist_dir = tmp_path / "verifier-sdist"
    verifier_wheel_dir = tmp_path / "verifier-wheel"
    wheelhouse = tmp_path / "wheelhouse"
    environment = tmp_path / "environment"
    for directory in (
        root_sdist_dir,
        root_wheel_dir,
        verifier_sdist_dir,
        verifier_wheel_dir,
        wheelhouse,
    ):
        directory.mkdir()

    _run_command(_ROOT, uv, "build", "--offline", "--sdist", "--out-dir", str(root_sdist_dir))
    _run_command(
        tmp_path,
        uv,
        "build",
        "--offline",
        "--wheel",
        "--out-dir",
        str(root_wheel_dir),
        str(_single_artifact(root_sdist_dir, ".tar.gz")),
    )
    _run_command(
        _VERIFIER_ROOT,
        uv,
        "build",
        "--offline",
        "--sdist",
        "--out-dir",
        str(verifier_sdist_dir),
    )
    _run_command(
        tmp_path,
        uv,
        "build",
        "--offline",
        "--wheel",
        "--out-dir",
        str(verifier_wheel_dir),
        str(_single_artifact(verifier_sdist_dir, ".tar.gz")),
    )

    root_wheel = _single_artifact(root_wheel_dir, ".whl")
    verifier_wheel = _single_artifact(verifier_wheel_dir, ".whl")
    with tarfile.open(_single_artifact(root_sdist_dir, ".tar.gz")) as archive:
        root_sdist_members = frozenset(member.name for member in archive.getmembers())
    assert not any("/public_verifier/" in member for member in root_sdist_members)

    with zipfile.ZipFile(root_wheel) as archive:
        root_members = frozenset(archive.namelist())
        metadata_name = next(name for name in root_members if name.endswith(".dist-info/METADATA"))
        metadata = archive.read(metadata_name).decode("utf-8")
    assert f"Requires-Dist: omninode-grant-verifier=={_VERIFIER_VERSION}" in metadata
    assert not any(member.startswith("omninode_grant_verifier/") for member in root_members)

    with zipfile.ZipFile(verifier_wheel) as archive:
        verifier_members = frozenset(archive.namelist())
    assert any(member.startswith("omninode_grant_verifier/") for member in verifier_members)
    assert not any(member.startswith("omninode_rsd/") for member in verifier_members)

    shutil.copy2(root_wheel, wheelhouse / root_wheel.name)
    shutil.copy2(verifier_wheel, wheelhouse / verifier_wheel.name)
    assert frozenset(path.name for path in wheelhouse.iterdir()) == {
        root_wheel.name,
        verifier_wheel.name,
    }

    _run_command(tmp_path, uv, "venv", "--offline", "--python", "3.12", str(environment))
    interpreter = environment / "bin" / "python"
    install_root = (
        uv,
        "pip",
        "install",
        "--offline",
        "--find-links",
        str(wheelhouse),
        "--python",
        str(interpreter),
        str(wheelhouse / root_wheel.name),
    )
    _run_command(tmp_path, *install_root)
    _installed_smoke(interpreter)

    records = _installed_records(interpreter)
    root_records = set(records["omninode-rsd"])
    verifier_records = set(records["omninode-grant-verifier"])
    assert root_records.isdisjoint(verifier_records)
    assert any(path.startswith("omninode_rsd/") for path in root_records)
    assert not any(path.startswith("omninode_grant_verifier/") for path in root_records)
    assert any(path.startswith("omninode_grant_verifier/") for path in verifier_records)
    assert not any(path.startswith("omninode_rsd/") for path in verifier_records)

    _run_command(
        tmp_path, uv, "pip", "uninstall", "--offline", "--python", str(interpreter), "omninode-rsd"
    )
    _installed_verifier_smoke(interpreter)
    _run_command(
        tmp_path,
        uv,
        "pip",
        "uninstall",
        "--offline",
        "--python",
        str(interpreter),
        "omninode-grant-verifier",
    )
    _run_command(
        tmp_path,
        uv,
        "pip",
        "install",
        "--offline",
        "--find-links",
        str(wheelhouse),
        "--python",
        str(interpreter),
        str(wheelhouse / verifier_wheel.name),
    )
    _run_command(tmp_path, *install_root)
    _installed_smoke(interpreter)


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


@pytest.mark.parametrize(
    "relative",
    (
        "src/omninode_rsd/delegation.py",
        "src/omninode_rsd/delegation-overlay.yaml",
        "tests/test_delegation.py",
    ),
)
def test_allows_only_the_delegated_request_safe_slice_files(tmp_path: Path, relative: str) -> None:
    findings = _write(tmp_path, relative, "safe artifact\n")

    assert findings == []


@pytest.mark.parametrize(
    "relative",
    (
        "src/omninode_rsd/delegation_extra.py",
        "tests/test_delegation_extra.py",
    ),
)
def test_rejects_delegated_request_safe_slice_adjacent_paths(tmp_path: Path, relative: str) -> None:
    findings = _write(tmp_path, relative, "unexpected artifact\n")

    assert any(item.path == relative and item.rule == "path_allowlist" for item in findings)


def test_rejects_unallowlisted_top_level_config_directory(tmp_path: Path) -> None:
    (tmp_path / "config").mkdir()

    findings = scan_tree(tmp_path)

    assert any(item.path == "config" and item.rule == "path_allowlist" for item in findings)


def test_rejects_unallowlisted_standalone_verifier_member(tmp_path: Path) -> None:
    findings = _write(tmp_path, "public_verifier/notes.txt", "unexpected\n")
    assert any(
        item.path == "public_verifier/notes.txt" and item.rule == "path_allowlist"
        for item in findings
    )


@pytest.mark.parametrize(
    "relative",
    (
        "runtime/container_bootstrap/manifest.toml",
        "runtime/oci/containerfile",
    ),
)
def test_rejects_planned_runtime_implementation_subtrees(tmp_path: Path, relative: str) -> None:
    findings = _write(tmp_path, relative, "planned artifact\n")

    assert any(item.path == "runtime" and item.rule == "path_allowlist" for item in findings)


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
