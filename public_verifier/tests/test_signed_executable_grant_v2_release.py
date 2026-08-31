"""Release and ancestry gates for the public executable-grant contract."""

from __future__ import annotations

import subprocess
import tarfile
import zipfile
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
_APPROVED_BASE = "1de48ae29331ba888bd6cf3ede891cf8aec73eb9"
_RESOURCES = (
    "omninode_grant_verifier/resources/executable_grant_v2_trust_anchor.json",
    "omninode_grant_verifier/resources/signed_executable_grant_v2.schema.json",
    "omninode_grant_verifier/resources/signed_executable_grant_v2.vectors.json",
)
_BLOCKED = (
    "rsd" + "_" + "canary",
    "input" + "-" + "bundle",
    "model" + "-" + "api-key",
    "ora" + "cle",
    "pri" + "vate",
)
_WHEEL_MEMBERS = frozenset(
    {
        "omninode_grant_verifier/__init__.py",
        *_RESOURCES,
        "omninode_grant_verifier-0.1.0.dist-info/METADATA",
        "omninode_grant_verifier-0.1.0.dist-info/WHEEL",
        "omninode_grant_verifier-0.1.0.dist-info/RECORD",
    }
)
_SDIST_MEMBERS = frozenset(
    {
        ".gitignore",
        "PKG-INFO",
        "pyproject.toml",
        "uv.lock",
        "src/omninode_grant_verifier/__init__.py",
        *(f"src/{resource}" for resource in _RESOURCES),
        "tests/test_signed_executable_grant_v2.py",
        "tests/test_signed_executable_grant_v2_release.py",
    }
)


def _run(*command: str) -> str:
    return subprocess.run(command, cwd=ROOT, check=True, capture_output=True, text=True).stdout


def test_public_contract_history_descends_only_from_approved_base() -> None:
    _run("git", "merge-base", "--is-ancestor", _APPROVED_BASE, "HEAD")
    changed = _run("git", "diff", "--name-only", f"{_APPROVED_BASE}..HEAD", "--", "public_verifier")
    assert not any(marker in path for marker in _BLOCKED for path in changed.splitlines())


def test_wheel_and_sdist_preserve_only_safe_contract_resources(tmp_path: Path) -> None:
    dist = tmp_path / "dist"
    _run("uv", "build", "--offline", "--out-dir", str(dist))
    wheel = next(dist.glob("omninode_grant_verifier-*.whl"))
    sdist = next(dist.glob("omninode_grant_verifier-*.tar.gz"))
    with zipfile.ZipFile(wheel) as archive:
        payloads = {name: archive.read(name) for name in archive.namelist()}
        assert frozenset(payloads) == _WHEEL_MEMBERS
    with tarfile.open(sdist) as archive:
        sdist_payloads: dict[str, bytes] = {}
        for member in archive.getmembers():
            if not member.isfile():
                continue
            stream = archive.extractfile(member)
            assert stream is not None
            sdist_payloads[member.name.split("/", maxsplit=1)[1]] = stream.read()
        assert frozenset(sdist_payloads) == _SDIST_MEMBERS
    all_payloads = {**payloads, **sdist_payloads}
    for resource in _RESOURCES:
        assert resource in payloads
        assert payloads[resource] == (ROOT / "src" / resource).read_bytes()
    for name, payload in all_payloads.items():
        assert not any(marker in name for marker in _BLOCKED)
        assert not any(marker.encode() in payload for marker in _BLOCKED)
