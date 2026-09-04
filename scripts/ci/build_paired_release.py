"""Validate and fingerprint the four artifacts in a paired public release."""

from __future__ import annotations

import argparse
import hashlib
import json
import subprocess
import zipfile
from pathlib import Path
from typing import cast


def _sha256(path: Path) -> str:
    digest = hashlib.sha256()
    with path.open("rb") as stream:
        for chunk in iter(lambda: stream.read(1024 * 1024), b""):
            digest.update(chunk)
    return digest.hexdigest()


def _artifact_names(dist_dir: Path) -> tuple[Path, ...]:
    artifacts = tuple(sorted((*dist_dir.glob("*.whl"), *dist_dir.glob("*.tar.gz"))))
    if len(artifacts) != 4:
        raise ValueError(f"expected exactly four paired artifacts, found {len(artifacts)}")
    normalized_names = tuple(path.name.replace("_", "-") for path in artifacts)
    expected_distributions = ("omninode-grant-verifier", "omninode-rsd")
    if any(
        sum(name.startswith(f"{distribution}-") for name in normalized_names) != 2
        for distribution in expected_distributions
    ):
        raise ValueError("artifact set contains an unexpected distribution")
    if {path.suffix for path in artifacts} != {".whl", ".gz"}:
        raise ValueError("artifact set must contain wheels and source archives")
    if sum(path.name.endswith(".whl") for path in artifacts) != 2:
        raise ValueError("artifact set must contain exactly two wheels")
    if sum(path.name.endswith(".tar.gz") for path in artifacts) != 2:
        raise ValueError("artifact set must contain exactly two source archives")
    return artifacts


def _wheel_metadata(path: Path) -> tuple[str, str]:
    with zipfile.ZipFile(path) as archive:
        metadata_name = next(
            name for name in archive.namelist() if name.endswith(".dist-info/METADATA")
        )
        metadata = archive.read(metadata_name).decode("utf-8")
    name = next(
        line.removeprefix("Name: ") for line in metadata.splitlines() if line.startswith("Name: ")
    )
    version = next(
        line.removeprefix("Version: ")
        for line in metadata.splitlines()
        if line.startswith("Version: ")
    )
    if "License-Expression: MIT" not in metadata:
        raise ValueError(f"{path.name} does not declare MIT metadata")
    if "License-File: LICENSE" not in metadata:
        raise ValueError(f"{path.name} does not package its MIT license")
    return name, version


def _source_revision() -> str:
    return subprocess.run(
        ("git", "rev-parse", "HEAD"), check=True, capture_output=True, text=True
    ).stdout.strip()


def build_manifest(dist_dir: Path, expected_version: str | None) -> dict[str, object]:
    artifacts = _artifact_names(dist_dir)
    wheels = [path for path in artifacts if path.name.endswith(".whl")]
    identities = [_wheel_metadata(path) for path in wheels]
    if {name for name, _ in identities} != {"omninode-rsd", "omninode-grant-verifier"}:
        raise ValueError("paired wheels do not identify the expected distributions")
    versions = {version for _, version in identities}
    if len(versions) != 1:
        raise ValueError("paired distributions have mismatched versions")
    version = versions.pop()
    if expected_version is not None and version != expected_version:
        raise ValueError(f"artifact version {version!r} does not match {expected_version!r}")
    revision = _source_revision()
    entries = [
        {
            "filename": path.name,
            "sha256": _sha256(path),
            "size": path.stat().st_size,
        }
        for path in artifacts
    ]
    return {
        "schema_version": "omninode-rsd-paired-release/v1",
        "source_revision": revision,
        "version": version,
        "artifacts": entries,
    }


def main() -> None:
    parser = argparse.ArgumentParser()
    parser.add_argument("--dist-dir", type=Path, default=Path("dist"))
    parser.add_argument("--expected-version")
    args = parser.parse_args()
    manifest = build_manifest(args.dist_dir, args.expected_version)
    dist_dir = args.dist_dir
    (dist_dir / "RELEASE_PROVENANCE.json").write_text(
        json.dumps(manifest, indent=2, sort_keys=True) + "\n", encoding="utf-8"
    )
    (dist_dir / "SHA256SUMS.txt").write_text(
        "".join(
            f"{entry['sha256']}  {entry['filename']}\n"
            for entry in cast(list[dict[str, object]], manifest["artifacts"])
        ),
        encoding="utf-8",
    )


if __name__ == "__main__":
    main()
