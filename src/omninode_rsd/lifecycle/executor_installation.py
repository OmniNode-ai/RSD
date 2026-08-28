"""Render-only Linux executor installation manifests.

The functions in this module return non-secret text and never write a file,
invoke a service manager, alter Secure Shell configuration, or contact an
executor.  Operators must separately authorize and attest any installation.
"""

from __future__ import annotations

import argparse
import base64
import binascii
import hashlib
import json
import os
import re
from collections.abc import Sequence
from dataclasses import dataclass
from pathlib import Path
from typing import Final, Literal

from pydantic import BaseModel, ConfigDict, Field, ValidationError, field_validator, model_validator

from omninode_rsd.lifecycle.executor_transport import ExecutorTransportPolicyV2
from omninode_rsd.lifecycle.infisical_disposable import ExecutorInstallationPolicyV1

_IDENTIFIER: Final = r"^[A-Za-z][A-Za-z0-9_.-]{0,127}$"
_SHA256: Final = r"^[0-9a-f]{64}$"
_SAFE_ABSOLUTE_PATH: Final = re.compile(r"^/(?:[A-Za-z0-9._-]+/)*[A-Za-z0-9._-]+$")


class ExecutorInstallationRenderError(RuntimeError):
    """Value-redacted render-only installation failure."""

    def __init__(self, phase: str) -> None:
        self.phase = phase
        super().__init__(f"executor installation render failed at phase: {phase}")


class _Model(BaseModel):
    model_config = ConfigDict(extra="forbid", frozen=True, strict=True, validate_default=True)


def _digest(value: str) -> str:
    return hashlib.sha256(value.encode("utf-8")).hexdigest()


def _canonical_json(value: object) -> str:
    try:
        return json.dumps(value, ensure_ascii=True, sort_keys=True, separators=(",", ":"))
    except (TypeError, ValueError):
        raise ExecutorInstallationRenderError("canonical_encoding") from None


def _path(value: str) -> str:
    if (
        type(value) is not str
        or _SAFE_ABSOLUTE_PATH.fullmatch(value) is None
        or not Path(value).is_absolute()
        or os.path.normpath(value) != value
    ):
        raise ValueError("installation path is invalid")
    return value


def _authorized_key_fingerprint(value: str) -> str:
    """Return the exact public-key blob fingerprint after canonical parsing."""

    try:
        _key_type, encoded = value.split(" ")
        raw = base64.b64decode(encoded, validate=True)
        if not raw or base64.b64encode(raw).decode("ascii") != encoded:
            raise ValueError
    except (ValueError, UnicodeError, binascii.Error):
        raise ExecutorInstallationRenderError("installation_manifest") from None
    return hashlib.sha256(raw).hexdigest()


class ExecutorInstallationManifestV2(_Model):
    """Non-secret immutable locations and ownership for a future install."""

    schema_version: Literal["rsd.executor-installation-manifest.v2"]
    executor_id: str = Field(pattern=_IDENTIFIER)
    daemon_user: str = Field(pattern=_IDENTIFIER)
    daemon_group: str = Field(pattern=_IDENTIFIER)
    credential_name: str = Field(pattern=_IDENTIFIER)
    daemon_executable_path: str
    force_command_path: str
    systemd_unit_path: str
    sshd_fragment_path: str
    authorized_key_policy_path: str
    daemon_socket_path: str
    client_authorized_key: str
    socket_mode: Literal[384]
    daemon_file_mode: Literal[448]
    config_file_mode: Literal[420]

    @field_validator(
        "daemon_executable_path",
        "force_command_path",
        "systemd_unit_path",
        "sshd_fragment_path",
        "authorized_key_policy_path",
        "daemon_socket_path",
    )
    @classmethod
    def canonical_paths(cls, value: str) -> str:
        return _path(value)

    @field_validator("client_authorized_key")
    @classmethod
    def canonical_authorized_key(cls, value: str) -> str:
        """Accept one complete, comment-free OpenSSH public-key entry."""

        try:
            if type(value) is not str:
                raise ValueError
            key_type, encoded = value.split(" ")
            if key_type not in {"ssh-ed25519", "ecdsa-sha2-nistp256", "rsa-sha2-512"}:
                raise ValueError
            raw = base64.b64decode(encoded, validate=True)
            if not raw or base64.b64encode(raw).decode("ascii") != encoded:
                raise ValueError
        except (ValueError, UnicodeError, binascii.Error):
            raise ValueError("authorized key is invalid") from None
        return value

    @model_validator(mode="after")
    def distinct_locations(self) -> ExecutorInstallationManifestV2:
        paths = (
            self.daemon_executable_path,
            self.force_command_path,
            self.systemd_unit_path,
            self.sshd_fragment_path,
            self.authorized_key_policy_path,
            self.daemon_socket_path,
        )
        if len(set(paths)) != len(paths):
            raise ValueError("installation manifest is invalid")
        return self


@dataclass(frozen=True, slots=True)
class RenderedExecutorFileV1:
    """One non-secret file that a separately authorized installer may write."""

    path: str
    owner: Literal["root"]
    group: str
    mode: int
    content: str
    content_sha256: str


@dataclass(frozen=True, slots=True)
class RenderedExecutorInstallationV2:
    """Value-free output; rendering itself has no install side effect."""

    manifest_sha256: str
    files: tuple[RenderedExecutorFileV1, RenderedExecutorFileV1, RenderedExecutorFileV1]
    template_bundle_sha256: str


def _rendered_file(
    *,
    path: str,
    group: str,
    mode: int,
    content: str,
) -> RenderedExecutorFileV1:
    return RenderedExecutorFileV1(
        path=path,
        owner="root",
        group=group,
        mode=mode,
        content=content,
        content_sha256=_digest(content),
    )


def render_executor_installation(
    manifest: ExecutorInstallationManifestV2,
    *,
    transport_policy: ExecutorTransportPolicyV2,
    installation_policy: ExecutorInstallationPolicyV1,
) -> RenderedExecutorInstallationV2:
    """Render hardened systemd/sshd/key restrictions without writing anything."""

    if (
        type(manifest) is not ExecutorInstallationManifestV2
        or type(transport_policy) is not ExecutorTransportPolicyV2
        or type(installation_policy) is not ExecutorInstallationPolicyV1
    ):
        raise ExecutorInstallationRenderError("installation_manifest")
    try:
        canonical_manifest = ExecutorInstallationManifestV2.model_validate_json(
            _canonical_json(manifest.model_dump(mode="json"))
        )
    except (ValidationError, ValueError):
        raise ExecutorInstallationRenderError("installation_manifest") from None
    if (
        canonical_manifest != manifest
        or manifest.executor_id != transport_policy.executor_id
        or manifest.executor_id != installation_policy.executor.executor_id
        or manifest.daemon_socket_path != transport_policy.daemon_socket_path
        or transport_policy.package_sha256 != installation_policy.package_sha256
        or transport_policy.template_bundle_sha256 != installation_policy.template_bundle_sha256
        or transport_policy.daemon_socket_policy_sha256
        != installation_policy.unix_socket_policy_sha256
        or transport_policy.ssh_policy != installation_policy.ssh
        or _authorized_key_fingerprint(manifest.client_authorized_key)
        != transport_policy.identity.public_key_fingerprint_sha256
        or transport_policy.identity.public_key_fingerprint_sha256
        != transport_policy.ssh_policy.client_key_fingerprint_sha256
    ):
        raise ExecutorInstallationRenderError("installation_binding")
    unit = "\n".join(
        (
            "[Unit]",
            "Description=OmniNode RSD executor daemon",
            "After=network.target",
            "",
            "[Service]",
            "Type=exec",
            f"User={manifest.daemon_user}",
            f"Group={manifest.daemon_group}",
            f"LoadCredentialEncrypted={manifest.credential_name}",
            f"ExecStart={manifest.daemon_executable_path} --uds {manifest.daemon_socket_path}",
            "UMask=0077",
            "LimitCORE=0",
            "NoNewPrivileges=yes",
            "PrivateTmp=yes",
            "PrivateDevices=yes",
            "ProtectSystem=strict",
            "ProtectHome=yes",
            "ProtectKernelTunables=yes",
            "ProtectKernelModules=yes",
            "ProtectControlGroups=yes",
            "RestrictAddressFamilies=AF_UNIX",
            "RestrictRealtime=yes",
            "RestrictSUIDSGID=yes",
            "LockPersonality=yes",
            "SystemCallArchitectures=native",
            "MemoryDenyWriteExecute=yes",
            "CapabilityBoundingSet=",
            "AmbientCapabilities=",
            "Restart=no",
            "",
            "[Install]",
            "WantedBy=multi-user.target",
            "",
        )
    )
    sshd = "\n".join(
        (
            f"Match User {transport_policy.ssh_policy.dedicated_user}",
            f"    ForceCommand {manifest.force_command_path}",
            "    DisableForwarding yes",
            "    PermitTTY no",
            "    AllowTcpForwarding no",
            "    X11Forwarding no",
            "    PermitTunnel no",
            "    GatewayPorts no",
            "    PermitOpen none",
            "    AllowAgentForwarding no",
            "    AllowStreamLocalForwarding no",
            "    PermitUserEnvironment no",
            "    StreamLocalBindUnlink no",
            "",
        )
    )
    key_policy = "\n".join(
        (
            (
                f'command="{manifest.force_command_path}",restrict,'
                "no-agent-forwarding,no-port-forwarding,no-pty,no-user-rc,no-X11-forwarding "
                f"{manifest.client_authorized_key}"
            ),
            "",
        )
    )
    files = (
        _rendered_file(
            path=manifest.systemd_unit_path,
            group="root",
            mode=manifest.config_file_mode,
            content=unit,
        ),
        _rendered_file(
            path=manifest.sshd_fragment_path,
            group="root",
            mode=manifest.config_file_mode,
            content=sshd,
        ),
        _rendered_file(
            path=manifest.authorized_key_policy_path,
            group="root",
            mode=manifest.config_file_mode,
            content=key_policy,
        ),
    )
    bundle = _digest(
        _canonical_json(
            {
                "files": [
                    {
                        "content_sha256": item.content_sha256,
                        "group": item.group,
                        "mode": item.mode,
                        "owner": item.owner,
                        "path": item.path,
                    }
                    for item in files
                ],
                "manifest": manifest.model_dump(mode="json"),
            }
        )
    )
    return RenderedExecutorInstallationV2(
        manifest_sha256=_digest(_canonical_json(manifest.model_dump(mode="json"))),
        files=files,
        template_bundle_sha256=bundle,
    )


def main(argv: Sequence[str] | None = None) -> int:
    """Read-only CLI entrypoint; this release intentionally has no install mode."""

    parser = argparse.ArgumentParser(description="Render-only RSD executor installation primitives")
    parser.add_argument("--version", action="store_true", help="print the render API version")
    arguments = parser.parse_args(argv)
    if arguments.version:
        print("rsd-executor-installation-render-v2")
        return 0
    parser.print_help()
    return 0


__all__ = [
    "ExecutorInstallationManifestV2",
    "ExecutorInstallationRenderError",
    "RenderedExecutorFileV1",
    "RenderedExecutorInstallationV2",
    "main",
    "render_executor_installation",
]
