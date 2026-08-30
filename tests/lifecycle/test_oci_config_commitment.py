"""Contract coverage for pure, value-redacted OCI config commitments."""

from __future__ import annotations

import hashlib
import inspect
import json
import os
import socket
from copy import deepcopy
from typing import Any

import pytest

from omninode_rsd.lifecycle import oci_config_commitment as commitment

_OCI_CONFIG_MEDIA_TYPE = "application/vnd.oci.image.config.v1+json"


def _canonical(value: object) -> bytes:
    return json.dumps(
        value, ensure_ascii=True, sort_keys=True, separators=(",", ":"), allow_nan=False
    ).encode("ascii")


def _config() -> dict[str, object]:
    return {
        "architecture": "amd64",
        "config": {
            "Cmd": ["serve", "--foreground"],
            "Entrypoint": ["/usr/local/bin/rsd-bootstrap"],
            "Env": ["APP_MODE=production", "PATH=/usr/bin:/bin"],
            "User": "12345:23456",
            "WorkingDir": "/opt/rsd",
        },
        "os": "linux",
        "rootfs": {"diff_ids": ["sha256:" + "a" * 64], "type": "layers"},
    }


def _payload(config: dict[str, object] | None = None) -> bytes:
    return _canonical(_config() if config is None else config)


def _descriptor(payload: bytes) -> tuple[str, str, int]:
    return _OCI_CONFIG_MEDIA_TYPE, "sha256:" + hashlib.sha256(payload).hexdigest(), len(payload)


def _derive(payload: bytes) -> commitment.PhaseAV5ExpandedOciConfigCommitmentClaimV1:
    return commitment.derive_phase_a_v5_expanded_oci_config_claim_v1(payload, *_descriptor(payload))


def _image_config(value: dict[str, object]) -> dict[str, Any]:
    return value["config"]  # type: ignore[return-value]


def test_public_api_is_explicitly_phase_a_v5_expanded_config_only() -> None:
    assert callable(commitment.derive_phase_a_v5_expanded_oci_config_claim_v1)
    assert callable(commitment.verify_phase_a_v5_expanded_oci_config_claim_v1)
    assert not hasattr(commitment, "derive_oci_config_commitment_v1")
    assert not hasattr(commitment, "verify_oci_config_commitment_v1")


def test_derives_complete_value_redacted_evidence() -> None:
    payload = _payload()

    result = _derive(payload)

    assert result.schema_version == "rsd.phase-a-v5-expanded-oci-config-commitment-claim.v1"
    assert result.signed_worker_attestation_scope == "phase-a-v5-expanded-oci-config-profile"
    assert result.non_authorizing is True
    assert result.oci_config_descriptor_media_type == _descriptor(payload)[0]
    assert result.oci_config_descriptor_digest == _descriptor(payload)[1]
    assert result.oci_config_descriptor_size == _descriptor(payload)[2]
    assert (result.runtime_uid, result.runtime_gid) == (12345, 23456)
    assert result.user_byte_count == len("12345:23456")
    assert result.working_dir_byte_count == len("/opt/rsd")
    assert result.environment_entry_count == 2
    assert result.environment_rendered_byte_count == len("APP_MODE=production") + len(
        "PATH=/usr/bin:/bin"
    )
    assert result.reserved_delivery_env_names_absent is True
    assert all(
        len(value) == 64
        for value in (
            result.user_commitment_sha256,
            result.working_dir_commitment_sha256,
            result.environment_sequence_commitment_sha256,
            result.environment_names_commitment_sha256,
            result.reserved_delivery_env_policy_commitment_sha256,
        )
    )

    serialized = result.model_dump_json()
    for raw in ("12345:23456", "/opt/rsd", "APP_MODE=production", "PATH=/usr/bin:/bin"):
        assert raw not in serialized


def test_requires_exact_oci_config_descriptor_and_verifies_exact_claim() -> None:
    payload = _payload()
    descriptor_media_type, descriptor_digest, descriptor_size = _descriptor(payload)
    claim = commitment.derive_phase_a_v5_expanded_oci_config_claim_v1(
        payload, descriptor_media_type, descriptor_digest, descriptor_size
    )

    assert (
        commitment.verify_phase_a_v5_expanded_oci_config_claim_v1(
            payload, descriptor_media_type, descriptor_digest, descriptor_size, claim
        )
        == claim
    )
    for incorrect_media_type, incorrect_digest, incorrect_size in (
        ("application/vnd.oci.image.manifest.v1+json", descriptor_digest, descriptor_size),
        (_OCI_CONFIG_MEDIA_TYPE + ";charset=utf-8", descriptor_digest, descriptor_size),
        (descriptor_media_type, "sha256:" + "b" * 64, descriptor_size),
        (descriptor_media_type, descriptor_digest, descriptor_size + 1),
        (
            descriptor_media_type,
            "sha256:" + descriptor_digest.removeprefix("sha256:").upper(),
            descriptor_size,
        ),
    ):
        with pytest.raises(commitment.OciConfigCommitmentError):
            commitment.derive_phase_a_v5_expanded_oci_config_claim_v1(
                payload, incorrect_media_type, incorrect_digest, incorrect_size
            )
        with pytest.raises(commitment.OciConfigCommitmentError):
            commitment.verify_phase_a_v5_expanded_oci_config_claim_v1(
                payload, incorrect_media_type, incorrect_digest, incorrect_size, claim
            )


def test_verification_rejects_forged_deserialized_claim() -> None:
    payload = _payload()
    descriptor_media_type, descriptor_digest, descriptor_size = _descriptor(payload)
    exact = _derive(payload)
    restored = commitment.PhaseAV5ExpandedOciConfigCommitmentClaimV1.model_validate_json(
        exact.model_dump_json()
    )
    forged_fields = restored.model_dump(mode="json")
    forged_fields["environment_entry_count"] = 1
    forged = commitment.PhaseAV5ExpandedOciConfigCommitmentClaimV1.model_validate_json(
        json.dumps(forged_fields, sort_keys=True, separators=(",", ":"))
    )
    media_type_forged = exact.model_copy(
        update={"oci_config_descriptor_media_type": "application/vnd.oci.image.manifest.v1+json"}
    )

    assert (
        commitment.verify_phase_a_v5_expanded_oci_config_claim_v1(
            payload, descriptor_media_type, descriptor_digest, descriptor_size, restored
        )
        == exact
    )
    with pytest.raises(commitment.OciConfigCommitmentError):
        commitment.verify_phase_a_v5_expanded_oci_config_claim_v1(
            payload, descriptor_media_type, descriptor_digest, descriptor_size, forged
        )
    with pytest.raises(commitment.OciConfigCommitmentError):
        commitment.verify_phase_a_v5_expanded_oci_config_claim_v1(
            payload, descriptor_media_type, descriptor_digest, descriptor_size, media_type_forged
        )


def test_rejects_current_v4_two_key_oci_config_by_design() -> None:
    config = _config()
    raw_config = _image_config(config)
    del raw_config["User"]
    del raw_config["WorkingDir"]
    del raw_config["Env"]
    payload = _payload(config)

    with pytest.raises(commitment.OciConfigCommitmentError):
        commitment.derive_phase_a_v5_expanded_oci_config_claim_v1(payload, *_descriptor(payload))


@pytest.mark.parametrize("user", ("1:1", "2147483647:2147483647", "42:99"))
def test_accepts_canonical_numeric_uid_gid_pairs(user: str) -> None:
    config = _config()
    _image_config(config)["User"] = user

    result = _derive(_payload(config))

    expected_uid, expected_gid = (int(part) for part in user.split(":"))
    assert (result.runtime_uid, result.runtime_gid) == (expected_uid, expected_gid)


@pytest.mark.parametrize(
    "user",
    (
        "",
        "0:1",
        "1:0",
        "01:1",
        "1:01",
        "1",
        "1:",
        ":1",
        "user:group",
        "1000 :1000",
        "1000: 1000",
        "1000:1000:1000",
        "2147483648:1",
        "1:2147483648",
        "-1:1",
        "1:-1",
    ),
)
def test_rejects_noncanonical_uid_gid_pairs(user: str) -> None:
    config = _config()
    _image_config(config)["User"] = user

    with pytest.raises(commitment.OciConfigCommitmentError):
        _derive(_payload(config))


@pytest.mark.parametrize("working_dir", ("/", "/a", "/opt/rsd", "/a" + "b" * 63))
def test_accepts_canonical_absolute_working_dirs(working_dir: str) -> None:
    config = _config()
    _image_config(config)["WorkingDir"] = working_dir

    result = _derive(_payload(config))

    assert result.working_dir_byte_count == len(working_dir)


@pytest.mark.parametrize(
    "working_dir",
    (
        "",
        "relative/path",
        "/trailing/",
        "//repeated",
        "/dot/./segment",
        "/dotdot/../segment",
        "/percent%value",
        "/back\\slash",
        "/bad\x00value",
        "/café",
        "/" + "a" * 65,
        "/" + "a" * 241,
    ),
)
def test_rejects_unsafe_working_dirs(working_dir: str) -> None:
    config = _config()
    _image_config(config)["WorkingDir"] = working_dir

    with pytest.raises(commitment.OciConfigCommitmentError):
        _derive(_payload(config))


def test_env_order_and_exact_full_sequence_are_committed() -> None:
    config = _config()
    _image_config(config)["Env"] = ["A_KEY=first=value", "Z_KEY="]

    result = _derive(_payload(config))

    assert result.environment_entry_count == 2
    assert result.environment_rendered_byte_count == len("A_KEY=first=value") + len("Z_KEY=")


@pytest.mark.parametrize(
    "entries",
    (
        ["Z_KEY=late", "A_KEY=early"],
        ["A_KEY=first", "A_KEY=duplicate"],
        ["lowercase=value"],
        ["1START=value"],
        ["NO_EQUALS"],
        ["A-HYPHEN=value"],
        ["A_KEY=value\n"],
        ["A_KEY=" + "x" * 1025],
        ["ENCRYPTION_KEY=value"],
        ["AUTH_SECRET=value"],
        ["DB_CONNECTION_URI=value"],
        ["REDIS_URL=value"],
        ["REQUIREPASS=value"],
        ["encryption_key=value"],
    ),
)
def test_rejects_malformed_unsorted_duplicate_and_reserved_env(entries: list[str]) -> None:
    config = _config()
    _image_config(config)["Env"] = entries

    with pytest.raises(commitment.OciConfigCommitmentError):
        _derive(_payload(config))


def test_rejects_env_count_and_rendered_byte_limits() -> None:
    config = _config()
    _image_config(config)["Env"] = [f"A{str(index).zfill(3)}=x" for index in range(33)]
    with pytest.raises(commitment.OciConfigCommitmentError):
        _derive(_payload(config))

    config = _config()
    _image_config(config)["Env"] = [f"A{str(index).zfill(3)}=" + "x" * 1024 for index in range(17)]
    with pytest.raises(commitment.OciConfigCommitmentError):
        _derive(_payload(config))


def test_rejects_noncanonical_json_duplicate_keys_floats_and_utf8() -> None:
    valid = _payload()
    raw_config = _config()
    reordered = json.dumps(
        {key: raw_config[key] for key in ("os", "architecture", "config", "rootfs")},
        ensure_ascii=True,
        sort_keys=False,
        separators=(",", ":"),
    ).encode("ascii")
    duplicate = valid.replace(b'"architecture":"amd64",', b'"architecture":"amd64","os":"linux",')
    with_float = valid.replace(b'"architecture":"amd64"', b'"architecture":1.0')
    utf8 = (
        json.dumps(_config(), ensure_ascii=False, sort_keys=True, separators=(",", ":"))
        .replace('"/opt/rsd"', '"/café"')
        .encode("utf-8")
    )

    for payload in (reordered, duplicate, with_float, utf8):
        with pytest.raises(commitment.OciConfigCommitmentError):
            _derive(payload)


def test_rejects_oversized_too_deep_and_too_many_node_json() -> None:
    oversized = b"{" + b" " * commitment._MAX_CONFIG_JSON_BYTES + b"}"
    deep: object = 0
    for _ in range(commitment._MAX_DEPTH + 1):
        deep = {"a": deep}
    too_deep = _canonical(deep)
    too_many_nodes = _canonical(
        {f"a{str(index).zfill(4)}": 0 for index in range(commitment._MAX_NODES)}
    )

    for payload in (oversized, too_deep, too_many_nodes):
        with pytest.raises(commitment.OciConfigCommitmentError):
            _derive(payload)


@pytest.mark.parametrize(
    "mutation",
    (
        ("User", "12346:23456"),
        ("WorkingDir", "/opt/rsd-next"),
        ("Env", ["APP_MODE=staging", "PATH=/usr/bin:/bin"]),
        ("Cmd", ["serve", "--safe"]),
        ("Entrypoint", ["/usr/local/bin/rsd-bootstrap-next"]),
    ),
)
def test_mutating_any_raw_config_field_changes_derived_evidence(
    mutation: tuple[str, object],
) -> None:
    original = _derive(_payload())
    config = deepcopy(_config())
    _image_config(config)[mutation[0]] = mutation[1]
    changed = _derive(_payload(config))

    assert changed.oci_config_descriptor_digest != original.oci_config_descriptor_digest
    assert changed.user_commitment_sha256 != original.user_commitment_sha256
    assert changed.working_dir_commitment_sha256 != original.working_dir_commitment_sha256
    assert (
        changed.environment_sequence_commitment_sha256
        != original.environment_sequence_commitment_sha256
    )
    assert (
        changed.environment_names_commitment_sha256 != original.environment_names_commitment_sha256
    )
    assert (
        changed.reserved_delivery_env_policy_commitment_sha256
        != original.reserved_delivery_env_policy_commitment_sha256
    )


def test_hash_domains_are_separate_and_all_subcommitments_bind_config_digest() -> None:
    original = _derive(_payload())
    config = _config()
    _image_config(config)["Cmd"] = ["serve", "--changed"]
    changed = _derive(_payload(config))

    assert original.user_commitment_sha256 != original.working_dir_commitment_sha256
    assert (
        original.environment_sequence_commitment_sha256
        != original.environment_names_commitment_sha256
    )
    assert original.user_commitment_sha256 != changed.user_commitment_sha256
    assert original.working_dir_commitment_sha256 != changed.working_dir_commitment_sha256
    assert (
        original.environment_sequence_commitment_sha256
        != changed.environment_sequence_commitment_sha256
    )
    assert (
        original.environment_names_commitment_sha256 != changed.environment_names_commitment_sha256
    )
    assert (
        original.reserved_delivery_env_policy_commitment_sha256
        != changed.reserved_delivery_env_policy_commitment_sha256
    )


@pytest.mark.parametrize(
    "field,value",
    (
        ("architecture", "arm64"),
        ("os", "windows"),
        ("rootfs", {"diff_ids": [], "type": "layers"}),
        ("rootfs", {"diff_ids": ["sha256:" + "A" * 64], "type": "layers"}),
        ("rootfs", {"diff_ids": ["sha256:" + "a" * 64], "type": "other"}),
    ),
)
def test_rejects_noncanonical_oci_platform_and_rootfs(field: str, value: object) -> None:
    config = _config()
    config[field] = value

    with pytest.raises(commitment.OciConfigCommitmentError):
        _derive(_payload(config))


def test_rejects_extra_config_keys_and_unsafe_existing_argv() -> None:
    config = _config()
    _image_config(config)["Hostname"] = "unexpected"
    with pytest.raises(commitment.OciConfigCommitmentError):
        _derive(_payload(config))

    config = _config()
    _image_config(config)["Entrypoint"] = ["relative"]
    with pytest.raises(commitment.OciConfigCommitmentError):
        _derive(_payload(config))

    config = _config()
    _image_config(config)["Cmd"] = ["unsafe space"]
    with pytest.raises(commitment.OciConfigCommitmentError):
        _derive(_payload(config))


def test_utility_has_no_environment_or_network_effect(monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.setattr(os, "getenv", lambda *_args, **_kwargs: pytest.fail("environment read"))
    monkeypatch.setattr(
        socket, "create_connection", lambda *_args, **_kwargs: pytest.fail("network access")
    )

    assert _derive(_payload()).runtime_uid == 12345
    source = inspect.getsource(commitment)
    assert "subprocess" not in source
    assert "socket" not in source
    assert "pathlib" not in source
