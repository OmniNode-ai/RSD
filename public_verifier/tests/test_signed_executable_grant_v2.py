"""Public vectors and fixed-anchor verification tests for executable grants v2."""

from __future__ import annotations

import json
from copy import deepcopy
from datetime import UTC, datetime

import pytest
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PublicKey
from omninode_grant_verifier import (
    ExecutableGrantVerificationError,
    parse_signed_executable_grant_v2,
    public_grant_trust_anchor_v1,
    signed_executable_grant_v2_json_schema,
    signed_executable_grant_v2_vectors,
    verify_signed_executable_grant_v2,
)


def _set_path(document: dict[str, object], path: str, value: object) -> None:
    current = document
    for part in path.split(".")[:-1]:
        nested = current[part]
        assert type(nested) is dict
        current = nested
    current[path.rsplit(".", maxsplit=1)[-1]] = value


def _wire_for_vector(vector: dict[str, object], base: dict[str, object]) -> dict[str, object]:
    wire = vector.get("wire")
    if wire is not None:
        assert type(wire) is dict
        return deepcopy(wire)
    result = deepcopy(base)
    patches = vector["patch"]
    assert type(patches) is list
    for patch in patches:
        assert type(patch) is list and len(patch) == 2 and isinstance(patch[0], str)
        _set_path(result, patch[0], patch[1])
    return result


def test_vectors_reach_their_declared_verification_stages() -> None:
    vectors = signed_executable_grant_v2_vectors()
    base = vectors["base_wire"]
    cases = vectors["vectors"]
    assert type(base) is dict and type(cases) is list
    for case in cases:
        assert type(case) is dict
        expected = case["expect"]
        assert type(expected) is dict
        stage, error = expected["stage"], expected["error"]
        assert isinstance(stage, str) and (error is None or isinstance(error, str))
        wire = json.dumps(_wire_for_vector(case, base))
        now_text = case.get("verification_now", vectors["now"])
        assert isinstance(now_text, str)
        now = datetime.fromisoformat(now_text.replace("Z", "+00:00")).astimezone(UTC)
        if stage == "verified":
            assert verify_signed_executable_grant_v2(wire, now=now)
        elif stage == "wire-contract/output-index":
            with pytest.raises(ExecutableGrantVerificationError, match=error):
                parse_signed_executable_grant_v2(wire)
        else:
            parsed = parse_signed_executable_grant_v2(wire)
            if stage == "issuer-fingerprint":
                key_octets = case["issuer_public_key_octets"]
                assert type(key_octets) is list
                Ed25519PublicKey.from_public_bytes(bytes(key_octets)).verify(
                    bytes(parsed.signature_octets), parsed.signed_payload()
                )
            with pytest.raises(ExecutableGrantVerificationError, match=error):
                verify_signed_executable_grant_v2(wire, now=now)


def test_schema_anchor_and_parser_are_fixed_public_resources() -> None:
    schema = signed_executable_grant_v2_json_schema()
    anchor = public_grant_trust_anchor_v1()
    assert schema["$id"] == "urn:omninode-rsd:signed-executable-grant:v2"
    assert anchor.issuer_key_id == "omninode-rsd-public-grant-authority"
    with pytest.raises(ExecutableGrantVerificationError, match="strict JSON"):
        parse_signed_executable_grant_v2('{"schema_version":"x","schema_version":"y"}')
