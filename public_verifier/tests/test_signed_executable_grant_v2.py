"""Public vectors and fixed-anchor verification tests for executable grants v2."""

from __future__ import annotations

import json
from copy import deepcopy
from datetime import UTC, datetime, timedelta, timezone, tzinfo
from typing import cast
from unittest.mock import MagicMock

import pytest
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PublicKey
from jsonschema import Draft202012Validator, FormatChecker
from omninode_grant_verifier import (
    ExecutableGrantVerificationError,
    parse_signed_executable_grant_v2,
    public_grant_trust_anchor_v1,
    signed_executable_grant_v2_json_schema,
    signed_executable_grant_v2_vectors,
    verify_signed_executable_grant_v2,
)

_VERIFIER_FORMAT_CHECKER = FormatChecker()


class _DatetimeSubclass(datetime):
    """A datetime subclass must not cross the exact public clock boundary."""


class _DatetimeSpoof:
    @property
    def __class__(self) -> type[datetime]:
        return datetime


class _RaisingTzinfo(tzinfo):
    def dst(self, dt: datetime | None) -> timedelta | None:
        return None

    def tzname(self, dt: datetime | None) -> str | None:
        return "raising"

    def utcoffset(self, dt: datetime | None) -> timedelta | None:
        raise RuntimeError("hostile timezone")


class _InvalidOffsetTzinfo(tzinfo):
    def dst(self, dt: datetime | None) -> timedelta | None:
        return None

    def tzname(self, dt: datetime | None) -> str | None:
        return "invalid-offset"

    def utcoffset(self, dt: datetime | None) -> timedelta | None:
        return cast(timedelta, "not-a-timedelta")


@_VERIFIER_FORMAT_CHECKER.checks("date-time")
def _is_verifier_datetime(value: object) -> bool:
    if type(value) is not str:
        return True
    try:
        datetime.fromisoformat(value.replace("Z", "+00:00"))
    except ValueError:
        return False
    return True


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


def _valid_wire() -> dict[str, object]:
    vectors = signed_executable_grant_v2_vectors()
    wire = vectors["base_wire"]
    assert type(wire) is dict
    return deepcopy(wire)


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


def test_parser_preserves_large_schema_valid_digest_bound_wire_compatibility() -> None:
    """Wire transport size is not a verifier contract bound."""

    candidate = _valid_wire()
    parsed = parse_signed_executable_grant_v2(json.dumps(candidate))
    large_topic = "a." * 10_000 + "a"
    large_event_class = "Model" + "A" * 20_000
    material = parsed.authorization_material.model_copy(
        update={
            "grant": parsed.authorization_material.grant.model_copy(
                update={
                    "expected_output_topic": large_topic,
                    "expected_output_event_class": large_event_class,
                }
            )
        }
    )
    authorization = candidate["authorization_material"]
    assert type(authorization) is dict
    grant = authorization["grant"]
    assert type(grant) is dict
    grant["expected_output_topic"] = large_topic
    grant["expected_output_event_class"] = large_event_class
    candidate["authorization_digest"] = material.authorization_digest()
    encoded = json.dumps(candidate, separators=(",", ":"))
    assert len(encoded.encode("utf-8")) > 16_384
    assert _schema_errors(candidate) == []
    reparsed = parse_signed_executable_grant_v2(encoded)
    assert reparsed.authorization_material.grant.expected_output_topic == large_topic
    assert reparsed.authorization_material.grant.expected_output_event_class == large_event_class


def test_parser_maps_invalid_utf8_to_the_public_error_taxonomy() -> None:
    """Malformed byte input cannot leak a decoder-specific exception."""

    with pytest.raises(ExecutableGrantVerificationError, match="strict JSON"):
        parse_signed_executable_grant_v2(b"\xff")


def test_parser_contains_deep_json_recursion_in_the_public_error_taxonomy() -> None:
    """A hostile JSON shape cannot leak a raw decoder or traversal error."""

    depth = 4_096
    valid_wire = json.dumps(_valid_wire(), separators=(",", ":")).encode("utf-8")
    wire = b'{"unexpected":' + b"[" * depth + b"]" * depth + b"," + valid_wire[1:]
    with pytest.raises(ExecutableGrantVerificationError, match="fixed contract"):
        parse_signed_executable_grant_v2(wire)


@pytest.mark.parametrize(
    "invalid_now",
    (
        None,
        "2030-01-01T00:00:00Z",
        0,
        MagicMock(spec=datetime),
        _DatetimeSpoof(),
        _DatetimeSubclass(2030, 1, 1, tzinfo=UTC),
    ),
)
def test_verifier_rejects_non_datetime_clocks_with_a_contract_error(invalid_now: object) -> None:
    """An invalid caller clock must fail closed through the public error boundary."""

    with pytest.raises(ExecutableGrantVerificationError, match="must be a datetime"):
        verify_signed_executable_grant_v2(
            json.dumps(_valid_wire()), now=cast(datetime, invalid_now)
        )


@pytest.mark.parametrize(
    ("invalid_now", "message"),
    (
        (datetime(2030, 1, 1), "must be UTC timezone-aware"),
        (
            datetime(2030, 1, 1, tzinfo=timezone(timedelta(hours=1))),
            "must be UTC timezone-aware",
        ),
        (datetime(2030, 1, 1, tzinfo=_RaisingTzinfo()), "timestamp is invalid"),
        (datetime(2030, 1, 1, tzinfo=_InvalidOffsetTzinfo()), "timestamp is invalid"),
    ),
)
def test_verifier_contains_hostile_or_non_utc_builtin_datetime_values(
    invalid_now: datetime, message: str
) -> None:
    """A built-in datetime's attached timezone cannot escape the public error boundary."""

    with pytest.raises(ExecutableGrantVerificationError, match=message):
        verify_signed_executable_grant_v2(json.dumps(_valid_wire()), now=invalid_now)


@pytest.mark.parametrize(
    "now",
    (
        datetime(2030, 1, 1, tzinfo=UTC),
        datetime(2030, 1, 1, tzinfo=timezone(timedelta(0))),
    ),
)
def test_verifier_accepts_canonical_utc_clocks(now: datetime) -> None:
    assert verify_signed_executable_grant_v2(json.dumps(_valid_wire()), now=now)


def _assert_closed_object(
    schema: object,
    *,
    fields: frozenset[str],
) -> dict[str, object]:
    assert type(schema) is dict
    assert schema["type"] == "object"
    assert schema["additionalProperties"] is False
    assert set(schema["required"]) == fields
    properties = schema["properties"]
    assert type(properties) is dict
    assert set(properties) == fields
    return properties


def test_published_json_schema_covers_every_fixed_signed_grant_field() -> None:
    """Keep the public schema closed and structurally aligned with the verifier DTO."""

    schema = signed_executable_grant_v2_json_schema()
    root = _assert_closed_object(
        schema,
        fields=frozenset(
            {
                "schema_version",
                "authorization_material",
                "authorization_digest",
                "signature_octets",
            }
        ),
    )
    authorization = _assert_closed_object(
        root["authorization_material"],
        fields=frozenset(
            {
                "schema_version",
                "domain",
                "issuer_key_id",
                "issuer_key_fingerprint_sha256",
                "grant",
            }
        ),
    )
    grant = _assert_closed_object(
        authorization["grant"],
        fields=frozenset(
            {
                "schema_version",
                "dispatch_policy",
                "grant_id",
                "envelope_id",
                "activation_id",
                "correlation_id",
                "nonce_sha256",
                "pins",
                "tenant_id",
                "backend_id",
                "served_model_id",
                "posture",
                "expected_output_topic",
                "expected_output_event_class",
                "expected_output_event_index",
                "issued_at",
                "not_before",
                "expires_at",
            }
        ),
    )
    _assert_closed_object(
        grant["pins"],
        fields=frozenset(
            {
                "artifact_sha256",
                "rendered_contract_sha256",
                "request_sha256",
            }
        ),
    )
    posture = _assert_closed_object(
        grant["posture"],
        fields=frozenset(
            {
                "attempt_count",
                "retry_disposition",
                "fallback_used",
                "recovery_disposition",
            }
        ),
    )
    assert posture["attempt_count"] == {"const": 1}
    assert posture["retry_disposition"] == {"const": "forbidden"}
    assert posture["fallback_used"] == {"const": False}
    assert posture["recovery_disposition"] == {"const": "report-only"}
    for field in ("grant_id", "envelope_id", "activation_id", "correlation_id"):
        field_schema = grant[field]
        assert type(field_schema) is dict
        assert field_schema["format"] == "uuid"
    for field in ("issued_at", "not_before", "expires_at"):
        field_schema = grant[field]
        assert type(field_schema) is dict
        assert field_schema["format"] == "date-time"


def _schema_errors(wire: object) -> list[str]:
    validator = Draft202012Validator(
        signed_executable_grant_v2_json_schema(), format_checker=_VERIFIER_FORMAT_CHECKER
    )
    return [error.message for error in validator.iter_errors(wire)]


def test_published_json_schema_enforces_the_verifier_wire_value_shapes() -> None:
    """The published schema rejects shapes the verifier's strict parser rejects."""

    valid = _valid_wire()
    assert _schema_errors(valid) == []

    invalid_cases: tuple[tuple[str, str, object], ...] = (
        ("impossible-date", "authorization_material.grant.issued_at", "2030-02-30T00:00:00Z"),
        ("impossible-time", "authorization_material.grant.not_before", "2030-01-01T25:00:00Z"),
        ("offset-not-z", "authorization_material.grant.expires_at", "2030-01-01T00:01:00+00:00"),
        ("malformed-uuid", "authorization_material.grant.grant_id", "not-a-uuid"),
        (
            "noncanonical-uuid",
            "authorization_material.grant.envelope_id",
            "40000000-0000-4000-8000-00000000000A",
        ),
        ("wrong-type", "signature_octets", "not-an-octet-array"),
    )
    for case_id, path, value in invalid_cases:
        candidate = _valid_wire()
        _set_path(candidate, path, value)
        assert _schema_errors(candidate), case_id
        with pytest.raises(ExecutableGrantVerificationError, match="fixed contract"):
            parse_signed_executable_grant_v2(json.dumps(candidate))

    extra = _valid_wire()
    grant = extra["authorization_material"]
    assert type(grant) is dict
    material = grant["grant"]
    assert type(material) is dict
    material["unexpected"] = True
    assert _schema_errors(extra)
    with pytest.raises(ExecutableGrantVerificationError, match="fixed contract"):
        parse_signed_executable_grant_v2(json.dumps(extra))

    missing = _valid_wire()
    material = missing["authorization_material"]
    assert type(material) is dict
    grant = material["grant"]
    assert type(grant) is dict
    del grant["nonce_sha256"]
    assert _schema_errors(missing)
    with pytest.raises(ExecutableGrantVerificationError, match="fixed contract"):
        parse_signed_executable_grant_v2(json.dumps(missing))
