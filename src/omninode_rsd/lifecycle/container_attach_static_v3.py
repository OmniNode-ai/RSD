"""Output-independent V3 target attach-ticket primitives.

This module deliberately stops at the target-verification boundary.  It has no
frame reader, secret carrier, Engine client, provider access, or effect API.
The static profile is suitable for compiling into a future role-specific
wrapper because its digest excludes wrapper bytes, artifact bindings,
signatures, generated provenance/SBOM/reproducibility results, and every
other field derived from built output.

It is therefore *not* evidence that a wrapper was built, inspected,
authorized, or allowed to receive a delivery.  Those cross-bindings remain a
separate V3 lifecycle/evidence slice.

This is the first published V3 replay grammar: it has no production authority,
durable V3 state, or migration path.  Future production authorities must use
this exact atomic claim shape rather than adopting a local draft or legacy key.
"""

from __future__ import annotations

import base64
import binascii
import hashlib
import json
import math
import re
import time
from dataclasses import dataclass
from datetime import UTC, datetime, timedelta
from threading import Lock
from typing import Literal, NoReturn, Protocol, Self

from cryptography.exceptions import InvalidSignature
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PublicKey
from pydantic import BaseModel, ConfigDict, Field, field_validator, model_validator

from omninode_rsd.lifecycle.infisical_disposable import (
    ContainerAttachTicketTrustAnchorV1,
    ContainerBootstrapEnvironmentConstructionPolicyV2,
    ContainerBootstrapFdPolicyV2,
    ContainerBootstrapMemorySafetyPolicyV2,
    ContainerBootstrapPid1PolicyV2,
    ContainerBootstrapStaticEnvironmentEntryV2,
    ContainerBootstrapStaticEnvironmentV2,
    ContainerBootstrapValkeyLaunchPolicyV2,
    ContainerSecretSinkV1,
    TargetDeliveryFieldV1,
    TargetDeliveryValueKindV1,
)

_SHA256 = r"^[0-9a-f]{64}$"
_UUID = (
    r"^[0-9a-f]{8}-[0-9a-f]{4}-[1-5][0-9a-f]{3}-"
    r"[89ab][0-9a-f]{3}-[0-9a-f]{12}$"
)
_COMMIT = r"^[0-9a-f]{40}$"
_CONTAINER_ID = r"^[0-9a-f]{64}$"
_HOSTNAME = r"^[a-z0-9][a-z0-9-]{14,61}[a-z0-9]$"
_TIMESTAMP = re.compile(r"^[0-9]{4}-[0-9]{2}-[0-9]{2}T[0-9]{2}:[0-9]{2}:[0-9]{2}Z$")

_STATIC_PROFILE_DOMAIN = b"omninode-rsd.container-bootstrap-static-role-profile.sha256.v3\x00"
_DELIVERY_DESCRIPTOR_DOMAIN = (
    b"omninode-rsd.container-bootstrap-target-delivery-descriptor.sha256.v3\x00"
)
_ATTACH_PROTOCOL_DOMAIN = b"omninode-rsd.container-bootstrap-attach-protocol.sha256.v3\x00"
_ATTACH_REQUEST_DOMAIN = b"omninode-rsd.container-attach-request.sha256.v3\x00"
_ATTACH_TICKET_DOMAIN = b"omninode-rsd.container-attach-ticket.ed25519.v3\x00"
_ATTACH_TICKET_HASH_DOMAIN = b"omninode-rsd.container-attach-ticket.sha256.v3\x00"
_RUNTIME_BINDING_DOMAIN = b"omninode-rsd.container-attach-runtime-binding.sha256.v3\x00"
_TICKET_REPLAY_CLAIM_DOMAIN = b"omninode-rsd.container-attach-ticket-replay-claim.sha256.v3\x00"
_CONTAINER_LIFETIME_CLAIM_DOMAIN = (
    b"omninode-rsd.container-attach-container-lifetime-claim.sha256.v3\x00"
)
_REPLAY_CLAIM_DOMAIN = b"omninode-rsd.container-attach-replay-claim.sha256.v3\x00"

_ComponentV3 = Literal[
    "primary_infisical",
    "primary_valkey",
    "restore_infisical",
    "restore_valkey",
]
_OperationScopeV3 = Literal["materialize_and_start_runtime_v1", "start_runtime_v2"]


class ContainerAttachStaticV3Error(ValueError):
    """A fixed, value-free V3 target-verification failure."""

    __slots__ = ("phase",)

    def __init__(
        self,
        phase: Literal["profile", "ticket", "signature", "freshness", "binding", "replay"],
    ):
        super().__init__("container attach V3 verification failed")
        self.phase = phase


class _Model(BaseModel):
    """Strict immutable V3 public metadata."""

    model_config = ConfigDict(extra="forbid", frozen=True, strict=True, validate_default=True)


def _fail(
    phase: Literal["profile", "ticket", "signature", "freshness", "binding", "replay"],
) -> NoReturn:
    """Raise after an exception scope so no collaborator error is retained."""

    raise ContainerAttachStaticV3Error(phase)


def _items(value: object, *, field: str) -> tuple[object, ...]:
    """Accept only an exact immutable tuple at a static-profile boundary."""

    if type(value) is not tuple:
        raise ValueError(f"{field} must be a tuple")
    return value


def _canonical_base64_bytes(value: str) -> bytes:
    """Decode one exact standard-base64 spelling without aliases."""

    if type(value) is not str:
        raise ValueError("base64 value is invalid")
    raw: bytes | None = None
    try:
        encoded = value.encode("ascii")
        raw = base64.b64decode(encoded, validate=True)
    except (UnicodeEncodeError, binascii.Error):
        raw = None
    if raw is None or base64.b64encode(raw).decode("ascii") != value:
        raise ValueError("base64 value is invalid")
    return raw


def _canonical_timestamp(value: str) -> datetime:
    """Parse the one UTC timestamp spelling used by V3 tickets."""

    if type(value) is not str or _TIMESTAMP.fullmatch(value) is None:
        raise ValueError("ticket timestamp is invalid")
    parsed: datetime | None = None
    try:
        parsed = datetime.strptime(value, "%Y-%m-%dT%H:%M:%SZ").replace(tzinfo=UTC)
    except ValueError:
        parsed = None
    if parsed is None:
        raise ValueError("ticket timestamp is invalid")
    return parsed


def _canonical_timestamp_text(value: datetime) -> str:
    """Render one exact, second-granularity UTC timestamp for a deadline."""

    if (
        type(value) is not datetime
        or value.tzinfo is None
        or value.utcoffset() != timedelta(0)
        or value.microsecond != 0
    ):
        raise ValueError("ticket timestamp is invalid")
    return value.strftime("%Y-%m-%dT%H:%M:%SZ")


def _canonical_model_bytes(model: BaseModel, *, exclude: set[str] | None = None) -> bytes:
    """Render a strict model as canonical ASCII-safe JSON."""

    payload: object | None = None
    try:
        payload = model.model_dump(mode="json", exclude=exclude or set(), warnings="error")
    except (TypeError, ValueError):
        payload = None
    if payload is None:
        raise ValueError("canonical model is invalid")
    rendered: str | None = None
    try:
        rendered = json.dumps(
            payload,
            ensure_ascii=True,
            sort_keys=True,
            separators=(",", ":"),
            allow_nan=False,
        )
    except (TypeError, ValueError):
        rendered = None
    if rendered is None:
        raise ValueError("canonical model is invalid")
    return rendered.encode("ascii")


def _no_duplicate_json_object(pairs: list[tuple[object, object]]) -> dict[str, object]:
    """Build one JSON object while rejecting duplicate/non-string keys."""

    result: dict[str, object] = {}
    for key, value in pairs:
        if type(key) is not str or key in result:
            raise ValueError("canonical JSON object is invalid")
        result[key] = value
    return result


def _json_arrays_as_tuples(value: object) -> object:
    """Translate JSON's only sequence shape into immutable typed-model tuples."""

    if type(value) is list:
        return tuple(_json_arrays_as_tuples(item) for item in value)
    if type(value) is dict:
        return {key: _json_arrays_as_tuples(item) for key, item in value.items()}
    return value


def _strict_canonical_model[T: _Model](value: T, expected: type[T]) -> T:
    """Round-trip one exact concrete model and reject constructed/type-drift trees."""

    if type(value) is not expected:
        raise ValueError("canonical model is invalid")
    _assert_exact_concrete_tree(value, expected)
    canonical: T | None = None
    try:
        canonical = expected.model_validate(value.model_dump(mode="python", warnings="error"))
    except (TypeError, ValueError):
        canonical = None
    if canonical is None or type(canonical) is not expected or canonical != value:
        raise ValueError("canonical model is invalid")
    return canonical


def _parse_canonical_json[T: _Model](payload: bytes, expected: type[T]) -> T:
    """Parse exactly canonical JSON without allowing mutable input sequences."""

    if type(payload) is not bytes or not 1 <= len(payload) <= 131_072:
        raise ValueError("canonical JSON is invalid")
    decoded: object | None = None
    try:
        decoded = json.loads(
            payload.decode("ascii"),
            object_pairs_hook=_no_duplicate_json_object,
        )
    except (UnicodeDecodeError, TypeError, ValueError):
        decoded = None
    if type(decoded) is not dict:
        raise ValueError("canonical JSON is invalid")
    model: T | None = None
    try:
        model = expected.model_validate(_json_arrays_as_tuples(decoded))
        model = _strict_canonical_model(model, expected)
    except (TypeError, ValueError):
        model = None
    if model is None or _canonical_model_bytes(model) != payload:
        raise ValueError("canonical JSON is invalid")
    return model


def _hash(domain: bytes, model: BaseModel) -> str:
    """Hash one canonical V3 model under its fixed domain."""

    return hashlib.sha256(domain + _canonical_model_bytes(model)).hexdigest()


def _expected_role(component: str) -> Literal["infisical", "valkey"]:
    """Return the compile-time role for one of four fixed targets."""

    return "valkey" if component.endswith("valkey") else "infisical"


def _trusted_utc_now() -> datetime:
    """Read production UTC at target verification time; tests patch this local seam."""

    return datetime.now(UTC).replace(microsecond=0)


def _trusted_monotonic_now() -> float:
    """Read production monotonic time for the bounded replay-authority call."""

    return time.monotonic()


def _valid_monotonic(value: object) -> bool:
    """Accept only an exact, finite, nonnegative monotonic-clock reading."""

    return type(value) is float and math.isfinite(value) and value >= 0.0


def _trusted_now() -> datetime:
    """Read exact trusted UTC for one V3 validation or claim use boundary."""

    now: datetime | None = None
    try:
        candidate = _trusted_utc_now()
        if (
            type(candidate) is datetime
            and candidate.tzinfo is not None
            and candidate.utcoffset() == timedelta(0)
        ):
            now = candidate.replace(microsecond=0)
    except Exception:
        now = None
    if now is None:
        _fail("freshness")
    return now


def _read_trusted_monotonic_now() -> float:
    """Read one finite monotonic value from the module-local clock boundary."""

    now: float | None = None
    try:
        candidate = _trusted_monotonic_now()
        if _valid_monotonic(candidate):
            now = candidate
    except Exception:
        now = None
    if now is None:
        _fail("freshness")
    return now


class ContainerBootstrapAttachProtocolV3(_Model):
    """Compiled V3 frame grammar and limits, without a runtime codec.

    The protocol is static input to the profile rather than a signed owner-side
    artifact.  The profile digest binds it; a future full V3 authorization
    chain must prove how that digest relates to its signed policy and image.
    """

    schema_version: Literal["rsd.container-bootstrap-attach-protocol.v3"]
    protocol_name: Literal["rsd_container_bootstrap_attach_v3"]
    frame_magic: Literal["ONC3"]
    frame_version: Literal[3]
    metadata_encoding: Literal["canonical_json_utf8_v1"]
    frame_header_layout: Literal["magic_4_version_u8_type_u8_length_u32be_v1"]
    secret_chunk_ordinal_layout: Literal["u16be_v1"]
    allowed_operation_scopes: tuple[
        Literal["materialize_and_start_runtime_v1"], Literal["start_runtime_v2"]
    ]
    first_frame: Literal["ticket_envelope_v3"]
    ready_state: Literal["ready_v3"]
    claim_state: Literal["claimed_v3"]
    write_closed_state: Literal["write_closed_v3"]
    terminal_ack_state: Literal["terminal_ack_v3"]
    ambiguous_state: Literal["attach_ambiguous_v3"]
    max_metadata_bytes: int = Field(ge=512, le=16_384)
    max_chunk_bytes: int = Field(ge=1, le=65_536)
    max_chunks_per_target: int = Field(ge=1, le=4)
    max_total_secret_bytes: int = Field(ge=1, le=262_144)
    max_stdout_bytes: int = Field(ge=512, le=1_048_576)
    max_stdout_frames: int = Field(ge=1, le=1024)
    ready_timeout_seconds: int = Field(ge=1, le=60)
    claim_timeout_seconds: int = Field(ge=1, le=60)
    terminal_ack_timeout_seconds: int = Field(ge=1, le=60)
    absolute_timeout_seconds: int = Field(ge=1, le=300)
    max_ticket_lifetime_seconds: int = Field(ge=1, le=300)
    docker_non_tty_required: Literal[True]
    docker_stdout_only_required: Literal[True]
    docker_stderr_rejected: Literal[True]
    actual_write_half_close_required: Literal[True]
    eof_required_before_terminal_ack: Literal[True]
    protocol_output_eof_required_after_terminal_ack: Literal[True]
    one_attach_per_container_lifetime: Literal[True]
    replay_allowed: Literal[False]
    auto_retry_after_secret_delivery_allowed: Literal[False]
    secret_persistence_allowed: Literal[False]
    secret_logging_allowed: Literal[False]
    secret_receipt_allowed: Literal[False]

    @field_validator("allowed_operation_scopes", mode="before")
    @classmethod
    def declared_scopes(cls, value: object) -> tuple[object, ...]:
        return _items(value, field="container attach V3 operation scopes")

    @model_validator(mode="after")
    def exact_bounded_protocol(self) -> Self:
        if (
            self.allowed_operation_scopes
            != ("materialize_and_start_runtime_v1", "start_runtime_v2")
            or self.max_total_secret_bytes < self.max_chunk_bytes
            or self.max_stdout_bytes < self.max_metadata_bytes
            or self.absolute_timeout_seconds
            < max(
                self.ready_timeout_seconds,
                self.claim_timeout_seconds,
                self.terminal_ack_timeout_seconds,
            )
            or self.max_ticket_lifetime_seconds < self.absolute_timeout_seconds
        ):
            raise ValueError("container bootstrap attach V3 protocol is invalid")
        return self


def strict_canonical_container_bootstrap_attach_protocol_v3(
    protocol: ContainerBootstrapAttachProtocolV3,
) -> ContainerBootstrapAttachProtocolV3:
    """Return the exact canonical V3 protocol or a fixed public error."""

    try:
        return _strict_canonical_model(protocol, ContainerBootstrapAttachProtocolV3)
    except (TypeError, ValueError):
        pass
    _fail("profile")


def container_bootstrap_attach_v3_protocol_canonical_json(
    protocol: ContainerBootstrapAttachProtocolV3,
) -> bytes:
    """Return canonical V3 protocol JSON for future cross-language consumers."""

    protocol = strict_canonical_container_bootstrap_attach_protocol_v3(protocol)
    try:
        return _canonical_model_bytes(protocol)
    except ValueError:
        pass
    _fail("profile")


def parse_container_bootstrap_attach_v3_protocol_canonical_json(
    payload: bytes,
) -> ContainerBootstrapAttachProtocolV3:
    """Parse only the exact canonical V3 protocol JSON spelling."""

    try:
        return _parse_canonical_json(payload, ContainerBootstrapAttachProtocolV3)
    except (TypeError, ValueError):
        pass
    _fail("profile")


def container_bootstrap_attach_v3_protocol_sha256(
    protocol: ContainerBootstrapAttachProtocolV3,
) -> str:
    """Return the static V3 frame-contract commitment."""

    protocol = strict_canonical_container_bootstrap_attach_protocol_v3(protocol)
    try:
        return _hash(_ATTACH_PROTOCOL_DOMAIN, protocol)
    except ValueError:
        pass
    _fail("profile")


class ContainerBootstrapDerivedUriCommitmentV3(_Model):
    """One exact, value-free URI derivation admitted to a static role profile.

    URI byte counts and grammar hashes cannot be universal constants: they
    depend on the signed, value-free delivery-map grammar for the particular
    allocation.  The compiled profile therefore carries these exact values as
    its target-side authority.  A later V3 evidence slice must prove this
    commitment was derived from the signed delivery map; this type does not
    claim that cross-binding has happened.
    """

    schema_version: Literal["rsd.container-bootstrap-derived-uri-commitment.v3"]
    source_purpose: Literal[
        "postgres_application_password",
        "primary_valkey_password",
        "restore_valkey_password",
    ]
    value_kind: Literal["derived_postgresql_uri_v1", "derived_valkey_uri_v1"]
    field_format: Literal["derived_postgresql_uri_v1", "derived_valkey_uri_v1"]
    target_field: Literal["DB_CONNECTION_URI", "REDIS_URL"]
    encoded_byte_count: int = Field(ge=1, le=1024)
    derivation_binding_sha256: str = Field(pattern=_SHA256)

    @model_validator(mode="after")
    def exact_uri_kind_and_target(self) -> Self:
        postgres = self.value_kind == "derived_postgresql_uri_v1"
        valid = self.field_format == self.value_kind and (
            (
                postgres
                and self.source_purpose == "postgres_application_password"
                and self.target_field == "DB_CONNECTION_URI"
            )
            or (
                not postgres
                and self.source_purpose in ("primary_valkey_password", "restore_valkey_password")
                and self.target_field == "REDIS_URL"
            )
        )
        if not valid:
            raise ValueError("container attach V3 derived URI commitment is invalid")
        return self


class ContainerBootstrapTargetDeliveryDescriptorV3(_Model):
    """One role-specific, value-free target descriptor set.

    The fields deliberately reuse ``TargetDeliveryFieldV1`` so source purpose,
    reference/fingerprint commitments, derivation grammar, format, byte count,
    sink, and all no-persistence flags cannot be silently dropped by V3.
    """

    schema_version: Literal["rsd.container-bootstrap-target-delivery-descriptor.v3"]
    component: _ComponentV3
    component_role: Literal["infisical", "valkey"]
    sink: ContainerSecretSinkV1
    fields: tuple[TargetDeliveryFieldV1, ...] = Field(min_length=1, max_length=4)
    derived_uri_commitments: tuple[ContainerBootstrapDerivedUriCommitmentV3, ...] = Field(
        max_length=2
    )

    @field_validator("fields", mode="before")
    @classmethod
    def declared_fields(cls, value: object) -> tuple[object, ...]:
        return _items(value, field="container attach V3 descriptor fields")

    @field_validator("derived_uri_commitments", mode="before")
    @classmethod
    def declared_derived_uri_commitments(cls, value: object) -> tuple[object, ...]:
        return _items(value, field="container attach V3 derived URI commitments")

    @field_validator("sink", mode="before")
    @classmethod
    def canonical_sink(cls, value: object) -> ContainerSecretSinkV1:
        if type(value) is ContainerSecretSinkV1:
            return value
        if type(value) is str:
            try:
                return ContainerSecretSinkV1(value)
            except ValueError:
                pass
        raise ValueError("container attach V3 descriptor sink is invalid")

    @model_validator(mode="after")
    def exact_role_delivery_descriptor(self) -> Self:
        expected: dict[
            str,
            tuple[
                ContainerSecretSinkV1,
                tuple[tuple[str, TargetDeliveryValueKindV1, str, int | None, str], ...],
            ],
        ] = {
            "primary_infisical": (
                ContainerSecretSinkV1.INFISICAL_TARGET_PROCESS_ENVIRONMENT,
                (
                    (
                        "encryption_key",
                        TargetDeliveryValueKindV1.DIRECT_PROVIDER_MATERIAL,
                        "infisical_hex_16_v1",
                        32,
                        "ENCRYPTION_KEY",
                    ),
                    (
                        "auth_secret",
                        TargetDeliveryValueKindV1.DIRECT_PROVIDER_MATERIAL,
                        "infisical_auth_secret_base64_32_v1",
                        44,
                        "AUTH_SECRET",
                    ),
                    (
                        "postgres_application_password",
                        TargetDeliveryValueKindV1.DERIVED_POSTGRESQL_URI,
                        "derived_postgresql_uri_v1",
                        None,
                        "DB_CONNECTION_URI",
                    ),
                    (
                        "primary_valkey_password",
                        TargetDeliveryValueKindV1.DERIVED_VALKEY_URI,
                        "derived_valkey_uri_v1",
                        None,
                        "REDIS_URL",
                    ),
                ),
            ),
            "restore_infisical": (
                ContainerSecretSinkV1.INFISICAL_TARGET_PROCESS_ENVIRONMENT,
                (
                    (
                        "encryption_key",
                        TargetDeliveryValueKindV1.DIRECT_PROVIDER_MATERIAL,
                        "infisical_hex_16_v1",
                        32,
                        "ENCRYPTION_KEY",
                    ),
                    (
                        "auth_secret",
                        TargetDeliveryValueKindV1.DIRECT_PROVIDER_MATERIAL,
                        "infisical_auth_secret_base64_32_v1",
                        44,
                        "AUTH_SECRET",
                    ),
                    (
                        "postgres_application_password",
                        TargetDeliveryValueKindV1.DERIVED_POSTGRESQL_URI,
                        "derived_postgresql_uri_v1",
                        None,
                        "DB_CONNECTION_URI",
                    ),
                    (
                        "restore_valkey_password",
                        TargetDeliveryValueKindV1.DERIVED_VALKEY_URI,
                        "derived_valkey_uri_v1",
                        None,
                        "REDIS_URL",
                    ),
                ),
            ),
            "primary_valkey": (
                ContainerSecretSinkV1.VALKEY_STDIN_CONFIGURATION,
                (
                    (
                        "primary_valkey_password",
                        TargetDeliveryValueKindV1.DIRECT_PROVIDER_MATERIAL,
                        "valkey_password_base64url_32_v1",
                        43,
                        "requirepass",
                    ),
                ),
            ),
            "restore_valkey": (
                ContainerSecretSinkV1.VALKEY_STDIN_CONFIGURATION,
                (
                    (
                        "restore_valkey_password",
                        TargetDeliveryValueKindV1.DIRECT_PROVIDER_MATERIAL,
                        "valkey_password_base64url_32_v1",
                        43,
                        "requirepass",
                    ),
                ),
            ),
        }
        expected_sink, expected_fields = expected[self.component]
        fields = self.fields
        derived_fields = tuple(
            field
            for field in fields
            if field.value_kind
            in (
                TargetDeliveryValueKindV1.DERIVED_POSTGRESQL_URI,
                TargetDeliveryValueKindV1.DERIVED_VALKEY_URI,
            )
        )
        expected_derived: dict[
            str,
            tuple[tuple[str, str, str], ...],
        ] = {
            "primary_infisical": (
                (
                    "postgres_application_password",
                    "derived_postgresql_uri_v1",
                    "DB_CONNECTION_URI",
                ),
                (
                    "primary_valkey_password",
                    "derived_valkey_uri_v1",
                    "REDIS_URL",
                ),
            ),
            "restore_infisical": (
                (
                    "postgres_application_password",
                    "derived_postgresql_uri_v1",
                    "DB_CONNECTION_URI",
                ),
                (
                    "restore_valkey_password",
                    "derived_valkey_uri_v1",
                    "REDIS_URL",
                ),
            ),
            "primary_valkey": (),
            "restore_valkey": (),
        }
        commitments = self.derived_uri_commitments
        valid = (
            self.component_role == _expected_role(self.component)
            and type(self.sink) is ContainerSecretSinkV1
            and self.sink is expected_sink
            and all(type(field) is TargetDeliveryFieldV1 for field in fields)
            and type(commitments) is tuple
            and all(
                type(commitment) is ContainerBootstrapDerivedUriCommitmentV3
                for commitment in commitments
            )
            and tuple(field.ordinal for field in fields) == tuple(range(1, len(fields) + 1))
            and len(fields) == len(expected_fields)
            and len({field.target_field for field in fields}) == len(fields)
            and len({field.source_purpose for field in fields}) == len(fields)
            and len({field.source_reference_sha256 for field in fields}) == len(fields)
            and len({field.source_fingerprint_sha256 for field in fields}) == len(fields)
            and all(
                field.source_purpose == purpose
                and field.value_kind is value_kind
                and field.format == field_format
                and (count is None or field.encoded_byte_count == count)
                and field.target_field == target_field
                and field.sink is self.sink
                and field.persistence_allowed is False
                and field.logging_allowed is False
                and field.receipt_allowed is False
                and (
                    field.value_kind is not TargetDeliveryValueKindV1.DIRECT_PROVIDER_MATERIAL
                    or field.derivation_binding_sha256 == field.source_fingerprint_sha256
                )
                for field, (purpose, value_kind, field_format, count, target_field) in zip(
                    fields, expected_fields, strict=True
                )
            )
            and tuple(
                (
                    commitment.source_purpose,
                    commitment.value_kind,
                    commitment.target_field,
                )
                for commitment in commitments
            )
            == expected_derived[self.component]
            and len(derived_fields) == len(commitments)
            and all(
                field.source_purpose == commitment.source_purpose
                and field.value_kind.value == commitment.value_kind
                and field.format == commitment.field_format
                and field.target_field == commitment.target_field
                and field.encoded_byte_count == commitment.encoded_byte_count
                and field.derivation_binding_sha256 == commitment.derivation_binding_sha256
                for field, commitment in zip(derived_fields, commitments, strict=True)
            )
        )
        if not valid:
            raise ValueError("container attach V3 descriptor is invalid")
        return self


def strict_canonical_container_bootstrap_target_delivery_descriptor_v3(
    descriptor: ContainerBootstrapTargetDeliveryDescriptorV3,
) -> ContainerBootstrapTargetDeliveryDescriptorV3:
    """Return the exact canonical target descriptor or a fixed public error."""

    try:
        return _strict_canonical_model(descriptor, ContainerBootstrapTargetDeliveryDescriptorV3)
    except (TypeError, ValueError):
        pass
    _fail("profile")


def container_bootstrap_target_delivery_descriptor_v3_canonical_json(
    descriptor: ContainerBootstrapTargetDeliveryDescriptorV3,
) -> bytes:
    """Return canonical descriptor JSON for cross-language target checks."""

    descriptor = strict_canonical_container_bootstrap_target_delivery_descriptor_v3(descriptor)
    try:
        return _canonical_model_bytes(descriptor)
    except ValueError:
        pass
    _fail("profile")


def parse_container_bootstrap_target_delivery_descriptor_v3_canonical_json(
    payload: bytes,
) -> ContainerBootstrapTargetDeliveryDescriptorV3:
    """Parse only the exact canonical V3 descriptor JSON spelling."""

    try:
        return _parse_canonical_json(payload, ContainerBootstrapTargetDeliveryDescriptorV3)
    except (TypeError, ValueError):
        pass
    _fail("profile")


def container_bootstrap_target_delivery_descriptor_v3_sha256(
    descriptor: ContainerBootstrapTargetDeliveryDescriptorV3,
) -> str:
    """Commit one complete target-side descriptor set under a V3 domain."""

    descriptor = strict_canonical_container_bootstrap_target_delivery_descriptor_v3(descriptor)
    try:
        return _hash(_DELIVERY_DESCRIPTOR_DOMAIN, descriptor)
    except ValueError:
        pass
    _fail("profile")


class ContainerBootstrapBaseLaunchCommitmentV3(_Model):
    """Value-free base-image/launch/patch commitments needed by one static role.

    These are commitments, not evidence that a base or derived image was
    resolved or inspected.  In particular, no derived-image or wrapper-output
    digest appears here; that cross-binding is intentionally deferred.
    """

    schema_version: Literal["rsd.container-bootstrap-base-launch-commitment.v3"]
    component: _ComponentV3
    component_role: Literal["infisical", "valkey"]
    base_image_policy_sha256: str = Field(pattern=_SHA256)
    base_resolution_attestation_sha256: str = Field(pattern=_SHA256)
    base_registry_index_digest_sha256: str = Field(pattern=_SHA256)
    base_linux_amd64_manifest_digest_sha256: str = Field(pattern=_SHA256)
    base_config_digest_sha256: str = Field(pattern=_SHA256)
    static_patch_policy_sha256: str = Field(pattern=_SHA256)
    wrapper_argv_prefix_sha256: str = Field(pattern=_SHA256)
    base_entrypoint_sha256: str = Field(pattern=_SHA256)
    base_command_sha256: str = Field(pattern=_SHA256)
    entrypoint_command_merge: Literal["exec_wrapper_then_base_entrypoint_and_cmd_v3"]
    merged_argv_sha256: str = Field(pattern=_SHA256)

    @model_validator(mode="after")
    def exact_output_independent_commitments(self) -> Self:
        values = (
            self.base_image_policy_sha256,
            self.base_resolution_attestation_sha256,
            self.base_registry_index_digest_sha256,
            self.base_linux_amd64_manifest_digest_sha256,
            self.base_config_digest_sha256,
            self.static_patch_policy_sha256,
            self.wrapper_argv_prefix_sha256,
            self.base_entrypoint_sha256,
            self.base_command_sha256,
            self.merged_argv_sha256,
        )
        if self.component_role != _expected_role(self.component) or len(set(values)) != len(values):
            raise ValueError("container bootstrap V3 base launch commitment is invalid")
        return self


class ContainerBootstrapStaticRoleProfileV3(_Model):
    """The output-independent, compile-time target profile for one fixed role.

    It intentionally contains no wrapper byte digest, artifact self-binding,
    signature, generated provenance/SBOM/reproducibility result, or derived
    image/output identity.  Its digest is therefore stable if hypothetical
    future wrapper bytes change, which removes the V2 fixed-point problem.
    """

    schema_version: Literal["rsd.container-bootstrap-static-role-profile.v3"]
    source_commit: str = Field(pattern=_COMMIT)
    component: _ComponentV3
    component_role: Literal["infisical", "valkey"]
    compile_target: Literal["x86_64-unknown-linux-musl"]
    ticket_trust_anchor: ContainerAttachTicketTrustAnchorV1
    attach_protocol: ContainerBootstrapAttachProtocolV3
    target_delivery_map_sha256: str = Field(pattern=_SHA256)
    target_delivery_descriptor: ContainerBootstrapTargetDeliveryDescriptorV3
    base_launch_commitment: ContainerBootstrapBaseLaunchCommitmentV3
    static_environment: ContainerBootstrapStaticEnvironmentV2
    child_environment_policy: ContainerBootstrapEnvironmentConstructionPolicyV2
    fd_policy: ContainerBootstrapFdPolicyV2
    pid1_policy: ContainerBootstrapPid1PolicyV2
    memory_safety_policy: ContainerBootstrapMemorySafetyPolicyV2
    valkey_launch_policy: ContainerBootstrapValkeyLaunchPolicyV2 | None = None

    @model_validator(mode="after")
    def exact_static_role_profile(self) -> Self:
        is_valkey = self.component.endswith("valkey")
        nested_exact = (
            type(self.ticket_trust_anchor) is ContainerAttachTicketTrustAnchorV1
            and type(self.attach_protocol) is ContainerBootstrapAttachProtocolV3
            and type(self.target_delivery_descriptor)
            is ContainerBootstrapTargetDeliveryDescriptorV3
            and type(self.base_launch_commitment) is ContainerBootstrapBaseLaunchCommitmentV3
            and type(self.static_environment) is ContainerBootstrapStaticEnvironmentV2
            and type(self.child_environment_policy)
            is ContainerBootstrapEnvironmentConstructionPolicyV2
            and type(self.fd_policy) is ContainerBootstrapFdPolicyV2
            and type(self.pid1_policy) is ContainerBootstrapPid1PolicyV2
            and type(self.memory_safety_policy) is ContainerBootstrapMemorySafetyPolicyV2
            and (
                type(self.valkey_launch_policy) is ContainerBootstrapValkeyLaunchPolicyV2
                if is_valkey
                else self.valkey_launch_policy is None
            )
        )
        valid = (
            nested_exact
            and self.component_role == _expected_role(self.component)
            and self.target_delivery_descriptor.component == self.component
            and self.target_delivery_descriptor.component_role == self.component_role
            and self.base_launch_commitment.component == self.component
            and self.base_launch_commitment.component_role == self.component_role
            and self.child_environment_policy.component == self.component
            and self.child_environment_policy.image_static_environment_sha256
            == self.static_environment.environment_sha256
            and self.attach_protocol.secret_persistence_allowed is False
            and self.attach_protocol.secret_logging_allowed is False
            and self.attach_protocol.secret_receipt_allowed is False
        )
        if not valid:
            raise ValueError("container bootstrap V3 static role profile is invalid")
        return self


def strict_canonical_container_bootstrap_static_role_profile_v3(
    profile: ContainerBootstrapStaticRoleProfileV3,
) -> ContainerBootstrapStaticRoleProfileV3:
    """Return an exact static profile or a redacted fixed error."""

    try:
        return _strict_canonical_model(profile, ContainerBootstrapStaticRoleProfileV3)
    except (TypeError, ValueError):
        pass
    _fail("profile")


def container_bootstrap_static_role_profile_v3_canonical_json(
    profile: ContainerBootstrapStaticRoleProfileV3,
) -> bytes:
    """Return the canonical, output-independent V3 profile JSON."""

    profile = strict_canonical_container_bootstrap_static_role_profile_v3(profile)
    try:
        return _canonical_model_bytes(profile)
    except ValueError:
        pass
    _fail("profile")


def parse_container_bootstrap_static_role_profile_v3_canonical_json(
    payload: bytes,
) -> ContainerBootstrapStaticRoleProfileV3:
    """Parse only the exact canonical, output-independent profile JSON spelling."""

    try:
        return _parse_canonical_json(payload, ContainerBootstrapStaticRoleProfileV3)
    except (TypeError, ValueError):
        pass
    _fail("profile")


def container_bootstrap_static_role_profile_v3_sha256(
    profile: ContainerBootstrapStaticRoleProfileV3,
) -> str:
    """Return a static digest independent of hypothetical wrapper output bytes."""

    profile = strict_canonical_container_bootstrap_static_role_profile_v3(profile)
    try:
        return _hash(_STATIC_PROFILE_DOMAIN, profile)
    except ValueError:
        pass
    _fail("profile")


class ContainerAttachRuntimeBindingV3(_Model):
    """Target-local nonsecret facts expected before any delivery frame is read."""

    schema_version: Literal["rsd.container-attach-runtime-binding.v3"]
    allocation_operation_id: str = Field(pattern=_UUID)
    operation_scope: _OperationScopeV3
    operation_id: str = Field(pattern=_UUID)
    component: _ComponentV3
    component_role: Literal["infisical", "valkey"]
    container_id: str = Field(pattern=_CONTAINER_ID)
    runtime_hostname: str = Field(pattern=_HOSTNAME)
    runtime_instance_binding_sha256: str = Field(pattern=_SHA256)
    request_nonce_sha256: str = Field(pattern=_SHA256)
    channel_binding_sha256: str = Field(pattern=_SHA256)
    session_binding_sha256: str = Field(pattern=_SHA256)

    @model_validator(mode="after")
    def exact_runtime_binding(self) -> Self:
        identities = (
            self.runtime_instance_binding_sha256,
            self.request_nonce_sha256,
            self.channel_binding_sha256,
            self.session_binding_sha256,
        )
        if (
            self.component_role != _expected_role(self.component)
            or self.runtime_instance_binding_sha256
            != container_attach_v3_runtime_instance_binding_sha256(
                container_id=self.container_id,
                runtime_hostname=self.runtime_hostname,
            )
            or len(set(identities)) != len(identities)
        ):
            raise ValueError("container attach V3 runtime binding is invalid")
        return self


def strict_canonical_container_attach_runtime_binding_v3(
    binding: ContainerAttachRuntimeBindingV3,
) -> ContainerAttachRuntimeBindingV3:
    """Return a canonical target-local runtime binding or a fixed error."""

    try:
        return _strict_canonical_model(binding, ContainerAttachRuntimeBindingV3)
    except (TypeError, ValueError):
        pass
    _fail("binding")


def container_attach_v3_runtime_binding_canonical_json(
    binding: ContainerAttachRuntimeBindingV3,
) -> bytes:
    """Render exact V3 runtime facts for a future target implementation."""

    binding = strict_canonical_container_attach_runtime_binding_v3(binding)
    try:
        return _canonical_model_bytes(binding)
    except ValueError:
        pass
    _fail("binding")


def parse_container_attach_v3_runtime_binding_canonical_json(
    payload: bytes,
) -> ContainerAttachRuntimeBindingV3:
    """Parse only the exact canonical V3 runtime-binding JSON spelling."""

    try:
        return _parse_canonical_json(payload, ContainerAttachRuntimeBindingV3)
    except (TypeError, ValueError):
        pass
    _fail("binding")


def container_attach_v3_runtime_instance_binding_preimage(
    *, container_id: str, runtime_hostname: str
) -> bytes:
    """Return the fixed public input to the V3 container-lifetime digest."""

    if (
        type(container_id) is not str
        or re.fullmatch(_CONTAINER_ID, container_id) is None
        or type(runtime_hostname) is not str
        or re.fullmatch(_HOSTNAME, runtime_hostname) is None
    ):
        raise ValueError("container attach V3 runtime binding is invalid")
    return (
        _RUNTIME_BINDING_DOMAIN
        + container_id.encode("ascii")
        + b"\x00"
        + runtime_hostname.encode("ascii")
    )


def container_attach_v3_runtime_instance_binding_sha256(
    *, container_id: str, runtime_hostname: str
) -> str:
    """Bind a full target container identity and runtime hostname under V3."""

    return hashlib.sha256(
        container_attach_v3_runtime_instance_binding_preimage(
            container_id=container_id,
            runtime_hostname=runtime_hostname,
        )
    ).hexdigest()


class ContainerAttachRequestV3(_Model):
    """Value-free V3 request metadata preceding a future secret frame stream."""

    schema_version: Literal["rsd.container-attach-request.v3"]
    allocation_operation_id: str = Field(pattern=_UUID)
    operation_scope: _OperationScopeV3
    operation_id: str = Field(pattern=_UUID)
    component: _ComponentV3
    component_role: Literal["infisical", "valkey"]
    container_id: str = Field(pattern=_CONTAINER_ID)
    runtime_hostname: str = Field(pattern=_HOSTNAME)
    runtime_instance_binding_sha256: str = Field(pattern=_SHA256)
    static_role_profile_sha256: str = Field(pattern=_SHA256)
    target_delivery_map_sha256: str = Field(pattern=_SHA256)
    target_delivery_descriptor_sha256: str = Field(pattern=_SHA256)
    attach_protocol_v3_sha256: str = Field(pattern=_SHA256)
    request_nonce_sha256: str = Field(pattern=_SHA256)
    channel_binding_sha256: str = Field(pattern=_SHA256)
    session_binding_sha256: str = Field(pattern=_SHA256)
    expected_ready_state: Literal["ready_v3"]
    expected_claim_state: Literal["claimed_v3"]
    expected_terminal_ack_state: Literal["terminal_ack_v3"]
    fields: tuple[TargetDeliveryFieldV1, ...] = Field(min_length=1, max_length=4)

    @field_validator("fields", mode="before")
    @classmethod
    def declared_fields(cls, value: object) -> tuple[object, ...]:
        return _items(value, field="container attach V3 request fields")

    @model_validator(mode="after")
    def exact_value_free_request(self) -> Self:
        identities = (
            self.runtime_instance_binding_sha256,
            self.static_role_profile_sha256,
            self.target_delivery_map_sha256,
            self.target_delivery_descriptor_sha256,
            self.attach_protocol_v3_sha256,
            self.request_nonce_sha256,
            self.channel_binding_sha256,
            self.session_binding_sha256,
        )
        if (
            self.component_role != _expected_role(self.component)
            or self.runtime_instance_binding_sha256
            != container_attach_v3_runtime_instance_binding_sha256(
                container_id=self.container_id,
                runtime_hostname=self.runtime_hostname,
            )
            or any(type(field) is not TargetDeliveryFieldV1 for field in self.fields)
            or tuple(field.ordinal for field in self.fields)
            != tuple(range(1, len(self.fields) + 1))
            or len(set(identities)) != len(identities)
        ):
            raise ValueError("container attach V3 request is invalid")
        return self


def strict_canonical_container_attach_request_v3(
    request: ContainerAttachRequestV3,
) -> ContainerAttachRequestV3:
    """Return an exact V3 request or a fixed ticket error."""

    try:
        return _strict_canonical_model(request, ContainerAttachRequestV3)
    except (TypeError, ValueError):
        pass
    _fail("ticket")


def container_attach_v3_request_canonical_json(request: ContainerAttachRequestV3) -> bytes:
    """Render canonical V3 request JSON for cross-language target checks."""

    request = strict_canonical_container_attach_request_v3(request)
    try:
        return _canonical_model_bytes(request)
    except ValueError:
        pass
    _fail("ticket")


def parse_container_attach_v3_request_canonical_json(payload: bytes) -> ContainerAttachRequestV3:
    """Parse only the exact canonical V3 request JSON spelling."""

    try:
        return _parse_canonical_json(payload, ContainerAttachRequestV3)
    except (TypeError, ValueError):
        pass
    _fail("ticket")


def container_attach_v3_request_sha256(request: ContainerAttachRequestV3) -> str:
    """Return the independent V3 request commitment signed by a ticket."""

    request = strict_canonical_container_attach_request_v3(request)
    try:
        return _hash(_ATTACH_REQUEST_DOMAIN, request)
    except ValueError:
        pass
    _fail("ticket")


class ContainerAttachAuthorizationTicketV3(_Model):
    """Signed V3 dynamic authority verified with the profile-owned public key."""

    schema_version: Literal["rsd.container-attach-authorization-ticket.v3"]
    protocol_sha256: str = Field(pattern=_SHA256)
    request_sha256: str = Field(pattern=_SHA256)
    allocation_operation_id: str = Field(pattern=_UUID)
    operation_scope: _OperationScopeV3
    operation_id: str = Field(pattern=_UUID)
    component: _ComponentV3
    component_role: Literal["infisical", "valkey"]
    container_id: str = Field(pattern=_CONTAINER_ID)
    runtime_hostname: str = Field(pattern=_HOSTNAME)
    runtime_instance_binding_sha256: str = Field(pattern=_SHA256)
    static_role_profile_sha256: str = Field(pattern=_SHA256)
    target_delivery_map_sha256: str = Field(pattern=_SHA256)
    target_delivery_descriptor_sha256: str = Field(pattern=_SHA256)
    request_nonce_sha256: str = Field(pattern=_SHA256)
    channel_binding_sha256: str = Field(pattern=_SHA256)
    session_binding_sha256: str = Field(pattern=_SHA256)
    issued_at: str
    expires_at: str
    signer_key_id: str = Field(pattern=r"^[a-z][a-z0-9-]{2,63}$")
    signature_base64: str = Field(min_length=4, max_length=256)

    @field_validator("issued_at", "expires_at")
    @classmethod
    def canonical_time(cls, value: str) -> str:
        _canonical_timestamp(value)
        return value

    @model_validator(mode="after")
    def exact_dynamic_authority(self) -> Self:
        identities = (
            self.protocol_sha256,
            self.request_sha256,
            self.runtime_instance_binding_sha256,
            self.static_role_profile_sha256,
            self.target_delivery_map_sha256,
            self.target_delivery_descriptor_sha256,
            self.request_nonce_sha256,
            self.channel_binding_sha256,
            self.session_binding_sha256,
        )
        lifetime = _canonical_timestamp(self.expires_at) - _canonical_timestamp(self.issued_at)
        signature = _canonical_base64_bytes(self.signature_base64)
        if (
            self.component_role != _expected_role(self.component)
            or self.runtime_instance_binding_sha256
            != container_attach_v3_runtime_instance_binding_sha256(
                container_id=self.container_id,
                runtime_hostname=self.runtime_hostname,
            )
            or len(set(identities)) != len(identities)
            or lifetime <= timedelta(0)
            or lifetime > timedelta(seconds=300)
            or len(signature) != 64
        ):
            raise ValueError("container attach V3 ticket is invalid")
        return self


def strict_canonical_container_attach_authorization_ticket_v3(
    ticket: ContainerAttachAuthorizationTicketV3,
) -> ContainerAttachAuthorizationTicketV3:
    """Return an exact signed-ticket model or a fixed public error."""

    try:
        return _strict_canonical_model(ticket, ContainerAttachAuthorizationTicketV3)
    except (TypeError, ValueError):
        pass
    _fail("ticket")


def container_attach_v3_ticket_canonical_message(
    ticket: ContainerAttachAuthorizationTicketV3,
) -> bytes:
    """Return the exact Ed25519 V3 ticket preimage without its signature field."""

    ticket = strict_canonical_container_attach_authorization_ticket_v3(ticket)
    try:
        return _ATTACH_TICKET_DOMAIN + _canonical_model_bytes(ticket, exclude={"signature_base64"})
    except ValueError:
        pass
    _fail("ticket")


def parse_container_attach_v3_ticket_canonical_json(
    payload: bytes,
) -> ContainerAttachAuthorizationTicketV3:
    """Parse only the exact canonical V3 ticket JSON spelling."""

    try:
        return _parse_canonical_json(payload, ContainerAttachAuthorizationTicketV3)
    except (TypeError, ValueError):
        pass
    _fail("ticket")


def container_attach_v3_ticket_sha256(ticket: ContainerAttachAuthorizationTicketV3) -> str:
    """Return a receipt-safe V3 commitment to a signed ticket."""

    ticket = strict_canonical_container_attach_authorization_ticket_v3(ticket)
    try:
        return _hash(_ATTACH_TICKET_HASH_DOMAIN, ticket)
    except ValueError:
        pass
    _fail("ticket")


class ContainerAttachTicketEnvelopeV3(_Model):
    """The first V3 metadata frame: one request plus its signed ticket."""

    schema_version: Literal["rsd.container-attach-ticket-envelope.v3"]
    request: ContainerAttachRequestV3
    ticket: ContainerAttachAuthorizationTicketV3

    @model_validator(mode="after")
    def exact_request_ticket_binding(self) -> Self:
        request = self.request
        ticket = self.ticket
        exact = (
            type(request) is ContainerAttachRequestV3
            and type(ticket) is ContainerAttachAuthorizationTicketV3
            and ticket.request_sha256 == container_attach_v3_request_sha256(request)
            and ticket.protocol_sha256 == request.attach_protocol_v3_sha256
            and ticket.allocation_operation_id == request.allocation_operation_id
            and ticket.operation_scope == request.operation_scope
            and ticket.operation_id == request.operation_id
            and ticket.component == request.component
            and ticket.component_role == request.component_role
            and ticket.container_id == request.container_id
            and ticket.runtime_hostname == request.runtime_hostname
            and ticket.runtime_instance_binding_sha256 == request.runtime_instance_binding_sha256
            and ticket.static_role_profile_sha256 == request.static_role_profile_sha256
            and ticket.target_delivery_map_sha256 == request.target_delivery_map_sha256
            and ticket.target_delivery_descriptor_sha256
            == request.target_delivery_descriptor_sha256
            and ticket.request_nonce_sha256 == request.request_nonce_sha256
            and ticket.channel_binding_sha256 == request.channel_binding_sha256
            and ticket.session_binding_sha256 == request.session_binding_sha256
        )
        if not exact:
            raise ValueError("container attach V3 ticket envelope is invalid")
        return self


def strict_canonical_container_attach_ticket_envelope_v3(
    envelope: ContainerAttachTicketEnvelopeV3,
) -> ContainerAttachTicketEnvelopeV3:
    """Return one canonical V3 envelope or a fixed public error."""

    try:
        return _strict_canonical_model(envelope, ContainerAttachTicketEnvelopeV3)
    except (TypeError, ValueError):
        pass
    _fail("ticket")


class ContainerAttachV3TicketValidation(_Model):
    """A value-free validation result that is not delivery authorization.

    This records only what the pure canonical/signature/freshness phase
    validated.  It must never be accepted as a bearer grant: the final target
    boundary calls :func:`claim_container_attach_v3_ticket` with raw inputs so
    it revalidates them and atomically consumes the exact replay claim.
    """

    schema_version: Literal["rsd.container-attach-ticket-validation.v3"]
    component: _ComponentV3
    component_role: Literal["infisical", "valkey"]
    static_role_profile_sha256: str = Field(pattern=_SHA256)
    attach_protocol_v3_sha256: str = Field(pattern=_SHA256)
    target_delivery_descriptor_sha256: str = Field(pattern=_SHA256)
    request_sha256: str = Field(pattern=_SHA256)
    ticket_sha256: str = Field(pattern=_SHA256)
    request_nonce_sha256: str = Field(pattern=_SHA256)
    channel_binding_sha256: str = Field(pattern=_SHA256)
    session_binding_sha256: str = Field(pattern=_SHA256)
    allocation_operation_id: str = Field(pattern=_UUID)
    operation_scope: _OperationScopeV3
    operation_id: str = Field(pattern=_UUID)
    container_id: str = Field(pattern=_CONTAINER_ID)
    runtime_hostname: str = Field(pattern=_HOSTNAME)
    runtime_instance_binding_sha256: str = Field(pattern=_SHA256)
    freshness_checked_at: str
    issued_at: str
    expires_at: str
    claim_timeout_seconds: int = Field(ge=1, le=60)
    max_ticket_lifetime_seconds: int = Field(ge=1, le=300)


class ContainerAttachV3TicketReplayClaimV3(_Model):
    """The exact nonsecret identity of one signed dynamic ticket instance."""

    schema_version: Literal["rsd.container-attach-ticket-replay-claim.v3"]
    static_role_profile_sha256: str = Field(pattern=_SHA256)
    request_sha256: str = Field(pattern=_SHA256)
    ticket_sha256: str = Field(pattern=_SHA256)
    allocation_operation_id: str = Field(pattern=_UUID)
    operation_scope: _OperationScopeV3
    operation_id: str = Field(pattern=_UUID)
    component: _ComponentV3
    component_role: Literal["infisical", "valkey"]
    container_id: str = Field(pattern=_CONTAINER_ID)
    runtime_hostname: str = Field(pattern=_HOSTNAME)
    runtime_instance_binding_sha256: str = Field(pattern=_SHA256)
    request_nonce_sha256: str = Field(pattern=_SHA256)
    channel_binding_sha256: str = Field(pattern=_SHA256)
    session_binding_sha256: str = Field(pattern=_SHA256)

    @model_validator(mode="after")
    def exact_ticket_claim_identity(self) -> Self:
        identities = (
            self.static_role_profile_sha256,
            self.request_sha256,
            self.ticket_sha256,
            self.request_nonce_sha256,
            self.channel_binding_sha256,
            self.session_binding_sha256,
        )
        if (
            self.component
            not in {
                "primary_infisical",
                "primary_valkey",
                "restore_infisical",
                "restore_valkey",
            }
            or self.component_role != _expected_role(self.component)
            or len(set(identities)) != len(identities)
        ):
            raise ValueError("container attach V3 ticket replay claim is invalid")
        if (
            self.runtime_instance_binding_sha256
            != container_attach_v3_runtime_instance_binding_sha256(
                container_id=self.container_id,
                runtime_hostname=self.runtime_hostname,
            )
        ):
            raise ValueError("container attach V3 ticket replay claim is invalid")
        return self


class ContainerAttachV3ContainerLifetimeClaimV3(_Model):
    """Stable one-attach identity for the actual target container lifetime.

    The immutable Docker container ID is the sole uniqueness identity. This
    deliberately excludes ticket bytes/signature/timestamps, static profile,
    role/component, hostname/runtime facts, and every fresh nonce, channel,
    and session binding. A reissued ticket/profile or substituted metadata
    cannot make the same container attachable again.
    """

    schema_version: Literal["rsd.container-attach-container-lifetime-claim.v3"]
    container_id: str = Field(pattern=_CONTAINER_ID)
    one_attach_per_container_lifetime: Literal[True]


class ContainerAttachV3ReplayClaimV3(_Model):
    """One atomic request containing both required V3 replay identities."""

    schema_version: Literal["rsd.container-attach-replay-claim.v3"]
    ticket_claim: ContainerAttachV3TicketReplayClaimV3
    container_lifetime_claim: ContainerAttachV3ContainerLifetimeClaimV3

    @model_validator(mode="after")
    def exact_atomic_claim_binding(self) -> Self:
        ticket_claim = self.ticket_claim
        lifetime_claim = self.container_lifetime_claim
        if (
            type(ticket_claim) is not ContainerAttachV3TicketReplayClaimV3
            or type(lifetime_claim) is not ContainerAttachV3ContainerLifetimeClaimV3
            or ticket_claim.container_id != lifetime_claim.container_id
        ):
            raise ValueError("container attach V3 replay claim is invalid")
        return self


class _ContainerAttachV3MonotonicDeadlineGuard:
    """Track a nondecreasing internal clock for one authority invocation."""

    __slots__ = ("__failed", "__lock", "_last_observed")

    def __init__(self, started_at: float) -> None:
        if not _valid_monotonic(started_at):
            raise ValueError("container attach V3 monotonic guard is invalid")
        self.__failed = False
        self.__lock = Lock()
        self._last_observed = started_at

    def now(self) -> float:
        """Return trusted time only if it never moved backward for this claim."""

        failed = False
        now = 0.0
        try:
            now = _read_trusted_monotonic_now()
        except Exception:
            failed = True
        with self.__lock:
            if failed or self.__failed or now < self._last_observed:
                self.__failed = True
                failed = True
            else:
                self._last_observed = now
        if failed:
            _fail("freshness")
        return now


@dataclass(frozen=True, slots=True)
class ContainerAttachV3ClaimDeadlineV3:
    """Frozen value-only deadline advice supplied to a replay authority.

    This record deliberately contains no callable, clock, guard, interval, or
    other live verifier capability.  An authority may enforce its numeric
    budget in its own implementation, but the verifier never reads this record
    after the authority returns.  It makes all post-return UTC and monotonic
    decisions from its local interval.
    """

    schema_version: Literal["rsd.container-attach-claim-deadline.v3"]
    ticket_sha256: str
    freshness_checked_at: str
    ticket_expires_at: str
    effective_deadline_at: str
    claim_timeout_seconds: int
    monotonic_started_at: float
    monotonic_deadline_at: float
    monotonic_budget_seconds: int

    def __post_init__(self) -> None:
        if (
            self.schema_version != "rsd.container-attach-claim-deadline.v3"
            or type(self.ticket_sha256) is not str
            or re.fullmatch(_SHA256, self.ticket_sha256) is None
            or type(self.claim_timeout_seconds) is not int
            or not 1 <= self.claim_timeout_seconds <= 60
            or type(self.monotonic_budget_seconds) is not int
            or self.monotonic_budget_seconds < 1
            or not _valid_monotonic(self.monotonic_started_at)
            or not _valid_monotonic(self.monotonic_deadline_at)
        ):
            raise ValueError("container attach V3 claim deadline is invalid")
        checked_at = _canonical_timestamp(self.freshness_checked_at)
        expires = _canonical_timestamp(self.ticket_expires_at)
        deadline = _canonical_timestamp(self.effective_deadline_at)
        expected = min(
            expires,
            checked_at + timedelta(seconds=self.claim_timeout_seconds),
        )
        if (
            checked_at >= expires
            or deadline != expected
            or self.monotonic_deadline_at
            != self.monotonic_started_at + float(self.monotonic_budget_seconds)
            or self.monotonic_deadline_at <= self.monotonic_started_at
        ):
            raise ValueError("container attach V3 claim deadline is invalid")


class _ContainerAttachV3ClaimInterval:
    """Verifier-owned monotonic interval, never supplied to an authority."""

    __slots__ = (
        "__claim_started_at",
        "__claim_timeout_seconds",
        "__deadline_at",
        "__deadline_monotonic",
        "__guard",
        "__monotonic_budget_seconds",
        "__monotonic_started",
        "__ticket_expires_at",
        "__ticket_sha256",
    )

    def __init__(
        self,
        *,
        ticket_sha256: str,
        claim_started_at: datetime,
        ticket_expires_at: datetime,
        claim_timeout_seconds: int,
        monotonic_started: float,
    ) -> None:
        if (
            type(ticket_sha256) is not str
            or re.fullmatch(_SHA256, ticket_sha256) is None
            or type(claim_timeout_seconds) is not int
            or not 1 <= claim_timeout_seconds <= 60
            or not _valid_monotonic(monotonic_started)
            or type(claim_started_at) is not datetime
            or type(ticket_expires_at) is not datetime
        ):
            raise ValueError("container attach V3 claim interval is invalid")
        deadline_at = min(
            ticket_expires_at,
            claim_started_at + timedelta(seconds=claim_timeout_seconds),
        )
        deadline_seconds = int((deadline_at - claim_started_at).total_seconds())
        deadline_monotonic = monotonic_started + float(deadline_seconds)
        if (
            claim_started_at >= ticket_expires_at
            or deadline_seconds <= 0
            or not _valid_monotonic(deadline_monotonic)
            or deadline_monotonic <= monotonic_started
        ):
            raise ValueError("container attach V3 claim interval is invalid")
        self.__ticket_sha256 = ticket_sha256
        self.__claim_started_at = claim_started_at
        self.__ticket_expires_at = ticket_expires_at
        self.__claim_timeout_seconds = claim_timeout_seconds
        self.__deadline_at = deadline_at
        self.__deadline_monotonic = deadline_monotonic
        self.__monotonic_budget_seconds = deadline_seconds
        self.__monotonic_started = monotonic_started
        self.__guard = _ContainerAttachV3MonotonicDeadlineGuard(monotonic_started)

    @property
    def deadline_at(self) -> datetime:
        """Return the verifier-owned wall-clock cap for a post-return check."""

        return self.__deadline_at

    def authority_deadline(self) -> ContainerAttachV3ClaimDeadlineV3:
        """Issue an advisory view with no direct reference to verifier state."""

        return ContainerAttachV3ClaimDeadlineV3(
            schema_version="rsd.container-attach-claim-deadline.v3",
            ticket_sha256=self.__ticket_sha256,
            freshness_checked_at=_canonical_timestamp_text(self.__claim_started_at),
            ticket_expires_at=_canonical_timestamp_text(self.__ticket_expires_at),
            claim_timeout_seconds=self.__claim_timeout_seconds,
            effective_deadline_at=_canonical_timestamp_text(self.__deadline_at),
            monotonic_started_at=self.__monotonic_started,
            monotonic_deadline_at=self.__deadline_monotonic,
            monotonic_budget_seconds=self.__monotonic_budget_seconds,
        )

    def _remaining_seconds(self) -> float:
        """Read one nondecreasing observation against the local absolute cap."""

        remaining = self.__deadline_monotonic - self.__guard.now()
        if not _valid_monotonic(remaining) or remaining <= 0.0:
            _fail("freshness")
        return remaining

    def require_after_authority(self) -> None:
        """Fail if the local monotonic interval elapsed or regressed."""

        self._remaining_seconds()


def strict_canonical_container_attach_v3_ticket_replay_claim(
    claim: ContainerAttachV3TicketReplayClaimV3,
) -> ContainerAttachV3TicketReplayClaimV3:
    """Return one exact ticket-instance claim or a fixed replay error."""

    try:
        return _strict_canonical_model(claim, ContainerAttachV3TicketReplayClaimV3)
    except (TypeError, ValueError):
        pass
    _fail("replay")


def container_attach_v3_ticket_replay_claim_sha256(
    claim: ContainerAttachV3TicketReplayClaimV3,
) -> str:
    """Hash one ticket-instance replay claim under its dedicated V3 domain."""

    try:
        canonical = strict_canonical_container_attach_v3_ticket_replay_claim(claim)
        return _hash(_TICKET_REPLAY_CLAIM_DOMAIN, canonical)
    except ContainerAttachStaticV3Error:
        pass
    _fail("replay")


def strict_canonical_container_attach_v3_container_lifetime_claim(
    claim: ContainerAttachV3ContainerLifetimeClaimV3,
) -> ContainerAttachV3ContainerLifetimeClaimV3:
    """Return one exact container-lifetime claim or a fixed replay error."""

    try:
        return _strict_canonical_model(claim, ContainerAttachV3ContainerLifetimeClaimV3)
    except (TypeError, ValueError):
        pass
    _fail("replay")


def container_attach_v3_container_lifetime_claim_sha256(
    claim: ContainerAttachV3ContainerLifetimeClaimV3,
) -> str:
    """Hash one stable container-lifetime identity under a dedicated V3 domain."""

    try:
        canonical = strict_canonical_container_attach_v3_container_lifetime_claim(claim)
        return _hash(_CONTAINER_LIFETIME_CLAIM_DOMAIN, canonical)
    except ContainerAttachStaticV3Error:
        pass
    _fail("replay")


def strict_canonical_container_attach_v3_replay_claim(
    claim: ContainerAttachV3ReplayClaimV3,
) -> ContainerAttachV3ReplayClaimV3:
    """Return one exact atomic replay request or a fixed replay error."""

    try:
        return _strict_canonical_model(claim, ContainerAttachV3ReplayClaimV3)
    except (TypeError, ValueError):
        pass
    _fail("replay")


def container_attach_v3_replay_claim_canonical_json(claim: ContainerAttachV3ReplayClaimV3) -> bytes:
    """Render both atomic replay identities for future target implementations."""

    claim = strict_canonical_container_attach_v3_replay_claim(claim)
    try:
        return _canonical_model_bytes(claim)
    except ValueError:
        pass
    _fail("replay")


def parse_container_attach_v3_replay_claim_canonical_json(
    payload: bytes,
) -> ContainerAttachV3ReplayClaimV3:
    """Parse only the exact canonical target replay-key JSON spelling."""

    try:
        return _parse_canonical_json(payload, ContainerAttachV3ReplayClaimV3)
    except (TypeError, ValueError):
        pass
    _fail("replay")


def container_attach_v3_replay_claim_sha256(claim: ContainerAttachV3ReplayClaimV3) -> str:
    """Commit the complete exact-once key under a dedicated V3 domain."""

    try:
        canonical = strict_canonical_container_attach_v3_replay_claim(claim)
        return _hash(_REPLAY_CLAIM_DOMAIN, canonical)
    except ContainerAttachStaticV3Error:
        pass
    _fail("replay")


class ContainerAttachV3ReplayClaimReceiptV3(_Model):
    """Value-free proof that one authority atomically claimed both identities."""

    schema_version: Literal["rsd.container-attach-replay-claim-receipt.v3"]
    replay_claim_sha256: str = Field(pattern=_SHA256)
    ticket_replay_claim_sha256: str = Field(pattern=_SHA256)
    container_lifetime_claim_sha256: str = Field(pattern=_SHA256)
    state: Literal["claimed_v3"]

    @model_validator(mode="after")
    def exact_atomic_receipt(self) -> Self:
        if (
            len(
                {
                    self.replay_claim_sha256,
                    self.ticket_replay_claim_sha256,
                    self.container_lifetime_claim_sha256,
                }
            )
            != 3
        ):
            raise ValueError("container attach V3 replay claim receipt is invalid")
        return self


class ContainerAttachV3ReplayAuthority(Protocol):
    """Sealed authority that atomically consumes ticket and container keys.

    This contract deliberately provides no default, in-memory, or permissive
    production implementation.  A future wrapper/runtime must provide a
    durable target-local implementation before it can accept frames.  The one
    call must make both nested identities unique or return no usable receipt;
    it must not expose a partial success.  It is scoped to one immutable
    Docker target, so the container-lifetime key is the immutable container ID
    alone; a multi-target authority must add its own trusted target namespace,
    never ticket/profile/request metadata.  ``deadline`` is frozen numeric
    advice only; an authority may enforce it with its own runtime, but receives
    no verifier clock or live timing capability.  Test doubles may implement
    this protocol only in tests.
    """

    def claim_once(
        self,
        *,
        claim: ContainerAttachV3ReplayClaimV3,
        deadline: ContainerAttachV3ClaimDeadlineV3,
    ) -> ContainerAttachV3ReplayClaimReceiptV3:
        """Atomically claim both keys under the supplied value-only deadline."""


class ContainerAttachV3ClaimedTicketV3(_Model):
    """Final value-free result after fresh validation and one-shot consumption."""

    schema_version: Literal["rsd.container-attach-claimed-ticket.v3"]
    component: _ComponentV3
    static_role_profile_sha256: str = Field(pattern=_SHA256)
    attach_protocol_v3_sha256: str = Field(pattern=_SHA256)
    target_delivery_descriptor_sha256: str = Field(pattern=_SHA256)
    request_sha256: str = Field(pattern=_SHA256)
    ticket_sha256: str = Field(pattern=_SHA256)
    request_nonce_sha256: str = Field(pattern=_SHA256)
    replay_claim_sha256: str = Field(pattern=_SHA256)
    ticket_replay_claim_sha256: str = Field(pattern=_SHA256)
    container_lifetime_claim_sha256: str = Field(pattern=_SHA256)


def _assert_exact_tuple(value: object, expected_element: type[object]) -> None:
    """Reject sequence coercion and every nested model subclass at this boundary."""

    if type(value) is not tuple or any(type(item) is not expected_element for item in value):
        raise ValueError("canonical model is invalid")


def _assert_exact_target_delivery_field(field: TargetDeliveryFieldV1) -> None:
    """Require concrete V1 field and enum values before canonical revalidation."""

    if (
        type(field) is not TargetDeliveryFieldV1
        or type(field.value_kind) is not TargetDeliveryValueKindV1
        or type(field.sink) is not ContainerSecretSinkV1
    ):
        raise ValueError("canonical model is invalid")


def _assert_exact_external_policy_tree(value: object) -> None:
    """Check every imported V2 nested model/tuple before it can be normalized."""

    if type(value) is ContainerAttachTicketTrustAnchorV1:
        return
    if type(value) is ContainerBootstrapStaticEnvironmentEntryV2:
        return
    if type(value) is ContainerBootstrapStaticEnvironmentV2:
        _assert_exact_tuple(value.entries, ContainerBootstrapStaticEnvironmentEntryV2)
        for entry in value.entries:
            _assert_exact_external_policy_tree(entry)
        return
    if type(value) is ContainerBootstrapEnvironmentConstructionPolicyV2:
        _assert_exact_tuple(value.static_entries, ContainerBootstrapStaticEnvironmentEntryV2)
        if type(value.dynamic_target_field_names) is not tuple or any(
            type(item) is not str for item in value.dynamic_target_field_names
        ):
            raise ValueError("canonical model is invalid")
        for entry in value.static_entries:
            _assert_exact_external_policy_tree(entry)
        return
    if type(value) is ContainerBootstrapFdPolicyV2:
        return
    if type(value) is ContainerBootstrapPid1PolicyV2:
        if type(value.signal_order) is not tuple or any(
            type(item) is not str for item in value.signal_order
        ):
            raise ValueError("canonical model is invalid")
        return
    if type(value) is ContainerBootstrapMemorySafetyPolicyV2:
        return
    if type(value) is ContainerBootstrapValkeyLaunchPolicyV2:
        sequences = (
            value.command,
            value.acl_denied_command_categories,
            value.static_directive_order,
        )
        if any(
            type(sequence) is not tuple or any(type(item) is not str for item in sequence)
            for sequence in sequences
        ):
            raise ValueError("canonical model is invalid")
        return
    raise ValueError("canonical model is invalid")


def _assert_exact_concrete_tree(value: object, expected: type[_Model]) -> None:
    """Reject model-construct, tuple, enum, and subclass drift recursively.

    Pydantic revalidation is intentionally still performed afterwards, but it
    may normalize a constructed nested subclass.  This preflight therefore
    inspects the original object graph first.
    """

    if type(value) is not expected:
        raise ValueError("canonical model is invalid")
    if type(value) is ContainerBootstrapAttachProtocolV3:
        if type(value.allowed_operation_scopes) is not tuple or any(
            type(scope) is not str for scope in value.allowed_operation_scopes
        ):
            raise ValueError("canonical model is invalid")
        return
    if type(value) is ContainerBootstrapDerivedUriCommitmentV3:
        return
    if type(value) is ContainerBootstrapTargetDeliveryDescriptorV3:
        _assert_exact_tuple(value.fields, TargetDeliveryFieldV1)
        _assert_exact_tuple(value.derived_uri_commitments, ContainerBootstrapDerivedUriCommitmentV3)
        for field in value.fields:
            _assert_exact_target_delivery_field(field)
        for commitment in value.derived_uri_commitments:
            _assert_exact_concrete_tree(commitment, ContainerBootstrapDerivedUriCommitmentV3)
        return
    if type(value) is ContainerBootstrapBaseLaunchCommitmentV3:
        return
    if type(value) is ContainerBootstrapStaticRoleProfileV3:
        _assert_exact_external_policy_tree(value.ticket_trust_anchor)
        _assert_exact_concrete_tree(value.attach_protocol, ContainerBootstrapAttachProtocolV3)
        _assert_exact_concrete_tree(
            value.target_delivery_descriptor, ContainerBootstrapTargetDeliveryDescriptorV3
        )
        _assert_exact_concrete_tree(
            value.base_launch_commitment, ContainerBootstrapBaseLaunchCommitmentV3
        )
        _assert_exact_external_policy_tree(value.static_environment)
        _assert_exact_external_policy_tree(value.child_environment_policy)
        _assert_exact_external_policy_tree(value.fd_policy)
        _assert_exact_external_policy_tree(value.pid1_policy)
        _assert_exact_external_policy_tree(value.memory_safety_policy)
        if value.valkey_launch_policy is not None:
            _assert_exact_external_policy_tree(value.valkey_launch_policy)
        return
    if type(value) is ContainerAttachRuntimeBindingV3:
        return
    if type(value) is ContainerAttachRequestV3:
        _assert_exact_tuple(value.fields, TargetDeliveryFieldV1)
        for field in value.fields:
            _assert_exact_target_delivery_field(field)
        return
    if type(value) is ContainerAttachAuthorizationTicketV3:
        return
    if type(value) is ContainerAttachTicketEnvelopeV3:
        _assert_exact_concrete_tree(value.request, ContainerAttachRequestV3)
        _assert_exact_concrete_tree(value.ticket, ContainerAttachAuthorizationTicketV3)
        return
    if type(value) is ContainerAttachV3TicketValidation:
        return
    if type(value) is ContainerAttachV3TicketReplayClaimV3:
        return
    if type(value) is ContainerAttachV3ContainerLifetimeClaimV3:
        return
    if type(value) is ContainerAttachV3ReplayClaimV3:
        _assert_exact_concrete_tree(value.ticket_claim, ContainerAttachV3TicketReplayClaimV3)
        _assert_exact_concrete_tree(
            value.container_lifetime_claim,
            ContainerAttachV3ContainerLifetimeClaimV3,
        )
        return
    if type(value) is ContainerAttachV3ReplayClaimReceiptV3:
        return
    if type(value) is ContainerAttachV3ClaimedTicketV3:
        return
    raise ValueError("canonical model is invalid")


def _runtime_binding_matches_request(
    binding: ContainerAttachRuntimeBindingV3,
    request: ContainerAttachRequestV3,
) -> bool:
    """Compare only target-local facts before any future chunk is accepted."""

    return (
        binding.allocation_operation_id == request.allocation_operation_id
        and binding.operation_scope == request.operation_scope
        and binding.operation_id == request.operation_id
        and binding.component == request.component
        and binding.component_role == request.component_role
        and binding.container_id == request.container_id
        and binding.runtime_hostname == request.runtime_hostname
        and binding.runtime_instance_binding_sha256 == request.runtime_instance_binding_sha256
        and binding.request_nonce_sha256 == request.request_nonce_sha256
        and binding.channel_binding_sha256 == request.channel_binding_sha256
        and binding.session_binding_sha256 == request.session_binding_sha256
    )


def _require_ticket_fresh(
    *,
    issued_at: str,
    expires_at: str,
    max_ticket_lifetime_seconds: int,
) -> tuple[datetime, datetime, datetime]:
    """Check a ticket against the internal trusted clock at its use boundary."""

    issued = _canonical_timestamp(issued_at)
    expires = _canonical_timestamp(expires_at)
    now = _trusted_now()
    if (
        now < issued
        or now >= expires
        or expires - issued > timedelta(seconds=max_ticket_lifetime_seconds)
    ):
        _fail("freshness")
    return now, issued, expires


def validate_container_attach_v3_ticket(
    *,
    static_role_profile: ContainerBootstrapStaticRoleProfileV3,
    envelope: ContainerAttachTicketEnvelopeV3,
    expected_runtime: ContainerAttachRuntimeBindingV3,
) -> ContainerAttachV3TicketValidation:
    """Purely validate a V3 ticket before any frame can be consumed.

    The only Ed25519 public key used here is the key embedded in the compiled
    static profile.  ``expected_runtime`` represents facts supplied by the
    future target boundary, not data accepted from a ticket.  This phase is
    intentionally not authorization and returns no delivery capability.  A
    target must call :func:`claim_container_attach_v3_ticket` before it can
    consider a ticket usable; that function revalidates raw inputs and
    consumes a required one-shot replay key.
    """

    profile: ContainerBootstrapStaticRoleProfileV3 | None = None
    canonical_envelope: ContainerAttachTicketEnvelopeV3 | None = None
    runtime: ContainerAttachRuntimeBindingV3 | None = None
    try:
        profile = _strict_canonical_model(
            static_role_profile, ContainerBootstrapStaticRoleProfileV3
        )
        canonical_envelope = _strict_canonical_model(envelope, ContainerAttachTicketEnvelopeV3)
        runtime = _strict_canonical_model(expected_runtime, ContainerAttachRuntimeBindingV3)
    except (TypeError, ValueError):
        pass
    if profile is None or canonical_envelope is None or runtime is None:
        _fail("binding")

    request = canonical_envelope.request
    ticket = canonical_envelope.ticket
    protocol = profile.attach_protocol
    descriptor = profile.target_delivery_descriptor
    commitments: tuple[str, str, str, str, str] | None = None
    try:
        profile_sha256 = _hash(_STATIC_PROFILE_DOMAIN, profile)
        protocol_sha256 = _hash(_ATTACH_PROTOCOL_DOMAIN, protocol)
        descriptor_sha256 = _hash(_DELIVERY_DESCRIPTOR_DOMAIN, descriptor)
        request_sha256 = _hash(_ATTACH_REQUEST_DOMAIN, request)
        ticket_sha256 = _hash(_ATTACH_TICKET_HASH_DOMAIN, ticket)
        commitments = (
            profile_sha256,
            protocol_sha256,
            descriptor_sha256,
            request_sha256,
            ticket_sha256,
        )
    except ValueError:
        pass
    if commitments is None:
        _fail("profile")
    (
        profile_sha256,
        protocol_sha256,
        descriptor_sha256,
        request_sha256,
        ticket_sha256,
    ) = commitments

    static_bindings_valid = (
        request.component == profile.component
        and request.component_role == profile.component_role
        and request.static_role_profile_sha256 == profile_sha256
        and request.attach_protocol_v3_sha256 == protocol_sha256
        and request.target_delivery_map_sha256 == profile.target_delivery_map_sha256
        and request.target_delivery_descriptor_sha256 == descriptor_sha256
        and request.fields == descriptor.fields
        and _runtime_binding_matches_request(runtime, request)
    )
    if not static_bindings_valid:
        _fail("binding")

    freshness_checked_at, _, _ = _require_ticket_fresh(
        issued_at=ticket.issued_at,
        expires_at=ticket.expires_at,
        max_ticket_lifetime_seconds=protocol.max_ticket_lifetime_seconds,
    )

    anchor = profile.ticket_trust_anchor
    signature_valid = False
    try:
        public_key = Ed25519PublicKey.from_public_bytes(
            _canonical_base64_bytes(anchor.public_key_base64)
        )
        public_key.verify(
            _canonical_base64_bytes(ticket.signature_base64),
            _ATTACH_TICKET_DOMAIN + _canonical_model_bytes(ticket, exclude={"signature_base64"}),
        )
        signature_valid = ticket.signer_key_id == anchor.key_id and anchor.algorithm == "ed25519"
    except (InvalidSignature, ValueError):
        signature_valid = False
    if not signature_valid:
        _fail("signature")

    return ContainerAttachV3TicketValidation(
        schema_version="rsd.container-attach-ticket-validation.v3",
        component=profile.component,
        component_role=profile.component_role,
        static_role_profile_sha256=profile_sha256,
        attach_protocol_v3_sha256=protocol_sha256,
        target_delivery_descriptor_sha256=descriptor_sha256,
        request_sha256=request_sha256,
        ticket_sha256=ticket_sha256,
        request_nonce_sha256=request.request_nonce_sha256,
        channel_binding_sha256=request.channel_binding_sha256,
        session_binding_sha256=request.session_binding_sha256,
        allocation_operation_id=request.allocation_operation_id,
        operation_scope=request.operation_scope,
        operation_id=request.operation_id,
        container_id=request.container_id,
        runtime_hostname=request.runtime_hostname,
        runtime_instance_binding_sha256=request.runtime_instance_binding_sha256,
        freshness_checked_at=_canonical_timestamp_text(freshness_checked_at),
        issued_at=ticket.issued_at,
        expires_at=ticket.expires_at,
        claim_timeout_seconds=protocol.claim_timeout_seconds,
        max_ticket_lifetime_seconds=protocol.max_ticket_lifetime_seconds,
    )


def _replay_claim_from_validation(
    validation: ContainerAttachV3TicketValidation,
) -> ContainerAttachV3ReplayClaimV3:
    """Derive both atomic replay identities from one fresh validation."""

    return ContainerAttachV3ReplayClaimV3(
        schema_version="rsd.container-attach-replay-claim.v3",
        ticket_claim=ContainerAttachV3TicketReplayClaimV3(
            schema_version="rsd.container-attach-ticket-replay-claim.v3",
            static_role_profile_sha256=validation.static_role_profile_sha256,
            request_sha256=validation.request_sha256,
            ticket_sha256=validation.ticket_sha256,
            allocation_operation_id=validation.allocation_operation_id,
            operation_scope=validation.operation_scope,
            operation_id=validation.operation_id,
            component=validation.component,
            component_role=validation.component_role,
            container_id=validation.container_id,
            runtime_hostname=validation.runtime_hostname,
            runtime_instance_binding_sha256=validation.runtime_instance_binding_sha256,
            request_nonce_sha256=validation.request_nonce_sha256,
            channel_binding_sha256=validation.channel_binding_sha256,
            session_binding_sha256=validation.session_binding_sha256,
        ),
        container_lifetime_claim=ContainerAttachV3ContainerLifetimeClaimV3(
            schema_version="rsd.container-attach-container-lifetime-claim.v3",
            container_id=validation.container_id,
            one_attach_per_container_lifetime=True,
        ),
    )


def _claim_interval_from_validation(
    validation: ContainerAttachV3TicketValidation,
    *,
    monotonic_started: float,
) -> _ContainerAttachV3ClaimInterval:
    """Bind a local deadline to the original UTC freshness observation only."""

    interval: _ContainerAttachV3ClaimInterval | None = None
    try:
        interval = _ContainerAttachV3ClaimInterval(
            ticket_sha256=validation.ticket_sha256,
            claim_started_at=_canonical_timestamp(validation.freshness_checked_at),
            ticket_expires_at=_canonical_timestamp(validation.expires_at),
            claim_timeout_seconds=validation.claim_timeout_seconds,
            monotonic_started=monotonic_started,
        )
    except (TypeError, ValueError):
        interval = None
    if interval is None:
        _fail("freshness")
    return interval


def _require_claim_still_fresh(
    *,
    validation: ContainerAttachV3TicketValidation,
    interval: _ContainerAttachV3ClaimInterval,
) -> None:
    """Refuse a late result using fresh UTC plus verifier-owned timing state."""

    now, _, expires = _require_ticket_fresh(
        issued_at=validation.issued_at,
        expires_at=validation.expires_at,
        max_ticket_lifetime_seconds=validation.max_ticket_lifetime_seconds,
    )
    if now >= expires or now >= interval.deadline_at:
        _fail("freshness")
    interval.require_after_authority()


def claim_container_attach_v3_ticket(
    *,
    static_role_profile: ContainerBootstrapStaticRoleProfileV3,
    envelope: ContainerAttachTicketEnvelopeV3,
    expected_runtime: ContainerAttachRuntimeBindingV3,
    replay_authority: ContainerAttachV3ReplayAuthority,
) -> ContainerAttachV3ClaimedTicketV3:
    """Revalidate then atomically consume one V3 ticket before frame success.

    The function deliberately accepts raw inputs rather than a caller-made
    validation result, so an untrusted caller cannot manufacture a validated
    decision.  The replay authority is mandatory and has no permissive
    default.  Any unavailable, malformed, or throwing authority result is
    treated as an ambiguous, non-usable replay failure.  The verifier observes
    its injected monotonic clock only before and after the authority call; its
    bounded claim decision relies on that clock source's nondecreasing contract
    and never gives that clock or a live deadline callback to the authority.
    """

    # Anchor elapsed claim time before wall-clock freshness validation.  That
    # makes validation/setup time consume budget and prevents a later UTC
    # rollback from inflating the interval derived from the signed expiry.
    monotonic_started = _read_trusted_monotonic_now()
    validation = validate_container_attach_v3_ticket(
        static_role_profile=static_role_profile,
        envelope=envelope,
        expected_runtime=expected_runtime,
    )
    claim = _replay_claim_from_validation(validation)
    claim_sha256 = container_attach_v3_replay_claim_sha256(claim)
    ticket_claim_sha256 = container_attach_v3_ticket_replay_claim_sha256(claim.ticket_claim)
    lifetime_claim_sha256 = container_attach_v3_container_lifetime_claim_sha256(
        claim.container_lifetime_claim
    )
    interval = _claim_interval_from_validation(
        validation,
        monotonic_started=monotonic_started,
    )
    deadline = interval.authority_deadline()

    claimed: ContainerAttachV3ReplayClaimReceiptV3 | None = None
    try:
        claimed = replay_authority.claim_once(claim=claim, deadline=deadline)
    except Exception:
        claimed = None
    if claimed is None:
        _fail("replay")

    canonical_claimed: ContainerAttachV3ReplayClaimReceiptV3 | None = None
    try:
        canonical_claimed = _strict_canonical_model(claimed, ContainerAttachV3ReplayClaimReceiptV3)
    except (TypeError, ValueError):
        canonical_claimed = None
    if (
        canonical_claimed is None
        or canonical_claimed.state != "claimed_v3"
        or canonical_claimed.replay_claim_sha256 != claim_sha256
        or canonical_claimed.ticket_replay_claim_sha256 != ticket_claim_sha256
        or canonical_claimed.container_lifetime_claim_sha256 != lifetime_claim_sha256
    ):
        _fail("replay")

    _require_claim_still_fresh(validation=validation, interval=interval)

    return ContainerAttachV3ClaimedTicketV3(
        schema_version="rsd.container-attach-claimed-ticket.v3",
        component=validation.component,
        static_role_profile_sha256=validation.static_role_profile_sha256,
        attach_protocol_v3_sha256=validation.attach_protocol_v3_sha256,
        target_delivery_descriptor_sha256=validation.target_delivery_descriptor_sha256,
        request_sha256=validation.request_sha256,
        ticket_sha256=validation.ticket_sha256,
        request_nonce_sha256=validation.request_nonce_sha256,
        replay_claim_sha256=claim_sha256,
        ticket_replay_claim_sha256=ticket_claim_sha256,
        container_lifetime_claim_sha256=lifetime_claim_sha256,
    )
