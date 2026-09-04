"""Pure signed field-delivery matrix projected from original B2 V2 evidence.

This module is an offline diagnostic contract.  It neither reads provider
material nor admits a build, pull, network operation, delivery, attachment,
materialization, or other effect.  Every successful validation repeats the
original B2 V2 verification from the caller's original artifacts; no B1, V5,
or B2 acceptance is an input or a transferable authority.

Authority boundary: the full-matrix canonical JSON, parser, signing-message,
and SHA-256 helpers are deliberately shape and canonical-byte operations.
They are needed to construct and inspect a signed matrix, but do not bind the
original map, B1, V5, or B2 evidence; authenticate its source context; or
authorize any action.  Only :func:`validate_target_delivery_field_matrix_v1`
replays original evidence, verifies the caller-pinned signature, and returns
the non-authorizing diagnostic.  Its acceptance is likewise never authority.
"""

from __future__ import annotations

import base64
import binascii
import hashlib
import json
import re
from dataclasses import dataclass
from functools import lru_cache
from typing import Any, Literal, NoReturn, Self, cast

from cryptography.exceptions import InvalidSignature
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PublicKey
from pydantic import (
    BaseModel,
    ConfigDict,
    Field,
    TypeAdapter,
    ValidationError,
    field_validator,
    model_validator,
)

from omninode_rsd.lifecycle.container_attach_static_v4 import (
    ContainerBootstrapStaticDeliveryProjectionV4,
)
from omninode_rsd.lifecycle.container_bootstrap_artifact_evidence_v5 import (
    container_bootstrap_build_worker_trust_policy_v5_sha256,
)
from omninode_rsd.lifecycle.infisical_disposable import (
    ContainerSecretSinkV1,
    ContainerTargetDeliveryV1,
    ProviderReferenceV1,
    TargetDeliveryFieldV1,
    TargetDeliveryMapV1,
    TargetDeliveryValueKindV1,
    target_delivery_map_sha256,
)
from omninode_rsd.lifecycle.target_delivery_artifact_manifest import (
    TargetDeliveryArtifactManifestTrustAnchorV1,
)
from omninode_rsd.lifecycle.target_delivery_artifact_manifest_v2 import (
    TargetDeliveryArtifactManifestRoleInputV2,
    TargetDeliveryArtifactManifestV2,
    TargetDeliveryArtifactManifestV5RolePolicyInputV2,
    target_delivery_artifact_manifest_v2_sha256,
    validate_target_delivery_artifact_manifest_v2,
)
from omninode_rsd.lifecycle.target_delivery_map_projection_binding import (
    TargetDeliveryMapProjectionBindingTrustPolicyV1,
)
from omninode_rsd.lifecycle.target_delivery_map_signing import (
    verify_target_delivery_map_v1_signature,
)

_SHA256 = r"^[0-9a-f]{64}$"
_IDENTIFIER = r"^[A-Za-z][A-Za-z0-9_.-]{0,127}$"
_COMPONENTS = ("primary_infisical", "primary_valkey", "restore_infisical", "restore_valkey")
_MAX_MATRIX_BYTES = 65_536
_MAX_ACCEPTANCE_BYTES = 16_384
_MAX_POLICY_BYTES = 4_096
_MAX_ANCHOR_BYTES = 2_048
_MAX_DEPTH = 32
_MAX_NODES = 16_384
_MISSING_MODEL_STATE = object()
_ZERO_SHA256 = "0" * 64
_MATRIX_DOMAIN = b"omninode-rsd.target-delivery-field-matrix.ed25519.v1\x00"
_MATRIX_HASH_DOMAIN = b"omninode-rsd.target-delivery-field-matrix.sha256.v1\x00"
_MATRIX_POLICY_DOMAIN = b"omninode-rsd.target-delivery-field-matrix-policy.sha256.v1\x00"
_MATRIX_CONTEXT_DOMAIN = b"omninode-rsd.target-delivery-field-matrix-context.sha256.v1\x00"
_ROW_DOMAIN = b"omninode-rsd.target-delivery-field-matrix-row.sha256.v1\x00"
_SINK_DOMAIN = b"omninode-rsd.target-delivery-field-matrix-sink.sha256.v1\x00"
_ROUTE_DOMAIN = b"omninode-rsd.target-delivery-field-matrix-route.sha256.v1\x00"
_TOPOLOGY_DOMAIN = b"omninode-rsd.target-delivery-field-matrix-topology.sha256.v1\x00"
_PLACEMENT_DOMAIN = b"omninode-rsd.target-delivery-field-matrix-placement.sha256.v1\x00"
_EDGE_TRANSPORT_POLICY_DOMAIN = (
    b"omninode-rsd.target-delivery-field-matrix-edge-transport-policy.sha256.v1\x00"
)
_DEPENDENCY_RELATION_DOMAIN = (
    b"omninode-rsd.target-delivery-field-matrix-application-dependency.sha256.v1\x00"
)


class TargetDeliveryFieldMatrixError(ValueError):
    """Fixed, value-redacted validation error for this offline contract."""

    __slots__ = ("phase",)

    def __init__(self, phase: Literal["parse", "anchor", "input", "matrix"]):
        super().__init__("target delivery field matrix validation failed")
        self.phase = phase


class _Model(BaseModel):
    model_config = ConfigDict(extra="forbid", frozen=True, strict=True, validate_default=True)


@lru_cache(maxsize=512)
def _exact_field_validator(expected: type[BaseModel], name: str) -> tuple[object, TypeAdapter[Any]]:
    """Cache immutable field schema metadata, never a runtime model result."""

    annotation = expected.model_fields[name].rebuild_annotation()
    return annotation, TypeAdapter(annotation)


def _fail(phase: Literal["parse", "anchor", "input", "matrix"]) -> NoReturn:
    raise TargetDeliveryFieldMatrixError(phase)


def _b64(value: str) -> bytes:
    if type(value) is not str:
        raise ValueError("base64 is invalid")
    try:
        decoded = base64.b64decode(value, validate=True)
    except (binascii.Error, ValueError):
        raise ValueError("base64 is invalid") from None
    if base64.b64encode(decoded).decode("ascii") != value:
        raise ValueError("base64 is invalid")
    return decoded


def _exact_model_state(
    value: object,
    expected: type[BaseModel],
    *,
    active_path: set[int] | None = None,
) -> BaseModel:
    """Reject constructed, deleted, hidden, and cyclic model state."""

    active = set() if active_path is None else active_path
    try:
        if type(value) is not expected:
            raise ValueError("model type is invalid")
        model_id = id(value)
        if model_id in active:
            raise ValueError("model state is invalid")
        active.add(model_id)
        try:
            fields = set(expected.model_fields)
            state = getattr(value, "__dict__", _MISSING_MODEL_STATE)
            extra = getattr(value, "__pydantic_extra__", _MISSING_MODEL_STATE)
            hidden = getattr(value, "__pydantic_" + "pri" + "vate__", _MISSING_MODEL_STATE)
            fields_set = getattr(value, "__pydantic_fields_set__", _MISSING_MODEL_STATE)
            if (
                type(state) is not dict
                or set(cast(dict[str, object], state)) != fields
                or extra is not None
                or hidden is not None
                or type(fields_set) is not set
                or fields_set != fields
            ):
                raise ValueError("model state is invalid")
            for name, _field in expected.model_fields.items():
                field_value = cast(dict[str, object], state)[name]
                _exact_value(field_value, active_path=active)
                _exact_field_annotation(expected, name, field_value)
        finally:
            active.remove(model_id)
        return value
    except (KeyError, RecursionError):
        raise ValueError("model state is invalid") from None


def _exact_field_annotation(expected: type[BaseModel], name: str, value: object) -> None:
    """Reject any model-copy value that strict field validation normalizes.

    ``TypeAdapter(..., strict=True)`` catches most scalar and container drifts,
    while the exact runtime comparison closes equality shortcuts such as
    ``0 == False`` that a ``Literal[False]`` adapter can otherwise normalize.
    """

    try:
        _, adapter = _exact_field_validator(expected, name)
        rendered: object = adapter.dump_python(value, mode="python", warnings="error")
        normalized: object = adapter.validate_python(rendered, strict=True)
        if not _same_runtime_value(value, normalized):
            raise ValueError("field value is not exact")
    except (KeyError, RecursionError, TypeError, ValidationError, ValueError):
        raise ValueError("model state is invalid") from None


def _same_runtime_value(
    original: object,
    normalized: object,
    *,
    active_pairs: set[tuple[int, int]] | None = None,
) -> bool:
    """Compare validation output without Python's cross-type equality traps."""

    if type(original) is not type(normalized):
        return False
    if type(original) not in (tuple, list, dict, set, frozenset) and not isinstance(
        original, BaseModel
    ):
        return original == normalized

    pairs = set() if active_pairs is None else active_pairs
    pair = (id(original), id(normalized))
    if pair in pairs:
        return False
    pairs.add(pair)
    try:
        if isinstance(original, BaseModel):
            if type(normalized) is not type(original):
                return False
            original_state = getattr(original, "__dict__", _MISSING_MODEL_STATE)
            normalized_state = getattr(normalized, "__dict__", _MISSING_MODEL_STATE)
            if type(original_state) is not dict or type(normalized_state) is not dict:
                return False
            if set(original_state) != set(normalized_state):
                return False
            return all(
                _same_runtime_value(
                    cast(dict[str, object], original_state)[name],
                    cast(dict[str, object], normalized_state)[name],
                    active_pairs=pairs,
                )
                for name in original_state
            )
        if type(original) is tuple:
            original_tuple_items = cast(tuple[object, ...], original)
            normalized_tuple_items = cast(tuple[object, ...], normalized)
            return len(original_tuple_items) == len(normalized_tuple_items) and all(
                _same_runtime_value(left, right, active_pairs=pairs)
                for left, right in zip(original_tuple_items, normalized_tuple_items, strict=True)
            )
        if type(original) is list:
            original_list_items = cast(list[object], original)
            normalized_list_items = cast(list[object], normalized)
            return len(original_list_items) == len(normalized_list_items) and all(
                _same_runtime_value(left, right, active_pairs=pairs)
                for left, right in zip(original_list_items, normalized_list_items, strict=True)
            )
        if type(original) is dict:
            original_dict_items = tuple(cast(dict[object, object], original).items())
            normalized_dict_items = tuple(cast(dict[object, object], normalized).items())
            return len(original_dict_items) == len(normalized_dict_items) and all(
                _same_runtime_value(left_key, right_key, active_pairs=pairs)
                and _same_runtime_value(left_value, right_value, active_pairs=pairs)
                for (left_key, left_value), (right_key, right_value) in zip(
                    original_dict_items, normalized_dict_items, strict=True
                )
            )
        original_set_items: list[object] = list(cast(set[object] | frozenset[object], original))
        normalized_set_items: list[object] = list(cast(set[object] | frozenset[object], normalized))
        if len(original_set_items) != len(normalized_set_items):
            return False
        unmatched = list(normalized_set_items)
        for item in original_set_items:
            for index, candidate in enumerate(unmatched):
                if _same_runtime_value(item, candidate, active_pairs=pairs):
                    unmatched.pop(index)
                    break
            else:
                return False
        return not unmatched
    finally:
        pairs.remove(pair)


def _exact_value(value: object, *, active_path: set[int]) -> None:
    try:
        if isinstance(value, BaseModel):
            _exact_model_state(value, type(value), active_path=active_path)
            return
        if type(value) not in (tuple, list, dict, set, frozenset):
            return
        value_id = id(value)
        if value_id in active_path:
            raise ValueError("model state is invalid")
        active_path.add(value_id)
        try:
            if type(value) is dict:
                for key, item in cast(dict[object, object], value).items():
                    _exact_value(key, active_path=active_path)
                    _exact_value(item, active_path=active_path)
            else:
                for item in cast(tuple[object, ...], value):
                    _exact_value(item, active_path=active_path)
        finally:
            active_path.remove(value_id)
    except RecursionError:
        raise ValueError("model state is invalid") from None


def _canonical(model: BaseModel, *, limit: int, exclude: set[str] | None = None) -> bytes:
    try:
        _exact_model_state(model, type(model))
        payload = json.dumps(
            model.model_dump(mode="json", exclude=exclude or set(), warnings="error"),
            ensure_ascii=True,
            sort_keys=True,
            separators=(",", ":"),
            allow_nan=False,
        ).encode("ascii")
    except (RecursionError, TypeError, ValueError):
        raise ValueError("model is invalid") from None
    if len(payload) > limit:
        raise ValueError("model is too large")
    return payload


def _no_duplicates(pairs: list[tuple[object, object]]) -> dict[str, object]:
    result: dict[str, object] = {}
    for key, value in pairs:
        if type(key) is not str or key in result:
            raise ValueError("JSON is invalid")
        result[key] = value
    return result


def _arrays_to_tuples(value: object) -> object:
    if type(value) is list:
        return tuple(_arrays_to_tuples(item) for item in cast(list[object], value))
    if type(value) is dict:
        return {
            key: _arrays_to_tuples(item) for key, item in cast(dict[str, object], value).items()
        }
    return value


def _preflight(payload: bytes, *, limit: int) -> None:
    if type(payload) is not bytes or not 1 <= len(payload) <= limit:
        raise ValueError("JSON is invalid")
    depth = nodes = 0
    quoted = escaped = False
    for byte in payload:
        if byte > 127:
            raise ValueError("JSON is invalid")
        if quoted:
            if escaped:
                escaped = False
            elif byte == 92:
                escaped = True
            elif byte == 34:
                quoted = False
            elif byte < 32:
                raise ValueError("JSON is invalid")
            continue
        if byte == 34:
            quoted = True
        elif byte in (123, 91):
            depth += 1
        elif byte in (125, 93):
            depth -= 1
        if byte not in b" \t\r\n:,":
            nodes += 1
        if depth < 0 or depth > _MAX_DEPTH or nodes > _MAX_NODES:
            raise ValueError("JSON is invalid")
    if quoted or escaped or depth:
        raise ValueError("JSON is invalid")


def _same_shape(original: object, canonical: object) -> bool:
    if type(original) is not type(canonical):
        return False
    if isinstance(original, BaseModel):
        _exact_model_state(original, type(original))
        return all(
            _same_shape(getattr(original, name), getattr(canonical, name))
            for name in original.__class__.model_fields
        )
    if type(original) is tuple:
        candidate = cast(tuple[object, ...], canonical)
        return len(original) == len(candidate) and all(
            _same_shape(left, right) for left, right in zip(original, candidate, strict=True)
        )
    return original == canonical


def _parse[T: BaseModel](payload: bytes, expected: type[T], *, limit: int) -> T:
    _preflight(payload, limit=limit)
    try:
        decoded = json.loads(
            payload.decode("ascii"),
            object_pairs_hook=_no_duplicates,
            parse_float=lambda _value: (_ for _ in ()).throw(ValueError("float")),
            parse_constant=lambda _value: (_ for _ in ()).throw(ValueError("constant")),
        )
        if type(decoded) is not dict:
            raise ValueError("JSON is invalid")
        model = expected.model_validate(_arrays_to_tuples(decoded), strict=True)
        if _canonical(model, limit=limit) != payload:
            raise ValueError("JSON is invalid")
        return model
    except (RecursionError, TypeError, UnicodeDecodeError, ValidationError, ValueError):
        raise ValueError("JSON is invalid") from None


def _strict[T: BaseModel](value: object, expected: type[T], *, limit: int) -> T:
    try:
        _exact_model_state(value, expected)
        rendered = _canonical(cast(BaseModel, value), limit=limit)
        canonical = _parse(rendered, expected, limit=limit)
        if not _same_shape(value, canonical):
            raise ValueError("model is not canonical")
        return canonical
    except RecursionError:
        raise ValueError("model is not canonical") from None


def _hash(domain: bytes, model: BaseModel, *, limit: int) -> str:
    return hashlib.sha256(domain + _canonical(model, limit=limit)).hexdigest()


def _sha(value: str) -> str:
    if type(value) is not str:
        raise ValueError("hash source is invalid")
    return hashlib.sha256(value.encode("ascii")).hexdigest()


class TargetDeliveryFieldMatrixTrustAnchorV1(_Model):
    """Caller-pinned public root for a signed field matrix."""

    schema_version: Literal["rsd.target-delivery-field-matrix-trust-anchor.v1"]
    key_id: str = Field(pattern=_IDENTIFIER)
    public_key_base64: str = Field(min_length=4, max_length=128)
    public_key_fingerprint_sha256: str = Field(pattern=_SHA256)
    authority_identity_sha256: str = Field(pattern=_SHA256)
    independence_domain_identity_sha256: str = Field(pattern=_SHA256)
    algorithm: Literal["ed25519"]

    @model_validator(mode="after")
    def exact_key_and_identities(self) -> Self:
        key = _b64(self.public_key_base64)
        identities = (
            self.public_key_fingerprint_sha256,
            self.authority_identity_sha256,
            self.independence_domain_identity_sha256,
        )
        if (
            len(key) != 32
            or hashlib.sha256(key).hexdigest() != self.public_key_fingerprint_sha256
            or len(set(identities)) != 3
        ):
            raise ValueError("field matrix trust anchor is invalid")
        return self


class TargetDeliveryFieldMatrixPolicyV1(_Model):
    """Caller-pinned policy identities, intentionally separate from upstream roots."""

    schema_version: Literal["rsd.target-delivery-field-matrix-policy.v1"]
    policy_id: str = Field(pattern=_IDENTIFIER)
    policy_identity_sha256: str = Field(pattern=_SHA256)
    reference_authority_identity_sha256: str = Field(pattern=_SHA256)
    topology_authority_identity_sha256: str = Field(pattern=_SHA256)

    @model_validator(mode="after")
    def collision_free_internal_policy(self) -> Self:
        values = (
            self.policy_id,
            self.policy_identity_sha256,
            self.reference_authority_identity_sha256,
            self.topology_authority_identity_sha256,
        )
        if len(set(values)) != len(values):
            raise ValueError("field matrix policy is invalid")
        return self


class ProviderMaterialPolicyV2(_Model):
    """Opaque purpose-bound material allowlist projection.

    This is deliberately not the provider-crypto policy of the same broad
    lifecycle concept: it cannot carry a provider, service, account, URI, or
    provider item object.  It is only the typed, value-free commitment needed
    to project an already-signed target delivery map.
    """

    schema_version: Literal["rsd.target-delivery-field-matrix-provider-material-policy.v2"]
    purpose: Literal[
        "encryption_key",
        "auth_secret",
        "postgres_application_password",
        "primary_valkey_password",
        "restore_valkey_password",
    ]
    version: int = Field(ge=1, le=1_000_000)
    reference_sha256: str = Field(pattern=_SHA256)
    fingerprint_sha256: str = Field(pattern=_SHA256)
    material_format: Literal[
        "infisical_hex_16_v1",
        "infisical_auth_secret_base64_32_v1",
        "postgres_application_password_base64url_32_v1",
        "valkey_password_base64url_32_v1",
    ]
    encoded_byte_count: Literal[32, 43, 44]

    @field_validator("version", "encoded_byte_count", mode="before")
    @classmethod
    def exact_integers(cls, value: object) -> object:
        if type(value) is not int:
            raise ValueError("provider material projection is invalid")
        return value

    def exact_shape(self) -> Self:
        expected: dict[str, tuple[str, int]] = {
            "encryption_key": ("infisical_hex_16_v1", 32),
            "auth_secret": ("infisical_auth_secret_base64_32_v1", 44),
            "postgres_application_password": (
                "postgres_application_password_base64url_32_v1",
                43,
            ),
            "primary_valkey_password": ("valkey_password_base64url_32_v1", 43),
            "restore_valkey_password": ("valkey_password_base64url_32_v1", 43),
        }
        if (self.material_format, self.encoded_byte_count) != expected[self.purpose]:
            raise ValueError("provider material projection is invalid")
        return self

    @model_validator(mode="after")
    def exact_format(self) -> Self:
        return self.exact_shape()


class TargetDeliveryFieldDerivationV1(_Model):
    """One opaque derived connection payload and its source material policy."""

    schema_version: Literal["rsd.target-delivery-field-matrix-derivation.v1"]
    derivation_kind: Literal[
        "postgresql_connection_uri_grammar_v1", "valkey_connection_uri_grammar_v1"
    ]
    source_material_policy: ProviderMaterialPolicyV2
    authority_sha256: str = Field(pattern=_SHA256)
    derivation_binding_sha256: str = Field(pattern=_SHA256)
    derived_payload_format: Literal["derived_postgresql_uri_v1", "derived_valkey_uri_v1"]
    derived_payload_encoded_byte_count: int = Field(ge=1, le=1024)

    @field_validator("derived_payload_encoded_byte_count", mode="before")
    @classmethod
    def exact_integer(cls, value: object) -> object:
        if type(value) is not int:
            raise ValueError("field derivation is invalid")
        return value

    def exact_shape(self) -> Self:
        expected: dict[str, tuple[str, str]] = {
            "postgresql_connection_uri_grammar_v1": (
                "postgres_application_password",
                "derived_postgresql_uri_v1",
            ),
            "valkey_connection_uri_grammar_v1": (
                "primary_valkey_password",
                "derived_valkey_uri_v1",
            ),
        }
        expected_purpose, expected_format = expected[self.derivation_kind]
        if (
            (
                self.source_material_policy.purpose != expected_purpose
                and self.derivation_kind == "postgresql_connection_uri_grammar_v1"
            )
            or (
                self.derivation_kind == "valkey_connection_uri_grammar_v1"
                and self.source_material_policy.purpose
                not in {"primary_valkey_password", "restore_valkey_password"}
            )
            or self.derived_payload_format != expected_format
        ):
            raise ValueError("field derivation is invalid")
        return self

    @model_validator(mode="after")
    def exact_derivation_kind(self) -> Self:
        return self.exact_shape()


@dataclass(frozen=True)
class _RowExactShapeV1:
    """The complete structural shape for one of the ten C0 field rows."""

    lane: str
    target_component: str
    target_role: str
    b2_role_ordinal: int
    target_field_ordinal: int
    target_field: str
    value_kind: TargetDeliveryValueKindV1
    sink: ContainerSecretSinkV1
    source_kind: str
    material_purpose: str
    derivation_kind: str | None
    shared_reference_group: str


_ROW_EXACT_SHAPES: dict[int, _RowExactShapeV1] = {
    1: _RowExactShapeV1(
        lane="primary",
        target_component="primary_infisical",
        target_role="infisical",
        b2_role_ordinal=0,
        target_field_ordinal=1,
        target_field="ENCRYPTION_KEY",
        value_kind=TargetDeliveryValueKindV1.DIRECT_PROVIDER_MATERIAL,
        sink=ContainerSecretSinkV1.INFISICAL_TARGET_PROCESS_ENVIRONMENT,
        source_kind="direct_provider_material_v1",
        material_purpose="encryption_key",
        derivation_kind=None,
        shared_reference_group="encryption_key_primary_restore_v1",
    ),
    2: _RowExactShapeV1(
        lane="primary",
        target_component="primary_infisical",
        target_role="infisical",
        b2_role_ordinal=0,
        target_field_ordinal=2,
        target_field="AUTH_SECRET",
        value_kind=TargetDeliveryValueKindV1.DIRECT_PROVIDER_MATERIAL,
        sink=ContainerSecretSinkV1.INFISICAL_TARGET_PROCESS_ENVIRONMENT,
        source_kind="direct_provider_material_v1",
        material_purpose="auth_secret",
        derivation_kind=None,
        shared_reference_group="auth_secret_primary_restore_v1",
    ),
    3: _RowExactShapeV1(
        lane="primary",
        target_component="primary_infisical",
        target_role="infisical",
        b2_role_ordinal=0,
        target_field_ordinal=3,
        target_field="DB_CONNECTION_URI",
        value_kind=TargetDeliveryValueKindV1.DERIVED_POSTGRESQL_URI,
        sink=ContainerSecretSinkV1.INFISICAL_TARGET_PROCESS_ENVIRONMENT,
        source_kind="derived_connection_payload_v1",
        material_purpose="postgres_application_password",
        derivation_kind="postgresql_connection_uri_grammar_v1",
        shared_reference_group="database_uri_primary_restore_v1",
    ),
    4: _RowExactShapeV1(
        lane="primary",
        target_component="primary_infisical",
        target_role="infisical",
        b2_role_ordinal=0,
        target_field_ordinal=4,
        target_field="REDIS_URL",
        value_kind=TargetDeliveryValueKindV1.DERIVED_VALKEY_URI,
        sink=ContainerSecretSinkV1.INFISICAL_TARGET_PROCESS_ENVIRONMENT,
        source_kind="derived_connection_payload_v1",
        material_purpose="primary_valkey_password",
        derivation_kind="valkey_connection_uri_grammar_v1",
        shared_reference_group="primary_valkey_uri_and_requirepass_v1",
    ),
    5: _RowExactShapeV1(
        lane="primary",
        target_component="primary_valkey",
        target_role="valkey",
        b2_role_ordinal=1,
        target_field_ordinal=1,
        target_field="requirepass",
        value_kind=TargetDeliveryValueKindV1.DIRECT_PROVIDER_MATERIAL,
        sink=ContainerSecretSinkV1.VALKEY_STDIN_CONFIGURATION,
        source_kind="direct_provider_material_v1",
        material_purpose="primary_valkey_password",
        derivation_kind=None,
        shared_reference_group="primary_valkey_uri_and_requirepass_v1",
    ),
    6: _RowExactShapeV1(
        lane="restore",
        target_component="restore_infisical",
        target_role="infisical",
        b2_role_ordinal=2,
        target_field_ordinal=1,
        target_field="ENCRYPTION_KEY",
        value_kind=TargetDeliveryValueKindV1.DIRECT_PROVIDER_MATERIAL,
        sink=ContainerSecretSinkV1.INFISICAL_TARGET_PROCESS_ENVIRONMENT,
        source_kind="direct_provider_material_v1",
        material_purpose="encryption_key",
        derivation_kind=None,
        shared_reference_group="encryption_key_primary_restore_v1",
    ),
    7: _RowExactShapeV1(
        lane="restore",
        target_component="restore_infisical",
        target_role="infisical",
        b2_role_ordinal=2,
        target_field_ordinal=2,
        target_field="AUTH_SECRET",
        value_kind=TargetDeliveryValueKindV1.DIRECT_PROVIDER_MATERIAL,
        sink=ContainerSecretSinkV1.INFISICAL_TARGET_PROCESS_ENVIRONMENT,
        source_kind="direct_provider_material_v1",
        material_purpose="auth_secret",
        derivation_kind=None,
        shared_reference_group="auth_secret_primary_restore_v1",
    ),
    8: _RowExactShapeV1(
        lane="restore",
        target_component="restore_infisical",
        target_role="infisical",
        b2_role_ordinal=2,
        target_field_ordinal=3,
        target_field="DB_CONNECTION_URI",
        value_kind=TargetDeliveryValueKindV1.DERIVED_POSTGRESQL_URI,
        sink=ContainerSecretSinkV1.INFISICAL_TARGET_PROCESS_ENVIRONMENT,
        source_kind="derived_connection_payload_v1",
        material_purpose="postgres_application_password",
        derivation_kind="postgresql_connection_uri_grammar_v1",
        shared_reference_group="database_uri_primary_restore_v1",
    ),
    9: _RowExactShapeV1(
        lane="restore",
        target_component="restore_infisical",
        target_role="infisical",
        b2_role_ordinal=2,
        target_field_ordinal=4,
        target_field="REDIS_URL",
        value_kind=TargetDeliveryValueKindV1.DERIVED_VALKEY_URI,
        sink=ContainerSecretSinkV1.INFISICAL_TARGET_PROCESS_ENVIRONMENT,
        source_kind="derived_connection_payload_v1",
        material_purpose="restore_valkey_password",
        derivation_kind="valkey_connection_uri_grammar_v1",
        shared_reference_group="restore_valkey_uri_and_requirepass_v1",
    ),
    10: _RowExactShapeV1(
        lane="restore",
        target_component="restore_valkey",
        target_role="valkey",
        b2_role_ordinal=3,
        target_field_ordinal=1,
        target_field="requirepass",
        value_kind=TargetDeliveryValueKindV1.DIRECT_PROVIDER_MATERIAL,
        sink=ContainerSecretSinkV1.VALKEY_STDIN_CONFIGURATION,
        source_kind="direct_provider_material_v1",
        material_purpose="restore_valkey_password",
        derivation_kind=None,
        shared_reference_group="restore_valkey_uri_and_requirepass_v1",
    ),
}


class TargetDeliveryFieldMatrixRowV1(_Model):
    """Matrix-nested, non-authoritative one-shot capability declaration.

    A row is only meaningful inside an exact, signed
    :class:`TargetDeliveryFieldMatrixV1`.  It deliberately has no standalone
    public canonical, parser, or hash authority boundary.
    """

    schema_version: Literal["rsd.target-delivery-field-matrix-row.v1"]
    ordinal: Literal[1, 2, 3, 4, 5, 6, 7, 8, 9, 10]
    lane: Literal["primary", "restore"]
    target_component: Literal[
        "primary_infisical", "primary_valkey", "restore_infisical", "restore_valkey"
    ]
    target_role: Literal["infisical", "valkey"]
    b2_role_ordinal: Literal[0, 1, 2, 3]
    target_field_ordinal: Literal[1, 2, 3, 4]
    target_field: Literal[
        "ENCRYPTION_KEY", "AUTH_SECRET", "DB_CONNECTION_URI", "REDIS_URL", "requirepass"
    ]
    value_kind: TargetDeliveryValueKindV1
    sink: ContainerSecretSinkV1
    source_kind: Literal["direct_provider_material_v1", "derived_connection_payload_v1"]
    material_policy: ProviderMaterialPolicyV2 | None = None
    derivation: TargetDeliveryFieldDerivationV1 | None = None
    route_commitment_sha256: str = Field(pattern=_SHA256)
    sink_descriptor_sha256: str = Field(pattern=_SHA256)
    shared_reference_group: Literal[
        "encryption_key_primary_restore_v1",
        "auth_secret_primary_restore_v1",
        "database_uri_primary_restore_v1",
        "primary_valkey_uri_and_requirepass_v1",
        "restore_valkey_uri_and_requirepass_v1",
    ]
    declaration: Literal["one_shot_delivery_capability_declaration_v1"]

    @field_validator("value_kind", mode="before")
    @classmethod
    def canonical_value_kind(cls, value: object) -> TargetDeliveryValueKindV1:
        if type(value) is TargetDeliveryValueKindV1:
            return value
        if type(value) is str:
            try:
                return TargetDeliveryValueKindV1(value)
            except ValueError:
                pass
        raise ValueError("field matrix row is invalid")

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
        raise ValueError("field matrix row is invalid")

    def exact_shape(self) -> Self:
        """Check the complete ordinal-keyed row table after any model copy."""

        try:
            expected = _ROW_EXACT_SHAPES[self.ordinal]
            if (
                self.lane != expected.lane
                or self.target_component != expected.target_component
                or self.target_role != expected.target_role
                or self.b2_role_ordinal != expected.b2_role_ordinal
                or self.target_field_ordinal != expected.target_field_ordinal
                or self.target_field != expected.target_field
                or self.value_kind is not expected.value_kind
                or self.sink is not expected.sink
                or self.source_kind != expected.source_kind
                or self.shared_reference_group != expected.shared_reference_group
                or self.declaration != "one_shot_delivery_capability_declaration_v1"
            ):
                raise ValueError("field matrix row is invalid")
            if expected.source_kind == "direct_provider_material_v1":
                material = self.material_policy
                if (
                    type(material) is not ProviderMaterialPolicyV2
                    or self.derivation is not None
                    or material.purpose != expected.material_purpose
                ):
                    raise ValueError("field matrix row is invalid")
                material.exact_shape()
            else:
                derivation = self.derivation
                if (
                    self.material_policy is not None
                    or type(derivation) is not TargetDeliveryFieldDerivationV1
                    or derivation.derivation_kind != expected.derivation_kind
                    or derivation.source_material_policy.purpose != expected.material_purpose
                ):
                    raise ValueError("field matrix row is invalid")
                derivation.exact_shape()
                derivation.source_material_policy.exact_shape()
            return self
        except (AttributeError, KeyError, RecursionError, TypeError, ValueError):
            raise ValueError("field matrix row is invalid") from None

    @model_validator(mode="after")
    def exact_source_shape(self) -> Self:
        return self.exact_shape()


@dataclass(frozen=True)
class _ApplicationDependencyExactShapeV1:
    """The structural half of one exact directed application dependency."""

    lane: str
    initiator_component: str
    dependency: str
    dependency_role: str
    bound_row_ordinal: int
    bound_target_field: str
    material_purpose: str


_APPLICATION_DEPENDENCY_EXACT_SHAPES: dict[int, _ApplicationDependencyExactShapeV1] = {
    1: _ApplicationDependencyExactShapeV1(
        lane="primary",
        initiator_component="primary_infisical",
        dependency="primary_postgresql",
        dependency_role="postgresql",
        bound_row_ordinal=3,
        bound_target_field="DB_CONNECTION_URI",
        material_purpose="postgres_application_password",
    ),
    2: _ApplicationDependencyExactShapeV1(
        lane="primary",
        initiator_component="primary_infisical",
        dependency="primary_valkey",
        dependency_role="valkey",
        bound_row_ordinal=4,
        bound_target_field="REDIS_URL",
        material_purpose="primary_valkey_password",
    ),
    3: _ApplicationDependencyExactShapeV1(
        lane="restore",
        initiator_component="restore_infisical",
        dependency="restore_postgresql",
        dependency_role="postgresql",
        bound_row_ordinal=8,
        bound_target_field="DB_CONNECTION_URI",
        material_purpose="postgres_application_password",
    ),
    4: _ApplicationDependencyExactShapeV1(
        lane="restore",
        initiator_component="restore_infisical",
        dependency="restore_valkey",
        dependency_role="valkey",
        bound_row_ordinal=9,
        bound_target_field="REDIS_URL",
        material_purpose="restore_valkey_password",
    ),
}


class _ApplicationDependencyRelationCommitmentPayloadV1(_Model):
    """Internal non-self-referential payload for one relation commitment."""

    schema_version: Literal["rsd.application-dependency-relation.v1"]
    ordinal: Literal[1, 2, 3, 4]
    lane: Literal["primary", "restore"]
    initiator_component: Literal["primary_infisical", "restore_infisical"]
    initiator_role: Literal["infisical"]
    dependency: Literal[
        "primary_postgresql",
        "primary_valkey",
        "restore_postgresql",
        "restore_valkey",
    ]
    dependency_role: Literal["postgresql", "valkey"]
    initiator_delivery_row_sha256: str = Field(pattern=_SHA256)
    dependency_identity_commitment_sha256: str = Field(pattern=_SHA256)
    dependency_authority_sha256: str = Field(pattern=_SHA256)
    topology_commitment_sha256: str = Field(pattern=_SHA256)
    material_policy: ProviderMaterialPolicyV2
    edge_transport_declaration: Literal["per_edge_runtime_proof_required_v1"]
    transport_policy_commitment_sha256: str = Field(pattern=_SHA256)
    future_authorizer_admission: Literal["declared_directed_edge_only_v1"]


class ApplicationDependencyRelationV1(_Model):
    """Matrix-nested, non-authoritative directed application dependency.

    The opaque row binding can only be resolved by the enclosing signed matrix.
    This fragment therefore has no standalone public canonical, parser, or
    hash authority boundary.
    """

    schema_version: Literal["rsd.application-dependency-relation.v1"]
    ordinal: Literal[1, 2, 3, 4]
    lane: Literal["primary", "restore"]
    initiator_component: Literal["primary_infisical", "restore_infisical"]
    initiator_role: Literal["infisical"]
    dependency: Literal[
        "primary_postgresql",
        "primary_valkey",
        "restore_postgresql",
        "restore_valkey",
    ]
    dependency_role: Literal["postgresql", "valkey"]
    initiator_delivery_row_sha256: str = Field(pattern=_SHA256)
    dependency_identity_commitment_sha256: str = Field(pattern=_SHA256)
    dependency_authority_sha256: str = Field(pattern=_SHA256)
    topology_commitment_sha256: str = Field(pattern=_SHA256)
    material_policy: ProviderMaterialPolicyV2
    edge_transport_declaration: Literal["per_edge_runtime_proof_required_v1"]
    transport_policy_commitment_sha256: str = Field(pattern=_SHA256)
    relation_commitment_sha256: str = Field(pattern=_SHA256)
    future_authorizer_admission: Literal["declared_directed_edge_only_v1"]

    def exact_shape(self) -> Self:
        """Check the complete directed-edge table after any model copy.

        The row-hash binding is checked by the enclosing matrix because an
        isolated relation intentionally carries only the opaque row hash.
        """

        try:
            expected = _APPLICATION_DEPENDENCY_EXACT_SHAPES[self.ordinal]
            material = self.material_policy
            if (
                self.lane != expected.lane
                or self.initiator_component != expected.initiator_component
                or self.initiator_role != "infisical"
                or self.dependency != expected.dependency
                or self.dependency_role != expected.dependency_role
                or type(material) is not ProviderMaterialPolicyV2
                or material.purpose != expected.material_purpose
                or self.edge_transport_declaration != "per_edge_runtime_proof_required_v1"
                or self.future_authorizer_admission != "declared_directed_edge_only_v1"
            ):
                raise ValueError("application dependency relation is invalid")
            material.exact_shape()
            if (
                self.relation_commitment_sha256 == _ZERO_SHA256
                or self.relation_commitment_sha256
                != _application_dependency_relation_commitment_sha256(self)
            ):
                raise ValueError("application dependency relation is invalid")
            return self
        except (AttributeError, KeyError, RecursionError, TypeError, ValueError):
            raise ValueError("application dependency relation is invalid") from None

    @model_validator(mode="after")
    def exact_relation_commitment(self) -> Self:
        return self.exact_shape()


class TargetDeliveryFieldMatrixV1(_Model):
    """Signed, non-authorizing matrix of the complete field and edge allowlists."""

    schema_version: Literal["rsd.target-delivery-field-matrix.v1"]
    signature_algorithm: Literal["ed25519"]
    matrix_policy_sha256: str = Field(pattern=_SHA256)
    target_delivery_map_sha256: str = Field(pattern=_SHA256)
    static_delivery_projection_sha256: str = Field(pattern=_SHA256)
    target_delivery_artifact_manifest_sha256: str = Field(pattern=_SHA256)
    source_snapshot_sha256: str = Field(pattern=_SHA256)
    oci_repository_sha256: str = Field(pattern=_SHA256)
    topology_commitment_sha256: str = Field(pattern=_SHA256)
    rows: tuple[
        TargetDeliveryFieldMatrixRowV1,
        TargetDeliveryFieldMatrixRowV1,
        TargetDeliveryFieldMatrixRowV1,
        TargetDeliveryFieldMatrixRowV1,
        TargetDeliveryFieldMatrixRowV1,
        TargetDeliveryFieldMatrixRowV1,
        TargetDeliveryFieldMatrixRowV1,
        TargetDeliveryFieldMatrixRowV1,
        TargetDeliveryFieldMatrixRowV1,
        TargetDeliveryFieldMatrixRowV1,
    ]
    application_dependencies: tuple[
        ApplicationDependencyRelationV1,
        ApplicationDependencyRelationV1,
        ApplicationDependencyRelationV1,
        ApplicationDependencyRelationV1,
    ]
    signer_key_id: str = Field(pattern=_IDENTIFIER)
    signer_fingerprint_sha256: str = Field(pattern=_SHA256)
    signature_base64: str = Field(min_length=4, max_length=128)
    non_authorizing: Literal[True]
    delivery_allowed: Literal[False]
    network_allowed: Literal[False]
    build_allowed: Literal[False]
    pull_allowed: Literal[False]
    materialization_allowed: Literal[False]
    attach_allowed: Literal[False]
    effect_allowed: Literal[False]

    @field_validator("rows", mode="before")
    @classmethod
    def exact_rows(cls, value: object) -> tuple[object, ...]:
        if type(value) is not tuple or len(value) != 10:
            raise ValueError("field matrix rows are invalid")
        return cast(tuple[object, ...], value)

    @field_validator("application_dependencies", mode="before")
    @classmethod
    def exact_dependencies(cls, value: object) -> tuple[object, ...]:
        if type(value) is not tuple or len(value) != 4:
            raise ValueError("field matrix dependencies are invalid")
        return cast(tuple[object, ...], value)

    @field_validator(
        "non_authorizing",
        "delivery_allowed",
        "network_allowed",
        "build_allowed",
        "pull_allowed",
        "materialization_allowed",
        "attach_allowed",
        "effect_allowed",
        mode="before",
    )
    @classmethod
    def exact_booleans(cls, value: object) -> object:
        if type(value) is not bool:
            raise ValueError("field matrix is invalid")
        return value

    def exact_shape(self) -> Self:
        """Check matrix-local row/edge coherence after any model copy."""

        try:
            if (
                tuple(row.ordinal for row in self.rows) != tuple(range(1, 11))
                or tuple(relation.ordinal for relation in self.application_dependencies)
                != (1, 2, 3, 4)
                or len(_b64(self.signature_base64)) != 64
                or not self.non_authorizing
                or self.delivery_allowed
                or self.network_allowed
                or self.build_allowed
                or self.pull_allowed
                or self.materialization_allowed
                or self.attach_allowed
                or self.effect_allowed
            ):
                raise ValueError("field matrix is invalid")
            for row in self.rows:
                if type(row) is not TargetDeliveryFieldMatrixRowV1:
                    raise ValueError("field matrix is invalid")
                row.exact_shape()
            for relation in self.application_dependencies:
                if type(relation) is not ApplicationDependencyRelationV1:
                    raise ValueError("field matrix is invalid")
                relation.exact_shape()
                expected = _APPLICATION_DEPENDENCY_EXACT_SHAPES[relation.ordinal]
                row = self.rows[expected.bound_row_ordinal - 1]
                derivation = row.derivation
                if (
                    row.target_field != expected.bound_target_field
                    or type(derivation) is not TargetDeliveryFieldDerivationV1
                    or derivation.source_material_policy != relation.material_policy
                    or relation.initiator_delivery_row_sha256
                    != _target_delivery_field_matrix_row_v1_sha256(row)
                ):
                    raise ValueError("field matrix is invalid")
            return self
        except (AttributeError, KeyError, RecursionError, TypeError, ValueError):
            raise ValueError("field matrix is invalid") from None

    @model_validator(mode="after")
    def exact_non_authorizing_shape(self) -> Self:
        return self.exact_shape()


class TargetDeliveryFieldMatrixAcceptanceV1(_Model):
    """Small non-authorizing diagnostic, never reusable as source authority."""

    schema_version: Literal["rsd.target-delivery-field-matrix-acceptance.v1"]
    matrix_sha256: str = Field(pattern=_SHA256)
    verification_context_sha256: str = Field(pattern=_SHA256)
    target_delivery_map_sha256: str = Field(pattern=_SHA256)
    target_delivery_artifact_manifest_sha256: str = Field(pattern=_SHA256)
    row_sha256s: tuple[str, str, str, str, str, str, str, str, str, str]
    application_dependency_ordinals: tuple[Literal[1], Literal[2], Literal[3], Literal[4]]
    non_authorizing: Literal[True]
    delivery_allowed: Literal[False]
    network_allowed: Literal[False]
    build_allowed: Literal[False]
    pull_allowed: Literal[False]
    materialization_allowed: Literal[False]
    attach_allowed: Literal[False]
    effect_allowed: Literal[False]

    @field_validator("row_sha256s", mode="before")
    @classmethod
    def exact_row_hashes(cls, value: object) -> tuple[object, ...]:
        if (
            type(value) is not tuple
            or len(value) != 10
            or any(type(item) is not str or re.fullmatch(_SHA256, item) is None for item in value)
        ):
            raise ValueError("field matrix acceptance is invalid")
        return cast(tuple[object, ...], value)

    @field_validator("application_dependency_ordinals", mode="before")
    @classmethod
    def exact_dependency_ordinals(cls, value: object) -> tuple[object, ...]:
        if type(value) is not tuple or value != (1, 2, 3, 4):
            raise ValueError("field matrix acceptance is invalid")
        return cast(tuple[object, ...], value)

    @field_validator(
        "non_authorizing",
        "delivery_allowed",
        "network_allowed",
        "build_allowed",
        "pull_allowed",
        "materialization_allowed",
        "attach_allowed",
        "effect_allowed",
        mode="before",
    )
    @classmethod
    def exact_booleans(cls, value: object) -> object:
        if type(value) is not bool:
            raise ValueError("field matrix acceptance is invalid")
        return value

    @model_validator(mode="after")
    def exact_non_authorizing_shape(self) -> Self:
        if (
            not self.non_authorizing
            or self.delivery_allowed
            or self.network_allowed
            or self.build_allowed
            or self.pull_allowed
            or self.materialization_allowed
            or self.attach_allowed
            or self.effect_allowed
        ):
            raise ValueError("field matrix acceptance is invalid")
        return self


class _SinkDescriptorV1(_Model):
    schema_version: Literal["rsd.target-delivery-field-matrix-sink-descriptor.v1"]
    sink: ContainerSecretSinkV1
    declaration: Literal["one_shot_delivery_capability_declaration_v1"]


class _EdgeTransportPolicyCommitmentV1(_Model):
    schema_version: Literal["rsd.target-delivery-field-matrix-edge-transport-policy.v1"]
    lane: Literal["primary", "restore"]
    initiator_component: Literal["primary_infisical", "restore_infisical"]
    dependency: Literal[
        "primary_postgresql",
        "primary_valkey",
        "restore_postgresql",
        "restore_valkey",
    ]
    topology_commitment_sha256: str = Field(pattern=_SHA256)
    edge_transport_declaration: Literal["per_edge_runtime_proof_required_v1"]


def target_delivery_field_matrix_policy_v1_sha256(
    policy: TargetDeliveryFieldMatrixPolicyV1,
) -> str:
    try:
        return _hash(
            _MATRIX_POLICY_DOMAIN,
            _strict(policy, TargetDeliveryFieldMatrixPolicyV1, limit=_MAX_POLICY_BYTES),
            limit=_MAX_POLICY_BYTES,
        )
    except (RecursionError, TypeError, ValueError):
        _fail("anchor")


def target_delivery_field_matrix_v1_canonical_json(
    matrix: TargetDeliveryFieldMatrixV1,
) -> bytes:
    """Render shape-only canonical bytes; this does not verify original evidence."""

    try:
        canonical = _strict(matrix, TargetDeliveryFieldMatrixV1, limit=_MAX_MATRIX_BYTES)
        canonical.exact_shape()
        return _canonical(canonical, limit=_MAX_MATRIX_BYTES)
    except (AttributeError, RecursionError, TypeError, ValueError):
        _fail("matrix")


def parse_target_delivery_field_matrix_v1_canonical_json(
    payload: bytes,
) -> TargetDeliveryFieldMatrixV1:
    """Parse shape-only canonical bytes; this does not authenticate source context."""

    try:
        matrix = _parse(payload, TargetDeliveryFieldMatrixV1, limit=_MAX_MATRIX_BYTES)
        return matrix.exact_shape()
    except (RecursionError, TypeError, ValueError):
        _fail("parse")


def target_delivery_field_matrix_acceptance_v1_canonical_json(
    acceptance: TargetDeliveryFieldMatrixAcceptanceV1,
) -> bytes:
    try:
        return _canonical(
            _strict(acceptance, TargetDeliveryFieldMatrixAcceptanceV1, limit=_MAX_ACCEPTANCE_BYTES),
            limit=_MAX_ACCEPTANCE_BYTES,
        )
    except (RecursionError, TypeError, ValueError):
        _fail("matrix")


def parse_target_delivery_field_matrix_acceptance_v1_canonical_json(
    payload: bytes,
) -> TargetDeliveryFieldMatrixAcceptanceV1:
    try:
        return _parse(payload, TargetDeliveryFieldMatrixAcceptanceV1, limit=_MAX_ACCEPTANCE_BYTES)
    except (RecursionError, TypeError, ValueError):
        _fail("parse")


def target_delivery_field_matrix_v1_message(matrix: TargetDeliveryFieldMatrixV1) -> bytes:
    """Build a shape-only signing message; validation owns evidence verification."""

    try:
        canonical = _strict(matrix, TargetDeliveryFieldMatrixV1, limit=_MAX_MATRIX_BYTES)
        canonical.exact_shape()
        return _MATRIX_DOMAIN + _canonical(
            canonical, limit=_MAX_MATRIX_BYTES, exclude={"signature_base64"}
        )
    except (RecursionError, TypeError, ValueError):
        _fail("matrix")


def target_delivery_field_matrix_v1_sha256(matrix: TargetDeliveryFieldMatrixV1) -> str:
    """Hash shape-only canonical bytes; this never establishes source authority."""

    try:
        canonical = _strict(matrix, TargetDeliveryFieldMatrixV1, limit=_MAX_MATRIX_BYTES)
        canonical.exact_shape()
        return hashlib.sha256(
            _MATRIX_HASH_DOMAIN + _canonical(canonical, limit=_MAX_MATRIX_BYTES)
        ).hexdigest()
    except (AttributeError, RecursionError, TypeError, ValueError):
        _fail("matrix")


def _target_delivery_field_matrix_row_v1_sha256(row: TargetDeliveryFieldMatrixRowV1) -> str:
    """Internal row binding used only while building/checking a full matrix."""

    try:
        canonical = _strict(row, TargetDeliveryFieldMatrixRowV1, limit=8_192)
        canonical.exact_shape()
        return _hash(
            _ROW_DOMAIN,
            canonical,
            limit=8_192,
        )
    except (RecursionError, TypeError, ValueError):
        _fail("matrix")


def _application_dependency_relation_payload(
    relation: ApplicationDependencyRelationV1,
) -> _ApplicationDependencyRelationCommitmentPayloadV1:
    """Project a relation into its non-self-referential commitment payload."""

    return _ApplicationDependencyRelationCommitmentPayloadV1(
        schema_version=relation.schema_version,
        ordinal=relation.ordinal,
        lane=relation.lane,
        initiator_component=relation.initiator_component,
        initiator_role=relation.initiator_role,
        dependency=relation.dependency,
        dependency_role=relation.dependency_role,
        initiator_delivery_row_sha256=relation.initiator_delivery_row_sha256,
        dependency_identity_commitment_sha256=relation.dependency_identity_commitment_sha256,
        dependency_authority_sha256=relation.dependency_authority_sha256,
        topology_commitment_sha256=relation.topology_commitment_sha256,
        material_policy=relation.material_policy,
        edge_transport_declaration=relation.edge_transport_declaration,
        transport_policy_commitment_sha256=relation.transport_policy_commitment_sha256,
        future_authorizer_admission=relation.future_authorizer_admission,
    )


def _application_dependency_relation_commitment_sha256(
    relation: ApplicationDependencyRelationV1,
) -> str:
    """Hash a structurally checked relation without a self-binding sentinel."""

    payload = _application_dependency_relation_payload(relation)
    return _hash(_DEPENDENCY_RELATION_DOMAIN, payload, limit=8_192)


def _application_dependency_relation_v1_sha256(relation: ApplicationDependencyRelationV1) -> str:
    """Internal commitment check for a matrix-nested relation."""

    try:
        canonical = _strict(relation, ApplicationDependencyRelationV1, limit=8_192)
        canonical.exact_shape()
        return _application_dependency_relation_commitment_sha256(canonical)
    except (RecursionError, TypeError, ValueError):
        _fail("matrix")


def _application_dependency_relation_from_payload(
    payload: _ApplicationDependencyRelationCommitmentPayloadV1,
) -> ApplicationDependencyRelationV1:
    """Construct a final relation only after its nonzero commitment is known."""

    canonical = _strict(
        payload,
        _ApplicationDependencyRelationCommitmentPayloadV1,
        limit=8_192,
    )
    return ApplicationDependencyRelationV1(
        schema_version=canonical.schema_version,
        ordinal=canonical.ordinal,
        lane=canonical.lane,
        initiator_component=canonical.initiator_component,
        initiator_role=canonical.initiator_role,
        dependency=canonical.dependency,
        dependency_role=canonical.dependency_role,
        initiator_delivery_row_sha256=canonical.initiator_delivery_row_sha256,
        dependency_identity_commitment_sha256=canonical.dependency_identity_commitment_sha256,
        dependency_authority_sha256=canonical.dependency_authority_sha256,
        topology_commitment_sha256=canonical.topology_commitment_sha256,
        material_policy=canonical.material_policy,
        edge_transport_declaration=canonical.edge_transport_declaration,
        transport_policy_commitment_sha256=canonical.transport_policy_commitment_sha256,
        relation_commitment_sha256=_hash(
            _DEPENDENCY_RELATION_DOMAIN,
            canonical,
            limit=8_192,
        ),
        future_authorizer_admission=canonical.future_authorizer_admission,
    )


def _route_commitment(route: ContainerTargetDeliveryV1) -> str:
    return _hash(_ROUTE_DOMAIN, route, limit=16_384)


def _topology_commitment(delivery_map: TargetDeliveryMapV1) -> str:
    return _hash(_TOPOLOGY_DOMAIN, delivery_map.topology, limit=16_384)


def _placement_commitment(delivery_map: TargetDeliveryMapV1, component: str) -> str:
    placement = getattr(delivery_map.topology, component)
    return _hash(_PLACEMENT_DOMAIN, placement, limit=4_096)


def _sink_descriptor_sha256(sink: ContainerSecretSinkV1) -> str:
    return _hash(
        _SINK_DOMAIN,
        _SinkDescriptorV1(
            schema_version="rsd.target-delivery-field-matrix-sink-descriptor.v1",
            sink=sink,
            declaration="one_shot_delivery_capability_declaration_v1",
        ),
        limit=1_024,
    )


def _edge_transport_policy_commitment(
    *,
    lane: Literal["primary", "restore"],
    initiator_component: Literal["primary_infisical", "restore_infisical"],
    dependency: Literal[
        "primary_postgresql", "primary_valkey", "restore_postgresql", "restore_valkey"
    ],
    topology_commitment_sha256: str,
) -> str:
    return _hash(
        _EDGE_TRANSPORT_POLICY_DOMAIN,
        _EdgeTransportPolicyCommitmentV1(
            schema_version="rsd.target-delivery-field-matrix-edge-transport-policy.v1",
            lane=lane,
            initiator_component=initiator_component,
            dependency=dependency,
            topology_commitment_sha256=topology_commitment_sha256,
            edge_transport_declaration="per_edge_runtime_proof_required_v1",
        ),
        limit=2_048,
    )


def _provider_reference(delivery_map: TargetDeliveryMapV1, purpose: str) -> ProviderReferenceV1:
    references = delivery_map.provider_references
    values: dict[str, ProviderReferenceV1] = {
        "encryption_key": references.encryption_key,
        "auth_secret": references.auth_secret,
        "postgres_application_password": references.postgres_application_password,
        "primary_valkey_password": references.primary_valkey_password,
        "restore_valkey_password": references.restore_valkey_password,
    }
    return values[purpose]


def _material_policy(
    delivery_map: TargetDeliveryMapV1,
    *,
    purpose: Literal[
        "encryption_key",
        "auth_secret",
        "postgres_application_password",
        "primary_valkey_password",
        "restore_valkey_password",
    ],
) -> ProviderMaterialPolicyV2:
    reference = _provider_reference(delivery_map, purpose)
    fingerprints = {
        item.purpose: item.fingerprint_sha256 for item in delivery_map.material_fingerprints
    }
    format_and_count: dict[str, tuple[str, int]] = {
        "encryption_key": ("infisical_hex_16_v1", 32),
        "auth_secret": ("infisical_auth_secret_base64_32_v1", 44),
        "postgres_application_password": ("postgres_application_password_base64url_32_v1", 43),
        "primary_valkey_password": ("valkey_password_base64url_32_v1", 43),
        "restore_valkey_password": ("valkey_password_base64url_32_v1", 43),
    }
    material_format, encoded_byte_count = format_and_count[purpose]
    return ProviderMaterialPolicyV2(
        schema_version="rsd.target-delivery-field-matrix-provider-material-policy.v2",
        purpose=purpose,
        version=reference.version,
        reference_sha256=reference.reference_sha256,
        fingerprint_sha256=fingerprints[purpose],
        material_format=cast(
            Literal[
                "infisical_hex_16_v1",
                "infisical_auth_secret_base64_32_v1",
                "postgres_application_password_base64url_32_v1",
                "valkey_password_base64url_32_v1",
            ],
            material_format,
        ),
        encoded_byte_count=cast(Literal[32, 43, 44], encoded_byte_count),
    )


def _authority_sha256(
    delivery_map: TargetDeliveryMapV1,
    *,
    lane: Literal["primary", "restore"],
    field: TargetDeliveryFieldV1,
) -> str | None:
    if field.target_field == "DB_CONNECTION_URI":
        if lane == "primary":
            return _sha(delivery_map.database_identities.primary_database.connection_uri.authority)
        return _sha(delivery_map.database_identities.restore_database.connection_uri.authority)
    if field.target_field == "REDIS_URL":
        if lane == "primary":
            return _sha(delivery_map.primary_valkey_connection_uri.authority)
        return _sha(delivery_map.restore_valkey_connection_uri.authority)
    return None


def _group(
    ordinal: int,
) -> Literal[
    "encryption_key_primary_restore_v1",
    "auth_secret_primary_restore_v1",
    "database_uri_primary_restore_v1",
    "primary_valkey_uri_and_requirepass_v1",
    "restore_valkey_uri_and_requirepass_v1",
]:
    groups: dict[int, str] = {
        1: "encryption_key_primary_restore_v1",
        6: "encryption_key_primary_restore_v1",
        2: "auth_secret_primary_restore_v1",
        7: "auth_secret_primary_restore_v1",
        3: "database_uri_primary_restore_v1",
        8: "database_uri_primary_restore_v1",
        4: "primary_valkey_uri_and_requirepass_v1",
        5: "primary_valkey_uri_and_requirepass_v1",
        9: "restore_valkey_uri_and_requirepass_v1",
        10: "restore_valkey_uri_and_requirepass_v1",
    }
    return cast(
        Literal[
            "encryption_key_primary_restore_v1",
            "auth_secret_primary_restore_v1",
            "database_uri_primary_restore_v1",
            "primary_valkey_uri_and_requirepass_v1",
            "restore_valkey_uri_and_requirepass_v1",
        ],
        groups[ordinal],
    )


def _row(
    *,
    ordinal: Literal[1, 2, 3, 4, 5, 6, 7, 8, 9, 10],
    lane: Literal["primary", "restore"],
    route: ContainerTargetDeliveryV1,
    field: TargetDeliveryFieldV1,
    b2_role_ordinal: Literal[0, 1, 2, 3],
    delivery_map: TargetDeliveryMapV1,
) -> TargetDeliveryFieldMatrixRowV1:
    source_kind: Literal["direct_provider_material_v1", "derived_connection_payload_v1"]
    material_policy: ProviderMaterialPolicyV2 | None
    derivation: TargetDeliveryFieldDerivationV1 | None
    if field.target_field in {"DB_CONNECTION_URI", "REDIS_URL"}:
        source_kind = "derived_connection_payload_v1"
        material_policy = None
        derivation = TargetDeliveryFieldDerivationV1(
            schema_version="rsd.target-delivery-field-matrix-derivation.v1",
            derivation_kind=(
                "postgresql_connection_uri_grammar_v1"
                if field.target_field == "DB_CONNECTION_URI"
                else "valkey_connection_uri_grammar_v1"
            ),
            source_material_policy=_material_policy(delivery_map, purpose=field.source_purpose),
            authority_sha256=cast(str, _authority_sha256(delivery_map, lane=lane, field=field)),
            derivation_binding_sha256=field.derivation_binding_sha256,
            derived_payload_format=(
                "derived_postgresql_uri_v1"
                if field.target_field == "DB_CONNECTION_URI"
                else "derived_valkey_uri_v1"
            ),
            derived_payload_encoded_byte_count=field.encoded_byte_count,
        )
    else:
        source_kind = "direct_provider_material_v1"
        material_policy = _material_policy(delivery_map, purpose=field.source_purpose)
        derivation = None
    return TargetDeliveryFieldMatrixRowV1(
        schema_version="rsd.target-delivery-field-matrix-row.v1",
        ordinal=ordinal,
        lane=lane,
        target_component=route.component,
        target_role="valkey" if route.component.endswith("valkey") else "infisical",
        b2_role_ordinal=b2_role_ordinal,
        target_field_ordinal=cast(Literal[1, 2, 3, 4], field.ordinal),
        target_field=field.target_field,
        value_kind=field.value_kind,
        sink=field.sink,
        source_kind=source_kind,
        material_policy=material_policy,
        derivation=derivation,
        route_commitment_sha256=_route_commitment(route),
        sink_descriptor_sha256=_sink_descriptor_sha256(field.sink),
        shared_reference_group=_group(ordinal),
        declaration="one_shot_delivery_capability_declaration_v1",
    )


def _expected_rows(
    delivery_map: TargetDeliveryMapV1,
) -> tuple[
    TargetDeliveryFieldMatrixRowV1,
    TargetDeliveryFieldMatrixRowV1,
    TargetDeliveryFieldMatrixRowV1,
    TargetDeliveryFieldMatrixRowV1,
    TargetDeliveryFieldMatrixRowV1,
    TargetDeliveryFieldMatrixRowV1,
    TargetDeliveryFieldMatrixRowV1,
    TargetDeliveryFieldMatrixRowV1,
    TargetDeliveryFieldMatrixRowV1,
    TargetDeliveryFieldMatrixRowV1,
]:
    primary_infisical = delivery_map.primary_infisical
    primary_valkey = delivery_map.primary_valkey
    restore_infisical = delivery_map.restore_infisical
    restore_valkey = delivery_map.restore_valkey
    return cast(
        tuple[
            TargetDeliveryFieldMatrixRowV1,
            TargetDeliveryFieldMatrixRowV1,
            TargetDeliveryFieldMatrixRowV1,
            TargetDeliveryFieldMatrixRowV1,
            TargetDeliveryFieldMatrixRowV1,
            TargetDeliveryFieldMatrixRowV1,
            TargetDeliveryFieldMatrixRowV1,
            TargetDeliveryFieldMatrixRowV1,
            TargetDeliveryFieldMatrixRowV1,
            TargetDeliveryFieldMatrixRowV1,
        ],
        (
            *(
                _row(
                    ordinal=cast(Literal[1, 2, 3, 4, 5, 6, 7, 8, 9, 10], ordinal),
                    lane="primary",
                    route=primary_infisical,
                    field=field,
                    b2_role_ordinal=0,
                    delivery_map=delivery_map,
                )
                for ordinal, field in enumerate(primary_infisical.fields, start=1)
            ),
            _row(
                ordinal=5,
                lane="primary",
                route=primary_valkey,
                field=primary_valkey.fields[0],
                b2_role_ordinal=1,
                delivery_map=delivery_map,
            ),
            *(
                _row(
                    ordinal=cast(Literal[1, 2, 3, 4, 5, 6, 7, 8, 9, 10], ordinal),
                    lane="restore",
                    route=restore_infisical,
                    field=field,
                    b2_role_ordinal=2,
                    delivery_map=delivery_map,
                )
                for ordinal, field in enumerate(restore_infisical.fields, start=6)
            ),
            _row(
                ordinal=10,
                lane="restore",
                route=restore_valkey,
                field=restore_valkey.fields[0],
                b2_role_ordinal=3,
                delivery_map=delivery_map,
            ),
        ),
    )


def _expected_dependencies(
    delivery_map: TargetDeliveryMapV1,
    rows: tuple[
        TargetDeliveryFieldMatrixRowV1,
        TargetDeliveryFieldMatrixRowV1,
        TargetDeliveryFieldMatrixRowV1,
        TargetDeliveryFieldMatrixRowV1,
        TargetDeliveryFieldMatrixRowV1,
        TargetDeliveryFieldMatrixRowV1,
        TargetDeliveryFieldMatrixRowV1,
        TargetDeliveryFieldMatrixRowV1,
        TargetDeliveryFieldMatrixRowV1,
        TargetDeliveryFieldMatrixRowV1,
    ],
) -> tuple[
    ApplicationDependencyRelationV1,
    ApplicationDependencyRelationV1,
    ApplicationDependencyRelationV1,
    ApplicationDependencyRelationV1,
]:
    primary_database = delivery_map.database_identities.primary_database
    restore_database = delivery_map.database_identities.restore_database
    topology_hash = _topology_commitment(delivery_map)

    def relation(
        *,
        ordinal: Literal[1, 2, 3, 4],
        lane: Literal["primary", "restore"],
        dependency: Literal[
            "primary_postgresql",
            "primary_valkey",
            "restore_postgresql",
            "restore_valkey",
        ],
        dependency_role: Literal["postgresql", "valkey"],
        row: TargetDeliveryFieldMatrixRowV1,
        identity: str,
        authority: str,
    ) -> ApplicationDependencyRelationV1:
        initiator_component: Literal["primary_infisical", "restore_infisical"] = (
            "primary_infisical" if lane == "primary" else "restore_infisical"
        )
        payload = _ApplicationDependencyRelationCommitmentPayloadV1(
            schema_version="rsd.application-dependency-relation.v1",
            ordinal=ordinal,
            lane=lane,
            initiator_component=initiator_component,
            initiator_role="infisical",
            dependency=dependency,
            dependency_role=dependency_role,
            initiator_delivery_row_sha256=_target_delivery_field_matrix_row_v1_sha256(row),
            dependency_identity_commitment_sha256=identity,
            dependency_authority_sha256=authority,
            topology_commitment_sha256=topology_hash,
            material_policy=cast(
                TargetDeliveryFieldDerivationV1, row.derivation
            ).source_material_policy,
            edge_transport_declaration="per_edge_runtime_proof_required_v1",
            transport_policy_commitment_sha256=_edge_transport_policy_commitment(
                lane=lane,
                initiator_component=initiator_component,
                dependency=dependency,
                topology_commitment_sha256=topology_hash,
            ),
            future_authorizer_admission="declared_directed_edge_only_v1",
        )
        return _application_dependency_relation_from_payload(payload)

    return (
        relation(
            ordinal=1,
            lane="primary",
            dependency="primary_postgresql",
            dependency_role="postgresql",
            row=rows[2],
            identity=primary_database.observation_binding_sha256,
            authority=cast(TargetDeliveryFieldDerivationV1, rows[2].derivation).authority_sha256,
        ),
        relation(
            ordinal=2,
            lane="primary",
            dependency="primary_valkey",
            dependency_role="valkey",
            row=rows[3],
            identity=_placement_commitment(delivery_map, "primary_valkey"),
            authority=cast(TargetDeliveryFieldDerivationV1, rows[3].derivation).authority_sha256,
        ),
        relation(
            ordinal=3,
            lane="restore",
            dependency="restore_postgresql",
            dependency_role="postgresql",
            row=rows[7],
            identity=restore_database.observation_binding_sha256,
            authority=cast(TargetDeliveryFieldDerivationV1, rows[7].derivation).authority_sha256,
        ),
        relation(
            ordinal=4,
            lane="restore",
            dependency="restore_valkey",
            dependency_role="valkey",
            row=rows[8],
            identity=_placement_commitment(delivery_map, "restore_valkey"),
            authority=cast(TargetDeliveryFieldDerivationV1, rows[8].derivation).authority_sha256,
        ),
    )


def _check_identity_separation(
    *,
    delivery_map: TargetDeliveryMapV1,
    b1_policy: TargetDeliveryMapProjectionBindingTrustPolicyV1,
    b2_anchor: TargetDeliveryArtifactManifestTrustAnchorV1,
    role_inputs: tuple[
        TargetDeliveryArtifactManifestRoleInputV2,
        TargetDeliveryArtifactManifestRoleInputV2,
        TargetDeliveryArtifactManifestRoleInputV2,
        TargetDeliveryArtifactManifestRoleInputV2,
    ],
    v5_role_policy_inputs: tuple[
        TargetDeliveryArtifactManifestV5RolePolicyInputV2,
        TargetDeliveryArtifactManifestV5RolePolicyInputV2,
        TargetDeliveryArtifactManifestV5RolePolicyInputV2,
        TargetDeliveryArtifactManifestV5RolePolicyInputV2,
    ],
    manifest: TargetDeliveryArtifactManifestV2,
    matrix_policy: TargetDeliveryFieldMatrixPolicyV1,
    matrix_anchor: TargetDeliveryFieldMatrixTrustAnchorV1,
    matrix: TargetDeliveryFieldMatrixV1,
) -> None:
    """Separate identities while retaining explicit map-material sharing only.

    Artifact and content commitments deliberately stay out of this registry.
    Physical builders are tracked separately: their reuse is permitted, but
    they may never become a protected root, authority, policy, run, or
    material-reference identity.
    """

    protected: set[str] = set()
    builders: set[str] = set()
    material_identities: set[str] = set()
    material_owners: dict[str, str] = {}

    def register_protected(*values: str) -> None:
        if (
            not values
            or any(type(value) is not str for value in values)
            or len(set(values)) != len(values)
            or any(value in protected for value in values)
            or any(value in builders or value in material_identities for value in values)
        ):
            raise ValueError("identity namespace collision")
        protected.update(values)

    def register_builder(*values: str) -> None:
        """Allow builder reuse only inside the physical-builder category."""

        if (
            not values
            or any(type(value) is not str for value in values)
            or any(value in protected or value in material_identities for value in values)
        ):
            raise ValueError("identity namespace collision")
        builders.update(values)

    def register_material_identity(owner: str, *values: str) -> None:
        if (
            type(owner) is not str
            or not values
            or any(type(value) is not str for value in values)
            or len(set(values)) != len(values)
            or any(value in protected or value in builders for value in values)
            or any(
                previous is not None and previous != owner
                for value in values
                for previous in (material_owners.get(value),)
            )
        ):
            raise ValueError("identity namespace collision")
        material_identities.update(values)
        material_owners.update({value: owner for value in values})

    expected_materials: dict[str, ProviderMaterialPolicyV2] = {
        "encryption_key": _material_policy(delivery_map, purpose="encryption_key"),
        "auth_secret": _material_policy(delivery_map, purpose="auth_secret"),
        "postgres_application_password": _material_policy(
            delivery_map, purpose="postgres_application_password"
        ),
        "primary_valkey_password": _material_policy(
            delivery_map, purpose="primary_valkey_password"
        ),
        "restore_valkey_password": _material_policy(
            delivery_map, purpose="restore_valkey_password"
        ),
    }

    map_anchor = b1_policy.map_signer_trust_anchor
    binding_anchor = b1_policy.binding_trust_anchor
    profile_anchor = b1_policy.profile_trust_anchor
    legacy_policy = b1_policy.phase_a_worker_trust_policy
    register_protected(
        manifest.b1_policy_sha256,
        b1_policy.policy_id,
        map_anchor.key_id,
        map_anchor.public_key_base64,
        map_anchor.public_key_fingerprint_sha256,
        b1_policy.map_authority_identity_sha256,
        b1_policy.map_independence_domain_identity_sha256,
        binding_anchor.key_id,
        binding_anchor.public_key_base64,
        binding_anchor.public_key_fingerprint_sha256,
        binding_anchor.authority_identity_sha256,
        binding_anchor.independence_domain_identity_sha256,
        profile_anchor.key_id,
        profile_anchor.public_key_base64,
        profile_anchor.public_key_fingerprint_sha256,
        legacy_policy.policy_id,
        legacy_policy.independence_domain_sha256,
        b2_anchor.key_id,
        b2_anchor.public_key_base64,
        b2_anchor.public_key_fingerprint_sha256,
        b2_anchor.authority_identity_sha256,
        b2_anchor.independence_domain_identity_sha256,
    )
    for worker in legacy_policy.worker_trust_anchors:
        register_protected(
            worker.key_id,
            worker.public_key_base64,
            worker.public_key_fingerprint_sha256,
            worker.worker_identity_sha256,
            worker.authority_identity_sha256,
        )

    reusable_profile_roots: set[tuple[str, str, str]] = set()
    for role_input in role_inputs:
        profile = role_input.profile_envelope.static_role_profile
        for root in (profile.ticket_trust_anchor, profile.replay_receipt_trust_anchor):
            root_values = (root.key_id, root.public_key_base64, root.public_key_fingerprint_sha256)
            if root_values not in reusable_profile_roots:
                register_protected(*root_values)
                reusable_profile_roots.add(root_values)

    material_owner_by_reference = {
        material.reference_sha256: purpose for purpose, material in expected_materials.items()
    }
    for index, reference in enumerate(delivery_map.provider_references.all()):
        register_material_identity(
            material_owner_by_reference.get(
                reference.reference_sha256, f"upstream-reference-{index}"
            ),
            reference.reference_sha256,
        )
    for fingerprint in delivery_map.material_fingerprints:
        register_material_identity(
            fingerprint.purpose,
            fingerprint.reference_sha256,
            fingerprint.fingerprint_sha256,
        )

    for role_input, policy_input in zip(role_inputs, v5_role_policy_inputs, strict=True):
        policy = policy_input.worker_trust_policy
        register_protected(
            container_bootstrap_build_worker_trust_policy_v5_sha256(policy),
            policy.policy_id,
            policy.independence_domain_sha256,
        )
        for v5_worker in policy.worker_trust_anchors:
            register_protected(
                v5_worker.key_id,
                v5_worker.public_key_base64,
                v5_worker.public_key_fingerprint_sha256,
                v5_worker.worker_identity_sha256,
                v5_worker.authority_identity_sha256,
            )
            register_builder(v5_worker.physical_builder_identity_sha256)
        for attestation in role_input.phase_a_v5_closure.worker_attestations:
            register_protected(attestation.run_id)
            register_builder(attestation.physical_builder_identity_sha256)

    register_protected(
        target_delivery_field_matrix_policy_v1_sha256(matrix_policy),
        matrix_policy.policy_id,
        matrix_policy.policy_identity_sha256,
        matrix_policy.reference_authority_identity_sha256,
        matrix_policy.topology_authority_identity_sha256,
        matrix_anchor.key_id,
        matrix_anchor.public_key_base64,
        matrix_anchor.public_key_fingerprint_sha256,
        matrix_anchor.authority_identity_sha256,
        matrix_anchor.independence_domain_identity_sha256,
    )

    material_policies: list[ProviderMaterialPolicyV2] = []
    for row in matrix.rows:
        if row.material_policy is not None:
            material_policies.append(row.material_policy)
        elif row.derivation is not None:
            material_policies.append(row.derivation.source_material_policy)
        else:
            raise ValueError("identity namespace collision")
    material_policies.extend(
        relation.material_policy for relation in matrix.application_dependencies
    )
    for material in material_policies:
        expected = expected_materials.get(material.purpose)
        if type(material) is not ProviderMaterialPolicyV2:
            raise ValueError("identity namespace collision")
        register_material_identity(
            material.purpose, material.reference_sha256, material.fingerprint_sha256
        )
        if material != expected:
            raise ValueError("identity namespace collision")


def validate_target_delivery_field_matrix_v1(
    *,
    delivery_map: TargetDeliveryMapV1,
    static_delivery_projection: ContainerBootstrapStaticDeliveryProjectionV4,
    b1_trust_policy: TargetDeliveryMapProjectionBindingTrustPolicyV1,
    manifest_trust_anchor: TargetDeliveryArtifactManifestTrustAnchorV1,
    role_inputs: tuple[
        TargetDeliveryArtifactManifestRoleInputV2,
        TargetDeliveryArtifactManifestRoleInputV2,
        TargetDeliveryArtifactManifestRoleInputV2,
        TargetDeliveryArtifactManifestRoleInputV2,
    ],
    v5_role_policy_inputs: tuple[
        TargetDeliveryArtifactManifestV5RolePolicyInputV2,
        TargetDeliveryArtifactManifestV5RolePolicyInputV2,
        TargetDeliveryArtifactManifestV5RolePolicyInputV2,
        TargetDeliveryArtifactManifestV5RolePolicyInputV2,
    ],
    manifest: TargetDeliveryArtifactManifestV2,
    matrix_policy: TargetDeliveryFieldMatrixPolicyV1,
    matrix_trust_anchor: TargetDeliveryFieldMatrixTrustAnchorV1,
    matrix: TargetDeliveryFieldMatrixV1,
) -> TargetDeliveryFieldMatrixAcceptanceV1:
    """The only C0 source/context/authentication boundary.

    This revalidates original B2 V2 inputs, checks identity separation and the
    caller-pinned matrix signature, then returns a diagnostic whose effect
    permissions remain false.  Canonical, parser, message, and hash helpers
    do none of those evidence or authorization checks.

    The deliberately absent ``acceptance`` parameter prevents a B2/V5
    diagnostic from becoming an authority or a validation back-edge.
    """

    try:
        if (
            type(matrix_policy) is not TargetDeliveryFieldMatrixPolicyV1
            or type(matrix_trust_anchor) is not TargetDeliveryFieldMatrixTrustAnchorV1
            or type(matrix) is not TargetDeliveryFieldMatrixV1
        ):
            raise ValueError("matrix type is invalid")
        matrix_policy = _strict(
            matrix_policy, TargetDeliveryFieldMatrixPolicyV1, limit=_MAX_POLICY_BYTES
        )
        matrix_trust_anchor = _strict(
            matrix_trust_anchor, TargetDeliveryFieldMatrixTrustAnchorV1, limit=_MAX_ANCHOR_BYTES
        )
        matrix = _strict(matrix, TargetDeliveryFieldMatrixV1, limit=_MAX_MATRIX_BYTES)
    except (AttributeError, RecursionError, TypeError, ValueError):
        _fail("anchor")

    try:
        if (
            type(delivery_map) is not TargetDeliveryMapV1
            or type(static_delivery_projection) is not ContainerBootstrapStaticDeliveryProjectionV4
            or type(b1_trust_policy) is not TargetDeliveryMapProjectionBindingTrustPolicyV1
            or type(manifest_trust_anchor) is not TargetDeliveryArtifactManifestTrustAnchorV1
            or type(role_inputs) is not tuple
            or len(role_inputs) != 4
            or any(
                type(item) is not TargetDeliveryArtifactManifestRoleInputV2 for item in role_inputs
            )
            or type(v5_role_policy_inputs) is not tuple
            or len(v5_role_policy_inputs) != 4
            or any(
                type(item) is not TargetDeliveryArtifactManifestV5RolePolicyInputV2
                for item in v5_role_policy_inputs
            )
            or type(manifest) is not TargetDeliveryArtifactManifestV2
        ):
            raise ValueError("input type is invalid")
        _exact_model_state(delivery_map, TargetDeliveryMapV1)
        _exact_model_state(
            static_delivery_projection,
            ContainerBootstrapStaticDeliveryProjectionV4,
        )
        _exact_model_state(
            b1_trust_policy,
            TargetDeliveryMapProjectionBindingTrustPolicyV1,
        )
        _exact_model_state(
            manifest_trust_anchor,
            TargetDeliveryArtifactManifestTrustAnchorV1,
        )
        for role_input in role_inputs:
            _exact_model_state(role_input, TargetDeliveryArtifactManifestRoleInputV2)
        for policy_input in v5_role_policy_inputs:
            _exact_model_state(
                policy_input,
                TargetDeliveryArtifactManifestV5RolePolicyInputV2,
            )
        _exact_model_state(manifest, TargetDeliveryArtifactManifestV2)
    except (AttributeError, RecursionError, TypeError, ValueError):
        _fail("input")

    try:
        validate_target_delivery_artifact_manifest_v2(
            delivery_map=delivery_map,
            static_delivery_projection=static_delivery_projection,
            b1_trust_policy=b1_trust_policy,
            manifest_trust_anchor=manifest_trust_anchor,
            role_inputs=role_inputs,
            v5_role_policy_inputs=v5_role_policy_inputs,
            manifest=manifest,
        )
        canonical_map = verify_target_delivery_map_v1_signature(
            delivery_map=delivery_map,
            signer_trust_anchor=b1_trust_policy.map_signer_trust_anchor,
        )
    except (AttributeError, RecursionError, TypeError, ValueError):
        _fail("input")

    try:
        _check_identity_separation(
            delivery_map=canonical_map,
            b1_policy=b1_trust_policy,
            b2_anchor=manifest_trust_anchor,
            role_inputs=role_inputs,
            v5_role_policy_inputs=v5_role_policy_inputs,
            manifest=manifest,
            matrix_policy=matrix_policy,
            matrix_anchor=matrix_trust_anchor,
            matrix=matrix,
        )
    except (AttributeError, RecursionError, TypeError, ValueError):
        _fail("anchor")

    try:
        rows = _expected_rows(canonical_map)
        dependencies = _expected_dependencies(canonical_map, rows)
        manifest_hash = target_delivery_artifact_manifest_v2_sha256(manifest)
        expected = TargetDeliveryFieldMatrixV1(
            schema_version="rsd.target-delivery-field-matrix.v1",
            signature_algorithm="ed25519",
            matrix_policy_sha256=target_delivery_field_matrix_policy_v1_sha256(matrix_policy),
            target_delivery_map_sha256=target_delivery_map_sha256(canonical_map),
            static_delivery_projection_sha256=manifest.static_delivery_projection_sha256,
            target_delivery_artifact_manifest_sha256=manifest_hash,
            source_snapshot_sha256=manifest.source.source_snapshot_sha256,
            oci_repository_sha256=_sha(manifest.derived_oci_repository),
            topology_commitment_sha256=_topology_commitment(canonical_map),
            rows=rows,
            application_dependencies=dependencies,
            signer_key_id=matrix_trust_anchor.key_id,
            signer_fingerprint_sha256=matrix_trust_anchor.public_key_fingerprint_sha256,
            signature_base64=matrix.signature_base64,
            non_authorizing=True,
            delivery_allowed=False,
            network_allowed=False,
            build_allowed=False,
            pull_allowed=False,
            materialization_allowed=False,
            attach_allowed=False,
            effect_allowed=False,
        )
        if matrix != expected:
            raise ValueError("matrix differs from original evidence")
        Ed25519PublicKey.from_public_bytes(_b64(matrix_trust_anchor.public_key_base64)).verify(
            _b64(matrix.signature_base64), target_delivery_field_matrix_v1_message(matrix)
        )
    except (InvalidSignature, RecursionError, TypeError, ValueError):
        _fail("matrix")

    return TargetDeliveryFieldMatrixAcceptanceV1(
        schema_version="rsd.target-delivery-field-matrix-acceptance.v1",
        matrix_sha256=target_delivery_field_matrix_v1_sha256(matrix),
        verification_context_sha256=hashlib.sha256(
            _MATRIX_CONTEXT_DOMAIN
            + matrix_trust_anchor.public_key_fingerprint_sha256.encode("ascii")
            + target_delivery_field_matrix_policy_v1_sha256(matrix_policy).encode("ascii")
            + manifest_hash.encode("ascii")
            + target_delivery_map_sha256(canonical_map).encode("ascii")
        ).hexdigest(),
        target_delivery_map_sha256=target_delivery_map_sha256(canonical_map),
        target_delivery_artifact_manifest_sha256=manifest_hash,
        row_sha256s=cast(
            tuple[str, str, str, str, str, str, str, str, str, str],
            tuple(_target_delivery_field_matrix_row_v1_sha256(row) for row in rows),
        ),
        application_dependency_ordinals=(1, 2, 3, 4),
        non_authorizing=True,
        delivery_allowed=False,
        network_allowed=False,
        build_allowed=False,
        pull_allowed=False,
        materialization_allowed=False,
        attach_allowed=False,
        effect_allowed=False,
    )
