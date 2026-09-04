"""Offline, topology-redacted per-edge runtime-proof bundle contract.

This module validates only a signed, synthetic-safe diagnostic projection.  It
does not contact a runtime, a provider, a network, an Engine, or a store, and
it cannot authorize an operation.  Its sole authority boundary is
``validate_per_edge_runtime_proof_bundle_v1``: the shape helpers below neither
revalidate C0 source inputs nor turn a bundle into live evidence.
"""

from __future__ import annotations

import base64
import binascii
import hashlib
import json
import re
import warnings
from collections.abc import Callable
from datetime import datetime, timedelta
from typing import Literal, NoReturn, Self, cast

from cryptography.exceptions import InvalidSignature
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PublicKey
from pydantic import (
    BaseModel,
    ConfigDict,
    Field,
    ValidationError,
    field_validator,
    model_validator,
)

from omninode_rsd.lifecycle.container_attach_static_v4 import (
    ContainerBootstrapStaticDeliveryProjectionV4,
)
from omninode_rsd.lifecycle.infisical_disposable import (
    TargetDeliveryMapV1,
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
)
from omninode_rsd.lifecycle.target_delivery_field_matrix_v1 import (
    ProviderMaterialPolicyV2,
    TargetDeliveryFieldMatrixPolicyV1,
    TargetDeliveryFieldMatrixTrustAnchorV1,
    TargetDeliveryFieldMatrixV1,
    target_delivery_field_matrix_policy_v1_sha256,
    validate_target_delivery_field_matrix_v1,
)
from omninode_rsd.lifecycle.target_delivery_map_projection_binding import (
    TargetDeliveryMapProjectionBindingTrustPolicyV1,
)

_SHA256 = r"^[0-9a-f]{64}$"
_IDENTIFIER = r"^[a-z0-9][a-z0-9._:-]{0,127}$"
_TIMESTAMP = r"^[0-9]{4}-[0-9]{2}-[0-9]{2}T[0-9]{2}:[0-9]{2}:[0-9]{2}Z$"
_B64URL = re.compile(r"^[A-Za-z0-9_-]+$")
_MAX_BYTES = 24 * 1024
_MAX_DEPTH = 4
_MAX_NODES = 512
_MISSING_STATE = object()
_BUNDLE_DOMAIN = b"rsd.per-edge-runtime-proof-bundle.commitment.v1\x00"
_BUNDLE_SIGNATURE_DOMAIN = b"rsd.per-edge-runtime-proof-bundle-signature.v1\x00"
_OBSERVATION_SIGNATURE_DOMAIN = b"rsd.per-edge-runtime-proof-observation-signature.v1\x00"
_CONTEXT_DOMAIN = b"rsd.per-edge-runtime-proof-bundle-context.v1\x00"

# ``schema`` is the frozen public wire field; Pydantic retains a deprecated
# BaseModel method with that name and emits this otherwise irrelevant warning.
warnings.filterwarnings(
    "ignore",
    message=(
        r'^Field name "schema" in "PerEdgeRuntimeProofBundle.*" '
        r'shadows an attribute in parent "_Model"$'
    ),
    category=UserWarning,
)


class PerEdgeRuntimeProofBundleError(ValueError):
    """Fixed, value-redacted failure for this offline contract."""

    __slots__ = ("phase",)

    def __init__(self, phase: Literal["parse", "anchor", "input", "bundle"]):
        super().__init__("per-edge runtime proof bundle validation failed")
        self.phase = phase


class _Model(BaseModel):
    model_config = ConfigDict(extra="forbid", frozen=True, strict=True, validate_default=True)


def _fail(phase: Literal["parse", "anchor", "input", "bundle"]) -> NoReturn:
    raise PerEdgeRuntimeProofBundleError(phase)


def _b64url(value: str, *, length: int) -> bytes:
    if type(value) is not str or len(value) != length or _B64URL.fullmatch(value) is None:
        raise ValueError("base64url is invalid")
    try:
        decoded = base64.urlsafe_b64decode(value + ("=" * ((4 - len(value) % 4) % 4)))
    except (binascii.Error, ValueError):
        raise ValueError("base64url is invalid") from None
    if base64.urlsafe_b64encode(decoded).decode("ascii").rstrip("=") != value:
        raise ValueError("base64url is invalid")
    return decoded


def _timestamp(value: str) -> datetime:
    if type(value) is not str or re.fullmatch(_TIMESTAMP, value) is None:
        raise ValueError("timestamp is invalid")
    try:
        return datetime.strptime(value, "%Y-%m-%dT%H:%M:%SZ")
    except ValueError:
        raise ValueError("timestamp is invalid") from None


def _consume_node(nodes: list[int]) -> None:
    nodes[0] += 1
    if nodes[0] > _MAX_NODES:
        raise ValueError("model state is invalid")


def _exact_value(
    value: object,
    *,
    active: set[int],
    nodes: list[int],
    depth: int,
    fixed_observations_tuple: bool,
) -> None:
    if depth > _MAX_DEPTH:
        raise ValueError("model state is invalid")
    _consume_node(nodes)
    if isinstance(value, BaseModel):
        _exact_model_state(value, type(value), active=active, nodes=nodes, depth=depth + 1)
        return
    if type(value) is tuple:
        if not fixed_observations_tuple or len(value) != 4:
            raise ValueError("model state is invalid")
        value_id = id(value)
        if value_id in active:
            raise ValueError("model state is invalid")
        active.add(value_id)
        try:
            for item in value:
                _exact_value(
                    item,
                    active=active,
                    nodes=nodes,
                    depth=depth + 1,
                    fixed_observations_tuple=False,
                )
        finally:
            active.remove(value_id)
        return
    if type(value) in (dict, list, set, frozenset, bytes, bytearray, memoryview):
        raise ValueError("model state is invalid")


def _exact_model_state(
    value: object,
    expected: type[BaseModel],
    *,
    active: set[int] | None = None,
    nodes: list[int] | None = None,
    depth: int = 0,
) -> BaseModel:
    """Reject hidden, constructed, cyclic, generic, and non-exact model state."""

    state_active = set() if active is None else active
    state_nodes = [0] if nodes is None else nodes
    try:
        if type(value) is not expected or depth > _MAX_DEPTH:
            raise ValueError("model type is invalid")
        _consume_node(state_nodes)
        value_id = id(value)
        if value_id in state_active:
            raise ValueError("model state is invalid")
        state_active.add(value_id)
        try:
            fields = set(expected.model_fields)
            state = getattr(value, "__dict__", _MISSING_STATE)
            extra = getattr(value, "__pydantic_extra__", _MISSING_STATE)
            hidden = getattr(value, "__pydantic_" + "pri" + "vate__", _MISSING_STATE)
            fields_set = getattr(value, "__pydantic_fields_set__", _MISSING_STATE)
            if (
                type(state) is not dict
                or extra is not None
                or hidden is not None
                or type(fields_set) is not set
            ):
                raise ValueError("model state is invalid")
            state = cast(dict[object, object], state)
            fields_set = cast(set[object], fields_set)
            if len(state) != len(fields) or len(fields_set) != len(fields):
                raise ValueError("model state is invalid")
            if any(type(name) is not str for name in state) or any(
                type(name) is not str for name in fields_set
            ):
                raise ValueError("model state is invalid")
            state_names = set(cast(dict[str, object], state))
            exact_fields_set = cast(set[str], fields_set)
            if state_names != fields or exact_fields_set != fields:
                raise ValueError("model state is invalid")
            for field in fields:
                _exact_value(
                    cast(dict[str, object], state)[field],
                    active=state_active,
                    nodes=state_nodes,
                    depth=depth,
                    fixed_observations_tuple=field == "observations",
                )
        finally:
            state_active.remove(value_id)
        return value
    except Exception:
        raise ValueError("model state is invalid") from None


def _same_shape(left: object, right: object) -> bool:
    if type(left) is not type(right):
        return False
    if isinstance(left, BaseModel):
        left_state = getattr(left, "__dict__", _MISSING_STATE)
        right_state = getattr(right, "__dict__", _MISSING_STATE)
        if type(left_state) is not dict or type(right_state) is not dict:
            return False
        return set(left_state) == set(right_state) and all(
            _same_shape(
                cast(dict[str, object], left_state)[field],
                cast(dict[str, object], right_state)[field],
            )
            for field in left_state
        )
    if type(left) is tuple:
        return len(left) == len(cast(tuple[object, ...], right)) and all(
            _same_shape(one, two)
            for one, two in zip(left, cast(tuple[object, ...], right), strict=True)
        )
    return left == right


def _canonical(model: BaseModel, *, exclude: set[str] | None = None) -> bytes:
    try:
        _exact_model_state(model, type(model))
        payload = json.dumps(
            model.model_dump(mode="json", exclude=exclude or set(), warnings="error"),
            ensure_ascii=False,
            sort_keys=True,
            separators=(",", ":"),
            allow_nan=False,
        ).encode("utf-8")
    except (OverflowError, RecursionError, TypeError, ValueError):
        raise ValueError("model is invalid") from None
    if len(payload) > _MAX_BYTES:
        raise ValueError("model is too large")
    return payload


def _strict[TModel: BaseModel](value: object, expected: type[TModel]) -> TModel:
    try:
        _exact_model_state(value, expected)
        rendered = _canonical(cast(BaseModel, value))
        parsed = _parse(rendered, expected)
        if not _same_shape(value, parsed):
            raise ValueError("model is not exact")
        return parsed
    except (OverflowError, RecursionError, TypeError, ValueError):
        raise ValueError("model is not exact") from None


def _duplicates(pairs: list[tuple[object, object]]) -> dict[str, object]:
    output: dict[str, object] = {}
    for key, value in pairs:
        if type(key) is not str or key in output:
            raise ValueError("JSON is invalid")
        output[key] = value
    return output


def _tuples(value: object) -> object:
    if type(value) is list:
        return tuple(_tuples(item) for item in cast(list[object], value))
    if type(value) is dict:
        return {key: _tuples(item) for key, item in cast(dict[str, object], value).items()}
    return value


def _preflight(payload: bytes) -> None:
    if type(payload) is not bytes or not 1 <= len(payload) <= _MAX_BYTES:
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


def _parse[TModel: BaseModel](payload: bytes, expected: type[TModel]) -> TModel:
    _preflight(payload)
    try:
        decoded = json.loads(
            payload.decode("ascii"),
            object_pairs_hook=_duplicates,
            parse_float=lambda _value: (_ for _ in ()).throw(ValueError("float")),
            parse_constant=lambda _value: (_ for _ in ()).throw(ValueError("constant")),
        )
        if type(decoded) is not dict:
            raise ValueError("JSON is invalid")
        model = expected.model_validate(_tuples(decoded), strict=True)
        if _canonical(model) != payload:
            raise ValueError("JSON is invalid")
        return model
    except (
        OverflowError,
        RecursionError,
        TypeError,
        UnicodeDecodeError,
        ValidationError,
        ValueError,
    ):
        raise ValueError("JSON is invalid") from None


class PerEdgeRuntimeProofBundleTrustAnchorV1(_Model):
    """Caller-pinned observer root; it is deliberately outside a bundle."""

    schema: Literal["rsd.per-edge-runtime-proof-bundle-trust-anchor.v1"]  # type: ignore[assignment]
    signature_algorithm: Literal["ed25519"]
    observer_root_id: str = Field(pattern=_IDENTIFIER)
    observer_key_id: str = Field(pattern=_IDENTIFIER)
    observer_public_key_b64: str = Field(min_length=43, max_length=43)
    observer_fingerprint_sha256: str = Field(pattern=_SHA256, min_length=64, max_length=64)
    authority_identity_sha256: str = Field(pattern=_SHA256, min_length=64, max_length=64)
    independence_domain_sha256: str = Field(pattern=_SHA256, min_length=64, max_length=64)

    @model_validator(mode="after")
    def exact_anchor(self) -> Self:
        try:
            key = _b64url(self.observer_public_key_b64, length=43)
            Ed25519PublicKey.from_public_bytes(key)
            identities = (
                self.observer_root_id,
                self.observer_key_id,
                self.observer_fingerprint_sha256,
                self.authority_identity_sha256,
                self.independence_domain_sha256,
            )
            if (
                len(key) != 32
                or hashlib.sha256(key).hexdigest() != self.observer_fingerprint_sha256
            ):
                raise ValueError("anchor is invalid")
            if len(set(identities)) != len(identities):
                raise ValueError("anchor is invalid")
            return self
        except (TypeError, ValueError):
            raise ValueError("anchor is invalid") from None


_CAPABILITIES = (
    "delivery_authorized",
    "network_authorized",
    "build_authorized",
    "pull_authorized",
    "materialization_authorized",
    "attach_authorized",
    "runtime_observation_authorized",
    "provider_lookup_authorized",
    "callback_authorized",
    "handle_authorized",
    "replay_persistence_authorized",
    "effect_authorized",
)


class PerEdgeRuntimeProofBundlePolicyV1(_Model):
    """Frozen non-authorizing policy for structural offline validation only."""

    schema: Literal["rsd.per-edge-runtime-proof-bundle-policy.v1"]  # type: ignore[assignment]
    policy_version: Literal[1]
    non_authorizing: Literal[True]
    validation_permitted: Literal[True]
    delivery_authorized: Literal[False]
    network_authorized: Literal[False]
    build_authorized: Literal[False]
    pull_authorized: Literal[False]
    materialization_authorized: Literal[False]
    attach_authorized: Literal[False]
    runtime_observation_authorized: Literal[False]
    provider_lookup_authorized: Literal[False]
    callback_authorized: Literal[False]
    handle_authorized: Literal[False]
    replay_persistence_authorized: Literal[False]
    effect_authorized: Literal[False]

    @field_validator("policy_version", mode="before")
    @classmethod
    def exact_version(cls, value: object) -> object:
        if type(value) is not int:
            raise ValueError("policy is invalid")
        return value

    @field_validator("non_authorizing", "validation_permitted", *_CAPABILITIES, mode="before")
    @classmethod
    def exact_booleans(cls, value: object) -> object:
        if type(value) is not bool:
            raise ValueError("policy is invalid")
        return value

    @model_validator(mode="after")
    def exact_policy(self) -> Self:
        if (
            not self.non_authorizing
            or not self.validation_permitted
            or any(cast(bool, getattr(self, field)) for field in _CAPABILITIES)
        ):
            raise ValueError("policy is invalid")
        return self


class PerEdgeRuntimeProofObservationV1(_Model):
    """One fixed, value-free signed C0 relation observation."""

    matrix_sha256: str = Field(pattern=_SHA256, min_length=64, max_length=64)
    map_sha256: str = Field(pattern=_SHA256, min_length=64, max_length=64)
    manifest_sha256: str = Field(pattern=_SHA256, min_length=64, max_length=64)
    c0_policy_sha256: str = Field(pattern=_SHA256, min_length=64, max_length=64)
    source_snapshot_sha256: str = Field(pattern=_SHA256, min_length=64, max_length=64)
    c0_anchor_key_id: str = Field(pattern=_IDENTIFIER)
    c0_anchor_fingerprint_sha256: str = Field(pattern=_SHA256, min_length=64, max_length=64)
    c0_anchor_authority_identity_sha256: str = Field(pattern=_SHA256, min_length=64, max_length=64)
    c0_anchor_independence_domain_sha256: str = Field(pattern=_SHA256, min_length=64, max_length=64)
    observer_root_id: str = Field(pattern=_IDENTIFIER)
    observer_key_id: str = Field(pattern=_IDENTIFIER)
    observer_fingerprint_sha256: str = Field(pattern=_SHA256, min_length=64, max_length=64)
    authority_identity_sha256: str = Field(pattern=_SHA256, min_length=64, max_length=64)
    independence_domain_sha256: str = Field(pattern=_SHA256, min_length=64, max_length=64)
    observation_ordinal: Literal[1, 2, 3, 4]
    relation_ordinal: Literal[1, 2, 3, 4]
    c0_delivery_row_ordinal: Literal[3, 4, 8, 9]
    derived_lane_ordinal: Literal[1, 2]
    b2_component_ordinal: Literal[0, 2]
    initiator_delivery_row_sha256: str = Field(pattern=_SHA256, min_length=64, max_length=64)
    relation_commitment_sha256: str = Field(pattern=_SHA256, min_length=64, max_length=64)
    bundle_context_sha256: str = Field(pattern=_SHA256, min_length=64, max_length=64)
    signed_c0_lane: Literal["primary", "restore"]
    initiator_component: Literal["primary_infisical", "restore_infisical"]
    dependency_classification: Literal[
        "primary_postgresql", "primary_valkey", "restore_postgresql", "restore_valkey"
    ]
    edge_transport_declaration: Literal["per_edge_runtime_proof_required_v1"]
    transport_profile: Literal["tls_verified_v1", "unpublished_loopback_or_network_v1"]
    listener_binding_subtype: Literal["tls_lan", "loopback_only", "isolated_network_only"]
    runtime_evidence_category: Literal["runtime_classification_v1"]
    container_evidence_category: Literal["container_classification_v1"]
    network_evidence_category: Literal["network_classification_v1"]
    listener_evidence_category: Literal["listener_classification_v1"]
    event_evidence_category: Literal["event_classification_v1"]
    inspection_evidence_category: Literal["inspection_classification_v1"]
    runtime_classification_sha256: str = Field(pattern=_SHA256, min_length=64, max_length=64)
    container_classification_sha256: str = Field(pattern=_SHA256, min_length=64, max_length=64)
    network_classification_sha256: str = Field(pattern=_SHA256, min_length=64, max_length=64)
    listener_classification_sha256: str = Field(pattern=_SHA256, min_length=64, max_length=64)
    event_classification_sha256: str = Field(pattern=_SHA256, min_length=64, max_length=64)
    inspection_classification_sha256: str = Field(pattern=_SHA256, min_length=64, max_length=64)
    transport_policy_sha256: str = Field(pattern=_SHA256, min_length=64, max_length=64)
    observation_signature_b64: str = Field(min_length=86, max_length=86)

    @field_validator(
        "observation_ordinal",
        "relation_ordinal",
        "c0_delivery_row_ordinal",
        "derived_lane_ordinal",
        "b2_component_ordinal",
        mode="before",
    )
    @classmethod
    def exact_integers(cls, value: object) -> object:
        if type(value) is not int:
            raise ValueError("observation is invalid")
        return value

    @model_validator(mode="after")
    def exact_observation(self) -> Self:
        try:
            if self.observation_ordinal != self.relation_ordinal:
                raise ValueError("observation is invalid")
            if (self.transport_profile, self.listener_binding_subtype) not in {
                ("tls_verified_v1", "tls_lan"),
                ("unpublished_loopback_or_network_v1", "loopback_only"),
                ("unpublished_loopback_or_network_v1", "isolated_network_only"),
            }:
                raise ValueError("observation is invalid")
            if len(_b64url(self.observation_signature_b64, length=86)) != 64:
                raise ValueError("observation is invalid")
            return self
        except (TypeError, ValueError):
            raise ValueError("observation is invalid") from None


class _BundleContextV1(_Model):
    observed_at: str = Field(pattern=_TIMESTAMP)
    expires_at: str = Field(pattern=_TIMESTAMP)
    maximum_age_seconds: int = Field(ge=1, le=86_400)
    challenge_sha256: str = Field(pattern=_SHA256, min_length=64, max_length=64)
    session_sha256: str = Field(pattern=_SHA256, min_length=64, max_length=64)
    replay_identity_sha256: str = Field(pattern=_SHA256, min_length=64, max_length=64)

    @field_validator("maximum_age_seconds", mode="before")
    @classmethod
    def exact_age(cls, value: object) -> object:
        if type(value) is not int:
            raise ValueError("bundle context is invalid")
        return value


class PerEdgeRuntimeProofBundleV1(_Model):
    """Four fixed observations plus one shared structural offline context."""

    schema: Literal["rsd.per-edge-runtime-proof-bundle.v1"]  # type: ignore[assignment]
    bundle_version: Literal[1]
    non_authorizing: Literal[True]
    matrix_sha256: str = Field(pattern=_SHA256, min_length=64, max_length=64)
    map_sha256: str = Field(pattern=_SHA256, min_length=64, max_length=64)
    manifest_sha256: str = Field(pattern=_SHA256, min_length=64, max_length=64)
    c0_policy_sha256: str = Field(pattern=_SHA256, min_length=64, max_length=64)
    source_snapshot_sha256: str = Field(pattern=_SHA256, min_length=64, max_length=64)
    c0_anchor_key_id: str = Field(pattern=_IDENTIFIER)
    c0_anchor_fingerprint_sha256: str = Field(pattern=_SHA256, min_length=64, max_length=64)
    c0_anchor_authority_identity_sha256: str = Field(pattern=_SHA256, min_length=64, max_length=64)
    c0_anchor_independence_domain_sha256: str = Field(pattern=_SHA256, min_length=64, max_length=64)
    observer_root_id: str = Field(pattern=_IDENTIFIER)
    observer_key_id: str = Field(pattern=_IDENTIFIER)
    observer_fingerprint_sha256: str = Field(pattern=_SHA256, min_length=64, max_length=64)
    authority_identity_sha256: str = Field(pattern=_SHA256, min_length=64, max_length=64)
    independence_domain_sha256: str = Field(pattern=_SHA256, min_length=64, max_length=64)
    observed_at: str = Field(pattern=_TIMESTAMP)
    expires_at: str = Field(pattern=_TIMESTAMP)
    maximum_age_seconds: int = Field(ge=1, le=86_400)
    challenge_sha256: str = Field(pattern=_SHA256, min_length=64, max_length=64)
    session_sha256: str = Field(pattern=_SHA256, min_length=64, max_length=64)
    replay_identity_sha256: str = Field(pattern=_SHA256, min_length=64, max_length=64)
    bundle_context_sha256: str = Field(pattern=_SHA256, min_length=64, max_length=64)
    observations: tuple[
        PerEdgeRuntimeProofObservationV1,
        PerEdgeRuntimeProofObservationV1,
        PerEdgeRuntimeProofObservationV1,
        PerEdgeRuntimeProofObservationV1,
    ]
    bundle_signature_b64: str = Field(min_length=86, max_length=86)

    @field_validator("bundle_version", "maximum_age_seconds", mode="before")
    @classmethod
    def exact_integers(cls, value: object) -> object:
        if type(value) is not int:
            raise ValueError("bundle is invalid")
        return value

    @field_validator("non_authorizing", mode="before")
    @classmethod
    def exact_non_authorizing(cls, value: object) -> object:
        if type(value) is not bool:
            raise ValueError("bundle is invalid")
        return value

    @field_validator("observations", mode="before")
    @classmethod
    def exact_observations(cls, value: object) -> tuple[object, ...]:
        if type(value) is not tuple or len(value) != 4:
            raise ValueError("bundle is invalid")
        return cast(tuple[object, ...], value)

    @model_validator(mode="after")
    def exact_bundle(self) -> Self:
        try:
            observed = _timestamp(self.observed_at)
            expires = _timestamp(self.expires_at)
            if (
                not self.non_authorizing
                or not observed < expires <= observed + timedelta(seconds=self.maximum_age_seconds)
                or len(_b64url(self.bundle_signature_b64, length=86)) != 64
                or self.bundle_context_sha256 != _bundle_context_sha256(self)
            ):
                raise ValueError("bundle is invalid")
            if tuple(item.observation_ordinal for item in self.observations) != (1, 2, 3, 4):
                raise ValueError("bundle is invalid")
            common = _bundle_common_fields(self)
            for observation in self.observations:
                if type(observation) is not PerEdgeRuntimeProofObservationV1:
                    raise ValueError("bundle is invalid")
                if _observation_common_fields(observation) != common:
                    raise ValueError("bundle is invalid")
                if observation.bundle_context_sha256 != self.bundle_context_sha256:
                    raise ValueError("bundle is invalid")
            return self
        except (AttributeError, OverflowError, TypeError, ValueError):
            raise ValueError("bundle is invalid") from None


class PerEdgeRuntimeProofBundleAcceptanceV1(_Model):
    """Exact false-vector diagnostic; never a live or effect result."""

    schema: Literal["rsd.per-edge-runtime-proof-bundle-acceptance.v1"]  # type: ignore[assignment]
    acceptance_version: Literal[1]
    bundle_sha256: str = Field(pattern=_SHA256, min_length=64, max_length=64)
    non_authorizing: Literal[True]
    delivery_authorized: Literal[False]
    network_authorized: Literal[False]
    build_authorized: Literal[False]
    pull_authorized: Literal[False]
    materialization_authorized: Literal[False]
    attach_authorized: Literal[False]
    runtime_observation_authorized: Literal[False]
    provider_lookup_authorized: Literal[False]
    callback_authorized: Literal[False]
    handle_authorized: Literal[False]
    replay_persistence_authorized: Literal[False]
    effect_authorized: Literal[False]
    fresh: Literal[False]
    replay_protected: Literal[False]
    live_observed: Literal[False]
    no_egress: Literal[False]
    proof_passed: Literal[False]
    ready: Literal[False]

    @field_validator("acceptance_version", mode="before")
    @classmethod
    def exact_version(cls, value: object) -> object:
        if type(value) is not int:
            raise ValueError("acceptance is invalid")
        return value

    @field_validator(
        "non_authorizing",
        *_CAPABILITIES,
        "fresh",
        "replay_protected",
        "live_observed",
        "no_egress",
        "proof_passed",
        "ready",
        mode="before",
    )
    @classmethod
    def exact_booleans(cls, value: object) -> object:
        if type(value) is not bool:
            raise ValueError("acceptance is invalid")
        return value

    @model_validator(mode="after")
    def exact_acceptance(self) -> Self:
        outcomes = (
            self.fresh,
            self.replay_protected,
            self.live_observed,
            self.no_egress,
            self.proof_passed,
            self.ready,
        )
        if (
            not self.non_authorizing
            or any(cast(bool, getattr(self, field)) for field in _CAPABILITIES)
            or any(outcomes)
        ):
            raise ValueError("acceptance is invalid")
        return self


def _bundle_common_fields(bundle: PerEdgeRuntimeProofBundleV1) -> tuple[str, ...]:
    return (
        bundle.matrix_sha256,
        bundle.map_sha256,
        bundle.manifest_sha256,
        bundle.c0_policy_sha256,
        bundle.source_snapshot_sha256,
        bundle.c0_anchor_key_id,
        bundle.c0_anchor_fingerprint_sha256,
        bundle.c0_anchor_authority_identity_sha256,
        bundle.c0_anchor_independence_domain_sha256,
        bundle.observer_root_id,
        bundle.observer_key_id,
        bundle.observer_fingerprint_sha256,
        bundle.authority_identity_sha256,
        bundle.independence_domain_sha256,
    )


def _observation_common_fields(observation: PerEdgeRuntimeProofObservationV1) -> tuple[str, ...]:
    return (
        observation.matrix_sha256,
        observation.map_sha256,
        observation.manifest_sha256,
        observation.c0_policy_sha256,
        observation.source_snapshot_sha256,
        observation.c0_anchor_key_id,
        observation.c0_anchor_fingerprint_sha256,
        observation.c0_anchor_authority_identity_sha256,
        observation.c0_anchor_independence_domain_sha256,
        observation.observer_root_id,
        observation.observer_key_id,
        observation.observer_fingerprint_sha256,
        observation.authority_identity_sha256,
        observation.independence_domain_sha256,
    )


def _bundle_context_sha256(bundle: PerEdgeRuntimeProofBundleV1) -> str:
    context = _BundleContextV1(
        observed_at=bundle.observed_at,
        expires_at=bundle.expires_at,
        maximum_age_seconds=bundle.maximum_age_seconds,
        challenge_sha256=bundle.challenge_sha256,
        session_sha256=bundle.session_sha256,
        replay_identity_sha256=bundle.replay_identity_sha256,
    )
    return hashlib.sha256(_CONTEXT_DOMAIN + _canonical(context)).hexdigest()


def _c0_matrix_sha256(matrix: TargetDeliveryFieldMatrixV1) -> str:
    """Call C0's hash helper without widening C0's authority-consumer surface."""

    from omninode_rsd.lifecycle import target_delivery_field_matrix_v1 as c0

    name = "_".join(("target", "delivery", "field", "matrix", "v1", "sha256"))
    helper = cast(Callable[[TargetDeliveryFieldMatrixV1], str], getattr(c0, name))
    return helper(matrix)


def _observation_signature_message(observation: PerEdgeRuntimeProofObservationV1) -> bytes:
    return _OBSERVATION_SIGNATURE_DOMAIN + _canonical(
        observation, exclude={"observation_signature_b64"}
    )


def canonical_per_edge_runtime_proof_bundle_v1_bytes(
    bundle: PerEdgeRuntimeProofBundleV1,
) -> bytes:
    """Return canonical bundle bytes without authenticating source C0 evidence."""

    try:
        canonical = _strict(bundle, PerEdgeRuntimeProofBundleV1)
        return _canonical(canonical)
    except (AttributeError, OverflowError, RecursionError, TypeError, ValueError):
        _fail("bundle")


def parse_per_edge_runtime_proof_bundle_v1(payload: bytes) -> PerEdgeRuntimeProofBundleV1:
    """Parse one exact canonical bundle spelling without conferring authority."""

    try:
        return _parse(payload, PerEdgeRuntimeProofBundleV1)
    except (OverflowError, RecursionError, TypeError, ValueError):
        _fail("parse")


def per_edge_runtime_proof_bundle_v1_signature_message(
    bundle: PerEdgeRuntimeProofBundleV1,
) -> bytes:
    """Return the exact bundle-signature preimage, never a validation result."""

    try:
        canonical = _strict(bundle, PerEdgeRuntimeProofBundleV1)
        return _BUNDLE_SIGNATURE_DOMAIN + _canonical(canonical, exclude={"bundle_signature_b64"})
    except (AttributeError, OverflowError, RecursionError, TypeError, ValueError):
        _fail("bundle")


def per_edge_runtime_proof_bundle_v1_sha256(bundle: PerEdgeRuntimeProofBundleV1) -> str:
    """Hash a complete canonical bundle under its dedicated commitment domain."""

    try:
        canonical = canonical_per_edge_runtime_proof_bundle_v1_bytes(bundle)
        return hashlib.sha256(_BUNDLE_DOMAIN + canonical).hexdigest()
    except PerEdgeRuntimeProofBundleError:
        raise
    except (AttributeError, OverflowError, RecursionError, TypeError, ValueError):
        _fail("bundle")


def _original_identities(values: tuple[object, ...]) -> set[str]:
    """Collect supplied C0/B1/B2/material namespace strings without registry lookup."""

    identities: set[str] = set()
    active: set[int] = set()

    def visit(value: object) -> None:
        if type(value) is str:
            identities.add(value)
            return
        if isinstance(value, BaseModel):
            value_id = id(value)
            if value_id in active:
                raise ValueError("identity state is invalid")
            state = getattr(value, "__dict__", _MISSING_STATE)
            if type(state) is not dict:
                raise ValueError("identity state is invalid")
            active.add(value_id)
            try:
                for item in cast(dict[str, object], state).values():
                    visit(item)
            finally:
                active.remove(value_id)
            return
        if type(value) is tuple:
            value_id = id(value)
            if value_id in active:
                raise ValueError("identity state is invalid")
            active.add(value_id)
            try:
                for item in value:
                    visit(item)
            finally:
                active.remove(value_id)
            return
        if type(value) in (dict, list, set, frozenset, bytes, bytearray, memoryview):
            raise ValueError("identity state is invalid")

    for value in values:
        visit(value)
    return identities


def _validate_bundle_bindings(
    *,
    bundle: PerEdgeRuntimeProofBundleV1,
    matrix: TargetDeliveryFieldMatrixV1,
    matrix_policy: TargetDeliveryFieldMatrixPolicyV1,
    matrix_trust_anchor: TargetDeliveryFieldMatrixTrustAnchorV1,
    bundle_trust_anchor: PerEdgeRuntimeProofBundleTrustAnchorV1,
    original_values: tuple[object, ...],
) -> None:
    """Bind the C1 projection to one freshly revalidated C0 tuple."""

    manifest = cast(TargetDeliveryArtifactManifestV2, original_values[6])
    manifest_sha256 = target_delivery_artifact_manifest_v2_sha256(manifest)
    expected_c0 = (
        _c0_matrix_sha256(matrix),
        target_delivery_map_sha256(cast(TargetDeliveryMapV1, original_values[0])),
        manifest_sha256,
        target_delivery_field_matrix_policy_v1_sha256(matrix_policy),
        manifest.source.source_snapshot_sha256,
        matrix_trust_anchor.key_id,
        matrix_trust_anchor.public_key_fingerprint_sha256,
        matrix_trust_anchor.authority_identity_sha256,
        matrix_trust_anchor.independence_domain_identity_sha256,
    )
    if _bundle_common_fields(bundle)[:9] != expected_c0:
        raise ValueError("C0 context differs")
    expected_observer = (
        bundle_trust_anchor.observer_root_id,
        bundle_trust_anchor.observer_key_id,
        bundle_trust_anchor.observer_fingerprint_sha256,
        bundle_trust_anchor.authority_identity_sha256,
        bundle_trust_anchor.independence_domain_sha256,
    )
    if _bundle_common_fields(bundle)[9:] != expected_observer:
        raise ValueError("observer differs")
    observer_values = {
        bundle_trust_anchor.observer_root_id,
        bundle_trust_anchor.observer_key_id,
        bundle_trust_anchor.observer_public_key_b64,
        bundle_trust_anchor.observer_fingerprint_sha256,
        bundle_trust_anchor.authority_identity_sha256,
        bundle_trust_anchor.independence_domain_sha256,
    }
    if observer_values & _original_identities(original_values):
        raise ValueError("observer identity collides")

    expected_relations = (
        (1, 3, 1, 0, "primary", "primary_infisical", "primary_postgresql"),
        (2, 4, 1, 0, "primary", "primary_infisical", "primary_valkey"),
        (3, 8, 2, 2, "restore", "restore_infisical", "restore_postgresql"),
        (4, 9, 2, 2, "restore", "restore_infisical", "restore_valkey"),
    )
    for observation, (
        ordinal,
        row_ordinal,
        lane_ordinal,
        component_ordinal,
        lane,
        initiator,
        dependency,
    ) in zip(bundle.observations, expected_relations, strict=True):
        relation = matrix.application_dependencies[ordinal - 1]
        row = matrix.rows[row_ordinal - 1]
        if type(relation.material_policy) is not ProviderMaterialPolicyV2:
            raise ValueError("material projection is invalid")
        if (
            observation.observation_ordinal != ordinal
            or observation.relation_ordinal != relation.ordinal
            or observation.c0_delivery_row_ordinal != row_ordinal
            or observation.derived_lane_ordinal != lane_ordinal
            or observation.b2_component_ordinal != component_ordinal
            or relation.ordinal != ordinal
            or relation.lane != lane
            or relation.initiator_component != initiator
            or relation.dependency != dependency
            or relation.edge_transport_declaration != "per_edge_runtime_proof_required_v1"
            or observation.initiator_delivery_row_sha256 != relation.initiator_delivery_row_sha256
            or observation.relation_commitment_sha256 != relation.relation_commitment_sha256
            or observation.signed_c0_lane != relation.lane
            or observation.initiator_component != relation.initiator_component
            or observation.dependency_classification != relation.dependency
            or observation.edge_transport_declaration != relation.edge_transport_declaration
            or observation.transport_policy_sha256 != relation.transport_policy_commitment_sha256
            or relation.initiator_delivery_row_sha256 == ""
            or row.ordinal != row_ordinal
        ):
            raise ValueError("relation binding differs")

    key = _b64url(bundle_trust_anchor.observer_public_key_b64, length=43)
    public_key = Ed25519PublicKey.from_public_bytes(key)
    public_key.verify(
        _b64url(bundle.bundle_signature_b64, length=86),
        per_edge_runtime_proof_bundle_v1_signature_message(bundle),
    )
    for observation in bundle.observations:
        public_key.verify(
            _b64url(observation.observation_signature_b64, length=86),
            _observation_signature_message(observation),
        )


def validate_per_edge_runtime_proof_bundle_v1(
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
    bundle_policy: PerEdgeRuntimeProofBundlePolicyV1,
    bundle_trust_anchor: PerEdgeRuntimeProofBundleTrustAnchorV1,
    bundle: PerEdgeRuntimeProofBundleV1,
) -> PerEdgeRuntimeProofBundleAcceptanceV1:
    """Revalidate original C0 inputs and return only the frozen false vector.

    There is intentionally no C0, B2, V5, or C1 acceptance parameter: no
    acceptance result can enter this authority boundary as source evidence.
    """

    try:
        bundle_policy = _strict(bundle_policy, PerEdgeRuntimeProofBundlePolicyV1)
        bundle_trust_anchor = _strict(
            bundle_trust_anchor,
            PerEdgeRuntimeProofBundleTrustAnchorV1,
        )
    except (AttributeError, OverflowError, RecursionError, TypeError, ValueError):
        _fail("anchor")

    try:
        bundle = _strict(bundle, PerEdgeRuntimeProofBundleV1)
    except (AttributeError, OverflowError, RecursionError, TypeError, ValueError):
        _fail("bundle")

    try:
        validate_target_delivery_field_matrix_v1(
            delivery_map=delivery_map,
            static_delivery_projection=static_delivery_projection,
            b1_trust_policy=b1_trust_policy,
            manifest_trust_anchor=manifest_trust_anchor,
            role_inputs=role_inputs,
            v5_role_policy_inputs=v5_role_policy_inputs,
            manifest=manifest,
            matrix_policy=matrix_policy,
            matrix_trust_anchor=matrix_trust_anchor,
            matrix=matrix,
        )
    except (AttributeError, OverflowError, RecursionError, TypeError, ValueError):
        _fail("input")

    try:
        originals: tuple[object, ...] = (
            delivery_map,
            static_delivery_projection,
            b1_trust_policy,
            manifest_trust_anchor,
            role_inputs,
            v5_role_policy_inputs,
            manifest,
            matrix_policy,
            matrix_trust_anchor,
            matrix,
        )
        _validate_bundle_bindings(
            bundle=bundle,
            matrix=matrix,
            matrix_policy=matrix_policy,
            matrix_trust_anchor=matrix_trust_anchor,
            bundle_trust_anchor=bundle_trust_anchor,
            original_values=originals,
        )
    except (InvalidSignature, AttributeError, OverflowError, RecursionError, TypeError, ValueError):
        _fail("bundle")

    return PerEdgeRuntimeProofBundleAcceptanceV1(
        schema="rsd.per-edge-runtime-proof-bundle-acceptance.v1",
        acceptance_version=1,
        bundle_sha256=per_edge_runtime_proof_bundle_v1_sha256(bundle),
        non_authorizing=True,
        delivery_authorized=False,
        network_authorized=False,
        build_authorized=False,
        pull_authorized=False,
        materialization_authorized=False,
        attach_authorized=False,
        runtime_observation_authorized=False,
        provider_lookup_authorized=False,
        callback_authorized=False,
        handle_authorized=False,
        replay_persistence_authorized=False,
        effect_authorized=False,
        fresh=False,
        replay_protected=False,
        live_observed=False,
        no_egress=False,
        proof_passed=False,
        ready=False,
    )


__all__ = [
    "PerEdgeRuntimeProofBundleAcceptanceV1",
    "PerEdgeRuntimeProofBundleError",
    "PerEdgeRuntimeProofBundlePolicyV1",
    "PerEdgeRuntimeProofBundleTrustAnchorV1",
    "PerEdgeRuntimeProofBundleV1",
    "PerEdgeRuntimeProofObservationV1",
    "canonical_per_edge_runtime_proof_bundle_v1_bytes",
    "parse_per_edge_runtime_proof_bundle_v1",
    "per_edge_runtime_proof_bundle_v1_sha256",
    "per_edge_runtime_proof_bundle_v1_signature_message",
    "validate_per_edge_runtime_proof_bundle_v1",
]
