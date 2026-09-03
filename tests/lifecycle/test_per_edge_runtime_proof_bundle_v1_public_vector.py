"""Immutable, synthetic public vector for the C1 runtime-proof bundle.

The vector carries only opaque C0 commitments, typed C0-safe material-policy
metadata, public keys, and signed diagnostic classifications.  It replays the
pinned B2 V2 public-vector chain and then revalidates a complete C0 matrix;
neither upstream acceptance nor a live observation can enter C1 validation.
"""

from __future__ import annotations

import base64
import binascii
import hashlib
import inspect
import json
import re
import stat
from dataclasses import dataclass
from pathlib import Path
from typing import Any, cast

import pytest
import yaml
from cryptography.exceptions import InvalidSignature
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PublicKey
from pydantic import BaseModel, ValidationError
from yaml.events import AliasEvent, NodeEvent
from yaml.nodes import MappingNode, Node, ScalarNode, SequenceNode
from yaml.tokens import AliasToken, AnchorToken, TagToken

from omninode_rsd.lifecycle import container_attach_static_v4 as static_v4
from omninode_rsd.lifecycle import container_bootstrap_artifact_evidence_v5 as evidence_v5
from omninode_rsd.lifecycle import per_edge_runtime_proof_bundle_v1 as c1
from omninode_rsd.lifecycle import target_delivery_artifact_manifest as manifest_v1
from omninode_rsd.lifecycle import target_delivery_artifact_manifest_v2 as manifest_v2
from omninode_rsd.lifecycle import target_delivery_field_matrix_v1 as c0
from omninode_rsd.lifecycle import target_delivery_map_projection_binding as binding
from omninode_rsd.lifecycle import target_delivery_map_signing as map_signing
from omninode_rsd.lifecycle.infisical_disposable import TargetDeliveryMapV1

_ROOT = Path(__file__).parents[2] / "src/omninode_rsd/lifecycle"
_VECTOR = _ROOT / "per_edge_runtime_proof_bundle_v1_public_vector.yaml"
_B2_V2_VECTOR = _ROOT / "target_delivery_artifact_manifest_v2_public_vector.yaml"
_B2_V2_SHA256 = "5b91cfb95243403b3ddc234d154df355f46787f0c3ea49613d5bf404b1a72237"
_B2_V2_BYTE_COUNT = 52_693
_B2_V2_LINE_COUNT = 667
_B1_VECTOR = _ROOT / "target_delivery_artifact_manifest_public_vector.yaml"
_B1_SHA256 = "4b10ec2b37f0768d0a8fa283d5a26cc6020e26a968ebb3928b78d4b8f73c65ed"
_B1_BYTE_COUNT = 339_553
_B1_LINE_COUNT = 4_174
_V5_VECTOR = _ROOT / "container_bootstrap_artifact_evidence_v5_public_vector.yaml"
_V5_SHA256 = "6c66df411fd080f1d20e2cfe8f8004f600a1cfe1fe5942259b148af15166ca91"
_V5_BYTE_COUNT = 238_294
_V5_LINE_COUNT = 2_948
_VECTOR_SHA256 = "0c2266d5082662300bd7e7b5d11ad50eb63154cb084e17522e166b014035b6c6"
_VECTOR_BYTE_COUNT = 51_584
_VECTOR_LINE_COUNT = 661
_MAX_VECTOR_BYTES = 2 * 1024 * 1024
_MAX_VECTOR_DEPTH = 32
_MAX_VECTOR_NODES = 32_768
_SEGMENT_LENGTH = 76
_COMPONENTS = ("primary_infisical", "primary_valkey", "restore_infisical", "restore_valkey")
_CANONICAL_YAML_INTEGER = re.compile(r"(?:0|[1-9][0-9]*)\Z")
_CANONICAL_YAML_BOOLEANS = frozenset({"true", "false"})
_YAML_11_BOOLEAN_LIKE = re.compile(r"(?:y|yes|n|no|true|false|on|off)\Z", re.ASCII | re.IGNORECASE)
_YAML_NULL_LIKE = re.compile(r"(?:~|null)\Z", re.ASCII | re.IGNORECASE)
_YAML_SPECIAL_FLOAT_LIKE = re.compile(
    r"[+-]?(?:\.(?:inf(?:inity)?|nan)|(?:inf(?:inity)?|nan))\Z",
    re.ASCII | re.IGNORECASE,
)
_YAML_NUMERIC_LIKE = re.compile(
    r"""
    [+-]?(?:
        0[xX][0-9A-Fa-f]+ |
        0[oO][0-7]+ |
        0[bB][01]+ |
        [0-9][0-9_]*(?::[0-9][0-9_]*(?::[0-9][0-9_]*)*)?(?:\.[0-9_]*)?(?:[eE][+-]?[0-9_]+)? |
        \.[0-9_]+(?:[eE][+-]?[0-9_]+)?
    )\Z
    """,
    re.ASCII | re.VERBOSE,
)
_YAML_TIMESTAMP_LIKE = re.compile(r"[0-9]{4}-[0-9]{1,2}-[0-9]{1,2}(?:[Tt \t].*)?\Z", re.ASCII)
_YAML_BOOL_TAG = "tag:yaml.org,2002:bool"
_YAML_FLOAT_TAG = "tag:yaml.org,2002:float"
_YAML_INT_TAG = "tag:yaml.org,2002:int"
_YAML_NULL_TAG = "tag:yaml.org,2002:null"
_YAML_TIMESTAMP_TAG = "tag:yaml.org,2002:timestamp"
_PRIVATE_OR_INTERNAL_ENDPOINT = re.compile(
    r"""(?ix)
    (?:
        \b10[.]\d{1,3}[.]\d{1,3}[.]\d{1,3}\b |
        \b127[.]\d{1,3}[.]\d{1,3}[.]\d{1,3}\b |
        \b169[.]254[.]\d{1,3}[.]\d{1,3}\b |
        \b172[.](?:1[6-9]|2\d|3[01])[.]\d{1,3}[.]\d{1,3}\b |
        \b192[.]168[.]\d{1,3}[.]\d{1,3}\b |
        (?<![0-9A-Fa-f:])::1(?![0-9A-Fa-f:]) |
        (?<![0-9A-Fa-f:])f[c-d][0-9A-Fa-f]{0,2}:[0-9A-Fa-f:]+ |
        (?<![0-9A-Fa-f:])fe[89ab][0-9A-Fa-f]:[0-9A-Fa-f:]+ |
        (?:[a-z0-9-]+[.])+"""
    + "(?:local|lan|inter"
    + "nal|corp|home|intranet|pri"
    + "vate|lab)\\b"
    + r"""
    )
    """
)
_FORBIDDEN_RAW_PREIMAGE_KEYS = {
    "raw_topology",
    "topology_preimage",
    "topology_message",
    "runtime_preimage",
    "runtime_message",
    "provider_preimage",
    "provider_message",
    "provider_material",
    "provider_crypto",
    "oci_preimage",
    "oci_message",
    "source_preimage",
    "source_message",
    "manifest_message",
    "bundle_message",
    "preimage",
    "message",
}
_C1_OUTCOME_FIELDS = (
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
    "fresh",
    "replay_protected",
    "live_observed",
    "no_egress",
    "proof_passed",
    "ready",
)


class _StrictVectorLoader(yaml.SafeLoader):
    """Safe YAML loader that also rejects duplicate and merge keys."""


def _strict_mapping(
    loader: yaml.SafeLoader, node: yaml.MappingNode, deep: bool = False
) -> dict[str, object]:
    if not isinstance(node, MappingNode):
        raise ValueError("vector mapping is invalid")
    result: dict[str, object] = {}
    for key_node, value_node in node.value:
        key = loader.construct_object(key_node, deep=deep)
        if type(key) is not str or key == "<<" or key in result:
            raise ValueError("vector mapping is invalid")
        result[key] = loader.construct_object(value_node, deep=deep)
    return result


_StrictVectorLoader.add_constructor(yaml.resolver.BaseResolver.DEFAULT_MAPPING_TAG, _strict_mapping)


class _NoAliasDumper(yaml.SafeDumper):
    def ignore_aliases(self, data: object) -> bool:
        return True


def _validate_yaml_scalar_spellings(node: Node) -> None:
    if isinstance(node, ScalarNode):
        if node.style is None:
            value = node.value
            if (
                value not in _CANONICAL_YAML_BOOLEANS
                and _CANONICAL_YAML_INTEGER.fullmatch(value) is None
                and (
                    not value
                    or _YAML_11_BOOLEAN_LIKE.fullmatch(value) is not None
                    or _YAML_NULL_LIKE.fullmatch(value) is not None
                    or _YAML_SPECIAL_FLOAT_LIKE.fullmatch(value) is not None
                    or _YAML_NUMERIC_LIKE.fullmatch(value) is not None
                    or _YAML_TIMESTAMP_LIKE.fullmatch(value) is not None
                )
            ):
                raise ValueError("vector scalar spelling is not portable")
        if node.tag == _YAML_BOOL_TAG:
            if node.style is not None or node.value not in _CANONICAL_YAML_BOOLEANS:
                raise ValueError("vector scalar spelling is not portable")
        elif node.tag == _YAML_INT_TAG:
            if node.style is not None or _CANONICAL_YAML_INTEGER.fullmatch(node.value) is None:
                raise ValueError("vector scalar spelling is not portable")
        elif node.tag in {_YAML_FLOAT_TAG, _YAML_NULL_TAG, _YAML_TIMESTAMP_TAG}:
            raise ValueError("vector scalar spelling is not portable")
        return
    if isinstance(node, MappingNode):
        for key, value in node.value:
            _validate_yaml_scalar_spellings(key)
            _validate_yaml_scalar_spellings(value)
        return
    if isinstance(node, SequenceNode):
        for item in node.value:
            _validate_yaml_scalar_spellings(item)


def _safe_tree(value: object, *, depth: int = 0, nodes: list[int] | None = None) -> None:
    if depth > _MAX_VECTOR_DEPTH:
        raise ValueError("vector nesting is invalid")
    count = [0] if nodes is None else nodes
    count[0] += 1
    if count[0] > _MAX_VECTOR_NODES:
        raise ValueError("vector node count is invalid")
    if type(value) is dict:
        for key, item in cast(dict[object, object], value).items():
            if type(key) is not str:
                raise ValueError("vector mapping key is invalid")
            _safe_tree(item, depth=depth + 1, nodes=count)
    elif type(value) is list:
        for item in cast(list[object], value):
            _safe_tree(item, depth=depth + 1, nodes=count)
    elif type(value) not in (str, int, bool, type(None)):
        raise ValueError("vector scalar is invalid")


def _load_yaml(raw: bytes) -> dict[str, object]:
    if not 1 <= len(raw) <= _MAX_VECTOR_BYTES or not raw.isascii() or not raw.endswith(b"\n"):
        raise ValueError("vector bytes are invalid")
    if any(line.rstrip(b" \t") != line for line in raw.splitlines()):
        raise ValueError("vector whitespace is invalid")
    try:
        for token in yaml.scan(raw):
            if isinstance(token, (AliasToken, AnchorToken, TagToken)):
                raise ValueError("vector YAML feature is invalid")
        for event in yaml.parse(raw):
            if isinstance(event, AliasEvent) or (
                isinstance(event, NodeEvent) and event.anchor is not None
            ):
                raise ValueError("vector aliases are forbidden")
        nodes = list(yaml.compose_all(raw, Loader=_StrictVectorLoader))
        if len(nodes) != 1 or nodes[0] is None:
            raise ValueError("vector is empty")
        _validate_yaml_scalar_spellings(nodes[0])
        value = yaml.load(raw, Loader=_StrictVectorLoader)
    except yaml.YAMLError as error:
        raise ValueError("vector YAML is invalid") from error
    _safe_tree(value)
    if type(value) is not dict:
        raise ValueError("vector root is invalid")
    return cast(dict[str, object], value)


def _mapping(value: object, expected: set[str]) -> dict[str, object]:
    if type(value) is not dict or set(cast(dict[str, object], value)) != expected:
        raise ValueError("vector mapping shape is invalid")
    return cast(dict[str, object], value)


def _string(value: object) -> str:
    if type(value) is not str:
        raise ValueError("vector string is invalid")
    return cast(str, value)


def _integer(value: object) -> int:
    if type(value) is not int:
        raise ValueError("vector integer is invalid")
    return cast(int, value)


def _bytes(value: object) -> bytes:
    item = _mapping(value, {"encoding", "segments"})
    if item["encoding"] != "base64url_fixed_segments_v1" or type(item["segments"]) is not list:
        raise ValueError("vector base64url envelope is invalid")
    segments = cast(list[object], item["segments"])
    if not segments or any(type(segment) is not str for segment in segments):
        raise ValueError("vector base64url segments are invalid")
    rendered = "".join(cast(str, segment) for segment in segments)
    if (
        any(len(cast(str, segment)) != _SEGMENT_LENGTH for segment in segments[:-1])
        or not 1 <= len(cast(str, segments[-1])) <= _SEGMENT_LENGTH
        or "=" in rendered
        or any(
            character not in "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789-_"
            for character in rendered
        )
        or len(rendered) % 4 == 1
    ):
        raise ValueError("vector base64url segments are invalid")
    try:
        decoded = base64.urlsafe_b64decode(rendered + "=" * (-len(rendered) % 4))
    except (binascii.Error, ValueError):
        raise ValueError("vector base64url is invalid") from None
    if base64.urlsafe_b64encode(decoded).decode("ascii").rstrip("=") != rendered:
        raise ValueError("vector base64url is not canonical")
    return decoded


def _standard_bytes(value: object) -> bytes:
    """Decode the fixed, padded carrier used by inherited B1/B2/V5 vectors."""

    item = _mapping(value, {"encoding", "segments"})
    if (
        item["encoding"] != "standard_base64_fixed_segments_v1"
        or type(item["segments"]) is not list
    ):
        raise ValueError("inherited vector base64 envelope is invalid")
    segments = cast(list[object], item["segments"])
    if not segments or any(type(segment) is not str for segment in segments):
        raise ValueError("inherited vector base64 segments are invalid")
    rendered = cast(list[str], segments)
    if any(len(segment) != _SEGMENT_LENGTH for segment in rendered[:-1]) or not (
        1 <= len(rendered[-1]) <= _SEGMENT_LENGTH
    ):
        raise ValueError("inherited vector base64 segmentation is invalid")
    encoded = "".join(rendered)
    try:
        decoded = base64.b64decode(encoded, validate=True)
    except (binascii.Error, ValueError):
        raise ValueError("inherited vector base64 is invalid") from None
    if base64.b64encode(decoded).decode("ascii") != encoded:
        raise ValueError("inherited vector base64 is not canonical")
    return decoded


def _json(payload: bytes) -> dict[str, object]:
    try:
        value = json.loads(
            payload.decode("ascii"),
            object_pairs_hook=_no_duplicate_json_mapping,
            parse_float=lambda _value: (_ for _ in ()).throw(ValueError("float")),
            parse_constant=lambda _value: (_ for _ in ()).throw(ValueError("constant")),
        )
    except (UnicodeDecodeError, ValueError, json.JSONDecodeError):
        raise ValueError("vector JSON is invalid") from None
    if type(value) is not dict:
        raise ValueError("vector JSON root is invalid")
    return cast(dict[str, object], value)


def _no_duplicate_json_mapping(pairs: list[tuple[object, object]]) -> dict[str, object]:
    result: dict[str, object] = {}
    for key, value in pairs:
        if type(key) is not str or key in result:
            raise ValueError("duplicate JSON key")
        result[key] = value
    return result


def _tuples(value: object) -> object:
    if type(value) is list:
        return tuple(_tuples(item) for item in cast(list[object], value))
    if type(value) is dict:
        return {key: _tuples(item) for key, item in cast(dict[str, object], value).items()}
    return value


def _canonical(model: BaseModel) -> bytes:
    return json.dumps(
        model.model_dump(mode="json", warnings="error"),
        ensure_ascii=True,
        sort_keys=True,
        separators=(",", ":"),
        allow_nan=False,
    ).encode("ascii")


def _model(payload: bytes, expected: type[BaseModel]) -> BaseModel:
    try:
        model = expected.model_validate(_tuples(_json(payload)), strict=True)
    except (TypeError, ValidationError, ValueError):
        raise ValueError("vector model is invalid") from None
    if _canonical(model) != payload:
        raise ValueError("vector model is not canonical")
    return model


def _dependency(
    value: object, *, path: Path, sha256: str, byte_count: int, line_count: int
) -> bytes:
    item = _mapping(value, {"filename", "sha256", "byte_count", "line_count"})
    if (
        item["filename"] != path.name
        or item["sha256"] != sha256
        or item["byte_count"] != byte_count
        or item["line_count"] != line_count
    ):
        raise ValueError("immutable dependency pin is invalid")
    try:
        mode = path.lstat().st_mode
    except OSError:
        raise ValueError("immutable dependency is unavailable") from None
    if not stat.S_ISREG(mode):
        raise ValueError("immutable dependency is not a regular file")
    raw = path.read_bytes()
    if (
        hashlib.sha256(raw).hexdigest() != sha256
        or len(raw) != byte_count
        or raw.count(b"\n") != line_count
    ):
        raise ValueError("immutable dependency bytes are invalid")
    return raw


def _immutable_vector_snapshot() -> bytes:
    try:
        mode = _VECTOR.lstat().st_mode
    except OSError:
        raise ValueError("immutable C1 public vector is unavailable") from None
    if not stat.S_ISREG(mode):
        raise ValueError("immutable C1 public vector is not a regular file")
    raw = _VECTOR.read_bytes()
    if (
        hashlib.sha256(raw).hexdigest() != _VECTOR_SHA256
        or len(raw) != _VECTOR_BYTE_COUNT
        or raw.count(b"\n") != _VECTOR_LINE_COUNT
    ):
        raise ValueError("immutable C1 public vector hash is invalid")
    return raw


def _verify_ed25519(*, public_key_base64: str, signature_base64: str, message: bytes) -> None:
    try:
        public_key = Ed25519PublicKey.from_public_bytes(
            base64.b64decode(public_key_base64, validate=True)
        )
        public_key.verify(base64.b64decode(signature_base64, validate=True), message)
    except (InvalidSignature, ValueError, binascii.Error):
        raise ValueError("inherited public signature is invalid") from None


def _b1_inputs(
    document: dict[str, object],
) -> tuple[
    TargetDeliveryMapV1,
    static_v4.ContainerBootstrapStaticDeliveryProjectionV4,
    binding.TargetDeliveryMapProjectionBindingTrustPolicyV1,
    tuple[Any, Any, Any, Any],
    tuple[Any, Any, Any, Any],
]:
    values = _mapping(
        document,
        {
            "schema_version",
            "component_order",
            "target_delivery_map",
            "static_delivery_projection",
            "b1_policy",
            "manifest_anchor",
            "roles",
            "manifest",
            "manifest_message",
            "manifest_sha256",
            "acceptance",
            "acceptance_sha256",
        },
    )
    if values[
        "schema_version"
    ] != "rsd.target-delivery-artifact-manifest-public-vector.v1" or values[
        "component_order"
    ] != list(_COMPONENTS):
        raise ValueError("inherited B1 vector metadata is invalid")
    map_payload = _standard_bytes(values["target_delivery_map"])
    try:
        delivery_map = TargetDeliveryMapV1.model_validate(_tuples(_json(map_payload)), strict=True)
    except (TypeError, ValidationError, ValueError):
        raise ValueError("inherited B1 map is invalid") from None
    if _canonical(delivery_map) != map_payload:
        raise ValueError("inherited B1 map is not canonical")
    projection = static_v4.parse_container_bootstrap_static_delivery_projection_v4_canonical_json(
        _standard_bytes(values["static_delivery_projection"])
    )
    policy = binding.parse_target_delivery_map_projection_binding_trust_policy_v1_canonical_json(
        _standard_bytes(values["b1_policy"])
    )
    roles = values["roles"]
    if type(roles) is not list or len(roles) != 4:
        raise ValueError("inherited B1 role count is invalid")
    envelopes: list[Any] = []
    bindings: list[Any] = []
    for ordinal, component in enumerate(_COMPONENTS):
        role = _mapping(
            cast(list[object], roles)[ordinal],
            {"profile_envelope", "projection_binding", "phase_a_closure"},
        )
        envelope = (
            static_v4.parse_container_bootstrap_static_role_profile_envelope_v4_canonical_json(
                _standard_bytes(role["profile_envelope"])
            )
        )
        if envelope.static_role_profile.component != component:
            raise ValueError("inherited B1 profile order is invalid")
        envelopes.append(envelope)
        bindings.append(
            binding.parse_target_delivery_map_projection_binding_v1_canonical_json(
                _standard_bytes(role["projection_binding"])
            )
        )
    return (
        delivery_map,
        projection,
        policy,
        cast(tuple[Any, Any, Any, Any], tuple(envelopes)),
        cast(tuple[Any, Any, Any, Any], tuple(bindings)),
    )


@dataclass(frozen=True)
class _B2Evidence:
    delivery_map: TargetDeliveryMapV1
    projection: static_v4.ContainerBootstrapStaticDeliveryProjectionV4
    b1_policy: binding.TargetDeliveryMapProjectionBindingTrustPolicyV1
    manifest_anchor: manifest_v1.TargetDeliveryArtifactManifestTrustAnchorV1
    role_inputs: tuple[Any, Any, Any, Any]
    policy_inputs: tuple[Any, Any, Any, Any]
    manifest: manifest_v2.TargetDeliveryArtifactManifestV2


def _revalidate_b2_v2(*, b2_raw: bytes, v5_raw: bytes) -> _B2Evidence:
    """Reconstruct B1/V4/V5/B2 source evidence from pinned public bytes only."""

    b2_document = _load_yaml(b2_raw)
    b2_values = _mapping(
        b2_document,
        {
            "schema_version",
            "purpose",
            "base64_encoding",
            "immutable_dependencies",
            "manifest_trust_anchor",
            "manifest",
            "manifest_message",
            "manifest_sha256",
            "expected_acceptance",
            "acceptance_sha256",
        },
    )
    if (
        b2_values["schema_version"] != "rsd.target-delivery-artifact-manifest-v2-public-vector.v1"
        or b2_values["purpose"] != "synthetic_offline_b2_v2_expected_acceptance_public_vector"
        or b2_values["base64_encoding"] != "standard_base64_fixed_segments_v1"
    ):
        raise ValueError("inherited B2 vector metadata is invalid")
    b2_dependencies = _mapping(
        b2_values["immutable_dependencies"], {"b1_v1_four_role", "phase_a_v5"}
    )
    b1_raw = _dependency(
        b2_dependencies["b1_v1_four_role"],
        path=_B1_VECTOR,
        sha256=_B1_SHA256,
        byte_count=_B1_BYTE_COUNT,
        line_count=_B1_LINE_COUNT,
    )
    if (
        _dependency(
            b2_dependencies["phase_a_v5"],
            path=_V5_VECTOR,
            sha256=_V5_SHA256,
            byte_count=_V5_BYTE_COUNT,
            line_count=_V5_LINE_COUNT,
        )
        != v5_raw
    ):
        raise ValueError("inherited V5 bytes differ")
    delivery_map, projection, b1_policy, envelopes, b1_bindings = _b1_inputs(_load_yaml(b1_raw))
    v5_values = _mapping(
        _load_yaml(v5_raw),
        {
            "schema_version",
            "purpose",
            "base64_encoding",
            "component_order",
            "common_profile_root",
            "common_source",
            "common_oci",
            "roles",
        },
    )
    if (
        v5_values["schema_version"]
        != "rsd.container-bootstrap-artifact-evidence-v5-public-vector.v1"
        or v5_values["base64_encoding"] != "standard_base64_fixed_segments_v1"
        or v5_values["component_order"] != list(_COMPONENTS)
        or _standard_bytes(v5_values["common_profile_root"])
        != static_v4.container_bootstrap_static_profile_trust_anchor_v4_canonical_json(
            b1_policy.profile_trust_anchor
        )
    ):
        raise ValueError("inherited V5 vector metadata is invalid")
    roles = v5_values["roles"]
    if type(roles) is not list or len(roles) != 4:
        raise ValueError("inherited V5 role count is invalid")
    role_inputs: list[Any] = []
    policy_inputs: list[Any] = []
    for ordinal, component in enumerate(_COMPONENTS):
        role = _mapping(
            cast(list[object], roles)[ordinal],
            {
                "component",
                "ordinal",
                "profile_envelope",
                "worker_policy",
                "closure",
                "acceptance",
                "expected",
            },
        )
        if role["component"] != component or _integer(role["ordinal"]) != ordinal:
            raise ValueError("inherited V5 role order is invalid")
        if _standard_bytes(role["profile_envelope"]) != (
            static_v4.container_bootstrap_static_role_profile_envelope_v4_canonical_json(
                envelopes[ordinal]
            )
        ):
            raise ValueError("inherited B1/V5 profile differs")
        _verify_ed25519(
            public_key_base64=b1_policy.profile_trust_anchor.public_key_base64,
            signature_base64=envelopes[ordinal].signature_base64,
            message=static_v4.container_bootstrap_static_role_profile_envelope_v4_canonical_message(
                envelopes[ordinal]
            ),
        )
        _verify_ed25519(
            public_key_base64=b1_policy.binding_trust_anchor.public_key_base64,
            signature_base64=b1_bindings[ordinal].signature_base64,
            message=binding.target_delivery_map_projection_binding_v1_message(b1_bindings[ordinal]),
        )
        policy_payload = _standard_bytes(role["worker_policy"])
        closure_payload = _standard_bytes(role["closure"])
        policy = evidence_v5.parse_container_bootstrap_build_worker_trust_policy_v5_canonical_json(
            policy_payload
        )
        closure = evidence_v5.parse_container_bootstrap_artifact_evidence_closure_v5_canonical_json(
            closure_payload
        )
        if (
            evidence_v5.container_bootstrap_build_worker_trust_policy_v5_canonical_json(policy)
            != policy_payload
            or evidence_v5.container_bootstrap_artifact_evidence_closure_v5_canonical_json(closure)
            != closure_payload
            or closure.worker_attestations[0].component != component
        ):
            raise ValueError("inherited V5 evidence is invalid")
        for attestation, worker in zip(
            closure.worker_attestations, policy.worker_trust_anchors, strict=True
        ):
            _verify_ed25519(
                public_key_base64=worker.public_key_base64,
                signature_base64=attestation.signature_base64,
                message=evidence_v5.container_bootstrap_artifact_worker_attestation_v5_message(
                    attestation
                ),
            )
        role_inputs.append(
            manifest_v2.TargetDeliveryArtifactManifestRoleInputV2(
                schema_version="rsd.target-delivery-artifact-manifest-role-input.v2",
                component=cast(Any, component),
                profile_envelope=envelopes[ordinal],
                projection_binding=b1_bindings[ordinal],
                phase_a_v5_closure=closure,
            )
        )
        policy_inputs.append(
            manifest_v2.TargetDeliveryArtifactManifestV5RolePolicyInputV2(
                schema_version="rsd.target-delivery-artifact-manifest-v5-role-policy-input.v2",
                component=cast(Any, component),
                worker_trust_policy=policy,
            )
        )
    manifest_anchor = (
        manifest_v1.parse_target_delivery_artifact_manifest_trust_anchor_v1_canonical_json(
            _standard_bytes(b2_values["manifest_trust_anchor"])
        )
    )
    manifest = manifest_v2.parse_target_delivery_artifact_manifest_v2_canonical_json(
        _standard_bytes(b2_values["manifest"])
    )
    message = _standard_bytes(b2_values["manifest_message"])
    if message != manifest_v2.target_delivery_artifact_manifest_v2_message(manifest) or _string(
        b2_values["manifest_sha256"]
    ) != manifest_v2.target_delivery_artifact_manifest_v2_sha256(manifest):
        raise ValueError("inherited B2 manifest is invalid")
    _verify_ed25519(
        public_key_base64=manifest_anchor.public_key_base64,
        signature_base64=manifest.signature_base64,
        message=message,
    )
    _verify_ed25519(
        public_key_base64=b1_policy.map_signer_trust_anchor.public_key_base64,
        signature_base64=delivery_map.signature_base64,
        message=map_signing.target_delivery_map_v1_canonical_message(delivery_map),
    )
    try:
        manifest_v2.validate_target_delivery_artifact_manifest_v2(
            delivery_map=delivery_map,
            static_delivery_projection=projection,
            b1_trust_policy=b1_policy,
            manifest_trust_anchor=manifest_anchor,
            role_inputs=cast(tuple[Any, Any, Any, Any], tuple(role_inputs)),
            v5_role_policy_inputs=cast(tuple[Any, Any, Any, Any], tuple(policy_inputs)),
            manifest=manifest,
        )
    except (AttributeError, TypeError, ValueError):
        raise ValueError("inherited B2 source evidence is invalid") from None
    return _B2Evidence(
        delivery_map=delivery_map,
        projection=projection,
        b1_policy=b1_policy,
        manifest_anchor=manifest_anchor,
        role_inputs=cast(tuple[Any, Any, Any, Any], tuple(role_inputs)),
        policy_inputs=cast(tuple[Any, Any, Any, Any], tuple(policy_inputs)),
        manifest=manifest,
    )


def _b64url(value: str, *, length: int) -> bytes:
    if type(value) is not str or len(value) != length or "=" in value:
        raise ValueError("base64url is invalid")
    try:
        decoded = base64.urlsafe_b64decode(value + "=" * (-len(value) % 4))
    except (binascii.Error, ValueError):
        raise ValueError("base64url is invalid") from None
    if base64.urlsafe_b64encode(decoded).decode("ascii").rstrip("=") != value:
        raise ValueError("base64url is invalid")
    return decoded


def _assert_redacted(value: object) -> None:
    forbidden_keys = {
        "private_key",
        "private_key_base64",
        "seed",
        "secret",
        "secret_value",
        "material_value",
        "provider_value",
        "uri",
        "url",
        "host",
        "hostname",
        "ip",
        "port",
        "container_id",
        "machine_id",
        "runtime_identifier",
        "network_identifier",
        "oci_repository",
        "derived_oci_repository",
        "topology",
        "callback",
        "handle",
    }
    forbidden_fragments = (
        "-----BEGIN",
        "PRIV" + "ATE KEY",
        "://",
        "localhost",
        "127.0.0.1",
        "192.168.",
        "/" + "Users/",
        "/" + "Volumes/",
    )
    if type(value) is dict:
        mapping = cast(dict[str, object], value)
        if (forbidden_keys | _FORBIDDEN_RAW_PREIMAGE_KEYS) & set(mapping):
            raise ValueError("public vector is not redacted")
        for nested in mapping.values():
            _assert_redacted(nested)
    elif type(value) is list:
        for nested in cast(list[object], value):
            _assert_redacted(nested)
    elif type(value) is str:
        if (
            any(fragment in value for fragment in forbidden_fragments)
            or _PRIVATE_OR_INTERNAL_ENDPOINT.search(value) is not None
        ):
            raise ValueError("public vector is not redacted")


def _assert_envelopes_redacted(document: dict[str, object]) -> None:
    for name in (
        "c0_policy",
        "c0_trust_anchor",
        "c0_matrix",
        "caller_pinned_c1_trust_anchor",
        "c1_policy",
        "bundle",
        "expected_acceptance",
    ):
        _assert_redacted(_json(_bytes(document[name])))


def _strings(value: object, *, active: set[int] | None = None) -> set[str]:
    """Collect only already-public scalar identities from a finite model graph."""

    if type(value) is str:
        return {cast(str, value)}
    if type(value) in (int, bool, bytes, type(None)):
        return set()
    seen = set() if active is None else active
    if isinstance(value, BaseModel):
        value_id = id(value)
        if value_id in seen:
            raise ValueError("public model graph is cyclic")
        seen.add(value_id)
        try:
            return set().union(
                *(_strings(item, active=seen) for item in value.model_dump(mode="python").values())
            )
        finally:
            seen.remove(value_id)
    if type(value) is tuple:
        return set().union(
            *(_strings(item, active=seen) for item in cast(tuple[object, ...], value))
        )
    if type(value) is list:
        return set().union(*(_strings(item, active=seen) for item in cast(list[object], value)))
    if type(value) is dict:
        return set().union(
            *(_strings(item, active=seen) for item in cast(dict[object, object], value).values())
        )
    return set()


@dataclass(frozen=True)
class _Evidence:
    b2: Any
    c0_policy: c0.TargetDeliveryFieldMatrixPolicyV1
    c0_anchor: c0.TargetDeliveryFieldMatrixTrustAnchorV1
    matrix: c0.TargetDeliveryFieldMatrixV1
    c1_anchor: c1.PerEdgeRuntimeProofBundleTrustAnchorV1
    c1_policy: c1.PerEdgeRuntimeProofBundlePolicyV1
    bundle: c1.PerEdgeRuntimeProofBundleV1
    acceptance: c1.PerEdgeRuntimeProofBundleAcceptanceV1


def _validate(document: dict[str, object]) -> _Evidence:
    top = _mapping(
        document,
        {
            "schema_version",
            "purpose",
            "base64_encoding",
            "immutable_dependencies",
            "c0_policy",
            "c0_trust_anchor",
            "c0_matrix",
            "caller_pinned_c1_trust_anchor",
            "c1_policy",
            "bundle",
            "expected_acceptance",
        },
    )
    if (
        top["schema_version"] != "rsd.per-edge-runtime-proof-bundle-v1-public-vector.v1"
        or top["purpose"] != "synthetic_offline_c1_expected_false_acceptance_public_vector"
        or top["base64_encoding"] != "base64url_fixed_segments_v1"
    ):
        raise ValueError("C1 vector metadata is invalid")
    dependencies = _mapping(top["immutable_dependencies"], {"b2_v2", "phase_a_v5"})
    b2_raw = _dependency(
        dependencies["b2_v2"],
        path=_B2_V2_VECTOR,
        sha256=_B2_V2_SHA256,
        byte_count=_B2_V2_BYTE_COUNT,
        line_count=_B2_V2_LINE_COUNT,
    )
    v5_raw = _dependency(
        dependencies["phase_a_v5"],
        path=_V5_VECTOR,
        sha256=_V5_SHA256,
        byte_count=_V5_BYTE_COUNT,
        line_count=_V5_LINE_COUNT,
    )
    _assert_envelopes_redacted(document)

    b2 = _revalidate_b2_v2(b2_raw=b2_raw, v5_raw=v5_raw)
    c0_policy = cast(
        c0.TargetDeliveryFieldMatrixPolicyV1,
        _model(_bytes(top["c0_policy"]), c0.TargetDeliveryFieldMatrixPolicyV1),
    )
    c0_anchor = cast(
        c0.TargetDeliveryFieldMatrixTrustAnchorV1,
        _model(_bytes(top["c0_trust_anchor"]), c0.TargetDeliveryFieldMatrixTrustAnchorV1),
    )
    matrix_payload = _bytes(top["c0_matrix"])
    matrix = c0.parse_target_delivery_field_matrix_v1_canonical_json(matrix_payload)
    if c0.target_delivery_field_matrix_v1_canonical_json(matrix) != matrix_payload:
        raise ValueError("C0 matrix is not canonical")
    c1_anchor = cast(
        c1.PerEdgeRuntimeProofBundleTrustAnchorV1,
        _model(
            _bytes(top["caller_pinned_c1_trust_anchor"]),
            c1.PerEdgeRuntimeProofBundleTrustAnchorV1,
        ),
    )
    c1_policy = cast(
        c1.PerEdgeRuntimeProofBundlePolicyV1,
        _model(_bytes(top["c1_policy"]), c1.PerEdgeRuntimeProofBundlePolicyV1),
    )
    bundle_payload = _bytes(top["bundle"])
    bundle = c1.parse_per_edge_runtime_proof_bundle_v1(bundle_payload)
    if c1.canonical_per_edge_runtime_proof_bundle_v1_bytes(bundle) != bundle_payload:
        raise ValueError("C1 bundle is not canonical")
    expected = cast(
        c1.PerEdgeRuntimeProofBundleAcceptanceV1,
        _model(_bytes(top["expected_acceptance"]), c1.PerEdgeRuntimeProofBundleAcceptanceV1),
    )

    try:
        c0.validate_target_delivery_field_matrix_v1(
            delivery_map=b2.delivery_map,
            static_delivery_projection=b2.projection,
            b1_trust_policy=b2.b1_policy,
            manifest_trust_anchor=b2.manifest_anchor,
            role_inputs=b2.role_inputs,
            v5_role_policy_inputs=b2.policy_inputs,
            manifest=b2.manifest,
            matrix_policy=c0_policy,
            matrix_trust_anchor=c0_anchor,
            matrix=matrix,
        )
        acceptance = c1.validate_per_edge_runtime_proof_bundle_v1(
            delivery_map=b2.delivery_map,
            static_delivery_projection=b2.projection,
            b1_trust_policy=b2.b1_policy,
            manifest_trust_anchor=b2.manifest_anchor,
            role_inputs=b2.role_inputs,
            v5_role_policy_inputs=b2.policy_inputs,
            manifest=b2.manifest,
            matrix_policy=c0_policy,
            matrix_trust_anchor=c0_anchor,
            matrix=matrix,
            bundle_policy=c1_policy,
            bundle_trust_anchor=c1_anchor,
            bundle=bundle,
        )
    except (c0.TargetDeliveryFieldMatrixError, c1.PerEdgeRuntimeProofBundleError):
        raise ValueError("C1 public vector evidence is invalid") from None
    if acceptance != expected:
        raise ValueError("C1 public vector acceptance is invalid")
    return _Evidence(
        b2=b2,
        c0_policy=c0_policy,
        c0_anchor=c0_anchor,
        matrix=matrix,
        c1_anchor=c1_anchor,
        c1_policy=c1_policy,
        bundle=bundle,
        acceptance=acceptance,
    )


def _immutable_document() -> dict[str, object]:
    """Read, hash-pin, and parse one fresh isolated public-vector document."""

    return _load_yaml(_immutable_vector_snapshot())


def _validated(raw: bytes | None = None) -> _Evidence:
    if raw is None:
        return _validate(_immutable_document())
    return _validate(_load_yaml(raw))


def _render(document: dict[str, object]) -> bytes:
    return yaml.dump(
        document,
        Dumper=_NoAliasDumper,
        allow_unicode=False,
        default_flow_style=False,
        sort_keys=False,
        width=1000,
    ).encode("ascii")


def _replace_envelope_json(
    document: dict[str, object], name: str, replacement: dict[str, object]
) -> None:
    payload = json.dumps(
        replacement,
        ensure_ascii=True,
        sort_keys=True,
        separators=(",", ":"),
        allow_nan=False,
    ).encode("ascii")
    encoded = base64.urlsafe_b64encode(payload).decode("ascii").rstrip("=")
    document[name] = {
        "encoding": "base64url_fixed_segments_v1",
        "segments": [
            encoded[index : index + _SEGMENT_LENGTH]
            for index in range(0, len(encoded), _SEGMENT_LENGTH)
        ],
    }


def test_fixed_public_vector_revalidates_c0_and_expected_false_acceptance() -> None:
    raw = _VECTOR.read_bytes()
    assert hashlib.sha256(raw).hexdigest() == _VECTOR_SHA256
    assert len(raw) == _VECTOR_BYTE_COUNT
    assert raw.count(b"\n") == _VECTOR_LINE_COUNT
    assert raw.count(b"# gitleaks:allow") == 0

    evidence = _validated()
    c0_public = Ed25519PublicKey.from_public_bytes(
        base64.b64decode(evidence.c0_anchor.public_key_base64, validate=True)
    )
    c0_public.verify(
        base64.b64decode(evidence.matrix.signature_base64, validate=True),
        c0.target_delivery_field_matrix_v1_message(evidence.matrix),
    )
    c1_public = Ed25519PublicKey.from_public_bytes(
        _b64url(evidence.c1_anchor.observer_public_key_b64, length=43)
    )
    c1_public.verify(
        _b64url(evidence.bundle.bundle_signature_b64, length=86),
        c1.per_edge_runtime_proof_bundle_v1_signature_message(evidence.bundle),
    )
    assert (
        c1.per_edge_runtime_proof_bundle_v1_sha256(evidence.bundle)
        == evidence.acceptance.bundle_sha256
    )
    assert len(evidence.bundle.observations) == 4
    assert all(len(item.observation_signature_b64) == 86 for item in evidence.bundle.observations)
    assert evidence.acceptance.non_authorizing is True
    assert all(getattr(evidence.acceptance, field) is False for field in _C1_OUTCOME_FIELDS)
    assert (
        evidence.acceptance.fresh,
        evidence.acceptance.replay_protected,
        evidence.acceptance.live_observed,
        evidence.acceptance.no_egress,
        evidence.acceptance.proof_passed,
        evidence.acceptance.ready,
    ) == (False, False, False, False, False, False)


def test_immutable_loader_rechecks_bytes_and_is_not_mutable_cache_state(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    first = _immutable_document()
    first_policy = cast(dict[str, object], first["c1_policy"])
    first_segments = cast(list[object], first_policy["segments"])
    original_segment = _string(first_segments[0])
    first_segments[0] = "A" * len(original_segment)

    second = _immutable_document()
    second_policy = cast(dict[str, object], second["c1_policy"])
    second_segments = cast(list[object], second_policy["segments"])
    assert _string(second_segments[0]) == original_segment

    vector_raw = _immutable_vector_snapshot()
    original_read_bytes = Path.read_bytes

    def stale_vector_bytes(path: Path) -> bytes:
        if path == _VECTOR:
            return vector_raw[:-1]
        return original_read_bytes(path)

    monkeypatch.setattr(Path, "read_bytes", stale_vector_bytes)
    with pytest.raises(ValueError, match="vector hash"):
        _immutable_document()

    def stale_dependency_bytes(path: Path) -> bytes:
        if path == _B2_V2_VECTOR:
            return b"x" * _B2_V2_BYTE_COUNT
        return original_read_bytes(path)

    monkeypatch.setattr(Path, "read_bytes", stale_dependency_bytes)
    with pytest.raises(ValueError, match="dependency bytes"):
        _validated()


def test_vector_binds_exact_four_c0_relations_and_signed_transport_assertions() -> None:
    evidence = _validated()
    assert tuple(
        (
            observation.observation_ordinal,
            observation.relation_ordinal,
            observation.c0_delivery_row_ordinal,
            observation.derived_lane_ordinal,
            observation.b2_component_ordinal,
            observation.signed_c0_lane,
            observation.initiator_component,
            observation.dependency_classification,
            observation.edge_transport_declaration,
        )
        for observation in evidence.bundle.observations
    ) == (
        (
            1,
            1,
            3,
            1,
            0,
            "primary",
            "primary_infisical",
            "primary_postgresql",
            "per_edge_runtime_proof_required_v1",
        ),
        (
            2,
            2,
            4,
            1,
            0,
            "primary",
            "primary_infisical",
            "primary_valkey",
            "per_edge_runtime_proof_required_v1",
        ),
        (
            3,
            3,
            8,
            2,
            2,
            "restore",
            "restore_infisical",
            "restore_postgresql",
            "per_edge_runtime_proof_required_v1",
        ),
        (
            4,
            4,
            9,
            2,
            2,
            "restore",
            "restore_infisical",
            "restore_valkey",
            "per_edge_runtime_proof_required_v1",
        ),
    )
    assert tuple(
        (relation.ordinal, relation.lane, relation.initiator_component, relation.dependency)
        for relation in evidence.matrix.application_dependencies
    ) == (
        (1, "primary", "primary_infisical", "primary_postgresql"),
        (2, "primary", "primary_infisical", "primary_valkey"),
        (3, "restore", "restore_infisical", "restore_postgresql"),
        (4, "restore", "restore_infisical", "restore_valkey"),
    )
    # The signed vector includes every permitted observer assertion pair.  They
    # are diagnostic classifications, not ordinal-to-transport live truth.
    assert {
        (item.transport_profile, item.listener_binding_subtype)
        for item in evidence.bundle.observations
    } == {
        ("tls_verified_v1", "tls_lan"),
        ("unpublished_loopback_or_network_v1", "loopback_only"),
        ("unpublished_loopback_or_network_v1", "isolated_network_only"),
    }
    assert all(
        type(relation.material_policy) is c0.ProviderMaterialPolicyV2
        for relation in evidence.matrix.application_dependencies
    )


def test_vector_c1_observer_namespace_is_disjoint_from_revalidated_inputs() -> None:
    evidence = _validated()
    original_strings = set().union(
        _strings(evidence.b2.delivery_map),
        _strings(evidence.b2.projection),
        _strings(evidence.b2.b1_policy),
        _strings(evidence.b2.manifest_anchor),
        _strings(evidence.b2.role_inputs),
        _strings(evidence.b2.policy_inputs),
        _strings(evidence.b2.manifest),
        _strings(evidence.c0_policy),
        _strings(evidence.c0_anchor),
        _strings(evidence.matrix),
    )
    observer_values = {
        evidence.c1_anchor.observer_root_id,
        evidence.c1_anchor.observer_key_id,
        evidence.c1_anchor.observer_public_key_b64,
        evidence.c1_anchor.observer_fingerprint_sha256,
        evidence.c1_anchor.authority_identity_sha256,
        evidence.c1_anchor.independence_domain_sha256,
    }
    assert len(observer_values) == 6
    assert observer_values.isdisjoint(original_strings)


@pytest.mark.parametrize(
    "raw",
    (
        b"schema_version: value\nschema_version: value\n",
        b"item: &value scalar\nother: *value\n",
        b"item:\n  - value\n",
    ),
)
def test_loader_rejects_duplicate_alias_and_wrong_shape(raw: bytes) -> None:
    with pytest.raises(ValueError):
        _validated(raw)


@pytest.mark.parametrize(
    "raw",
    (
        b"item: !!str value\n",
        b"item: 1.0\n",
        b"item: yes\n",
        b"item: null\n",
        b"item: 2026-08-30T12:00:00Z\n",
    ),
)
def test_loader_rejects_tags_and_ambiguous_yaml_scalar_spellings(raw: bytes) -> None:
    with pytest.raises(ValueError):
        _load_yaml(raw)


def test_vector_rejects_truncation_and_noncanonical_fixed_segment_base64url() -> None:
    raw = _immutable_vector_snapshot()
    with pytest.raises(ValueError):
        _validated(raw[:-1])
    document = _load_yaml(raw)
    envelope = cast(dict[str, object], document["c1_policy"])
    segments = cast(list[object], envelope["segments"])
    segments[0] = cast(str, segments[0]) + "="
    with pytest.raises(ValueError, match="base64url"):
        _validated(_render(document))


def test_vector_rejects_observation_order_and_signature_mutations() -> None:
    raw = _immutable_vector_snapshot()
    document = _load_yaml(raw)
    bundle = _json(_bytes(document["bundle"]))
    observations = cast(list[object], bundle["observations"])
    bundle["observations"] = list(reversed(observations))
    _replace_envelope_json(document, "bundle", bundle)
    with pytest.raises(ValueError):
        _validated(_render(document))

    document = _load_yaml(raw)
    bundle = _json(_bytes(document["bundle"]))
    signature = _string(bundle["bundle_signature_b64"])
    bundle["bundle_signature_b64"] = ("A" if signature[0] != "A" else "B") + signature[1:]
    _replace_envelope_json(document, "bundle", bundle)
    with pytest.raises(ValueError, match="evidence"):
        _validated(_render(document))


def test_vector_rejects_dependency_pin_and_unredacted_carrier_mutations() -> None:
    raw = _immutable_vector_snapshot()
    document = _load_yaml(raw)
    dependency = cast(
        dict[str, object], cast(dict[str, object], document["immutable_dependencies"])["b2_v2"]
    )
    dependency["sha256"] = "0" * 64
    with pytest.raises(ValueError, match="dependency pin"):
        _validated(_render(document))

    document = _load_yaml(raw)
    bundle = _json(_bytes(document["bundle"]))
    bundle["uri"] = "https" + "://invalid.example"
    _replace_envelope_json(document, "bundle", bundle)
    with pytest.raises(ValueError, match="redacted"):
        _validated(_render(document))


@pytest.mark.parametrize(
    "unsafe",
    ("10" + ".0.0.1", "169" + ".254.1.1", "fe80" + "::1", "node" + ".lab"),
)
def test_vector_rejects_private_internal_and_lab_endpoint_markers(unsafe: str) -> None:
    document = _load_yaml(_immutable_vector_snapshot())
    bundle = _json(_bytes(document["bundle"]))
    bundle["runtime_classification_sha256"] = unsafe
    _replace_envelope_json(document, "bundle", bundle)
    with pytest.raises(ValueError, match="redacted"):
        _validated(_render(document))


def test_vector_keeps_anchor_external_and_has_no_acceptance_back_edge() -> None:
    document = _load_yaml(_immutable_vector_snapshot())
    assert "c0_acceptance" not in document
    assert "b2_acceptance" not in document
    assert "acceptance" not in document
    bundle = _json(_bytes(document["bundle"]))
    assert "observer_public_key_b64" not in bundle
    assert (
        "acceptance"
        not in inspect.signature(c1.validate_per_edge_runtime_proof_bundle_v1).parameters
    )
