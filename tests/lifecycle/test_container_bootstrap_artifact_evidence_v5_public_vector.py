"""Immutable, fail-closed public fixture coverage for Phase-A V5 evidence.

The fixture carries stable, language-neutral canonical JSON bytes and public
Ed25519 signature material. An independent audit can verify those bytes with
OpenSSL or another compatible verifier, while this repository keeps its proof
dependency-local for portable Python test execution.
"""

from __future__ import annotations

import base64
import copy
import hashlib
import json
import re
from functools import cache
from pathlib import Path
from typing import cast

import pytest
import yaml
from yaml.events import AliasEvent
from yaml.nodes import MappingNode, Node, ScalarNode, SequenceNode
from yaml.tokens import AliasToken, AnchorToken, TagToken

from omninode_rsd.lifecycle import container_attach_static_v4 as static_v4
from omninode_rsd.lifecycle import container_bootstrap_artifact_evidence_v5 as evidence_v5
from omninode_rsd.lifecycle import container_bootstrap_oci_safe_config_evidence_v5 as oci_v5

_ROOT = Path(__file__).parents[2] / "src/omninode_rsd/lifecycle"
_VECTOR = _ROOT / "container_bootstrap_artifact_evidence_v5_public_vector.yaml"
_B2_VECTOR = _ROOT / "target_delivery_artifact_manifest_public_vector.yaml"
_V4_VECTOR = _ROOT / "container_attach_static_v4_vectors.yaml"
_COMPONENTS = (
    "primary_infisical",
    "primary_valkey",
    "restore_infisical",
    "restore_valkey",
)
_MAX_VECTOR_BYTES = 2 * 1024 * 1024
_VECTOR_SHA256 = "6c66df411fd080f1d20e2cfe8f8004f600a1cfe1fe5942259b148af15166ca91"
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
        [0-9][0-9_]*
        (?::[0-9][0-9_]*(?::[0-9][0-9_]*)*)?
        (?:\.[0-9_]*)?
        (?:[eE][+-]?[0-9_]+)? |
        \.[0-9_]+(?:[eE][+-]?[0-9_]+)?
    )
    \Z
    """,
    re.ASCII | re.VERBOSE,
)
_YAML_TIMESTAMP_LIKE = re.compile(r"""[0-9]{4}-[0-9]{1,2}-[0-9]{1,2}(?:[Tt \t].*)?\Z""", re.ASCII)
_YAML_BOOL_TAG = "tag:yaml.org,2002:bool"
_YAML_FLOAT_TAG = "tag:yaml.org,2002:float"
_YAML_INT_TAG = "tag:yaml.org,2002:int"
_YAML_NULL_TAG = "tag:yaml.org,2002:null"
_YAML_TIMESTAMP_TAG = "tag:yaml.org,2002:timestamp"
_IMMUTABLE_VECTOR_SHA256S = {
    "container_attach_static_v3_vectors.yaml": (
        "f14144b4b79b1b5a282b5b068f5a1a2c523f54283db1954be94aae7e014e9110"
    ),
    "container_attach_static_v4_vectors.yaml": (
        "61c7ff5383c0d7617e191476f2faf7ffb9f2829929f4736e83cdbafce4f6d627"
    ),
    "container_bootstrap_artifact_evidence_v4_vectors.yaml": (
        "248bdc9d3aedb18f7b84feb93e28faaa6d6082602d1f0a03e4d4095da75b1a68"
    ),
    "target_delivery_map_projection_binding_public_vector.yaml": (
        "5955a5788ab7360e23e85fa221962cdf63318759f48f051d5746add9d2770893"
    ),
    "target_delivery_artifact_manifest_public_vector.yaml": (
        "4b10ec2b37f0768d0a8fa283d5a26cc6020e26a968ebb3928b78d4b8f73c65ed"
    ),
}


class _StrictVectorLoader(yaml.SafeLoader):
    """Safe YAML loader that rejects duplicate mapping keys."""


def _strict_mapping(
    loader: yaml.SafeLoader, node: yaml.MappingNode, deep: bool = False
) -> dict[str, object]:
    result: dict[str, object] = {}
    for key_node, value_node in node.value:
        key = loader.construct_object(key_node, deep=deep)
        if type(key) is not str or key in result:
            raise ValueError("vector mapping is invalid")
        result[key] = loader.construct_object(value_node, deep=deep)
    return result


_StrictVectorLoader.add_constructor(yaml.resolver.BaseResolver.DEFAULT_MAPPING_TAG, _strict_mapping)


class _NoAliasDumper(yaml.SafeDumper):
    def ignore_aliases(self, data: object) -> bool:
        return True


def _canonical_json(value: object) -> bytes:
    return json.dumps(
        value, ensure_ascii=True, sort_keys=True, separators=(",", ":"), allow_nan=False
    ).encode("ascii")


def _safe_tree(value: object, *, depth: int = 0) -> None:
    if depth > 32:
        raise ValueError("vector exceeds depth")
    if type(value) in (str, int, bool):
        if type(value) is str and not value.isascii():
            raise ValueError("vector contains non-ASCII text")
        return
    if type(value) is list:
        for item in cast(list[object], value):
            _safe_tree(item, depth=depth + 1)
        return
    if type(value) is dict:
        for key, item in cast(dict[object, object], value).items():
            if type(key) is not str or not key.isascii():
                raise ValueError("vector key is invalid")
            _safe_tree(item, depth=depth + 1)
        return
    raise ValueError("vector scalar is invalid")


def _validate_plain_yaml_scalar_portability(value: str) -> None:
    """Require a spelling whose scalar meaning is stable across YAML schemas."""

    if value in _CANONICAL_YAML_BOOLEANS or _CANONICAL_YAML_INTEGER.fullmatch(value):
        return
    if (
        not value
        or _YAML_11_BOOLEAN_LIKE.fullmatch(value) is not None
        or _YAML_NULL_LIKE.fullmatch(value) is not None
        or _YAML_SPECIAL_FLOAT_LIKE.fullmatch(value) is not None
        or _YAML_NUMERIC_LIKE.fullmatch(value) is not None
        or _YAML_TIMESTAMP_LIKE.fullmatch(value) is not None
    ):
        raise ValueError("vector scalar spelling is invalid")


def _validate_yaml_scalar_spellings(node: Node) -> None:
    """Reject implicit scalar forms whose meaning varies across YAML schemas."""

    if isinstance(node, ScalarNode):
        if node.style is None:
            _validate_plain_yaml_scalar_portability(node.value)
        if node.tag == _YAML_BOOL_TAG:
            if node.style is not None or node.value not in _CANONICAL_YAML_BOOLEANS:
                raise ValueError("vector scalar spelling is invalid")
        elif node.tag == _YAML_INT_TAG:
            if node.style is not None or _CANONICAL_YAML_INTEGER.fullmatch(node.value) is None:
                raise ValueError("vector scalar spelling is invalid")
        elif node.tag in {_YAML_FLOAT_TAG, _YAML_NULL_TAG, _YAML_TIMESTAMP_TAG}:
            raise ValueError("vector scalar spelling is invalid")
        return
    if isinstance(node, SequenceNode):
        for child in node.value:
            _validate_yaml_scalar_spellings(child)
        return
    if isinstance(node, MappingNode):
        for key_node, value_node in node.value:
            _validate_yaml_scalar_spellings(key_node)
            _validate_yaml_scalar_spellings(value_node)
        return
    raise ValueError("vector YAML node is invalid")


def _load_yaml(raw: bytes) -> dict[str, object]:
    if not 1 <= len(raw) <= _MAX_VECTOR_BYTES or not raw.isascii():
        raise ValueError("vector bytes are invalid")
    text = raw.decode("ascii")
    if not text.endswith("\n") or any(line.endswith((" ", "\t")) for line in text.splitlines()):
        raise ValueError("vector whitespace is invalid")
    for token in yaml.scan(text):
        if isinstance(token, (AliasToken, AnchorToken, TagToken)):
            raise ValueError("vector YAML feature is invalid")
    if any(isinstance(event, AliasEvent) for event in yaml.parse(text)):
        raise ValueError("vector YAML feature is invalid")
    nodes = list(yaml.compose_all(text, Loader=_StrictVectorLoader))
    if len(nodes) != 1 or nodes[0] is None:
        raise ValueError("vector document is invalid")
    _validate_yaml_scalar_spellings(nodes[0])
    parsed = yaml.load(text, Loader=_StrictVectorLoader)
    if type(parsed) is not dict:
        raise ValueError("vector document is invalid")
    value = cast(dict[str, object], parsed)
    _safe_tree(value)
    return value


def _mapping(value: object, expected: set[str]) -> dict[str, object]:
    if type(value) is not dict or set(value) != expected:
        raise ValueError("vector mapping shape is invalid")
    return cast(dict[str, object], value)


def _string(value: object) -> str:
    if type(value) is not str or not value.isascii():
        raise ValueError("vector string is invalid")
    return cast(str, value)


def _integer(value: object) -> int:
    if type(value) is not int:
        raise ValueError("vector integer is invalid")
    return cast(int, value)


def _boolean(value: object) -> bool:
    if type(value) is not bool:
        raise ValueError("vector boolean is invalid")
    return cast(bool, value)


def _bytes(value: object, *, fixed_segments: bool = True) -> bytes:
    item = _mapping(value, {"encoding", "segments"})
    if (
        item["encoding"] != "standard_base64_fixed_segments_v1"
        or type(item["segments"]) is not list
    ):
        raise ValueError("vector base64 envelope is invalid")
    segments = cast(list[object], item["segments"])
    if not segments or any(
        type(segment) is not str or not segment.isascii() for segment in segments
    ):
        raise ValueError("vector base64 segments are invalid")
    rendered = cast(list[str], segments)
    if fixed_segments and (
        any(len(segment) != 76 for segment in rendered[:-1]) or not 1 <= len(rendered[-1]) <= 76
    ):
        raise ValueError("vector base64 segmentation is invalid")
    encoded = "".join(rendered)
    try:
        decoded = base64.b64decode(encoded, validate=True)
    except (ValueError, base64.binascii.Error):
        raise ValueError("vector base64 is invalid") from None
    if base64.b64encode(decoded).decode("ascii") != encoded:
        raise ValueError("vector base64 is invalid")
    return decoded


def _vector_bytes(payload: bytes) -> dict[str, object]:
    encoded = base64.b64encode(payload).decode("ascii")
    return {
        "encoding": "standard_base64_fixed_segments_v1",
        "segments": [encoded[index : index + 76] for index in range(0, len(encoded), 76)],
    }


def _as_tuples(value: object) -> object:
    if type(value) is list:
        return tuple(_as_tuples(item) for item in cast(list[object], value))
    if type(value) is dict:
        return {key: _as_tuples(item) for key, item in cast(dict[str, object], value).items()}
    return value


def _render(doc: dict[str, object]) -> bytes:
    return yaml.dump(
        doc,
        Dumper=_NoAliasDumper,
        allow_unicode=False,
        default_flow_style=False,
        sort_keys=False,
        width=1000,
    ).encode("ascii")


def _reordered_json(payload: bytes, *path: str | int) -> bytes:
    value = json.loads(payload.decode("ascii"))
    target: object = value
    for element in path:
        target = cast(dict[str, object] | list[object], target)[element]
    if type(target) is not dict:
        raise ValueError("reorder target is invalid")
    parent = cast(dict[str, object], target)
    reordered = dict(reversed(list(parent.items())))
    if not path:
        value = reordered
    else:
        target_parent: object = value
        for element in path[:-1]:
            target_parent = cast(dict[str, object] | list[object], target_parent)[element]
        cast(dict[str, object] | list[object], target_parent)[path[-1]] = reordered
    return json.dumps(value, ensure_ascii=True, sort_keys=False, separators=(",", ":")).encode(
        "ascii"
    )


def _set_json_vector(doc: dict[str, object], *path: str | int, payload: bytes) -> None:
    target: object = doc
    for element in path[:-1]:
        target = cast(dict[str, object] | list[object], target)[element]
    cast(dict[str, object] | list[object], target)[path[-1]] = _vector_bytes(payload)


def _closure_json(doc: dict[str, object], role_index: int) -> dict[str, object]:
    role = cast(list[object], doc["roles"])[role_index]
    payload = _bytes(cast(dict[str, object], role)["closure"])
    decoded = json.loads(payload.decode("ascii"))
    if type(decoded) is not dict:
        raise ValueError("closure JSON is invalid")
    return cast(dict[str, object], decoded)


def _write_closure_json(
    doc: dict[str, object], role_index: int, closure: dict[str, object]
) -> None:
    _set_json_vector(doc, "roles", role_index, "closure", payload=_canonical_json(closure))


def _assert_non_authorizing(value: object) -> None:
    if type(value) is dict:
        mapping = cast(dict[str, object], value)
        required = {
            "non_authorizing": True,
            "evidence_effect_allowed": False,
            "build_allowed": False,
            "materialization_allowed": False,
            "attach_allowed": False,
        }
        for key, expected in required.items():
            if key in mapping and mapping[key] is not expected:
                raise ValueError("vector effect flag is invalid")
        for nested in mapping.values():
            _assert_non_authorizing(nested)
    elif type(value) is list:
        for nested in cast(list[object], value):
            _assert_non_authorizing(nested)


def _assert_no_raw_config(value: object) -> None:
    forbidden_keys = {"User", "WorkingDir", "Env", "config"}
    forbidden_values = {
        "APP_BUILD_VARIANT",
        "PATH=/usr/bin:/bin",
        "RSD_PHASE=offline-public-vector",
    }
    if type(value) is dict:
        mapping = cast(dict[str, object], value)
        if forbidden_keys & set(mapping):
            raise ValueError("raw OCI config key is present")
        for nested in mapping.values():
            _assert_no_raw_config(nested)
    elif type(value) is list:
        for nested in cast(list[object], value):
            _assert_no_raw_config(nested)
    elif type(value) is str and value in forbidden_values:
        raise ValueError("raw OCI config value is present")


def _source(values: object) -> dict[str, object]:
    source = _mapping(
        values,
        {
            "canonical_repository_identity_sha256",
            "git_object_format",
            "commit_oid",
            "tree_oid",
            "canonical_source_snapshot_sha256",
            "wrapper_subtree_path",
            "wrapper_tree_entries",
            "source_clean",
            "untracked_files_absent",
            "submodules_absent",
            "recipe_sha256",
            "toolchain_sha256",
            "lock_sha256",
            "vendor_sha256",
            "builder_recipe_identity_sha256",
        },
    )
    for key in (
        "canonical_repository_identity_sha256",
        "git_object_format",
        "commit_oid",
        "tree_oid",
        "canonical_source_snapshot_sha256",
        "wrapper_subtree_path",
        "recipe_sha256",
        "toolchain_sha256",
        "lock_sha256",
        "vendor_sha256",
        "builder_recipe_identity_sha256",
    ):
        _string(source[key])
    for key in ("source_clean", "untracked_files_absent", "submodules_absent"):
        if _boolean(source[key]) is not True:
            raise ValueError("source cleanliness is invalid")
    if type(source["wrapper_tree_entries"]) is not list:
        raise ValueError("source tree entries are invalid")
    return source


@cache
def _immutable_reference_documents() -> tuple[dict[str, object], dict[str, object]]:
    return _load_yaml(_V4_VECTOR.read_bytes()), _load_yaml(_B2_VECTOR.read_bytes())


def _assert_fixture_global_identity_separation(
    *,
    root: static_v4.ContainerBootstrapStaticProfileTrustAnchorV4,
    policies: tuple[evidence_v5.ContainerBootstrapBuildWorkerTrustPolicyV5, ...],
    run_ids: tuple[str, ...],
) -> None:
    """Enforce fixture-wide collision coverage beyond each V5 policy."""

    anchors = tuple(anchor for policy in policies for anchor in policy.worker_trust_anchors)
    policy_ids = {policy.policy_id for policy in policies}
    domains = {policy.independence_domain_sha256 for policy in policies}
    worker_key_ids = {anchor.key_id for anchor in anchors}
    public_keys = {anchor.public_key_base64 for anchor in anchors}
    fingerprints = {anchor.public_key_fingerprint_sha256 for anchor in anchors}
    worker_ids = {anchor.worker_identity_sha256 for anchor in anchors}
    authority_ids = {anchor.authority_identity_sha256 for anchor in anchors}
    builder_ids = {anchor.physical_builder_identity_sha256 for anchor in anchors}
    unique_run_ids = set(run_ids)

    # Fixture-only collision coverage: all eight builder identifiers are distinct.
    # The V5 contract only requires each role's A/B builder pair to differ; a pair
    # may be reused across roles.
    if not (
        len(policies) == len(policy_ids) == len(domains) == 4
        and len(anchors)
        == len(worker_key_ids)
        == len(public_keys)
        == len(fingerprints)
        == len(worker_ids)
        == len(authority_ids)
        == len(builder_ids)
        == len(run_ids)
        == len(unique_run_ids)
        == 8
    ):
        raise ValueError("fixture global identity namespace is invalid")
    if (
        root.key_id in worker_key_ids
        or root.key_id in policy_ids
        or bool(worker_key_ids & policy_ids)
    ):
        raise ValueError("fixture key identifier namespace is invalid")
    if root.public_key_base64 in public_keys:
        raise ValueError("fixture public key namespace is invalid")
    all_hashes = (
        domains
        | worker_ids
        | authority_ids
        | builder_ids
        | fingerprints
        | {root.public_key_fingerprint_sha256}
    )
    if len(all_hashes) != 37:
        raise ValueError("fixture hash identity namespace is invalid")


def _validate(doc: dict[str, object]) -> None:
    top = _mapping(
        doc,
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
    if top["schema_version"] != "rsd.container-bootstrap-artifact-evidence-v5-public-vector.v1":
        raise ValueError("vector schema is invalid")
    if top["purpose"] != "synthetic_offline_cross_language_phase_a_v5_public_vector":
        raise ValueError("vector purpose is invalid")
    if top["base64_encoding"] != "standard_base64_fixed_segments_v1":
        raise ValueError("vector base64 policy is invalid")
    if top["component_order"] != list(_COMPONENTS):
        raise ValueError("vector component order is invalid")
    common_oci = _mapping(top["common_oci"], {"repository"})
    if common_oci["repository"] != "registry.example.invalid/omninode/rsd":
        raise ValueError("vector OCI repository is invalid")
    source = _source(top["common_source"])
    root_bytes = _bytes(top["common_profile_root"])
    root = static_v4.parse_container_bootstrap_static_profile_trust_anchor_v4_canonical_json(
        root_bytes
    )
    static_vector, b2 = _immutable_reference_documents()
    if root_bytes != _bytes(
        static_vector["profile_root_canonical_json_utf8_base64"], fixed_segments=False
    ):
        raise ValueError("profile root is not the immutable common V4 root")
    b2_roles = cast(list[object], b2["roles"])
    raw_roles = top["roles"]
    if type(raw_roles) is not list or len(raw_roles) != len(_COMPONENTS) or len(b2_roles) != 4:
        raise ValueError("vector role count is invalid")

    policies: list[evidence_v5.ContainerBootstrapBuildWorkerTrustPolicyV5] = []
    run_ids: list[str] = []
    for ordinal, component in enumerate(_COMPONENTS):
        role = _mapping(
            cast(list[object], raw_roles)[ordinal],
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
        expected = _mapping(
            role["expected"],
            {
                "profile_sha256",
                "profile_envelope_sha256",
                "worker_policy_sha256",
                "closure_sha256",
                "oci_safe_config_evidence_sha256",
                "acceptance_sha256",
                "worker_attestation_sha256s",
                "worker_run_ids",
                "ordinal",
                "selected_delivery_route_sha256",
                "derived_reference",
            },
        )
        if role["component"] != component or _integer(role["ordinal"]) != ordinal:
            raise ValueError("role ordering is invalid")
        if _integer(expected["ordinal"]) != ordinal:
            raise ValueError("expected role ordinal is invalid")
        envelope_bytes = _bytes(role["profile_envelope"])
        b2_role = _mapping(
            b2_roles[ordinal], {"profile_envelope", "projection_binding", "phase_a_closure"}
        )
        if envelope_bytes != _bytes(b2_role["profile_envelope"]):
            raise ValueError("profile envelope is not the immutable B2 envelope")
        envelope = (
            static_v4.parse_container_bootstrap_static_role_profile_envelope_v4_canonical_json(
                envelope_bytes
            )
        )
        profile = static_v4.verify_container_bootstrap_static_role_profile_envelope_v4(
            envelope=envelope, profile_trust_anchor=root
        )
        policy_bytes = _bytes(role["worker_policy"])
        closure_bytes = _bytes(role["closure"])
        acceptance_bytes = _bytes(role["acceptance"])
        policy = evidence_v5.parse_container_bootstrap_build_worker_trust_policy_v5_canonical_json(
            policy_bytes
        )
        closure = evidence_v5.parse_container_bootstrap_artifact_evidence_closure_v5_canonical_json(
            closure_bytes
        )
        acceptance = (
            evidence_v5.parse_container_bootstrap_artifact_evidence_acceptance_v5_canonical_json(
                acceptance_bytes
            )
        )
        if (
            policy_bytes
            != evidence_v5.container_bootstrap_build_worker_trust_policy_v5_canonical_json(policy)
        ):
            raise ValueError("worker policy is not canonical")
        if (
            closure_bytes
            != evidence_v5.container_bootstrap_artifact_evidence_closure_v5_canonical_json(closure)
        ):
            raise ValueError("closure is not canonical")
        if (
            acceptance_bytes
            != evidence_v5.container_bootstrap_artifact_evidence_acceptance_v5_canonical_json(
                acceptance
            )
        ):
            raise ValueError("acceptance is not canonical")
        validated = evidence_v5.validate_container_bootstrap_artifact_evidence_closure_v5(
            closure=closure,
            worker_trust_policy=policy,
            profile_envelope=envelope,
            profile_trust_anchor=root,
        )
        if validated != acceptance:
            raise ValueError("acceptance does not exactly match closure validation")
        expected_strings = (
            ("profile_sha256", profile.profile_sha256),
            (
                "profile_envelope_sha256",
                static_v4.container_bootstrap_static_role_profile_envelope_v4_sha256(envelope),
            ),
            (
                "worker_policy_sha256",
                evidence_v5.container_bootstrap_build_worker_trust_policy_v5_sha256(policy),
            ),
            ("closure_sha256", validated.closure_sha256),
            (
                "oci_safe_config_evidence_sha256",
                oci_v5.container_bootstrap_oci_safe_config_evidence_v5_sha256(
                    closure.oci_safe_config_evidence
                ),
            ),
            (
                "acceptance_sha256",
                evidence_v5.container_bootstrap_artifact_evidence_acceptance_v5_sha256(acceptance),
            ),
            ("selected_delivery_route_sha256", profile.selected_delivery_route_sha256),
            ("derived_reference", closure.oci_safe_config_evidence.derived_reference),
        )
        for key, actual in expected_strings:
            if expected[key] != actual:
                raise ValueError(f"expected {key} is invalid")
        if closure.oci_safe_config_evidence.derived_repository != common_oci["repository"]:
            raise ValueError("role repository diverges")
        hashes = expected["worker_attestation_sha256s"]
        runs = expected["worker_run_ids"]
        if type(hashes) is not list or type(runs) is not list or len(hashes) != len(runs) != 2:
            raise ValueError("worker expectation count is invalid")
        for item, expected_hash, expected_run, _trust_anchor in zip(
            closure.worker_attestations, hashes, runs, policy.worker_trust_anchors, strict=True
        ):
            if (
                expected_hash
                != evidence_v5.container_bootstrap_artifact_worker_attestation_v5_sha256(item)
            ):
                raise ValueError("worker attestation hash is invalid")
            if expected_run != item.run_id:
                raise ValueError("worker run identifier is invalid")
            source_scalars = (
                "canonical_repository_identity_sha256",
                "git_object_format",
                "commit_oid",
                "tree_oid",
                "canonical_source_snapshot_sha256",
                "wrapper_subtree_path",
                "source_clean",
                "untracked_files_absent",
                "submodules_absent",
                "recipe_sha256",
                "toolchain_sha256",
                "lock_sha256",
                "vendor_sha256",
                "builder_recipe_identity_sha256",
            )
            if any(getattr(item, key) != source[key] for key in source_scalars):
                raise ValueError("worker source provenance diverges")
            entries = [entry.model_dump(mode="json") for entry in item.wrapper_tree_entries]
            if entries != source["wrapper_tree_entries"]:
                raise ValueError("worker source tree diverges")
            if item.component != component or item.component_role != profile.component_role:
                raise ValueError("worker role binding diverges")
            run_ids.append(item.run_id)
        policies.append(policy)
        closure_model = closure.model_dump(mode="json")
        acceptance_model = acceptance.model_dump(mode="json")
        _assert_non_authorizing(closure_model)
        _assert_non_authorizing(acceptance_model)
        _assert_no_raw_config(closure_model)
        _assert_no_raw_config(acceptance_model)
    _assert_fixture_global_identity_separation(
        root=root, policies=tuple(policies), run_ids=tuple(run_ids)
    )


@cache
def _valid_immutable_document() -> dict[str, object]:
    raw = _VECTOR.read_bytes()
    if hashlib.sha256(raw).hexdigest() != _VECTOR_SHA256:
        raise ValueError("immutable V5 public vector hash is invalid")
    document = _load_yaml(raw)
    _validate(document)
    return document


def _validated_document(raw: bytes | None = None) -> dict[str, object]:
    if raw is None:
        return copy.deepcopy(_valid_immutable_document())
    document = _load_yaml(raw)
    _validate(document)
    return document


def _fixture_identity_inputs() -> tuple[
    static_v4.ContainerBootstrapStaticProfileTrustAnchorV4,
    tuple[evidence_v5.ContainerBootstrapBuildWorkerTrustPolicyV5, ...],
    tuple[str, ...],
]:
    document = _validated_document()
    root = static_v4.parse_container_bootstrap_static_profile_trust_anchor_v4_canonical_json(
        _bytes(document["common_profile_root"])
    )
    policies: list[evidence_v5.ContainerBootstrapBuildWorkerTrustPolicyV5] = []
    run_ids: list[str] = []
    for role_value in cast(list[object], document["roles"]):
        role = cast(dict[str, object], role_value)
        policies.append(
            evidence_v5.parse_container_bootstrap_build_worker_trust_policy_v5_canonical_json(
                _bytes(role["worker_policy"])
            )
        )
        closure = evidence_v5.parse_container_bootstrap_artifact_evidence_closure_v5_canonical_json(
            _bytes(role["closure"])
        )
        run_ids.extend(item.run_id for item in closure.worker_attestations)
    return root, tuple(policies), tuple(run_ids)


def _must_reject(document: dict[str, object]) -> None:
    with pytest.raises((ValueError, evidence_v5.ContainerBootstrapArtifactEvidenceV5Error)):
        _validated_document(_render(document))


def test_fixed_public_vector_validates_exactly_and_preserves_prior_fixtures() -> None:
    assert hashlib.sha256(_VECTOR.read_bytes()).hexdigest() == _VECTOR_SHA256
    assert _VECTOR.read_bytes().count(b"# gitleaks:allow") == 5
    for filename, expected in _IMMUTABLE_VECTOR_SHA256S.items():
        assert hashlib.sha256((_ROOT / filename).read_bytes()).hexdigest() == expected
    _validated_document()


def test_immutable_baseline_hash_rejects_stale_on_disk_bytes(
    monkeypatch: pytest.MonkeyPatch, tmp_path: Path
) -> None:
    raw = _VECTOR.read_bytes()
    stale_path = tmp_path / "stale-phase-a-v5-vector.yaml"
    stale_path.write_bytes(raw + b"\n")
    _valid_immutable_document.cache_clear()
    monkeypatch.setitem(globals(), "_VECTOR", stale_path)
    try:
        with pytest.raises(ValueError, match="immutable V5 public vector hash"):
            _validated_document()

        supplied_mutation = _load_yaml(raw)
        first_role = cast(dict[str, object], cast(list[object], supplied_mutation["roles"])[0])
        cast(dict[str, object], first_role["expected"])["closure_sha256"] = "0" * 64
        with pytest.raises(ValueError, match="expected closure_sha256"):
            _validated_document(_render(supplied_mutation))
    finally:
        _valid_immutable_document.cache_clear()


def test_fixture_identity_separation_rejects_cross_role_key_id_collision() -> None:
    root, policies, run_ids = _fixture_identity_inputs()
    mutated_policies = list(policies)
    mutated_anchors = list(mutated_policies[1].worker_trust_anchors)
    mutated_anchors[0] = mutated_anchors[0].model_copy(
        update={"key_id": policies[0].worker_trust_anchors[0].key_id}
    )
    mutated_policies[1] = mutated_policies[1].model_copy(
        update={"worker_trust_anchors": tuple(mutated_anchors)}
    )

    with pytest.raises(ValueError, match="fixture global identity namespace"):
        _assert_fixture_global_identity_separation(
            root=root, policies=tuple(mutated_policies), run_ids=run_ids
        )


def test_fixture_identity_separation_rejects_cross_category_hash_collision() -> None:
    root, policies, run_ids = _fixture_identity_inputs()
    mutated_policies = list(policies)
    mutated_anchors = list(mutated_policies[1].worker_trust_anchors)
    mutated_anchors[0] = mutated_anchors[0].model_copy(
        update={"worker_identity_sha256": policies[0].independence_domain_sha256}
    )
    mutated_policies[1] = mutated_policies[1].model_copy(
        update={"worker_trust_anchors": tuple(mutated_anchors)}
    )

    with pytest.raises(ValueError, match="fixture hash identity namespace"):
        _assert_fixture_global_identity_separation(
            root=root, policies=tuple(mutated_policies), run_ids=run_ids
        )


@pytest.mark.parametrize("mutation", ("swap", "duplicate", "omit", "relabel"))
def test_public_vector_rejects_role_order_and_identity_mutations(mutation: str) -> None:
    doc = copy.deepcopy(_validated_document())
    roles = cast(list[object], doc["roles"])
    if mutation == "swap":
        roles[0], roles[1] = roles[1], roles[0]
    elif mutation == "duplicate":
        roles[1] = copy.deepcopy(roles[0])
    elif mutation == "omit":
        roles.pop()
    else:
        cast(dict[str, object], roles[2])["component"] = "primary_valkey"
    _must_reject(doc)


@pytest.mark.parametrize(
    ("target", "path"),
    (
        ("common_profile_root", ()),
        ("profile_envelope", ("roles", 0, "profile_envelope")),
        ("worker_policy", ("roles", 0, "worker_policy")),
        ("policy_anchor", ("roles", 0, "worker_policy")),
    ),
)
def test_public_vector_rejects_reordered_canonical_payloads(
    target: str, path: tuple[str | int, ...]
) -> None:
    doc = copy.deepcopy(_validated_document())
    if target == "common_profile_root":
        source = _bytes(doc["common_profile_root"])
        doc["common_profile_root"] = _vector_bytes(_reordered_json(source))
    else:
        value: object = doc
        for item in path:
            value = cast(dict[str, object] | list[object], value)[item]
        payload = _bytes(value)
        reordered = (
            _reordered_json(payload, "worker_trust_anchors", 0)
            if target == "policy_anchor"
            else _reordered_json(payload)
        )
        _set_json_vector(doc, *path, payload=reordered)
    _must_reject(doc)


@pytest.mark.parametrize(
    "field",
    ("signature_base64", "worker_identity_sha256", "physical_builder_identity_sha256", "run_id"),
)
def test_public_vector_rejects_unsigned_worker_claim_mutations(field: str) -> None:
    doc = copy.deepcopy(_validated_document())
    closure = _closure_json(doc, 0)
    workers = cast(list[object], closure["worker_attestations"])
    worker = cast(dict[str, object], workers[0])
    worker[field] = (
        "A" * 88
        if field == "signature_base64"
        else ("b" * 64 if field != "run_id" else "different-run")
    )
    _write_closure_json(doc, 0, closure)
    _must_reject(doc)


def test_public_vector_rejects_stale_hash_and_cross_role_transplants() -> None:
    stale = copy.deepcopy(_validated_document())
    stale_role = cast(dict[str, object], cast(list[object], stale["roles"])[0])
    cast(dict[str, object], stale_role["expected"])["closure_sha256"] = "0" * 64
    _must_reject(stale)

    transplanted = copy.deepcopy(_validated_document())
    roles = cast(list[object], transplanted["roles"])
    cast(dict[str, object], roles[0])["closure"] = copy.deepcopy(
        cast(dict[str, object], roles[1])["closure"]
    )
    _must_reject(transplanted)

    evidence_transplant = copy.deepcopy(_validated_document())
    first = _closure_json(evidence_transplant, 0)
    second = _closure_json(evidence_transplant, 1)
    first["oci_safe_config_evidence"] = second["oci_safe_config_evidence"]
    first["oci_safe_config_evidence_sha256"] = second["oci_safe_config_evidence_sha256"]
    _write_closure_json(evidence_transplant, 0, first)
    _must_reject(evidence_transplant)


def test_public_vector_rejects_source_repository_and_nested_config_commitment_tampering() -> None:
    divergent_source = copy.deepcopy(_validated_document())
    cast(dict[str, object], divergent_source["common_source"])["commit_oid"] = "a" * 40
    _must_reject(divergent_source)

    divergent_repository = copy.deepcopy(_validated_document())
    cast(dict[str, object], divergent_repository["common_oci"])["repository"] = (
        "registry.example.invalid/other"
    )
    _must_reject(divergent_repository)

    nested = copy.deepcopy(_validated_document())
    closure = _closure_json(nested, 0)
    oci = cast(dict[str, object], closure["oci_safe_config_evidence"])
    claim = cast(dict[str, object], oci["expanded_oci_config_claim"])
    claim["runtime_uid"] = _integer(claim["runtime_uid"]) + 1
    oci_model = oci_v5.ContainerBootstrapOciSafeConfigEvidenceV5.model_validate(
        _as_tuples(oci), strict=True
    )
    new_hash = oci_v5.container_bootstrap_oci_safe_config_evidence_v5_sha256(oci_model)
    closure["oci_safe_config_evidence_sha256"] = new_hash
    for worker in cast(list[object], closure["worker_attestations"]):
        cast(dict[str, object], worker)["oci_safe_config_evidence_sha256"] = new_hash
    _write_closure_json(nested, 0, closure)
    _must_reject(nested)


def test_public_vector_rejects_acceptance_and_effect_flag_tampering() -> None:
    acceptance = copy.deepcopy(_validated_document())
    role = cast(dict[str, object], cast(list[object], acceptance["roles"])[0])
    decoded = json.loads(_bytes(role["acceptance"]).decode("ascii"))
    cast(dict[str, object], decoded)["closure_sha256"] = "0" * 64
    role["acceptance"] = _vector_bytes(_canonical_json(decoded))
    _must_reject(acceptance)

    effect = copy.deepcopy(_validated_document())
    closure = _closure_json(effect, 0)
    cast(dict[str, object], closure["oci_safe_config_evidence"])["build_allowed"] = True
    _write_closure_json(effect, 0, closure)
    _must_reject(effect)


@pytest.mark.parametrize(
    ("before", "after", "path", "expected"),
    (
        (
            b"source_clean: true\n",
            b"source_clean: yes\n",
            ("common_source", "source_clean"),
            True,
        ),
        (
            b"untracked_files_absent: true\n",
            b"untracked_files_absent: ON\n",
            ("common_source", "untracked_files_absent"),
            True,
        ),
        (
            b"submodules_absent: true\n",
            b"submodules_absent: TRUE\n",
            ("common_source", "submodules_absent"),
            True,
        ),
        (b"  ordinal: 0\n", b"  ordinal: 0x0\n", ("roles", 0, "ordinal"), 0),
        (b"  ordinal: 0\n", b"  ordinal: 0_0\n", ("roles", 0, "ordinal"), 0),
        (b"  ordinal: 0\n", b"  ordinal: 00\n", ("roles", 0, "ordinal"), 0),
    ),
    ids=(
        "legacy-yes-bool",
        "legacy-on-bool",
        "uppercase-bool",
        "hex-integer",
        "underscored-integer",
        "leading-zero-integer",
    ),
)
def test_public_vector_loader_rejects_noncanonical_implicit_scalars(
    before: bytes,
    after: bytes,
    path: tuple[str | int, ...],
    expected: bool | int,
) -> None:
    raw = _VECTOR.read_bytes()
    assert before in raw
    mutated = raw.replace(before, after, 1)

    legacy_document = yaml.load(mutated.decode("ascii"), Loader=_StrictVectorLoader)
    assert type(legacy_document) is dict
    legacy_value: object = legacy_document
    for item in path:
        if type(item) is str:
            legacy_value = cast(dict[str, object], legacy_value)[item]
        else:
            legacy_value = cast(list[object], legacy_value)[item]
    assert type(legacy_value) is type(expected)
    assert legacy_value == expected

    with pytest.raises(ValueError, match="vector scalar spelling"):
        _validated_document(mutated)


@pytest.mark.parametrize(
    "scalar",
    (
        b"1e3",
        b"1E3",
        b"1e+3",
        b"1e-3",
        b"+12e03",
        b"-2E+05",
        b"1.e3",
        b".1e3",
        b"0o10",
        b"0O10",
        b"0x10",
        b"0X10",
        b"0b101",
        b"0B101",
        b"0B11",
        b"+0x10",
        b"-0o10",
        b"+1",
        b"-1",
        b"+0",
        b"-0",
        b"+1.0",
        b"-1.0",
        b"+.1",
        b"-.1",
        b".1",
        b"1.",
        b"1.0",
        b"1_000",
        b"0_0",
        b"00",
        b"012",
        b"1:20",
        b"1:60",
        b"12:34:56",
        b"1:20.5",
        b".inf",
        b".Inf",
        b".INF",
        b"-.inf",
        b"+.INF",
        b".nan",
        b".NaN",
        b".NAN",
        b"-.NaN",
        b"nan",
        b"Infinity",
        b"+Infinity",
        b"null",
        b"Null",
        b"NULL",
        b"~",
        b"2026-08-30",
        b"2026-08-30T01:02:03Z",
        b"2026-08-30 01:02:03-05:00",
        b"2026-8-3",
        b"yes",
        b"Y",
        b"ON",
        b"TRUE",
        b"False",
        b"off",
        b"N",
        b"No",
    ),
)
def test_public_vector_loader_rejects_cross_schema_plain_scalars(scalar: bytes) -> None:
    with pytest.raises(ValueError, match="vector scalar spelling"):
        _load_yaml(b"value: " + scalar + b"\n")


@pytest.mark.parametrize("scalar", (b"1e3", b"1E3", b"0o10", b"0O10"))
def test_public_vector_loader_rejects_pyyaml_string_numeric_gaps(scalar: bytes) -> None:
    legacy_document = yaml.load(b"value: " + scalar + b"\n", Loader=_StrictVectorLoader)
    assert legacy_document == {"value": scalar.decode("ascii")}

    with pytest.raises(ValueError, match="vector scalar spelling"):
        _load_yaml(b"value: " + scalar + b"\n")


def test_public_vector_loader_rejects_empty_plain_null() -> None:
    with pytest.raises(ValueError, match="vector scalar spelling"):
        _load_yaml(b"value:\n")


@pytest.mark.parametrize(
    "scalar",
    (b"yes", b"1e3", b"0o10", b"0x10", b"+1", b".Inf", b"1:20", b"null", b"2026-08-30"),
)
def test_public_vector_loader_keeps_quoted_scalar_like_strings(scalar: bytes) -> None:
    assert _load_yaml(b'value: "' + scalar + b'"\n') == {"value": scalar.decode("ascii")}


def test_public_vector_loader_keeps_quoted_empty_string() -> None:
    assert _load_yaml(b'value: ""\n') == {"value": ""}


@pytest.mark.parametrize(
    "scalar",
    (
        b"0b" + b"a" * 62,
        b"0octopus",
        b"0origin",
        b"0x",
        b"0O",
        b"0xG",
        b"0xhello",
        b"0bcat",
        b"0octopus.example/rsd",
        b"0xray.example/rsd",
        b"0bloom.example/rsd",
    ),
)
def test_public_vector_loader_keeps_non_numeric_zero_prefix_strings(scalar: bytes) -> None:
    assert _load_yaml(b"value: " + scalar + b"\n") == {"value": scalar.decode("ascii")}


def test_public_vector_loader_keeps_canonical_plain_scalar_spellings() -> None:
    assert _load_yaml(b"yes_value: true\nno_value: false\nzero: 0\npositive: 123\n") == {
        "yes_value": True,
        "no_value": False,
        "zero": 0,
        "positive": 123,
    }


def test_public_vector_loader_keeps_ordinary_plain_strings() -> None:
    assert _load_yaml(b"ordinary: oncall\nidentifier: rsd-v5\n") == {
        "ordinary": "oncall",
        "identifier": "rsd-v5",
    }


@pytest.mark.parametrize(
    "raw",
    (
        b"schema_version: "
        b"rsd.container-bootstrap-artifact-evidence-v5-public-vector.v1\n"
        b"roles: &roles []\ncopy: *roles\n",
        b"schema_version: "
        b"rsd.container-bootstrap-artifact-evidence-v5-public-vector.v1\n"
        b"schema_version: duplicate\n",
        b"schema_version: !!str rsd.container-bootstrap-artifact-evidence-v5-public-vector.v1\n",
        b"schema_version: rsd.container-bootstrap-artifact-evidence-v5-public-vector.v1 \n",
        b"\xff",
        b"x" * (_MAX_VECTOR_BYTES + 1),
    ),
)
def test_public_vector_loader_rejects_yaml_features_and_size(raw: bytes) -> None:
    with pytest.raises((UnicodeDecodeError, ValueError, yaml.YAMLError)):
        _validated_document(raw)


def test_public_vector_loader_rejects_malformed_child_base64_and_json() -> None:
    malformed_base64 = copy.deepcopy(_validated_document())
    role = cast(dict[str, object], cast(list[object], malformed_base64["roles"])[0])
    segments = cast(list[object], cast(dict[str, object], role["closure"])["segments"])
    segments[0] = "!" + _string(segments[0])[1:]
    _must_reject(malformed_base64)

    malformed_json = copy.deepcopy(_validated_document())
    role = cast(dict[str, object], cast(list[object], malformed_json["roles"])[0])
    role["closure"] = _vector_bytes(b"{")
    _must_reject(malformed_json)
