"""Pure four-role checks for the Phase-B2 manifest boundary."""

from __future__ import annotations

import base64
import hashlib
import importlib.util
import inspect
import json
from pathlib import Path
from typing import Any, cast

import pytest
import yaml
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey
from pydantic import ValidationError
from yaml.events import AliasEvent

from omninode_rsd.lifecycle import container_bootstrap_artifact_evidence_v4 as evidence
from omninode_rsd.lifecycle import target_delivery_artifact_manifest as manifest_module
from omninode_rsd.lifecycle import target_delivery_map_projection_binding as binding
from omninode_rsd.lifecycle import target_delivery_map_signing as signing
from omninode_rsd.lifecycle.container_attach_static_v4 import (
    container_bootstrap_static_delivery_projection_v4_sha256,
    container_bootstrap_static_role_profile_envelope_v4_sha256,
    parse_container_bootstrap_static_delivery_projection_v4_canonical_json,
    parse_container_bootstrap_static_role_profile_envelope_v4_canonical_json,
)
from omninode_rsd.lifecycle.infisical_disposable import (
    TargetDeliveryMapV1,
    target_delivery_map_sha256,
)

_VECTOR = (
    Path(__file__).parents[2]
    / "src/omninode_rsd/lifecycle/target_delivery_artifact_manifest_public_vector.yaml"
)


class _StrictVectorLoader(yaml.SafeLoader):
    """Reject duplicate keys in the immutable public B2 vector."""


def _strict_mapping(
    loader: yaml.SafeLoader, node: yaml.MappingNode, deep: bool = False
) -> dict[object, object]:
    result: dict[object, object] = {}
    for key_node, value_node in node.value:
        key = loader.construct_object(key_node, deep=deep)
        if type(key) is not str or key in result:
            raise ValueError("duplicate vector key")
        result[key] = loader.construct_object(value_node, deep=deep)
    return result


_StrictVectorLoader.add_constructor(yaml.resolver.BaseResolver.DEFAULT_MAPPING_TAG, _strict_mapping)


def _decoded(value: object) -> bytes:
    if type(value) is not dict or set(value) != {"encoding", "segments"}:
        raise ValueError("vector bytes are invalid")
    segments = value["segments"]
    if (
        value["encoding"] != "standard_base64_fixed_segments_v1"
        or type(segments) is not list
        or not segments
        or any(type(segment) is not str or not segment.isascii() for segment in segments)
        or any(len(segment) != 76 for segment in segments[:-1])
        or not 1 <= len(segments[-1]) <= 76
    ):
        raise ValueError("vector bytes are invalid")
    encoded = "".join(cast(list[str], segments))
    decoded = base64.b64decode(encoded, validate=True)
    if base64.b64encode(decoded).decode("ascii") != encoded:
        raise ValueError("vector bytes are invalid")
    return decoded


def _tuples(value: object) -> object:
    if type(value) is list:
        return tuple(_tuples(item) for item in value)
    if type(value) is dict:
        return {key: _tuples(item) for key, item in value.items()}
    return value


def _safe_vector_value(value: object, *, depth: int = 0) -> None:
    if depth > 32:
        raise ValueError("vector is too deep")
    if type(value) is str:
        if not value.isascii():
            raise ValueError("vector string is not ASCII")
        return
    if type(value) is list:
        for item in value:
            _safe_vector_value(item, depth=depth + 1)
        return
    if type(value) is dict:
        for key, item in value.items():
            if type(key) is not str or not key.isascii():
                raise ValueError("vector key is invalid")
            _safe_vector_value(item, depth=depth + 1)
        return
    raise ValueError("vector scalar is invalid")


def _load(name: str, filename: str) -> Any:
    spec = importlib.util.spec_from_file_location(name, Path(__file__).with_name(filename))
    if spec is None or spec.loader is None:
        raise RuntimeError("test fixture is unavailable")
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    return module


def _sha(label: str) -> str:
    return hashlib.sha256(label.encode("ascii")).hexdigest()


def _anchor(
    key: Ed25519PrivateKey, label: str
) -> evidence.ContainerBootstrapBuildWorkerTrustAnchorV4:
    public = key.public_key().public_bytes_raw()
    return evidence.ContainerBootstrapBuildWorkerTrustAnchorV4(
        schema_version="rsd.container-bootstrap-build-worker-trust-anchor.v4",
        key_id=f"b2-worker-{label}",
        worker_identity_sha256=_sha(f"b2-worker-identity-{label}"),
        authority_identity_sha256=_sha(f"b2-worker-authority-{label}"),
        public_key_base64=base64.b64encode(public).decode("ascii"),
        public_key_fingerprint_sha256=hashlib.sha256(public).hexdigest(),
        algorithm="ed25519",
    )


def _signed_binding(
    *,
    key: Ed25519PrivateKey,
    anchor: binding.TargetDeliveryMapProjectionBindingTrustAnchorV1,
    delivery_map: object,
    projection: object,
    envelope: object,
    map_anchor: object,
    profile_anchor: object,
) -> binding.TargetDeliveryMapProjectionBindingV1:
    profile = cast(Any, envelope).static_role_profile
    unsigned = binding.TargetDeliveryMapProjectionBindingV1(
        schema_version="rsd.target-delivery-map-projection-binding.v1",
        projection_algorithm="project_target_delivery_map_v1_structurally.v1",
        target_delivery_map_schema_version="rsd.target-delivery-map.v1",
        projection_schema_version="rsd.container-bootstrap-static-delivery-projection.v4",
        component_order=(
            "primary_infisical",
            "primary_valkey",
            "restore_infisical",
            "restore_valkey",
        ),
        target_delivery_map_sha256=target_delivery_map_sha256(cast(Any, delivery_map)),
        static_delivery_projection_sha256=container_bootstrap_static_delivery_projection_v4_sha256(
            cast(Any, projection)
        ),
        verified_static_role_profile_sha256=profile.profile_sha256,
        verified_static_role_profile_envelope_sha256=container_bootstrap_static_role_profile_envelope_v4_sha256(
            cast(Any, envelope)
        ),
        profile_component=profile.component,
        profile_component_role=profile.component_role,
        selected_delivery_route_sha256=profile.selected_delivery_route_sha256,
        selected_delivery_route_ordinal=(
            "primary_infisical",
            "primary_valkey",
            "restore_infisical",
            "restore_valkey",
        ).index(profile.component),
        verified_profile_trust_anchor_key_id=cast(Any, profile_anchor).key_id,
        verified_profile_trust_anchor_public_key_fingerprint_sha256=cast(
            Any, profile_anchor
        ).public_key_fingerprint_sha256,
        verified_map_signer_key_id=cast(Any, map_anchor).key_id,
        verified_map_signer_public_key_fingerprint_sha256=cast(
            Any, map_anchor
        ).public_key_fingerprint_sha256,
        binding_signer_key_id=anchor.key_id,
        binding_signer_public_key_fingerprint_sha256=anchor.public_key_fingerprint_sha256,
        signature_base64=base64.b64encode(b"x" * 64).decode("ascii"),
    )
    return unsigned.model_copy(
        update={
            "signature_base64": base64.b64encode(
                key.sign(binding.target_delivery_map_projection_binding_v1_message(unsigned))
            ).decode("ascii")
        }
    )


def _common_source_envelope(static: Any, bundle: dict[str, object]) -> object:
    """Keep four independently signed profiles on one attested source identity."""
    profile = cast(Any, bundle["profile_envelope"]).static_role_profile
    source = _sha("b2-common-wrapper-source-tree")
    preimage = type(profile.static_patch_preimage)(
        **{
            **profile.static_patch_preimage.model_dump(mode="python"),
            "wrapper_source_tree_sha256": source,
        }
    )
    preimage_hash = static.container_bootstrap_static_patch_preimage_v4_sha256(preimage)
    patch = type(profile.static_patch_policy)(
        **{
            **profile.static_patch_policy.model_dump(mode="python"),
            "preimage": preimage,
            "static_patch_preimage_sha256": preimage_hash,
        }
    )
    rebuilt = static.build_container_bootstrap_static_role_profile_v4(
        wrapper_source_tree_sha256=source,
        component=profile.component,
        component_role=profile.component_role,
        compile_target=profile.compile_target,
        wrapper_executable_path=profile.wrapper_executable_path,
        wrapper_executable_mode=profile.wrapper_executable_mode,
        wrapper_executable_symlink_allowed=profile.wrapper_executable_symlink_allowed,
        ticket_trust_anchor=profile.ticket_trust_anchor,
        replay_receipt_trust_anchor=profile.replay_receipt_trust_anchor,
        attach_protocol=profile.attach_protocol,
        static_delivery_projection=profile.static_delivery_projection,
        selected_delivery_route=profile.selected_delivery_route,
        static_launch_plan=profile.static_launch_plan,
        static_patch_preimage=preimage,
        static_patch_policy=patch,
        static_environment=profile.static_environment,
        child_environment_policy=profile.child_environment_policy,
        fd_policy=profile.fd_policy,
        pid1_policy=profile.pid1_policy,
        memory_safety_policy=profile.memory_safety_policy,
        valkey_launch_policy=profile.valkey_launch_policy,
    )
    return static._profile_envelope(rebuilt)


def test_four_role_manifest_revalidates_original_inputs(tmp_path: Path) -> None:
    assert (
        "acceptance"
        not in inspect.signature(
            manifest_module.validate_target_delivery_artifact_manifest_v1
        ).parameters
    )
    static = _load("_b2_static", "test_container_attach_static_v4.py")
    evidence_fixture = _load("_b2_evidence", "test_container_bootstrap_artifact_evidence_v4.py")
    b1_fixture = _load("_b2_b1", "test_target_delivery_map_signing.py")
    components = ("primary_infisical", "primary_valkey", "restore_infisical", "restore_valkey")
    bundles = [
        static._bundle(tmp_path / component, component=component, documentation_authorities=True)
        for component in components
    ]
    for bundle in bundles:
        bundle["profile_envelope"] = _common_source_envelope(static, bundle)
    delivery_map, documented_bundle, _ = b1_fixture._documentation_signed_map(tmp_path / "map")
    projection = documented_bundle["projection"]
    # The fixture provides a common structural projection even though every
    # profile envelope is separately signed for its selected route.
    assert all(bundle["projection"] == projection for bundle in bundles)
    map_public = static.v2_fixtures._PUBLIC
    map_anchor = signing.TargetDeliveryMapSignerTrustAnchorV1(
        schema_version="rsd.target-delivery-map-signer-trust-anchor.v1",
        key_id="v2-signer",
        public_key_base64=base64.b64encode(map_public).decode("ascii"),
        public_key_fingerprint_sha256=hashlib.sha256(map_public).hexdigest(),
        algorithm="ed25519",
    )
    binding_key = Ed25519PrivateKey.generate()
    binding_public = binding_key.public_key().public_bytes_raw()
    binding_anchor = binding.TargetDeliveryMapProjectionBindingTrustAnchorV1(
        schema_version="rsd.target-delivery-map-projection-binding-trust-anchor.v1",
        key_id="b2-binding-root",
        authority_identity_sha256=_sha("b2-binding-authority"),
        independence_domain_identity_sha256=_sha("b2-binding-domain"),
        public_key_base64=base64.b64encode(binding_public).decode("ascii"),
        public_key_fingerprint_sha256=hashlib.sha256(binding_public).hexdigest(),
        algorithm="ed25519",
    )
    worker_keys = (Ed25519PrivateKey.generate(), Ed25519PrivateKey.generate())
    worker_anchors = (_anchor(worker_keys[0], "one"), _anchor(worker_keys[1], "two"))
    workers = evidence.ContainerBootstrapBuildWorkerTrustPolicyV4(
        schema_version="rsd.container-bootstrap-build-worker-trust-policy.v4",
        policy_id="b2-worker-policy",
        independence_domain_sha256=_sha("b2-worker-domain"),
        worker_trust_anchors=worker_anchors,
    )
    policy = binding.TargetDeliveryMapProjectionBindingTrustPolicyV1(
        schema_version="rsd.target-delivery-map-projection-binding-trust-policy.v1",
        policy_id="b2-policy",
        map_signer_trust_anchor=map_anchor,
        map_authority_identity_sha256=_sha("b2-map-authority"),
        map_independence_domain_identity_sha256=_sha("b2-map-domain"),
        binding_trust_anchor=binding_anchor,
        profile_trust_anchor=bundles[0]["profile_trust_anchor"],
        phase_a_worker_trust_policy=workers,
    )
    roles = []
    for ordinal, bundle in enumerate(bundles):
        envelope = bundle["profile_envelope"]
        first = evidence_fixture._attestation(
            signing_key=worker_keys[0],
            anchor=worker_anchors[0],
            run_id=f"b2-run-{ordinal}-one",
            envelope=envelope,
        )
        second = evidence_fixture._attestation(
            signing_key=worker_keys[1],
            anchor=worker_anchors[1],
            run_id=f"b2-run-{ordinal}-two",
            envelope=envelope,
        )
        closure = evidence.ContainerBootstrapArtifactEvidenceClosureV4(
            schema_version="rsd.container-bootstrap-artifact-evidence-closure.v4",
            worker_attestations=(first, second),
            evidence_effect_allowed=False,
            build_allowed=False,
            materialization_allowed=False,
            attach_allowed=False,
        )
        roles.append(
            manifest_module.TargetDeliveryArtifactManifestRoleInputV1(
                schema_version="rsd.target-delivery-artifact-manifest-role-input.v1",
                component=components[ordinal],
                profile_envelope=envelope,
                projection_binding=_signed_binding(
                    key=binding_key,
                    anchor=binding_anchor,
                    delivery_map=delivery_map,
                    projection=projection,
                    envelope=envelope,
                    map_anchor=map_anchor,
                    profile_anchor=policy.profile_trust_anchor,
                ),
                phase_a_closure=closure,
            )
        )
    manifest_key = Ed25519PrivateKey.generate()
    manifest_public = manifest_key.public_key().public_bytes_raw()
    manifest_anchor = manifest_module.TargetDeliveryArtifactManifestTrustAnchorV1(
        schema_version="rsd.target-delivery-artifact-manifest-trust-anchor.v1",
        key_id="b2-manifest-root",
        public_key_base64=base64.b64encode(manifest_public).decode("ascii"),
        public_key_fingerprint_sha256=hashlib.sha256(manifest_public).hexdigest(),
        authority_identity_sha256=_sha("b2-manifest-authority"),
        independence_domain_identity_sha256=_sha("b2-manifest-domain"),
        algorithm="ed25519",
    )
    role_tuple = cast(tuple[Any, Any, Any, Any], tuple(roles))
    entries = []
    for role in role_tuple:
        b1 = binding.validate_target_delivery_map_projection_binding_v1(
            delivery_map=delivery_map,
            static_delivery_projection=projection,
            profile_envelope=role.profile_envelope,
            binding=role.projection_binding,
            trust_policy=policy,
        )
        phase_a = evidence.validate_container_bootstrap_artifact_evidence_closure_v4(
            closure=role.phase_a_closure,
            worker_trust_policy=workers,
            profile_envelope=role.profile_envelope,
            profile_trust_anchor=policy.profile_trust_anchor,
        )
        entries.append(
            manifest_module._entry(
                role,
                phase_a.closure_sha256,
                phase_a.verification_context_sha256,
                b1.binding_sha256,
                b1.verification_context_sha256,
                policy.profile_trust_anchor.key_id,
                policy.profile_trust_anchor.public_key_fingerprint_sha256,
            )
        )
    source = entries[0].source
    policy_hash = hashlib.sha256(
        b"omninode-rsd.target-delivery-artifact-manifest-b1-policy.sha256.v1\x00"
        + binding.target_delivery_map_projection_binding_trust_policy_v1_canonical_json(policy)
    ).hexdigest()
    unsigned = manifest_module.TargetDeliveryArtifactManifestV1(
        schema_version="rsd.target-delivery-artifact-manifest.v1",
        signature_algorithm="ed25519",
        component_order=components,
        target_delivery_map_sha256=b1.target_delivery_map_sha256,
        static_delivery_projection_sha256=b1.static_delivery_projection_sha256,
        map_signer_key_id=map_anchor.key_id,
        map_signer_fingerprint_sha256=map_anchor.public_key_fingerprint_sha256,
        b1_policy_sha256=policy_hash,
        source=source,
        roles=cast(tuple[Any, Any, Any, Any], tuple(entries)),
        signer_key_id=manifest_anchor.key_id,
        signer_fingerprint_sha256=manifest_anchor.public_key_fingerprint_sha256,
        signature_base64=base64.b64encode(b"m" * 64).decode("ascii"),
        build_allowed=False,
        materialization_allowed=False,
        attach_allowed=False,
        effect_allowed=False,
    )
    signed = unsigned.model_copy(
        update={
            "signature_base64": base64.b64encode(
                manifest_key.sign(
                    manifest_module.target_delivery_artifact_manifest_v1_message(unsigned)
                )
            ).decode("ascii")
        }
    )
    acceptance = manifest_module.validate_target_delivery_artifact_manifest_v1(
        delivery_map=delivery_map,
        static_delivery_projection=projection,
        b1_trust_policy=policy,
        manifest_trust_anchor=manifest_anchor,
        role_inputs=role_tuple,
        manifest=signed,
    )
    assert (
        manifest_module.validate_target_delivery_artifact_manifest_v1(
            delivery_map=delivery_map,
            static_delivery_projection=projection,
            b1_trust_policy=policy,
            manifest_trust_anchor=manifest_anchor,
            role_inputs=role_tuple,
            manifest=signed,
        )
        == acceptance
    )
    assert (
        acceptance.manifest_sha256
        == manifest_module.target_delivery_artifact_manifest_v1_sha256(signed)
    )
    assert (
        acceptance.evidence_effect_allowed,
        acceptance.build_allowed,
        acceptance.materialization_allowed,
        acceptance.attach_allowed,
        acceptance.effect_allowed,
    ) == (False, False, False, False, False)
    assert (
        manifest_module.parse_target_delivery_artifact_manifest_v1_canonical_json(
            manifest_module.target_delivery_artifact_manifest_v1_canonical_json(signed)
        )
        == signed
    )
    assert (
        manifest_module.parse_target_delivery_artifact_manifest_acceptance_v1_canonical_json(
            manifest_module.target_delivery_artifact_manifest_acceptance_v1_canonical_json(
                acceptance
            )
        )
        == acceptance
    )
    assert (
        manifest_module.parse_target_delivery_artifact_manifest_trust_anchor_v1_canonical_json(
            manifest_module.target_delivery_artifact_manifest_trust_anchor_v1_canonical_json(
                manifest_anchor
            )
        )
        == manifest_anchor
    )
    sequence_values = ("same",)
    assert (
        manifest_module._sequence(manifest_module._SOURCE_TREE_ENTRIES_DOMAIN, sequence_values)[0]
        != manifest_module._sequence(manifest_module._OCI_LAYERS_DOMAIN, sequence_values)[0]
    )
    duplicated_acceptance = acceptance.model_copy(update={"roles": (acceptance.roles[0],) * 4})
    with pytest.raises(ValidationError):
        manifest_module.TargetDeliveryArtifactManifestAcceptanceV1(
            **{**acceptance.model_dump(mode="python"), "roles": list(acceptance.roles)}
        )
    with pytest.raises(manifest_module.TargetDeliveryArtifactManifestError):
        manifest_module.parse_target_delivery_artifact_manifest_acceptance_v1_canonical_json(
            manifest_module.target_delivery_artifact_manifest_acceptance_v1_canonical_json(
                duplicated_acceptance
            )
        )
    impossible_oci = signed.roles[0].oci.model_copy(
        update={"diff_id_count": signed.roles[0].oci.layer_count + 1}
    )
    impossible_role = signed.roles[0].model_copy(update={"oci": impossible_oci})
    impossible_manifest = signed.model_copy(update={"roles": (impossible_role, *signed.roles[1:])})
    with pytest.raises(manifest_module.TargetDeliveryArtifactManifestError):
        manifest_module.parse_target_delivery_artifact_manifest_v1_canonical_json(
            manifest_module.target_delivery_artifact_manifest_v1_canonical_json(impossible_manifest)
        )
    with pytest.raises(manifest_module.TargetDeliveryArtifactManifestError):
        manifest_module.validate_target_delivery_artifact_manifest_v1(
            delivery_map=delivery_map,
            static_delivery_projection=projection,
            b1_trust_policy=policy,
            manifest_trust_anchor=manifest_anchor,
            role_inputs=cast(
                tuple[Any, Any, Any, Any],
                (role_tuple[1], role_tuple[0], role_tuple[2], role_tuple[3]),
            ),
            manifest=signed,
        )
    colliding_anchor = manifest_module.TargetDeliveryArtifactManifestTrustAnchorV1(
        schema_version="rsd.target-delivery-artifact-manifest-trust-anchor.v1",
        key_id=map_anchor.key_id,
        public_key_base64=map_anchor.public_key_base64,
        public_key_fingerprint_sha256=map_anchor.public_key_fingerprint_sha256,
        authority_identity_sha256=_sha("b2-collision-authority"),
        independence_domain_identity_sha256=_sha("b2-collision-domain"),
        algorithm="ed25519",
    )
    with pytest.raises(manifest_module.TargetDeliveryArtifactManifestError):
        manifest_module.validate_target_delivery_artifact_manifest_v1(
            delivery_map=delivery_map,
            static_delivery_projection=projection,
            b1_trust_policy=policy,
            manifest_trust_anchor=colliding_anchor,
            role_inputs=role_tuple,
            manifest=signed,
        )

    class _ManifestSubclass(manifest_module.TargetDeliveryArtifactManifestV1):
        pass

    malformed_manifests: tuple[object, ...] = (
        object(),
        manifest_module.TargetDeliveryArtifactManifestV1.model_construct(),
        _ManifestSubclass.model_validate(signed.model_dump(mode="python")),
    )
    for malformed_manifest in malformed_manifests:
        with pytest.raises(manifest_module.TargetDeliveryArtifactManifestError):
            manifest_module.validate_target_delivery_artifact_manifest_v1(
                delivery_map=delivery_map,
                static_delivery_projection=projection,
                b1_trust_policy=policy,
                manifest_trust_anchor=manifest_anchor,
                role_inputs=role_tuple,
                manifest=cast(Any, malformed_manifest),
            )
    with pytest.raises(manifest_module.TargetDeliveryArtifactManifestError):
        manifest_module.validate_target_delivery_artifact_manifest_v1(
            delivery_map=delivery_map,
            static_delivery_projection=projection,
            b1_trust_policy=policy,
            manifest_trust_anchor=manifest_anchor,
            role_inputs=cast(Any, list(role_tuple)),
            manifest=signed,
        )


@pytest.mark.parametrize(
    "mutation",
    (
        "none",
        "summary_hash",
        "summary_count",
        "summary_byte_count",
        "duplicate_run_id",
        "worker_substitution",
        "stale_b1",
        "stale_phase_a",
        "stale_profile",
        "divergent_source",
        "true_permission",
    ),
)
def test_public_vector_revalidates_all_original_chains(mutation: str) -> None:
    raw = _VECTOR.read_bytes()
    assert raw.count(b"# gitleaks:allow") == 7
    if any(isinstance(event, AliasEvent) for event in yaml.parse(raw)):
        raise ValueError("YAML aliases are invalid")
    values = yaml.load(raw, Loader=_StrictVectorLoader)
    _safe_vector_value(values)
    if type(values) is not dict or values.get("schema_version") != (
        "rsd.target-delivery-artifact-manifest-public-vector.v1"
    ):
        raise ValueError("vector is invalid")
    components = values["component_order"]
    if components != ["primary_infisical", "primary_valkey", "restore_infisical", "restore_valkey"]:
        raise ValueError("vector order is invalid")
    map_bytes = _decoded(values["target_delivery_map"])
    map_value = json.loads(map_bytes.decode("ascii"))
    delivery_map = TargetDeliveryMapV1.model_validate(_tuples(map_value), strict=True)
    if (
        json.dumps(
            delivery_map.model_dump(mode="json"),
            ensure_ascii=True,
            sort_keys=True,
            separators=(",", ":"),
        ).encode("ascii")
        != map_bytes
    ):
        raise ValueError("map is not canonical")
    projection = parse_container_bootstrap_static_delivery_projection_v4_canonical_json(
        _decoded(values["static_delivery_projection"])
    )
    policy = binding.parse_target_delivery_map_projection_binding_trust_policy_v1_canonical_json(
        _decoded(values["b1_policy"])
    )
    anchor = manifest_module.parse_target_delivery_artifact_manifest_trust_anchor_v1_canonical_json(
        _decoded(values["manifest_anchor"])
    )
    raw_roles = values["roles"]
    if type(raw_roles) is not list or len(raw_roles) != 4:
        raise ValueError("roles are invalid")
    roles = tuple(
        manifest_module.TargetDeliveryArtifactManifestRoleInputV1(
            schema_version="rsd.target-delivery-artifact-manifest-role-input.v1",
            component=cast(Any, components)[ordinal],
            profile_envelope=parse_container_bootstrap_static_role_profile_envelope_v4_canonical_json(
                _decoded(cast(dict[str, object], raw)["profile_envelope"])
            ),
            projection_binding=binding.parse_target_delivery_map_projection_binding_v1_canonical_json(
                _decoded(cast(dict[str, object], raw)["projection_binding"])
            ),
            phase_a_closure=evidence.parse_container_bootstrap_artifact_evidence_closure_v4_canonical_json(
                _decoded(cast(dict[str, object], raw)["phase_a_closure"])
            ),
        )
        for ordinal, raw in enumerate(raw_roles)
    )
    signed = manifest_module.parse_target_delivery_artifact_manifest_v1_canonical_json(
        _decoded(values["manifest"])
    )
    acceptance = (
        manifest_module.parse_target_delivery_artifact_manifest_acceptance_v1_canonical_json(
            _decoded(values["acceptance"])
        )
    )
    assert _decoded(values["manifest_message"]) == (
        manifest_module.target_delivery_artifact_manifest_v1_message(signed)
    )
    assert values["manifest_sha256"] == manifest_module.target_delivery_artifact_manifest_v1_sha256(
        signed
    )
    assert (
        values["acceptance_sha256"]
        == hashlib.sha256(
            manifest_module.target_delivery_artifact_manifest_acceptance_v1_canonical_json(
                acceptance
            )
        ).hexdigest()
    )
    assert (
        manifest_module.validate_target_delivery_artifact_manifest_v1(
            delivery_map=delivery_map,
            static_delivery_projection=projection,
            b1_trust_policy=policy,
            manifest_trust_anchor=anchor,
            role_inputs=cast(tuple[Any, Any, Any, Any], roles),
            manifest=signed,
        )
        == acceptance
    )
    canonical = manifest_module.target_delivery_artifact_manifest_v1_canonical_json(signed)
    for malformed in (
        b"\xef\xbb\xbf" + canonical,
        b" " + canonical,
        canonical.replace(b'"schema_version"', b'"schema_version" ', 1),
        canonical.removesuffix(b"}") + b',"unknown":true}',
    ):
        with pytest.raises(manifest_module.TargetDeliveryArtifactManifestError):
            manifest_module.parse_target_delivery_artifact_manifest_v1_canonical_json(malformed)
    with pytest.raises(manifest_module.TargetDeliveryArtifactManifestError):
        manifest_module.validate_target_delivery_artifact_manifest_v1(
            delivery_map=delivery_map,
            static_delivery_projection=projection,
            b1_trust_policy=policy,
            manifest_trust_anchor=anchor,
            role_inputs=cast(tuple[Any, Any, Any, Any], (roles[1], roles[0], roles[2], roles[3])),
            manifest=signed,
        )
    if mutation == "none":
        return
    mutated_roles = roles
    mutated_manifest = signed
    if mutation in {"summary_hash", "summary_count", "summary_byte_count"}:
        source_updates: dict[str, object] = {
            "summary_hash": {"wrapper_tree_entries_sha256": "0" * 64},
            "summary_count": {
                "wrapper_tree_entry_count": signed.roles[0].source.wrapper_tree_entry_count + 1
            },
            "summary_byte_count": {
                "wrapper_tree_entries_byte_count": signed.roles[
                    0
                ].source.wrapper_tree_entries_byte_count
                + 1
            },
        }[mutation]
        changed_source = signed.roles[0].source.model_copy(update=source_updates)
        changed_entry = signed.roles[0].model_copy(update={"source": changed_source})
        mutated_manifest = signed.model_copy(update={"roles": (changed_entry, *signed.roles[1:])})
    elif mutation == "duplicate_run_id":
        first, second = roles[0].phase_a_closure.worker_attestations
        closure = roles[0].phase_a_closure.model_copy(
            update={
                "worker_attestations": (first, second.model_copy(update={"run_id": first.run_id}))
            }
        )
        changed_role = roles[0].model_copy(update={"phase_a_closure": closure})
        mutated_roles = (changed_role, *roles[1:])
    elif mutation == "worker_substitution":
        first, second = roles[0].phase_a_closure.worker_attestations
        closure = roles[0].phase_a_closure.model_copy(
            update={"worker_attestations": (second, first)}
        )
        changed_role = roles[0].model_copy(update={"phase_a_closure": closure})
        mutated_roles = (changed_role, *roles[1:])
    elif mutation == "stale_b1":
        stale = roles[0].projection_binding.model_copy(
            update={"target_delivery_map_sha256": "0" * 64}
        )
        changed_role = roles[0].model_copy(update={"projection_binding": stale})
        mutated_roles = (changed_role, *roles[1:])
    elif mutation == "stale_phase_a":
        stale_closure = roles[0].phase_a_closure.model_copy(update={"build_allowed": True})
        changed_role = roles[0].model_copy(update={"phase_a_closure": stale_closure})
        mutated_roles = (changed_role, *roles[1:])
    elif mutation == "stale_profile":
        stale_profile = roles[0].profile_envelope.model_copy(
            update={"signature_base64": base64.b64encode(b"z" * 64).decode("ascii")}
        )
        changed_role = roles[0].model_copy(update={"profile_envelope": stale_profile})
        mutated_roles = (changed_role, *roles[1:])
    elif mutation == "divergent_source":
        first, second = roles[0].phase_a_closure.worker_attestations
        divergent = second.model_copy(update={"canonical_source_snapshot_sha256": "0" * 64})
        closure = roles[0].phase_a_closure.model_copy(
            update={"worker_attestations": (first, divergent)}
        )
        changed_role = roles[0].model_copy(update={"phase_a_closure": closure})
        mutated_roles = (changed_role, *roles[1:])
    elif mutation == "true_permission":
        mutated_manifest = signed.model_copy(update={"build_allowed": True})
    else:
        raise AssertionError("unexpected mutation")
    with pytest.raises(manifest_module.TargetDeliveryArtifactManifestError):
        manifest_module.validate_target_delivery_artifact_manifest_v1(
            delivery_map=delivery_map,
            static_delivery_projection=projection,
            b1_trust_policy=policy,
            manifest_trust_anchor=anchor,
            role_inputs=cast(tuple[Any, Any, Any, Any], mutated_roles),
            manifest=mutated_manifest,
        )
