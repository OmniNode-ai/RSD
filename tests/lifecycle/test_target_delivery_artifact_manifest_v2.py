"""Strict B2 V2 aggregation coverage over original B1 and V5 evidence."""

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

from omninode_rsd.lifecycle import container_attach_static_v4 as static_v4
from omninode_rsd.lifecycle import container_bootstrap_artifact_evidence_v5 as evidence_v5
from omninode_rsd.lifecycle import container_bootstrap_oci_safe_config_evidence_v5 as oci_v5
from omninode_rsd.lifecycle import target_delivery_artifact_manifest as manifest_v1
from omninode_rsd.lifecycle import target_delivery_artifact_manifest_v2 as manifest_v2
from omninode_rsd.lifecycle import target_delivery_map_projection_binding as binding
from omninode_rsd.lifecycle.infisical_disposable import TargetDeliveryMapV1

_ROOT = Path(__file__).parents[2] / "src/omninode_rsd/lifecycle"
_B2_VECTOR = _ROOT / "target_delivery_artifact_manifest_public_vector.yaml"
_V5_VECTOR = _ROOT / "container_bootstrap_artifact_evidence_v5_public_vector.yaml"
_COMPONENTS = ("primary_infisical", "primary_valkey", "restore_infisical", "restore_valkey")


def _sha(label: str) -> str:
    return hashlib.sha256(label.encode("ascii")).hexdigest()


def _decode(value: object) -> bytes:
    mapped = cast(dict[str, object], value)
    segments = cast(list[str], mapped["segments"])
    return base64.b64decode("".join(segments), validate=True)


def _tuples(value: object) -> object:
    if type(value) is list:
        return tuple(_tuples(item) for item in cast(list[object], value))
    if type(value) is dict:
        return {key: _tuples(item) for key, item in cast(dict[str, object], value).items()}
    return value


def _load_v5_fixture() -> Any:
    path = Path(__file__).with_name("test_container_bootstrap_artifact_evidence_v5.py")
    spec = importlib.util.spec_from_file_location("_b2_v2_v5_fixture", path)
    if spec is None or spec.loader is None:
        raise RuntimeError("V5 fixture is unavailable")
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    return module


def _vector_inputs() -> tuple[
    TargetDeliveryMapV1,
    static_v4.ContainerBootstrapStaticDeliveryProjectionV4,
    binding.TargetDeliveryMapProjectionBindingTrustPolicyV1,
    manifest_v1.TargetDeliveryArtifactManifestTrustAnchorV1,
    tuple[
        static_v4.ContainerBootstrapStaticRoleProfileEnvelopeV4,
        static_v4.ContainerBootstrapStaticRoleProfileEnvelopeV4,
        static_v4.ContainerBootstrapStaticRoleProfileEnvelopeV4,
        static_v4.ContainerBootstrapStaticRoleProfileEnvelopeV4,
    ],
    tuple[
        binding.TargetDeliveryMapProjectionBindingV1,
        binding.TargetDeliveryMapProjectionBindingV1,
        binding.TargetDeliveryMapProjectionBindingV1,
        binding.TargetDeliveryMapProjectionBindingV1,
    ],
]:
    b2 = cast(dict[str, object], yaml.safe_load(_B2_VECTOR.read_text(encoding="ascii")))
    delivery_map = TargetDeliveryMapV1.model_validate(
        _tuples(json.loads(_decode(b2["target_delivery_map"]).decode("ascii"))), strict=True
    )
    projection = static_v4.parse_container_bootstrap_static_delivery_projection_v4_canonical_json(
        _decode(b2["static_delivery_projection"])
    )
    policy = binding.parse_target_delivery_map_projection_binding_trust_policy_v1_canonical_json(
        _decode(b2["b1_policy"])
    )
    anchor = manifest_v1.parse_target_delivery_artifact_manifest_trust_anchor_v1_canonical_json(
        _decode(b2["manifest_anchor"])
    )
    raw_roles = cast(list[dict[str, object]], b2["roles"])
    envelopes = tuple(
        static_v4.parse_container_bootstrap_static_role_profile_envelope_v4_canonical_json(
            _decode(role["profile_envelope"])
        )
        for role in raw_roles
    )
    bindings = tuple(
        binding.parse_target_delivery_map_projection_binding_v1_canonical_json(
            _decode(role["projection_binding"])
        )
        for role in raw_roles
    )
    return (
        delivery_map,
        projection,
        policy,
        anchor,
        cast(tuple[Any, Any, Any, Any], envelopes),
        cast(tuple[Any, Any, Any, Any], bindings),
    )


def _new_manifest_anchor() -> tuple[
    manifest_v1.TargetDeliveryArtifactManifestTrustAnchorV1, Ed25519PrivateKey
]:
    key = Ed25519PrivateKey.generate()
    public = key.public_key().public_bytes_raw()
    return (
        manifest_v1.TargetDeliveryArtifactManifestTrustAnchorV1(
            schema_version="rsd.target-delivery-artifact-manifest-trust-anchor.v1",
            key_id="b2-v2-manifest-root",
            public_key_base64=base64.b64encode(public).decode("ascii"),
            public_key_fingerprint_sha256=hashlib.sha256(public).hexdigest(),
            authority_identity_sha256=_sha("b2-v2-manifest-authority"),
            independence_domain_identity_sha256=_sha("b2-v2-manifest-domain"),
            algorithm="ed25519",
        ),
        key,
    )


def _v5_closure(
    *,
    fixture: Any,
    envelope: static_v4.ContainerBootstrapStaticRoleProfileEnvelopeV4,
    component: str,
    ordinal: int,
    first_worker_identity_sha256: str | None = None,
    first_physical_builder_identity_sha256: str | None = None,
) -> tuple[
    evidence_v5.ContainerBootstrapArtifactEvidenceClosureV5,
    evidence_v5.ContainerBootstrapBuildWorkerTrustPolicyV5,
]:
    keys = (Ed25519PrivateKey.generate(), Ed25519PrivateKey.generate())
    first_updates = {
        "physical_builder_identity_sha256": (
            first_physical_builder_identity_sha256 or _sha("b2-v2-shared-builder-a")
        )
    }
    if first_worker_identity_sha256 is not None:
        first_updates["worker_identity_sha256"] = first_worker_identity_sha256
    first = fixture._anchor(keys[0], f"b2-v2-{ordinal}-a").model_copy(update=first_updates)
    second = fixture._anchor(keys[1], f"b2-v2-{ordinal}-b").model_copy(
        update={"physical_builder_identity_sha256": _sha("b2-v2-shared-builder-b")}
    )
    policy = evidence_v5.ContainerBootstrapBuildWorkerTrustPolicyV5(
        schema_version="rsd.container-bootstrap-build-worker-trust-policy.v5",
        policy_id=f"b2-v2-v5-policy-{ordinal}",
        epoch=1,
        independence_domain_sha256=_sha(f"b2-v2-v5-domain-{ordinal}"),
        scope="phase_a_v5_worker_evidence_closure",
        worker_trust_anchors=(first, second),
    )
    oci = fixture._shared_oci(envelope)
    closure = evidence_v5.ContainerBootstrapArtifactEvidenceClosureV5(
        schema_version="rsd.container-bootstrap-artifact-evidence-closure.v5",
        worker_attestations=(
            fixture._attestation(
                signing_key=keys[0],
                anchor=first,
                policy=policy,
                profile_envelope=envelope,
                shared_oci=oci,
                run_id=f"b2-v2-run-{ordinal}-a",
            ),
            fixture._attestation(
                signing_key=keys[1],
                anchor=second,
                policy=policy,
                profile_envelope=envelope,
                shared_oci=oci,
                run_id=f"b2-v2-run-{ordinal}-b",
            ),
        ),
        oci_safe_config_evidence=oci,
        oci_safe_config_evidence_sha256=(
            oci_v5.container_bootstrap_oci_safe_config_evidence_v5_sha256(oci)
        ),
        non_authorizing=True,
        evidence_effect_allowed=False,
        build_allowed=False,
        materialization_allowed=False,
        attach_allowed=False,
    )
    assert envelope.static_role_profile.component == component
    return closure, policy


def _public_v5_closures() -> tuple[
    tuple[
        evidence_v5.ContainerBootstrapArtifactEvidenceClosureV5,
        evidence_v5.ContainerBootstrapBuildWorkerTrustPolicyV5,
    ],
    tuple[
        evidence_v5.ContainerBootstrapArtifactEvidenceClosureV5,
        evidence_v5.ContainerBootstrapBuildWorkerTrustPolicyV5,
    ],
    tuple[
        evidence_v5.ContainerBootstrapArtifactEvidenceClosureV5,
        evidence_v5.ContainerBootstrapBuildWorkerTrustPolicyV5,
    ],
    tuple[
        evidence_v5.ContainerBootstrapArtifactEvidenceClosureV5,
        evidence_v5.ContainerBootstrapBuildWorkerTrustPolicyV5,
    ],
]:
    vector = cast(dict[str, object], yaml.safe_load(_V5_VECTOR.read_text(encoding="ascii")))
    roles = cast(list[dict[str, object]], vector["roles"])
    return cast(
        tuple[Any, Any, Any, Any],
        tuple(
            (
                evidence_v5.parse_container_bootstrap_artifact_evidence_closure_v5_canonical_json(
                    _decode(role["closure"])
                ),
                evidence_v5.parse_container_bootstrap_build_worker_trust_policy_v5_canonical_json(
                    _decode(role["worker_policy"])
                ),
            )
            for role in roles
        ),
    )


def _signed_manifest_from_original_evidence(
    *,
    delivery_map: TargetDeliveryMapV1,
    projection: static_v4.ContainerBootstrapStaticDeliveryProjectionV4,
    b1_policy: binding.TargetDeliveryMapProjectionBindingTrustPolicyV1,
    role_inputs: tuple[Any, Any, Any, Any],
    policy_inputs: tuple[Any, Any, Any, Any],
) -> tuple[
    manifest_v1.TargetDeliveryArtifactManifestTrustAnchorV1,
    manifest_v2.TargetDeliveryArtifactManifestV2,
    Ed25519PrivateKey,
]:
    anchor, signing_key = _new_manifest_anchor()
    b1_acceptances = tuple(
        binding.validate_target_delivery_map_projection_binding_v1(
            delivery_map=delivery_map,
            static_delivery_projection=projection,
            profile_envelope=role.profile_envelope,
            binding=role.projection_binding,
            trust_policy=b1_policy,
        )
        for role in role_inputs
    )
    v5_acceptances = tuple(
        evidence_v5.validate_container_bootstrap_artifact_evidence_closure_v5(
            closure=role.phase_a_v5_closure,
            worker_trust_policy=policy_input.worker_trust_policy,
            profile_envelope=role.profile_envelope,
            profile_trust_anchor=b1_policy.profile_trust_anchor,
        )
        for role, policy_input in zip(role_inputs, policy_inputs, strict=True)
    )
    policy_hashes = tuple(
        evidence_v5.container_bootstrap_build_worker_trust_policy_v5_sha256(
            policy_input.worker_trust_policy
        )
        for policy_input in policy_inputs
    )
    entries = tuple(
        manifest_v2._entry(
            role,
            v5_policy=policy_input.worker_trust_policy,
            v5_policy_sha256=policy_hash,
            v5_closure_sha256=v5_acceptance.closure_sha256,
            v5_context_sha256=v5_acceptance.verification_context_sha256,
            b1_binding_sha256=b1_acceptance.binding_sha256,
            b1_context_sha256=b1_acceptance.verification_context_sha256,
        )
        for role, policy_input, policy_hash, b1_acceptance, v5_acceptance in zip(
            role_inputs,
            policy_inputs,
            policy_hashes,
            b1_acceptances,
            v5_acceptances,
            strict=True,
        )
    )
    b1_policy_hash = hashlib.sha256(
        manifest_v2._B1_POLICY_HASH_DOMAIN
        + binding.target_delivery_map_projection_binding_trust_policy_v1_canonical_json(b1_policy)
    ).hexdigest()
    unsigned = manifest_v2.TargetDeliveryArtifactManifestV2(
        schema_version="rsd.target-delivery-artifact-manifest.v2",
        signature_algorithm="ed25519",
        component_order=cast(Any, _COMPONENTS),
        target_delivery_map_sha256=b1_acceptances[0].target_delivery_map_sha256,
        static_delivery_projection_sha256=b1_acceptances[0].static_delivery_projection_sha256,
        map_signer_key_id=b1_policy.map_signer_trust_anchor.key_id,
        map_signer_fingerprint_sha256=b1_policy.map_signer_trust_anchor.public_key_fingerprint_sha256,
        b1_policy_sha256=b1_policy_hash,
        common_profile_root_key_id=b1_policy.profile_trust_anchor.key_id,
        common_profile_root_fingerprint_sha256=(
            b1_policy.profile_trust_anchor.public_key_fingerprint_sha256
        ),
        source=manifest_v2._source(role_inputs[0].phase_a_v5_closure.worker_attestations[0]),
        derived_oci_repository=(
            role_inputs[0].phase_a_v5_closure.oci_safe_config_evidence.derived_repository
        ),
        roles=cast(Any, entries),
        signer_key_id=anchor.key_id,
        signer_fingerprint_sha256=anchor.public_key_fingerprint_sha256,
        signature_base64=base64.b64encode(bytes(64)).decode("ascii"),
        non_authorizing=True,
        evidence_effect_allowed=False,
        build_allowed=False,
        materialization_allowed=False,
        attach_allowed=False,
        effect_allowed=False,
    )
    signed = unsigned.model_copy(
        update={
            "signature_base64": base64.b64encode(
                signing_key.sign(manifest_v2.target_delivery_artifact_manifest_v2_message(unsigned))
            ).decode("ascii")
        }
    )
    return anchor, signed, signing_key


def _signed_artifacts(
    *,
    use_public_v5: bool = False,
    worker_identity_overrides: tuple[str | None, str | None, str | None, str | None] | None = None,
    physical_builder_identity_overrides: tuple[str | None, str | None, str | None, str | None]
    | None = None,
) -> tuple[
    TargetDeliveryMapV1,
    static_v4.ContainerBootstrapStaticDeliveryProjectionV4,
    binding.TargetDeliveryMapProjectionBindingTrustPolicyV1,
    manifest_v1.TargetDeliveryArtifactManifestTrustAnchorV1,
    tuple[
        manifest_v2.TargetDeliveryArtifactManifestRoleInputV2,
        manifest_v2.TargetDeliveryArtifactManifestRoleInputV2,
        manifest_v2.TargetDeliveryArtifactManifestRoleInputV2,
        manifest_v2.TargetDeliveryArtifactManifestRoleInputV2,
    ],
    tuple[
        manifest_v2.TargetDeliveryArtifactManifestV5RolePolicyInputV2,
        manifest_v2.TargetDeliveryArtifactManifestV5RolePolicyInputV2,
        manifest_v2.TargetDeliveryArtifactManifestV5RolePolicyInputV2,
        manifest_v2.TargetDeliveryArtifactManifestV5RolePolicyInputV2,
    ],
    manifest_v2.TargetDeliveryArtifactManifestV2,
    Ed25519PrivateKey,
]:
    delivery_map, projection, b1_policy, _old_anchor, envelopes, bindings = _vector_inputs()
    worker_overrides = worker_identity_overrides or (None, None, None, None)
    builder_overrides = physical_builder_identity_overrides or (None, None, None, None)
    closures_and_policies = (
        _public_v5_closures()
        if use_public_v5
        else cast(
            tuple[Any, Any, Any, Any],
            tuple(
                _v5_closure(
                    fixture=_load_v5_fixture(),
                    envelope=envelope,
                    component=component,
                    ordinal=ordinal,
                    first_worker_identity_sha256=worker_identity,
                    first_physical_builder_identity_sha256=physical_builder_identity,
                )
                for ordinal, (
                    component,
                    envelope,
                    worker_identity,
                    physical_builder_identity,
                ) in enumerate(
                    zip(_COMPONENTS, envelopes, worker_overrides, builder_overrides, strict=True)
                )
            ),
        )
    )
    role_inputs = cast(
        tuple[Any, Any, Any, Any],
        tuple(
            manifest_v2.TargetDeliveryArtifactManifestRoleInputV2(
                schema_version="rsd.target-delivery-artifact-manifest-role-input.v2",
                component=cast(Any, component),
                profile_envelope=envelope,
                projection_binding=projection_binding,
                phase_a_v5_closure=closure,
            )
            for component, envelope, projection_binding, (closure, _policy) in zip(
                _COMPONENTS, envelopes, bindings, closures_and_policies, strict=True
            )
        ),
    )
    policy_inputs = cast(
        tuple[Any, Any, Any, Any],
        tuple(
            manifest_v2.TargetDeliveryArtifactManifestV5RolePolicyInputV2(
                schema_version="rsd.target-delivery-artifact-manifest-v5-role-policy-input.v2",
                component=cast(Any, component),
                worker_trust_policy=policy,
            )
            for component, (_closure, policy) in zip(
                _COMPONENTS, closures_and_policies, strict=True
            )
        ),
    )
    anchor, signing_key = _new_manifest_anchor()
    b1_acceptances = tuple(
        binding.validate_target_delivery_map_projection_binding_v1(
            delivery_map=delivery_map,
            static_delivery_projection=projection,
            profile_envelope=role.profile_envelope,
            binding=role.projection_binding,
            trust_policy=b1_policy,
        )
        for role in role_inputs
    )
    v5_acceptances = tuple(
        evidence_v5.validate_container_bootstrap_artifact_evidence_closure_v5(
            closure=role.phase_a_v5_closure,
            worker_trust_policy=policy_input.worker_trust_policy,
            profile_envelope=role.profile_envelope,
            profile_trust_anchor=b1_policy.profile_trust_anchor,
        )
        for role, policy_input in zip(role_inputs, policy_inputs, strict=True)
    )
    policy_hashes = tuple(
        evidence_v5.container_bootstrap_build_worker_trust_policy_v5_sha256(
            policy_input.worker_trust_policy
        )
        for policy_input in policy_inputs
    )
    entries = tuple(
        manifest_v2._entry(
            role,
            v5_policy=policy_input.worker_trust_policy,
            v5_policy_sha256=policy_hash,
            v5_closure_sha256=v5_acceptance.closure_sha256,
            v5_context_sha256=v5_acceptance.verification_context_sha256,
            b1_binding_sha256=b1_acceptance.binding_sha256,
            b1_context_sha256=b1_acceptance.verification_context_sha256,
        )
        for role, policy_input, policy_hash, b1_acceptance, v5_acceptance in zip(
            role_inputs,
            policy_inputs,
            policy_hashes,
            b1_acceptances,
            v5_acceptances,
            strict=True,
        )
    )
    b1_policy_hash = hashlib.sha256(
        manifest_v2._B1_POLICY_HASH_DOMAIN
        + binding.target_delivery_map_projection_binding_trust_policy_v1_canonical_json(b1_policy)
    ).hexdigest()
    unsigned = manifest_v2.TargetDeliveryArtifactManifestV2(
        schema_version="rsd.target-delivery-artifact-manifest.v2",
        signature_algorithm="ed25519",
        component_order=cast(Any, _COMPONENTS),
        target_delivery_map_sha256=b1_acceptances[0].target_delivery_map_sha256,
        static_delivery_projection_sha256=b1_acceptances[0].static_delivery_projection_sha256,
        map_signer_key_id=b1_policy.map_signer_trust_anchor.key_id,
        map_signer_fingerprint_sha256=b1_policy.map_signer_trust_anchor.public_key_fingerprint_sha256,
        b1_policy_sha256=b1_policy_hash,
        common_profile_root_key_id=b1_policy.profile_trust_anchor.key_id,
        common_profile_root_fingerprint_sha256=(
            b1_policy.profile_trust_anchor.public_key_fingerprint_sha256
        ),
        source=manifest_v2._source(role_inputs[0].phase_a_v5_closure.worker_attestations[0]),
        derived_oci_repository=(
            role_inputs[0].phase_a_v5_closure.oci_safe_config_evidence.derived_repository
        ),
        roles=cast(Any, entries),
        signer_key_id=anchor.key_id,
        signer_fingerprint_sha256=anchor.public_key_fingerprint_sha256,
        signature_base64=base64.b64encode(bytes(64)).decode("ascii"),
        non_authorizing=True,
        evidence_effect_allowed=False,
        build_allowed=False,
        materialization_allowed=False,
        attach_allowed=False,
        effect_allowed=False,
    )
    signed = unsigned.model_copy(
        update={
            "signature_base64": base64.b64encode(
                signing_key.sign(manifest_v2.target_delivery_artifact_manifest_v2_message(unsigned))
            ).decode("ascii")
        }
    )
    return (
        delivery_map,
        projection,
        b1_policy,
        anchor,
        role_inputs,
        policy_inputs,
        signed,
        signing_key,
    )


def _validate_signed() -> tuple[
    manifest_v2.TargetDeliveryArtifactManifestAcceptanceV2,
    manifest_v2.TargetDeliveryArtifactManifestV2,
    tuple[
        manifest_v2.TargetDeliveryArtifactManifestV5RolePolicyInputV2,
        manifest_v2.TargetDeliveryArtifactManifestV5RolePolicyInputV2,
        manifest_v2.TargetDeliveryArtifactManifestV5RolePolicyInputV2,
        manifest_v2.TargetDeliveryArtifactManifestV5RolePolicyInputV2,
    ],
]:
    delivery_map, projection, b1_policy, anchor, roles, policies, signed, _signing_key = (
        _signed_artifacts()
    )
    acceptance = manifest_v2.validate_target_delivery_artifact_manifest_v2(
        delivery_map=delivery_map,
        static_delivery_projection=projection,
        b1_trust_policy=b1_policy,
        manifest_trust_anchor=anchor,
        role_inputs=roles,
        v5_role_policy_inputs=policies,
        manifest=signed,
    )
    return acceptance, signed, policies


def _assert_no_raw_config(value: object) -> None:
    forbidden_keys = {"User", "WorkingDir", "Env"}
    forbidden_values = {"12345:23456", "/opt/rsd", "APP_MODE=production", "PATH=/usr/bin:/bin"}
    if type(value) is dict:
        mapped = cast(dict[str, object], value)
        assert not (set(mapped) & forbidden_keys)
        for nested in mapped.values():
            _assert_no_raw_config(nested)
    elif type(value) is list:
        for nested in cast(list[object], value):
            _assert_no_raw_config(nested)
    elif type(value) is str:
        assert value not in forbidden_values


def _validate(
    *,
    delivery_map: TargetDeliveryMapV1,
    projection: static_v4.ContainerBootstrapStaticDeliveryProjectionV4,
    b1_policy: binding.TargetDeliveryMapProjectionBindingTrustPolicyV1,
    anchor: manifest_v1.TargetDeliveryArtifactManifestTrustAnchorV1,
    roles: tuple[
        manifest_v2.TargetDeliveryArtifactManifestRoleInputV2,
        manifest_v2.TargetDeliveryArtifactManifestRoleInputV2,
        manifest_v2.TargetDeliveryArtifactManifestRoleInputV2,
        manifest_v2.TargetDeliveryArtifactManifestRoleInputV2,
    ],
    policies: tuple[
        manifest_v2.TargetDeliveryArtifactManifestV5RolePolicyInputV2,
        manifest_v2.TargetDeliveryArtifactManifestV5RolePolicyInputV2,
        manifest_v2.TargetDeliveryArtifactManifestV5RolePolicyInputV2,
        manifest_v2.TargetDeliveryArtifactManifestV5RolePolicyInputV2,
    ],
    manifest: manifest_v2.TargetDeliveryArtifactManifestV2,
) -> manifest_v2.TargetDeliveryArtifactManifestAcceptanceV2:
    return manifest_v2.validate_target_delivery_artifact_manifest_v2(
        delivery_map=delivery_map,
        static_delivery_projection=projection,
        b1_trust_policy=b1_policy,
        manifest_trust_anchor=anchor,
        role_inputs=roles,
        v5_role_policy_inputs=policies,
        manifest=manifest,
    )


def _replace_first_role(
    manifest: manifest_v2.TargetDeliveryArtifactManifestV2,
    role: manifest_v2.TargetDeliveryArtifactManifestRoleEntryV2,
) -> manifest_v2.TargetDeliveryArtifactManifestV2:
    return manifest.model_copy(update={"roles": cast(Any, (role, *manifest.roles[1:]))})


def _fully_valid_cross_profile_ticket_collision_inputs(
    tmp_path: Path,
    *,
    physical_builder_collision: bool = False,
) -> tuple[
    TargetDeliveryMapV1,
    static_v4.ContainerBootstrapStaticDeliveryProjectionV4,
    binding.TargetDeliveryMapProjectionBindingTrustPolicyV1,
    manifest_v1.TargetDeliveryArtifactManifestTrustAnchorV1,
    tuple[Any, Any, Any, Any],
    tuple[Any, Any, Any, Any],
    manifest_v2.TargetDeliveryArtifactManifestV2,
]:
    path = Path(__file__).with_name("test_target_delivery_artifact_manifest.py")
    spec = importlib.util.spec_from_file_location("_b2_v2_v1_fixture", path)
    if spec is None or spec.loader is None:
        raise RuntimeError("B2 V1 fixture is unavailable")
    fixture = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(fixture)
    static = fixture._load("_b2_v2_static", "test_container_attach_static_v4.py")
    b1_fixture = fixture._load("_b2_v2_b1", "test_target_delivery_map_signing.py")
    bundles = [
        static._bundle(tmp_path / component, component=component, documentation_authorities=True)
        for component in _COMPONENTS
    ]

    ticket_key = Ed25519PrivateKey.generate()
    ticket_public = ticket_key.public_key().public_bytes_raw()
    ticket_root = static.ContainerAttachTicketTrustAnchorV1(
        schema_version="rsd.container-attach-ticket-trust-anchor.v1",
        key_id="b2-v2-role-one-ticket-root",
        public_key_base64=base64.b64encode(ticket_public).decode("ascii"),
        public_key_fingerprint_sha256=hashlib.sha256(ticket_public).hexdigest(),
        algorithm="ed25519",
    )
    rebuilt = static._rebuild_profile(
        bundles[1]["profile"],
        ticket_trust_anchor=ticket_root,
    )
    bundles[1]["profile_envelope"] = static._profile_envelope(rebuilt)
    for bundle in bundles:
        bundle["profile_envelope"] = fixture._common_source_envelope(static, bundle)

    delivery_map, documented_bundle, _map_signing_key = b1_fixture._documentation_signed_map(
        tmp_path / "map"
    )
    projection = documented_bundle["projection"]
    assert all(bundle["projection"] == projection for bundle in bundles)
    map_public = static.v2_fixtures._PUBLIC
    map_anchor = fixture.signing.TargetDeliveryMapSignerTrustAnchorV1(
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
        key_id="b2-v2-binding-root",
        authority_identity_sha256=_sha("b2-v2-binding-authority"),
        independence_domain_identity_sha256=_sha("b2-v2-binding-domain"),
        public_key_base64=base64.b64encode(binding_public).decode("ascii"),
        public_key_fingerprint_sha256=hashlib.sha256(binding_public).hexdigest(),
        algorithm="ed25519",
    )
    legacy_keys = (Ed25519PrivateKey.generate(), Ed25519PrivateKey.generate())
    legacy_anchors = (
        fixture._anchor(legacy_keys[0], "v2-one"),
        fixture._anchor(legacy_keys[1], "v2-two"),
    )
    legacy_policy = fixture.evidence.ContainerBootstrapBuildWorkerTrustPolicyV4(
        schema_version="rsd.container-bootstrap-build-worker-trust-policy.v4",
        policy_id="b2-v2-legacy-worker-policy",
        independence_domain_sha256=_sha("b2-v2-legacy-worker-domain"),
        worker_trust_anchors=legacy_anchors,
    )
    b1_policy = binding.TargetDeliveryMapProjectionBindingTrustPolicyV1(
        schema_version="rsd.target-delivery-map-projection-binding-trust-policy.v1",
        policy_id="b2-v2-policy",
        map_signer_trust_anchor=map_anchor,
        map_authority_identity_sha256=_sha("b2-v2-map-authority"),
        map_independence_domain_identity_sha256=_sha("b2-v2-map-domain"),
        binding_trust_anchor=binding_anchor,
        profile_trust_anchor=bundles[0]["profile_trust_anchor"],
        phase_a_worker_trust_policy=legacy_policy,
    )
    collision = ticket_root.public_key_fingerprint_sha256
    role_values: list[manifest_v2.TargetDeliveryArtifactManifestRoleInputV2] = []
    policy_values: list[manifest_v2.TargetDeliveryArtifactManifestV5RolePolicyInputV2] = []
    for ordinal, (component, bundle) in enumerate(zip(_COMPONENTS, bundles, strict=True)):
        envelope = bundle["profile_envelope"]
        closure, worker_policy = _v5_closure(
            fixture=_load_v5_fixture(),
            envelope=envelope,
            component=component,
            ordinal=ordinal,
            first_worker_identity_sha256=(
                collision if ordinal == 0 and not physical_builder_collision else None
            ),
            first_physical_builder_identity_sha256=(
                collision if ordinal == 0 and physical_builder_collision else None
            ),
        )
        role_values.append(
            manifest_v2.TargetDeliveryArtifactManifestRoleInputV2(
                schema_version="rsd.target-delivery-artifact-manifest-role-input.v2",
                component=cast(Any, component),
                profile_envelope=envelope,
                projection_binding=fixture._signed_binding(
                    key=binding_key,
                    anchor=binding_anchor,
                    delivery_map=delivery_map,
                    projection=projection,
                    envelope=envelope,
                    map_anchor=map_anchor,
                    profile_anchor=b1_policy.profile_trust_anchor,
                ),
                phase_a_v5_closure=closure,
            )
        )
        policy_values.append(
            manifest_v2.TargetDeliveryArtifactManifestV5RolePolicyInputV2(
                schema_version="rsd.target-delivery-artifact-manifest-v5-role-policy-input.v2",
                component=cast(Any, component),
                worker_trust_policy=worker_policy,
            )
        )
    roles = cast(tuple[Any, Any, Any, Any], tuple(role_values))
    policies = cast(tuple[Any, Any, Any, Any], tuple(policy_values))
    anchor, signed, _signing_key = _signed_manifest_from_original_evidence(
        delivery_map=delivery_map,
        projection=projection,
        b1_policy=b1_policy,
        role_inputs=roles,
        policy_inputs=policies,
    )
    return delivery_map, projection, b1_policy, anchor, roles, policies, signed


def test_v2_revalidates_original_b1_and_v5_with_reused_physical_builders() -> None:
    acceptance, signed, policies = _validate_signed()
    assert (
        "acceptance"
        not in inspect.signature(
            manifest_v2.validate_target_delivery_artifact_manifest_v2
        ).parameters
    )
    assert tuple(role.component for role in signed.roles) == _COMPONENTS
    assert tuple(summary.component for summary in acceptance.roles) == _COMPONENTS
    assert len({role.v5_worker_trust_policy_sha256 for role in signed.roles}) == 4
    assert len({role.v5_worker_trust_policy_id for role in signed.roles}) == 4
    assert len({role.v5_worker_independence_domain_sha256 for role in signed.roles}) == 4
    assert len({run_id for role in signed.roles for run_id in role.worker_run_ids}) == 8
    assert len({role.oci.derived_reference for role in signed.roles}) == 1
    assert len({role.oci.linux_amd64_manifest_digest_sha256 for role in signed.roles}) == 1
    assert {
        anchor.physical_builder_identity_sha256
        for policy_input in policies
        for anchor in policy_input.worker_trust_policy.worker_trust_anchors
    } == {_sha("b2-v2-shared-builder-a"), _sha("b2-v2-shared-builder-b")}
    assert (
        acceptance.non_authorizing,
        acceptance.evidence_effect_allowed,
        acceptance.build_allowed,
        acceptance.materialization_allowed,
        acceptance.attach_allowed,
        acceptance.effect_allowed,
    ) == (True, False, False, False, False, False)
    _assert_no_raw_config(
        json.loads(manifest_v2.target_delivery_artifact_manifest_v2_canonical_json(signed))
    )
    assert (
        manifest_v2.parse_target_delivery_artifact_manifest_v2_canonical_json(
            manifest_v2.target_delivery_artifact_manifest_v2_canonical_json(signed)
        )
        == signed
    )
    assert (
        manifest_v2.parse_target_delivery_artifact_manifest_acceptance_v2_canonical_json(
            manifest_v2.target_delivery_artifact_manifest_acceptance_v2_canonical_json(acceptance)
        )
        == acceptance
    )


def test_v2_accepts_role_specific_oci_references_and_digests() -> None:
    delivery_map, projection, b1_policy, anchor, roles, policies, signed, _signing_key = (
        _signed_artifacts(use_public_v5=True)
    )
    manifest_v2.validate_target_delivery_artifact_manifest_v2(
        delivery_map=delivery_map,
        static_delivery_projection=projection,
        b1_trust_policy=b1_policy,
        manifest_trust_anchor=anchor,
        role_inputs=roles,
        v5_role_policy_inputs=policies,
        manifest=signed,
    )
    assert len({role.oci.derived_reference for role in signed.roles}) == 4
    assert len({role.oci.linux_amd64_manifest_digest_sha256 for role in signed.roles}) == 4


def test_v2_reconstructs_signed_redacted_oci_config_descriptor_commitments() -> None:
    delivery_map, projection, b1_policy, anchor, roles, policies, signed, _signing_key = (
        _signed_artifacts()
    )
    _validate(
        delivery_map=delivery_map,
        projection=projection,
        b1_policy=b1_policy,
        anchor=anchor,
        roles=roles,
        policies=policies,
        manifest=signed,
    )
    for role_input, entry in zip(roles, signed.roles, strict=True):
        claim = role_input.phase_a_v5_closure.oci_safe_config_evidence.expanded_oci_config_claim
        summary = entry.oci.config
        assert summary.oci_config_descriptor_media_type == claim.oci_config_descriptor_media_type
        assert (
            summary.oci_config_descriptor_sha256
            == claim.oci_config_descriptor_digest.removeprefix("sha256:")
        )
        assert summary.oci_config_descriptor_size_bytes == claim.oci_config_descriptor_size
    rendered = json.loads(manifest_v2.target_delivery_artifact_manifest_v2_canonical_json(signed))
    assert rendered["roles"][0]["oci"]["config"] == signed.roles[0].oci.config.model_dump(
        mode="json"
    )


def test_v2_rejects_resigned_v5_worker_identity_to_v5_domain_collision() -> None:
    collision = _sha("b2-v2-v5-domain-1")
    delivery_map, projection, b1_policy, anchor, roles, policies, signed, _signing_key = (
        _signed_artifacts(worker_identity_overrides=(collision, None, None, None))
    )
    # Each closure remains independently re-signed and valid under its own V5 policy.
    evidence_v5.validate_container_bootstrap_artifact_evidence_closure_v5(
        closure=roles[0].phase_a_v5_closure,
        worker_trust_policy=policies[0].worker_trust_policy,
        profile_envelope=roles[0].profile_envelope,
        profile_trust_anchor=b1_policy.profile_trust_anchor,
    )
    with pytest.raises(manifest_v2.TargetDeliveryArtifactManifestV2Error):
        _validate(
            delivery_map=delivery_map,
            projection=projection,
            b1_policy=b1_policy,
            anchor=anchor,
            roles=roles,
            policies=policies,
            manifest=signed,
        )


def test_v2_rejects_resigned_v5_worker_identity_to_b1_policy_hash() -> None:
    _map, _projection, original_b1_policy, _anchor, _envelopes, _bindings = _vector_inputs()
    collision = manifest_v2._b1_policy_sha256(original_b1_policy)
    delivery_map, projection, b1_policy, anchor, roles, policies, signed, _signing_key = (
        _signed_artifacts(worker_identity_overrides=(collision, None, None, None))
    )
    assert manifest_v2._b1_policy_sha256(b1_policy) == collision
    # The closure remains independently re-signed and valid.  Its worker identity
    # only aliases the B1 policy identity derived into the V2 signature preimage.
    evidence_v5.validate_container_bootstrap_artifact_evidence_closure_v5(
        closure=roles[0].phase_a_v5_closure,
        worker_trust_policy=policies[0].worker_trust_policy,
        profile_envelope=roles[0].profile_envelope,
        profile_trust_anchor=b1_policy.profile_trust_anchor,
    )
    with pytest.raises(manifest_v2.TargetDeliveryArtifactManifestV2Error) as error:
        _validate(
            delivery_map=delivery_map,
            projection=projection,
            b1_policy=b1_policy,
            anchor=anchor,
            roles=roles,
            policies=policies,
            manifest=signed,
        )
    assert error.value.phase == "anchor"


def test_v2_rejects_resigned_v5_builder_to_b1_policy_hash() -> None:
    _map, _projection, original_b1_policy, _anchor, _envelopes, _bindings = _vector_inputs()
    collision = manifest_v2._b1_policy_sha256(original_b1_policy)
    delivery_map, projection, b1_policy, anchor, roles, policies, signed, _signing_key = (
        _signed_artifacts(physical_builder_identity_overrides=(collision, None, None, None))
    )
    assert manifest_v2._b1_policy_sha256(b1_policy) == collision
    evidence_v5.validate_container_bootstrap_artifact_evidence_closure_v5(
        closure=roles[0].phase_a_v5_closure,
        worker_trust_policy=policies[0].worker_trust_policy,
        profile_envelope=roles[0].profile_envelope,
        profile_trust_anchor=b1_policy.profile_trust_anchor,
    )
    with pytest.raises(manifest_v2.TargetDeliveryArtifactManifestV2Error) as error:
        _validate(
            delivery_map=delivery_map,
            projection=projection,
            b1_policy=b1_policy,
            anchor=anchor,
            roles=roles,
            policies=policies,
            manifest=signed,
        )
    assert error.value.phase == "anchor"


def test_v2_rejects_resigned_v5_worker_identity_to_other_profile_ticket_fingerprint(
    tmp_path: Path,
) -> None:
    delivery_map, projection, b1_policy, anchor, roles, policies, signed = (
        _fully_valid_cross_profile_ticket_collision_inputs(tmp_path)
    )
    # The helper independently validates/re-signs every B1 and V5 object before
    # producing this V2 signature; only the cross-role identity alias remains.
    with pytest.raises(manifest_v2.TargetDeliveryArtifactManifestV2Error) as error:
        _validate(
            delivery_map=delivery_map,
            projection=projection,
            b1_policy=b1_policy,
            anchor=anchor,
            roles=roles,
            policies=policies,
            manifest=signed,
        )
    assert error.value.phase == "anchor"


def test_v2_rejects_resigned_v5_builder_to_v5_domain_collision() -> None:
    cases = (
        (_sha("b2-v2-v5-domain-1"), 0),
        (_sha("b2-v2-v5-domain-0"), 1),
    )
    for collision, builder_role in cases:
        overrides = cast(
            tuple[str | None, str | None, str | None, str | None],
            tuple(collision if index == builder_role else None for index in range(4)),
        )
        delivery_map, projection, b1_policy, anchor, roles, policies, signed, _signing_key = (
            _signed_artifacts(physical_builder_identity_overrides=overrides)
        )
        # Each modified closure is independently re-signed and valid.  The two
        # cases exercise protected-after-builder and builder-after-protected order.
        evidence_v5.validate_container_bootstrap_artifact_evidence_closure_v5(
            closure=roles[builder_role].phase_a_v5_closure,
            worker_trust_policy=policies[builder_role].worker_trust_policy,
            profile_envelope=roles[builder_role].profile_envelope,
            profile_trust_anchor=b1_policy.profile_trust_anchor,
        )
        with pytest.raises(manifest_v2.TargetDeliveryArtifactManifestV2Error) as error:
            _validate(
                delivery_map=delivery_map,
                projection=projection,
                b1_policy=b1_policy,
                anchor=anchor,
                roles=roles,
                policies=policies,
                manifest=signed,
            )
        assert error.value.phase == "anchor"


def test_v2_rejects_resigned_v5_builder_to_legacy_worker_identity_or_authority() -> None:
    _map, _projection, b1_policy, _anchor, _envelopes, _bindings = _vector_inputs()
    legacy_workers = b1_policy.phase_a_worker_trust_policy.worker_trust_anchors
    for collision in (
        legacy_workers[0].worker_identity_sha256,
        legacy_workers[1].authority_identity_sha256,
    ):
        delivery_map, projection, checked_policy, anchor, roles, policies, signed, _signing_key = (
            _signed_artifacts(physical_builder_identity_overrides=(collision, None, None, None))
        )
        evidence_v5.validate_container_bootstrap_artifact_evidence_closure_v5(
            closure=roles[0].phase_a_v5_closure,
            worker_trust_policy=policies[0].worker_trust_policy,
            profile_envelope=roles[0].profile_envelope,
            profile_trust_anchor=checked_policy.profile_trust_anchor,
        )
        with pytest.raises(manifest_v2.TargetDeliveryArtifactManifestV2Error) as error:
            _validate(
                delivery_map=delivery_map,
                projection=projection,
                b1_policy=checked_policy,
                anchor=anchor,
                roles=roles,
                policies=policies,
                manifest=signed,
            )
        assert error.value.phase == "anchor"


def test_v2_rejects_resigned_v5_builder_to_other_profile_ticket_fingerprint(
    tmp_path: Path,
) -> None:
    delivery_map, projection, b1_policy, anchor, roles, policies, signed = (
        _fully_valid_cross_profile_ticket_collision_inputs(
            tmp_path, physical_builder_collision=True
        )
    )
    # The altered V5 closure and every B1 relation were independently rechecked
    # while constructing this signature; only the cross-role builder alias remains.
    evidence_v5.validate_container_bootstrap_artifact_evidence_closure_v5(
        closure=roles[0].phase_a_v5_closure,
        worker_trust_policy=policies[0].worker_trust_policy,
        profile_envelope=roles[0].profile_envelope,
        profile_trust_anchor=b1_policy.profile_trust_anchor,
    )
    with pytest.raises(manifest_v2.TargetDeliveryArtifactManifestV2Error) as error:
        _validate(
            delivery_map=delivery_map,
            projection=projection,
            b1_policy=b1_policy,
            anchor=anchor,
            roles=roles,
            policies=policies,
            manifest=signed,
        )
    assert error.value.phase == "anchor"


def test_v2_public_models_and_parser_reject_malformed_role_values() -> None:
    _acceptance, signed, _policies = _validate_signed()
    role_payload = signed.roles[0].model_dump(mode="python")
    for field, value in (
        ("worker_attestation_sha256s", ("A" * 64, _sha("other-attestation"))),
        ("worker_run_ids", ("0-not-an-identifier", "valid-run-id")),
        ("physical_builder_identity_sha256s", ("z" * 64, _sha("other-builder"))),
        ("v5_worker_trust_policy_id", "0-policy"),
        ("v5_worker_trust_policy_epoch", True),
        ("v5_worker_independence_domain_sha256", "A" * 64),
        ("wrapper_executable_path", "bin/wrapper"),
    ):
        candidate = dict(role_payload)
        candidate[field] = value
        with pytest.raises(ValueError):
            manifest_v2.TargetDeliveryArtifactManifestRoleEntryV2.model_validate(
                candidate, strict=True
            )

    source_payload = signed.source.model_dump(mode="python")
    for field, value in (
        ("repository_identity_sha256", "A" * 64),
        ("wrapper_subtree_path", "../wrapper"),
        ("wrapper_tree_entry_count", True),
    ):
        candidate = dict(source_payload)
        candidate[field] = value
        with pytest.raises(ValueError):
            manifest_v2.TargetDeliveryArtifactSourceSummaryV2.model_validate(candidate, strict=True)

    config_payload = signed.roles[0].oci.config.model_dump(mode="python")
    for field, value in (
        ("oci_config_descriptor_media_type", "application/json"),
        ("oci_config_descriptor_sha256", "A" * 64),
        ("oci_config_descriptor_size_bytes", True),
    ):
        candidate = dict(config_payload)
        candidate[field] = value
        with pytest.raises(ValueError):
            manifest_v2.TargetDeliveryArtifactConfigCommitmentSummaryV2.model_validate(
                candidate, strict=True
            )

    oci_payload = signed.roles[0].oci.model_dump(mode="python")
    for field, value in (
        ("derived_reference", "registry.example/target:not-a-digest"),
        ("linux_amd64_manifest_digest_sha256", "A" * 64),
        ("wrapper_path", "wrapper"),
        ("wrapper_byte_count", True),
    ):
        candidate = dict(oci_payload)
        candidate[field] = value
        with pytest.raises(ValueError):
            manifest_v2.TargetDeliveryArtifactOciSummaryV2.model_validate(candidate, strict=True)

    manifest_payload = signed.model_dump(mode="python")
    for field, value in (
        ("component_order", list(_COMPONENTS)),
        ("map_signer_key_id", "0-map-signer"),
        ("b1_policy_sha256", "A" * 64),
    ):
        candidate = dict(manifest_payload)
        candidate[field] = value
        with pytest.raises(ValueError):
            manifest_v2.TargetDeliveryArtifactManifestV2.model_validate(candidate, strict=True)

    canonical = manifest_v2.target_delivery_artifact_manifest_v2_canonical_json(signed)
    parser_payload = json.loads(canonical)
    parser_payload["roles"][0]["worker_attestation_sha256s"][0] = "A" * 64
    malformed = json.dumps(
        parser_payload, ensure_ascii=True, sort_keys=True, separators=(",", ":")
    ).encode("ascii")
    with pytest.raises(manifest_v2.TargetDeliveryArtifactManifestV2Error):
        manifest_v2.parse_target_delivery_artifact_manifest_v2_canonical_json(malformed)


def test_v2_rejects_inconsistent_outer_oci_repository_reference_and_digest() -> None:
    delivery_map, projection, b1_policy, anchor, roles, policies, signed, signing_key = (
        _signed_artifacts()
    )
    first = signed.roles[0]
    alternate_repository = f"{signed.derived_oci_repository}-other"
    alternate_digest = _sha("alternate-oci-manifest-digest")
    bad_references = (
        f"{alternate_repository}@sha256:{first.oci.linux_amd64_manifest_digest_sha256}",
        f"{signed.derived_oci_repository}@sha256:{alternate_digest}",
    )
    malformed_manifests = (
        *(
            _replace_first_role(
                signed,
                first.model_copy(
                    update={"oci": first.oci.model_copy(update={"derived_reference": ref})}
                ),
            )
            for ref in bad_references
        ),
        signed.model_copy(update={"derived_oci_repository": alternate_repository}),
    )

    for malformed_manifest in malformed_manifests:
        with pytest.raises(ValueError):
            manifest_v2.TargetDeliveryArtifactManifestV2.model_validate(
                malformed_manifest.model_dump(mode="python"), strict=True
            )
        malformed_payload = json.dumps(
            malformed_manifest.model_dump(mode="json"),
            ensure_ascii=True,
            sort_keys=True,
            separators=(",", ":"),
        ).encode("ascii")
        with pytest.raises(manifest_v2.TargetDeliveryArtifactManifestV2Error):
            manifest_v2.parse_target_delivery_artifact_manifest_v2_canonical_json(malformed_payload)

    signed_malformed = malformed_manifests[1].model_copy(
        update={"signature_base64": base64.b64encode(bytes(64)).decode("ascii")}
    )
    signature_preimage = json.dumps(
        signed_malformed.model_dump(mode="json", exclude={"signature_base64"}),
        ensure_ascii=True,
        sort_keys=True,
        separators=(",", ":"),
    ).encode("ascii")
    signature = signing_key.sign(manifest_v2._MANIFEST_DOMAIN + signature_preimage)
    signed_malformed = signed_malformed.model_copy(
        update={"signature_base64": base64.b64encode(signature).decode("ascii")}
    )
    signing_key.public_key().verify(
        base64.b64decode(signed_malformed.signature_base64, validate=True),
        manifest_v2._MANIFEST_DOMAIN + signature_preimage,
    )
    with pytest.raises(manifest_v2.TargetDeliveryArtifactManifestV2Error):
        _validate(
            delivery_map=delivery_map,
            projection=projection,
            b1_policy=b1_policy,
            anchor=anchor,
            roles=roles,
            policies=policies,
            manifest=signed_malformed,
        )


def test_v2_rejects_policy_role_swaps_and_malformed_state() -> None:
    delivery_map, projection, b1_policy, anchor, roles, policies, signed, _signing_key = (
        _signed_artifacts()
    )
    swapped_first = policies[0].model_copy(
        update={"worker_trust_policy": policies[1].worker_trust_policy}
    )
    swapped = cast(tuple[Any, Any, Any, Any], (swapped_first, *policies[1:]))
    with pytest.raises(manifest_v2.TargetDeliveryArtifactManifestV2Error):
        manifest_v2.validate_target_delivery_artifact_manifest_v2(
            delivery_map=delivery_map,
            static_delivery_projection=projection,
            b1_trust_policy=b1_policy,
            manifest_trust_anchor=anchor,
            role_inputs=roles,
            v5_role_policy_inputs=swapped,
            manifest=signed,
        )
    with pytest.raises(manifest_v2.TargetDeliveryArtifactManifestV2Error):
        manifest_v2.validate_target_delivery_artifact_manifest_v2(
            delivery_map=delivery_map,
            static_delivery_projection=projection,
            b1_trust_policy=b1_policy,
            manifest_trust_anchor=anchor,
            role_inputs=roles,
            v5_role_policy_inputs=policies,
            manifest=cast(Any, object()),
        )
    malformed = manifest_v2.TargetDeliveryArtifactManifestV2.model_construct(
        **{
            key: value
            for key, value in signed.model_dump(mode="python").items()
            if key != "effect_allowed"
        }
    )
    with pytest.raises(manifest_v2.TargetDeliveryArtifactManifestV2Error):
        manifest_v2.target_delivery_artifact_manifest_v2_canonical_json(malformed)
    acceptance, _same_signed, _same_policies = _validate_signed()
    deleted_state = acceptance.model_copy()
    object.__delattr__(deleted_state, "__pydantic_fields_set__")
    with pytest.raises(manifest_v2.TargetDeliveryArtifactManifestV2Error):
        manifest_v2.target_delivery_artifact_manifest_acceptance_v2_canonical_json(deleted_state)


def test_v2_rejects_hidden_or_constructed_top_level_original_inputs() -> None:
    delivery_map, projection, b1_policy, anchor, roles, policies, signed, _signing_key = (
        _signed_artifacts()
    )

    def assert_anchor_failure(
        *,
        map_value: TargetDeliveryMapV1 = delivery_map,
        projection_value: static_v4.ContainerBootstrapStaticDeliveryProjectionV4 = projection,
        policy_value: binding.TargetDeliveryMapProjectionBindingTrustPolicyV1 = b1_policy,
    ) -> None:
        with pytest.raises(manifest_v2.TargetDeliveryArtifactManifestV2Error) as error:
            _validate(
                delivery_map=map_value,
                projection=projection_value,
                b1_policy=policy_value,
                anchor=anchor,
                roles=roles,
                policies=policies,
                manifest=signed,
            )
        assert error.value.phase == "anchor"

    hidden_map = delivery_map.model_copy()
    object.__setattr__(hidden_map, "unexpected_top_level_state", "value")
    assert_anchor_failure(map_value=hidden_map)

    hidden_projection = projection.model_copy()
    object.__setattr__(hidden_projection, "unexpected_top_level_state", "value")
    assert_anchor_failure(projection_value=hidden_projection)

    hidden_policy = b1_policy.model_copy()
    object.__setattr__(hidden_policy, "unexpected_top_level_state", "value")
    assert_anchor_failure(policy_value=hidden_policy)

    missing_field = next(iter(TargetDeliveryMapV1.model_fields))
    malformed_map = TargetDeliveryMapV1.model_construct(
        **{
            name: value
            for name, value in delivery_map.model_dump(mode="python").items()
            if name != missing_field
        }
    )
    assert_anchor_failure(map_value=malformed_map)

    deleted_policy_state = b1_policy.model_copy()
    object.__delattr__(deleted_policy_state, "__pydantic_fields_set__")
    assert_anchor_failure(policy_value=deleted_policy_state)


def _assert_fixed_cycle_failure(
    operation: Any,
    *,
    phase: str,
) -> None:
    with pytest.raises(manifest_v2.TargetDeliveryArtifactManifestV2Error) as error:
        operation()
    assert error.value.phase == phase
    assert str(error.value) == "target delivery artifact manifest V2 validation failed"
    assert "RecursionError" not in str(error.value)


def test_v2_rejects_forged_cyclic_role_input_and_manifest_state() -> None:
    delivery_map, projection, b1_policy, anchor, roles, policies, signed, _signing_key = (
        _signed_artifacts()
    )
    cyclic_role = roles[0].model_copy()
    object.__setattr__(cyclic_role, "profile_envelope", cyclic_role)
    cyclic_role_inputs = cast(tuple[Any, Any, Any, Any], (cyclic_role, *roles[1:]))
    _assert_fixed_cycle_failure(
        lambda: _validate(
            delivery_map=delivery_map,
            projection=projection,
            b1_policy=b1_policy,
            anchor=anchor,
            roles=cyclic_role_inputs,
            policies=policies,
            manifest=signed,
        ),
        phase="anchor",
    )

    cyclic_source = signed.model_copy()
    object.__setattr__(cyclic_source, "source", cyclic_source)
    for operation in (
        lambda: manifest_v2.target_delivery_artifact_manifest_v2_canonical_json(cyclic_source),
        lambda: manifest_v2.target_delivery_artifact_manifest_v2_message(cyclic_source),
        lambda: manifest_v2.target_delivery_artifact_manifest_v2_sha256(cyclic_source),
    ):
        _assert_fixed_cycle_failure(operation, phase="manifest")

    tuple_list_cycle: list[object] = []
    cyclic_roles: tuple[object, ...] = (tuple_list_cycle,)
    tuple_list_cycle.append(cyclic_roles)
    cyclic_tuple = signed.model_copy()
    object.__setattr__(cyclic_tuple, "roles", cyclic_roles)
    _assert_fixed_cycle_failure(
        lambda: manifest_v2.target_delivery_artifact_manifest_v2_canonical_json(cyclic_tuple),
        phase="manifest",
    )


def test_v2_rejects_forged_dict_and_deep_container_cycles_without_leaks() -> None:
    acceptance, signed, _policies = _validate_signed()
    cyclic_mapping: dict[str, object] = {}
    cyclic_mapping["self"] = cyclic_mapping
    mapping_manifest = signed.model_copy()
    object.__setattr__(mapping_manifest, "source", cyclic_mapping)
    _assert_fixed_cycle_failure(
        lambda: manifest_v2.target_delivery_artifact_manifest_v2_canonical_json(mapping_manifest),
        phase="manifest",
    )

    deep_value: object = ()
    for _ in range(2_048):
        deep_value = (deep_value,)
    deep_manifest = signed.model_copy()
    object.__setattr__(deep_manifest, "roles", deep_value)
    _assert_fixed_cycle_failure(
        lambda: manifest_v2.target_delivery_artifact_manifest_v2_canonical_json(deep_manifest),
        phase="manifest",
    )

    cyclic_acceptance = acceptance.model_copy()
    object.__setattr__(cyclic_acceptance, "roles", cyclic_acceptance)
    _assert_fixed_cycle_failure(
        lambda: manifest_v2.target_delivery_artifact_manifest_acceptance_v2_canonical_json(
            cyclic_acceptance
        ),
        phase="manifest",
    )


def test_v2_allows_shared_acyclic_models_outside_the_active_path() -> None:
    _acceptance, signed, _policies = _validate_signed()
    shared_oci = signed.roles[0].oci
    shared_manifest = signed.model_copy(
        update={
            "roles": cast(
                Any,
                tuple(role.model_copy(update={"oci": shared_oci}) for role in signed.roles),
            )
        }
    )
    canonical = manifest_v2.target_delivery_artifact_manifest_v2_canonical_json(shared_manifest)
    assert (
        manifest_v2.parse_target_delivery_artifact_manifest_v2_canonical_json(canonical)
        == shared_manifest
    )


def test_v2_parsers_reject_noncanonical_and_wrong_signature_domain() -> None:
    _acceptance, signed, _policies = _validate_signed()
    canonical = manifest_v2.target_delivery_artifact_manifest_v2_canonical_json(signed)
    for malformed in (
        b" " + canonical,
        canonical.replace(b'"schema_version"', b'"schema_version" ', 1),
        canonical.removesuffix(b"}") + b',"unknown":true}',
    ):
        with pytest.raises(manifest_v2.TargetDeliveryArtifactManifestV2Error):
            manifest_v2.parse_target_delivery_artifact_manifest_v2_canonical_json(malformed)
    assert manifest_v2.target_delivery_artifact_manifest_v2_message(signed).startswith(
        b"omninode-rsd.target-delivery-artifact-manifest.ed25519.v2\x00"
    )
