"""Focused grammar and C0-binding coverage for the C1 offline bundle."""

from __future__ import annotations

import base64
import hashlib
import importlib.util
import json
from pathlib import Path
from types import ModuleType
from typing import Any, cast

from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey

from omninode_rsd.lifecycle import per_edge_runtime_proof_bundle_v1 as c1
from omninode_rsd.lifecycle import target_delivery_field_matrix_v1 as c0


def _sha(label: str) -> str:
    return hashlib.sha256(label.encode("ascii")).hexdigest()


def _url(value: bytes) -> str:
    return base64.urlsafe_b64encode(value).decode("ascii").rstrip("=")


def _c0_fixture() -> ModuleType:
    path = Path(__file__).with_name("test_target_delivery_field_matrix_v1.py")
    spec = importlib.util.spec_from_file_location("_runtime_proof_c0_fixture", path)
    if spec is None or spec.loader is None:
        raise RuntimeError("C0 fixture is unavailable")
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    return module


def _c0_inputs() -> tuple[Any, ...]:
    return cast(tuple[Any, ...], _c0_fixture()._inputs())


def _policy() -> c1.PerEdgeRuntimeProofBundlePolicyV1:
    return c1.PerEdgeRuntimeProofBundlePolicyV1(
        schema="rsd.per-edge-runtime-proof-bundle-policy.v1",
        policy_version=1,
        non_authorizing=True,
        validation_permitted=True,
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
    )


def _anchor() -> tuple[c1.PerEdgeRuntimeProofBundleTrustAnchorV1, Ed25519PrivateKey]:
    private_key = Ed25519PrivateKey.generate()
    public_key = private_key.public_key().public_bytes_raw()
    return (
        c1.PerEdgeRuntimeProofBundleTrustAnchorV1(
            schema="rsd.per-edge-runtime-proof-bundle-trust-anchor.v1",
            signature_algorithm="ed25519",
            observer_root_id="runtime-proof-observer-root",
            observer_key_id="runtime-proof-observer-key",
            observer_public_key_b64=_url(public_key),
            observer_fingerprint_sha256=hashlib.sha256(public_key).hexdigest(),
            authority_identity_sha256=_sha("runtime-proof-observer-authority"),
            independence_domain_sha256=_sha("runtime-proof-observer-domain"),
        ),
        private_key,
    )


def _context_sha256() -> str:
    model = c1._BundleContextV1(
        observed_at="2026-08-30T12:00:00Z",
        expires_at="2026-08-30T12:10:00Z",
        maximum_age_seconds=600,
        challenge_sha256=_sha("challenge"),
        session_sha256=_sha("session"),
        replay_identity_sha256=_sha("replay"),
    )
    return hashlib.sha256(c1._CONTEXT_DOMAIN + c1._canonical(model)).hexdigest()


def _sign_observation(
    observation: c1.PerEdgeRuntimeProofObservationV1,
    private_key: Ed25519PrivateKey,
) -> c1.PerEdgeRuntimeProofObservationV1:
    return observation.model_copy(
        update={
            "observation_signature_b64": _url(
                private_key.sign(c1._observation_signature_message(observation))
            )
        }
    )


def _sign_bundle(
    bundle: c1.PerEdgeRuntimeProofBundleV1,
    private_key: Ed25519PrivateKey,
) -> c1.PerEdgeRuntimeProofBundleV1:
    signed_observations = tuple(
        _sign_observation(item, private_key) for item in bundle.observations
    )
    unsigned = bundle.model_copy(
        update={"observations": signed_observations, "bundle_signature_b64": _url(bytes(64))}
    )
    return unsigned.model_copy(
        update={
            "bundle_signature_b64": _url(
                private_key.sign(c1.per_edge_runtime_proof_bundle_v1_signature_message(unsigned))
            )
        }
    )


def _bundle() -> tuple[
    tuple[Any, ...],
    c1.PerEdgeRuntimeProofBundlePolicyV1,
    c1.PerEdgeRuntimeProofBundleTrustAnchorV1,
    c1.PerEdgeRuntimeProofBundleV1,
    Ed25519PrivateKey,
]:
    inputs = _c0_inputs()
    (
        delivery_map,
        _projection,
        _b1_policy,
        _manifest_anchor,
        _role_inputs,
        _policy_inputs,
        manifest,
        matrix_policy,
        matrix_anchor,
        matrix,
        _matrix_private_key,
    ) = inputs
    anchor, private_key = _anchor()
    context = _context_sha256()
    expected = ((1, 3, 1, 0), (2, 4, 1, 0), (3, 8, 2, 2), (4, 9, 2, 2))
    observations: list[c1.PerEdgeRuntimeProofObservationV1] = []
    for ordinal, row_ordinal, lane_ordinal, component_ordinal in expected:
        relation = matrix.application_dependencies[ordinal - 1]
        observations.append(
            c1.PerEdgeRuntimeProofObservationV1(
                matrix_sha256=c0.target_delivery_field_matrix_v1_sha256(matrix),
                map_sha256=c0.target_delivery_map_sha256(delivery_map),
                manifest_sha256=c0.target_delivery_artifact_manifest_v2_sha256(manifest),
                c0_policy_sha256=c0.target_delivery_field_matrix_policy_v1_sha256(matrix_policy),
                source_snapshot_sha256=manifest.source.source_snapshot_sha256,
                c0_anchor_key_id=matrix_anchor.key_id,
                c0_anchor_fingerprint_sha256=matrix_anchor.public_key_fingerprint_sha256,
                c0_anchor_authority_identity_sha256=matrix_anchor.authority_identity_sha256,
                c0_anchor_independence_domain_sha256=(
                    matrix_anchor.independence_domain_identity_sha256
                ),
                observer_root_id=anchor.observer_root_id,
                observer_key_id=anchor.observer_key_id,
                observer_fingerprint_sha256=anchor.observer_fingerprint_sha256,
                authority_identity_sha256=anchor.authority_identity_sha256,
                independence_domain_sha256=anchor.independence_domain_sha256,
                observation_ordinal=ordinal,
                relation_ordinal=ordinal,
                c0_delivery_row_ordinal=row_ordinal,
                derived_lane_ordinal=lane_ordinal,
                b2_component_ordinal=component_ordinal,
                initiator_delivery_row_sha256=relation.initiator_delivery_row_sha256,
                relation_commitment_sha256=relation.relation_commitment_sha256,
                bundle_context_sha256=context,
                signed_c0_lane=relation.lane,
                initiator_component=relation.initiator_component,
                dependency_classification=relation.dependency,
                edge_transport_declaration=relation.edge_transport_declaration,
                transport_profile=(
                    "tls_verified_v1" if ordinal in {1, 3} else "unpublished_loopback_or_network_v1"
                ),
                listener_binding_subtype=("tls_lan" if ordinal in {1, 3} else "loopback_only"),
                runtime_evidence_category="runtime_classification_v1",
                container_evidence_category="container_classification_v1",
                network_evidence_category="network_classification_v1",
                listener_evidence_category="listener_classification_v1",
                event_evidence_category="event_classification_v1",
                inspection_evidence_category="inspection_classification_v1",
                runtime_classification_sha256=_sha(f"runtime-{ordinal}"),
                container_classification_sha256=_sha(f"container-{ordinal}"),
                network_classification_sha256=_sha(f"network-{ordinal}"),
                listener_classification_sha256=_sha(f"listener-{ordinal}"),
                event_classification_sha256=_sha(f"event-{ordinal}"),
                inspection_classification_sha256=_sha(f"inspection-{ordinal}"),
                transport_policy_sha256=relation.transport_policy_commitment_sha256,
                observation_signature_b64=_url(bytes(64)),
            )
        )
    bundle = c1.PerEdgeRuntimeProofBundleV1(
        schema="rsd.per-edge-runtime-proof-bundle.v1",
        bundle_version=1,
        non_authorizing=True,
        matrix_sha256=c0.target_delivery_field_matrix_v1_sha256(matrix),
        map_sha256=c0.target_delivery_map_sha256(delivery_map),
        manifest_sha256=c0.target_delivery_artifact_manifest_v2_sha256(manifest),
        c0_policy_sha256=c0.target_delivery_field_matrix_policy_v1_sha256(matrix_policy),
        source_snapshot_sha256=manifest.source.source_snapshot_sha256,
        c0_anchor_key_id=matrix_anchor.key_id,
        c0_anchor_fingerprint_sha256=matrix_anchor.public_key_fingerprint_sha256,
        c0_anchor_authority_identity_sha256=matrix_anchor.authority_identity_sha256,
        c0_anchor_independence_domain_sha256=matrix_anchor.independence_domain_identity_sha256,
        observer_root_id=anchor.observer_root_id,
        observer_key_id=anchor.observer_key_id,
        observer_fingerprint_sha256=anchor.observer_fingerprint_sha256,
        authority_identity_sha256=anchor.authority_identity_sha256,
        independence_domain_sha256=anchor.independence_domain_sha256,
        observed_at="2026-08-30T12:00:00Z",
        expires_at="2026-08-30T12:10:00Z",
        maximum_age_seconds=600,
        challenge_sha256=_sha("challenge"),
        session_sha256=_sha("session"),
        replay_identity_sha256=_sha("replay"),
        bundle_context_sha256=context,
        observations=cast(tuple[Any, Any, Any, Any], tuple(observations)),
        bundle_signature_b64=_url(bytes(64)),
    )
    return inputs, _policy(), anchor, _sign_bundle(bundle, private_key), private_key


def _validate(
    values: tuple[
        tuple[Any, ...],
        c1.PerEdgeRuntimeProofBundlePolicyV1,
        c1.PerEdgeRuntimeProofBundleTrustAnchorV1,
        c1.PerEdgeRuntimeProofBundleV1,
        Ed25519PrivateKey,
    ],
) -> c1.PerEdgeRuntimeProofBundleAcceptanceV1:
    inputs, policy, anchor, bundle, _private_key = values
    return c1.validate_per_edge_runtime_proof_bundle_v1(
        delivery_map=inputs[0],
        static_delivery_projection=inputs[1],
        b1_trust_policy=inputs[2],
        manifest_trust_anchor=inputs[3],
        role_inputs=inputs[4],
        v5_role_policy_inputs=inputs[5],
        manifest=inputs[6],
        matrix_policy=inputs[7],
        matrix_trust_anchor=inputs[8],
        matrix=inputs[9],
        bundle_policy=policy,
        bundle_trust_anchor=anchor,
        bundle=bundle,
    )


def test_validates_exact_c0_projection_and_returns_only_false_outcomes() -> None:
    values = _bundle()
    acceptance = _validate(values)
    bundle = values[3]

    assert acceptance.bundle_sha256 == c1.per_edge_runtime_proof_bundle_v1_sha256(bundle)
    assert acceptance.non_authorizing is True
    assert all(getattr(acceptance, field) is False for field in c1._CAPABILITIES)
    assert (
        acceptance.fresh,
        acceptance.replay_protected,
        acceptance.live_observed,
        acceptance.no_egress,
        acceptance.proof_passed,
        acceptance.ready,
    ) == (False, False, False, False, False, False)


def test_canonical_parse_hash_and_bundle_signature_domains_are_exact() -> None:
    _inputs, _policy_value, _anchor_value, bundle, _private_key = _bundle()
    payload = c1.canonical_per_edge_runtime_proof_bundle_v1_bytes(bundle)

    assert c1.parse_per_edge_runtime_proof_bundle_v1(payload) == bundle
    assert c1.canonical_per_edge_runtime_proof_bundle_v1_bytes(bundle) == payload
    assert c1.per_edge_runtime_proof_bundle_v1_signature_message(bundle).startswith(
        b"rsd.per-edge-runtime-proof-bundle-signature.v1\x00"
    )
    assert (
        c1.per_edge_runtime_proof_bundle_v1_sha256(bundle)
        == hashlib.sha256(
            b"rsd.per-edge-runtime-proof-bundle.commitment.v1\x00" + payload
        ).hexdigest()
    )
    rendered = json.loads(payload)
    assert "observer_public_key_b64" not in rendered
    assert rendered["observations"][0]["observation_signature_b64"] != ""


def test_binds_each_relation_row_lane_component_and_transport_policy() -> None:
    values = _bundle()
    inputs, policy, anchor, bundle, private_key = values
    changed = bundle.observations[0].model_copy(
        update={"c0_delivery_row_ordinal": 4, "derived_lane_ordinal": 2}
    )
    candidate = _sign_bundle(
        bundle.model_copy(update={"observations": (changed, *bundle.observations[1:])}), private_key
    )

    try:
        _validate((inputs, policy, anchor, candidate, private_key))
    except c1.PerEdgeRuntimeProofBundleError as error:
        assert error.phase == "bundle"
    else:
        raise AssertionError("non-bijective C0 relation projection was accepted")


def test_accepts_all_signed_transport_profile_listener_pairs_as_observer_assertions() -> None:
    inputs, policy, anchor, bundle, private_key = _bundle()
    pairs = (
        ("unpublished_loopback_or_network_v1", "isolated_network_only"),
        ("tls_verified_v1", "tls_lan"),
        ("unpublished_loopback_or_network_v1", "loopback_only"),
        ("tls_verified_v1", "tls_lan"),
    )
    observations = tuple(
        item.model_copy(update={"transport_profile": profile, "listener_binding_subtype": subtype})
        for item, (profile, subtype) in zip(bundle.observations, pairs, strict=True)
    )
    candidate = _sign_bundle(bundle.model_copy(update={"observations": observations}), private_key)

    acceptance = _validate((inputs, policy, anchor, candidate, private_key))

    assert acceptance.ready is False
    assert acceptance.live_observed is False


def test_revalidates_original_c0_inputs_without_acceptance_back_edge() -> None:
    inputs, policy, anchor, bundle, private_key = _bundle()
    altered_matrix = inputs[9].model_copy(update={"source_snapshot_sha256": _sha("substitution")})
    altered_inputs = (*inputs[:9], altered_matrix, inputs[10])

    try:
        _validate((altered_inputs, policy, anchor, bundle, private_key))
    except c1.PerEdgeRuntimeProofBundleError as error:
        assert error.phase == "input"
    else:
        raise AssertionError("substituted original C0 evidence was accepted")
