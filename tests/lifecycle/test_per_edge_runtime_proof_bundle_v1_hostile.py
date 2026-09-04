"""Hostile state and public-safety coverage for the C1 bundle grammar."""

from __future__ import annotations

import importlib.util
import itertools
import json
from pathlib import Path
from types import ModuleType
from typing import Any, cast

import pytest
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey
from pydantic import ValidationError

from omninode_rsd.lifecycle import per_edge_runtime_proof_bundle_v1 as c1
from omninode_rsd.lifecycle import provider_crypto
from omninode_rsd.lifecycle import target_delivery_field_matrix_v1 as c0


def _fixture() -> ModuleType:
    path = Path(__file__).with_name("test_per_edge_runtime_proof_bundle_v1.py")
    spec = importlib.util.spec_from_file_location("_runtime_proof_fixture", path)
    if spec is None or spec.loader is None:
        raise RuntimeError("runtime proof fixture is unavailable")
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    return module


def _values() -> tuple[Any, ...]:
    return cast(tuple[Any, ...], _fixture()._bundle())


def _assert_rejected(values: tuple[Any, ...], *, phase: str | None = None) -> None:
    with pytest.raises(c1.PerEdgeRuntimeProofBundleError) as error:
        _fixture()._validate(values)
    if phase is not None:
        assert error.value.phase == phase


def test_rejects_generic_containers_extra_state_and_scalar_coercion() -> None:
    inputs, policy, anchor, bundle, private_key = _values()
    for generic_value in (
        {"digest": bundle.matrix_sha256},
        [bundle.matrix_sha256],
        bundle.matrix_sha256.encode("ascii"),
    ):
        generic = bundle.model_copy(update={"matrix_sha256": generic_value})
        _assert_rejected((inputs, policy, anchor, generic, private_key), phase="bundle")

    generic_observations = bundle.model_copy(update={"observations": list(bundle.observations)})
    _assert_rejected((inputs, policy, anchor, generic_observations, private_key), phase="bundle")

    extra = bundle.model_copy()
    state = dict(extra.__dict__)
    state["unexpected"] = "value"
    object.__setattr__(extra, "__dict__", state)
    _assert_rejected((inputs, policy, anchor, extra, private_key), phase="bundle")

    coerced = bundle.model_copy(update={"maximum_age_seconds": "600"})
    _assert_rejected((inputs, policy, anchor, coerced, private_key), phase="bundle")


def test_rejects_duplicate_noncanonical_alias_and_oversize_json() -> None:
    _inputs, _policy, _anchor, bundle, _private_key = _values()
    payload = c1.canonical_per_edge_runtime_proof_bundle_v1_bytes(bundle)

    for hostile in (
        b'{"schema":"rsd.per-edge-runtime-proof-bundle.v1","schema":"duplicate"}',
        payload + b" ",
        payload.replace(b'"schema"', b'"schema_alias"', 1),
        b"{" + (b" " * (24 * 1024)) + b"}",
    ):
        with pytest.raises(c1.PerEdgeRuntimeProofBundleError) as error:
            c1.parse_per_edge_runtime_proof_bundle_v1(hostile)
        assert error.value.phase == "parse"


def test_rejects_cycles_hidden_state_and_oversized_models() -> None:
    inputs, policy, anchor, bundle, private_key = _values()
    cyclic = bundle.model_copy()
    object.__setattr__(cyclic, "observations", (cyclic, *bundle.observations[1:]))
    _assert_rejected((inputs, policy, anchor, cyclic, private_key), phase="bundle")

    hidden = bundle.model_copy()
    object.__setattr__(hidden, "__pydantic_private__", {"hidden": "state"})
    _assert_rejected((inputs, policy, anchor, hidden, private_key), phase="bundle")

    oversized = bundle.model_copy(update={"bundle_signature_b64": "a" * (24 * 1024)})
    _assert_rejected((inputs, policy, anchor, oversized, private_key), phase="bundle")


def test_rejects_transport_enum_subtype_and_calendar_substitutions() -> None:
    inputs, policy, anchor, bundle, private_key = _values()
    unknown = bundle.observations[0].model_copy(update={"transport_profile": "unknown_v1"})
    candidate = bundle.model_copy(update={"observations": (unknown, *bundle.observations[1:])})
    _assert_rejected((inputs, policy, anchor, candidate, private_key), phase="bundle")

    mismatch = bundle.observations[0].model_copy(
        update={"listener_binding_subtype": "loopback_only"}
    )
    candidate = bundle.model_copy(update={"observations": (mismatch, *bundle.observations[1:])})
    _assert_rejected((inputs, policy, anchor, candidate, private_key), phase="bundle")

    calendar = bundle.model_copy(update={"expires_at": "2026-08-30T11:59:59Z"})
    _assert_rejected((inputs, policy, anchor, calendar, private_key), phase="bundle")


def test_rejects_wrong_signature_domain_self_signer_and_mixed_context() -> None:
    fixture = _fixture()
    inputs, policy, anchor, bundle, private_key = _values()
    wrong_domain = bundle.observations[0].model_copy(
        update={"observation_signature_b64": bundle.bundle_signature_b64}
    )
    unsigned = bundle.model_copy(
        update={
            "observations": (wrong_domain, *bundle.observations[1:]),
            "bundle_signature_b64": fixture._url(bytes(64)),
        }
    )
    domain_candidate = unsigned.model_copy(
        update={
            "bundle_signature_b64": fixture._url(
                private_key.sign(c1.per_edge_runtime_proof_bundle_v1_signature_message(unsigned))
            )
        }
    )
    _assert_rejected((inputs, policy, anchor, domain_candidate, private_key), phase="bundle")

    self_signed = fixture._sign_bundle(bundle, Ed25519PrivateKey.generate())
    _assert_rejected((inputs, policy, anchor, self_signed, private_key), phase="bundle")

    mixed = bundle.observations[0].model_copy(update={"matrix_sha256": _fixture()._sha("mixed")})
    mixed_candidate = bundle.model_copy(update={"observations": (mixed, *bundle.observations[1:])})
    _assert_rejected((inputs, policy, anchor, mixed_candidate, private_key), phase="bundle")


def test_rejects_back_edges_identity_collisions_and_true_effect_vectors() -> None:
    fixture = _fixture()
    inputs, policy, anchor, bundle, private_key = _values()
    reverse = bundle.observations[0].model_copy(
        update={"dependency_classification": "primary_valkey"}
    )
    reverse_candidate = fixture._sign_bundle(
        bundle.model_copy(update={"observations": (reverse, *bundle.observations[1:])}), private_key
    )
    _assert_rejected((inputs, policy, anchor, reverse_candidate, private_key), phase="bundle")

    colliding_anchor = anchor.model_copy(update={"observer_key_id": inputs[8].key_id})
    colliding_observations = tuple(
        item.model_copy(update={"observer_key_id": colliding_anchor.observer_key_id})
        for item in bundle.observations
    )
    collision = fixture._sign_bundle(
        bundle.model_copy(
            update={
                "observer_key_id": colliding_anchor.observer_key_id,
                "observations": colliding_observations,
            }
        ),
        private_key,
    )
    _assert_rejected((inputs, policy, colliding_anchor, collision, private_key), phase="bundle")

    with pytest.raises(ValidationError):
        c1.PerEdgeRuntimeProofBundleAcceptanceV1(
            schema="rsd.per-edge-runtime-proof-bundle-acceptance.v1",
            acceptance_version=1,
            bundle_sha256="0" * 64,
            non_authorizing=True,
            delivery_authorized=True,
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


def test_rejects_noncanonical_observer_material_and_raw_extra_fields() -> None:
    fixture = _fixture()
    inputs, policy, anchor, bundle, private_key = _values()
    with pytest.raises(ValidationError):
        c1.PerEdgeRuntimeProofBundleTrustAnchorV1(
            schema="rsd.per-edge-runtime-proof-bundle-trust-anchor.v1",
            signature_algorithm="ed25519",
            observer_root_id="runtime-proof-observer-root",
            observer_key_id="runtime-proof-observer-key",
            observer_public_key_b64=anchor.observer_public_key_b64 + "=",
            observer_fingerprint_sha256=anchor.observer_fingerprint_sha256,
            authority_identity_sha256=anchor.authority_identity_sha256,
            independence_domain_sha256=anchor.independence_domain_sha256,
        )

    payload = c1.canonical_per_edge_runtime_proof_bundle_v1_bytes(bundle)
    for field in ("material_policy", "provider_value", "host", "uri", "effect_callback"):
        hostile = payload[:-1] + f',"{field}":"forbidden"}}'.encode("ascii")
        with pytest.raises(c1.PerEdgeRuntimeProofBundleError) as error:
            c1.parse_per_edge_runtime_proof_bundle_v1(hostile)
        assert error.value.phase == "parse"

    assert not hasattr(c1, "parse_per_edge_runtime_proof_observation_v1")
    assert not hasattr(c1, "validate_per_edge_runtime_proof_observation_v1")
    assert fixture._validate((inputs, policy, anchor, bundle, private_key)).ready is False


def test_normalizes_extreme_utc_overflow_to_public_error_phases() -> None:
    inputs, policy, anchor, bundle, private_key = _values()
    observations = tuple(
        item.model_copy(update={"bundle_context_sha256": "0" * 64}) for item in bundle.observations
    )
    extreme = bundle.model_copy(
        update={
            "observed_at": "9999-12-31T23:59:58Z",
            "expires_at": "9999-12-31T23:59:59Z",
            "maximum_age_seconds": 3,
            "bundle_context_sha256": "0" * 64,
            "observations": observations,
        }
    )

    for callback in (
        lambda: c1.canonical_per_edge_runtime_proof_bundle_v1_bytes(extreme),
        lambda: c1.per_edge_runtime_proof_bundle_v1_signature_message(extreme),
        lambda: c1.per_edge_runtime_proof_bundle_v1_sha256(extreme),
    ):
        with pytest.raises(c1.PerEdgeRuntimeProofBundleError) as error:
            callback()
        assert error.value.phase == "bundle"

    payload = json.dumps(
        extreme.model_dump(mode="json"),
        sort_keys=True,
        separators=(",", ":"),
    ).encode("ascii")
    with pytest.raises(c1.PerEdgeRuntimeProofBundleError) as error:
        c1.parse_per_edge_runtime_proof_bundle_v1(payload)
    assert error.value.phase == "parse"
    _assert_rejected((inputs, policy, anchor, extreme, private_key), phase="bundle")


def test_rejects_oversized_in_memory_observation_tuple_before_serialization() -> None:
    inputs, policy, anchor, bundle, private_key = _values()
    oversized = bundle.model_copy(update={"observations": bundle.observations * 125_000})

    with pytest.raises(c1.PerEdgeRuntimeProofBundleError) as error:
        c1.canonical_per_edge_runtime_proof_bundle_v1_bytes(oversized)
    assert error.value.phase == "bundle"
    _assert_rejected((inputs, policy, anchor, oversized, private_key), phase="bundle")


def test_rejects_every_observer_identity_collision_and_cross_c0_namespace_sharing() -> None:
    fixture = _fixture()
    inputs, policy, anchor, bundle, private_key = _values()
    identity_fields = (
        "observer_root_id",
        "observer_key_id",
        "observer_fingerprint_sha256",
        "authority_identity_sha256",
        "independence_domain_sha256",
    )
    for source, target in itertools.combinations(identity_fields, 2):
        raw = anchor.model_dump(mode="python")
        raw[target] = raw[source]
        with pytest.raises(ValidationError):
            c1.PerEdgeRuntimeProofBundleTrustAnchorV1(**raw)

    protected_root = inputs[0].provider_references.encryption_key.reference_sha256
    colliding_anchor = anchor.model_copy(update={"observer_root_id": protected_root})
    observations = tuple(
        item.model_copy(update={"observer_root_id": protected_root}) for item in bundle.observations
    )
    collision = fixture._sign_bundle(
        bundle.model_copy(
            update={"observer_root_id": protected_root, "observations": observations}
        ),
        private_key,
    )
    _assert_rejected((inputs, policy, colliding_anchor, collision, private_key), phase="bundle")


def test_rejects_unpadded_base64url_fingerprint_mismatch_and_provider_crypto_model() -> None:
    _inputs, _policy, anchor, bundle, _private_key = _values()
    raw = anchor.model_dump(mode="python")
    malformed = (
        anchor.observer_public_key_b64 + "=",
        anchor.observer_public_key_b64[:-1],
        "+" + anchor.observer_public_key_b64[1:],
        " " + anchor.observer_public_key_b64[1:],
    )
    for public_key in malformed:
        raw["observer_public_key_b64"] = public_key
        with pytest.raises(ValidationError):
            c1.PerEdgeRuntimeProofBundleTrustAnchorV1(**raw)

    raw["observer_public_key_b64"] = anchor.observer_public_key_b64
    raw["observer_fingerprint_sha256"] = "0" * 64
    with pytest.raises(ValidationError):
        c1.PerEdgeRuntimeProofBundleTrustAnchorV1(**raw)

    foreign_policy = provider_crypto.ProviderMaterialPolicyV2.model_construct()
    foreign = bundle.model_copy(update={"matrix_sha256": foreign_policy})
    with pytest.raises(c1.PerEdgeRuntimeProofBundleError) as error:
        c1.canonical_per_edge_runtime_proof_bundle_v1_bytes(foreign)
    assert error.value.phase == "bundle"


def test_rejects_c0_and_b2_acceptance_back_edges_by_signature() -> None:
    inputs, policy, anchor, bundle, _private_key = _values()
    c0_acceptance = c0.validate_target_delivery_field_matrix_v1(
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
    )
    b2_acceptance = c0.validate_target_delivery_artifact_manifest_v2(
        delivery_map=inputs[0],
        static_delivery_projection=inputs[1],
        b1_trust_policy=inputs[2],
        manifest_trust_anchor=inputs[3],
        role_inputs=inputs[4],
        v5_role_policy_inputs=inputs[5],
        manifest=inputs[6],
    )
    arguments = {
        "delivery_map": inputs[0],
        "static_delivery_projection": inputs[1],
        "b1_trust_policy": inputs[2],
        "manifest_trust_anchor": inputs[3],
        "role_inputs": inputs[4],
        "v5_role_policy_inputs": inputs[5],
        "manifest": inputs[6],
        "matrix_policy": inputs[7],
        "matrix_trust_anchor": inputs[8],
        "matrix": inputs[9],
        "bundle_policy": policy,
        "bundle_trust_anchor": anchor,
        "bundle": bundle,
    }
    for name, acceptance in (("c0_acceptance", c0_acceptance), ("b2_acceptance", b2_acceptance)):
        with pytest.raises(TypeError):
            c1.validate_per_edge_runtime_proof_bundle_v1(**arguments, **{name: acceptance})


def test_normalizes_fields_set_eq_bomb_without_comparing_subclass_metadata() -> None:
    class EqBomb(str):
        __hash__ = str.__hash__

        def __eq__(self, other: object) -> bool:
            raise RuntimeError("fields-set equality must not execute")

    inputs, policy, anchor, bundle, private_key = _values()
    poisoned = bundle.model_copy()
    fields_set = set(poisoned.__pydantic_fields_set__)
    field = next(iter(fields_set))
    fields_set.remove(field)
    fields_set.add(EqBomb(field))
    object.__setattr__(poisoned, "__pydantic_fields_set__", fields_set)

    for callback in (
        lambda: c1.canonical_per_edge_runtime_proof_bundle_v1_bytes(poisoned),
        lambda: c1.per_edge_runtime_proof_bundle_v1_signature_message(poisoned),
        lambda: c1.per_edge_runtime_proof_bundle_v1_sha256(poisoned),
    ):
        with pytest.raises(c1.PerEdgeRuntimeProofBundleError) as error:
            callback()
        assert error.value.phase == "bundle"
    _assert_rejected((inputs, policy, anchor, poisoned, private_key), phase="bundle")
