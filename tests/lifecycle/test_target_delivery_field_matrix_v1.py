"""Adversarial coverage for the public, opaque field-delivery matrix."""

from __future__ import annotations

import base64
import hashlib
import importlib.util
import json
from pathlib import Path
from typing import Any, cast

import pytest
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey
from pydantic import ValidationError

from omninode_rsd.lifecycle import target_delivery_field_matrix_v1 as matrix_v1


def _sha(label: str) -> str:
    return hashlib.sha256(label.encode("ascii")).hexdigest()


def _b2_fixture() -> Any:
    path = Path(__file__).with_name("test_target_delivery_artifact_manifest_v2.py")
    spec = importlib.util.spec_from_file_location("_field_matrix_b2_fixture", path)
    if spec is None or spec.loader is None:
        raise RuntimeError("B2 fixture is unavailable")
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    return module


def _anchor() -> tuple[matrix_v1.TargetDeliveryFieldMatrixTrustAnchorV1, Ed25519PrivateKey]:
    private_key = Ed25519PrivateKey.generate()
    public_key = private_key.public_key().public_bytes_raw()
    return (
        matrix_v1.TargetDeliveryFieldMatrixTrustAnchorV1(
            schema_version="rsd.target-delivery-field-matrix-trust-anchor.v1",
            key_id="field-matrix-root",
            public_key_base64=base64.b64encode(public_key).decode("ascii"),
            public_key_fingerprint_sha256=hashlib.sha256(public_key).hexdigest(),
            authority_identity_sha256=_sha("field-matrix-authority"),
            independence_domain_identity_sha256=_sha("field-matrix-domain"),
            algorithm="ed25519",
        ),
        private_key,
    )


def _policy() -> matrix_v1.TargetDeliveryFieldMatrixPolicyV1:
    return matrix_v1.TargetDeliveryFieldMatrixPolicyV1(
        schema_version="rsd.target-delivery-field-matrix-policy.v1",
        policy_id="field-matrix-policy",
        policy_identity_sha256=_sha("field-matrix-policy-identity"),
        reference_authority_identity_sha256=_sha("field-matrix-reference-authority"),
        topology_authority_identity_sha256=_sha("field-matrix-topology-authority"),
    )


def _resign(
    value: matrix_v1.TargetDeliveryFieldMatrixV1,
    private_key: Ed25519PrivateKey,
) -> matrix_v1.TargetDeliveryFieldMatrixV1:
    canonical = matrix_v1.TargetDeliveryFieldMatrixV1.model_validate(
        value.model_dump(mode="python"), strict=True
    )
    return canonical.model_copy(
        update={
            "signature_base64": base64.b64encode(
                private_key.sign(matrix_v1.target_delivery_field_matrix_v1_message(canonical))
            ).decode("ascii")
        }
    )


def _replace_relation(
    value: matrix_v1.ApplicationDependencyRelationV1, **changes: object
) -> matrix_v1.ApplicationDependencyRelationV1:
    raw = value.model_dump(mode="python")
    raw.update(changes)
    raw.pop("relation_commitment_sha256")
    payload = matrix_v1._ApplicationDependencyRelationCommitmentPayloadV1.model_validate(
        raw,
        strict=True,
    )
    return matrix_v1._application_dependency_relation_from_payload(payload)


def _inputs() -> tuple[Any, ...]:
    fixture = _b2_fixture()
    (
        delivery_map,
        projection,
        b1_policy,
        manifest_anchor,
        role_inputs,
        policy_inputs,
        manifest,
        _,
    ) = fixture._signed_artifacts()
    matrix_anchor, private_key = _anchor()
    matrix_policy = _policy()
    rows = matrix_v1._expected_rows(delivery_map)
    dependencies = matrix_v1._expected_dependencies(delivery_map, rows)
    draft = matrix_v1.TargetDeliveryFieldMatrixV1(
        schema_version="rsd.target-delivery-field-matrix.v1",
        signature_algorithm="ed25519",
        matrix_policy_sha256=matrix_v1.target_delivery_field_matrix_policy_v1_sha256(matrix_policy),
        target_delivery_map_sha256=matrix_v1.target_delivery_map_sha256(delivery_map),
        static_delivery_projection_sha256=manifest.static_delivery_projection_sha256,
        target_delivery_artifact_manifest_sha256=(
            matrix_v1.target_delivery_artifact_manifest_v2_sha256(manifest)
        ),
        source_snapshot_sha256=manifest.source.source_snapshot_sha256,
        oci_repository_sha256=_sha(manifest.derived_oci_repository),
        topology_commitment_sha256=matrix_v1._topology_commitment(delivery_map),
        rows=rows,
        application_dependencies=dependencies,
        signer_key_id=matrix_anchor.key_id,
        signer_fingerprint_sha256=matrix_anchor.public_key_fingerprint_sha256,
        signature_base64=base64.b64encode(bytes(64)).decode("ascii"),
        non_authorizing=True,
        delivery_allowed=False,
        network_allowed=False,
        build_allowed=False,
        pull_allowed=False,
        materialization_allowed=False,
        attach_allowed=False,
        effect_allowed=False,
    )
    return (
        delivery_map,
        projection,
        b1_policy,
        manifest_anchor,
        role_inputs,
        policy_inputs,
        manifest,
        matrix_policy,
        matrix_anchor,
        _resign(draft, private_key),
        private_key,
    )


def _validate(values: tuple[Any, ...]) -> matrix_v1.TargetDeliveryFieldMatrixAcceptanceV1:
    (
        delivery_map,
        projection,
        b1_policy,
        manifest_anchor,
        role_inputs,
        policy_inputs,
        manifest,
        matrix_policy,
        matrix_anchor,
        signed,
        _private_key,
    ) = values
    return matrix_v1.validate_target_delivery_field_matrix_v1(
        delivery_map=delivery_map,
        static_delivery_projection=projection,
        b1_trust_policy=b1_policy,
        manifest_trust_anchor=manifest_anchor,
        role_inputs=role_inputs,
        v5_role_policy_inputs=policy_inputs,
        manifest=manifest,
        matrix_policy=matrix_policy,
        matrix_trust_anchor=matrix_anchor,
        matrix=signed,
    )


def _with_matrix(
    values: tuple[Any, ...], replacement: matrix_v1.TargetDeliveryFieldMatrixV1
) -> tuple[Any, ...]:
    return (*values[:-2], replacement, values[-1])


def _resign_for_policy(
    values: tuple[Any, ...], policy: matrix_v1.TargetDeliveryFieldMatrixPolicyV1
) -> matrix_v1.TargetDeliveryFieldMatrixV1:
    signed = cast(matrix_v1.TargetDeliveryFieldMatrixV1, values[-2])
    private_key = cast(Ed25519PrivateKey, values[-1])
    return _resign(
        signed.model_copy(
            update={
                "matrix_policy_sha256": matrix_v1.target_delivery_field_matrix_policy_v1_sha256(
                    policy
                )
            }
        ),
        private_key,
    )


def _with_policy(
    values: tuple[Any, ...],
    policy: matrix_v1.TargetDeliveryFieldMatrixPolicyV1,
    matrix: matrix_v1.TargetDeliveryFieldMatrixV1,
) -> tuple[Any, ...]:
    return (*values[:7], policy, values[8], matrix, values[-1])


def _assert_failure(values: tuple[Any, ...], *, phase: str) -> None:
    with pytest.raises(matrix_v1.TargetDeliveryFieldMatrixError) as error:
        _validate(values)
    assert error.value.phase == phase
    assert str(error.value) == "target delivery field matrix validation failed"


def _assert_fragment_failure(callback: Any) -> None:
    with pytest.raises(matrix_v1.TargetDeliveryFieldMatrixError) as error:
        callback()
    assert error.value.phase == "matrix"
    assert str(error.value) == "target delivery field matrix validation failed"


def _assert_original_b2_valid(values: tuple[Any, ...]) -> None:
    (
        delivery_map,
        projection,
        b1_policy,
        manifest_anchor,
        role_inputs,
        policy_inputs,
        manifest,
        *_rest,
    ) = values
    acceptance = matrix_v1.validate_target_delivery_artifact_manifest_v2(
        delivery_map=delivery_map,
        static_delivery_projection=projection,
        b1_trust_policy=b1_policy,
        manifest_trust_anchor=manifest_anchor,
        role_inputs=role_inputs,
        v5_role_policy_inputs=policy_inputs,
        manifest=manifest,
    )
    assert acceptance.non_authorizing is True


def test_projects_exact_ten_rows_and_four_application_dependencies() -> None:
    values = _inputs()
    acceptance = _validate(values)
    signed = cast(matrix_v1.TargetDeliveryFieldMatrixV1, values[-2])

    assert tuple(row.ordinal for row in signed.rows) == tuple(range(1, 11))
    assert tuple(row.lane for row in signed.rows) == (
        "primary",
        "primary",
        "primary",
        "primary",
        "primary",
        "restore",
        "restore",
        "restore",
        "restore",
        "restore",
    )
    assert tuple(row.target_field for row in signed.rows) == (
        "ENCRYPTION_KEY",
        "AUTH_SECRET",
        "DB_CONNECTION_URI",
        "REDIS_URL",
        "requirepass",
        "ENCRYPTION_KEY",
        "AUTH_SECRET",
        "DB_CONNECTION_URI",
        "REDIS_URL",
        "requirepass",
    )
    assert tuple(row.source_kind for row in signed.rows) == (
        "direct_provider_material_v1",
        "direct_provider_material_v1",
        "derived_connection_payload_v1",
        "derived_connection_payload_v1",
        "direct_provider_material_v1",
        "direct_provider_material_v1",
        "direct_provider_material_v1",
        "derived_connection_payload_v1",
        "derived_connection_payload_v1",
        "direct_provider_material_v1",
    )
    assert signed.rows[2].derivation is not None
    assert (
        signed.rows[2].derivation.source_material_policy.purpose == "postgres_application_password"
    )
    assert signed.rows[3].derivation is not None
    assert signed.rows[3].derivation.source_material_policy.purpose == "primary_valkey_password"
    assert tuple(relation.dependency for relation in signed.application_dependencies) == (
        "primary_postgresql",
        "primary_valkey",
        "restore_postgresql",
        "restore_valkey",
    )
    assert all(
        relation.relation_commitment_sha256 != "0" * 64
        for relation in signed.application_dependencies
    )
    assert (
        tuple(relation.edge_transport_declaration for relation in signed.application_dependencies)
        == ("per_edge_runtime_proof_required_v1",) * 4
    )
    assert len(acceptance.row_sha256s) == 10
    assert acceptance.application_dependency_ordinals == (1, 2, 3, 4)
    assert (
        acceptance.non_authorizing,
        acceptance.delivery_allowed,
        acceptance.network_allowed,
        acceptance.build_allowed,
        acceptance.pull_allowed,
        acceptance.materialization_allowed,
        acceptance.attach_allowed,
        acceptance.effect_allowed,
    ) == (True, False, False, False, False, False, False, False)


def test_fragments_have_no_standalone_public_hash_authority() -> None:
    assert not hasattr(matrix_v1, "target_delivery_field_matrix_row_v1_sha256")
    assert not hasattr(matrix_v1, "application_dependency_relation_v1_sha256")


def test_shape_helpers_do_not_bind_original_evidence_or_authorize() -> None:
    values = _inputs()
    _assert_original_b2_valid(values)
    signed = cast(matrix_v1.TargetDeliveryFieldMatrixV1, values[-2])
    private_key = cast(Ed25519PrivateKey, values[-1])
    top_level_substitution = _resign(
        signed.model_copy(update={"source_snapshot_sha256": _sha("substituted-snapshot")}),
        private_key,
    )
    row_substitution = _resign(
        signed.model_copy(
            update={
                "rows": (
                    signed.rows[0].model_copy(
                        update={"route_commitment_sha256": _sha("substituted-route")}
                    ),
                    *signed.rows[1:],
                )
            }
        ),
        private_key,
    )

    for substituted in (top_level_substitution, row_substitution):
        canonical = matrix_v1.target_delivery_field_matrix_v1_canonical_json(substituted)
        assert (
            matrix_v1.parse_target_delivery_field_matrix_v1_canonical_json(canonical) == substituted
        )
        assert matrix_v1.target_delivery_field_matrix_v1_message(substituted)
        assert len(matrix_v1.target_delivery_field_matrix_v1_sha256(substituted)) == 64
        _assert_failure(_with_matrix(values, substituted), phase="matrix")


def test_shape_helpers_and_acceptance_have_no_production_authority_consumer() -> None:
    module_path = Path(matrix_v1.__file__).resolve()
    package_root = module_path.parents[1]
    authority_surface = {
        "TargetDeliveryFieldMatrixAcceptanceV1",
        "target_delivery_field_matrix_v1_canonical_json",
        "target_delivery_field_matrix_v1_message",
        "target_delivery_field_matrix_v1_sha256",
    }
    for source_path in package_root.rglob("*.py"):
        if source_path.resolve() != module_path:
            source = source_path.read_text(encoding="utf-8")
            assert not any(name in source for name in authority_surface)


def test_rejects_zero_relation_commitment_at_every_authority_boundary() -> None:
    values = _inputs()
    signed = cast(matrix_v1.TargetDeliveryFieldMatrixV1, values[-2])
    relation = signed.application_dependencies[0]
    raw_relation = relation.model_dump(mode="python")
    raw_relation["relation_commitment_sha256"] = "0" * 64
    with pytest.raises(ValidationError):
        matrix_v1.ApplicationDependencyRelationV1.model_validate(raw_relation, strict=True)

    zero_relation = relation.model_copy(update={"relation_commitment_sha256": "0" * 64})
    with pytest.raises(ValueError, match="application dependency relation is invalid"):
        zero_relation.exact_shape()

    zero_matrix = signed.model_copy(
        update={"application_dependencies": (zero_relation, *signed.application_dependencies[1:])}
    )
    with pytest.raises(ValueError, match="field matrix is invalid"):
        zero_matrix.exact_shape()
    serialized = json.dumps(
        zero_matrix.model_dump(mode="json"),
        ensure_ascii=True,
        sort_keys=True,
        separators=(",", ":"),
        allow_nan=False,
    ).encode("ascii")
    with pytest.raises(matrix_v1.TargetDeliveryFieldMatrixError) as error:
        matrix_v1.parse_target_delivery_field_matrix_v1_canonical_json(serialized)
    assert error.value.phase == "parse"
    assert str(error.value) == "target delivery field matrix validation failed"
    for callback in (
        matrix_v1.target_delivery_field_matrix_v1_canonical_json,
        matrix_v1.target_delivery_field_matrix_v1_message,
        matrix_v1.target_delivery_field_matrix_v1_sha256,
    ):
        _assert_fragment_failure(lambda callback=callback: callback(zero_matrix))


@pytest.mark.parametrize(
    "attribute,value",
    (
        ("lane", "restore"),
        ("target_component", "restore_infisical"),
        ("target_field", "AUTH_SECRET"),
        ("sink", "valkey_stdin_configuration_v1"),
        ("shared_reference_group", "auth_secret_primary_restore_v1"),
    ),
)
def test_rejects_model_copy_row_lane_role_field_sink_and_group_mutations(
    attribute: str, value: object
) -> None:
    values = _inputs()
    signed = cast(matrix_v1.TargetDeliveryFieldMatrixV1, values[-2])
    changed_row = signed.rows[0].model_copy(update={attribute: value})
    changed = signed.model_copy(update={"rows": (changed_row, *signed.rows[1:])})
    _assert_fragment_failure(
        lambda: matrix_v1._target_delivery_field_matrix_row_v1_sha256(changed_row)
    )
    _assert_fragment_failure(
        lambda: matrix_v1.target_delivery_field_matrix_v1_canonical_json(changed)
    )


def test_rejects_resigned_reference_and_derivation_mutations() -> None:
    values = _inputs()
    signed = cast(matrix_v1.TargetDeliveryFieldMatrixV1, values[-2])
    private_key = cast(Ed25519PrivateKey, values[-1])
    direct_policy = cast(matrix_v1.ProviderMaterialPolicyV2, signed.rows[0].material_policy)
    changed_direct = signed.rows[0].model_copy(
        update={
            "material_policy": direct_policy.model_copy(update={"reference_sha256": _sha("other")})
        }
    )
    direct_matrix = signed.model_copy(update={"rows": (changed_direct, *signed.rows[1:])})
    _assert_failure(_with_matrix(values, _resign(direct_matrix, private_key)), phase="anchor")

    changed_purpose = signed.rows[0].model_copy(
        update={"material_policy": signed.rows[1].material_policy}
    )
    _assert_fragment_failure(
        lambda: matrix_v1._target_delivery_field_matrix_row_v1_sha256(changed_purpose)
    )

    derivation = cast(matrix_v1.TargetDeliveryFieldDerivationV1, signed.rows[2].derivation)
    changed_derived = signed.rows[2].model_copy(
        update={"derivation": derivation.model_copy(update={"authority_sha256": _sha("other")})}
    )
    changed_relation = _replace_relation(
        signed.application_dependencies[0],
        initiator_delivery_row_sha256=matrix_v1._target_delivery_field_matrix_row_v1_sha256(
            changed_derived
        ),
    )
    derived_matrix = signed.model_copy(
        update={
            "rows": (*signed.rows[:2], changed_derived, *signed.rows[3:]),
            "application_dependencies": (changed_relation, *signed.application_dependencies[1:]),
        }
    )
    _assert_failure(_with_matrix(values, _resign(derived_matrix, private_key)), phase="matrix")

    changed_value_kind = signed.rows[2].model_copy(
        update={"value_kind": matrix_v1.TargetDeliveryValueKindV1.DERIVED_VALKEY_URI}
    )
    value_kind_matrix = signed.model_copy(
        update={"rows": (*signed.rows[:2], changed_value_kind, *signed.rows[3:])}
    )
    _assert_fragment_failure(
        lambda: matrix_v1.target_delivery_field_matrix_v1_canonical_json(value_kind_matrix)
    )


@pytest.mark.parametrize(
    "changes",
    (
        {"ordinal": 2},
        {"dependency": "primary_valkey", "dependency_role": "valkey"},
        {"lane": "restore", "initiator_component": "restore_infisical"},
    ),
)
def test_rejects_model_copy_reverse_and_cross_lane_dependency_fragments(
    changes: dict[str, object],
) -> None:
    values = _inputs()
    signed = cast(matrix_v1.TargetDeliveryFieldMatrixV1, values[-2])
    changed = signed.application_dependencies[0].model_copy(update=changes)
    _assert_fragment_failure(lambda: matrix_v1._application_dependency_relation_v1_sha256(changed))


def test_rejects_direct_database_row_and_wrong_dependency_row_binding() -> None:
    values = _inputs()
    signed = cast(matrix_v1.TargetDeliveryFieldMatrixV1, values[-2])
    database = signed.rows[2]
    derivation = cast(matrix_v1.TargetDeliveryFieldDerivationV1, database.derivation)
    direct_database = database.model_copy(
        update={
            "source_kind": "direct_provider_material_v1",
            "value_kind": matrix_v1.TargetDeliveryValueKindV1.DIRECT_PROVIDER_MATERIAL,
            "material_policy": derivation.source_material_policy,
            "derivation": None,
        }
    )
    _assert_fragment_failure(
        lambda: matrix_v1._target_delivery_field_matrix_row_v1_sha256(direct_database)
    )

    wrong_binding = _replace_relation(
        signed.application_dependencies[0],
        initiator_delivery_row_sha256=matrix_v1._target_delivery_field_matrix_row_v1_sha256(
            signed.rows[3]
        ),
    )
    changed = signed.model_copy(
        update={"application_dependencies": (wrong_binding, *signed.application_dependencies[1:])}
    )
    _assert_fragment_failure(lambda: matrix_v1.target_delivery_field_matrix_v1_message(changed))

    duplicate = signed.model_copy(
        update={
            "application_dependencies": (
                signed.application_dependencies[0],
                signed.application_dependencies[0],
                *signed.application_dependencies[2:],
            )
        }
    )
    _assert_fragment_failure(lambda: matrix_v1.target_delivery_field_matrix_v1_sha256(duplicate))


def test_schema_rejects_missing_extra_and_raw_sensitive_injection() -> None:
    values = _inputs()
    signed = cast(matrix_v1.TargetDeliveryFieldMatrixV1, values[-2])
    raw = signed.model_dump(mode="python")
    with pytest.raises(ValidationError):
        matrix_v1.TargetDeliveryFieldMatrixV1.model_validate(
            {**raw, "application_dependencies": raw["application_dependencies"][:-1]}
        )
    with pytest.raises(ValidationError):
        matrix_v1.TargetDeliveryFieldMatrixV1.model_validate(
            {
                **raw,
                "application_dependencies": (
                    *raw["application_dependencies"],
                    raw["application_dependencies"][0],
                ),
            }
        )
    with pytest.raises(ValidationError):
        matrix_v1.ProviderMaterialPolicyV2.model_validate(
            {
                **cast(dict[str, object], raw["rows"][0]["material_policy"]),
                "provider": "forbidden-provider",
            }
        )
    forbidden = {"provider", "service", "account", "authority", "uri", "host", "port", "endpoint"}
    for model in (
        matrix_v1.ProviderMaterialPolicyV2,
        matrix_v1.TargetDeliveryFieldMatrixRowV1,
        matrix_v1.TargetDeliveryFieldDerivationV1,
        matrix_v1.ApplicationDependencyRelationV1,
        matrix_v1.TargetDeliveryFieldMatrixV1,
    ):
        assert not (set(model.model_fields) & forbidden)


def test_forbids_global_transport_freshness_and_runtime_surface() -> None:
    fields = set(matrix_v1.TargetDeliveryFieldMatrixV1.model_fields)
    relation_fields = set(matrix_v1.ApplicationDependencyRelationV1.model_fields)
    forbidden = {
        "tls",
        "no_egress",
        "freshness",
        "timestamp",
        "nonce",
        "expiry",
        "runtime_id",
        "callback",
    }
    assert not (fields & forbidden)
    assert not (relation_fields & forbidden)
    assert "edge_transport_declaration" in relation_fields
    assert "transport_policy_commitment_sha256" in relation_fields
    assert "transport_profile" not in relation_fields


def test_revalidates_original_b2_inputs_and_rejects_substitution() -> None:
    values = _inputs()
    _validate(values)
    bad_manifest = cast(Any, values[6]).model_copy(
        update={"signature_base64": base64.b64encode(bytes(64)).decode("ascii")}
    )
    _assert_failure((*values[:6], bad_manifest, *values[7:]), phase="input")

    bad_role = cast(Any, values[4])[0].model_copy()
    object.__setattr__(bad_role, "phase_a_v5_closure", bad_role)
    bad_roles = cast(tuple[Any, Any, Any, Any], (bad_role, *cast(Any, values[4])[1:]))
    _assert_failure((*values[:4], bad_roles, *values[5:]), phase="input")

    bad_map = cast(Any, values[0]).model_copy(update={"source_commit": "0" * 40})
    _assert_failure((bad_map, *values[1:]), phase="input")


def test_rejects_non_exact_c0_and_upstream_model_copy_scalars_before_b2() -> None:
    values = _inputs()
    signed = cast(matrix_v1.TargetDeliveryFieldMatrixV1, values[-2])
    c0_bool_as_int = signed.model_copy(update={"non_authorizing": 1})
    _assert_failure(_with_matrix(values, c0_bool_as_int), phase="anchor")

    projection_bool_as_int = values[1].model_copy(update={"generated_wrapper_output_bound": 0})
    _assert_failure(
        (values[0], projection_bool_as_int, *values[2:]),
        phase="input",
    )

    original_map = values[0]
    original_route = original_map.primary_infisical
    float_field = original_route.fields[0].model_copy(update={"encoded_byte_count": 43.0})
    float_route = original_route.model_copy(
        update={"fields": (float_field, *original_route.fields[1:])}
    )
    float_map = original_map.model_copy(update={"primary_infisical": float_route})
    _assert_failure((float_map, *values[1:]), phase="input")

    list_route = original_route.model_copy(update={"fields": list(original_route.fields)})
    list_map = original_map.model_copy(update={"primary_infisical": list_route})
    _assert_failure((list_map, *values[1:]), phase="input")

    enum_as_string = original_route.fields[0].model_copy(
        update={"value_kind": original_route.fields[0].value_kind.value}
    )
    enum_route = original_route.model_copy(
        update={"fields": (enum_as_string, *original_route.fields[1:])}
    )
    enum_map = original_map.model_copy(update={"primary_infisical": enum_route})
    _assert_failure((enum_map, *values[1:]), phase="input")

    class DerivedRow(matrix_v1.TargetDeliveryFieldMatrixRowV1):
        pass

    subclass_row = DerivedRow.model_validate(signed.rows[0].model_dump(mode="python"), strict=True)
    subclass_matrix = signed.model_copy(update={"rows": (subclass_row, *signed.rows[1:])})
    _assert_failure(_with_matrix(values, subclass_matrix), phase="anchor")


def test_rejects_wrong_c0_b2_and_b1_roots_or_policies() -> None:
    values = _inputs()
    wrong_matrix_anchor, _ = _anchor()
    _assert_failure((*values[:8], wrong_matrix_anchor, *values[9:]), phase="matrix")

    wrong_matrix_policy = matrix_v1.TargetDeliveryFieldMatrixPolicyV1(
        schema_version="rsd.target-delivery-field-matrix-policy.v1",
        policy_id="other-field-matrix-policy",
        policy_identity_sha256=_sha("other-field-matrix-policy-identity"),
        reference_authority_identity_sha256=_sha("other-field-matrix-reference-authority"),
        topology_authority_identity_sha256=_sha("other-field-matrix-topology-authority"),
    )
    _assert_failure((*values[:7], wrong_matrix_policy, *values[8:]), phase="matrix")

    fixture = _b2_fixture()
    wrong_b2_anchor, _ = fixture._new_manifest_anchor()
    _assert_failure((*values[:3], wrong_b2_anchor, *values[4:]), phase="input")

    wrong_b1_policy = cast(Any, values[2]).model_copy(update={"policy_id": "other-b1-policy"})
    _assert_failure((*values[:2], wrong_b1_policy, *values[3:]), phase="input")


@pytest.mark.parametrize(
    ("field", "identity"),
    (
        (
            "policy_identity_sha256",
            lambda values: (
                values[5][0]
                .worker_trust_policy.worker_trust_anchors[0]
                .physical_builder_identity_sha256
            ),
        ),
        (
            "reference_authority_identity_sha256",
            lambda values: (
                values[4][
                    0
                ].profile_envelope.static_role_profile.ticket_trust_anchor.public_key_fingerprint_sha256
            ),
        ),
        (
            "reference_authority_identity_sha256",
            lambda values: (
                values[4][
                    0
                ].profile_envelope.static_role_profile.replay_receipt_trust_anchor.public_key_fingerprint_sha256
            ),
        ),
        (
            "policy_id",
            lambda values: values[4][0].phase_a_v5_closure.worker_attestations[0].run_id,
        ),
    ),
)
def test_rejects_independently_resigned_c0_policy_collisions(field: str, identity: Any) -> None:
    values = _inputs()
    _assert_original_b2_valid(values)
    policy = cast(matrix_v1.TargetDeliveryFieldMatrixPolicyV1, values[7]).model_copy(
        update={field: identity(values)}
    )
    resigned = _resign_for_policy(values, policy)
    assert matrix_v1.target_delivery_field_matrix_v1_message(resigned)
    _assert_failure(_with_policy(values, policy, resigned), phase="anchor")


def test_rejects_physical_builder_aliases_with_c0_root_and_material_identity() -> None:
    values = _inputs()
    _assert_original_b2_valid(values)
    builder = (
        values[5][0].worker_trust_policy.worker_trust_anchors[0].physical_builder_identity_sha256
    )
    original_anchor = cast(matrix_v1.TargetDeliveryFieldMatrixTrustAnchorV1, values[8])
    builder_anchor = original_anchor.model_copy(update={"authority_identity_sha256": builder})
    signed = cast(matrix_v1.TargetDeliveryFieldMatrixV1, values[-2])
    private_key = cast(Ed25519PrivateKey, values[-1])
    builder_anchor_matrix = _resign(
        signed.model_copy(
            update={
                "signer_key_id": builder_anchor.key_id,
                "signer_fingerprint_sha256": builder_anchor.public_key_fingerprint_sha256,
            }
        ),
        private_key,
    )
    assert matrix_v1.target_delivery_field_matrix_v1_message(builder_anchor_matrix)
    _assert_failure(
        (*values[:8], builder_anchor, builder_anchor_matrix, values[-1]), phase="anchor"
    )

    direct = cast(matrix_v1.ProviderMaterialPolicyV2, signed.rows[0].material_policy)
    builder_material = direct.model_copy(update={"reference_sha256": builder})
    builder_row = signed.rows[0].model_copy(update={"material_policy": builder_material})
    builder_matrix = _resign(
        signed.model_copy(update={"rows": (builder_row, *signed.rows[1:])}), private_key
    )
    assert matrix_v1.target_delivery_field_matrix_v1_message(builder_matrix)
    _assert_failure(_with_matrix(values, builder_matrix), phase="anchor")


def test_allows_explicitly_repeated_profile_roots_builders_and_content() -> None:
    values = _inputs()
    _assert_original_b2_valid(values)
    role_inputs = values[4]
    policy_inputs = values[5]
    assert (
        len(
            {
                (
                    role.profile_envelope.static_role_profile.ticket_trust_anchor.key_id,
                    role.profile_envelope.static_role_profile.ticket_trust_anchor.public_key_base64,
                    role.profile_envelope.static_role_profile.ticket_trust_anchor.public_key_fingerprint_sha256,
                )
                for role in role_inputs
            }
        )
        == 1
    )
    assert (
        len(
            {
                (
                    role.profile_envelope.static_role_profile.replay_receipt_trust_anchor.key_id,
                    role.profile_envelope.static_role_profile.replay_receipt_trust_anchor.public_key_base64,
                    role.profile_envelope.static_role_profile.replay_receipt_trust_anchor.public_key_fingerprint_sha256,
                )
                for role in role_inputs
            }
        )
        == 1
    )
    assert (
        len(
            {
                anchor.physical_builder_identity_sha256
                for policy_input in policy_inputs
                for anchor in policy_input.worker_trust_policy.worker_trust_anchors
            }
        )
        == 2
    )
    assert (
        len(
            {
                role.phase_a_v5_closure.worker_attestations[0].canonical_source_snapshot_sha256
                for role in role_inputs
            }
        )
        == 1
    )
    assert _validate(values).non_authorizing is True

    shared_ticket = role_inputs[0].profile_envelope.static_role_profile.ticket_trust_anchor
    shared_replay = role_inputs[0].profile_envelope.static_role_profile.replay_receipt_trust_anchor
    shared_roles = tuple(
        role.model_copy(
            update={
                "profile_envelope": role.profile_envelope.model_copy(
                    update={
                        "static_role_profile": role.profile_envelope.static_role_profile.model_copy(
                            update={
                                "ticket_trust_anchor": shared_ticket,
                                "replay_receipt_trust_anchor": shared_replay,
                            }
                        )
                    }
                )
            }
        )
        for role in role_inputs
    )
    assert _validate((*values[:4], shared_roles, *values[5:])).non_authorizing is True


def test_canonical_signature_and_hostile_model_state_fail_closed_without_leaks() -> None:
    values = _inputs()
    acceptance = _validate(values)
    signed = cast(matrix_v1.TargetDeliveryFieldMatrixV1, values[-2])
    canonical = matrix_v1.target_delivery_field_matrix_v1_canonical_json(signed)
    assert matrix_v1.parse_target_delivery_field_matrix_v1_canonical_json(canonical) == signed
    assert matrix_v1.target_delivery_field_matrix_v1_message(signed).startswith(
        b"omninode-rsd.target-delivery-field-matrix.ed25519.v1\x00"
    )
    for malformed in (
        b" " + canonical,
        canonical.replace(b'"schema_version"', b'"schema_version" ', 1),
        canonical.removesuffix(b"}") + b',"secret":"must-not-leak"}',
    ):
        with pytest.raises(matrix_v1.TargetDeliveryFieldMatrixError) as error:
            matrix_v1.parse_target_delivery_field_matrix_v1_canonical_json(malformed)
        assert "must-not-leak" not in str(error.value)

    bad_signature = signed.model_copy(
        update={"signature_base64": base64.b64encode(bytes(64)).decode("ascii")}
    )
    _assert_failure(_with_matrix(values, bad_signature), phase="matrix")

    constructed = matrix_v1.TargetDeliveryFieldMatrixV1.model_construct(
        **{
            key: value
            for key, value in signed.model_dump(mode="python").items()
            if key != "effect_allowed"
        }
    )
    hidden = signed.model_copy()
    object.__setattr__(hidden, "raw_secret", "must-not-leak")
    deleted = signed.model_copy()
    object.__delattr__(deleted, "__pydantic_fields_set__")
    cyclic = signed.model_copy()
    object.__setattr__(cyclic, "rows", (cyclic,))
    for hostile in (constructed, hidden, deleted, cyclic):
        with pytest.raises(matrix_v1.TargetDeliveryFieldMatrixError) as error:
            matrix_v1.target_delivery_field_matrix_v1_canonical_json(hostile)
        assert str(error.value) == "target delivery field matrix validation failed"
        assert "must-not-leak" not in str(error.value)

    warmed = signed.model_copy(deep=True)
    assert matrix_v1.target_delivery_field_matrix_v1_canonical_json(warmed)
    object.__setattr__(warmed.rows[0], "raw_secret", "must-not-leak")
    with pytest.raises(matrix_v1.TargetDeliveryFieldMatrixError) as error:
        matrix_v1.target_delivery_field_matrix_v1_canonical_json(warmed)
    assert str(error.value) == "target delivery field matrix validation failed"
    assert "must-not-leak" not in str(error.value)

    accepted = matrix_v1.target_delivery_field_matrix_acceptance_v1_canonical_json(acceptance)
    assert (
        matrix_v1.parse_target_delivery_field_matrix_acceptance_v1_canonical_json(accepted)
        == acceptance
    )
