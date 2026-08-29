"""Compatibility tests for the centralized V1 map signature dialect."""

from __future__ import annotations

import base64
import hashlib
import importlib.util
import json
import sys
from pathlib import Path
from typing import Any, cast

import pytest
import yaml
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey

from omninode_rsd.lifecycle import authorization
from omninode_rsd.lifecycle import target_delivery_map_projection_binding as binding
from omninode_rsd.lifecycle import target_delivery_map_signing as signing
from omninode_rsd.lifecycle.container_attach_static_v4 import (
    ContainerBootstrapStaticProfileTrustAnchorV4,
    ContainerBootstrapStaticRoleProfileEnvelopeV4,
    container_bootstrap_static_delivery_projection_v4_sha256,
    container_bootstrap_static_delivery_route_v4_sha256,
    container_bootstrap_static_role_profile_envelope_v4_canonical_message,
    container_bootstrap_static_role_profile_envelope_v4_sha256,
    parse_container_bootstrap_static_delivery_projection_v4_canonical_json,
    parse_container_bootstrap_static_profile_trust_anchor_v4_canonical_json,
    parse_container_bootstrap_static_role_profile_envelope_v4_canonical_json,
    project_target_delivery_map_v1_structurally,
    verify_container_bootstrap_static_role_profile_envelope_v4,
)
from omninode_rsd.lifecycle.container_bootstrap_artifact_evidence_v4 import (
    ContainerBootstrapBuildWorkerTrustPolicyV4,
)
from omninode_rsd.lifecycle.infisical_disposable import (
    TargetDeliveryMapV1,
    target_delivery_map_sha256,
)


class _StrictVectorLoader(yaml.SafeLoader):
    """Reject duplicate keys in the immutable public B1 vector."""


def _strict_yaml_mapping(
    loader: yaml.SafeLoader, node: yaml.MappingNode, deep: bool = False
) -> dict[object, object]:
    result: dict[object, object] = {}
    for key_node, value_node in node.value:
        key = loader.construct_object(key_node, deep=deep)
        if key in result:
            raise ValueError("duplicate B1 vector key")
        result[key] = loader.construct_object(value_node, deep=deep)
    return result


_StrictVectorLoader.add_constructor(
    yaml.resolver.BaseResolver.DEFAULT_MAPPING_TAG,
    _strict_yaml_mapping,
)


def _vector_segmented_bytes(value: object) -> bytes:
    if type(value) is not dict or set(value) != {"encoding", "segments"}:
        raise ValueError("vector bytes are invalid")
    encoding = value["encoding"]
    segments = value["segments"]
    if (
        type(encoding) is not str
        or encoding != "standard_base64_fixed_segments_v1"
        or type(segments) is not list
        or not segments
        or any(type(segment) is not str or not segment.isascii() for segment in segments)
    ):
        raise ValueError("vector bytes are invalid")
    joined = "".join(cast(list[str], segments))
    decoded = base64.b64decode(joined, validate=True)
    if base64.b64encode(decoded).decode("ascii") != joined:
        raise ValueError("vector bytes are invalid")
    if any(len(segment) != 76 for segment in segments[:-1]) or not 1 <= len(segments[-1]) <= 76:
        raise ValueError("vector bytes are invalid")
    return decoded


def _canonical_json(model: object) -> bytes:
    return json.dumps(
        cast(Any, model).model_dump(mode="json", warnings="error"),
        ensure_ascii=True,
        sort_keys=True,
        separators=(",", ":"),
        allow_nan=False,
    ).encode("ascii")


def _fixture_module() -> Any:
    path = Path(__file__).with_name("test_infisical_disposable.py")
    spec = importlib.util.spec_from_file_location("_rsd_map_signing_fixture", path)
    if spec is None or spec.loader is None:
        raise RuntimeError("fixture module is unavailable")
    module = importlib.util.module_from_spec(spec)
    sys.modules[spec.name] = module
    spec.loader.exec_module(module)
    return module


def _static_v4_fixture_module() -> Any:
    path = Path(__file__).with_name("test_container_attach_static_v4.py")
    spec = importlib.util.spec_from_file_location("_rsd_b1_static_v4_fixture", path)
    if spec is None or spec.loader is None:
        raise RuntimeError("static V4 fixture module is unavailable")
    module = importlib.util.module_from_spec(spec)
    sys.modules[spec.name] = module
    spec.loader.exec_module(module)
    return module


def _updated(model: object, **changes: object) -> dict[str, object]:
    values = cast(Any, model).model_dump(mode="python")
    values.update(changes)
    return values


def _documentation_signed_map(tmp_path: Path) -> tuple[Any, Any, Any]:
    """Return a complete signed V1 map projecting exactly to the public V4 profile."""

    fixture = _static_v4_fixture_module()
    bundle = fixture._bundle(tmp_path, component="primary_valkey", documentation_authorities=True)
    original_map = cast(Any, bundle["controls"])["delivery_map"]
    original_projection = fixture.project_target_delivery_map_v1_structurally(original_map)
    expected_projection = fixture._documentation_delivery_projection(original_projection)
    topology = original_map.topology
    primary_network = type(topology.primary_network)(
        **_updated(
            topology.primary_network,
            subnet="203.0.113.0/26",
            gateway="203.0.113.1",
        )
    )
    restore_network = type(topology.restore_network)(
        **_updated(
            topology.restore_network,
            subnet="198.51.100.0/26",
            gateway="198.51.100.1",
        )
    )
    documented_topology = type(topology)(
        **_updated(
            topology,
            primary_network=primary_network,
            restore_network=restore_network,
            primary_infisical=type(topology.primary_infisical)(
                **_updated(topology.primary_infisical, static_ipv4="203.0.113.2")
            ),
            primary_valkey=type(topology.primary_valkey)(
                **_updated(topology.primary_valkey, static_ipv4="203.0.113.30")
            ),
            restore_infisical=type(topology.restore_infisical)(
                **_updated(topology.restore_infisical, static_ipv4="198.51.100.2")
            ),
            restore_valkey=type(topology.restore_valkey)(
                **_updated(topology.restore_valkey, static_ipv4="198.51.100.30")
            ),
        )
    )
    postgres_authority = "postgresql://203.0.113.40:5432"
    primary_uri = original_map.database_identities.primary_database.connection_uri
    restore_uri = original_map.database_identities.restore_database.connection_uri
    documented_primary_uri = type(primary_uri)(
        **_updated(
            primary_uri,
            authority=postgres_authority,
            rendered_uri_byte_count=fixture.postgresql_connection_uri_rendered_byte_count(
                authority=postgres_authority,
                application_role=primary_uri.application_role,
                database_name=primary_uri.database_name,
            ),
        )
    )
    documented_restore_uri = type(restore_uri)(
        **_updated(
            restore_uri,
            authority=postgres_authority,
            rendered_uri_byte_count=fixture.postgresql_connection_uri_rendered_byte_count(
                authority=postgres_authority,
                application_role=restore_uri.application_role,
                database_name=restore_uri.database_name,
            ),
        )
    )
    primary_valkey_uri = original_map.primary_valkey_connection_uri
    restore_valkey_uri = original_map.restore_valkey_connection_uri
    documented_primary_valkey_uri = type(primary_valkey_uri)(
        **_updated(
            primary_valkey_uri,
            authority="redis://203.0.113.30:6379",
            rendered_uri_byte_count=fixture.valkey_connection_uri_rendered_byte_count(
                authority="redis://203.0.113.30:6379",
                database_index=primary_valkey_uri.database_index,
            ),
        )
    )
    documented_restore_valkey_uri = type(restore_valkey_uri)(
        **_updated(
            restore_valkey_uri,
            authority="redis://198.51.100.30:6379",
            rendered_uri_byte_count=fixture.valkey_connection_uri_rendered_byte_count(
                authority="redis://198.51.100.30:6379",
                database_index=restore_valkey_uri.database_index,
            ),
        )
    )

    def documented_route(route: Any, postgres: Any, valkey: Any) -> Any:
        fields = tuple(
            type(field)(
                **_updated(
                    field,
                    encoded_byte_count=(
                        postgres.rendered_uri_byte_count
                        if field.target_field == "DB_CONNECTION_URI"
                        else valkey.rendered_uri_byte_count
                    ),
                    derivation_binding_sha256=fixture.static_v4.runtime_connection_uri_grammar_sha256(
                        postgres if field.target_field == "DB_CONNECTION_URI" else valkey
                    ),
                )
            )
            if field.target_field in {"DB_CONNECTION_URI", "REDIS_URL"}
            else field
            for field in route.fields
        )
        return type(route)(**_updated(route, fields=fields))

    database_identities = type(original_map.database_identities)(
        **_updated(
            original_map.database_identities,
            primary_database=type(original_map.database_identities.primary_database)(
                **_updated(
                    original_map.database_identities.primary_database,
                    connection_uri=documented_primary_uri,
                )
            ),
            restore_database=type(original_map.database_identities.restore_database)(
                **_updated(
                    original_map.database_identities.restore_database,
                    connection_uri=documented_restore_uri,
                )
            ),
        )
    )
    unsigned = type(original_map)(
        **_updated(
            original_map,
            topology=documented_topology,
            database_identities=database_identities,
            primary_valkey_connection_uri=documented_primary_valkey_uri,
            restore_valkey_connection_uri=documented_restore_valkey_uri,
            primary_infisical=documented_route(
                original_map.primary_infisical,
                documented_primary_uri,
                documented_primary_valkey_uri,
            ),
            restore_infisical=documented_route(
                original_map.restore_infisical,
                documented_restore_uri,
                documented_restore_valkey_uri,
            ),
        )
    )
    signed = fixture.v2_fixtures._resign_v1_target_delivery_map(unsigned)
    assert fixture.project_target_delivery_map_v1_structurally(signed) == expected_projection
    return signed, bundle, fixture


def _unsigned_map(tmp_path: Path) -> TargetDeliveryMapV1:
    fixture = _fixture_module()
    allocation, executor, _ = fixture._allocation_bundle(tmp_path)
    receipt = fixture._allocation_receipt(allocation)
    attestation = fixture._allocation_attestation(allocation, receipt)
    result = fixture._materialization_intent(allocation, executor, receipt, attestation)
    return cast(TargetDeliveryMapV1, result[5])


def test_central_message_is_byte_identical_to_authorization_v1_message(tmp_path: Path) -> None:
    delivery_map = _unsigned_map(tmp_path)

    assert signing.target_delivery_map_v1_canonical_message(delivery_map) == (
        authorization._target_delivery_map_message(delivery_map)
    )


def test_central_v1_dialect_matches_committed_historical_message_vector() -> None:
    path = (
        Path(__file__).parents[2]
        / "src/omninode_rsd/lifecycle/target_delivery_map_projection_binding_public_vector.yaml"
    )
    vector = yaml.load(path.read_bytes(), Loader=_StrictVectorLoader)
    assert type(vector) is dict
    delivery_map = TargetDeliveryMapV1.model_validate_json(
        _vector_segmented_bytes(vector["target_delivery_map_canonical_json_utf8_base64"]),
        strict=True,
    )
    message = _vector_segmented_bytes(vector["target_delivery_map_message_base64"])
    assert signing.target_delivery_map_v1_canonical_message(delivery_map) == message
    assert (
        target_delivery_map_sha256(delivery_map) == vector["hashes"]["target_delivery_map_sha256"]
    )


def test_authorization_and_central_verifier_accept_same_valid_v1_map(tmp_path: Path) -> None:
    key = Ed25519PrivateKey.generate()
    public = key.public_key().public_bytes_raw()
    draft = _unsigned_map(tmp_path).model_copy(
        update={
            "signer_key_id": "map-signer",
            "signature_base64": base64.b64encode(b"x" * 64).decode("ascii"),
        }
    )
    signed = draft.model_copy(
        update={
            "signature_base64": base64.b64encode(
                key.sign(signing.target_delivery_map_v1_canonical_message(draft))
            ).decode("ascii")
        }
    )
    fingerprint = hashlib.sha256(public).hexdigest()
    anchor = signing.TargetDeliveryMapSignerTrustAnchorV1(
        schema_version="rsd.target-delivery-map-signer-trust-anchor.v1",
        key_id="map-signer",
        public_key_base64=base64.b64encode(public).decode("ascii"),
        public_key_fingerprint_sha256=fingerprint,
        algorithm="ed25519",
    )
    legacy_anchor = authorization.TrustedEd25519SignerV1(
        key_id="map-signer",
        public_key_base64=anchor.public_key_base64,
        public_key_fingerprint_sha256=fingerprint,
    )

    assert (
        signing.verify_target_delivery_map_v1_signature(
            delivery_map=signed, signer_trust_anchor=anchor
        )
        == signed
    )
    authorization._verify_target_delivery_map_signature(signed, signer=legacy_anchor)

    tampered = signed.model_copy(
        update={"signature_base64": base64.b64encode(b"y" * 64).decode("ascii")}
    )
    with pytest.raises(signing.TargetDeliveryMapSigningError):
        signing.verify_target_delivery_map_v1_signature(
            delivery_map=tampered, signer_trust_anchor=anchor
        )
    with pytest.raises(authorization.AuthorizationError):
        authorization._verify_target_delivery_map_signature(tampered, signer=legacy_anchor)


def test_binding_parser_is_canonical_and_its_message_excludes_only_signature() -> None:
    key = Ed25519PrivateKey.generate()
    public = key.public_key().public_bytes_raw()

    def digest(label: str) -> str:
        return hashlib.sha256(label.encode("ascii")).hexdigest()

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
        target_delivery_map_sha256=digest("complete-signed-map"),
        static_delivery_projection_sha256=digest("projection"),
        verified_static_role_profile_sha256=digest("profile"),
        verified_static_role_profile_envelope_sha256=digest("profile-envelope"),
        profile_component="primary_valkey",
        profile_component_role="valkey",
        selected_delivery_route_sha256=digest("selected-route"),
        selected_delivery_route_ordinal=1,
        verified_profile_trust_anchor_key_id="profile-root",
        verified_profile_trust_anchor_public_key_fingerprint_sha256=digest("profile-root-key"),
        verified_map_signer_key_id="map-signer",
        verified_map_signer_public_key_fingerprint_sha256=digest("map-public-key"),
        binding_signer_key_id="binding-signer",
        binding_signer_public_key_fingerprint_sha256=hashlib.sha256(public).hexdigest(),
        signature_base64=base64.b64encode(b"z" * 64).decode("ascii"),
    )
    signed = unsigned.model_copy(
        update={
            "signature_base64": base64.b64encode(
                key.sign(binding.target_delivery_map_projection_binding_v1_message(unsigned))
            ).decode("ascii")
        }
    )
    canonical = binding.target_delivery_map_projection_binding_v1_canonical_json(signed)

    assert (
        binding.parse_target_delivery_map_projection_binding_v1_canonical_json(canonical) == signed
    )
    assert binding.target_delivery_map_projection_binding_v1_message(signed) == (
        binding.target_delivery_map_projection_binding_v1_message(unsigned)
    )
    with pytest.raises(binding.TargetDeliveryMapProjectionBindingError):
        binding.parse_target_delivery_map_projection_binding_v1_canonical_json(
            canonical.replace(b'"schema_version"', b'"schema_version" ')
        )
    with pytest.raises(binding.TargetDeliveryMapProjectionBindingError):
        binding.parse_target_delivery_map_projection_binding_v1_canonical_json(
            canonical.removesuffix(b"}") + b',"extra":1}'
        )


def test_b1_accepts_complete_signed_map_bound_to_verified_public_v4_profile(
    tmp_path: Path,
) -> None:
    delivery_map, bundle, fixture = _documentation_signed_map(tmp_path)
    projection = bundle["projection"]
    profile_envelope = bundle["profile_envelope"]
    profile_anchor = bundle["profile_trust_anchor"]
    map_public = fixture.v2_fixtures._PUBLIC
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
        key_id="binding-root",
        authority_identity_sha256=hashlib.sha256(b"binding-authority").hexdigest(),
        independence_domain_identity_sha256=hashlib.sha256(b"binding-domain").hexdigest(),
        public_key_base64=base64.b64encode(binding_public).decode("ascii"),
        public_key_fingerprint_sha256=hashlib.sha256(binding_public).hexdigest(),
        algorithm="ed25519",
    )
    worker_anchors = []
    for ordinal in (1, 2):
        worker_key = Ed25519PrivateKey.generate()
        worker_public = worker_key.public_key().public_bytes_raw()
        worker_anchors.append(
            binding.ContainerBootstrapBuildWorkerTrustAnchorV4(
                schema_version="rsd.container-bootstrap-build-worker-trust-anchor.v4",
                key_id=f"worker-{ordinal}",
                worker_identity_sha256=hashlib.sha256(
                    f"worker-identity-{ordinal}".encode("ascii")
                ).hexdigest(),
                authority_identity_sha256=hashlib.sha256(
                    f"worker-authority-{ordinal}".encode("ascii")
                ).hexdigest(),
                public_key_base64=base64.b64encode(worker_public).decode("ascii"),
                public_key_fingerprint_sha256=hashlib.sha256(worker_public).hexdigest(),
                algorithm="ed25519",
            )
        )
    workers = binding.ContainerBootstrapBuildWorkerTrustPolicyV4(
        schema_version="rsd.container-bootstrap-build-worker-trust-policy.v4",
        policy_id="phase-a-workers",
        independence_domain_sha256=hashlib.sha256(b"phase-a-domain").hexdigest(),
        worker_trust_anchors=tuple(worker_anchors),
    )
    trust_policy = binding.TargetDeliveryMapProjectionBindingTrustPolicyV1(
        schema_version="rsd.target-delivery-map-projection-binding-trust-policy.v1",
        policy_id="b1-policy",
        map_signer_trust_anchor=map_anchor,
        map_authority_identity_sha256=hashlib.sha256(b"map-authority").hexdigest(),
        map_independence_domain_identity_sha256=hashlib.sha256(b"map-domain").hexdigest(),
        binding_trust_anchor=binding_anchor,
        profile_trust_anchor=profile_anchor,
        phase_a_worker_trust_policy=workers,
    )
    policy_json = binding.target_delivery_map_projection_binding_trust_policy_v1_canonical_json(
        trust_policy
    )
    assert (
        binding.parse_target_delivery_map_projection_binding_trust_policy_v1_canonical_json(
            policy_json
        )
        == trust_policy
    )
    with pytest.raises(binding.TargetDeliveryMapProjectionBindingError):
        binding.parse_target_delivery_map_projection_binding_trust_policy_v1_canonical_json(
            policy_json.removesuffix(b"}") + b',"extra":1}'
        )
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
        target_delivery_map_sha256=fixture.v2_fixtures.target_delivery_map_sha256(delivery_map),
        static_delivery_projection_sha256=(
            fixture.container_bootstrap_static_delivery_projection_v4_sha256(projection)
        ),
        verified_static_role_profile_sha256=profile_envelope.static_role_profile.profile_sha256,
        verified_static_role_profile_envelope_sha256=(
            fixture.container_bootstrap_static_role_profile_envelope_v4_sha256(profile_envelope)
        ),
        profile_component=profile_envelope.static_role_profile.component,
        profile_component_role=profile_envelope.static_role_profile.component_role,
        selected_delivery_route_sha256=(
            profile_envelope.static_role_profile.selected_delivery_route_sha256
        ),
        selected_delivery_route_ordinal=(
            ("primary_infisical", "primary_valkey", "restore_infisical", "restore_valkey").index(
                profile_envelope.static_role_profile.component
            )
        ),
        verified_profile_trust_anchor_key_id=profile_anchor.key_id,
        verified_profile_trust_anchor_public_key_fingerprint_sha256=(
            profile_anchor.public_key_fingerprint_sha256
        ),
        verified_map_signer_key_id=map_anchor.key_id,
        verified_map_signer_public_key_fingerprint_sha256=(
            map_anchor.public_key_fingerprint_sha256
        ),
        binding_signer_key_id=binding_anchor.key_id,
        binding_signer_public_key_fingerprint_sha256=(binding_anchor.public_key_fingerprint_sha256),
        signature_base64=base64.b64encode(b"b" * 64).decode("ascii"),
    )
    signed = unsigned.model_copy(
        update={
            "signature_base64": base64.b64encode(
                binding_key.sign(
                    binding.target_delivery_map_projection_binding_v1_message(unsigned)
                )
            ).decode("ascii")
        }
    )

    def resigned_for_profile(
        envelope: Any,
        root: Any,
        **changes: object,
    ) -> binding.TargetDeliveryMapProjectionBindingV1:
        profile = envelope.static_role_profile
        draft = signed.model_copy(
            update={
                "verified_static_role_profile_sha256": profile.profile_sha256,
                "verified_static_role_profile_envelope_sha256": (
                    fixture.container_bootstrap_static_role_profile_envelope_v4_sha256(envelope)
                ),
                "profile_component": profile.component,
                "profile_component_role": profile.component_role,
                "selected_delivery_route_sha256": profile.selected_delivery_route_sha256,
                "selected_delivery_route_ordinal": (
                    (
                        "primary_infisical",
                        "primary_valkey",
                        "restore_infisical",
                        "restore_valkey",
                    ).index(profile.component)
                ),
                "verified_profile_trust_anchor_key_id": root.key_id,
                "verified_profile_trust_anchor_public_key_fingerprint_sha256": (
                    root.public_key_fingerprint_sha256
                ),
                **changes,
                "signature_base64": base64.b64encode(b"q" * 64).decode("ascii"),
            }
        )
        return draft.model_copy(
            update={
                "signature_base64": base64.b64encode(
                    binding_key.sign(
                        binding.target_delivery_map_projection_binding_v1_message(draft)
                    )
                ).decode("ascii")
            }
        )

    acceptance = binding.validate_target_delivery_map_projection_binding_v1(
        delivery_map=delivery_map,
        static_delivery_projection=projection,
        profile_envelope=profile_envelope,
        binding=signed,
        trust_policy=trust_policy,
    )

    assert acceptance.target_delivery_map_sha256 == unsigned.target_delivery_map_sha256
    assert (
        acceptance.static_delivery_projection_sha256 == unsigned.static_delivery_projection_sha256
    )
    assert (
        acceptance.build_allowed,
        acceptance.materialization_allowed,
        acceptance.attach_allowed,
        acceptance.effect_allowed,
    ) == (False, False, False, False)

    # The projection is shared by four profiles, but each B1 relation is a
    # profile-specific signed claim.  A fully valid independently signed route
    # profile cannot consume this primary-Valkey relation.
    other_bundle = fixture._bundle(
        tmp_path / "primary-infisical-profile",
        component="primary_infisical",
        documentation_authorities=True,
    )
    other_envelope = other_bundle["profile_envelope"]
    assert other_envelope.static_role_profile.static_delivery_projection == projection
    with pytest.raises(binding.TargetDeliveryMapProjectionBindingError):
        binding.validate_target_delivery_map_projection_binding_v1(
            delivery_map=delivery_map,
            static_delivery_projection=projection,
            profile_envelope=other_envelope,
            binding=signed,
            trust_policy=trust_policy,
        )
    other_signed = resigned_for_profile(other_envelope, profile_anchor)
    other_acceptance = binding.validate_target_delivery_map_projection_binding_v1(
        delivery_map=delivery_map,
        static_delivery_projection=projection,
        profile_envelope=other_envelope,
        binding=other_signed,
        trust_policy=trust_policy,
    )
    assert other_acceptance.profile_sha256 != acceptance.profile_sha256

    # A different profile-integrity root creates a distinct, valid envelope;
    # it must also have a distinct B1 relation signer assertion.
    alternate_key = Ed25519PrivateKey.generate()
    alternate_public = alternate_key.public_key().public_bytes_raw()
    alternate_root = ContainerBootstrapStaticProfileTrustAnchorV4(
        schema_version="rsd.container-bootstrap-static-profile-trust-anchor.v4",
        key_id="alternate-profile-root",
        public_key_base64=base64.b64encode(alternate_public).decode("ascii"),
        public_key_fingerprint_sha256=hashlib.sha256(alternate_public).hexdigest(),
        algorithm="ed25519",
    )
    alternate_unsigned = ContainerBootstrapStaticRoleProfileEnvelopeV4(
        schema_version="rsd.container-bootstrap-static-role-profile-envelope.v4",
        static_role_profile=profile_envelope.static_role_profile,
        static_role_profile_sha256=profile_envelope.static_role_profile.profile_sha256,
        signer_key_id=alternate_root.key_id,
        signature_base64=base64.b64encode(b"r" * 64).decode("ascii"),
    )
    alternate_envelope = alternate_unsigned.model_copy(
        update={
            "signature_base64": base64.b64encode(
                alternate_key.sign(
                    container_bootstrap_static_role_profile_envelope_v4_canonical_message(
                        alternate_unsigned
                    )
                )
            ).decode("ascii")
        }
    )
    alternate_policy = type(trust_policy)(
        **_updated(trust_policy, profile_trust_anchor=alternate_root)
    )
    with pytest.raises(binding.TargetDeliveryMapProjectionBindingError):
        binding.validate_target_delivery_map_projection_binding_v1(
            delivery_map=delivery_map,
            static_delivery_projection=projection,
            profile_envelope=alternate_envelope,
            binding=signed,
            trust_policy=alternate_policy,
        )
    assert binding.validate_target_delivery_map_projection_binding_v1(
        delivery_map=delivery_map,
        static_delivery_projection=projection,
        profile_envelope=alternate_envelope,
        binding=resigned_for_profile(alternate_envelope, alternate_root),
        trust_policy=alternate_policy,
    ).profile_envelope_sha256 == fixture.container_bootstrap_static_role_profile_envelope_v4_sha256(
        alternate_envelope
    )

    # Re-signed internally coherent claim swaps must not silently select a
    # different route, role, ordinal, envelope, or profile root.
    alternate_route = projection.primary_infisical
    for changed_binding in (
        resigned_for_profile(
            profile_envelope,
            profile_anchor,
            profile_component="primary_infisical",
            profile_component_role="infisical",
            selected_delivery_route_sha256=(
                container_bootstrap_static_delivery_route_v4_sha256(alternate_route)
            ),
            selected_delivery_route_ordinal=0,
        ),
        resigned_for_profile(
            profile_envelope,
            profile_anchor,
            selected_delivery_route_sha256="a" * 64,
        ),
        resigned_for_profile(
            profile_envelope,
            profile_anchor,
            verified_static_role_profile_sha256="d" * 64,
        ),
        resigned_for_profile(
            profile_envelope,
            profile_anchor,
            verified_static_role_profile_envelope_sha256="b" * 64,
        ),
        resigned_for_profile(
            profile_envelope,
            profile_anchor,
            verified_profile_trust_anchor_key_id="other-profile-root",
        ),
        resigned_for_profile(
            profile_envelope,
            profile_anchor,
            verified_profile_trust_anchor_public_key_fingerprint_sha256="c" * 64,
        ),
    ):
        with pytest.raises(binding.TargetDeliveryMapProjectionBindingError):
            binding.validate_target_delivery_map_projection_binding_v1(
                delivery_map=delivery_map,
                static_delivery_projection=projection,
                profile_envelope=profile_envelope,
                binding=changed_binding,
                trust_policy=trust_policy,
            )

    stale = delivery_map.model_copy(update={"source_commit": "d" * 40})
    stale = fixture.v2_fixtures._resign_v1_target_delivery_map(stale)
    with pytest.raises(binding.TargetDeliveryMapProjectionBindingError):
        binding.validate_target_delivery_map_projection_binding_v1(
            delivery_map=stale,
            static_delivery_projection=projection,
            profile_envelope=profile_envelope,
            binding=signed,
            trust_policy=trust_policy,
        )
    # These complete-map fields intentionally do not participate in the static
    # V4 projection.  A new V1 signature alone still cannot reuse this B1 relation.
    for changes in (
        {"source_commit": "e" * 40},
        {"allocation_intent_sha256": "e" * 64},
        {"wrapper_manifest_sha256": "e" * 64},
        {"attach_protocol_sha256": "e" * 64},
        {"secret_handling_policy_sha256": "e" * 64},
        {"created_at": "2026-08-29T12:34:56Z"},
    ):
        resigned = fixture.v2_fixtures._resign_v1_target_delivery_map(delivery_map, **changes)
        assert fixture.project_target_delivery_map_v1_structurally(resigned) == projection
        with pytest.raises(binding.TargetDeliveryMapProjectionBindingError):
            binding.validate_target_delivery_map_projection_binding_v1(
                delivery_map=resigned,
                static_delivery_projection=projection,
                profile_envelope=profile_envelope,
                binding=signed,
                trust_policy=trust_policy,
            )
    with pytest.raises(binding.TargetDeliveryMapProjectionBindingError):
        binding.validate_target_delivery_map_projection_binding_v1(
            delivery_map=delivery_map.model_copy(
                update={"signature_base64": base64.b64encode(b"z" * 64).decode("ascii")}
            ),
            static_delivery_projection=projection,
            profile_envelope=profile_envelope,
            binding=signed,
            trust_policy=trust_policy,
        )
    with pytest.raises(binding.TargetDeliveryMapProjectionBindingError):
        binding.validate_target_delivery_map_projection_binding_v1(
            delivery_map=delivery_map,
            static_delivery_projection=projection,
            profile_envelope=profile_envelope,
            binding=signed.model_copy(
                update={"signature_base64": base64.b64encode(b"z" * 64).decode("ascii")}
            ),
            trust_policy=trust_policy,
        )
    ticket_key_id = profile_envelope.static_role_profile.ticket_trust_anchor.key_id
    colliding_policy = type(trust_policy)(**_updated(trust_policy, policy_id=ticket_key_id))
    with pytest.raises(binding.TargetDeliveryMapProjectionBindingError):
        binding.validate_target_delivery_map_projection_binding_v1(
            delivery_map=delivery_map,
            static_delivery_projection=projection,
            profile_envelope=profile_envelope,
            binding=signed,
            trust_policy=colliding_policy,
        )
    colliding_identity = type(trust_policy)(
        **_updated(
            trust_policy,
            map_authority_identity_sha256=(
                profile_envelope.static_role_profile.ticket_trust_anchor.public_key_fingerprint_sha256
            ),
        )
    )
    with pytest.raises(binding.TargetDeliveryMapProjectionBindingError):
        binding.validate_target_delivery_map_projection_binding_v1(
            delivery_map=delivery_map,
            static_delivery_projection=projection,
            profile_envelope=profile_envelope,
            binding=signed,
            trust_policy=colliding_identity,
        )


def test_committed_public_b1_vector_is_self_contained_and_verifies_from_disk() -> None:
    """The fixed public fixture never calls a builder, fixture, or signing helper."""

    path = (
        Path(__file__).parents[2]
        / "src/omninode_rsd/lifecycle/target_delivery_map_projection_binding_public_vector.yaml"
    )
    raw = path.read_bytes()
    assert not any(isinstance(event, yaml.events.AliasEvent) for event in yaml.parse(raw))
    vector = yaml.load(raw, Loader=_StrictVectorLoader)
    assert type(vector) is dict
    required = {
        "schema_version",
        "target_delivery_map_canonical_json_utf8_base64",
        "map_trust_anchor_canonical_json_utf8_base64",
        "static_delivery_projection_canonical_json_utf8_base64",
        "profile_envelope_canonical_json_utf8_base64",
        "profile_root_canonical_json_utf8_base64",
        "worker_policy_canonical_json_utf8_base64",
        "trust_policy_canonical_json_utf8_base64",
        "binding_canonical_json_utf8_base64",
        "acceptance_canonical_json_utf8_base64",
        "target_delivery_map_message_base64",
        "binding_message_base64",
        "hashes",
    }
    assert set(vector) == required
    assert vector["schema_version"] == "rsd.target-delivery-map-projection-binding-public-vector.v1"
    values = {
        key: _vector_segmented_bytes(vector[key]) for key in required - {"schema_version", "hashes"}
    }
    hashes = vector["hashes"]
    assert type(hashes) is dict and set(hashes) == {
        "target_delivery_map_sha256",
        "static_delivery_projection_sha256",
        "profile_sha256",
        "profile_envelope_sha256",
        "binding_sha256",
        "verification_context_sha256",
    }
    assert all(type(value) is str and len(value) == 64 for value in hashes.values())
    delivery_map = TargetDeliveryMapV1.model_validate_json(
        values["target_delivery_map_canonical_json_utf8_base64"], strict=True
    )
    assert _canonical_json(delivery_map) == values["target_delivery_map_canonical_json_utf8_base64"]
    map_anchor = signing.TargetDeliveryMapSignerTrustAnchorV1.model_validate_json(
        values["map_trust_anchor_canonical_json_utf8_base64"], strict=True
    )
    assert _canonical_json(map_anchor) == values["map_trust_anchor_canonical_json_utf8_base64"]
    projection = parse_container_bootstrap_static_delivery_projection_v4_canonical_json(
        values["static_delivery_projection_canonical_json_utf8_base64"]
    )
    envelope = parse_container_bootstrap_static_role_profile_envelope_v4_canonical_json(
        values["profile_envelope_canonical_json_utf8_base64"]
    )
    profile_root = parse_container_bootstrap_static_profile_trust_anchor_v4_canonical_json(
        values["profile_root_canonical_json_utf8_base64"]
    )
    worker_value = json.loads(values["worker_policy_canonical_json_utf8_base64"])
    workers = ContainerBootstrapBuildWorkerTrustPolicyV4.model_validate(
        binding._arrays_to_tuples(worker_value), strict=True
    )
    assert _canonical_json(workers) == values["worker_policy_canonical_json_utf8_base64"]
    policy = binding.parse_target_delivery_map_projection_binding_trust_policy_v1_canonical_json(
        values["trust_policy_canonical_json_utf8_base64"]
    )
    signed = binding.parse_target_delivery_map_projection_binding_v1_canonical_json(
        values["binding_canonical_json_utf8_base64"]
    )
    expected_acceptance = (
        binding.parse_target_delivery_map_projection_binding_acceptance_v1_canonical_json(
            values["acceptance_canonical_json_utf8_base64"]
        )
    )
    assert policy.map_signer_trust_anchor == map_anchor
    assert policy.profile_trust_anchor == profile_root
    assert policy.phase_a_worker_trust_policy == workers
    assert (
        signing.target_delivery_map_v1_canonical_message(delivery_map)
        == values["target_delivery_map_message_base64"]
    )
    assert (
        binding.target_delivery_map_projection_binding_v1_message(signed)
        == values["binding_message_base64"]
    )
    assert (
        signing.verify_target_delivery_map_v1_signature(
            delivery_map=delivery_map, signer_trust_anchor=map_anchor
        )
        == delivery_map
    )
    assert (
        verify_container_bootstrap_static_role_profile_envelope_v4(
            envelope=envelope, profile_trust_anchor=profile_root
        )
        == envelope.static_role_profile
    )
    assert project_target_delivery_map_v1_structurally(delivery_map) == projection
    acceptance = binding.validate_target_delivery_map_projection_binding_v1(
        delivery_map=delivery_map,
        static_delivery_projection=projection,
        profile_envelope=envelope,
        binding=signed,
        trust_policy=policy,
    )
    assert acceptance == expected_acceptance
    assert (
        binding.validate_target_delivery_map_projection_binding_v1(
            delivery_map=delivery_map,
            static_delivery_projection=projection,
            profile_envelope=envelope,
            binding=signed,
            trust_policy=policy,
        )
        == acceptance
    )
    assert (
        acceptance.build_allowed,
        acceptance.materialization_allowed,
        acceptance.attach_allowed,
        acceptance.effect_allowed,
    ) == (False, False, False, False)
    assert hashes == {
        "target_delivery_map_sha256": acceptance.target_delivery_map_sha256,
        "static_delivery_projection_sha256": acceptance.static_delivery_projection_sha256,
        "profile_sha256": acceptance.profile_sha256,
        "profile_envelope_sha256": acceptance.profile_envelope_sha256,
        "binding_sha256": acceptance.binding_sha256,
        "verification_context_sha256": acceptance.verification_context_sha256,
    }
    assert (
        container_bootstrap_static_delivery_projection_v4_sha256(projection)
        == hashes["static_delivery_projection_sha256"]
    )
    assert (
        container_bootstrap_static_role_profile_envelope_v4_sha256(envelope)
        == hashes["profile_envelope_sha256"]
    )


@pytest.mark.parametrize(
    "payload",
    (
        b"schema_version: one\nschema_version: two\n",
        b"first: &same value\nsecond: *same\n",
    ),
)
def test_public_vector_yaml_rejects_duplicate_keys_and_aliases(payload: bytes) -> None:
    if b"*same" in payload:
        assert any(isinstance(event, yaml.events.AliasEvent) for event in yaml.parse(payload))
    else:
        with pytest.raises(ValueError, match="duplicate B1 vector key"):
            yaml.load(payload, Loader=_StrictVectorLoader)


def test_b1_canonical_parsers_reject_duplicate_escaped_float_and_size_mutations() -> None:
    path = (
        Path(__file__).parents[2]
        / "src/omninode_rsd/lifecycle/target_delivery_map_projection_binding_public_vector.yaml"
    )
    vector = yaml.load(path.read_bytes(), Loader=_StrictVectorLoader)
    assert type(vector) is dict
    canonical = _vector_segmented_bytes(vector["binding_canonical_json_utf8_base64"])
    malformed = (
        canonical.replace(
            b"{", b'{"schema_version":"rsd.target-delivery-map-projection-binding.v1",', 1
        ),
        canonical.replace(b'"schema_version"', b'"schema\\u005fversion"', 1),
        canonical.replace(
            b'"target_delivery_map_sha256":"', b'"target_delivery_map_sha256":1.0,"x":"', 1
        ),
        b"{" * 33 + b"}" * 33,
        b"x" * 393_217,
    )
    for payload in malformed:
        with pytest.raises(binding.TargetDeliveryMapProjectionBindingError):
            binding.parse_target_delivery_map_projection_binding_v1_canonical_json(payload)
