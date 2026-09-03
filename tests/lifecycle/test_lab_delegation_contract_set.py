"""Positive and negative coverage for the authored lab-delegation contract set.

The negative cases exist so a green validation is never mistaken for a proof of
the topology: each one names a specific wrong contract and asserts whether the
library rejects it. The remaining ``accepts`` case is deliberate — it records
the observation value that this Gap 2 slice does not bind to anything real.
"""

from __future__ import annotations

import base64
import copy
from collections.abc import Callable
from typing import Any

import pytest
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey
from pydantic import ValidationError

from omninode_rsd.lifecycle import infisical_disposable as core
from omninode_rsd.lifecycle import lab_delegation_contract_set as harness
from omninode_rsd.lifecycle import target_delivery_map_signing as map_signing


def _build(mutate: Callable[[dict[str, Any]], None] | None = None) -> Any:
    contract_set = copy.deepcopy(harness._load(harness._DEFAULT_SET))
    if mutate is not None:
        mutate(contract_set)
    report = harness.Report()
    references, digests = harness._provider_references(contract_set["provider_references"], report)
    topology = harness._topology(contract_set["topology"], report)
    databases = harness._postgres(
        authored=contract_set["postgres"],
        authority=contract_set["addresses"]["postgresql_authority"],
        lane_authority=contract_set["postgres"]["lane_authority"],
        references=digests,
        commitments=contract_set["unbound_commitments"],
        report=report,
    )
    primary_valkey, restore_valkey = harness._valkey(
        authored=contract_set["valkey"],
        topology=topology,
        references=digests,
        report=report,
    )
    return harness._delivery_map(
        contract_set=contract_set,
        topology=topology,
        references=references,
        reference_digests=digests,
        databases=databases,
        primary_valkey_uri=primary_valkey,
        restore_valkey_uri=restore_valkey,
        report=report,
    )


def test_authored_contract_set_builds_a_valid_signed_map() -> None:
    delivery_map, anchor = _build()

    verified = map_signing.verify_target_delivery_map_v1_signature(
        delivery_map=delivery_map, signer_trust_anchor=anchor
    )

    assert verified.schema_version == "rsd.target-delivery-map.v1"
    assert core.target_delivery_map_sha256(verified) == core.target_delivery_map_sha256(
        delivery_map
    )


def test_authored_map_projects_the_exact_c0_field_and_dependency_shape() -> None:
    from omninode_rsd.lifecycle import target_delivery_field_matrix_v1 as matrix_v1

    delivery_map, _ = _build()

    rows = matrix_v1._expected_rows(delivery_map)
    dependencies = matrix_v1._expected_dependencies(delivery_map, rows)

    assert len(rows) == 10
    assert tuple(row.target_field for row in rows) == (
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
    assert tuple((edge.initiator_component, edge.dependency) for edge in dependencies) == (
        ("primary_infisical", "primary_postgresql"),
        ("primary_infisical", "primary_valkey"),
        ("restore_infisical", "restore_postgresql"),
        ("restore_infisical", "restore_valkey"),
    )


def _cross_lane_network(contract_set: dict[str, Any]) -> None:
    contract_set["topology"]["placements"]["primary_valkey"]["network"] = contract_set["topology"][
        "restore_network"
    ]["name"]


def _address_outside_lane(contract_set: dict[str, Any]) -> None:
    contract_set["topology"]["placements"]["primary_valkey"]["static_ipv4"] = "198.51.100.31"


def _shared_application_role(contract_set: dict[str, Any]) -> None:
    contract_set["postgres"]["restore"]["application_role"] = contract_set["postgres"]["primary"][
        "application_role"
    ]


def _owner_is_application_role(contract_set: dict[str, Any]) -> None:
    contract_set["postgres"]["primary"]["owner_role"] = contract_set["postgres"]["primary"][
        "application_role"
    ]


def _duplicate_provider_identity(contract_set: dict[str, Any]) -> None:
    contract_set["provider_references"]["auth_secret"]["account"] = contract_set[
        "provider_references"
    ]["encryption_key"]["account"]


@pytest.mark.parametrize(
    ("mutate", "reason"),
    [
        (_cross_lane_network, "a cache attached to the other lane's network"),
        (_address_outside_lane, "a static address outside its own lane subnet"),
        (_shared_application_role, "primary and restore sharing one application role"),
        (_owner_is_application_role, "an owner role that is also the application role"),
        (_duplicate_provider_identity, "two provider references with one identity"),
    ],
)
def test_rejects_wrong_contract(mutate: Callable[[dict[str, Any]], None], reason: str) -> None:
    with pytest.raises(ValidationError):
        _build(mutate)


def test_rejects_a_map_signed_by_an_unpinned_key() -> None:
    delivery_map, anchor = _build()
    other_key = Ed25519PrivateKey.generate()
    forged = core.TargetDeliveryMapV1.model_validate(
        {
            **delivery_map.model_dump(mode="python"),
            "signature_base64": base64.b64encode(
                other_key.sign(map_signing.target_delivery_map_v1_canonical_message(delivery_map))
            ).decode("ascii"),
        }
    )

    with pytest.raises(map_signing.TargetDeliveryMapSigningError):
        map_signing.verify_target_delivery_map_v1_signature(
            delivery_map=forged, signer_trust_anchor=anchor
        )


def _wrong_postgres_port(contract_set: dict[str, Any]) -> None:
    contract_set["addresses"]["postgresql_authority"] = "postgresql://203.0.113.40:9999"


def _invented_material_fingerprint(contract_set: dict[str, Any]) -> None:
    contract_set["unbound_commitments"]["material_fingerprint_labels"]["encryption_key"] = (
        "an-invented-label-for-material-that-never-existed"
    )


def _wrong_material_fingerprint_receipt(contract_set: dict[str, Any]) -> None:
    contract_set["unbound_commitments"]["material_fingerprint_receipt"]["fingerprints"][
        "encryption_key"
    ] = "f" * 64


def _coordinated_invented_material_fingerprint(contract_set: dict[str, Any]) -> None:
    label = "an-invented-label-and-coordinated-receipt-replacement"
    contract_set["unbound_commitments"]["material_fingerprint_labels"]["encryption_key"] = label
    contract_set["unbound_commitments"]["material_fingerprint_receipt"]["fingerprints"][
        "encryption_key"
    ] = harness._digest(label)


def _invented_observed_oid(contract_set: dict[str, Any]) -> None:
    contract_set["postgres"]["primary"]["observed"]["database_oid"] = 999_999


def test_rejects_postgres_authority_outside_the_declared_lane() -> None:
    with pytest.raises(ValueError, match="PostgreSQL authority must match the declared lane"):
        _build(_wrong_postgres_port)


@pytest.mark.parametrize(
    "mutate",
    [
        _invented_material_fingerprint,
        _wrong_material_fingerprint_receipt,
        _coordinated_invented_material_fingerprint,
    ],
)
def test_rejects_a_material_fingerprint_not_bound_by_its_receipt(
    mutate: Callable[[dict[str, Any]], None],
) -> None:
    with pytest.raises(ValueError, match="material fingerprint receipt"):
        _build(mutate)


def test_accepts_an_observed_oid_the_contract_vocabulary_does_not_bind() -> None:
    """This passes until OMN-17408 Gap 3 supplies an observation receipt."""

    delivery_map, anchor = _build(_invented_observed_oid)

    assert (
        map_signing.verify_target_delivery_map_v1_signature(
            delivery_map=delivery_map, signer_trust_anchor=anchor
        ).schema_version
        == "rsd.target-delivery-map.v1"
    )
