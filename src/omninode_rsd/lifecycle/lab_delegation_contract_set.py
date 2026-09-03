"""Offline validation of the authored lab-delegation contract set.

This script performs no network, database, container, or provider access. It
reads authored facts, recomputes every canonical commitment the library owns,
builds and signs a complete ``TargetDeliveryMapV1``, verifies that signature
under a locally generated pinned anchor, and projects the C0 field/dependency
matrix that a later phase would have to reproduce.

It reports three outcome classes, deliberately kept separate:

  PASS    a library validator accepted a structure it actually constrains
  UNBOUND a value the library accepts without binding it to anything real
  BLOCKED a stage that cannot run offline, with the exact missing input

A PASS is only ever evidence about the constraint the validator names. The
UNBOUND lines exist so a green run is not mistaken for a proof of the topology.
"""

from __future__ import annotations

import argparse
import base64
import hashlib
import json
import sys
from pathlib import Path
from typing import Any, Final, cast

import yaml
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey

from omninode_rsd.lifecycle import infisical_disposable as core
from omninode_rsd.lifecycle import target_delivery_field_matrix_v1 as matrix_v1
from omninode_rsd.lifecycle import target_delivery_map_signing as map_signing

_DEFAULT_SET: Final[Path] = Path(__file__).with_name("lab_delegation_contract_set.yaml")
_COMPONENTS: Final[tuple[str, ...]] = (
    "primary_infisical",
    "primary_valkey",
    "restore_infisical",
    "restore_valkey",
)


class Report:
    """Ordered validation transcript with a fail-closed exit status."""

    def __init__(self) -> None:
        self.lines: list[str] = []
        self.failed = False

    def stage(self, name: str) -> None:
        self.lines.append(f"\n== {name}")

    def ok(self, proved: str) -> None:
        self.lines.append(f"  PASS    {proved}")

    def unbound(self, detail: str) -> None:
        self.lines.append(f"  UNBOUND {detail}")

    def blocked(self, detail: str) -> None:
        self.lines.append(f"  BLOCKED {detail}")

    def fail(self, detail: str) -> None:
        self.failed = True
        self.lines.append(f"  FAIL    {detail}")

    def render(self) -> str:
        return "\n".join(self.lines)


def _digest(label: str) -> str:
    return hashlib.sha256(f"omninode-rsd.lab-delegation.v1\x00{label}".encode()).hexdigest()


def _reference_sha256(*, provider: str, service: str, account: str, version: int) -> str:
    return hashlib.sha256(
        json.dumps(
            {"account": account, "provider": provider, "service": service, "version": version},
            sort_keys=True,
            separators=(",", ":"),
        ).encode()
    ).hexdigest()


def _load(path: Path) -> dict[str, Any]:
    data = yaml.safe_load(path.read_text(encoding="utf-8"))
    if (
        not isinstance(data, dict)
        or data.get("schema_version") != "rsd.lab-delegation-contract-set.v1"
    ):
        raise SystemExit(f"{path}: not a lab-delegation contract set")
    return data


def _apply_overlay(contract_set: dict[str, Any], overlay_path: Path | None) -> str:
    if overlay_path is None:
        return "committed documentation-range default"
    overlay = yaml.safe_load(overlay_path.read_text(encoding="utf-8"))
    if (
        not isinstance(overlay, dict)
        or not isinstance(overlay.get("addresses"), dict)
        or not isinstance(overlay.get("postgres"), dict)
        or "postgresql_authority" not in overlay["addresses"]
        or "lane_authority" not in overlay["postgres"]
    ):
        raise SystemExit(
            f"{overlay_path}: overlay must define `addresses.postgresql_authority` "
            "and `postgres.lane_authority`"
        )
    contract_set["addresses"].update(overlay["addresses"])
    contract_set["postgres"].update(overlay["postgres"])
    return f"overlay {overlay_path.name}"


def _provider_references(
    authored: dict[str, Any], report: Report
) -> tuple[core.ProviderReferencesV2, dict[str, str]]:
    built: dict[str, core.ProviderReferenceV1] = {}
    for name, item in authored.items():
        built[name] = core.ProviderReferenceV1(
            provider=item["provider"],
            service=item["service"],
            account=item["account"],
            version=int(item["version"]),
            reference_sha256=_reference_sha256(
                provider=item["provider"],
                service=item["service"],
                account=item["account"],
                version=int(item["version"]),
            ),
        )
    references = core.ProviderReferencesV2(**built)
    report.ok(
        "ProviderReferencesV2 bound each reference digest to its own "
        "(provider, service, account, version) and required all seven distinct"
    )
    report.unbound(
        "a provider reference names a secret but proves no store, path, or "
        "existence: any well-formed identifier tuple validates"
    )
    return references, {name: value.reference_sha256 for name, value in built.items()}


def _topology(authored: dict[str, Any], report: Report) -> core.AllocationTopologyV2:
    placements = authored["placements"]
    topology = core.AllocationTopologyV2(
        primary_network=core.IsolatedNetworkPlanV1(
            name=authored["primary_network"]["name"],
            driver="bridge",
            internal=True,
            subnet=authored["primary_network"]["subnet"],
            gateway=authored["primary_network"]["gateway"],
            options=(),
        ),
        restore_network=core.IsolatedNetworkPlanV1(
            name=authored["restore_network"]["name"],
            driver="bridge",
            internal=True,
            subnet=authored["restore_network"]["subnet"],
            gateway=authored["restore_network"]["gateway"],
            options=(),
        ),
        **{
            component: core.ComponentPlacementV1(
                component=cast(Any, component),
                network_name=placements[component]["network"],
                alias=placements[component]["alias"],
                static_ipv4=placements[component]["static_ipv4"],
            )
            for component in _COMPONENTS
        },
        executor=core.ExecutorPlacementV1(
            executor_id=authored["executor_id"], placement="host_control_plane_v1"
        ),
    )
    report.ok(
        "AllocationTopologyV2 proved both lanes are internal, non-routable, "
        "non-overlapping bridges, that every component address falls inside "
        "its own lane and is not the gateway, and that the executor stays off "
        "both disposable networks"
    )
    return topology


def _postgres(
    *,
    authored: dict[str, Any],
    authority: str,
    lane_authority: str,
    references: dict[str, str],
    commitments: dict[str, Any],
    report: Report,
) -> core.PostgreSQLRuntimeDatabaseIdentitiesV1:
    identities: dict[str, core.PostgreSQLRuntimeDatabaseIdentityV1] = {}
    password_reference = references["postgres_application_password"]
    for identity, lane in (("primary_database", "primary"), ("restore_database", "restore")):
        spec = authored[lane]
        observed = spec["observed"]
        operation_id = commitments["prepared_operation_ids"][identity]
        transition = core.PostgreSQLLoginTransitionIntentV1(
            schema_version="rsd.postgresql-login-transition-intent.v1",
            transition_kind="enable_application_login_with_provider_verifier_v1",
            database_identity=cast(Any, identity),
            prepared_operation_id=operation_id,
            system_identifier=authored["system_identifier"],
            database_name=spec["database_name"],
            database_oid=int(observed["database_oid"]),
            schema_oid=int(observed["schema_oid"]),
            owner_role=spec["owner_role"],
            owner_role_oid=int(observed["owner_role_oid"]),
            application_role=spec["application_role"],
            application_role_oid=int(observed["application_role_oid"]),
            application_password_reference_sha256=password_reference,
            prepared_control_policy_sha256=_digest(commitments["prepared_control_policy_label"]),
            scram_verifier_install=core.PostgreSQLScramVerifierInstallV1(
                schema_version="rsd.postgresql-scram-verifier-install.v1",
                database_identity=cast(Any, identity),
                prepared_operation_id=operation_id,
                application_password_reference_sha256=password_reference,
                algorithm="scram-sha-256",
                iterations=int(authored["scram"]["iterations"]),
                salt_bytes=int(authored["scram"]["salt_bytes"]),
                derivation_scope="executor_bounded_memory_v1",
                sink="postgresql_prepared_psql_stdin_verifier_v1",
                plaintext_to_psql_allowed=False,
                verifier_in_receipt_allowed=False,
                sql_in_receipt_allowed=False,
                output_in_receipt_allowed=False,
                logs_allowed=False,
                template_sha256=_digest(
                    f"{commitments['prepared_control_policy_label']}.template.{identity}"
                ),
            ),
            owner_can_login=False,
            owner_password_absent=True,
            application_can_login=True,
            application_password_verifier_installed=True,
        )
        grammar = core.PostgreSQLConnectionUriGrammarV1(
            schema_version="rsd.postgresql-connection-uri-grammar.v1",
            database_identity=cast(Any, identity),
            authority=authority,
            database_name=spec["database_name"],
            application_role=spec["application_role"],
            application_password_reference_sha256=password_reference,
            prepared_operation_id=operation_id,
            target_process=(
                "primary_infisical" if identity == "primary_database" else "restore_infisical"
            ),
            environment_variable="DB_CONNECTION_URI",
            uri_grammar="postgresql_user_password_authority_database_v1",
            application_password_format="postgres_application_password_base64url_32_v1",
            application_password_encoded_byte_count=43,
            rendered_uri_byte_count=core.postgresql_connection_uri_rendered_byte_count(
                authority=authority,
                application_role=spec["application_role"],
                database_name=spec["database_name"],
            ),
            return_uri_allowed=False,
            persistent_storage_allowed=False,
            logging_allowed=False,
            public_artifact_allowed=False,
        )
        identities[identity] = core.PostgreSQLRuntimeDatabaseIdentityV1(
            database_identity=cast(Any, identity),
            observation_binding_sha256=_digest(commitments["observation_binding_labels"][identity]),
            schema_oid=int(observed["schema_oid"]),
            login_transition=transition,
            connection_uri=grammar,
        )
    if any(database.connection_uri.authority != lane_authority for database in identities.values()):
        raise ValueError("PostgreSQL authority must match the declared lane")
    result = core.PostgreSQLRuntimeDatabaseIdentitiesV1(**identities)
    report.ok(
        "PostgreSQL identities proved the owner role can never log in, the "
        "owner password is absent, the verifier install is bound to the same "
        "operation id and password reference as its transition, and the "
        "primary and restore lanes share no name, OID, role, or operation id"
    )
    report.ok(
        "PostgreSQLConnectionUriGrammarV1 required both authorities to equal "
        "the declared PostgreSQL lane and accepted that authority only as a "
        f"canonical scheme+IP-literal+port triple and recomputed its rendered "
        f"byte count ({identities['primary_database'].connection_uri.rendered_uri_byte_count} "
        "bytes primary) without ever assembling the URI"
    )
    report.unbound(
        "database_oid / schema_oid / role OIDs / system_identifier are "
        "post-provisioning observations. They are authored here as intent and "
        "the map binds them to no observation receipt"
    )
    return result


def _valkey(
    *,
    authored: dict[str, Any],
    topology: core.AllocationTopologyV2,
    references: dict[str, str],
    report: Report,
) -> tuple[core.ValkeyConnectionUriGrammarV1, core.ValkeyConnectionUriGrammarV1]:
    grammars: list[core.ValkeyConnectionUriGrammarV1] = []
    for cache, placement, index_key, password in (
        (
            "primary_valkey",
            topology.primary_valkey,
            "primary_database_index",
            "primary_valkey_password",
        ),
        (
            "restore_valkey",
            topology.restore_valkey,
            "restore_database_index",
            "restore_valkey_password",
        ),
    ):
        authority = core.valkey_static_authority(placement.static_ipv4)
        grammars.append(
            core.ValkeyConnectionUriGrammarV1(
                schema_version="rsd.valkey-connection-uri-grammar.v1",
                cache_identity=cast(Any, cache),
                authority=authority,
                database_index=int(authored[index_key]),
                password_reference_sha256=references[password],
                target_process=(
                    "primary_infisical" if cache == "primary_valkey" else "restore_infisical"
                ),
                environment_variable="REDIS_URL",
                uri_grammar="redis_password_authority_database_v1",
                password_format="valkey_password_base64url_32_v1",
                password_encoded_byte_count=43,
                rendered_uri_byte_count=core.valkey_connection_uri_rendered_byte_count(
                    authority=authority, database_index=int(authored[index_key])
                ),
                return_uri_allowed=False,
                persistent_storage_allowed=False,
                logging_allowed=False,
                public_artifact_allowed=False,
            )
        )
    report.ok(
        "ValkeyConnectionUriGrammarV1 forced each cache authority to "
        "valkey_static_authority(<lane static address>) and forced the "
        "primary/restore cache to feed only its own lane's Infisical process"
    )
    report.blocked(
        "an existing Valkey on an operator-chosen host and port cannot be "
        "expressed: the authority is derived from the allocated container "
        "address at the fixed default port, so only a disposable in-lane "
        "cache is representable"
    )
    return grammars[0], grammars[1]


def _delivery_map(
    *,
    contract_set: dict[str, Any],
    topology: core.AllocationTopologyV2,
    references: core.ProviderReferencesV2,
    reference_digests: dict[str, str],
    databases: core.PostgreSQLRuntimeDatabaseIdentitiesV1,
    primary_valkey_uri: core.ValkeyConnectionUriGrammarV1,
    restore_valkey_uri: core.ValkeyConnectionUriGrammarV1,
    report: Report,
) -> tuple[core.TargetDeliveryMapV1, map_signing.TargetDeliveryMapSignerTrustAnchorV1]:
    commitments = contract_set["unbound_commitments"]
    fingerprints = {
        purpose: _digest(label)
        for purpose, label in commitments["material_fingerprint_labels"].items()
    }
    material = cast(
        tuple[Any, Any, Any, Any, Any],
        tuple(
            core.ProviderMaterialFingerprintBindingV1(
                purpose=cast(Any, purpose),
                reference_sha256=reference_digests[purpose],
                fingerprint_sha256=fingerprints[purpose],
            )
            for purpose in (
                "encryption_key",
                "auth_secret",
                "primary_valkey_password",
                "restore_valkey_password",
                "postgres_application_password",
            )
        ),
    )
    primary_uri = databases.primary_database.connection_uri
    restore_uri = databases.restore_database.connection_uri

    def direct(
        ordinal: int, purpose: str, target: str, fmt: str, size: int, sink: str
    ) -> core.TargetDeliveryFieldV1:
        return core.TargetDeliveryFieldV1(
            ordinal=ordinal,
            source_purpose=cast(Any, purpose),
            source_reference_sha256=reference_digests[purpose],
            source_fingerprint_sha256=fingerprints[purpose],
            value_kind=core.TargetDeliveryValueKindV1.DIRECT_PROVIDER_MATERIAL,
            target_field=cast(Any, target),
            format=cast(Any, fmt),
            encoded_byte_count=size,
            sink=cast(Any, sink),
            derivation_binding_sha256=fingerprints[purpose],
            persistence_allowed=False,
            logging_allowed=False,
            receipt_allowed=False,
        )

    def derived(
        ordinal: int, purpose: str, target: str, fmt: str, grammar: Any
    ) -> core.TargetDeliveryFieldV1:
        return core.TargetDeliveryFieldV1(
            ordinal=ordinal,
            source_purpose=cast(Any, purpose),
            source_reference_sha256=reference_digests[purpose],
            source_fingerprint_sha256=fingerprints[purpose],
            value_kind=core.TargetDeliveryValueKindV1(fmt),
            target_field=cast(Any, target),
            format=cast(Any, fmt),
            encoded_byte_count=grammar.rendered_uri_byte_count,
            sink=core.ContainerSecretSinkV1.INFISICAL_TARGET_PROCESS_ENVIRONMENT,
            derivation_binding_sha256=core.runtime_connection_uri_grammar_sha256(grammar),
            persistence_allowed=False,
            logging_allowed=False,
            receipt_allowed=False,
        )

    routes: dict[str, core.ContainerTargetDeliveryV1] = {}
    lane_fields = {
        "primary_infisical": (
            direct(
                1,
                "encryption_key",
                "ENCRYPTION_KEY",
                "infisical_hex_16_v1",
                32,
                "infisical_target_process_environment_v1",
            ),
            direct(
                2,
                "auth_secret",
                "AUTH_SECRET",
                "infisical_auth_secret_base64_32_v1",
                44,
                "infisical_target_process_environment_v1",
            ),
            derived(
                3,
                "postgres_application_password",
                "DB_CONNECTION_URI",
                "derived_postgresql_uri_v1",
                primary_uri,
            ),
            derived(
                4,
                "primary_valkey_password",
                "REDIS_URL",
                "derived_valkey_uri_v1",
                primary_valkey_uri,
            ),
        ),
        "restore_infisical": (
            direct(
                1,
                "encryption_key",
                "ENCRYPTION_KEY",
                "infisical_hex_16_v1",
                32,
                "infisical_target_process_environment_v1",
            ),
            direct(
                2,
                "auth_secret",
                "AUTH_SECRET",
                "infisical_auth_secret_base64_32_v1",
                44,
                "infisical_target_process_environment_v1",
            ),
            derived(
                3,
                "postgres_application_password",
                "DB_CONNECTION_URI",
                "derived_postgresql_uri_v1",
                restore_uri,
            ),
            derived(
                4,
                "restore_valkey_password",
                "REDIS_URL",
                "derived_valkey_uri_v1",
                restore_valkey_uri,
            ),
        ),
        "primary_valkey": (
            direct(
                1,
                "primary_valkey_password",
                "requirepass",
                "valkey_password_base64url_32_v1",
                43,
                "valkey_stdin_configuration_v1",
            ),
        ),
        "restore_valkey": (
            direct(
                1,
                "restore_valkey_password",
                "requirepass",
                "valkey_password_base64url_32_v1",
                43,
                "valkey_stdin_configuration_v1",
            ),
        ),
    }
    attach_protocol = _digest(commitments["attach_protocol_label"])
    for component in _COMPONENTS:
        routes[component] = core.ContainerTargetDeliveryV1(
            component=cast(Any, component),
            derived_image_policy_sha256=_digest(
                commitments["derived_image_policy_labels"][component]
            ),
            wrapper_artifact_binding_sha256=_digest(
                commitments["wrapper_artifact_binding_labels"][component]
            ),
            attach_protocol_sha256=attach_protocol,
            sink=lane_fields[component][0].sink,
            fields=lane_fields[component],
        )

    private_key = Ed25519PrivateKey.generate()
    public_key = private_key.public_key().public_bytes_raw()
    anchor = map_signing.TargetDeliveryMapSignerTrustAnchorV1(
        schema_version="rsd.target-delivery-map-signer-trust-anchor.v1",
        key_id="lab-delegation-map-signer",
        public_key_base64=base64.b64encode(public_key).decode("ascii"),
        public_key_fingerprint_sha256=hashlib.sha256(public_key).hexdigest(),
        algorithm="ed25519",
    )
    draft = core.TargetDeliveryMapV1(
        schema_version="rsd.target-delivery-map.v1",
        source_commit=_digest(commitments["source_commit_label"])[:40],
        allocation_intent_sha256=_digest(commitments["allocation_intent_label"]),
        topology=topology,
        wrapper_manifest_sha256=_digest(commitments["wrapper_manifest_label"]),
        attach_protocol_sha256=attach_protocol,
        secret_handling_policy_sha256=_digest(commitments["secret_handling_policy_label"]),
        provider_references=references,
        material_fingerprints=material,
        database_identities=databases,
        primary_valkey_connection_uri=primary_valkey_uri,
        restore_valkey_connection_uri=restore_valkey_uri,
        primary_infisical=routes["primary_infisical"],
        primary_valkey=routes["primary_valkey"],
        restore_infisical=routes["restore_infisical"],
        restore_valkey=routes["restore_valkey"],
        created_at=contract_set["created_at"],
        signer_key_id=anchor.key_id,
        signature_base64=base64.b64encode(bytes(64)).decode("ascii"),
    )
    signed = core.TargetDeliveryMapV1.model_validate(
        {
            **draft.model_dump(mode="python"),
            "signature_base64": base64.b64encode(
                private_key.sign(map_signing.target_delivery_map_v1_canonical_message(draft))
            ).decode("ascii"),
        }
    )
    report.ok(
        "TargetDeliveryMapV1 proved the exact four-component route grammar: "
        "field order, target field names, formats, encoded sizes and sinks per "
        "component; that every field's source reference matches its provider "
        "reference and its fingerprint matches the declared material; that "
        "each derived URI field commits to its own grammar digest; and that "
        "both cache authorities equal their lane's allocated static address"
    )
    report.unbound(
        "material fingerprints are free 64-hex values. The map requires only "
        "that the five are distinct and match the fields that cite them, so "
        "they commit to no real provider material"
    )
    report.unbound(
        "source_commit, allocation_intent, wrapper_manifest, attach_protocol, "
        "secret_handling_policy, image policy and wrapper artifact digests are "
        "accepted as opaque 64-hex strings. Only three per route are required "
        "to differ; none is bound to an existing artifact at this layer"
    )
    return signed, anchor


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--contract-set", type=Path, default=_DEFAULT_SET)
    parser.add_argument(
        "--overlay",
        type=Path,
        default=None,
        help="YAML file whose `addresses` map replaces the committed defaults",
    )
    arguments = parser.parse_args(argv)

    contract_set = _load(arguments.contract_set)
    address_source = _apply_overlay(contract_set, arguments.overlay)
    report = Report()
    report.lines.append(f"contract set : {arguments.contract_set.name}")
    report.lines.append(f"addresses    : {address_source}")

    report.stage("provider references")
    references, reference_digests = _provider_references(
        contract_set["provider_references"], report
    )

    report.stage("allocation topology")
    topology = _topology(contract_set["topology"], report)

    report.stage("postgresql delivery")
    databases = _postgres(
        authored=contract_set["postgres"],
        authority=contract_set["addresses"]["postgresql_authority"],
        lane_authority=contract_set["postgres"]["lane_authority"],
        references=reference_digests,
        commitments=contract_set["unbound_commitments"],
        report=report,
    )

    report.stage("valkey delivery")
    primary_valkey_uri, restore_valkey_uri = _valkey(
        authored=contract_set["valkey"],
        topology=topology,
        references=reference_digests,
        report=report,
    )

    report.stage("target delivery map")
    delivery_map, anchor = _delivery_map(
        contract_set=contract_set,
        topology=topology,
        references=references,
        reference_digests=reference_digests,
        databases=databases,
        primary_valkey_uri=primary_valkey_uri,
        restore_valkey_uri=restore_valkey_uri,
        report=report,
    )

    report.stage("map signature")
    map_signing.verify_target_delivery_map_v1_signature(
        delivery_map=delivery_map, signer_trust_anchor=anchor
    )
    report.ok(
        "verify_target_delivery_map_v1_signature accepted the map under its "
        "pinned Ed25519 anchor and matching signer key id"
    )
    report.lines.append(f"  map digest: {core.target_delivery_map_sha256(delivery_map)}")

    report.stage("C0 field and dependency projection")
    rows = matrix_v1._expected_rows(delivery_map)
    dependencies = matrix_v1._expected_dependencies(delivery_map, rows)
    report.ok(
        f"the map projected exactly {len(rows)} one-shot field rows and "
        f"{len(dependencies)} directed application dependencies"
    )
    for row in rows:
        report.lines.append(
            "    row "
            + str(row.ordinal).rjust(2)
            + "  "
            + row.lane.ljust(7)
            + " "
            + row.target_component.ljust(18)
            + " "
            + row.target_field.ljust(18)
            + " "
            + row.source_kind.ljust(32)
            + " "
            + row.shared_reference_group
        )
    for edge in dependencies:
        report.lines.append(
            "    edge "
            + str(edge.ordinal)
            + "  "
            + edge.lane.ljust(7)
            + " "
            + edge.initiator_component.ljust(18)
            + " -> "
            + edge.dependency.ljust(18)
            + " ("
            + edge.dependency_role
            + ")"
        )
    report.blocked(
        "_expected_rows / _expected_dependencies are non-public helpers. There "
        "is no public API to project an authored map into its C0 field and "
        "dependency matrix without also supplying full B2 V2 evidence"
    )

    report.stage("V4 / V5 / B1 / B2 / C0 signed-evidence chain")
    report.blocked(
        "V4 and V5 require two independently signed build-worker attestations "
        "per role with canonical OCI index, manifest and config sidecars. No "
        "signed build worker exists for this topology, and the packaged public "
        "vectors carry public keys and signatures only, so their evidence "
        "cannot be rebound to this map"
    )
    report.blocked(
        "B1, B2 V2 and C0 each rerun the whole upstream chain on every call "
        "and accept no upstream acceptance as input, so all three are "
        "unreachable for an authored map until real build evidence exists"
    )

    report.stage("not expressible in this contract vocabulary")
    for missing in (
        "a model delegation endpoint, model identifier, or inference route: "
        "the vocabulary has no field of any kind for one",
        "a secret store address, project, or environment: a provider "
        "reference carries only (provider, service, account, version)",
        "delivery to a pre-existing shared service: every component is a "
        "disposable container allocated onto one of the two isolated lanes",
    ):
        report.blocked(missing)

    print(report.render())
    if report.failed:
        print("\nRESULT: FAILED")
        return 1
    print("\nRESULT: every runnable stage passed; blocked stages are listed above")
    return 0


if __name__ == "__main__":
    sys.exit(main())
