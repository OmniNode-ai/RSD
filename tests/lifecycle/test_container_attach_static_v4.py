"""Adversarial offline tests for V4 output-independent target primitives."""

from __future__ import annotations

import ast
import base64
import hashlib
import importlib.util
import ipaddress
import json
import re
import sys
from datetime import UTC, datetime
from pathlib import Path
from typing import Any, cast
from urllib.parse import urlsplit

import pytest
import yaml
from cryptography.hazmat.primitives.asymmetric.ed25519 import (
    Ed25519PrivateKey,
)

from omninode_rsd.lifecycle import container_attach_static_v4 as static_v4
from omninode_rsd.lifecycle.container_attach_static_v4 import (
    ContainerAttachAuthorizationTicketV4,
    ContainerAttachRequestV4,
    ContainerAttachRuntimeBindingV4,
    ContainerAttachStaticV4Error,
    ContainerAttachTicketEnvelopeV4,
    ContainerAttachV4ClaimIntentV4,
    ContainerAttachV4ClaimPreparationV4,
    ContainerAttachV4ReceiptValidationV4,
    ContainerAttachV4ReplayClaimReceiptV4,
    ContainerAttachV4ReplayReceiptTrustAnchorV4,
    ContainerBootstrapAttachProtocolV4,
    ContainerBootstrapStaticDeliveryFieldV4,
    ContainerBootstrapStaticDeliveryProjectionV4,
    ContainerBootstrapStaticDeliveryRouteV4,
    ContainerBootstrapStaticLaunchPlanV4,
    ContainerBootstrapStaticPatchPolicyV4,
    ContainerBootstrapStaticPatchPreimageV4,
    ContainerBootstrapStaticPostgreSQLUriGrammarV4,
    ContainerBootstrapStaticProfileTrustAnchorV4,
    ContainerBootstrapStaticRoleProfileEnvelopeV4,
    ContainerBootstrapStaticValkeyUriGrammarV4,
    build_container_bootstrap_static_role_profile_v4,
    container_attach_v4_claim_intent_canonical_json,
    container_attach_v4_claim_preparation_canonical_json,
    container_attach_v4_container_lifetime_claim_sha256,
    container_attach_v4_replay_claim_receipt_canonical_message,
    container_attach_v4_replay_claim_sha256,
    container_attach_v4_request_canonical_json,
    container_attach_v4_request_sha256,
    container_attach_v4_runtime_instance_binding_sha256,
    container_attach_v4_ticket_canonical_message,
    container_attach_v4_ticket_replay_claim_sha256,
    container_bootstrap_attach_v4_protocol_sha256,
    container_bootstrap_static_delivery_projection_v4_canonical_json,
    container_bootstrap_static_delivery_projection_v4_sha256,
    container_bootstrap_static_launch_plan_v4_sha256,
    container_bootstrap_static_patch_preimage_v4_sha256,
    container_bootstrap_static_role_profile_envelope_v4_canonical_message,
    container_bootstrap_static_role_profile_envelope_v4_sha256,
    container_bootstrap_static_role_profile_v4_canonical_json,
    container_bootstrap_static_role_profile_v4_sha256,
    container_bootstrap_static_uri_grammar_v4_sha256,
    container_bootstrap_static_valkey_launch_policy_v4_sha256,
    parse_container_attach_v4_request_canonical_json,
    parse_container_bootstrap_static_delivery_projection_v4_canonical_json,
    prepare_container_attach_v4_claim_intent,
    project_target_delivery_map_v1_structurally,
    validate_container_attach_v4_claim_receipt,
)
from omninode_rsd.lifecycle.infisical_disposable import (
    ContainerAttachTicketTrustAnchorV1,
    ContainerBootstrapEnvironmentConstructionPolicyV2,
    ContainerBootstrapStaticEnvironmentEntryV2,
    ContainerBootstrapStaticEnvironmentV2,
    ProviderReferencesV2,
    canonical_sha256,
    container_bootstrap_environment_construction_policy_sha256,
    container_bootstrap_valkey_static_configuration_sha256,
    postgresql_connection_uri_rendered_byte_count,
    valkey_connection_uri_rendered_byte_count,
)


def _load_v2_fixtures() -> Any:
    """Load public value-free V2 fixtures without making ``tests`` a package."""

    path = Path(__file__).with_name("test_container_attach_v2.py")
    spec = importlib.util.spec_from_file_location("_rsd_v4_v2_fixtures", path)
    if spec is None or spec.loader is None:
        raise RuntimeError("V2 fixture module is unavailable")
    module = importlib.util.module_from_spec(spec)
    sys.modules[spec.name] = module
    spec.loader.exec_module(module)
    return module


v2_fixtures = _load_v2_fixtures()
_SIGNER = Ed25519PrivateKey.from_private_bytes(b"4" * 32)
_PUBLIC = _SIGNER.public_key().public_bytes_raw()
_PROFILE_SIGNER = Ed25519PrivateKey.from_private_bytes(b"5" * 32)
_PROFILE_PUBLIC = _PROFILE_SIGNER.public_key().public_bytes_raw()
_REPLAY_SIGNER = Ed25519PrivateKey.from_private_bytes(b"6" * 32)
_REPLAY_PUBLIC = _REPLAY_SIGNER.public_key().public_bytes_raw()
_NOW = datetime(2026, 8, 29, 12, 1, tzinfo=UTC)
_VECTOR_PATH = (
    Path(__file__).parents[2]
    / "src"
    / "omninode_rsd"
    / "lifecycle"
    / "container_attach_static_v4_vectors.yaml"
)
_VECTOR_BASE64_SEGMENT_CHARS = 16
_VECTOR_BASE64_ENCODING = "standard_base64_fixed_segments_v1"
_DOCUMENTATION_NETWORKS = (
    ipaddress.ip_network("192.0.2.0/24"),
    ipaddress.ip_network("198.51.100.0/24"),
    ipaddress.ip_network("203.0.113.0/24"),
)
# These are public PostgreSQL and Valkey grammar constants, not published
# endpoints or deployment values. The vector authorities themselves use only
# RFC 5737 documentation addresses.
_POSTGRESQL_PROTOCOL_PORT = 5432
_VALKEY_PROTOCOL_PORT = 6379
_VECTOR_POSTGRESQL_AUTHORITY = f"postgresql://203.0.113.40:{_POSTGRESQL_PROTOCOL_PORT}"
_VECTOR_PRIMARY_VALKEY_BIND_ADDRESS = "203.0.113.30"
_VECTOR_RESTORE_VALKEY_BIND_ADDRESS = "198.51.100.30"
_VECTOR_PRIMARY_VALKEY_AUTHORITY = "redis://203.0.113.30:6379"
_VECTOR_RESTORE_VALKEY_AUTHORITY = "redis://198.51.100.30:6379"
_VECTOR_ALLOWED_URI_PORTS = frozenset((_POSTGRESQL_PROTOCOL_PORT, _VALKEY_PROTOCOL_PORT))


class _StrictVectorLoader(yaml.SafeLoader):
    """Reject duplicate YAML keys in the public cross-language vector."""


def _strict_mapping(
    loader: yaml.SafeLoader, node: yaml.MappingNode, deep: bool = False
) -> dict[object, object]:
    """Construct one mapping while rejecting duplicate scalar keys."""

    mapping: dict[object, object] = {}
    for key_node, value_node in node.value:
        key = loader.construct_object(key_node, deep=deep)
        if key in mapping:
            raise ValueError("duplicate V4 vector key")
        mapping[key] = loader.construct_object(value_node, deep=deep)
    return mapping


_StrictVectorLoader.add_constructor(
    yaml.resolver.BaseResolver.DEFAULT_MAPPING_TAG,
    _strict_mapping,
)


def _hash(label: str) -> str:
    return hashlib.sha256(label.encode("ascii")).hexdigest()


def _signature(message: bytes) -> str:
    return base64.b64encode(_SIGNER.sign(message)).decode("ascii")


def _canonical_vector_base64(value: object) -> bytes:
    """Decode one exact fixed-segment standard-base64 vector spelling."""

    if type(value) is not dict or set(value) != {"encoding", "segments"}:
        raise ValueError("V4 vector base64 is invalid")
    encoding = value["encoding"]
    segments = value["segments"]
    if (
        type(encoding) is not str
        or encoding != _VECTOR_BASE64_ENCODING
        or type(segments) is not list
        or not segments
        or any(type(segment) is not str for segment in segments)
        or any(len(segment) != _VECTOR_BASE64_SEGMENT_CHARS for segment in segments[:-1])
        or not 1 <= len(segments[-1]) <= _VECTOR_BASE64_SEGMENT_CHARS
    ):
        raise ValueError("V4 vector base64 is invalid")
    compact = "".join(cast(list[str], segments))
    decoded = base64.b64decode(compact, validate=True)
    if _vector_base64(decoded) != value:
        raise ValueError("V4 vector base64 is not canonical")
    return decoded


def _updated_fields(model: object, **changes: object) -> dict[str, object]:
    fields = cast(Any, model).model_dump(mode="python")
    fields.update(changes)
    return cast(dict[str, object], fields)


def _documentation_uri_field(
    field: ContainerBootstrapStaticDeliveryFieldV4,
    grammar: ContainerBootstrapStaticPostgreSQLUriGrammarV4
    | ContainerBootstrapStaticValkeyUriGrammarV4,
) -> ContainerBootstrapStaticDeliveryFieldV4:
    """Rebind one derived descriptor to an explicit public vector grammar."""

    return ContainerBootstrapStaticDeliveryFieldV4(
        **_updated_fields(
            field,
            encoded_byte_count=grammar.rendered_uri_byte_count,
            derivation_binding_sha256=container_bootstrap_static_uri_grammar_v4_sha256(grammar),
        )
    )


def _documentation_route(
    route: ContainerBootstrapStaticDeliveryRouteV4,
    *,
    postgresql: ContainerBootstrapStaticPostgreSQLUriGrammarV4 | None,
    valkey: ContainerBootstrapStaticValkeyUriGrammarV4 | None,
) -> ContainerBootstrapStaticDeliveryRouteV4:
    """Return one route with only its target-URI descriptor commitments changed."""

    fields: list[ContainerBootstrapStaticDeliveryFieldV4] = []
    for field in route.fields:
        if field.target_field == "DB_CONNECTION_URI" and postgresql is not None:
            fields.append(_documentation_uri_field(field, postgresql))
        elif field.target_field == "REDIS_URL" and valkey is not None:
            fields.append(_documentation_uri_field(field, valkey))
        else:
            fields.append(field)
    return ContainerBootstrapStaticDeliveryRouteV4(**_updated_fields(route, fields=tuple(fields)))


def _documentation_delivery_projection(
    projection: ContainerBootstrapStaticDeliveryProjectionV4,
) -> ContainerBootstrapStaticDeliveryProjectionV4:
    """Create the vector-only projection with RFC 5737 authorities.

    This fixture intentionally proves parser/hash interoperability with public
    documentation addresses. It does not alter or stand in for the separately
    authenticated V1 map that a later closure must verify.
    """

    primary_postgresql = ContainerBootstrapStaticPostgreSQLUriGrammarV4(
        **_updated_fields(
            projection.primary_postgresql_connection_uri,
            authority=_VECTOR_POSTGRESQL_AUTHORITY,
            rendered_uri_byte_count=postgresql_connection_uri_rendered_byte_count(
                authority=_VECTOR_POSTGRESQL_AUTHORITY,
                application_role=projection.primary_postgresql_connection_uri.application_role,
                database_name=projection.primary_postgresql_connection_uri.database_name,
            ),
        )
    )
    restore_postgresql = ContainerBootstrapStaticPostgreSQLUriGrammarV4(
        **_updated_fields(
            projection.restore_postgresql_connection_uri,
            authority=_VECTOR_POSTGRESQL_AUTHORITY,
            rendered_uri_byte_count=postgresql_connection_uri_rendered_byte_count(
                authority=_VECTOR_POSTGRESQL_AUTHORITY,
                application_role=projection.restore_postgresql_connection_uri.application_role,
                database_name=projection.restore_postgresql_connection_uri.database_name,
            ),
        )
    )
    primary_valkey = ContainerBootstrapStaticValkeyUriGrammarV4(
        **_updated_fields(
            projection.primary_valkey_connection_uri,
            authority=_VECTOR_PRIMARY_VALKEY_AUTHORITY,
            rendered_uri_byte_count=valkey_connection_uri_rendered_byte_count(
                authority=_VECTOR_PRIMARY_VALKEY_AUTHORITY,
                database_index=projection.primary_valkey_connection_uri.database_index,
            ),
        )
    )
    restore_valkey = ContainerBootstrapStaticValkeyUriGrammarV4(
        **_updated_fields(
            projection.restore_valkey_connection_uri,
            authority=_VECTOR_RESTORE_VALKEY_AUTHORITY,
            rendered_uri_byte_count=valkey_connection_uri_rendered_byte_count(
                authority=_VECTOR_RESTORE_VALKEY_AUTHORITY,
                database_index=projection.restore_valkey_connection_uri.database_index,
            ),
        )
    )
    return ContainerBootstrapStaticDeliveryProjectionV4(
        **_updated_fields(
            projection,
            primary_postgresql_connection_uri=primary_postgresql,
            restore_postgresql_connection_uri=restore_postgresql,
            primary_valkey_connection_uri=primary_valkey,
            restore_valkey_connection_uri=restore_valkey,
            primary_infisical=_documentation_route(
                projection.primary_infisical,
                postgresql=primary_postgresql,
                valkey=primary_valkey,
            ),
            restore_infisical=_documentation_route(
                projection.restore_infisical,
                postgresql=restore_postgresql,
                valkey=restore_valkey,
            ),
        )
    )


def _documentation_valkey_launch_policy(policy: object, *, bind_address: str) -> object:
    """Recompute one vector-only Valkey static policy for a documented address."""

    original = cast(Any, policy)
    draft = original.model_copy(
        update={"isolated_bind_address": bind_address, "static_configuration_sha256": "0" * 64}
    )
    return type(original)(
        **_updated_fields(
            original,
            isolated_bind_address=bind_address,
            static_configuration_sha256=container_bootstrap_valkey_static_configuration_sha256(
                draft
            ),
        )
    )


def _anchor(*, key_id: str = "v4-signer") -> ContainerAttachTicketTrustAnchorV1:
    return ContainerAttachTicketTrustAnchorV1(
        schema_version="rsd.container-attach-ticket-trust-anchor.v1",
        key_id=key_id,
        public_key_base64=base64.b64encode(_PUBLIC).decode("ascii"),
        public_key_fingerprint_sha256=hashlib.sha256(_PUBLIC).hexdigest(),
        algorithm="ed25519",
    )


def _profile_trust_anchor() -> ContainerBootstrapStaticProfileTrustAnchorV4:
    """Return the separately pinned public profile-integrity root."""

    return ContainerBootstrapStaticProfileTrustAnchorV4(
        schema_version="rsd.container-bootstrap-static-profile-trust-anchor.v4",
        key_id="v4-profile-root",
        public_key_base64=base64.b64encode(_PROFILE_PUBLIC).decode("ascii"),
        public_key_fingerprint_sha256=hashlib.sha256(_PROFILE_PUBLIC).hexdigest(),
        algorithm="ed25519",
    )


def _replay_receipt_trust_anchor() -> ContainerAttachV4ReplayReceiptTrustAnchorV4:
    """Return the independently pinned public external replay-receipt root."""

    return ContainerAttachV4ReplayReceiptTrustAnchorV4(
        schema_version="rsd.container-attach-replay-receipt-trust-anchor.v4",
        key_id="v4-replay-root",
        public_key_base64=base64.b64encode(_REPLAY_PUBLIC).decode("ascii"),
        public_key_fingerprint_sha256=hashlib.sha256(_REPLAY_PUBLIC).hexdigest(),
        algorithm="ed25519",
    )


def _profile_envelope(
    profile: object,
) -> ContainerBootstrapStaticRoleProfileEnvelopeV4:
    """Sign one test-only profile identity under its independent profile root."""

    profile_model = cast(Any, profile)
    unsigned = ContainerBootstrapStaticRoleProfileEnvelopeV4(
        schema_version="rsd.container-bootstrap-static-role-profile-envelope.v4",
        static_role_profile=profile_model,
        static_role_profile_sha256=container_bootstrap_static_role_profile_v4_sha256(profile_model),
        signer_key_id="v4-profile-root",
        signature_base64=base64.b64encode(b"p" * 64).decode("ascii"),
    )
    return unsigned.model_copy(
        update={
            "signature_base64": base64.b64encode(
                _PROFILE_SIGNER.sign(
                    container_bootstrap_static_role_profile_envelope_v4_canonical_message(unsigned)
                )
            ).decode("ascii")
        }
    )


def _protocol() -> ContainerBootstrapAttachProtocolV4:
    return ContainerBootstrapAttachProtocolV4(
        schema_version="rsd.container-bootstrap-attach-protocol.v4",
        protocol_name="rsd_container_bootstrap_attach_v4",
        frame_magic="ONC4",
        frame_version=4,
        metadata_encoding="canonical_json_utf8_v1",
        frame_header_layout="magic_4_version_u8_type_u8_length_u32be_v1",
        secret_chunk_ordinal_layout="u16be_v1",
        allowed_operation_scopes=("materialize_and_start_runtime_v1", "start_runtime_v2"),
        first_frame="ticket_envelope_v4",
        ready_state="ready_v4",
        claim_state="claimed_v4",
        write_closed_state="write_closed_v4",
        terminal_ack_state="terminal_ack_v4",
        ambiguous_state="attach_ambiguous_v4",
        max_metadata_bytes=8192,
        max_chunk_bytes=4096,
        max_chunks_per_target=4,
        max_total_secret_bytes=16384,
        max_stdout_bytes=65536,
        max_stdout_frames=32,
        ready_timeout_seconds=10,
        claim_timeout_seconds=10,
        terminal_ack_timeout_seconds=10,
        absolute_timeout_seconds=30,
        max_ticket_lifetime_seconds=300,
        docker_non_tty_required=True,
        docker_stdout_only_required=True,
        docker_stderr_rejected=True,
        actual_write_half_close_required=True,
        eof_required_before_terminal_ack=True,
        protocol_output_eof_required_after_terminal_ack=True,
        one_attach_per_container_lifetime=True,
        replay_allowed=False,
        auto_retry_after_secret_delivery_allowed=False,
        secret_persistence_allowed=False,
        secret_logging_allowed=False,
        secret_receipt_allowed=False,
    )


def _launch(component: str, artifact: object) -> ContainerBootstrapStaticLaunchPlanV4:
    source = cast(Any, artifact)
    base = source.base_image_policy
    prefix = ("/usr/local/libexec/omninode-rsd-bootstrap-v4",)
    entrypoint = cast(tuple[str, ...], source.base_entrypoint)
    command = cast(tuple[str, ...], source.base_command)
    return ContainerBootstrapStaticLaunchPlanV4(
        schema_version="rsd.container-bootstrap-static-launch-plan.v4",
        component=cast(Any, component),
        component_role="valkey" if component.endswith("valkey") else "infisical",
        base_image_policy_sha256=canonical_sha256(base),
        base_resolution_attestation_sha256=canonical_sha256(base.resolution_attestation),
        base_registry_index_digest_sha256=base.registry_index_digest_sha256,
        base_linux_amd64_manifest_digest_sha256=base.linux_amd64_manifest_digest_sha256,
        base_config_digest_sha256=base.config_digest_sha256,
        wrapper_executable_path=prefix[0],
        wrapper_argv_prefix=prefix,
        base_entrypoint=entrypoint,
        base_command=command,
        entrypoint_command_merge="exec_wrapper_then_base_entrypoint_and_cmd_v4",
        merged_argv_sha256=static_v4._merged_argv_sha256(
            wrapper_argv_prefix=prefix,
            base_entrypoint=entrypoint,
            base_command=command,
        ),
    )


def _patch(
    component: str,
    *,
    static_launch_plan: ContainerBootstrapStaticLaunchPlanV4,
    static_environment: object,
    child_environment_policy: object,
    valkey_launch_policy: object,
) -> tuple[ContainerBootstrapStaticPatchPreimageV4, ContainerBootstrapStaticPatchPolicyV4]:
    is_valkey = component.endswith("valkey")
    environment = cast(Any, static_environment)
    child_policy = cast(Any, child_environment_policy)
    valkey_policy = cast(Any, valkey_launch_policy)
    preimage = ContainerBootstrapStaticPatchPreimageV4(
        schema_version="rsd.container-bootstrap-static-patch-preimage.v4",
        wrapper_source_tree_sha256=_hash(f"{component}-source-tree"),
        component=cast(Any, component),
        component_role="valkey" if component.endswith("valkey") else "infisical",
        patch_kind=(
            "valkey_stdin_launcher_and_acl_v4"
            if is_valkey
            else "infisical_no_write_launcher_and_envp_v4"
        ),
        patch_content_sha256=_hash(f"{component}-static-source-patch"),
        static_launch_plan_sha256=container_bootstrap_static_launch_plan_v4_sha256(
            static_launch_plan
        ),
        child_environment_policy_sha256=(
            container_bootstrap_environment_construction_policy_sha256(child_policy)
        ),
        static_environment_sha256=environment.environment_sha256,
        valkey_static_configuration_sha256=(
            container_bootstrap_valkey_static_configuration_sha256(valkey_policy)
            if is_valkey
            else None
        ),
        valkey_launch_policy_sha256=(
            container_bootstrap_static_valkey_launch_policy_v4_sha256(valkey_policy)
            if is_valkey
            else None
        ),
        infisical_ca_updater_allowed=False,
        infisical_explicit_target_envp_required=not is_valkey,
        mutable_configuration_carrier_allowed=False,
        secret_carrier_allowed=False,
        provider_access_allowed=False,
        network_access_allowed=False,
        filesystem_output_binding_allowed=False,
        artifact_output_binding_allowed=False,
        derived_image_output_binding_allowed=False,
        provenance_sbom_repro_output_binding_allowed=False,
    )
    policy = ContainerBootstrapStaticPatchPolicyV4(
        schema_version="rsd.container-bootstrap-static-patch-policy.v4",
        preimage=preimage,
        static_patch_preimage_sha256=container_bootstrap_static_patch_preimage_v4_sha256(preimage),
        patch_policy_intent="compile_static_target_inputs_only_v4",
        wrapper_bytes_claimed=False,
        generated_artifact_claimed=False,
        generated_image_claimed=False,
        generated_provenance_claimed=False,
        generated_sbom_claimed=False,
        generated_reproducibility_claimed=False,
    )
    return preimage, policy


def _maximum_public_static_environment_entries(
    *, prefix: str, count: int
) -> tuple[ContainerBootstrapStaticEnvironmentEntryV2, ...]:
    """Build valid maximum-length nonsecret V2 static entries for a cap test."""

    return tuple(
        ContainerBootstrapStaticEnvironmentEntryV2(
            name=f"{prefix}{str(index).zfill(3)}" + "X" * (128 - len(prefix) - 3),
            value="x" * 1024,
        )
        for index in range(count)
    )


def _maximum_public_v4_profile(tmp_path: Path) -> tuple[object, object, object, object]:
    """Construct a legal maximum-shape V4 graph without any target value."""

    bundle = _bundle(tmp_path)
    component = "primary_infisical"
    static_entries = _maximum_public_static_environment_entries(prefix="STATIC", count=64)
    static_rendered = tuple(entry.rendered for entry in static_entries)
    static_environment = ContainerBootstrapStaticEnvironmentV2(
        schema_version="rsd.container-bootstrap-static-environment.v2",
        entries=static_entries,
        environment_sha256=hashlib.sha256(
            json.dumps(static_rendered, separators=(",", ":")).encode("utf-8")
        ).hexdigest(),
        target_delivery_fields_forbidden=True,
        inherited_environment_allowed=False,
    )
    child_entries = _maximum_public_static_environment_entries(prefix="CHILD", count=32)
    child_rendered = tuple(entry.rendered for entry in child_entries)
    child_policy = ContainerBootstrapEnvironmentConstructionPolicyV2(
        schema_version="rsd.container-bootstrap-environment-construction-policy.v2",
        component=component,
        host_environment_allowed=False,
        env_file_allowed=False,
        docker_config_environment_allowed=False,
        inherited_environment_cleared_before_child_exec=True,
        inherited_environment_read_allowed=False,
        inherited_environment_pass_through_allowed=False,
        explicit_child_envp_required=True,
        global_setenv_for_target_values_allowed=False,
        static_entries=child_entries,
        static_environment_sha256=hashlib.sha256(
            json.dumps(child_rendered, separators=(",", ":")).encode("utf-8")
        ).hexdigest(),
        image_static_environment_sha256=static_environment.environment_sha256,
        dynamic_target_field_names=(
            "ENCRYPTION_KEY",
            "AUTH_SECRET",
            "DB_CONNECTION_URI",
            "REDIS_URL",
        ),
        wrapper_network_client_allowed=False,
        telemetry_environment_allowed=False,
        target_value_in_argv_allowed=False,
        target_value_in_file_allowed=False,
        target_value_in_logs_allowed=False,
    )
    original_launch = cast(Any, bundle["profile"]).static_launch_plan
    maximal_args = (
        original_launch.wrapper_executable_path,
        *("a" * 256 for _ in range(63)),
    )
    launch = ContainerBootstrapStaticLaunchPlanV4(
        **_updated_fields(
            original_launch,
            wrapper_argv_prefix=maximal_args,
            base_entrypoint=maximal_args,
            base_command=maximal_args,
            merged_argv_sha256=static_v4._merged_argv_sha256(
                wrapper_argv_prefix=maximal_args,
                base_entrypoint=maximal_args,
                base_command=maximal_args,
            ),
        )
    )
    preimage, patch = _patch(
        component,
        static_launch_plan=launch,
        static_environment=static_environment,
        child_environment_policy=child_policy,
        valkey_launch_policy=None,
    )
    source = cast(Any, bundle["profile"])
    profile = build_container_bootstrap_static_role_profile_v4(
        wrapper_source_tree_sha256=_hash(f"{component}-source-tree"),
        component=component,
        component_role="infisical",
        compile_target="x86_64-unknown-linux-musl",
        wrapper_executable_path=source.wrapper_executable_path,
        wrapper_executable_mode="0555",
        wrapper_executable_symlink_allowed=False,
        ticket_trust_anchor=source.ticket_trust_anchor,
        replay_receipt_trust_anchor=source.replay_receipt_trust_anchor,
        attach_protocol=source.attach_protocol,
        static_delivery_projection=source.static_delivery_projection,
        selected_delivery_route=source.selected_delivery_route,
        static_launch_plan=launch,
        static_patch_preimage=preimage,
        static_patch_policy=patch,
        static_environment=static_environment,
        child_environment_policy=child_policy,
        fd_policy=source.fd_policy,
        pid1_policy=source.pid1_policy,
        memory_safety_policy=source.memory_safety_policy,
        valkey_launch_policy=None,
    )
    profile_envelope = _profile_envelope(profile)
    request = cast(Any, bundle["request"]).model_copy(
        update={
            "static_role_profile_sha256": profile.profile_sha256,
            "static_role_profile_envelope_sha256": (
                container_bootstrap_static_role_profile_envelope_v4_sha256(profile_envelope)
            ),
        }
    )
    ticket = _resign_ticket_for_request(cast(Any, bundle["ticket"]), request)
    envelope = ContainerAttachTicketEnvelopeV4(
        schema_version="rsd.container-attach-ticket-envelope.v4",
        request=request,
        ticket=ticket,
    )
    return profile, profile_envelope, envelope, bundle["runtime"]


def _bundle(
    tmp_path: Path,
    *,
    component: str = "primary_infisical",
    documentation_authorities: bool = False,
) -> dict[str, object]:
    """Build pure V4 static inputs and a signed dynamic ticket fixture."""

    controls = v2_fixtures._controls(tmp_path, component=component)
    delivery_map = cast(Any, controls["delivery_map"])
    projection = project_target_delivery_map_v1_structurally(delivery_map)
    artifact = cast(Any, controls["manifest"]).__getattribute__(component)
    if documentation_authorities:
        projection = _documentation_delivery_projection(projection)
        if component.endswith("valkey"):
            bind_address = (
                _VECTOR_PRIMARY_VALKEY_BIND_ADDRESS
                if component == "primary_valkey"
                else _VECTOR_RESTORE_VALKEY_BIND_ADDRESS
            )
            artifact = artifact.model_copy(
                update={
                    "valkey_launch_policy": _documentation_valkey_launch_policy(
                        artifact.valkey_launch_policy,
                        bind_address=bind_address,
                    )
                }
            )
    route = getattr(projection, component)
    launch = _launch(component, artifact)
    preimage, patch = _patch(
        component,
        static_launch_plan=launch,
        static_environment=artifact.static_environment,
        child_environment_policy=artifact.child_environment_policy,
        valkey_launch_policy=artifact.valkey_launch_policy,
    )
    replay_receipt_trust_anchor = _replay_receipt_trust_anchor()
    profile = build_container_bootstrap_static_role_profile_v4(
        wrapper_source_tree_sha256=_hash(f"{component}-source-tree"),
        component=cast(Any, component),
        component_role="valkey" if component.endswith("valkey") else "infisical",
        compile_target="x86_64-unknown-linux-musl",
        wrapper_executable_path="/usr/local/libexec/omninode-rsd-bootstrap-v4",
        wrapper_executable_mode="0555",
        wrapper_executable_symlink_allowed=False,
        ticket_trust_anchor=_anchor(),
        replay_receipt_trust_anchor=replay_receipt_trust_anchor,
        attach_protocol=_protocol(),
        static_delivery_projection=projection,
        selected_delivery_route=route,
        static_launch_plan=launch,
        static_patch_preimage=preimage,
        static_patch_policy=patch,
        static_environment=artifact.static_environment,
        child_environment_policy=artifact.child_environment_policy,
        fd_policy=artifact.fd_policy,
        pid1_policy=artifact.pid1_policy,
        memory_safety_policy=artifact.memory_safety_policy,
        valkey_launch_policy=artifact.valkey_launch_policy,
    )
    profile_trust_anchor = _profile_trust_anchor()
    profile_envelope = _profile_envelope(profile)
    container_id = "c" * 64 if component == "primary_infisical" else _hash(f"{component}-container")
    hostname = (
        "rsd-runtime-hostname-123456"
        if component == "primary_infisical"
        else f"rsd-{component.replace('_', '-')}-runtime-123456"
    )
    runtime = ContainerAttachRuntimeBindingV4(
        schema_version="rsd.container-attach-runtime-binding.v4",
        allocation_operation_id="123e4567-e89b-42d3-a456-426614174000",
        operation_scope="materialize_and_start_runtime_v1",
        operation_id="123e4567-e89b-42d3-a456-426614174001",
        component=cast(Any, component),
        component_role="valkey" if component.endswith("valkey") else "infisical",
        container_id=container_id,
        runtime_hostname=hostname,
        runtime_instance_binding_sha256=container_attach_v4_runtime_instance_binding_sha256(
            container_id=container_id, runtime_hostname=hostname
        ),
        request_nonce_sha256=_hash(f"{component}-nonce"),
        channel_binding_sha256=_hash(f"{component}-channel"),
        session_binding_sha256=_hash(f"{component}-session"),
    )
    request = ContainerAttachRequestV4(
        schema_version="rsd.container-attach-request.v4",
        allocation_operation_id=runtime.allocation_operation_id,
        operation_scope=runtime.operation_scope,
        operation_id=runtime.operation_id,
        component=runtime.component,
        component_role=runtime.component_role,
        container_id=runtime.container_id,
        runtime_hostname=runtime.runtime_hostname,
        runtime_instance_binding_sha256=runtime.runtime_instance_binding_sha256,
        static_role_profile_sha256=container_bootstrap_static_role_profile_v4_sha256(profile),
        static_role_profile_envelope_sha256=(
            container_bootstrap_static_role_profile_envelope_v4_sha256(profile_envelope)
        ),
        static_profile_trust_anchor_fingerprint_sha256=(
            profile_trust_anchor.public_key_fingerprint_sha256
        ),
        replay_receipt_trust_anchor_key_id=replay_receipt_trust_anchor.key_id,
        replay_receipt_trust_anchor_fingerprint_sha256=(
            replay_receipt_trust_anchor.public_key_fingerprint_sha256
        ),
        static_delivery_projection_sha256=container_bootstrap_static_delivery_projection_v4_sha256(
            projection
        ),
        selected_delivery_route_sha256=static_v4.container_bootstrap_static_delivery_route_v4_sha256(
            route
        ),
        attach_protocol_v4_sha256=container_bootstrap_attach_v4_protocol_sha256(
            profile.attach_protocol
        ),
        request_nonce_sha256=runtime.request_nonce_sha256,
        channel_binding_sha256=runtime.channel_binding_sha256,
        session_binding_sha256=runtime.session_binding_sha256,
        expected_ready_state="ready_v4",
        expected_claim_state="claimed_v4",
        expected_terminal_ack_state="terminal_ack_v4",
        fields=route.fields,
    )
    unsigned = ContainerAttachAuthorizationTicketV4(
        schema_version="rsd.container-attach-authorization-ticket.v4",
        protocol_sha256=request.attach_protocol_v4_sha256,
        request_sha256=container_attach_v4_request_sha256(request),
        allocation_operation_id=request.allocation_operation_id,
        operation_scope=request.operation_scope,
        operation_id=request.operation_id,
        component=request.component,
        component_role=request.component_role,
        container_id=request.container_id,
        runtime_hostname=request.runtime_hostname,
        runtime_instance_binding_sha256=request.runtime_instance_binding_sha256,
        static_role_profile_sha256=request.static_role_profile_sha256,
        static_role_profile_envelope_sha256=request.static_role_profile_envelope_sha256,
        static_profile_trust_anchor_fingerprint_sha256=(
            request.static_profile_trust_anchor_fingerprint_sha256
        ),
        replay_receipt_trust_anchor_key_id=request.replay_receipt_trust_anchor_key_id,
        replay_receipt_trust_anchor_fingerprint_sha256=(
            request.replay_receipt_trust_anchor_fingerprint_sha256
        ),
        static_delivery_projection_sha256=request.static_delivery_projection_sha256,
        selected_delivery_route_sha256=request.selected_delivery_route_sha256,
        request_nonce_sha256=request.request_nonce_sha256,
        channel_binding_sha256=request.channel_binding_sha256,
        session_binding_sha256=request.session_binding_sha256,
        issued_at="2026-08-29T12:00:00Z",
        expires_at="2026-08-29T12:05:00Z",
        signer_key_id="v4-signer",
        signature_base64=base64.b64encode(b"x" * 64).decode("ascii"),
    )
    ticket = unsigned.model_copy(
        update={
            "signature_base64": _signature(container_attach_v4_ticket_canonical_message(unsigned))
        }
    )
    envelope = ContainerAttachTicketEnvelopeV4(
        schema_version="rsd.container-attach-ticket-envelope.v4",
        request=request,
        ticket=ticket,
    )
    return {
        "controls": controls,
        "projection": projection,
        "route": route,
        "profile": profile,
        "profile_envelope": profile_envelope,
        "profile_trust_anchor": profile_trust_anchor,
        "replay_receipt_trust_anchor": replay_receipt_trust_anchor,
        "runtime": runtime,
        "request": request,
        "ticket": ticket,
        "envelope": envelope,
    }


def _public_vector_data(tmp_path: Path) -> dict[str, object]:
    """Build deterministic public V4 vector objects without target values.

    The vector deliberately starts from the ordinary value-free fixture rather
    than an artifact, a wrapper byte stream, or a runtime adapter.  Its
    RFC-5737 authority substitution is vector-only: it is not an authenticated
    V1-map attestation.  It exposes the canonical interoperability graph only.
    """

    bundle = _bundle(
        tmp_path,
        component="primary_valkey",
        documentation_authorities=True,
    )
    profile = cast(Any, bundle["profile"])
    profile_envelope = cast(Any, bundle["profile_envelope"])
    profile_trust_anchor = cast(Any, bundle["profile_trust_anchor"])
    replay_receipt_trust_anchor = cast(Any, bundle["replay_receipt_trust_anchor"])
    request = cast(Any, bundle["request"])
    ticket = cast(Any, bundle["ticket"])
    runtime = cast(Any, bundle["runtime"])
    validation = static_v4.ContainerAttachV4TicketValidation(
        schema_version="rsd.container-attach-ticket-validation.v4",
        component=profile.component,
        component_role=profile.component_role,
        static_role_profile_sha256=profile.profile_sha256,
        static_role_profile_envelope_sha256=(
            container_bootstrap_static_role_profile_envelope_v4_sha256(profile_envelope)
        ),
        static_profile_trust_anchor_fingerprint_sha256=(
            profile_trust_anchor.public_key_fingerprint_sha256
        ),
        replay_receipt_trust_anchor_key_id=(profile.replay_receipt_trust_anchor.key_id),
        replay_receipt_trust_anchor_fingerprint_sha256=(
            profile.replay_receipt_trust_anchor.public_key_fingerprint_sha256
        ),
        static_delivery_projection_sha256=(
            container_bootstrap_static_delivery_projection_v4_sha256(
                profile.static_delivery_projection
            )
        ),
        selected_delivery_route_sha256=(
            static_v4.container_bootstrap_static_delivery_route_v4_sha256(
                profile.selected_delivery_route
            )
        ),
        attach_protocol_v4_sha256=container_bootstrap_attach_v4_protocol_sha256(
            profile.attach_protocol
        ),
        request_sha256=container_attach_v4_request_sha256(request),
        ticket_sha256=static_v4.container_attach_v4_ticket_sha256(ticket),
        request_nonce_sha256=request.request_nonce_sha256,
        channel_binding_sha256=request.channel_binding_sha256,
        session_binding_sha256=request.session_binding_sha256,
        allocation_operation_id=request.allocation_operation_id,
        operation_scope=request.operation_scope,
        operation_id=request.operation_id,
        container_id=request.container_id,
        runtime_hostname=request.runtime_hostname,
        runtime_instance_binding_sha256=request.runtime_instance_binding_sha256,
        freshness_checked_at="2026-08-29T12:01:00Z",
        issued_at=ticket.issued_at,
        expires_at=ticket.expires_at,
        claim_timeout_seconds=profile.attach_protocol.claim_timeout_seconds,
        max_ticket_lifetime_seconds=profile.attach_protocol.max_ticket_lifetime_seconds,
    )
    replay_claim = static_v4._replay_claim_from_validation(validation)
    deadline = static_v4.ContainerAttachV4ClaimDeadlineV4(
        schema_version="rsd.container-attach-claim-deadline.v4",
        ticket_sha256=validation.ticket_sha256,
        ticket_expires_at=validation.expires_at,
        effective_deadline_at=validation.expires_at,
        claim_timeout_seconds=validation.claim_timeout_seconds,
        atomic_deadline_predicate_required=True,
        authority_local_monotonic_budget_required=True,
    )
    preparation = static_v4.build_container_attach_v4_claim_preparation(
        validation=validation,
        claim_deadline=deadline,
    )
    claim_intent = ContainerAttachV4ClaimIntentV4(
        schema_version="rsd.container-attach-claim-intent.v4",
        static_role_profile_envelope=profile_envelope,
        ticket_envelope=cast(Any, bundle["envelope"]),
        expected_runtime=runtime,
        preparation=preparation,
        replay_receipt_trust_anchor_key_id=(profile.replay_receipt_trust_anchor.key_id),
        replay_receipt_trust_anchor_fingerprint_sha256=(
            profile.replay_receipt_trust_anchor.public_key_fingerprint_sha256
        ),
        peer_authenticated_executor_capability_required=True,
        atomic_persistence_authorized=False,
    )
    receipt = _signed_replay_receipt(preparation)
    return {
        "profile_trust_anchor": profile_trust_anchor,
        "profile_envelope": profile_envelope,
        "projection": profile.static_delivery_projection,
        "route": profile.selected_delivery_route,
        "launch": profile.static_launch_plan,
        "preimage": profile.static_patch_preimage,
        "patch": profile.static_patch_policy,
        "profile": profile,
        "protocol": profile.attach_protocol,
        "request": request,
        "runtime": runtime,
        "ticket": ticket,
        "ticket_envelope": bundle["envelope"],
        "replay_claim": replay_claim,
        "preparation": preparation,
        "claim_intent": claim_intent,
        "replay_receipt_trust_anchor": replay_receipt_trust_anchor,
        "receipt": receipt,
    }


def _rebuild_profile(
    profile: object,
    **changes: object,
) -> object:
    """Recompute a valid V4 profile after an intentional input substitution."""

    original = cast(Any, profile)

    def selected(name: str) -> object:
        return changes[name] if name in changes else getattr(original, name)

    return build_container_bootstrap_static_role_profile_v4(
        wrapper_source_tree_sha256=cast(str, selected("wrapper_source_tree_sha256")),
        component=cast(Any, selected("component")),
        component_role=cast(Any, selected("component_role")),
        compile_target=cast(Any, selected("compile_target")),
        wrapper_executable_path=cast(str, selected("wrapper_executable_path")),
        wrapper_executable_mode=cast(Any, selected("wrapper_executable_mode")),
        wrapper_executable_symlink_allowed=cast(
            Any, selected("wrapper_executable_symlink_allowed")
        ),
        ticket_trust_anchor=cast(
            ContainerAttachTicketTrustAnchorV1, selected("ticket_trust_anchor")
        ),
        replay_receipt_trust_anchor=cast(
            ContainerAttachV4ReplayReceiptTrustAnchorV4,
            selected("replay_receipt_trust_anchor"),
        ),
        attach_protocol=cast(ContainerBootstrapAttachProtocolV4, selected("attach_protocol")),
        static_delivery_projection=cast(Any, selected("static_delivery_projection")),
        selected_delivery_route=cast(Any, selected("selected_delivery_route")),
        static_launch_plan=cast(
            ContainerBootstrapStaticLaunchPlanV4, selected("static_launch_plan")
        ),
        static_patch_preimage=cast(
            ContainerBootstrapStaticPatchPreimageV4, selected("static_patch_preimage")
        ),
        static_patch_policy=cast(
            ContainerBootstrapStaticPatchPolicyV4, selected("static_patch_policy")
        ),
        static_environment=cast(Any, selected("static_environment")),
        child_environment_policy=cast(Any, selected("child_environment_policy")),
        fd_policy=cast(Any, selected("fd_policy")),
        pid1_policy=cast(Any, selected("pid1_policy")),
        memory_safety_policy=cast(Any, selected("memory_safety_policy")),
        valkey_launch_policy=cast(Any, selected("valkey_launch_policy")),
    )


def _resign_ticket_for_request(
    ticket: ContainerAttachAuthorizationTicketV4,
    request: ContainerAttachRequestV4,
) -> ContainerAttachAuthorizationTicketV4:
    """Issue a synthetic test ticket that exactly follows one changed request."""

    unsigned = ContainerAttachAuthorizationTicketV4(
        **_updated_fields(
            ticket,
            protocol_sha256=request.attach_protocol_v4_sha256,
            request_sha256=container_attach_v4_request_sha256(request),
            allocation_operation_id=request.allocation_operation_id,
            operation_scope=request.operation_scope,
            operation_id=request.operation_id,
            component=request.component,
            component_role=request.component_role,
            container_id=request.container_id,
            runtime_hostname=request.runtime_hostname,
            runtime_instance_binding_sha256=request.runtime_instance_binding_sha256,
            static_role_profile_sha256=request.static_role_profile_sha256,
            static_role_profile_envelope_sha256=request.static_role_profile_envelope_sha256,
            static_profile_trust_anchor_fingerprint_sha256=(
                request.static_profile_trust_anchor_fingerprint_sha256
            ),
            replay_receipt_trust_anchor_key_id=(request.replay_receipt_trust_anchor_key_id),
            replay_receipt_trust_anchor_fingerprint_sha256=(
                request.replay_receipt_trust_anchor_fingerprint_sha256
            ),
            static_delivery_projection_sha256=request.static_delivery_projection_sha256,
            selected_delivery_route_sha256=request.selected_delivery_route_sha256,
            request_nonce_sha256=request.request_nonce_sha256,
            channel_binding_sha256=request.channel_binding_sha256,
            session_binding_sha256=request.session_binding_sha256,
            signature_base64=base64.b64encode(b"x" * 64).decode("ascii"),
        )
    )
    return unsigned.model_copy(
        update={
            "signature_base64": _signature(container_attach_v4_ticket_canonical_message(unsigned))
        }
    )


def _signed_replay_receipt(
    preparation: ContainerAttachV4ClaimPreparationV4,
    *,
    authority_claim_started_at: str = "2026-08-29T12:01:00Z",
    authority_effective_deadline_at: str = "2026-08-29T12:01:10Z",
    authority_claim_timeout_seconds: int = 10,
    claimed_at: str = "2026-08-29T12:01:00Z",
) -> ContainerAttachV4ReplayClaimReceiptV4:
    """Create one test-only detached receipt after an authority claim."""

    claim_sha = container_attach_v4_replay_claim_sha256(preparation.replay_claim)
    ticket_sha = container_attach_v4_ticket_replay_claim_sha256(
        preparation.replay_claim.ticket_claim
    )
    lifetime_sha = container_attach_v4_container_lifetime_claim_sha256(
        preparation.replay_claim.container_lifetime_claim
    )
    unsigned = ContainerAttachV4ReplayClaimReceiptV4(
        schema_version="rsd.container-attach-replay-claim-receipt.v4",
        preparation_sha256=preparation.preparation_sha256,
        replay_claim_sha256=claim_sha,
        ticket_replay_claim_sha256=ticket_sha,
        container_lifetime_claim_sha256=lifetime_sha,
        replay_receipt_trust_anchor_key_id=(
            preparation.validation.replay_receipt_trust_anchor_key_id
        ),
        replay_receipt_trust_anchor_fingerprint_sha256=(
            preparation.validation.replay_receipt_trust_anchor_fingerprint_sha256
        ),
        state="claimed_v4",
        authority_claim_started_at=authority_claim_started_at,
        authority_effective_deadline_at=authority_effective_deadline_at,
        authority_claim_timeout_seconds=authority_claim_timeout_seconds,
        atomic_deadline_predicate_enforced=True,
        claimed_at=claimed_at,
        signer_key_id="v4-replay-root",
        signature_base64=base64.b64encode(b"r" * 64).decode("ascii"),
    )
    return unsigned.model_copy(
        update={
            "signature_base64": base64.b64encode(
                _REPLAY_SIGNER.sign(
                    container_attach_v4_replay_claim_receipt_canonical_message(unsigned)
                )
            ).decode("ascii")
        }
    )


def _verify(
    bundle: dict[str, object],
    monkeypatch: pytest.MonkeyPatch,
    *,
    profile_envelope: object | None = None,
    profile_trust_anchor: object | None = None,
    envelope: object | None = None,
    runtime: object | None = None,
    receipt: object | None = None,
) -> ContainerAttachV4ReceiptValidationV4:
    """Validate a signed receipt without invoking a replay authority.

    The V4 test helper deliberately owns no persistence collaborator.  It
    proves that intent/receipt validation remains value-free and non-bearer;
    future peer-authenticated redemption is out of scope.
    """

    monkeypatch.setattr(static_v4, "_trusted_utc_now", lambda: _NOW)
    monotonic = iter((100.0, 101.0, 102.0))
    monkeypatch.setattr(static_v4, "_trusted_monotonic_now", lambda: next(monotonic))
    claim_intent = prepare_container_attach_v4_claim_intent(
        static_role_profile_envelope=cast(Any, profile_envelope or bundle["profile_envelope"]),
        profile_trust_anchor=cast(Any, profile_trust_anchor or bundle["profile_trust_anchor"]),
        envelope=cast(Any, envelope or bundle["envelope"]),
        expected_runtime=cast(Any, runtime or bundle["runtime"]),
    )
    selected_receipt = receipt or _signed_replay_receipt(claim_intent.preparation)
    return validate_container_attach_v4_claim_receipt(
        claim_intent=claim_intent,
        profile_trust_anchor=cast(Any, profile_trust_anchor or bundle["profile_trust_anchor"]),
        receipt=cast(Any, selected_receipt),
    )


@pytest.mark.parametrize(
    "component",
    ("primary_infisical", "primary_valkey", "restore_infisical", "restore_valkey"),
)
def test_verifies_each_exact_v4_role(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch, component: str
) -> None:
    bundle = _bundle(tmp_path, component=component)

    claimed = _verify(bundle, monkeypatch)

    assert claimed.component == component
    assert claimed.static_role_profile_sha256 == bundle["profile"].profile_sha256


def test_projection_is_structural_and_non_authorizing(tmp_path: Path) -> None:
    bundle = _bundle(tmp_path)
    projection = bundle["projection"]
    canonical = container_bootstrap_static_delivery_projection_v4_canonical_json(projection)

    assert (
        parse_container_bootstrap_static_delivery_projection_v4_canonical_json(canonical)
        == projection
    )
    assert projection.allocation_parameterized is True
    assert projection.generated_wrapper_output_bound is False
    assert b"wrapper_manifest_sha256" not in canonical
    assert b"wrapper_artifact_binding_sha256" not in canonical
    assert b"derived_image_policy_sha256" not in canonical
    assert b"target_delivery_map_sha256" not in canonical
    assert b"signature_base64" not in canonical
    # The complete value-free grammar intentionally retains public schemes and
    # authorities, but never a rendered credential-bearing target URI.
    assert b"postgresql_user_password_authority_database_v1" in canonical
    assert b"redis_password_authority_database_v1" in canonical
    assert b"DB_CONNECTION_URI=" not in canonical
    assert b"REDIS_URL=" not in canonical

    with pytest.raises(ValueError):
        type(projection)(**_updated_fields(projection, generated_wrapper_output_bound=True))


def test_output_only_v1_map_mutations_do_not_change_projection_or_profile(tmp_path: Path) -> None:
    bundle = _bundle(tmp_path)
    delivery_map = cast(Any, bundle["controls"])["delivery_map"]
    original = bundle["projection"]
    target = delivery_map.primary_infisical.model_copy(
        update={
            "derived_image_policy_sha256": _hash("different-derived-image"),
            "wrapper_artifact_binding_sha256": _hash("different-artifact-binding"),
            "attach_protocol_sha256": _hash("different-v1-protocol"),
        }
    )
    hostile_map = delivery_map.model_copy(
        update={
            "wrapper_manifest_sha256": _hash("different-manifest"),
            "primary_infisical": target,
            "signature_base64": base64.b64encode(b"q" * 64).decode("ascii"),
        }
    )

    projected = project_target_delivery_map_v1_structurally(hostile_map)

    assert projected == original
    assert container_bootstrap_static_delivery_projection_v4_sha256(projected) == (
        container_bootstrap_static_delivery_projection_v4_sha256(original)
    )
    assert (
        container_bootstrap_static_role_profile_v4_sha256(bundle["profile"])
        == bundle["profile"].profile_sha256
    )


def test_structural_projection_rejects_hostile_v1_map_state_before_dump(tmp_path: Path) -> None:
    bundle = _bundle(tmp_path)
    delivery_map = cast(Any, bundle["controls"])["delivery_map"]
    references = delivery_map.provider_references
    encryption_reference = references.encryption_key
    target = delivery_map.primary_infisical
    field = target.fields[0]

    class HostileInt(int):
        pass

    class HostileProviderReferences(ProviderReferencesV2):
        pass

    int_subclass_reference = encryption_reference.model_copy(update={"version": HostileInt(1)})
    int_subclass_references = references.model_copy(
        update={"encryption_key": int_subclass_reference}
    )
    int_subclass_map = delivery_map.model_copy(
        update={"provider_references": int_subclass_references}
    )
    scalar_reference = encryption_reference.model_copy(update={"version": 1.0})
    scalar_references = references.model_copy(update={"encryption_key": scalar_reference})
    scalar_map = delivery_map.model_copy(update={"provider_references": scalar_references})
    enum_field = field.model_copy(update={"value_kind": field.value_kind.value})
    enum_target = target.model_copy(update={"fields": (enum_field, *target.fields[1:])})
    enum_map = delivery_map.model_copy(update={"primary_infisical": enum_target})
    container_map = delivery_map.model_copy(
        update={"material_fingerprints": list(delivery_map.material_fingerprints)}
    )
    subclassed_references = HostileProviderReferences.model_validate(
        references.model_dump(mode="python"), strict=True
    )
    subclass_map = delivery_map.model_copy(update={"provider_references": subclassed_references})
    hidden_map = delivery_map.model_copy()
    object.__setattr__(hidden_map, "hidden", "must-not-leak")
    deleted_map = delivery_map.model_copy()
    object.__delattr__(deleted_map, "created_at")
    constructed_fields = delivery_map.model_dump(mode="python")
    constructed_fields.pop("created_at")
    constructed_map = type(delivery_map).model_construct(**constructed_fields)

    for hostile in (
        int_subclass_map,
        scalar_map,
        enum_map,
        container_map,
        subclass_map,
        hidden_map,
        deleted_map,
        constructed_map,
    ):
        with pytest.raises(ContainerAttachStaticV4Error) as error:
            project_target_delivery_map_v1_structurally(hostile)
        assert error.value.phase == "projection"
        assert str(error.value) == "container attach V4 verification failed"
        assert "must-not-leak" not in str(error.value)


def test_v1_observed_operation_binding_does_not_enter_static_v4_projection(
    tmp_path: Path,
) -> None:
    """The future V1-to-V4 closure, not static input, owns prepared operation IDs."""

    bundle = _bundle(tmp_path)
    delivery_map = cast(Any, bundle["controls"])["delivery_map"]
    original = bundle["projection"]
    primary_identity = delivery_map.database_identities.primary_database
    changed_operation_id = "123e4567-e89b-42d3-a456-426614174099"
    changed_grammar = primary_identity.connection_uri.model_copy(
        update={"prepared_operation_id": changed_operation_id}
    )
    changed_transition = primary_identity.login_transition.model_copy(
        update={
            "prepared_operation_id": changed_operation_id,
            "scram_verifier_install": (
                primary_identity.login_transition.scram_verifier_install.model_copy(
                    update={"prepared_operation_id": changed_operation_id}
                )
            ),
        }
    )
    changed_fields = tuple(
        field.model_copy(
            update={
                "derivation_binding_sha256": static_v4.runtime_connection_uri_grammar_sha256(
                    changed_grammar
                )
            }
        )
        if field.target_field == "DB_CONNECTION_URI"
        else field
        for field in delivery_map.primary_infisical.fields
    )
    changed_target = delivery_map.primary_infisical.model_copy(update={"fields": changed_fields})
    changed_map = delivery_map.model_copy(
        update={
            "database_identities": delivery_map.database_identities.model_copy(
                update={
                    "primary_database": (
                        primary_identity.model_copy(
                            update={
                                "connection_uri": changed_grammar,
                                "login_transition": changed_transition,
                            }
                        )
                    )
                }
            ),
            "primary_infisical": changed_target,
        }
    )

    projection = project_target_delivery_map_v1_structurally(changed_map)

    assert projection == original
    static_payload = container_bootstrap_static_delivery_projection_v4_canonical_json(projection)
    assert b"prepared_operation_id" not in static_payload
    assert changed_grammar.prepared_operation_id.encode("ascii") not in static_payload


def test_v1_allocation_and_policy_aggregates_do_not_enter_static_v4_projection(
    tmp_path: Path,
) -> None:
    """The later signed-map closure, never compiled input, owns those facts."""

    bundle = _bundle(tmp_path)
    delivery_map = cast(Any, bundle["controls"])["delivery_map"]
    original = bundle["projection"]
    changed_map = delivery_map.model_copy(
        update={
            "allocation_intent_sha256": _hash("other-allocation-operation"),
            "secret_handling_policy_sha256": _hash("other-secret-policy-chain"),
        }
    )

    projected = project_target_delivery_map_v1_structurally(changed_map)

    assert projected == original
    canonical = container_bootstrap_static_delivery_projection_v4_canonical_json(projected)
    assert b"allocation_intent_sha256" not in canonical
    assert b"secret_handling_policy_sha256" not in canonical


def test_projection_intentionally_omits_every_v1_allocation_topology_field(tmp_path: Path) -> None:
    """Topology is a later V1 closure concern, not a V4 compiled input."""

    bundle = _bundle(tmp_path)
    delivery_map = cast(Any, bundle["controls"])["delivery_map"]
    original = bundle["projection"]
    topology = delivery_map.topology
    primary_name = "PrimaryNet"
    restore_name = "RestoreNet"
    changed_topology = topology.model_copy(
        update={
            "primary_network": topology.primary_network.model_copy(update={"name": primary_name}),
            "restore_network": topology.restore_network.model_copy(update={"name": restore_name}),
            "primary_infisical": topology.primary_infisical.model_copy(
                update={"network_name": primary_name, "alias": "PrimaryInfisical"}
            ),
            "primary_valkey": topology.primary_valkey.model_copy(
                update={"network_name": primary_name, "alias": "PrimaryValkey"}
            ),
            "restore_infisical": topology.restore_infisical.model_copy(
                update={"network_name": restore_name, "alias": "RestoreInfisical"}
            ),
            "restore_valkey": topology.restore_valkey.model_copy(
                update={"network_name": restore_name, "alias": "RestoreValkey"}
            ),
        }
    )
    changed_map = type(delivery_map)(**_updated_fields(delivery_map, topology=changed_topology))

    projected = project_target_delivery_map_v1_structurally(changed_map)

    assert projected == original
    canonical = container_bootstrap_static_delivery_projection_v4_canonical_json(projected)
    assert not any(
        marker in canonical
        for marker in (
            b'"topology"',
            b'"network_name"',
            b'"static_ipv4"',
            b'"alias"',
            b'"subnet"',
            b'"gateway"',
            b'"driver"',
            b'"options"',
        )
    )
    assert "primary_network" not in type(projected).model_fields
    assert "placement" not in type(projected.primary_infisical).model_fields


def test_v1_artifact_and_manifest_output_values_do_not_enter_v4_profile(tmp_path: Path) -> None:
    bundle = _bundle(tmp_path)
    profile_json = container_bootstrap_static_role_profile_v4_canonical_json(bundle["profile"])
    v2_artifact = cast(Any, bundle["controls"])["manifest"].primary_infisical
    changed_artifact = v2_artifact.model_copy(
        update={
            "artifact_sha256": _hash("hypothetical-new-wrapper-bytes"),
            "artifact_byte_count": v2_artifact.artifact_byte_count + 1,
            "artifact_binding_sha256": _hash("hypothetical-new-artifact-binding"),
        }
    )

    assert changed_artifact.artifact_sha256.encode("ascii") not in profile_json
    assert changed_artifact.artifact_binding_sha256.encode("ascii") not in profile_json
    assert b"artifact_byte_count" not in profile_json
    assert b"derived_image_policy_sha256" not in profile_json
    assert b"wrapper_manifest_sha256" not in profile_json

    rebuilt = _rebuild_profile(
        bundle["profile"],
        static_launch_plan=_launch("primary_infisical", changed_artifact),
    )
    assert rebuilt == bundle["profile"]


def test_included_projection_and_source_inputs_change_their_v4_commitments(
    tmp_path: Path,
) -> None:
    """Only actual static input drift changes V4 commitments and profiles."""

    bundle = _bundle(tmp_path)
    projection = bundle["projection"]
    profile = bundle["profile"]
    original_field = projection.primary_infisical.fields[0]
    changed_field = original_field.model_copy(
        update={
            "source_reference_sha256": _hash("changed-source-reference"),
            "source_fingerprint_sha256": _hash("changed-source-fingerprint"),
            "derivation_binding_sha256": _hash("changed-source-fingerprint"),
        }
    )
    changed_route = projection.primary_infisical.model_copy(
        update={"fields": (changed_field, *projection.primary_infisical.fields[1:])}
    )
    changed_projection = type(projection)(
        **_updated_fields(projection, primary_infisical=changed_route)
    )
    changed_profile = _rebuild_profile(
        profile,
        static_delivery_projection=changed_projection,
        selected_delivery_route=changed_projection.primary_infisical,
    )
    changed_preimage = profile.static_patch_preimage.model_copy(
        update={"wrapper_source_tree_sha256": _hash("other-source-tree")}
    )
    changed_patch = ContainerBootstrapStaticPatchPolicyV4(
        schema_version="rsd.container-bootstrap-static-patch-policy.v4",
        preimage=changed_preimage,
        static_patch_preimage_sha256=container_bootstrap_static_patch_preimage_v4_sha256(
            changed_preimage
        ),
        patch_policy_intent="compile_static_target_inputs_only_v4",
        wrapper_bytes_claimed=False,
        generated_artifact_claimed=False,
        generated_image_claimed=False,
        generated_provenance_claimed=False,
        generated_sbom_claimed=False,
        generated_reproducibility_claimed=False,
    )
    source_changed_profile = _rebuild_profile(
        profile,
        wrapper_source_tree_sha256=_hash("other-source-tree"),
        static_patch_preimage=changed_preimage,
        static_patch_policy=changed_patch,
    )

    assert container_bootstrap_static_delivery_projection_v4_sha256(
        changed_projection
    ) != container_bootstrap_static_delivery_projection_v4_sha256(projection)
    assert changed_profile.profile_sha256 != profile.profile_sha256
    assert source_changed_profile.profile_sha256 != profile.profile_sha256
    assert source_changed_profile.wrapper_source_tree_sha256 == _hash("other-source-tree")


def test_static_launch_plan_rejects_argv_drift_and_commits_exact_merge(tmp_path: Path) -> None:
    bundle = _bundle(tmp_path)
    profile = bundle["profile"]
    launch = profile.static_launch_plan
    mismatched = _updated_fields(
        launch,
        wrapper_argv_prefix=("/usr/local/libexec/another-v4-wrapper",),
    )

    with pytest.raises(ValueError):
        type(launch)(**mismatched)
    with pytest.raises(ValueError):
        type(launch)(**_updated_fields(launch, base_command=["--not-a-tuple"]))

    changed = ContainerBootstrapStaticLaunchPlanV4(
        **_updated_fields(
            launch,
            base_entrypoint=("changed-base-entrypoint",),
            merged_argv_sha256=static_v4._merged_argv_sha256(
                wrapper_argv_prefix=launch.wrapper_argv_prefix,
                base_entrypoint=("changed-base-entrypoint",),
                base_command=launch.base_command,
            ),
        )
    )
    changed_preimage = profile.static_patch_preimage.model_copy(
        update={
            "static_launch_plan_sha256": container_bootstrap_static_launch_plan_v4_sha256(changed)
        }
    )
    changed_patch = ContainerBootstrapStaticPatchPolicyV4(
        schema_version="rsd.container-bootstrap-static-patch-policy.v4",
        preimage=changed_preimage,
        static_patch_preimage_sha256=container_bootstrap_static_patch_preimage_v4_sha256(
            changed_preimage
        ),
        patch_policy_intent="compile_static_target_inputs_only_v4",
        wrapper_bytes_claimed=False,
        generated_artifact_claimed=False,
        generated_image_claimed=False,
        generated_provenance_claimed=False,
        generated_sbom_claimed=False,
        generated_reproducibility_claimed=False,
    )
    changed_profile = _rebuild_profile(
        profile,
        static_launch_plan=changed,
        static_patch_preimage=changed_preimage,
        static_patch_policy=changed_patch,
    )

    assert static_v4.container_bootstrap_static_launch_plan_v4_sha256(changed) != (
        static_v4.container_bootstrap_static_launch_plan_v4_sha256(launch)
    )
    assert changed_profile.profile_sha256 != profile.profile_sha256


@pytest.mark.parametrize(
    "path",
    (
        "/usr/local/libexec/./wrapper",
        "/usr/local/libexec/wrapper/.",
        "/usr/local/libexec/wrapper/",
        "/usr/local/libexec/a//wrapper",
        "/usr/local/libexec/a/../wrapper",
        "/usr/local/libexec/wrapper\\ghost",
        "/usr/local/libexec/wrapper%2fghost",
        "/usr/local/libexec/wrapper\x00ghost",
        "/usr/local/libexec/wrapper\nghost",
        "/usr/local/libexec/wrapper\tghost",
        "/usr/local/libexec/wrapper\x7fghost",
    ),
)
def test_static_phase_a_fed_paths_have_one_canonical_ascii_spelling(
    tmp_path: Path, path: str
) -> None:
    """Static wrapper paths cannot carry aliases into Phase A evidence."""

    launch = cast(Any, _bundle(tmp_path)["profile"]).static_launch_plan
    with pytest.raises(ValueError):
        ContainerBootstrapStaticLaunchPlanV4(
            **_updated_fields(launch, wrapper_executable_path=path)
        )
    assert (
        static_v4._canonical_static_absolute_path("/usr/local/libexec/valid-wrapper")
        == "/usr/local/libexec/valid-wrapper"
    )


def test_static_launch_argv_limits_are_explicit_and_parser_closed(tmp_path: Path) -> None:
    """Every legal 64 x 256 upstream vector has one parser-safe spelling."""

    launch = cast(Any, _bundle(tmp_path)["profile"]).static_launch_plan
    wrapper_prefix = (launch.wrapper_executable_path, *("p" * 256 for _ in range(63)))
    base_entrypoint = tuple("e" * 256 for _ in range(64))
    base_command = tuple("c" * 256 for _ in range(64))
    maximum = ContainerBootstrapStaticLaunchPlanV4(
        **_updated_fields(
            launch,
            wrapper_argv_prefix=wrapper_prefix,
            base_entrypoint=base_entrypoint,
            base_command=base_command,
            merged_argv_sha256=static_v4._merged_argv_sha256(
                wrapper_argv_prefix=wrapper_prefix,
                base_entrypoint=base_entrypoint,
                base_command=base_command,
            ),
        )
    )
    canonical = static_v4.container_bootstrap_static_launch_plan_v4_canonical_json(maximum)
    assert len(maximum.wrapper_argv_prefix) == 64
    assert len(maximum.base_entrypoint) == 64
    assert len(maximum.base_command) == 64
    assert all(
        sum(len(item.encode("ascii")) for item in argv) <= 16_384
        for argv in (maximum.wrapper_argv_prefix, maximum.base_entrypoint, maximum.base_command)
    )
    assert (
        static_v4.parse_container_bootstrap_static_launch_plan_v4_canonical_json(canonical)
        == maximum
    )
    with pytest.raises(ValueError):
        ContainerBootstrapStaticLaunchPlanV4(
            **_updated_fields(launch, base_command=tuple("c" * 256 for _ in range(65)))
        )
    with pytest.raises(ValueError):
        ContainerBootstrapStaticLaunchPlanV4(**_updated_fields(launch, base_command=("c" * 257,)))


def test_fixed_static_v4_profile_vector_remains_signed_and_byte_exact() -> None:
    """Validation-only grammar hardening leaves the fixed static vector unchanged."""

    raw = _VECTOR_PATH.read_bytes()
    vector = yaml.load(raw, Loader=_StrictVectorLoader)
    assert type(vector) is dict
    values = cast(dict[str, object], vector)
    envelope_payload = _canonical_vector_base64(
        values["profile_envelope_canonical_json_utf8_base64"]
    )
    root_payload = _canonical_vector_base64(values["profile_root_canonical_json_utf8_base64"])
    envelope = static_v4.parse_container_bootstrap_static_role_profile_envelope_v4_canonical_json(
        envelope_payload
    )
    root = static_v4.parse_container_bootstrap_static_profile_trust_anchor_v4_canonical_json(
        root_payload
    )
    profile = static_v4.verify_container_bootstrap_static_role_profile_envelope_v4(
        envelope=envelope,
        profile_trust_anchor=root,
    )
    assert (
        static_v4.container_bootstrap_static_role_profile_envelope_v4_canonical_json(envelope)
        == envelope_payload
    )
    assert (
        static_v4.container_bootstrap_static_role_profile_envelope_v4_sha256(envelope)
        == values["profile_envelope_sha256"]
    )
    assert profile.profile_sha256 == values["profile_sha256"]


def test_static_v4_rejects_topology_fields_and_invalid_protocol_states(tmp_path: Path) -> None:
    bundle = _bundle(tmp_path)
    protocol = _protocol()

    with pytest.raises(ValueError):
        type(bundle["projection"])(
            **_updated_fields(
                bundle["projection"],
                primary_network={"untrusted": "topology"},
            )
        )
    with pytest.raises(ValueError):
        ContainerBootstrapAttachProtocolV4(**_updated_fields(protocol, frame_magic="ONC5"))
    with pytest.raises(ValueError):
        ContainerBootstrapAttachProtocolV4(**_updated_fields(protocol, ready_state="ready_v3"))
    with pytest.raises(ValueError):
        type(bundle["projection"])(
            **_updated_fields(
                bundle["projection"],
                primary_infisical=bundle["projection"].restore_infisical,
            )
        )


def test_projection_rejects_cross_role_uri_authority_drift_without_topology(tmp_path: Path) -> None:
    """Primary and restore target URI grammars remain distinct static inputs."""

    bundle = _bundle(tmp_path)
    projection = bundle["projection"]
    same_authority = projection.restore_valkey_connection_uri.model_copy(
        update={"authority": projection.primary_valkey_connection_uri.authority}
    )
    with pytest.raises(ValueError):
        type(projection)(
            **_updated_fields(
                projection,
                restore_valkey_connection_uri=same_authority,
            )
        )


def test_projection_rejects_uri_grammar_and_descriptor_drift(tmp_path: Path) -> None:
    bundle = _bundle(tmp_path)
    projection = bundle["projection"]
    malformed_grammar = projection.primary_postgresql_connection_uri.model_copy(
        update={
            "rendered_uri_byte_count": (
                projection.primary_postgresql_connection_uri.rendered_uri_byte_count + 1
            )
        }
    )
    malformed_field = projection.primary_infisical.fields[0].model_copy(
        update={"source_fingerprint_sha256": _hash("wrong-fingerprint")}
    )
    malformed_route = projection.primary_infisical.model_copy(
        update={
            "fields": (
                malformed_field,
                *projection.primary_infisical.fields[1:],
            )
        }
    )

    with pytest.raises(ValueError):
        type(projection)(
            **_updated_fields(projection, primary_postgresql_connection_uri=malformed_grammar)
        )
    with pytest.raises(ValueError):
        type(projection)(**_updated_fields(projection, primary_infisical=malformed_route))


def test_projection_rejects_role_swap_and_wrong_valkey_stdin_route(tmp_path: Path) -> None:
    bundle = _bundle(tmp_path)
    projection = bundle["projection"]
    swapped = projection.restore_infisical.model_copy(
        update={"component": "primary_infisical", "component_role": "infisical"}
    )
    valkey_field = projection.primary_valkey.fields[0].model_copy(
        update={"target_field": "REDIS_URL"}
    )
    valkey_route = projection.primary_valkey.model_copy(update={"fields": (valkey_field,)})

    with pytest.raises(ValueError):
        type(projection)(**_updated_fields(projection, primary_infisical=swapped))
    with pytest.raises(ValueError):
        type(projection)(**_updated_fields(projection, primary_valkey=valkey_route))


def test_profile_rejects_static_patch_launch_anchor_and_valkey_binding_drift(
    tmp_path: Path,
) -> None:
    bundle = _bundle(tmp_path, component="primary_valkey")
    profile = bundle["profile"]
    bad_anchor = _anchor(key_id="other-v4-signer")
    bad_patch = profile.static_patch_preimage.model_copy(
        update={"wrapper_source_tree_sha256": _hash("other-source-tree")}
    )
    bad_launch = profile.static_launch_plan.model_copy(
        update={"merged_argv_sha256": _hash("wrong-argv-merge")}
    )
    bad_valkey = profile.valkey_launch_policy.model_copy(
        update={"static_configuration_sha256": _hash("other-valkey-static-configuration")}
    )

    for changes in (
        {"ticket_trust_anchor": bad_anchor},
        {"static_patch_preimage": bad_patch},
        {"static_launch_plan": bad_launch},
        {"valkey_launch_policy": bad_valkey},
    ):
        fields = _updated_fields(profile, **changes, profile_sha256="0" * 64)
        with pytest.raises(ValueError):
            type(profile)(**fields)


def test_profile_binds_role_specific_patch_environment_and_valkey_semantics(
    tmp_path: Path,
) -> None:
    """A source-patch preimage cannot be paired with unrelated static controls."""

    infisical_profile = _bundle(tmp_path)["profile"]
    valkey_profile = _bundle(tmp_path, component="primary_valkey")["profile"]

    def rebuilt_policy(
        preimage: ContainerBootstrapStaticPatchPreimageV4,
    ) -> ContainerBootstrapStaticPatchPolicyV4:
        return ContainerBootstrapStaticPatchPolicyV4(
            schema_version="rsd.container-bootstrap-static-patch-policy.v4",
            preimage=preimage,
            static_patch_preimage_sha256=container_bootstrap_static_patch_preimage_v4_sha256(
                preimage
            ),
            patch_policy_intent="compile_static_target_inputs_only_v4",
            wrapper_bytes_claimed=False,
            generated_artifact_claimed=False,
            generated_image_claimed=False,
            generated_provenance_claimed=False,
            generated_sbom_claimed=False,
            generated_reproducibility_claimed=False,
        )

    bad_infisical_kind = infisical_profile.static_patch_preimage.model_copy(
        update={"patch_kind": "valkey_stdin_launcher_and_acl_v4"}
    )
    bad_infisical_env = infisical_profile.static_patch_preimage.model_copy(
        update={"child_environment_policy_sha256": _hash("unrelated-child-env")}
    )
    bad_infisical_launch = infisical_profile.static_patch_preimage.model_copy(
        update={"static_launch_plan_sha256": _hash("unrelated-launch-plan")}
    )
    bad_valkey_policy = valkey_profile.static_patch_preimage.model_copy(
        update={"valkey_static_configuration_sha256": _hash("unrelated-valkey-policy")}
    )
    bad_valkey_launch_policy = valkey_profile.static_patch_preimage.model_copy(
        update={"valkey_launch_policy_sha256": _hash("unrelated-valkey-launch-policy")}
    )
    for profile, preimage in (
        (infisical_profile, bad_infisical_kind),
        (infisical_profile, bad_infisical_env),
        (infisical_profile, bad_infisical_launch),
        (valkey_profile, bad_valkey_policy),
        (valkey_profile, bad_valkey_launch_policy),
    ):
        with pytest.raises(ContainerAttachStaticV4Error) as error:
            _rebuild_profile(
                profile,
                static_patch_preimage=preimage,
                static_patch_policy=rebuilt_policy(preimage),
            )
        assert error.value.phase == "profile"


def test_request_ticket_and_runtime_binding_fail_before_claim_intent(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    bundle = _bundle(tmp_path)
    request = bundle["request"].model_copy(
        update={"selected_delivery_route_sha256": _hash("wrong-route")}
    )
    ticket = bundle["ticket"].model_copy(update={"request_sha256": _hash("wrong-request")})
    envelope = bundle["envelope"].model_copy(update={"request": request, "ticket": ticket})

    with pytest.raises(ContainerAttachStaticV4Error) as error:
        _verify(bundle, monkeypatch, envelope=envelope)

    assert error.value.phase == "binding"


def test_signature_anchor_expiry_and_runtime_substitution_fail_closed(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    bundle = _bundle(tmp_path)
    bad_signature = bundle["ticket"].model_copy(
        update={"signature_base64": base64.b64encode(b"z" * 64).decode("ascii")}
    )
    bad_envelope = bundle["envelope"].model_copy(update={"ticket": bad_signature})
    runtime = bundle["runtime"].model_copy(
        update={"runtime_hostname": "rsd-different-hostname-123456"}
    )

    with pytest.raises(ContainerAttachStaticV4Error) as signature_error:
        _verify(bundle, monkeypatch, envelope=bad_envelope)
    assert signature_error.value.phase == "signature"
    with pytest.raises(ContainerAttachStaticV4Error) as runtime_error:
        _verify(bundle, monkeypatch, runtime=runtime)
    assert runtime_error.value.phase == "binding"

    monkeypatch.setattr(
        static_v4, "_trusted_utc_now", lambda: datetime(2026, 8, 29, 12, 5, tzinfo=UTC)
    )
    with pytest.raises(ContainerAttachStaticV4Error) as expiry_error:
        prepare_container_attach_v4_claim_intent(
            static_role_profile_envelope=bundle["profile_envelope"],
            profile_trust_anchor=bundle["profile_trust_anchor"],
            envelope=bundle["envelope"],
            expected_runtime=bundle["runtime"],
        )
    assert expiry_error.value.phase == "freshness"


def test_replay_claim_derives_distinct_ticket_and_stable_container_identities(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    bundle = _bundle(tmp_path)
    first_intent = _claim_intent(bundle, monkeypatch)

    request = bundle["request"].model_copy(
        update={
            "request_nonce_sha256": _hash("fresh-v4-nonce"),
            "channel_binding_sha256": _hash("fresh-v4-channel"),
            "session_binding_sha256": _hash("fresh-v4-session"),
        }
    )
    unsigned = ContainerAttachAuthorizationTicketV4(
        **_updated_fields(
            bundle["ticket"],
            request_sha256=container_attach_v4_request_sha256(request),
            request_nonce_sha256=request.request_nonce_sha256,
            channel_binding_sha256=request.channel_binding_sha256,
            session_binding_sha256=request.session_binding_sha256,
            signature_base64=base64.b64encode(b"x" * 64).decode("ascii"),
        )
    )
    ticket = unsigned.model_copy(
        update={
            "signature_base64": _signature(container_attach_v4_ticket_canonical_message(unsigned))
        }
    )
    reissued = ContainerAttachTicketEnvelopeV4(
        schema_version="rsd.container-attach-ticket-envelope.v4", request=request, ticket=ticket
    )
    runtime = bundle["runtime"].model_copy(
        update={
            "request_nonce_sha256": request.request_nonce_sha256,
            "channel_binding_sha256": request.channel_binding_sha256,
            "session_binding_sha256": request.session_binding_sha256,
        }
    )
    reissued_intent = prepare_container_attach_v4_claim_intent(
        static_role_profile_envelope=bundle["profile_envelope"],
        profile_trust_anchor=bundle["profile_trust_anchor"],
        envelope=reissued,
        expected_runtime=runtime,
    )
    assert (
        first_intent.preparation.ticket_replay_claim_sha256
        != reissued_intent.preparation.ticket_replay_claim_sha256
    )
    assert (
        first_intent.preparation.container_lifetime_claim_sha256
        == reissued_intent.preparation.container_lifetime_claim_sha256
    )


def test_replay_lifetime_claim_is_stable_across_reprofiled_resigned_ticket(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    """The durable lifetime key must not vary with profile or ticket identity."""

    bundle = _bundle(tmp_path)
    first_intent = _claim_intent(bundle, monkeypatch)
    profile = bundle["profile"]
    changed_preimage = profile.static_patch_preimage.model_copy(
        update={"wrapper_source_tree_sha256": _hash("reprofiled-source-tree")}
    )
    changed_patch = ContainerBootstrapStaticPatchPolicyV4(
        schema_version="rsd.container-bootstrap-static-patch-policy.v4",
        preimage=changed_preimage,
        static_patch_preimage_sha256=container_bootstrap_static_patch_preimage_v4_sha256(
            changed_preimage
        ),
        patch_policy_intent="compile_static_target_inputs_only_v4",
        wrapper_bytes_claimed=False,
        generated_artifact_claimed=False,
        generated_image_claimed=False,
        generated_provenance_claimed=False,
        generated_sbom_claimed=False,
        generated_reproducibility_claimed=False,
    )
    reprofiled = _rebuild_profile(
        profile,
        wrapper_source_tree_sha256=_hash("reprofiled-source-tree"),
        static_patch_preimage=changed_preimage,
        static_patch_policy=changed_patch,
    )
    reprofiled_envelope = _profile_envelope(reprofiled)
    request = bundle["request"].model_copy(
        update={
            "static_role_profile_sha256": reprofiled.profile_sha256,
            "static_role_profile_envelope_sha256": (
                container_bootstrap_static_role_profile_envelope_v4_sha256(reprofiled_envelope)
            ),
            "request_nonce_sha256": _hash("reprofiled-nonce"),
            "channel_binding_sha256": _hash("reprofiled-channel"),
            "session_binding_sha256": _hash("reprofiled-session"),
        }
    )
    ticket = _resign_ticket_for_request(bundle["ticket"], request)
    envelope = ContainerAttachTicketEnvelopeV4(
        schema_version="rsd.container-attach-ticket-envelope.v4",
        request=request,
        ticket=ticket,
    )
    runtime = bundle["runtime"].model_copy(
        update={
            "request_nonce_sha256": request.request_nonce_sha256,
            "channel_binding_sha256": request.channel_binding_sha256,
            "session_binding_sha256": request.session_binding_sha256,
        }
    )

    reprofiled_intent = prepare_container_attach_v4_claim_intent(
        static_role_profile_envelope=reprofiled_envelope,
        profile_trust_anchor=bundle["profile_trust_anchor"],
        envelope=envelope,
        expected_runtime=runtime,
    )
    assert (
        first_intent.preparation.container_lifetime_claim_sha256
        == reprofiled_intent.preparation.container_lifetime_claim_sha256
    )


def test_profile_owned_anchor_rejects_a_rebound_request_before_any_effect(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    bundle = _bundle(tmp_path)
    reanchored = _rebuild_profile(
        bundle["profile"], ticket_trust_anchor=_anchor(key_id="other-key")
    )
    reanchored_envelope = _profile_envelope(reanchored)
    request = bundle["request"].model_copy(
        update={
            "static_role_profile_sha256": reanchored.profile_sha256,
            "static_role_profile_envelope_sha256": (
                container_bootstrap_static_role_profile_envelope_v4_sha256(reanchored_envelope)
            ),
        }
    )
    ticket = _resign_ticket_for_request(bundle["ticket"], request)
    envelope = ContainerAttachTicketEnvelopeV4(
        schema_version="rsd.container-attach-ticket-envelope.v4",
        request=request,
        ticket=ticket,
    )
    with pytest.raises(ContainerAttachStaticV4Error) as error:
        _verify(
            bundle,
            monkeypatch,
            profile_envelope=reanchored_envelope,
            envelope=envelope,
        )

    assert error.value.phase == "signature"


def test_external_profile_root_rejects_a_fresh_self_attested_profile_and_ticket(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    """A supplied profile cannot replace the separately configured profile root."""

    bundle = _bundle(tmp_path)
    attacker_profile_signer = Ed25519PrivateKey.from_private_bytes(b"7" * 32)
    attacker_ticket_signer = Ed25519PrivateKey.from_private_bytes(b"8" * 32)
    attacker_profile_public = attacker_profile_signer.public_key().public_bytes_raw()
    attacker_ticket_public = attacker_ticket_signer.public_key().public_bytes_raw()
    attacker_ticket_anchor = ContainerAttachTicketTrustAnchorV1(
        schema_version="rsd.container-attach-ticket-trust-anchor.v1",
        key_id="attacker-ticket-key",
        public_key_base64=base64.b64encode(attacker_ticket_public).decode("ascii"),
        public_key_fingerprint_sha256=hashlib.sha256(attacker_ticket_public).hexdigest(),
        algorithm="ed25519",
    )
    attacker_profile = _rebuild_profile(
        bundle["profile"], ticket_trust_anchor=attacker_ticket_anchor
    )
    attacker_root = ContainerBootstrapStaticProfileTrustAnchorV4(
        schema_version="rsd.container-bootstrap-static-profile-trust-anchor.v4",
        key_id="attacker-profile-root",
        public_key_base64=base64.b64encode(attacker_profile_public).decode("ascii"),
        public_key_fingerprint_sha256=hashlib.sha256(attacker_profile_public).hexdigest(),
        algorithm="ed25519",
    )
    unsigned_profile_envelope = ContainerBootstrapStaticRoleProfileEnvelopeV4(
        schema_version="rsd.container-bootstrap-static-role-profile-envelope.v4",
        static_role_profile=attacker_profile,
        static_role_profile_sha256=attacker_profile.profile_sha256,
        signer_key_id=attacker_root.key_id,
        signature_base64=base64.b64encode(b"a" * 64).decode("ascii"),
    )
    attacker_profile_envelope = unsigned_profile_envelope.model_copy(
        update={
            "signature_base64": base64.b64encode(
                attacker_profile_signer.sign(
                    container_bootstrap_static_role_profile_envelope_v4_canonical_message(
                        unsigned_profile_envelope
                    )
                )
            ).decode("ascii")
        }
    )
    request = bundle["request"].model_copy(
        update={
            "static_role_profile_sha256": attacker_profile.profile_sha256,
            "static_role_profile_envelope_sha256": (
                container_bootstrap_static_role_profile_envelope_v4_sha256(
                    attacker_profile_envelope
                )
            ),
            "static_profile_trust_anchor_fingerprint_sha256": (
                attacker_root.public_key_fingerprint_sha256
            ),
        }
    )
    unsigned_ticket = ContainerAttachAuthorizationTicketV4(
        **_updated_fields(
            bundle["ticket"],
            protocol_sha256=request.attach_protocol_v4_sha256,
            request_sha256=container_attach_v4_request_sha256(request),
            static_role_profile_sha256=request.static_role_profile_sha256,
            static_role_profile_envelope_sha256=request.static_role_profile_envelope_sha256,
            static_profile_trust_anchor_fingerprint_sha256=(
                request.static_profile_trust_anchor_fingerprint_sha256
            ),
            signer_key_id=attacker_ticket_anchor.key_id,
            signature_base64=base64.b64encode(b"a" * 64).decode("ascii"),
        )
    )
    attacker_ticket = unsigned_ticket.model_copy(
        update={
            "signature_base64": base64.b64encode(
                attacker_ticket_signer.sign(
                    container_attach_v4_ticket_canonical_message(unsigned_ticket)
                )
            ).decode("ascii")
        }
    )
    attacker_envelope = ContainerAttachTicketEnvelopeV4(
        schema_version="rsd.container-attach-ticket-envelope.v4",
        request=request,
        ticket=attacker_ticket,
    )

    with pytest.raises(ContainerAttachStaticV4Error) as error:
        _verify(
            bundle,
            monkeypatch,
            profile_envelope=attacker_profile_envelope,
            envelope=attacker_envelope,
        )

    assert error.value.phase == "binding"


def test_raw_ticket_parser_applies_verified_profile_limit_and_depth_bounds(
    tmp_path: Path,
) -> None:
    bundle = _bundle(tmp_path)
    raw = static_v4.container_attach_v4_ticket_envelope_canonical_json(bundle["envelope"])
    assert (
        static_v4.parse_container_attach_v4_ticket_envelope_for_profile_v4(
            static_role_profile_envelope=bundle["profile_envelope"],
            profile_trust_anchor=bundle["profile_trust_anchor"],
            payload=raw,
        )
        == bundle["envelope"]
    )
    oversized = raw + b" " * (bundle["profile"].attach_protocol.max_metadata_bytes + 1)
    with pytest.raises(ContainerAttachStaticV4Error) as oversize:
        static_v4.parse_container_attach_v4_ticket_envelope_for_profile_v4(
            static_role_profile_envelope=bundle["profile_envelope"],
            profile_trust_anchor=bundle["profile_trust_anchor"],
            payload=oversized,
        )
    assert oversize.value.phase == "ticket"
    nested = b'{"x":' + b"[" * 40 + b"0" + b"]" * 40 + b"}"
    with pytest.raises(ContainerAttachStaticV4Error):
        parse_container_attach_v4_request_canonical_json(nested)
    token_dense = b"[" + b",".join(b"0" for _ in range(4_097)) + b"]"
    with pytest.raises(ContainerAttachStaticV4Error) as dense:
        parse_container_attach_v4_request_canonical_json(token_dense)
    assert dense.value.phase == "ticket"


def _claim_intent(
    bundle: dict[str, object],
    monkeypatch: pytest.MonkeyPatch,
) -> ContainerAttachV4ClaimIntentV4:
    """Build a fresh V4 non-authorizing intent under the fixture clock."""

    monkeypatch.setattr(static_v4, "_trusted_utc_now", lambda: _NOW)
    return prepare_container_attach_v4_claim_intent(
        static_role_profile_envelope=cast(Any, bundle["profile_envelope"]),
        profile_trust_anchor=cast(Any, bundle["profile_trust_anchor"]),
        envelope=cast(Any, bundle["envelope"]),
        expected_runtime=cast(Any, bundle["runtime"]),
    )


def test_claim_intent_is_non_authorizing_and_receipt_validation_is_non_bearer(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    """A serialized graph cannot invoke persistence or become an attach grant."""

    bundle = _bundle(tmp_path)
    intent = _claim_intent(bundle, monkeypatch)
    raw = container_attach_v4_claim_intent_canonical_json(intent)

    assert isinstance(intent, ContainerAttachV4ClaimIntentV4)
    assert intent.atomic_persistence_authorized is False
    assert intent.peer_authenticated_executor_capability_required is True
    assert b"secret-sentinel" not in raw
    assert b"claim_once" not in Path(static_v4.__file__).read_bytes()

    receipt = _signed_replay_receipt(intent.preparation)
    first = _verify(bundle, monkeypatch, receipt=receipt)
    second = _verify(bundle, monkeypatch, receipt=receipt)

    assert isinstance(first, ContainerAttachV4ReceiptValidationV4)
    assert first == second
    assert first.attach_allowed is False
    assert first.effect_allowed is False
    assert first.durable_one_shot_receipt_redemption_required is True
    assert first.peer_authenticated_executor_capability_required is True
    for removed_name in (
        "ContainerAttachV4ReplayAuthority",
        "ContainerAttachV4AuthorityClaimRequestV4",
        "finalize_container_attach_v4_claim",
        "verify_container_attach_v4_authority_claim_request",
    ):
        assert not hasattr(static_v4, removed_name)


def test_receipt_root_is_profile_authenticated_and_role_separated(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    """A caller cannot choose a receipt key or reuse another profile role root."""

    bundle = _bundle(tmp_path)
    intent = _claim_intent(bundle, monkeypatch)
    attacker = Ed25519PrivateKey.from_private_bytes(b"9" * 32)
    attacker_public = attacker.public_key().public_bytes_raw()
    attacker_root = ContainerAttachV4ReplayReceiptTrustAnchorV4(
        schema_version="rsd.container-attach-replay-receipt-trust-anchor.v4",
        key_id="attacker-receipt-root",
        public_key_base64=base64.b64encode(attacker_public).decode("ascii"),
        public_key_fingerprint_sha256=hashlib.sha256(attacker_public).hexdigest(),
        algorithm="ed25519",
    )
    unsigned = _signed_replay_receipt(intent.preparation).model_copy(
        update={
            "replay_receipt_trust_anchor_key_id": attacker_root.key_id,
            "replay_receipt_trust_anchor_fingerprint_sha256": (
                attacker_root.public_key_fingerprint_sha256
            ),
            "signer_key_id": attacker_root.key_id,
            "signature_base64": base64.b64encode(b"a" * 64).decode("ascii"),
        }
    )
    attacker_receipt = unsigned.model_copy(
        update={
            "signature_base64": base64.b64encode(
                attacker.sign(container_attach_v4_replay_claim_receipt_canonical_message(unsigned))
            ).decode("ascii")
        }
    )

    with pytest.raises(ContainerAttachStaticV4Error) as error:
        _verify(bundle, monkeypatch, receipt=attacker_receipt)
    assert error.value.phase == "replay"

    reused_ticket_root = ContainerAttachV4ReplayReceiptTrustAnchorV4(
        schema_version="rsd.container-attach-replay-receipt-trust-anchor.v4",
        key_id=bundle["profile"].ticket_trust_anchor.key_id,
        public_key_base64=bundle["profile"].ticket_trust_anchor.public_key_base64,
        public_key_fingerprint_sha256=(
            bundle["profile"].ticket_trust_anchor.public_key_fingerprint_sha256
        ),
        algorithm="ed25519",
    )
    with pytest.raises(ContainerAttachStaticV4Error) as reused:
        _rebuild_profile(bundle["profile"], replay_receipt_trust_anchor=reused_ticket_root)
    assert reused.value.phase == "profile"

    reused_profile_root = ContainerAttachV4ReplayReceiptTrustAnchorV4(
        schema_version="rsd.container-attach-replay-receipt-trust-anchor.v4",
        key_id=bundle["profile_trust_anchor"].key_id,
        public_key_base64=bundle["profile_trust_anchor"].public_key_base64,
        public_key_fingerprint_sha256=(
            bundle["profile_trust_anchor"].public_key_fingerprint_sha256
        ),
        algorithm="ed25519",
    )
    profile_with_reused_root = _rebuild_profile(
        bundle["profile"], replay_receipt_trust_anchor=reused_profile_root
    )
    with pytest.raises(ContainerAttachStaticV4Error) as profile_reused:
        static_v4.verify_container_bootstrap_static_role_profile_envelope_v4(
            envelope=_profile_envelope(cast(Any, profile_with_reused_root)),
            profile_trust_anchor=bundle["profile_trust_anchor"],
        )
    assert profile_reused.value.phase == "profile"


def test_profile_owned_receipt_root_binds_request_ticket_and_intent(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    """A re-signed request cannot redirect receipt verification to another key."""

    bundle = _bundle(tmp_path)
    request = cast(Any, bundle["request"]).model_copy(
        update={
            "replay_receipt_trust_anchor_key_id": "redirected-receipt-root",
            "replay_receipt_trust_anchor_fingerprint_sha256": _hash("redirected-root"),
        }
    )
    redirected_ticket = _resign_ticket_for_request(bundle["ticket"], request)
    redirected_envelope = ContainerAttachTicketEnvelopeV4(
        schema_version="rsd.container-attach-ticket-envelope.v4",
        request=request,
        ticket=redirected_ticket,
    )
    monkeypatch.setattr(static_v4, "_trusted_utc_now", lambda: _NOW)

    with pytest.raises(ContainerAttachStaticV4Error) as error:
        prepare_container_attach_v4_claim_intent(
            static_role_profile_envelope=bundle["profile_envelope"],
            profile_trust_anchor=bundle["profile_trust_anchor"],
            envelope=redirected_envelope,
            expected_runtime=bundle["runtime"],
        )
    assert error.value.phase == "binding"


@pytest.mark.parametrize(
    "receipt_kwargs",
    (
        {"authority_effective_deadline_at": "2026-08-29T12:01:11Z"},
        {"authority_claim_timeout_seconds": 9},
    ),
)
def test_receipt_validation_rejects_signed_internal_timing_drift(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
    receipt_kwargs: dict[str, object],
) -> None:
    """Receipt timing is checked against signed ticket bounds, not caller time."""

    bundle = _bundle(tmp_path)
    intent = _claim_intent(bundle, monkeypatch)
    receipt = _signed_replay_receipt(intent.preparation, **receipt_kwargs)
    monotonic = iter((100.0, 101.0))
    monkeypatch.setattr(static_v4, "_trusted_monotonic_now", lambda: next(monotonic))

    with pytest.raises(ContainerAttachStaticV4Error) as error:
        validate_container_attach_v4_claim_receipt(
            claim_intent=intent,
            profile_trust_anchor=bundle["profile_trust_anchor"],
            receipt=receipt,
        )
    assert error.value.phase == "freshness"


def test_receipt_validation_does_not_compare_authority_clock_to_finalizer_clock(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    """Receipt timing is internally signed; finalizer time is local and independent."""

    bundle = _bundle(tmp_path)
    intent = _claim_intent(bundle, monkeypatch)
    receipt = _signed_replay_receipt(
        intent.preparation,
        authority_claim_started_at="2026-08-29T12:04:40Z",
        authority_effective_deadline_at="2026-08-29T12:04:50Z",
        claimed_at="2026-08-29T12:04:41Z",
    )

    result = _verify(bundle, monkeypatch, receipt=receipt)

    assert result.attach_allowed is False
    assert result.effect_allowed is False


def test_claim_intent_revalidation_rejects_stale_preparation_graph(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    """Altered operation/runtime fields cannot spend a prior intent/receipt."""

    bundle = _bundle(tmp_path)
    intent = _claim_intent(bundle, monkeypatch)
    changed_request = bundle["request"].model_copy(
        update={"operation_id": "123e4567-e89b-42d3-a456-426614174099"}
    )
    changed_ticket = _resign_ticket_for_request(bundle["ticket"], changed_request)
    changed_envelope = ContainerAttachTicketEnvelopeV4(
        schema_version="rsd.container-attach-ticket-envelope.v4",
        request=changed_request,
        ticket=changed_ticket,
    )
    altered_intent = intent.model_copy(update={"ticket_envelope": changed_envelope})

    with pytest.raises(ContainerAttachStaticV4Error) as error:
        validate_container_attach_v4_claim_receipt(
            claim_intent=altered_intent,
            profile_trust_anchor=bundle["profile_trust_anchor"],
            receipt=_signed_replay_receipt(intent.preparation),
        )
    assert error.value.phase in {"binding", "freshness", "replay"}


def test_claim_intent_parser_is_bounded_and_cannot_authorize(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    """The complete graph has a finite parser, but no authority invocation API."""

    intent = _claim_intent(_bundle(tmp_path), monkeypatch)
    raw = container_attach_v4_claim_intent_canonical_json(intent)

    assert len(raw) <= static_v4._MAX_CLAIM_INTENT_BYTES
    assert static_v4.parse_container_attach_v4_claim_intent_canonical_json(raw) == intent
    with pytest.raises(ContainerAttachStaticV4Error) as trailing:
        static_v4.parse_container_attach_v4_claim_intent_canonical_json(raw + b" ")
    assert trailing.value.phase == "replay"
    with pytest.raises(ContainerAttachStaticV4Error):
        static_v4.parse_container_attach_v4_claim_intent_canonical_json(
            b"{" + b" " * static_v4._MAX_CLAIM_INTENT_BYTES
        )


def test_maximum_legal_static_profile_fits_the_finite_claim_intent_cap(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    """Schema maxima cannot make the non-authorizing graph unparsable."""

    profile, profile_envelope, envelope, runtime = _maximum_public_v4_profile(tmp_path)
    monkeypatch.setattr(static_v4, "_trusted_utc_now", lambda: _NOW)
    intent = prepare_container_attach_v4_claim_intent(
        static_role_profile_envelope=cast(Any, profile_envelope),
        profile_trust_anchor=_profile_trust_anchor(),
        envelope=cast(Any, envelope),
        expected_runtime=cast(Any, runtime),
    )
    profile_raw = container_bootstrap_static_role_profile_v4_canonical_json(cast(Any, profile))
    profile_envelope_raw = (
        static_v4.container_bootstrap_static_role_profile_envelope_v4_canonical_json(
            cast(Any, profile_envelope)
        )
    )
    intent_raw = container_attach_v4_claim_intent_canonical_json(intent)

    assert len(profile_raw) <= static_v4._MAX_STATIC_CANONICAL_BYTES
    assert len(profile_envelope_raw) <= static_v4._MAX_PROFILE_ENVELOPE_CANONICAL_BYTES
    assert (
        static_v4.parse_container_bootstrap_static_role_profile_envelope_v4_canonical_json(
            profile_envelope_raw
        )
        == profile_envelope
    )
    assert len(intent_raw) <= static_v4._MAX_CLAIM_INTENT_BYTES
    assert static_v4.parse_container_attach_v4_claim_intent_canonical_json(intent_raw) == intent
    with pytest.raises(ValueError):
        ContainerBootstrapStaticLaunchPlanV4(
            **_updated_fields(
                cast(Any, profile).static_launch_plan,
                base_command=tuple("a" * 256 for _ in range(65)),
            )
        )
    with pytest.raises(ValueError):
        ContainerBootstrapStaticLaunchPlanV4(
            **_updated_fields(
                cast(Any, profile).static_launch_plan,
                wrapper_argv_prefix=tuple("a" * 256 for _ in range(64)),
                merged_argv_sha256=static_v4._merged_argv_sha256(
                    wrapper_argv_prefix=tuple("a" * 256 for _ in range(64)),
                    base_entrypoint=cast(Any, profile).static_launch_plan.base_entrypoint,
                    base_command=cast(Any, profile).static_launch_plan.base_command,
                ),
            )
        )


def test_receipt_validation_rechecks_expiry_and_local_monotonic_budget(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    """Receipt validation independently rejects a late local return."""

    bundle = _bundle(tmp_path)
    intent = _claim_intent(bundle, monkeypatch)
    receipt = _signed_replay_receipt(intent.preparation)
    monkeypatch.setattr(static_v4, "_trusted_utc_now", lambda: _NOW)
    clock = iter((100.0, 110.0))
    monkeypatch.setattr(static_v4, "_trusted_monotonic_now", lambda: next(clock))
    with pytest.raises(ContainerAttachStaticV4Error) as timeout:
        validate_container_attach_v4_claim_receipt(
            claim_intent=intent,
            profile_trust_anchor=bundle["profile_trust_anchor"],
            receipt=receipt,
        )
    assert timeout.value.phase == "freshness"


@pytest.mark.parametrize("invalid", (float("nan"), float("inf"), float("-inf"), True, 100))
def test_receipt_validation_rejects_nonfinite_or_nonexact_local_monotonic_reading(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch, invalid: object
) -> None:
    bundle = _bundle(tmp_path)
    intent = _claim_intent(bundle, monkeypatch)
    receipt = _signed_replay_receipt(intent.preparation)
    monkeypatch.setattr(static_v4, "_trusted_utc_now", lambda: _NOW)
    monkeypatch.setattr(static_v4, "_trusted_monotonic_now", lambda: invalid)
    with pytest.raises(ContainerAttachStaticV4Error) as error:
        validate_container_attach_v4_claim_receipt(
            claim_intent=intent,
            profile_trust_anchor=bundle["profile_trust_anchor"],
            receipt=receipt,
        )
    assert error.value.phase == "freshness"
    bundle = _bundle(tmp_path)
    canonical = container_attach_v4_request_canonical_json(bundle["request"])

    assert parse_container_attach_v4_request_canonical_json(canonical) == bundle["request"]
    with pytest.raises(ContainerAttachStaticV4Error):
        parse_container_attach_v4_request_canonical_json(canonical + b" ")
    constructed = type(bundle["request"]).model_construct(
        **bundle["request"].model_dump(mode="python")
    )
    with pytest.raises(ContainerAttachStaticV4Error):
        container_attach_v4_request_sha256(constructed)


def test_recursive_exact_types_reject_nested_subclass_and_stale_profile_copy(
    tmp_path: Path,
) -> None:
    bundle = _bundle(tmp_path)
    route = bundle["route"]
    profile = bundle["profile"]

    class HostileDeliveryField(ContainerBootstrapStaticDeliveryFieldV4):
        pass

    subclassed_field = HostileDeliveryField(**route.fields[0].model_dump(mode="python"))
    subclassed_route = route.model_copy(update={"fields": (subclassed_field, *route.fields[1:])})
    stale_profile = profile.model_copy(
        update={"selected_delivery_route": subclassed_route},
    )

    with pytest.raises(ContainerAttachStaticV4Error):
        static_v4.container_bootstrap_static_delivery_route_v4_sha256(subclassed_route)
    with pytest.raises(ContainerAttachStaticV4Error):
        container_bootstrap_static_role_profile_v4_sha256(stale_profile)


def test_projection_canonical_boundary_rejects_hostile_model_copy_state(tmp_path: Path) -> None:
    bundle = _bundle(tmp_path)
    projection = cast(ContainerBootstrapStaticDeliveryProjectionV4, bundle["projection"])
    route = projection.primary_infisical
    field = route.fields[0]

    class HostileDeliveryRoute(ContainerBootstrapStaticDeliveryRouteV4):
        pass

    zero_flag = projection.model_copy(update={"generated_wrapper_output_bound": 0})
    one_flag = projection.model_copy(update={"allocation_parameterized": 1})
    float_grammar = projection.primary_valkey_connection_uri.model_copy(
        update={"password_encoded_byte_count": 43.0}
    )
    float_projection = projection.model_copy(
        update={"primary_valkey_connection_uri": float_grammar}
    )
    list_route = route.model_copy(update={"fields": list(route.fields)})
    list_projection = projection.model_copy(update={"primary_infisical": list_route})
    enum_field = field.model_copy(update={"value_kind": field.value_kind.value})
    enum_route = route.model_copy(update={"fields": (enum_field, *route.fields[1:])})
    enum_projection = projection.model_copy(update={"primary_infisical": enum_route})
    subclassed_route = HostileDeliveryRoute.model_validate(
        route.model_dump(mode="python"), strict=True
    )
    subclass_projection = projection.model_copy(update={"primary_infisical": subclassed_route})
    hidden_projection = projection.model_copy()
    object.__setattr__(hidden_projection, "hidden", "x")
    deleted_projection = projection.model_copy()
    object.__delattr__(deleted_projection, "generated_wrapper_output_bound")
    cyclic_projection = projection.model_copy()
    object.__setattr__(cyclic_projection, "primary_infisical", cyclic_projection)
    constructed_projection = ContainerBootstrapStaticDeliveryProjectionV4.model_construct(
        **{
            **projection.model_dump(mode="python"),
            "generated_wrapper_output_bound": 0,
        }
    )

    for hostile in (
        zero_flag,
        one_flag,
        float_projection,
        list_projection,
        enum_projection,
        subclass_projection,
        hidden_projection,
        deleted_projection,
        cyclic_projection,
        constructed_projection,
    ):
        for helper in (
            container_bootstrap_static_delivery_projection_v4_canonical_json,
            container_bootstrap_static_delivery_projection_v4_sha256,
        ):
            with pytest.raises(ContainerAttachStaticV4Error) as error:
                helper(hostile)
            assert error.value.phase == "projection"
            assert str(error.value) == "container attach V4 verification failed"

    serialized = json.dumps(
        zero_flag.model_dump(mode="json"),
        ensure_ascii=True,
        sort_keys=True,
        separators=(",", ":"),
        allow_nan=False,
    ).encode("ascii")
    with pytest.raises(ContainerAttachStaticV4Error) as parser_error:
        parse_container_bootstrap_static_delivery_projection_v4_canonical_json(serialized)
    assert parser_error.value.phase == "projection"
    assert str(parser_error.value) == "container attach V4 verification failed"

    stale_profile = bundle["profile"].model_copy(update={"static_delivery_projection": zero_flag})
    stale_envelope = bundle["profile_envelope"].model_copy(
        update={"static_role_profile": stale_profile}
    )
    with pytest.raises(ContainerAttachStaticV4Error) as message_error:
        container_bootstrap_static_role_profile_envelope_v4_canonical_message(stale_envelope)
    assert message_error.value.phase == "profile"
    assert str(message_error.value) == "container attach V4 verification failed"

    preimage = bundle["profile"].static_patch_preimage
    optional_defaults = ContainerBootstrapStaticPatchPreimageV4(
        **preimage.model_dump(mode="python", exclude_none=True)
    )
    assert container_bootstrap_static_patch_preimage_v4_sha256(optional_defaults) == (
        container_bootstrap_static_patch_preimage_v4_sha256(preimage)
    )


def test_static_models_reject_secret_sentinel_and_never_render_a_target_value(
    tmp_path: Path,
) -> None:
    bundle = _bundle(tmp_path)
    sentinel = "not-a-hash-secret-sentinel"
    field = bundle["route"].fields[0]

    with pytest.raises(ValueError):
        ContainerBootstrapStaticDeliveryFieldV4(
            **_updated_fields(field, source_reference_sha256=sentinel)
        )

    for payload in (
        container_bootstrap_static_delivery_projection_v4_canonical_json(bundle["projection"]),
        container_bootstrap_static_role_profile_v4_canonical_json(bundle["profile"]),
        container_attach_v4_request_canonical_json(bundle["request"]),
        static_v4.container_attach_v4_ticket_envelope_canonical_json(bundle["envelope"]),
    ):
        assert sentinel.encode("ascii") not in payload
        assert b"DB_CONNECTION_URI=" not in payload
        assert b"REDIS_URL=" not in payload


def test_module_is_contract_only_and_has_no_effect_or_io_imports() -> None:
    tree = ast.parse(Path(static_v4.__file__).read_text(encoding="utf-8"))
    imported = {
        alias.name.split(".", 1)[0]
        for node in ast.walk(tree)
        if isinstance(node, ast.Import)
        for alias in node.names
    } | {
        node.module.split(".", 1)[0]
        for node in ast.walk(tree)
        if isinstance(node, ast.ImportFrom) and node.module is not None
    }

    assert not imported & {"socket", "subprocess", "pathlib", "os", "requests"}
    source = Path(static_v4.__file__).read_text(encoding="utf-8")
    assert "NoMutationBackend" not in source
    assert "read_secret" not in source
    assert "open(" not in source
    assert not any(
        name.startswith(("execute_", "materialize_", "start_", "deliver_"))
        for name, value in vars(static_v4).items()
        if callable(value)
    )
    assert not any(
        name.endswith(("Backend", "Engine", "Provider"))
        for name, value in vars(static_v4).items()
        if isinstance(value, type)
    )


def _vector_base64(payload: bytes) -> dict[str, object]:
    """Encode every public vector blob under one fixed segment grammar."""

    encoded = base64.b64encode(payload).decode("ascii")
    return {
        "encoding": _VECTOR_BASE64_ENCODING,
        "segments": [
            encoded[index : index + _VECTOR_BASE64_SEGMENT_CHARS]
            for index in range(0, len(encoded), _VECTOR_BASE64_SEGMENT_CHARS)
        ],
    }


def _assert_vector_text_is_public_safe(text: str) -> tuple[str, ...]:
    """Reject non-public textual carriers and return approved URI authorities."""

    lowered = text.lower()
    assert not any(
        marker in lowered
        for marker in (
            "private_key",
            "signing_seed",
            "seed_base64",
            "secret-sentinel",
            "authorization:",
        )
    )
    assert "http://" not in lowered
    assert "https://" not in lowered
    authorities: list[str] = []
    for match in re.finditer(r"(?:postgresql|redis)://[^\"'\s]+", text, flags=re.IGNORECASE):
        authority = match.group(0)
        parsed = urlsplit(authority)
        assert parsed.scheme in {"postgresql", "redis"}
        assert authority == authority.lower()
        assert parsed.username is None
        assert parsed.password is None
        assert parsed.hostname is not None
        assert parsed.path == ""
        assert parsed.query == ""
        assert parsed.fragment == ""
        try:
            port = parsed.port
        except ValueError as error:
            raise AssertionError("vector URI port is malformed") from error
        expected_port = (
            _POSTGRESQL_PROTOCOL_PORT if parsed.scheme == "postgresql" else _VALKEY_PROTOCOL_PORT
        )
        assert port == expected_port
        try:
            address = ipaddress.ip_address(parsed.hostname)
        except ValueError:
            assert parsed.hostname.endswith(".invalid")
        else:
            assert any(address in network for network in _DOCUMENTATION_NETWORKS)
        authorities.append(authority)
    for candidate in re.findall(r"(?<![0-9.])(?:[0-9]{1,3}\.){3}[0-9]{1,3}(?![0-9.])", text):
        address = ipaddress.ip_address(candidate)
        assert any(address in network for network in _DOCUMENTATION_NETWORKS)
    return tuple(authorities)


def _assert_decoded_vector_payload_is_public_safe(payload: bytes) -> tuple[str, ...]:
    """Inspect textual decoded payloads without treating binary signatures as text."""

    return _assert_vector_text_is_public_safe(payload.decode("ascii", errors="ignore"))


def _decode_nested_canonical_base64(value: str) -> bytes:
    """Decode one nested standard-base64 model field with its exact spelling."""

    decoded = base64.b64decode(value, validate=True)
    if base64.b64encode(decoded).decode("ascii") != value:
        raise AssertionError("nested vector base64 is noncanonical")
    return decoded


def _assert_vector_value_is_recursively_public_safe(
    value: object,
    *,
    field_name: str | None = None,
) -> tuple[str, ...]:
    """Walk the YAML envelope and every decoded canonical JSON payload."""

    if type(value) is dict:
        if set(value) == {"encoding", "segments"}:
            payload = _canonical_vector_base64(value)
            authorities = list(_assert_decoded_vector_payload_is_public_safe(payload))
            try:
                decoded = json.loads(payload.decode("ascii"))
            except (UnicodeDecodeError, json.JSONDecodeError):
                decoded = None
            if decoded is not None:
                authorities.extend(_assert_vector_value_is_recursively_public_safe(decoded))
            return tuple(authorities)
        authorities = []
        for key, nested in value.items():
            assert type(key) is str
            authorities.extend(
                _assert_vector_value_is_recursively_public_safe(nested, field_name=key)
            )
        return tuple(authorities)
    if type(value) is list:
        authorities = []
        for nested in value:
            authorities.extend(
                _assert_vector_value_is_recursively_public_safe(nested, field_name=field_name)
            )
        return tuple(authorities)
    if type(value) is str:
        authorities = list(_assert_vector_text_is_public_safe(value))
        if field_name is not None and field_name.endswith("_base64"):
            payload = _decode_nested_canonical_base64(value)
            authorities.extend(_assert_decoded_vector_payload_is_public_safe(payload))
            try:
                decoded = json.loads(payload.decode("ascii"))
            except (UnicodeDecodeError, json.JSONDecodeError):
                decoded = None
            if decoded is not None:
                authorities.extend(_assert_vector_value_is_recursively_public_safe(decoded))
        return tuple(authorities)
    return ()


def _cross_language_v4_vector_expected(tmp_path: Path) -> dict[str, object]:
    """Return every V4 vector commitment from one fixed public fixture graph."""

    values = _public_vector_data(tmp_path)
    profile_root = cast(Any, values["profile_trust_anchor"])
    profile_envelope = cast(Any, values["profile_envelope"])
    projection = cast(Any, values["projection"])
    route = cast(Any, values["route"])
    launch = cast(Any, values["launch"])
    preimage = cast(Any, values["preimage"])
    patch = cast(Any, values["patch"])
    profile = cast(Any, values["profile"])
    protocol = cast(Any, values["protocol"])
    request = cast(Any, values["request"])
    runtime = cast(Any, values["runtime"])
    ticket = cast(Any, values["ticket"])
    ticket_envelope = cast(Any, values["ticket_envelope"])
    replay_claim = cast(Any, values["replay_claim"])
    preparation = cast(Any, values["preparation"])
    claim_intent = cast(Any, values["claim_intent"])
    replay_root = cast(Any, values["replay_receipt_trust_anchor"])
    receipt = cast(Any, values["receipt"])
    return {
        "schema_version": "rsd.container-bootstrap-static-v4-vector-set.v4",
        "base64_encoding": "standard_base64_fixed_segments_v1",
        "static_uri_grammar_digest_domain_base64": _vector_base64(
            b"omninode-rsd.container-bootstrap-static-uri-grammar.sha256.v4\x00"
        ),
        "projection_digest_domain_base64": _vector_base64(
            b"omninode-rsd.container-bootstrap-static-delivery-projection.sha256.v4\x00"
        ),
        "route_digest_domain_base64": _vector_base64(
            b"omninode-rsd.container-bootstrap-static-delivery-route.sha256.v4\x00"
        ),
        "launch_plan_digest_domain_base64": _vector_base64(
            b"omninode-rsd.container-bootstrap-static-launch-plan.sha256.v4\x00"
        ),
        "patch_preimage_digest_domain_base64": _vector_base64(
            b"omninode-rsd.container-bootstrap-static-patch-preimage.sha256.v4\x00"
        ),
        "patch_policy_digest_domain_base64": _vector_base64(
            b"omninode-rsd.container-bootstrap-static-patch-policy.sha256.v4\x00"
        ),
        "profile_digest_domain_base64": _vector_base64(
            b"omninode-rsd.container-bootstrap-static-role-profile.sha256.v4\x00"
        ),
        "profile_envelope_signature_domain_base64": _vector_base64(
            b"omninode-rsd.container-bootstrap-static-role-profile-envelope.ed25519.v4\x00"
        ),
        "profile_envelope_hash_domain_base64": _vector_base64(
            b"omninode-rsd.container-bootstrap-static-role-profile-envelope.sha256.v4\x00"
        ),
        "protocol_digest_domain_base64": _vector_base64(
            b"omninode-rsd.container-bootstrap-attach-protocol.sha256.v4\x00"
        ),
        "request_digest_domain_base64": _vector_base64(
            b"omninode-rsd.container-attach-request.sha256.v4\x00"
        ),
        "runtime_binding_digest_domain_base64": _vector_base64(
            b"omninode-rsd.container-attach-runtime-binding.sha256.v4\x00"
        ),
        "ticket_signature_domain_base64": _vector_base64(
            b"omninode-rsd.container-attach-ticket.ed25519.v4\x00"
        ),
        "ticket_hash_domain_base64": _vector_base64(
            b"omninode-rsd.container-attach-ticket.sha256.v4\x00"
        ),
        "ticket_replay_claim_digest_domain_base64": _vector_base64(
            b"omninode-rsd.container-attach-ticket-replay-claim.sha256.v4\x00"
        ),
        "container_lifetime_claim_digest_domain_base64": _vector_base64(
            b"omninode-rsd.container-attach-container-lifetime-claim.sha256.v4\x00"
        ),
        "replay_claim_digest_domain_base64": _vector_base64(
            b"omninode-rsd.container-attach-replay-claim.sha256.v4\x00"
        ),
        "replay_preparation_digest_domain_base64": _vector_base64(
            b"omninode-rsd.container-attach-claim-preparation.sha256.v4\x00"
        ),
        "replay_receipt_signature_domain_base64": _vector_base64(
            b"omninode-rsd.container-attach-replay-receipt.ed25519.v4\x00"
        ),
        "profile_root_canonical_json_utf8_base64": _vector_base64(
            static_v4.container_bootstrap_static_profile_trust_anchor_v4_canonical_json(
                profile_root
            )
        ),
        "profile_envelope_canonical_json_utf8_base64": _vector_base64(
            static_v4.container_bootstrap_static_role_profile_envelope_v4_canonical_json(
                profile_envelope
            )
        ),
        "profile_envelope_sha256": container_bootstrap_static_role_profile_envelope_v4_sha256(
            profile_envelope
        ),
        "projection_canonical_json_utf8_base64": _vector_base64(
            container_bootstrap_static_delivery_projection_v4_canonical_json(projection)
        ),
        "projection_sha256": container_bootstrap_static_delivery_projection_v4_sha256(projection),
        "route_canonical_json_utf8_base64": _vector_base64(
            static_v4.container_bootstrap_static_delivery_route_v4_canonical_json(route)
        ),
        "route_sha256": static_v4.container_bootstrap_static_delivery_route_v4_sha256(route),
        "launch_plan_canonical_json_utf8_base64": _vector_base64(
            static_v4.container_bootstrap_static_launch_plan_v4_canonical_json(launch)
        ),
        "launch_plan_sha256": static_v4.container_bootstrap_static_launch_plan_v4_sha256(launch),
        "patch_preimage_canonical_json_utf8_base64": _vector_base64(
            static_v4.container_bootstrap_static_patch_preimage_v4_canonical_json(preimage)
        ),
        "patch_preimage_sha256": static_v4.container_bootstrap_static_patch_preimage_v4_sha256(
            preimage
        ),
        "patch_policy_canonical_json_utf8_base64": _vector_base64(
            static_v4.container_bootstrap_static_patch_policy_v4_canonical_json(patch)
        ),
        "patch_policy_sha256": static_v4.container_bootstrap_static_patch_policy_v4_sha256(patch),
        "profile_canonical_json_utf8_base64": _vector_base64(
            container_bootstrap_static_role_profile_v4_canonical_json(profile)
        ),
        "profile_sha256": container_bootstrap_static_role_profile_v4_sha256(profile),
        "protocol_canonical_json_utf8_base64": _vector_base64(
            static_v4.container_bootstrap_attach_v4_protocol_canonical_json(protocol)
        ),
        "protocol_sha256": container_bootstrap_attach_v4_protocol_sha256(protocol),
        "request_canonical_json_utf8_base64": _vector_base64(
            container_attach_v4_request_canonical_json(request)
        ),
        "request_sha256": container_attach_v4_request_sha256(request),
        "runtime_binding_canonical_json_utf8_base64": _vector_base64(
            static_v4.container_attach_v4_runtime_binding_canonical_json(runtime)
        ),
        "runtime_instance_binding_preimage_base64": _vector_base64(
            static_v4.container_attach_v4_runtime_instance_binding_preimage(
                container_id=runtime.container_id,
                runtime_hostname=runtime.runtime_hostname,
            )
        ),
        "runtime_instance_binding_sha256": runtime.runtime_instance_binding_sha256,
        "ticket_canonical_json_utf8_base64": _vector_base64(
            static_v4.container_attach_v4_ticket_canonical_json(ticket)
        ),
        "ticket_canonical_message_base64": _vector_base64(
            container_attach_v4_ticket_canonical_message(ticket)
        ),
        "ticket_sha256": static_v4.container_attach_v4_ticket_sha256(ticket),
        "ticket_envelope_canonical_json_utf8_base64": _vector_base64(
            static_v4.container_attach_v4_ticket_envelope_canonical_json(ticket_envelope)
        ),
        "replay_claim_canonical_json_utf8_base64": _vector_base64(
            static_v4.container_attach_v4_replay_claim_canonical_json(replay_claim)
        ),
        "replay_claim_sha256": container_attach_v4_replay_claim_sha256(replay_claim),
        "ticket_replay_claim_sha256": container_attach_v4_ticket_replay_claim_sha256(
            replay_claim.ticket_claim
        ),
        "container_lifetime_claim_sha256": container_attach_v4_container_lifetime_claim_sha256(
            replay_claim.container_lifetime_claim
        ),
        "preparation_canonical_json_utf8_base64": _vector_base64(
            container_attach_v4_claim_preparation_canonical_json(preparation)
        ),
        "claim_intent_canonical_json_utf8_base64": _vector_base64(
            container_attach_v4_claim_intent_canonical_json(claim_intent)
        ),
        "replay_receipt_root_canonical_json_utf8_base64": _vector_base64(
            static_v4.container_attach_v4_replay_receipt_trust_anchor_v4_canonical_json(replay_root)
        ),
        "replay_receipt_canonical_json_utf8_base64": _vector_base64(
            static_v4.container_attach_v4_replay_claim_receipt_canonical_json(receipt)
        ),
        "profile_root_public_key_base64": _vector_base64(
            base64.b64decode(profile_root.public_key_base64, validate=True)
        ),
        "profile_root_signer_key_id": profile_root.key_id,
        "ticket_public_key_base64": _vector_base64(
            base64.b64decode(profile.ticket_trust_anchor.public_key_base64, validate=True)
        ),
        "ticket_signer_key_id": ticket.signer_key_id,
        "replay_receipt_public_key_base64": _vector_base64(
            base64.b64decode(replay_root.public_key_base64, validate=True)
        ),
        "replay_receipt_signer_key_id": receipt.signer_key_id,
        "profile_envelope_canonical_message_base64": _vector_base64(
            container_bootstrap_static_role_profile_envelope_v4_canonical_message(profile_envelope)
        ),
        "replay_receipt_canonical_message_base64": _vector_base64(
            container_attach_v4_replay_claim_receipt_canonical_message(receipt)
        ),
        "frame_magic": protocol.frame_magic,
        "frame_version": protocol.frame_version,
        "frame_header_layout": protocol.frame_header_layout,
        "secret_chunk_ordinal_layout": protocol.secret_chunk_ordinal_layout,
        "max_metadata_bytes": protocol.max_metadata_bytes,
        "max_chunk_bytes": protocol.max_chunk_bytes,
        "max_chunks_per_target": protocol.max_chunks_per_target,
        "max_total_secret_bytes": protocol.max_total_secret_bytes,
    }


def test_cross_language_vector_is_public_key_only_and_binds_the_full_v4_graph(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    """Verify the full public V4 graph, profile root, and replay receipt.

    The vector intentionally contains no signing seed, target material,
    credential-bearing URI, provider reference, artifact output, or runtime
    effect. It is a parser/hash/signature interoperability vector only.
    """

    raw = _VECTOR_PATH.read_text(encoding="ascii")
    assert not any(marker in raw for marker in ("&", "*", "!"))
    parsed = yaml.load(raw, Loader=_StrictVectorLoader)
    assert type(parsed) is dict
    vector = cast(dict[str, object], parsed)
    assert vector == _cross_language_v4_vector_expected(tmp_path)
    assert vector["base64_encoding"] == _VECTOR_BASE64_ENCODING
    for name, encoded in vector.items():
        if name.endswith("_base64"):
            assert type(encoded) is dict
            assert set(encoded) == {"encoding", "segments"}
            assert _canonical_vector_base64(encoded)
    authorities = _assert_vector_value_is_recursively_public_safe(vector)
    assert set(authorities) == {
        _VECTOR_POSTGRESQL_AUTHORITY,
        _VECTOR_PRIMARY_VALKEY_AUTHORITY,
        _VECTOR_RESTORE_VALKEY_AUTHORITY,
    }
    assert {urlsplit(authority).port for authority in authorities} == _VECTOR_ALLOWED_URI_PORTS

    profile_root = (
        static_v4.parse_container_bootstrap_static_profile_trust_anchor_v4_canonical_json(
            _canonical_vector_base64(vector["profile_root_canonical_json_utf8_base64"])
        )
    )
    profile_envelope = (
        static_v4.parse_container_bootstrap_static_role_profile_envelope_v4_canonical_json(
            _canonical_vector_base64(vector["profile_envelope_canonical_json_utf8_base64"])
        )
    )
    projection = static_v4.parse_container_bootstrap_static_delivery_projection_v4_canonical_json(
        _canonical_vector_base64(vector["projection_canonical_json_utf8_base64"])
    )
    request = static_v4.parse_container_attach_v4_request_canonical_json(
        _canonical_vector_base64(vector["request_canonical_json_utf8_base64"])
    )
    runtime = static_v4.parse_container_attach_v4_runtime_binding_canonical_json(
        _canonical_vector_base64(vector["runtime_binding_canonical_json_utf8_base64"])
    )
    ticket_envelope = static_v4.parse_container_attach_v4_ticket_envelope_canonical_json(
        _canonical_vector_base64(vector["ticket_envelope_canonical_json_utf8_base64"])
    )
    replay_claim = static_v4.parse_container_attach_v4_replay_claim_canonical_json(
        _canonical_vector_base64(vector["replay_claim_canonical_json_utf8_base64"])
    )
    preparation = static_v4.parse_container_attach_v4_claim_preparation_canonical_json(
        _canonical_vector_base64(vector["preparation_canonical_json_utf8_base64"])
    )
    claim_intent = static_v4.parse_container_attach_v4_claim_intent_canonical_json(
        _canonical_vector_base64(vector["claim_intent_canonical_json_utf8_base64"])
    )
    receipt_root = (
        static_v4.parse_container_attach_v4_replay_receipt_trust_anchor_v4_canonical_json(
            _canonical_vector_base64(vector["replay_receipt_root_canonical_json_utf8_base64"])
        )
    )
    receipt = static_v4.parse_container_attach_v4_replay_claim_receipt_canonical_json(
        _canonical_vector_base64(vector["replay_receipt_canonical_json_utf8_base64"])
    )
    profile = static_v4.verify_container_bootstrap_static_role_profile_envelope_v4(
        envelope=profile_envelope,
        profile_trust_anchor=profile_root,
    )
    assert profile.static_delivery_projection == projection
    assert profile.selected_delivery_route.fields == request.fields
    assert request.static_role_profile_envelope_sha256 == vector["profile_envelope_sha256"]
    assert ticket_envelope.request == request
    assert preparation.replay_claim == replay_claim
    assert preparation.validation.request_sha256 == vector["request_sha256"]
    assert replay_claim.container_lifetime_claim.container_id == runtime.container_id
    monkeypatch.setattr(static_v4, "_trusted_utc_now", lambda: _NOW)
    monkeypatch.setattr(static_v4, "_trusted_monotonic_now", lambda: 101.0)
    assert claim_intent.static_role_profile_envelope == profile_envelope
    assert claim_intent.ticket_envelope == ticket_envelope
    assert claim_intent.expected_runtime == runtime
    assert claim_intent.preparation == preparation
    validated = validate_container_attach_v4_claim_receipt(
        claim_intent=claim_intent,
        profile_trust_anchor=profile_root,
        receipt=receipt,
    )
    assert validated.replay_claim_sha256 == vector["replay_claim_sha256"]
    assert validated.attach_allowed is False
    assert validated.effect_allowed is False
    assert _canonical_vector_base64(vector["ticket_public_key_base64"]) == base64.b64decode(
        profile.ticket_trust_anchor.public_key_base64, validate=True
    )
    assert _canonical_vector_base64(vector["replay_receipt_public_key_base64"]) == base64.b64decode(
        receipt_root.public_key_base64, validate=True
    )
    assert _canonical_vector_base64(vector["profile_envelope_canonical_message_base64"]) == (
        container_bootstrap_static_role_profile_envelope_v4_canonical_message(profile_envelope)
    )
    assert _canonical_vector_base64(vector["replay_receipt_canonical_message_base64"]) == (
        container_attach_v4_replay_claim_receipt_canonical_message(receipt)
    )


def test_vector_encoding_and_recursive_public_safety_reject_aliases_and_private_endpoints() -> None:
    """Every vector blob has one spelling and only synthetic public authority data."""

    with pytest.raises(ValueError):
        _canonical_vector_base64("YWJj")
    with pytest.raises(ValueError):
        _canonical_vector_base64(
            {"encoding": _VECTOR_BASE64_ENCODING, "segments": ["YWJj", "ZA=="]}
        )
    forbidden_host = ".".join(("10", "0", "0", "7"))
    forbidden_authority = "postgresql:" + "//" + forbidden_host + ":5432"
    with pytest.raises(AssertionError):
        _assert_vector_value_is_recursively_public_safe(
            _vector_base64(('{"authority":"' + forbidden_authority + '"}').encode("ascii"))
        )
    nested_base64 = base64.b64encode(
        ('{"authority":"' + forbidden_authority + '"}').encode("ascii")
    ).decode("ascii")
    with pytest.raises(AssertionError):
        _assert_vector_value_is_recursively_public_safe(
            _vector_base64(('{"signature_base64":"' + nested_base64 + '"}').encode("ascii"))
        )
    for hostile_authority in (
        _VECTOR_POSTGRESQL_AUTHORITY.rsplit(":", 1)[0] + ":15432",
        "postgresql:" + "//" + "not-synthetic" + ".example:5432",
        "postgresql:" + "//" + "user@" + "203.0.113.40:5432",
        "POSTGRESQL:" + "//" + "not-synthetic" + ".example:5432",
        "redis:" + "//" + "203.0.113.30:5432",
        _VECTOR_POSTGRESQL_AUTHORITY + "/unexpected-path",
    ):
        with pytest.raises(AssertionError):
            _assert_vector_value_is_recursively_public_safe(
                _vector_base64(('{"authority":"' + hostile_authority + '"}').encode("ascii"))
            )
    with pytest.raises(AssertionError):
        _assert_vector_value_is_recursively_public_safe(
            _vector_base64(('{"uri":"https:' + "//" + 'real.example/service"}').encode("ascii"))
        )
    with pytest.raises(AssertionError):
        _assert_vector_value_is_recursively_public_safe(
            _vector_base64(b'{"credential":"secret-sentinel"}')
        )
