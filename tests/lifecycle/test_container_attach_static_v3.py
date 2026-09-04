"""Adversarial offline tests for output-independent V3 target ticket checks.

The fixtures borrow only existing value-free V2 policy objects.  They never
open a container socket, resolve an image, read provider material, or create a
runtime effect.
"""

from __future__ import annotations

import base64
import hashlib
import importlib.util
import json
import sys
from datetime import UTC, datetime, timedelta
from pathlib import Path
from typing import Any, cast

import pytest
import yaml
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey, Ed25519PublicKey

from omninode_rsd.lifecycle import container_attach_static_v3 as static_v3
from omninode_rsd.lifecycle.container_attach_static_v3 import (
    ContainerAttachAuthorizationTicketV3,
    ContainerAttachRequestV3,
    ContainerAttachRuntimeBindingV3,
    ContainerAttachStaticV3Error,
    ContainerAttachTicketEnvelopeV3,
    ContainerAttachV3ClaimDeadlineV3,
    ContainerAttachV3ClaimedTicketV3,
    ContainerAttachV3ReplayClaimReceiptV3,
    ContainerAttachV3ReplayClaimV3,
    ContainerBootstrapAttachProtocolV3,
    ContainerBootstrapBaseLaunchCommitmentV3,
    ContainerBootstrapDerivedUriCommitmentV3,
    ContainerBootstrapStaticRoleProfileV3,
    ContainerBootstrapTargetDeliveryDescriptorV3,
    claim_container_attach_v3_ticket,
    container_attach_v3_container_lifetime_claim_sha256,
    container_attach_v3_replay_claim_canonical_json,
    container_attach_v3_replay_claim_sha256,
    container_attach_v3_request_canonical_json,
    container_attach_v3_request_sha256,
    container_attach_v3_runtime_binding_canonical_json,
    container_attach_v3_runtime_instance_binding_preimage,
    container_attach_v3_runtime_instance_binding_sha256,
    container_attach_v3_ticket_canonical_message,
    container_attach_v3_ticket_replay_claim_sha256,
    container_attach_v3_ticket_sha256,
    container_bootstrap_attach_v3_protocol_canonical_json,
    container_bootstrap_attach_v3_protocol_sha256,
    container_bootstrap_static_role_profile_v3_canonical_json,
    container_bootstrap_static_role_profile_v3_sha256,
    container_bootstrap_target_delivery_descriptor_v3_canonical_json,
    container_bootstrap_target_delivery_descriptor_v3_sha256,
    parse_container_attach_v3_replay_claim_canonical_json,
    parse_container_attach_v3_request_canonical_json,
    parse_container_attach_v3_runtime_binding_canonical_json,
    parse_container_attach_v3_ticket_canonical_json,
    parse_container_bootstrap_attach_v3_protocol_canonical_json,
    parse_container_bootstrap_static_role_profile_v3_canonical_json,
    parse_container_bootstrap_target_delivery_descriptor_v3_canonical_json,
    validate_container_attach_v3_ticket,
)
from omninode_rsd.lifecycle.infisical_disposable import (
    ContainerAttachTicketTrustAnchorV1,
    ContainerBootstrapStaticEnvironmentV2,
    canonical_sha256,
    target_delivery_map_sha256,
)


def _load_v2_fixtures() -> Any:
    """Load existing V2 policy fixtures without making ``tests`` a package."""

    path = Path(__file__).with_name("test_container_attach_v2.py")
    spec = importlib.util.spec_from_file_location("_rsd_v3_v2_fixtures", path)
    if spec is None or spec.loader is None:
        raise RuntimeError("V2 fixture module is unavailable")
    module = importlib.util.module_from_spec(spec)
    sys.modules[spec.name] = module
    spec.loader.exec_module(module)
    return module


v2_fixtures = _load_v2_fixtures()

_SIGNER = Ed25519PrivateKey.from_private_bytes(b"3" * 32)
_PUBLIC = _SIGNER.public_key().public_bytes_raw()
_NOW = datetime(2026, 8, 29, 12, 1, tzinfo=UTC)
_VECTOR_PATH = (
    Path(__file__).parents[2]
    / "src"
    / "omninode_rsd"
    / "lifecycle"
    / "container_attach_static_v3_vectors.yaml"
)


def _hash(label: str) -> str:
    return hashlib.sha256(label.encode("ascii")).hexdigest()


def _signature(message: bytes) -> str:
    return base64.b64encode(_SIGNER.sign(message)).decode("ascii")


def _updated_fields(model: object, **changes: object) -> dict[str, object]:
    """Make a constructor mapping without duplicate keyword expansion."""

    fields = cast(Any, model).model_dump(mode="python")
    fields.update(changes)
    return cast(dict[str, object], fields)


def _resign_ticket_for_request(
    ticket: ContainerAttachAuthorizationTicketV3,
    request: ContainerAttachRequestV3,
) -> ContainerAttachAuthorizationTicketV3:
    """Reissue a synthetic ticket after a deliberate value-free binding change."""

    unsigned = ContainerAttachAuthorizationTicketV3(
        **_updated_fields(
            ticket,
            protocol_sha256=request.attach_protocol_v3_sha256,
            request_sha256=container_attach_v3_request_sha256(request),
            allocation_operation_id=request.allocation_operation_id,
            operation_scope=request.operation_scope,
            operation_id=request.operation_id,
            component=request.component,
            component_role=request.component_role,
            container_id=request.container_id,
            runtime_hostname=request.runtime_hostname,
            runtime_instance_binding_sha256=request.runtime_instance_binding_sha256,
            static_role_profile_sha256=request.static_role_profile_sha256,
            target_delivery_map_sha256=request.target_delivery_map_sha256,
            target_delivery_descriptor_sha256=request.target_delivery_descriptor_sha256,
            request_nonce_sha256=request.request_nonce_sha256,
            channel_binding_sha256=request.channel_binding_sha256,
            session_binding_sha256=request.session_binding_sha256,
            signature_base64=base64.b64encode(b"x" * 64).decode("ascii"),
        )
    )
    return unsigned.model_copy(
        update={
            "signature_base64": _signature(container_attach_v3_ticket_canonical_message(unsigned))
        }
    )


def _envelope_for_request(
    request: ContainerAttachRequestV3,
    ticket: ContainerAttachAuthorizationTicketV3,
) -> ContainerAttachTicketEnvelopeV3:
    """Build an exact synthetic first-frame envelope from a request/ticket pair."""

    return ContainerAttachTicketEnvelopeV3(
        schema_version="rsd.container-attach-ticket-envelope.v3",
        request=request,
        ticket=ticket,
    )


class _StrictVectorLoader(yaml.SafeLoader):
    """Reject duplicate YAML keys in a vector intended for another language."""


def _strict_mapping(
    loader: yaml.SafeLoader, node: yaml.MappingNode, deep: bool = False
) -> dict[object, object]:
    """Construct one mapping while rejecting duplicate scalar keys."""

    mapping: dict[object, object] = {}
    for key_node, value_node in node.value:
        key = loader.construct_object(key_node, deep=deep)
        if key in mapping:
            raise ValueError("duplicate V3 vector key")
        mapping[key] = loader.construct_object(value_node, deep=deep)
    return mapping


_StrictVectorLoader.add_constructor(
    yaml.resolver.BaseResolver.DEFAULT_MAPPING_TAG,
    _strict_mapping,
)


def _canonical_vector_base64(value: object) -> bytes:
    """Decode one exact vector base64 spelling without a permissive alias."""

    if type(value) is not str:
        raise AssertionError("vector base64 field is not a string")
    raw = base64.b64decode(value, validate=True)
    assert base64.b64encode(raw).decode("ascii") == value
    return raw


def _anchor(*, key_id: str = "v3-signer") -> ContainerAttachTicketTrustAnchorV1:
    return ContainerAttachTicketTrustAnchorV1(
        schema_version="rsd.container-attach-ticket-trust-anchor.v1",
        key_id=key_id,
        public_key_base64=base64.b64encode(_PUBLIC).decode("ascii"),
        public_key_fingerprint_sha256=hashlib.sha256(_PUBLIC).hexdigest(),
        algorithm="ed25519",
    )


def _protocol() -> ContainerBootstrapAttachProtocolV3:
    return ContainerBootstrapAttachProtocolV3(
        schema_version="rsd.container-bootstrap-attach-protocol.v3",
        protocol_name="rsd_container_bootstrap_attach_v3",
        frame_magic="ONC3",
        frame_version=3,
        metadata_encoding="canonical_json_utf8_v1",
        frame_header_layout="magic_4_version_u8_type_u8_length_u32be_v1",
        secret_chunk_ordinal_layout="u16be_v1",
        allowed_operation_scopes=("materialize_and_start_runtime_v1", "start_runtime_v2"),
        first_frame="ticket_envelope_v3",
        ready_state="ready_v3",
        claim_state="claimed_v3",
        write_closed_state="write_closed_v3",
        terminal_ack_state="terminal_ack_v3",
        ambiguous_state="attach_ambiguous_v3",
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


def _base_launch(component: str, artifact: object) -> ContainerBootstrapBaseLaunchCommitmentV3:
    """Build only value-free base-launch commitments, never a V2 artifact identity."""

    v2_artifact = cast(Any, artifact)
    base = v2_artifact.base_image_policy
    return ContainerBootstrapBaseLaunchCommitmentV3(
        schema_version="rsd.container-bootstrap-base-launch-commitment.v3",
        component=cast(Any, component),
        component_role="valkey" if component.endswith("valkey") else "infisical",
        base_image_policy_sha256=canonical_sha256(base),
        base_resolution_attestation_sha256=canonical_sha256(base.resolution_attestation),
        base_registry_index_digest_sha256=base.registry_index_digest_sha256,
        base_linux_amd64_manifest_digest_sha256=base.linux_amd64_manifest_digest_sha256,
        base_config_digest_sha256=base.config_digest_sha256,
        static_patch_policy_sha256=_hash(f"v3-{component}-static-patch-policy"),
        wrapper_argv_prefix_sha256=_hash(f"v3-{component}-wrapper-argv-prefix"),
        base_entrypoint_sha256=_hash(f"v3-{component}-base-entrypoint"),
        base_command_sha256=_hash(f"v3-{component}-base-command"),
        entrypoint_command_merge="exec_wrapper_then_base_entrypoint_and_cmd_v3",
        merged_argv_sha256=_hash(f"v3-{component}-merged-argv"),
    )


def _derived_uri_commitments(
    delivery: object,
) -> tuple[ContainerBootstrapDerivedUriCommitmentV3, ...]:
    """Extract only exact public grammar commitments for the compiled profile."""

    return tuple(
        ContainerBootstrapDerivedUriCommitmentV3(
            schema_version="rsd.container-bootstrap-derived-uri-commitment.v3",
            source_purpose=cast(Any, field.source_purpose),
            value_kind=cast(Any, field.value_kind.value),
            field_format=cast(Any, field.format),
            target_field=cast(Any, field.target_field),
            encoded_byte_count=field.encoded_byte_count,
            derivation_binding_sha256=field.derivation_binding_sha256,
        )
        for field in cast(Any, delivery).fields
        if field.value_kind.value in ("derived_postgresql_uri_v1", "derived_valkey_uri_v1")
    )


def _profile_bundle(tmp_path: Path, *, component: str = "primary_infisical") -> dict[str, object]:
    """Build a complete pure V3 profile and signed ticket fixture."""

    controls = v2_fixtures._controls(tmp_path, component=component)
    artifact = cast(Any, controls["manifest"]).__getattribute__(component)
    delivery_map = controls["delivery_map"]
    delivery = getattr(delivery_map, component)
    descriptor = ContainerBootstrapTargetDeliveryDescriptorV3(
        schema_version="rsd.container-bootstrap-target-delivery-descriptor.v3",
        component=cast(Any, component),
        component_role="valkey" if component.endswith("valkey") else "infisical",
        sink=delivery.sink,
        fields=delivery.fields,
        derived_uri_commitments=_derived_uri_commitments(delivery),
    )
    profile = ContainerBootstrapStaticRoleProfileV3(
        schema_version="rsd.container-bootstrap-static-role-profile.v3",
        source_commit=v2_fixtures.v1_fixtures._COMMIT,
        component=cast(Any, component),
        component_role="valkey" if component.endswith("valkey") else "infisical",
        compile_target="x86_64-unknown-linux-musl",
        ticket_trust_anchor=_anchor(),
        attach_protocol=_protocol(),
        target_delivery_map_sha256=target_delivery_map_sha256(delivery_map),
        target_delivery_descriptor=descriptor,
        base_launch_commitment=_base_launch(component, artifact),
        static_environment=artifact.static_environment,
        child_environment_policy=artifact.child_environment_policy,
        fd_policy=artifact.fd_policy,
        pid1_policy=artifact.pid1_policy,
        memory_safety_policy=artifact.memory_safety_policy,
        valkey_launch_policy=artifact.valkey_launch_policy,
    )
    container_id = "c" * 64 if component == "primary_infisical" else _hash(f"{component}-container")
    hostname = (
        "rsd-runtime-hostname-123456"
        if component == "primary_infisical"
        else f"rsd-{component.replace('_', '-')}-runtime-123456"
    )
    runtime = ContainerAttachRuntimeBindingV3(
        schema_version="rsd.container-attach-runtime-binding.v3",
        allocation_operation_id="123e4567-e89b-42d3-a456-426614174000",
        operation_scope="materialize_and_start_runtime_v1",
        operation_id="123e4567-e89b-42d3-a456-426614174001",
        component=cast(Any, component),
        component_role="valkey" if component.endswith("valkey") else "infisical",
        container_id=container_id,
        runtime_hostname=hostname,
        runtime_instance_binding_sha256=container_attach_v3_runtime_instance_binding_sha256(
            container_id=container_id,
            runtime_hostname=hostname,
        ),
        request_nonce_sha256=_hash(f"{component}-nonce"),
        channel_binding_sha256=_hash(f"{component}-channel"),
        session_binding_sha256=_hash(f"{component}-session"),
    )
    request = ContainerAttachRequestV3(
        schema_version="rsd.container-attach-request.v3",
        allocation_operation_id=runtime.allocation_operation_id,
        operation_scope=runtime.operation_scope,
        operation_id=runtime.operation_id,
        component=runtime.component,
        component_role=runtime.component_role,
        container_id=runtime.container_id,
        runtime_hostname=runtime.runtime_hostname,
        runtime_instance_binding_sha256=runtime.runtime_instance_binding_sha256,
        static_role_profile_sha256=container_bootstrap_static_role_profile_v3_sha256(profile),
        target_delivery_map_sha256=profile.target_delivery_map_sha256,
        target_delivery_descriptor_sha256=(
            container_bootstrap_target_delivery_descriptor_v3_sha256(descriptor)
        ),
        attach_protocol_v3_sha256=container_bootstrap_attach_v3_protocol_sha256(
            profile.attach_protocol
        ),
        request_nonce_sha256=runtime.request_nonce_sha256,
        channel_binding_sha256=runtime.channel_binding_sha256,
        session_binding_sha256=runtime.session_binding_sha256,
        expected_ready_state="ready_v3",
        expected_claim_state="claimed_v3",
        expected_terminal_ack_state="terminal_ack_v3",
        fields=descriptor.fields,
    )
    unsigned_ticket = ContainerAttachAuthorizationTicketV3(
        schema_version="rsd.container-attach-authorization-ticket.v3",
        protocol_sha256=request.attach_protocol_v3_sha256,
        request_sha256=container_attach_v3_request_sha256(request),
        allocation_operation_id=request.allocation_operation_id,
        operation_scope=request.operation_scope,
        operation_id=request.operation_id,
        component=request.component,
        component_role=request.component_role,
        container_id=request.container_id,
        runtime_hostname=request.runtime_hostname,
        runtime_instance_binding_sha256=request.runtime_instance_binding_sha256,
        static_role_profile_sha256=request.static_role_profile_sha256,
        target_delivery_map_sha256=request.target_delivery_map_sha256,
        target_delivery_descriptor_sha256=request.target_delivery_descriptor_sha256,
        request_nonce_sha256=request.request_nonce_sha256,
        channel_binding_sha256=request.channel_binding_sha256,
        session_binding_sha256=request.session_binding_sha256,
        issued_at="2026-08-29T12:00:00Z",
        expires_at="2026-08-29T12:05:00Z",
        signer_key_id="v3-signer",
        signature_base64=base64.b64encode(b"x" * 64).decode("ascii"),
    )
    ticket = unsigned_ticket.model_copy(
        update={
            "signature_base64": _signature(
                container_attach_v3_ticket_canonical_message(unsigned_ticket)
            )
        }
    )
    envelope = ContainerAttachTicketEnvelopeV3(
        schema_version="rsd.container-attach-ticket-envelope.v3",
        request=request,
        ticket=ticket,
    )
    return {
        "profile": profile,
        "descriptor": descriptor,
        "runtime": runtime,
        "request": request,
        "ticket": ticket,
        "envelope": envelope,
    }


class _OneShotReplayAuthority:
    """Test-only atomic replay double; no production adapter exists in this slice."""

    def __init__(self) -> None:
        self.ticket_claimed: set[str] = set()
        self.container_lifetime_claimed: set[str] = set()
        self.deadlines: list[object] = []
        self.calls = 0

    def claim_once(
        self, *, claim: object, deadline: object
    ) -> ContainerAttachV3ReplayClaimReceiptV3:
        self.calls += 1
        checked = cast(ContainerAttachV3ReplayClaimV3, claim)
        claim_sha256 = container_attach_v3_replay_claim_sha256(checked)
        ticket_claim_sha256 = container_attach_v3_ticket_replay_claim_sha256(checked.ticket_claim)
        lifetime_claim_sha256 = container_attach_v3_container_lifetime_claim_sha256(
            checked.container_lifetime_claim
        )
        if (
            ticket_claim_sha256 in self.ticket_claimed
            or lifetime_claim_sha256 in self.container_lifetime_claimed
        ):
            raise RuntimeError("duplicate target replay claim")
        self.deadlines.append(deadline)
        # This test seam mimics the protocol's all-or-nothing transaction:
        # it makes neither identity visible until both collision checks pass.
        self.ticket_claimed.add(ticket_claim_sha256)
        self.container_lifetime_claimed.add(lifetime_claim_sha256)
        return ContainerAttachV3ReplayClaimReceiptV3(
            schema_version="rsd.container-attach-replay-claim-receipt.v3",
            replay_claim_sha256=claim_sha256,
            ticket_replay_claim_sha256=ticket_claim_sha256,
            container_lifetime_claim_sha256=lifetime_claim_sha256,
            state="claimed_v3",
        )


def _verify(
    bundle: dict[str, object],
    monkeypatch: pytest.MonkeyPatch,
    *,
    profile: object | None = None,
    envelope: object | None = None,
    runtime: object | None = None,
    replay_authority: object | None = None,
) -> object:
    monkeypatch.setattr(static_v3, "_trusted_utc_now", lambda: _NOW)
    return claim_container_attach_v3_ticket(
        static_role_profile=cast(Any, profile or bundle["profile"]),
        envelope=cast(Any, envelope or bundle["envelope"]),
        expected_runtime=cast(Any, runtime or bundle["runtime"]),
        replay_authority=cast(Any, replay_authority or _OneShotReplayAuthority()),
    )


@pytest.mark.parametrize(
    "component",
    ("primary_infisical", "primary_valkey", "restore_infisical", "restore_valkey"),
)
def test_verifies_each_exact_static_v3_role(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch, component: str
) -> None:
    bundle = _profile_bundle(tmp_path, component=component)

    verification = _verify(bundle, monkeypatch)

    assert verification.component == component
    assert (
        verification.static_role_profile_sha256
        == container_bootstrap_static_role_profile_v3_sha256(
            cast(ContainerBootstrapStaticRoleProfileV3, bundle["profile"])
        )
    )


def test_static_profile_digest_is_output_independent_and_canonical(tmp_path: Path) -> None:
    profile = cast(ContainerBootstrapStaticRoleProfileV3, _profile_bundle(tmp_path)["profile"])

    canonical = container_bootstrap_static_role_profile_v3_canonical_json(profile)
    decoded = json.loads(canonical)

    assert canonical == json.dumps(
        decoded, ensure_ascii=True, sort_keys=True, separators=(",", ":")
    ).encode("ascii")
    assert container_bootstrap_static_role_profile_v3_sha256(profile) == (
        container_bootstrap_static_role_profile_v3_sha256(profile.model_copy())
    )
    forbidden = {
        "artifact_sha256",
        "artifact_binding_sha256",
        "signature_base64",
        "build_provenance_sha256",
        "sbom",
        "reproducibility",
        "derived_image",
    }
    rendered = json.dumps(decoded, sort_keys=True)
    assert all(token not in rendered for token in forbidden)


def test_profile_rejects_role_and_nested_policy_swaps(tmp_path: Path) -> None:
    bundle = _profile_bundle(tmp_path)
    profile = cast(ContainerBootstrapStaticRoleProfileV3, bundle["profile"])

    with pytest.raises(ValueError, match="static role profile"):
        ContainerBootstrapStaticRoleProfileV3(**_updated_fields(profile, component_role="valkey"))
    with pytest.raises(ValueError):
        ContainerBootstrapStaticRoleProfileV3(
            **_updated_fields(profile, valkey_launch_policy=cast(Any, profile.fd_policy))
        )


def test_profile_requires_exact_static_environment_child_policy_cross_binding(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    bundle = _profile_bundle(tmp_path)
    profile = cast(ContainerBootstrapStaticRoleProfileV3, bundle["profile"])
    mismatched_policy = profile.child_environment_policy.model_copy(
        update={"image_static_environment_sha256": _hash("wrong-static-environment")}
    )

    with pytest.raises(ValueError, match="static role profile"):
        ContainerBootstrapStaticRoleProfileV3(
            **_updated_fields(profile, child_environment_policy=mismatched_policy)
        )

    constructed = profile.model_construct(
        **_updated_fields(profile, child_environment_policy=mismatched_policy)
    )
    with pytest.raises(ContainerAttachStaticV3Error) as raised:
        _verify(bundle, monkeypatch, profile=constructed)
    assert raised.value.phase == "binding"


@pytest.mark.parametrize(
    "field_update",
    (
        {"sink": "valkey_stdin_configuration_v1"},
        {"fields": ()},
        {"fields": ("not-a-field",)},
    ),
)
def test_descriptor_rejects_type_drift_missing_and_wrong_sink(
    tmp_path: Path, field_update: dict[str, object]
) -> None:
    descriptor = cast(
        ContainerBootstrapTargetDeliveryDescriptorV3,
        _profile_bundle(tmp_path)["descriptor"],
    )

    with pytest.raises(ValueError):
        ContainerBootstrapTargetDeliveryDescriptorV3(**_updated_fields(descriptor, **field_update))


@pytest.mark.parametrize(
    "changed",
    (
        {"target_field": "AUTH_SECRET"},
        {"source_purpose": "auth_secret"},
        {"format": "infisical_auth_secret_base64_32_v1"},
        {"encoded_byte_count": 1},
        {"derivation_binding_sha256": _hash("wrong-derivation")},
    ),
)
def test_descriptor_rejects_exact_field_drift(tmp_path: Path, changed: dict[str, object]) -> None:
    descriptor = cast(
        ContainerBootstrapTargetDeliveryDescriptorV3,
        _profile_bundle(tmp_path)["descriptor"],
    )
    first = descriptor.fields[0]

    with pytest.raises(ValueError, match="descriptor"):
        ContainerBootstrapTargetDeliveryDescriptorV3(
            **_updated_fields(
                descriptor,
                fields=(first.model_copy(update=changed), *descriptor.fields[1:]),
            )
        )


def test_valkey_descriptor_requires_the_single_stdin_route(tmp_path: Path) -> None:
    descriptor = cast(
        ContainerBootstrapTargetDeliveryDescriptorV3,
        _profile_bundle(tmp_path, component="primary_valkey")["descriptor"],
    )
    field = descriptor.fields[0]

    with pytest.raises(ValueError, match="descriptor"):
        ContainerBootstrapTargetDeliveryDescriptorV3(
            **_updated_fields(
                descriptor,
                fields=(field.model_copy(update={"target_field": "REDIS_URL"}),),
            )
        )


def test_descriptor_commitment_is_canonical_and_order_sensitive(tmp_path: Path) -> None:
    descriptor = cast(
        ContainerBootstrapTargetDeliveryDescriptorV3,
        _profile_bundle(tmp_path)["descriptor"],
    )

    canonical = container_bootstrap_target_delivery_descriptor_v3_canonical_json(descriptor)

    assert canonical == json.dumps(
        json.loads(canonical), ensure_ascii=True, sort_keys=True, separators=(",", ":")
    ).encode("ascii")
    assert container_bootstrap_target_delivery_descriptor_v3_sha256(descriptor) != _hash(
        "unrelated-descriptor"
    )


@pytest.mark.parametrize(
    "request_update",
    (
        {"static_role_profile_sha256": _hash("wrong-profile")},
        {"target_delivery_map_sha256": _hash("wrong-map")},
        {"target_delivery_descriptor_sha256": _hash("wrong-descriptor")},
        {"attach_protocol_v3_sha256": _hash("wrong-protocol")},
        {"request_nonce_sha256": _hash("replayed-nonce")},
        {"runtime_hostname": "rsd-other-runtime-hostname-123456"},
    ),
)
def test_ticket_envelope_rejects_request_ticket_binding_drift(
    tmp_path: Path, request_update: dict[str, object]
) -> None:
    bundle = _profile_bundle(tmp_path)
    request = cast(ContainerAttachRequestV3, bundle["request"])
    ticket = cast(ContainerAttachAuthorizationTicketV3, bundle["ticket"])
    changed_request = request.model_copy(update=request_update)

    with pytest.raises(ValueError):
        ContainerAttachTicketEnvelopeV3(
            schema_version="rsd.container-attach-ticket-envelope.v3",
            request=changed_request,
            ticket=ticket,
        )


@pytest.mark.parametrize(
    "runtime_update",
    (
        {"container_id": "d" * 64},
        {"runtime_hostname": "rsd-other-runtime-hostname-123456"},
        {"operation_id": "123e4567-e89b-42d3-a456-426614174002"},
        {"request_nonce_sha256": _hash("replay-input")},
    ),
)
def test_target_verifier_rejects_runtime_binding_replay_or_substitution(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
    runtime_update: dict[str, object],
) -> None:
    bundle = _profile_bundle(tmp_path)
    runtime = cast(ContainerAttachRuntimeBindingV3, bundle["runtime"])
    changed = runtime.model_copy(update=runtime_update)

    with pytest.raises(ContainerAttachStaticV3Error) as raised:
        _verify(bundle, monkeypatch, runtime=changed)

    assert raised.value.phase == "binding"


def test_target_verifier_uses_only_profile_owned_anchor(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    bundle = _profile_bundle(tmp_path)
    profile = cast(ContainerBootstrapStaticRoleProfileV3, bundle["profile"])
    wrong_anchor = _anchor(key_id="other-signer")
    changed_profile = profile.model_copy(update={"ticket_trust_anchor": wrong_anchor})

    with pytest.raises(ContainerAttachStaticV3Error) as raised:
        _verify(bundle, monkeypatch, profile=changed_profile)

    assert raised.value.phase == "binding"


@pytest.mark.parametrize("alternate_key", (b"4" * 32, b"5" * 32))
def test_reissued_profile_anchor_key_or_key_id_substitution_still_fails_signature(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch, alternate_key: bytes
) -> None:
    """A signer cannot move a valid ticket to a profile with a different anchor."""

    bundle = _profile_bundle(tmp_path)
    profile = cast(ContainerBootstrapStaticRoleProfileV3, bundle["profile"])
    request = cast(ContainerAttachRequestV3, bundle["request"])
    ticket = cast(ContainerAttachAuthorizationTicketV3, bundle["ticket"])
    public = Ed25519PrivateKey.from_private_bytes(alternate_key).public_key().public_bytes_raw()
    alternate_anchor = ContainerAttachTicketTrustAnchorV1(
        schema_version="rsd.container-attach-ticket-trust-anchor.v1",
        key_id="alternate-signer",
        public_key_base64=base64.b64encode(public).decode("ascii"),
        public_key_fingerprint_sha256=hashlib.sha256(public).hexdigest(),
        algorithm="ed25519",
    )
    changed_profile = profile.model_copy(update={"ticket_trust_anchor": alternate_anchor})
    changed_request = request.model_copy(
        update={
            "static_role_profile_sha256": container_bootstrap_static_role_profile_v3_sha256(
                changed_profile
            )
        }
    )
    changed_ticket = _resign_ticket_for_request(ticket, changed_request)

    with pytest.raises(ContainerAttachStaticV3Error) as raised:
        _verify(
            bundle,
            monkeypatch,
            profile=changed_profile,
            envelope=_envelope_for_request(changed_request, changed_ticket),
        )

    assert raised.value.phase == "signature"


def test_anchor_fingerprint_and_subclass_type_drift_fail_closed(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    bundle = _profile_bundle(tmp_path)
    profile = cast(ContainerBootstrapStaticRoleProfileV3, bundle["profile"])
    anchor = profile.ticket_trust_anchor

    with pytest.raises(ValueError, match="trust anchor"):
        ContainerAttachTicketTrustAnchorV1(
            **_updated_fields(
                anchor, public_key_fingerprint_sha256=_hash("wrong-anchor-fingerprint")
            )
        )

    class ProfileSubclass(ContainerBootstrapStaticRoleProfileV3):
        pass

    subclass = ProfileSubclass.model_validate(profile.model_dump(mode="python"))
    with pytest.raises(ContainerAttachStaticV3Error) as raised:
        _verify(bundle, monkeypatch, profile=subclass)

    assert raised.value.phase == "binding"


def test_target_verifier_rejects_key_and_signature_substitution(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    bundle = _profile_bundle(tmp_path)
    ticket = cast(ContainerAttachAuthorizationTicketV3, bundle["ticket"])
    envelope = cast(ContainerAttachTicketEnvelopeV3, bundle["envelope"])
    bad_ticket = ticket.model_copy(
        update={"signature_base64": base64.b64encode(b"y" * 64).decode("ascii")}
    )
    bad_envelope = envelope.model_copy(update={"ticket": bad_ticket})

    with pytest.raises(ContainerAttachStaticV3Error) as raised:
        _verify(bundle, monkeypatch, envelope=bad_envelope)

    assert raised.value.phase == "signature"


def test_missing_duplicate_and_source_descriptor_drift_are_rejected(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    bundle = _profile_bundle(tmp_path)
    descriptor = cast(ContainerBootstrapTargetDeliveryDescriptorV3, bundle["descriptor"])
    first = descriptor.fields[0]

    with pytest.raises(ValueError):
        ContainerBootstrapTargetDeliveryDescriptorV3(
            **_updated_fields(descriptor, fields=(first, first, *descriptor.fields[2:]))
        )
    with pytest.raises(ValueError, match="descriptor"):
        ContainerBootstrapTargetDeliveryDescriptorV3(
            **_updated_fields(
                descriptor,
                fields=(
                    first.model_copy(update={"source_fingerprint_sha256": _hash("source-drift")}),
                    *descriptor.fields[1:],
                ),
            )
        )
    request = cast(ContainerAttachRequestV3, bundle["request"])
    ticket = cast(ContainerAttachAuthorizationTicketV3, bundle["ticket"])
    changed_request = request.model_copy(
        update={
            "fields": (
                first.model_copy(update={"source_reference_sha256": _hash("reference-drift")}),
                *descriptor.fields[1:],
            )
        }
    )
    changed_ticket = _resign_ticket_for_request(ticket, changed_request)
    with pytest.raises(ContainerAttachStaticV3Error) as raised:
        _verify(
            bundle,
            monkeypatch,
            envelope=_envelope_for_request(changed_request, changed_ticket),
        )
    assert raised.value.phase == "binding"


@pytest.mark.parametrize(
    ("issued_at", "expires_at", "phase"),
    (
        ("2026-08-29T11:55:00Z", "2026-08-29T12:00:00Z", "freshness"),
        ("2026-08-29T12:00:00Z", "2026-08-29T12:01:00Z", "freshness"),
        ("2026-08-29T12:02:00Z", "2026-08-29T12:05:00Z", "freshness"),
    ),
)
def test_target_verifier_rejects_stale_future_and_overlong_tickets(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
    issued_at: str,
    expires_at: str,
    phase: str,
) -> None:
    bundle = _profile_bundle(tmp_path)
    ticket = cast(ContainerAttachAuthorizationTicketV3, bundle["ticket"])
    unsigned = ticket.model_copy(
        update={
            "issued_at": issued_at,
            "expires_at": expires_at,
            "signature_base64": base64.b64encode(b"x" * 64).decode("ascii"),
        }
    )
    signed = unsigned.model_copy(
        update={
            "signature_base64": _signature(container_attach_v3_ticket_canonical_message(unsigned))
        }
    )
    envelope = cast(ContainerAttachTicketEnvelopeV3, bundle["envelope"]).model_copy(
        update={"ticket": signed}
    )

    with pytest.raises(ContainerAttachStaticV3Error) as raised:
        _verify(bundle, monkeypatch, envelope=envelope)

    assert raised.value.phase == phase


def test_ticket_model_rejects_overlong_or_noncanonical_freshness_inputs(tmp_path: Path) -> None:
    ticket = cast(ContainerAttachAuthorizationTicketV3, _profile_bundle(tmp_path)["ticket"])

    with pytest.raises(ValueError, match="ticket"):
        ContainerAttachAuthorizationTicketV3(
            **_updated_fields(ticket, expires_at="2026-08-29T12:05:01Z")
        )
    with pytest.raises(ValueError, match="timestamp"):
        ContainerAttachAuthorizationTicketV3(
            **_updated_fields(ticket, issued_at="2026-08-29T12:00:00+00:00")
        )


def test_noncanonical_signature_and_constructed_type_drift_fail_closed(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    bundle = _profile_bundle(tmp_path)
    ticket = cast(ContainerAttachAuthorizationTicketV3, bundle["ticket"])
    envelope = cast(ContainerAttachTicketEnvelopeV3, bundle["envelope"])
    noncanonical = ticket.model_construct(
        **_updated_fields(ticket, signature_base64=ticket.signature_base64 + "\n")
    )
    constructed = envelope.model_construct(request=envelope.request, ticket=noncanonical)

    with pytest.raises(ContainerAttachStaticV3Error) as raised:
        _verify(bundle, monkeypatch, envelope=constructed)

    assert raised.value.phase == "binding"


def test_claim_revalidates_raw_inputs_and_consumes_the_exact_ticket_once(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    """A pure validation is not usable; only one atomic claim makes it final."""

    bundle = _profile_bundle(tmp_path)
    monkeypatch.setattr(static_v3, "_trusted_utc_now", lambda: _NOW)
    validation = validate_container_attach_v3_ticket(
        static_role_profile=cast(Any, bundle["profile"]),
        envelope=cast(Any, bundle["envelope"]),
        expected_runtime=cast(Any, bundle["runtime"]),
    )
    authority = _OneShotReplayAuthority()

    claimed = claim_container_attach_v3_ticket(
        static_role_profile=cast(Any, bundle["profile"]),
        envelope=cast(Any, bundle["envelope"]),
        expected_runtime=cast(Any, bundle["runtime"]),
        replay_authority=authority,
    )

    assert validation.schema_version == "rsd.container-attach-ticket-validation.v3"
    assert type(claimed) is ContainerAttachV3ClaimedTicketV3
    assert authority.calls == 1
    with pytest.raises(ContainerAttachStaticV3Error) as raised:
        claim_container_attach_v3_ticket(
            static_role_profile=cast(Any, bundle["profile"]),
            envelope=cast(Any, bundle["envelope"]),
            expected_runtime=cast(Any, bundle["runtime"]),
            replay_authority=authority,
        )
    assert raised.value.phase == "replay"
    assert authority.calls == 2


def test_atomic_claim_rejects_a_reissued_ticket_for_the_same_container_lifetime(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    """Fresh ticket/nonces cannot bypass the independent lifetime identity."""

    bundle = _profile_bundle(tmp_path)
    runtime = cast(ContainerAttachRuntimeBindingV3, bundle["runtime"])
    request = cast(ContainerAttachRequestV3, bundle["request"])
    ticket = cast(ContainerAttachAuthorizationTicketV3, bundle["ticket"])
    reissued_runtime = ContainerAttachRuntimeBindingV3(
        **_updated_fields(
            runtime,
            operation_id="123e4567-e89b-42d3-a456-426614174002",
            request_nonce_sha256=_hash("reissued-nonce"),
            channel_binding_sha256=_hash("reissued-channel"),
            session_binding_sha256=_hash("reissued-session"),
        )
    )
    reissued_request = ContainerAttachRequestV3(
        **_updated_fields(
            request,
            operation_id=reissued_runtime.operation_id,
            request_nonce_sha256=reissued_runtime.request_nonce_sha256,
            channel_binding_sha256=reissued_runtime.channel_binding_sha256,
            session_binding_sha256=reissued_runtime.session_binding_sha256,
        )
    )
    reissued_ticket = _resign_ticket_for_request(ticket, reissued_request)
    reissued_envelope = _envelope_for_request(reissued_request, reissued_ticket)
    authority = _OneShotReplayAuthority()

    _verify(bundle, monkeypatch, replay_authority=authority)
    with pytest.raises(ContainerAttachStaticV3Error) as raised:
        _verify(
            bundle,
            monkeypatch,
            envelope=reissued_envelope,
            runtime=reissued_runtime,
            replay_authority=authority,
        )

    assert raised.value.phase == "replay"
    assert authority.calls == 2
    assert len(authority.ticket_claimed) == 1
    assert len(authority.container_lifetime_claimed) == 1


def test_atomic_claim_rejects_resigned_ticket_with_new_times_for_same_request(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    """Ticket signature/time changes cannot mint a second container attach."""

    bundle = _profile_bundle(tmp_path)
    ticket = cast(ContainerAttachAuthorizationTicketV3, bundle["ticket"])
    unsigned_reissue = ticket.model_copy(
        update={
            "issued_at": "2026-08-29T12:00:01Z",
            "expires_at": "2026-08-29T12:04:59Z",
            "signature_base64": base64.b64encode(b"x" * 64).decode("ascii"),
        }
    )
    reissued_ticket = unsigned_reissue.model_copy(
        update={
            "signature_base64": _signature(
                container_attach_v3_ticket_canonical_message(unsigned_reissue)
            )
        }
    )
    reissued_envelope = _envelope_for_request(
        cast(ContainerAttachRequestV3, bundle["request"]),
        reissued_ticket,
    )
    authority = _OneShotReplayAuthority()

    _verify(bundle, monkeypatch, replay_authority=authority)
    with pytest.raises(ContainerAttachStaticV3Error) as raised:
        _verify(bundle, monkeypatch, envelope=reissued_envelope, replay_authority=authority)

    assert raised.value.phase == "replay"
    assert authority.calls == 2
    assert len(authority.ticket_claimed) == 1
    assert len(authority.container_lifetime_claimed) == 1


def test_atomic_claim_rejects_reprofiled_valid_ticket_for_same_container_lifetime(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    """A changed static profile is not a new immutable container lifetime."""

    bundle = _profile_bundle(tmp_path)
    profile = cast(ContainerBootstrapStaticRoleProfileV3, bundle["profile"])
    request = cast(ContainerAttachRequestV3, bundle["request"])
    ticket = cast(ContainerAttachAuthorizationTicketV3, bundle["ticket"])
    reprofiled = ContainerBootstrapStaticRoleProfileV3(
        **_updated_fields(profile, source_commit="b" * 40)
    )
    reprofiled_request = ContainerAttachRequestV3(
        **_updated_fields(
            request,
            static_role_profile_sha256=container_bootstrap_static_role_profile_v3_sha256(
                reprofiled
            ),
        )
    )
    reprofiled_ticket = _resign_ticket_for_request(ticket, reprofiled_request)
    reprofiled_envelope = _envelope_for_request(reprofiled_request, reprofiled_ticket)
    authority = _OneShotReplayAuthority()

    _verify(bundle, monkeypatch, replay_authority=authority)
    with pytest.raises(ContainerAttachStaticV3Error) as raised:
        _verify(
            bundle,
            monkeypatch,
            profile=reprofiled,
            envelope=reprofiled_envelope,
            replay_authority=authority,
        )

    assert raised.value.phase == "replay"
    assert authority.calls == 2
    assert len(authority.ticket_claimed) == 1
    assert len(authority.container_lifetime_claimed) == 1


def test_atomic_claim_rejects_component_and_hostname_reissue_for_same_container(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    """Only the immutable Docker ID keys the lifetime, never mutable metadata."""

    initial = _profile_bundle(tmp_path, component="primary_infisical")
    alternate = _profile_bundle(tmp_path, component="primary_valkey")
    initial_runtime = cast(ContainerAttachRuntimeBindingV3, initial["runtime"])
    alternate_runtime = cast(ContainerAttachRuntimeBindingV3, alternate["runtime"])
    alternate_request = cast(ContainerAttachRequestV3, alternate["request"])
    alternate_ticket = cast(ContainerAttachAuthorizationTicketV3, alternate["ticket"])
    substituted_runtime = ContainerAttachRuntimeBindingV3(
        **_updated_fields(
            alternate_runtime,
            container_id=initial_runtime.container_id,
            runtime_instance_binding_sha256=container_attach_v3_runtime_instance_binding_sha256(
                container_id=initial_runtime.container_id,
                runtime_hostname=alternate_runtime.runtime_hostname,
            ),
        )
    )
    substituted_request = ContainerAttachRequestV3(
        **_updated_fields(
            alternate_request,
            container_id=substituted_runtime.container_id,
            runtime_instance_binding_sha256=substituted_runtime.runtime_instance_binding_sha256,
        )
    )
    substituted_ticket = _resign_ticket_for_request(alternate_ticket, substituted_request)
    substituted_envelope = _envelope_for_request(substituted_request, substituted_ticket)
    authority = _OneShotReplayAuthority()

    _verify(initial, monkeypatch, replay_authority=authority)
    with pytest.raises(ContainerAttachStaticV3Error) as raised:
        _verify(
            alternate,
            monkeypatch,
            envelope=substituted_envelope,
            runtime=substituted_runtime,
            replay_authority=authority,
        )

    assert raised.value.phase == "replay"
    assert authority.calls == 2
    assert len(authority.ticket_claimed) == 1
    assert len(authority.container_lifetime_claimed) == 1


class _PartialAtomicReplayAuthority:
    """Hostile test seam that exposes a partial authority-side write only."""

    def __init__(self) -> None:
        self.calls = 0
        self.ticket_only_claims: set[str] = set()

    def claim_once(self, *, claim: object, deadline: object) -> object:
        del deadline
        self.calls += 1
        checked = cast(ContainerAttachV3ReplayClaimV3, claim)
        self.ticket_only_claims.add(
            container_attach_v3_ticket_replay_claim_sha256(checked.ticket_claim)
        )
        raise RuntimeError("partial target replay authority failure")


class _DeadlineMutationReplayAuthority(_OneShotReplayAuthority):
    """Hostile authority that mutates only its frozen value-only advice."""

    def __init__(self) -> None:
        super().__init__()
        self.mutated_deadline: object | None = None

    def claim_once(
        self, *, claim: object, deadline: object
    ) -> ContainerAttachV3ReplayClaimReceiptV3:
        receipt = super().claim_once(claim=claim, deadline=deadline)
        exposed = cast(ContainerAttachV3ClaimDeadlineV3, deadline)
        with pytest.raises(AttributeError):
            setattr(  # noqa: B010 - intentionally prove frozen ordinary mutation.
                exposed,
                "effective_deadline_at",
                "2026-08-29T12:05:00Z",
            )
        assert not hasattr(exposed, "__dict__")
        assert set(type(exposed).__slots__) == {
            "schema_version",
            "ticket_sha256",
            "freshness_checked_at",
            "ticket_expires_at",
            "effective_deadline_at",
            "claim_timeout_seconds",
            "monotonic_started_at",
            "monotonic_deadline_at",
            "monotonic_budget_seconds",
        }
        assert all(not callable(getattr(exposed, name)) for name in type(exposed).__slots__)
        assert not any(
            "guard" in name or "interval" in name or "remaining" in name for name in dir(exposed)
        )
        with pytest.raises(AttributeError):
            object.__setattr__(
                exposed,
                "_ContainerAttachV3ClaimDeadlineV3__remaining_seconds_reader",
                object(),
            )
        with pytest.raises(AttributeError):
            object.__setattr__(
                exposed,
                "_ContainerAttachV3ClaimDeadlineV3__guard",
                1_000_000.0,
            )
        with pytest.raises(AttributeError):
            object.__setattr__(
                exposed,
                "_ContainerAttachV3ClaimDeadlineV3__interval",
                1_000_000.0,
            )
        object.__setattr__(exposed, "effective_deadline_at", "2026-08-29T12:05:00Z")
        object.__setattr__(exposed, "monotonic_deadline_at", 1_000_000.0)
        self.mutated_deadline = exposed
        return receipt


def test_atomic_claim_partial_or_failed_authority_never_yields_a_usable_ticket(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    """The sealed authority must be all-or-nothing; uncertainty is fail-closed."""

    bundle = _profile_bundle(tmp_path)
    authority = _PartialAtomicReplayAuthority()

    with pytest.raises(ContainerAttachStaticV3Error) as raised:
        _verify(bundle, monkeypatch, replay_authority=authority)

    assert raised.value.phase == "replay"
    assert raised.value.__context__ is None
    assert raised.value.__cause__ is None
    assert authority.calls == 1
    assert len(authority.ticket_only_claims) == 1


def test_atomic_claim_rejects_a_late_return_after_authority_mutates_deadline_view(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    """Only verifier-owned timing state decides whether a consumed claim is usable."""

    bundle = _profile_bundle(tmp_path)
    authority = _DeadlineMutationReplayAuthority()
    monotonic_values = iter((100.0, 110.0))
    monkeypatch.setattr(static_v3, "_trusted_utc_now", lambda: _NOW)
    monkeypatch.setattr(static_v3, "_trusted_monotonic_now", lambda: next(monotonic_values))

    with pytest.raises(ContainerAttachStaticV3Error) as raised:
        claim_container_attach_v3_ticket(
            static_role_profile=cast(Any, bundle["profile"]),
            envelope=cast(Any, bundle["envelope"]),
            expected_runtime=cast(Any, bundle["runtime"]),
            replay_authority=authority,
        )

    mutated = cast(ContainerAttachV3ClaimDeadlineV3, authority.mutated_deadline)
    assert raised.value.phase == "freshness"
    assert mutated.effective_deadline_at == "2026-08-29T12:05:00Z"
    assert authority.calls == 1
    assert len(authority.container_lifetime_claimed) == 1


def test_atomic_claim_deadline_is_derived_and_rechecked_after_authority_return(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    """A late, possibly consumed claim can never produce a usable V3 result."""

    bundle = _profile_bundle(tmp_path)
    authority = _OneShotReplayAuthority()
    now_values = iter((_NOW, _NOW + timedelta(seconds=10)))
    monotonic_values = iter((100.0, 110.0))
    monkeypatch.setattr(static_v3, "_trusted_utc_now", lambda: next(now_values))
    monkeypatch.setattr(static_v3, "_trusted_monotonic_now", lambda: next(monotonic_values))

    with pytest.raises(ContainerAttachStaticV3Error) as raised:
        claim_container_attach_v3_ticket(
            static_role_profile=cast(Any, bundle["profile"]),
            envelope=cast(Any, bundle["envelope"]),
            expected_runtime=cast(Any, bundle["runtime"]),
            replay_authority=authority,
        )

    deadline = cast(ContainerAttachV3ClaimDeadlineV3, authority.deadlines[0])
    assert raised.value.phase == "freshness"
    assert authority.calls == 1
    assert deadline.freshness_checked_at == "2026-08-29T12:01:00Z"
    assert deadline.ticket_expires_at == "2026-08-29T12:05:00Z"
    assert deadline.claim_timeout_seconds == 10
    assert deadline.effective_deadline_at == "2026-08-29T12:01:10Z"
    assert deadline.monotonic_started_at == 100.0
    assert deadline.monotonic_deadline_at == 110.0
    assert deadline.monotonic_budget_seconds == 10
    assert len(authority.ticket_claimed) == 1
    assert len(authority.container_lifetime_claimed) == 1


def test_atomic_claim_deadline_cannot_outlive_ticket_expiry(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    """The authority gets the earlier of signed claim timeout and ticket expiry."""

    bundle = _profile_bundle(tmp_path)
    ticket = cast(ContainerAttachAuthorizationTicketV3, bundle["ticket"])
    unsigned = ticket.model_copy(
        update={
            "expires_at": "2026-08-29T12:01:05Z",
            "signature_base64": base64.b64encode(b"x" * 64).decode("ascii"),
        }
    )
    short_ticket = unsigned.model_copy(
        update={
            "signature_base64": _signature(container_attach_v3_ticket_canonical_message(unsigned))
        }
    )
    short_envelope = _envelope_for_request(
        cast(ContainerAttachRequestV3, bundle["request"]),
        short_ticket,
    )
    authority = _OneShotReplayAuthority()

    _verify(bundle, monkeypatch, envelope=short_envelope, replay_authority=authority)

    deadline = cast(ContainerAttachV3ClaimDeadlineV3, authority.deadlines[0])
    assert deadline.ticket_expires_at == "2026-08-29T12:01:05Z"
    assert deadline.effective_deadline_at == "2026-08-29T12:01:05Z"


def test_atomic_claim_rejects_late_return_when_wall_clock_is_rolled_back(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    """Monotonic expiry prevents a blocked claim from using a stale wall clock."""

    bundle = _profile_bundle(tmp_path)
    authority = _OneShotReplayAuthority()
    wall_values = iter((_NOW, _NOW, _NOW))
    monotonic_values = iter((100.0, 110.0))
    monkeypatch.setattr(static_v3, "_trusted_utc_now", lambda: next(wall_values))
    monkeypatch.setattr(static_v3, "_trusted_monotonic_now", lambda: next(monotonic_values))

    with pytest.raises(ContainerAttachStaticV3Error) as raised:
        claim_container_attach_v3_ticket(
            static_role_profile=cast(Any, bundle["profile"]),
            envelope=cast(Any, bundle["envelope"]),
            expected_runtime=cast(Any, bundle["runtime"]),
            replay_authority=authority,
        )

    assert raised.value.phase == "freshness"
    assert authority.calls == 1
    assert len(authority.container_lifetime_claimed) == 1


def test_atomic_claim_does_not_inflate_a_short_ticket_after_setup_clock_rollback(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    """The initial validated UTC snapshot, not a later UTC read, bounds the claim."""

    bundle = _profile_bundle(tmp_path)
    ticket = cast(ContainerAttachAuthorizationTicketV3, bundle["ticket"])
    unsigned = ticket.model_copy(
        update={
            "expires_at": "2026-08-29T12:01:01Z",
            "signature_base64": base64.b64encode(b"x" * 64).decode("ascii"),
        }
    )
    short_ticket = unsigned.model_copy(
        update={
            "signature_base64": _signature(container_attach_v3_ticket_canonical_message(unsigned))
        }
    )
    short_envelope = _envelope_for_request(
        cast(ContainerAttachRequestV3, bundle["request"]),
        short_ticket,
    )
    authority = _OneShotReplayAuthority()
    wall_reads: list[datetime] = []
    wall_values = iter((_NOW, datetime(2026, 8, 29, 12, 0, tzinfo=UTC)))
    monotonic_values = iter((100.0, 102.0))

    def wall_clock() -> datetime:
        current = next(wall_values)
        wall_reads.append(current)
        return current

    monkeypatch.setattr(static_v3, "_trusted_utc_now", wall_clock)
    monkeypatch.setattr(static_v3, "_trusted_monotonic_now", lambda: next(monotonic_values))

    with pytest.raises(ContainerAttachStaticV3Error) as raised:
        claim_container_attach_v3_ticket(
            static_role_profile=cast(Any, bundle["profile"]),
            envelope=short_envelope,
            expected_runtime=cast(Any, bundle["runtime"]),
            replay_authority=authority,
        )

    deadline = cast(ContainerAttachV3ClaimDeadlineV3, authority.deadlines[0])
    assert raised.value.phase == "freshness"
    assert wall_reads == [_NOW, datetime(2026, 8, 29, 12, 0, tzinfo=UTC)]
    assert deadline.effective_deadline_at == "2026-08-29T12:01:01Z"
    assert deadline.monotonic_budget_seconds == 1
    assert authority.calls == 1
    assert len(authority.container_lifetime_claimed) == 1


def test_atomic_claim_rejects_monotonic_clock_regression_after_authority_return(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    """A nonmonotonic trusted-clock seam cannot make a consumed claim usable."""

    bundle = _profile_bundle(tmp_path)
    authority = _OneShotReplayAuthority()
    wall_values = iter((_NOW, _NOW))
    monotonic_values = iter((100.0, 99.0))
    monkeypatch.setattr(static_v3, "_trusted_utc_now", lambda: next(wall_values))
    monkeypatch.setattr(static_v3, "_trusted_monotonic_now", lambda: next(monotonic_values))

    with pytest.raises(ContainerAttachStaticV3Error) as raised:
        claim_container_attach_v3_ticket(
            static_role_profile=cast(Any, bundle["profile"]),
            envelope=cast(Any, bundle["envelope"]),
            expected_runtime=cast(Any, bundle["runtime"]),
            replay_authority=authority,
        )

    assert raised.value.phase == "freshness"
    assert authority.calls == 1
    assert len(authority.container_lifetime_claimed) == 1


def test_atomic_claim_allows_nondecreasing_verifier_observations(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    """A normal authority return is usable within the verifier's local budget."""

    bundle = _profile_bundle(tmp_path)
    authority = _OneShotReplayAuthority()
    monotonic_values = iter((100.0, 103.0))
    monkeypatch.setattr(static_v3, "_trusted_utc_now", lambda: _NOW)
    monkeypatch.setattr(static_v3, "_trusted_monotonic_now", lambda: next(monotonic_values))

    claimed = claim_container_attach_v3_ticket(
        static_role_profile=cast(Any, bundle["profile"]),
        envelope=cast(Any, bundle["envelope"]),
        expected_runtime=cast(Any, bundle["runtime"]),
        replay_authority=authority,
    )

    assert type(claimed) is ContainerAttachV3ClaimedTicketV3
    assert authority.calls == 1
    assert len(authority.container_lifetime_claimed) == 1


def test_verifier_monotonic_guard_latches_a_regression(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    """A verifier-observed regression permanently invalidates that interval."""

    guard = static_v3._ContainerAttachV3MonotonicDeadlineGuard(100.0)
    monotonic_values = iter((99.0, 102.0))
    monkeypatch.setattr(static_v3, "_trusted_monotonic_now", lambda: next(monotonic_values))

    with pytest.raises(ContainerAttachStaticV3Error) as first:
        guard.now()
    with pytest.raises(ContainerAttachStaticV3Error) as second:
        guard.now()

    assert first.value.phase == "freshness"
    assert second.value.phase == "freshness"


@pytest.mark.parametrize(
    "invalid_monotonic",
    (0, True, -1.0, float("nan"), float("inf"), float("-inf"), "100.0"),
)
def test_atomic_claim_rejects_invalid_monotonic_clock_before_authority(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch, invalid_monotonic: object
) -> None:
    """No invalid test seam reading can reach the authority transaction."""

    bundle = _profile_bundle(tmp_path)
    authority = _OneShotReplayAuthority()
    monkeypatch.setattr(static_v3, "_trusted_utc_now", lambda: _NOW)
    monkeypatch.setattr(static_v3, "_trusted_monotonic_now", lambda: invalid_monotonic)

    with pytest.raises(ContainerAttachStaticV3Error) as raised:
        claim_container_attach_v3_ticket(
            static_role_profile=cast(Any, bundle["profile"]),
            envelope=cast(Any, bundle["envelope"]),
            expected_runtime=cast(Any, bundle["runtime"]),
            replay_authority=authority,
        )

    assert raised.value.phase == "freshness"
    assert raised.value.__context__ is None
    assert raised.value.__cause__ is None
    assert authority.calls == 0


def test_atomic_claim_rejects_unavailable_or_invalid_monotonic_read_after_consumption(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    """A consumed claim stays non-usable if post-claim monotonic time is invalid."""

    bundle = _profile_bundle(tmp_path)
    authority = _OneShotReplayAuthority()
    monotonic_values = iter((100.0, float("nan")))
    monkeypatch.setattr(static_v3, "_trusted_utc_now", lambda: _NOW)
    monkeypatch.setattr(static_v3, "_trusted_monotonic_now", lambda: next(monotonic_values))

    with pytest.raises(ContainerAttachStaticV3Error) as raised:
        claim_container_attach_v3_ticket(
            static_role_profile=cast(Any, bundle["profile"]),
            envelope=cast(Any, bundle["envelope"]),
            expected_runtime=cast(Any, bundle["runtime"]),
            replay_authority=authority,
        )

    assert raised.value.phase == "freshness"
    assert raised.value.__context__ is None
    assert raised.value.__cause__ is None
    assert authority.calls == 1
    assert len(authority.container_lifetime_claimed) == 1


def test_atomic_claim_redacts_an_unavailable_monotonic_clock(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    """Clock failures do not expose collaborator text before the claim call."""

    bundle = _profile_bundle(tmp_path)
    authority = _OneShotReplayAuthority()

    def unavailable_clock() -> float:
        raise RuntimeError("monotonic-clock-sentinel")

    monkeypatch.setattr(static_v3, "_trusted_utc_now", lambda: _NOW)
    monkeypatch.setattr(static_v3, "_trusted_monotonic_now", unavailable_clock)

    with pytest.raises(ContainerAttachStaticV3Error) as raised:
        claim_container_attach_v3_ticket(
            static_role_profile=cast(Any, bundle["profile"]),
            envelope=cast(Any, bundle["envelope"]),
            expected_runtime=cast(Any, bundle["runtime"]),
            replay_authority=authority,
        )

    assert raised.value.phase == "freshness"
    assert "monotonic-clock-sentinel" not in repr(raised.value)
    assert raised.value.__context__ is None
    assert raised.value.__cause__ is None
    assert authority.calls == 0


def test_atomic_claim_post_claim_expiry_is_nonusable_even_if_consumed(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    """Expiry is exclusive before and after the replay authority transaction."""

    bundle = _profile_bundle(tmp_path)
    authority = _OneShotReplayAuthority()
    now_values = iter(
        (
            _NOW,
            datetime(2026, 8, 29, 12, 5, tzinfo=UTC),
        )
    )
    monkeypatch.setattr(static_v3, "_trusted_utc_now", lambda: next(now_values))

    with pytest.raises(ContainerAttachStaticV3Error) as raised:
        claim_container_attach_v3_ticket(
            static_role_profile=cast(Any, bundle["profile"]),
            envelope=cast(Any, bundle["envelope"]),
            expected_runtime=cast(Any, bundle["runtime"]),
            replay_authority=authority,
        )

    assert raised.value.phase == "freshness"
    assert authority.calls == 1
    assert len(authority.container_lifetime_claimed) == 1


class _UnavailableReplayAuthority:
    """Test only: fail without exposing an arbitrary collaborator error."""

    def __init__(self) -> None:
        self.calls = 0

    def claim_once(self, *, claim: object, deadline: object) -> object:
        del claim, deadline
        self.calls += 1
        raise RuntimeError("secret-sentinel replay authority unavailable")


def test_claim_requires_an_available_authority_after_validation_only(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    bundle = _profile_bundle(tmp_path)
    unavailable = _UnavailableReplayAuthority()

    with pytest.raises(ContainerAttachStaticV3Error) as raised:
        _verify(bundle, monkeypatch, replay_authority=unavailable)
    assert raised.value.phase == "replay"
    assert "secret-sentinel" not in repr(raised.value)
    assert raised.value.__context__ is None
    assert raised.value.__cause__ is None
    assert unavailable.calls == 1

    bad_ticket = cast(ContainerAttachAuthorizationTicketV3, bundle["ticket"]).model_copy(
        update={"signature_base64": base64.b64encode(b"z" * 64).decode("ascii")}
    )
    bad_envelope = cast(ContainerAttachTicketEnvelopeV3, bundle["envelope"]).model_copy(
        update={"ticket": bad_ticket}
    )
    unavailable_before_signature = _UnavailableReplayAuthority()
    with pytest.raises(ContainerAttachStaticV3Error) as invalid:
        _verify(
            bundle,
            monkeypatch,
            envelope=bad_envelope,
            replay_authority=unavailable_before_signature,
        )
    assert invalid.value.phase == "signature"
    assert unavailable_before_signature.calls == 0


def test_descriptor_requires_authoritative_derived_uri_count_and_grammar_commitments(
    tmp_path: Path,
) -> None:
    descriptor = cast(
        ContainerBootstrapTargetDeliveryDescriptorV3,
        _profile_bundle(tmp_path)["descriptor"],
    )
    postgres_field = descriptor.fields[2]
    postgres_commitment = descriptor.derived_uri_commitments[0]

    with pytest.raises(ValueError, match="descriptor"):
        ContainerBootstrapTargetDeliveryDescriptorV3(
            **_updated_fields(
                descriptor,
                fields=(
                    *descriptor.fields[:2],
                    postgres_field.model_copy(
                        update={"encoded_byte_count": postgres_field.encoded_byte_count + 1}
                    ),
                    descriptor.fields[3],
                ),
            )
        )
    with pytest.raises(ValueError, match="descriptor"):
        ContainerBootstrapTargetDeliveryDescriptorV3(
            **_updated_fields(
                descriptor,
                derived_uri_commitments=(
                    postgres_commitment.model_copy(
                        update={"derivation_binding_sha256": _hash("wrong-uri-grammar")}
                    ),
                    descriptor.derived_uri_commitments[1],
                ),
            )
        )


def test_recursive_nested_subclass_tuple_and_enum_drift_fail_before_normalization(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    bundle = _profile_bundle(tmp_path)
    profile = cast(ContainerBootstrapStaticRoleProfileV3, bundle["profile"])
    descriptor = cast(ContainerBootstrapTargetDeliveryDescriptorV3, bundle["descriptor"])

    class DerivedCommitmentSubclass(ContainerBootstrapDerivedUriCommitmentV3):
        pass

    class StaticEnvironmentSubclass(ContainerBootstrapStaticEnvironmentV2):
        pass

    nested_commitment = DerivedCommitmentSubclass.model_validate(
        descriptor.derived_uri_commitments[0].model_dump(mode="python")
    )
    nested_descriptor = descriptor.model_construct(
        **_updated_fields(
            descriptor,
            fields=list(descriptor.fields),
            derived_uri_commitments=(nested_commitment, *descriptor.derived_uri_commitments[1:]),
        )
    )
    nested_environment = StaticEnvironmentSubclass.model_validate(
        profile.static_environment.model_dump(mode="python")
    )
    constructed = profile.model_construct(
        **_updated_fields(
            profile,
            target_delivery_descriptor=nested_descriptor,
            static_environment=nested_environment,
        )
    )

    with pytest.raises(ContainerAttachStaticV3Error) as raised:
        _verify(bundle, monkeypatch, profile=constructed)
    assert raised.value.phase == "binding"

    enum_drift_field = descriptor.fields[0].model_construct(
        **_updated_fields(
            descriptor.fields[0],
            value_kind="direct_provider_material_v1",
        )
    )
    enum_drift_descriptor = descriptor.model_construct(
        **_updated_fields(
            descriptor,
            fields=(enum_drift_field, *descriptor.fields[1:]),
        )
    )
    enum_drift_profile = profile.model_construct(
        **_updated_fields(profile, target_delivery_descriptor=enum_drift_descriptor)
    )
    with pytest.raises(ContainerAttachStaticV3Error) as enum_raised:
        _verify(bundle, monkeypatch, profile=enum_drift_profile)
    assert enum_raised.value.phase == "binding"

    valkey_bundle = _profile_bundle(tmp_path, component="primary_valkey")
    valkey_profile = cast(ContainerBootstrapStaticRoleProfileV3, valkey_bundle["profile"])
    assert valkey_profile.valkey_launch_policy is not None
    malformed_valkey_policy = valkey_profile.valkey_launch_policy.model_construct(
        **_updated_fields(
            valkey_profile.valkey_launch_policy,
            static_directive_order=list(valkey_profile.valkey_launch_policy.static_directive_order),
        )
    )
    malformed_valkey_profile = valkey_profile.model_construct(
        **_updated_fields(valkey_profile, valkey_launch_policy=malformed_valkey_policy)
    )
    with pytest.raises(ContainerAttachStaticV3Error) as valkey_raised:
        _verify(valkey_bundle, monkeypatch, profile=malformed_valkey_profile)
    assert valkey_raised.value.phase == "binding"


def test_profile_is_value_free_and_claim_returns_only_value_free_metadata(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    bundle = _profile_bundle(tmp_path)
    profile = cast(ContainerBootstrapStaticRoleProfileV3, bundle["profile"])

    rendered = container_bootstrap_static_role_profile_v3_canonical_json(profile).decode("ascii")
    verification = _verify(bundle, monkeypatch)

    assert all(
        marker not in rendered
        for marker in (
            "postgres://",
            "redis://",
            "provider_references",
            "artifact_binding_sha256",
            "signature_base64",
        )
    )
    assert set(verification.model_dump()) == {
        "schema_version",
        "component",
        "static_role_profile_sha256",
        "attach_protocol_v3_sha256",
        "target_delivery_descriptor_sha256",
        "request_sha256",
        "ticket_sha256",
        "request_nonce_sha256",
        "replay_claim_sha256",
        "ticket_replay_claim_sha256",
        "container_lifetime_claim_sha256",
    }
    assert profile.attach_protocol.replay_allowed is False


def test_canonical_json_parser_rejects_duplicate_noncanonical_or_extra_values(
    tmp_path: Path,
) -> None:
    profile = cast(ContainerBootstrapStaticRoleProfileV3, _profile_bundle(tmp_path)["profile"])
    canonical = container_bootstrap_static_role_profile_v3_canonical_json(profile)
    duplicate = b'{"schema_version":"x","schema_version":"x"}'
    noncanonical = canonical + b"\n"
    extra = json.dumps(
        {**json.loads(canonical), "unexpected": "sentinel"},
        ensure_ascii=True,
        sort_keys=True,
        separators=(",", ":"),
    ).encode("ascii")

    for payload in (duplicate, noncanonical, extra):
        with pytest.raises(ContainerAttachStaticV3Error) as raised:
            parse_container_bootstrap_static_role_profile_v3_canonical_json(payload)
        assert raised.value.phase == "profile"


def test_protocol_rejects_frame_limit_and_state_drift() -> None:
    protocol = _protocol()

    with pytest.raises(ValueError):
        ContainerBootstrapAttachProtocolV3(**_updated_fields(protocol, frame_magic="ONC2"))
    with pytest.raises(ValueError, match="protocol"):
        ContainerBootstrapAttachProtocolV3(
            **_updated_fields(protocol, max_ticket_lifetime_seconds=1)
        )


def test_protocol_canonical_hash_and_ticket_message_are_domain_separated(tmp_path: Path) -> None:
    bundle = _profile_bundle(tmp_path)
    profile = cast(ContainerBootstrapStaticRoleProfileV3, bundle["profile"])
    ticket = cast(ContainerAttachAuthorizationTicketV3, bundle["ticket"])

    assert container_bootstrap_attach_v3_protocol_canonical_json(
        profile.attach_protocol
    ).startswith(b'{"absolute_timeout_seconds"')
    assert container_attach_v3_ticket_canonical_message(ticket).startswith(
        b"omninode-rsd.container-attach-ticket.ed25519.v3\x00"
    )
    assert container_attach_v3_ticket_sha256(ticket) != container_attach_v3_request_sha256(
        cast(ContainerAttachRequestV3, bundle["request"])
    )


def test_cross_language_vector_is_canonical_public_key_only_and_self_verifying(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    """Keep a Rust-consumable vector without tracking any signing seed."""

    raw = _VECTOR_PATH.read_text(encoding="ascii")
    assert not any(marker in raw for marker in ("&", "*", "!"))
    assert not any(marker in raw for marker in ("private_key", "signing_seed", "seed_base64"))
    parsed = yaml.load(raw, Loader=_StrictVectorLoader)
    assert type(parsed) is dict
    vector = cast(dict[str, object], parsed)
    expected_keys = {
        "schema_version",
        "profile_digest_domain_base64",
        "descriptor_digest_domain_base64",
        "protocol_digest_domain_base64",
        "request_digest_domain_base64",
        "runtime_binding_digest_domain_base64",
        "ticket_signature_domain_base64",
        "ticket_hash_domain_base64",
        "ticket_replay_claim_digest_domain_base64",
        "container_lifetime_claim_digest_domain_base64",
        "replay_claim_digest_domain_base64",
        "profile_canonical_json_utf8_base64",
        "profile_sha256",
        "descriptor_canonical_json_utf8_base64",
        "descriptor_sha256",
        "protocol_canonical_json_utf8_base64",
        "protocol_sha256",
        "request_canonical_json_utf8_base64",
        "request_sha256",
        "runtime_binding_canonical_json_utf8_base64",
        "runtime_instance_binding_preimage_base64",
        "runtime_instance_binding_sha256",
        "ticket_canonical_json_utf8_base64",
        "ticket_canonical_message_base64",
        "ticket_sha256",
        "replay_claim_canonical_json_utf8_base64",
        "replay_claim_sha256",
        "ticket_replay_claim_sha256",
        "container_lifetime_claim_sha256",
        "public_key_base64",
        "signer_key_id",
        "signature_base64",
        "frame_magic",
        "frame_version",
        "frame_header_layout",
        "secret_chunk_ordinal_layout",
        "max_metadata_bytes",
        "max_chunk_bytes",
        "max_chunks_per_target",
        "max_total_secret_bytes",
    }
    assert set(vector) == expected_keys
    assert vector["schema_version"] == "rsd.container-bootstrap-static-v3-vector-set.v2"
    assert all(
        type(vector[key]) is str
        for key in expected_keys
        - {
            "frame_version",
            "max_metadata_bytes",
            "max_chunk_bytes",
            "max_chunks_per_target",
            "max_total_secret_bytes",
        }
    )
    assert all(
        type(vector[key]) is int
        for key in (
            "frame_version",
            "max_metadata_bytes",
            "max_chunk_bytes",
            "max_chunks_per_target",
            "max_total_secret_bytes",
        )
    )

    profile = parse_container_bootstrap_static_role_profile_v3_canonical_json(
        _canonical_vector_base64(vector["profile_canonical_json_utf8_base64"])
    )
    descriptor = parse_container_bootstrap_target_delivery_descriptor_v3_canonical_json(
        _canonical_vector_base64(vector["descriptor_canonical_json_utf8_base64"])
    )
    protocol = parse_container_bootstrap_attach_v3_protocol_canonical_json(
        _canonical_vector_base64(vector["protocol_canonical_json_utf8_base64"])
    )
    request = parse_container_attach_v3_request_canonical_json(
        _canonical_vector_base64(vector["request_canonical_json_utf8_base64"])
    )
    runtime = parse_container_attach_v3_runtime_binding_canonical_json(
        _canonical_vector_base64(vector["runtime_binding_canonical_json_utf8_base64"])
    )
    ticket = parse_container_attach_v3_ticket_canonical_json(
        _canonical_vector_base64(vector["ticket_canonical_json_utf8_base64"])
    )
    replay_claim = parse_container_attach_v3_replay_claim_canonical_json(
        _canonical_vector_base64(vector["replay_claim_canonical_json_utf8_base64"])
    )
    envelope = ContainerAttachTicketEnvelopeV3(
        schema_version="rsd.container-attach-ticket-envelope.v3",
        request=request,
        ticket=ticket,
    )
    monkeypatch.setattr(static_v3, "_trusted_utc_now", lambda: _NOW)
    validation = validate_container_attach_v3_ticket(
        static_role_profile=profile,
        envelope=envelope,
        expected_runtime=runtime,
    )
    derived_replay_claim = static_v3._replay_claim_from_validation(validation)

    assert profile.target_delivery_descriptor == descriptor
    assert profile.attach_protocol == protocol
    assert container_bootstrap_static_role_profile_v3_canonical_json(profile) == (
        _canonical_vector_base64(vector["profile_canonical_json_utf8_base64"])
    )
    assert container_bootstrap_target_delivery_descriptor_v3_canonical_json(descriptor) == (
        _canonical_vector_base64(vector["descriptor_canonical_json_utf8_base64"])
    )
    assert container_bootstrap_attach_v3_protocol_canonical_json(protocol) == (
        _canonical_vector_base64(vector["protocol_canonical_json_utf8_base64"])
    )
    assert container_attach_v3_request_canonical_json(request) == _canonical_vector_base64(
        vector["request_canonical_json_utf8_base64"]
    )
    assert container_attach_v3_runtime_binding_canonical_json(runtime) == _canonical_vector_base64(
        vector["runtime_binding_canonical_json_utf8_base64"]
    )
    assert container_bootstrap_static_role_profile_v3_sha256(profile) == vector["profile_sha256"]
    assert (
        container_bootstrap_target_delivery_descriptor_v3_sha256(descriptor)
        == vector["descriptor_sha256"]
    )
    assert container_bootstrap_attach_v3_protocol_sha256(protocol) == vector["protocol_sha256"]
    assert container_attach_v3_request_sha256(request) == vector["request_sha256"]
    assert runtime.runtime_instance_binding_sha256 == vector["runtime_instance_binding_sha256"]
    assert runtime.runtime_instance_binding_sha256 == (
        container_attach_v3_runtime_instance_binding_sha256(
            container_id=runtime.container_id,
            runtime_hostname=runtime.runtime_hostname,
        )
    )
    assert _canonical_vector_base64(vector["runtime_instance_binding_preimage_base64"]) == (
        container_attach_v3_runtime_instance_binding_preimage(
            container_id=runtime.container_id,
            runtime_hostname=runtime.runtime_hostname,
        )
    )
    assert container_attach_v3_ticket_sha256(ticket) == vector["ticket_sha256"]
    assert container_attach_v3_replay_claim_canonical_json(replay_claim) == (
        _canonical_vector_base64(vector["replay_claim_canonical_json_utf8_base64"])
    )
    assert container_attach_v3_replay_claim_sha256(replay_claim) == vector["replay_claim_sha256"]
    assert replay_claim == derived_replay_claim
    assert (
        container_attach_v3_ticket_replay_claim_sha256(replay_claim.ticket_claim)
        == vector["ticket_replay_claim_sha256"]
    )
    assert (
        container_attach_v3_container_lifetime_claim_sha256(replay_claim.container_lifetime_claim)
        == vector["container_lifetime_claim_sha256"]
    )
    assert replay_claim.ticket_claim.ticket_sha256 == vector["ticket_sha256"]
    assert replay_claim.ticket_claim.request_sha256 == ticket.request_sha256
    assert replay_claim.ticket_claim.request_sha256 == vector["request_sha256"]
    assert replay_claim.ticket_claim.request_nonce_sha256 == ticket.request_nonce_sha256
    assert replay_claim.container_lifetime_claim.container_id == runtime.container_id
    assert request.container_id == runtime.container_id
    assert request.runtime_hostname == runtime.runtime_hostname
    assert request.runtime_instance_binding_sha256 == runtime.runtime_instance_binding_sha256
    assert request.request_nonce_sha256 == runtime.request_nonce_sha256
    assert request.channel_binding_sha256 == runtime.channel_binding_sha256
    assert request.session_binding_sha256 == runtime.session_binding_sha256

    assert _canonical_vector_base64(vector["profile_digest_domain_base64"]) == (
        b"omninode-rsd.container-bootstrap-static-role-profile.sha256.v3\x00"
    )
    assert _canonical_vector_base64(vector["descriptor_digest_domain_base64"]) == (
        b"omninode-rsd.container-bootstrap-target-delivery-descriptor.sha256.v3\x00"
    )
    assert _canonical_vector_base64(vector["protocol_digest_domain_base64"]) == (
        b"omninode-rsd.container-bootstrap-attach-protocol.sha256.v3\x00"
    )
    assert _canonical_vector_base64(vector["request_digest_domain_base64"]) == (
        b"omninode-rsd.container-attach-request.sha256.v3\x00"
    )
    assert _canonical_vector_base64(vector["runtime_binding_digest_domain_base64"]) == (
        b"omninode-rsd.container-attach-runtime-binding.sha256.v3\x00"
    )
    message = _canonical_vector_base64(vector["ticket_canonical_message_base64"])
    assert message == container_attach_v3_ticket_canonical_message(ticket)
    assert _canonical_vector_base64(vector["ticket_signature_domain_base64"]) == (
        b"omninode-rsd.container-attach-ticket.ed25519.v3\x00"
    )
    assert _canonical_vector_base64(vector["ticket_hash_domain_base64"]) == (
        b"omninode-rsd.container-attach-ticket.sha256.v3\x00"
    )
    assert _canonical_vector_base64(vector["ticket_replay_claim_digest_domain_base64"]) == (
        b"omninode-rsd.container-attach-ticket-replay-claim.sha256.v3\x00"
    )
    assert _canonical_vector_base64(vector["container_lifetime_claim_digest_domain_base64"]) == (
        b"omninode-rsd.container-attach-container-lifetime-claim.sha256.v3\x00"
    )
    assert _canonical_vector_base64(vector["replay_claim_digest_domain_base64"]) == (
        b"omninode-rsd.container-attach-replay-claim.sha256.v3\x00"
    )
    assert ticket.signer_key_id == vector["signer_key_id"]
    assert ticket.signature_base64 == vector["signature_base64"]
    assert profile.ticket_trust_anchor.public_key_base64 == vector["public_key_base64"]
    Ed25519PublicKey.from_public_bytes(
        _canonical_vector_base64(vector["public_key_base64"])
    ).verify(_canonical_vector_base64(vector["signature_base64"]), message)
    assert (
        protocol.frame_magic,
        protocol.frame_version,
        protocol.frame_header_layout,
        protocol.secret_chunk_ordinal_layout,
        protocol.max_metadata_bytes,
        protocol.max_chunk_bytes,
        protocol.max_chunks_per_target,
        protocol.max_total_secret_bytes,
    ) == (
        vector["frame_magic"],
        vector["frame_version"],
        vector["frame_header_layout"],
        vector["secret_chunk_ordinal_layout"],
        vector["max_metadata_bytes"],
        vector["max_chunk_bytes"],
        vector["max_chunks_per_target"],
        vector["max_total_secret_bytes"],
    )


def test_verifier_error_is_fixed_and_has_no_collaborator_context(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    bundle = _profile_bundle(tmp_path)
    profile = cast(ContainerBootstrapStaticRoleProfileV3, bundle["profile"])
    constructed = profile.model_construct(**_updated_fields(profile, component="invalid"))

    with pytest.raises(ContainerAttachStaticV3Error) as raised:
        _verify(bundle, monkeypatch, profile=constructed)

    error = raised.value
    assert str(error) == "container attach V3 verification failed"
    assert "invalid" not in repr(error)
    assert error.__context__ is None
    assert error.__cause__ is None
