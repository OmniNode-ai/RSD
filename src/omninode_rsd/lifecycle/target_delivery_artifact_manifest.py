"""Pure Phase-B2 signed target-delivery artifact manifest.

This module is deliberately a downstream, offline aggregation contract.  It
does not read source, inspect an OCI image, build a wrapper, contact a
provider, or authorize delivery.  Its only input evidence is the original
signed V1/B1/V4 artifacts.  Every validation call rechecks those artifacts;
the returned acceptance is a small non-portable diagnostic, never a grant.

One B1 policy and profile root are intentionally shared by all four profiles.
Supporting independently rooted roles would require a new B1 interface rather
than silently weakening the common-root relation here.
"""

from __future__ import annotations

import base64
import binascii
import hashlib
import json
from typing import Literal, NoReturn, Self, cast

from cryptography.exceptions import InvalidSignature
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PublicKey
from pydantic import BaseModel, ConfigDict, Field, ValidationError, field_validator, model_validator

from omninode_rsd.lifecycle.container_attach_static_v4 import (
    ContainerBootstrapStaticDeliveryProjectionV4,
    ContainerBootstrapStaticRoleProfileEnvelopeV4,
    container_bootstrap_static_delivery_projection_v4_canonical_json,
    container_bootstrap_static_role_profile_envelope_v4_sha256,
    parse_container_bootstrap_static_delivery_projection_v4_canonical_json,
)
from omninode_rsd.lifecycle.container_bootstrap_artifact_evidence_v4 import (
    ContainerBootstrapArtifactEvidenceClosureV4,
    ContainerBootstrapArtifactWorkerAttestationV4,
    container_bootstrap_artifact_worker_attestation_v4_sha256,
    validate_container_bootstrap_artifact_evidence_closure_v4,
)
from omninode_rsd.lifecycle.infisical_disposable import TargetDeliveryMapV1
from omninode_rsd.lifecycle.target_delivery_map_projection_binding import (
    TargetDeliveryMapProjectionBindingTrustPolicyV1,
    TargetDeliveryMapProjectionBindingV1,
    parse_target_delivery_map_projection_binding_trust_policy_v1_canonical_json,
    target_delivery_map_projection_binding_trust_policy_v1_canonical_json,
    validate_target_delivery_map_projection_binding_v1,
)

_SHA256 = r"^[0-9a-f]{64}$"
_IDENTIFIER = r"^[A-Za-z][A-Za-z0-9_.-]{0,127}$"
_COMPONENTS = ("primary_infisical", "primary_valkey", "restore_infisical", "restore_valkey")
_ROLES = {
    "primary_infisical": "infisical",
    "primary_valkey": "valkey",
    "restore_infisical": "infisical",
    "restore_valkey": "valkey",
}
_MAX_MANIFEST_BYTES = 65_536
_MAX_ACCEPTANCE_BYTES = 16_384
_MAX_DEPTH = 32
_MAX_NODES = 4_096
_MANIFEST_DOMAIN = b"omninode-rsd.target-delivery-artifact-manifest.ed25519.v1\x00"
_MANIFEST_HASH_DOMAIN = b"omninode-rsd.target-delivery-artifact-manifest.sha256.v1\x00"
_CONTEXT_DOMAIN = b"omninode-rsd.target-delivery-artifact-manifest-context.sha256.v1\x00"
_SOURCE_TREE_ENTRIES_DOMAIN = (
    b"omninode-rsd.target-delivery-artifact-manifest-source-tree-entries.sha256.v1\x00"
)
_OCI_LAYERS_DOMAIN = b"omninode-rsd.target-delivery-artifact-manifest-oci-layers.sha256.v1\x00"
_OCI_DIFF_IDS_DOMAIN = b"omninode-rsd.target-delivery-artifact-manifest-oci-diff-ids.sha256.v1\x00"
_OCI_ENTRYPOINT_DOMAIN = (
    b"omninode-rsd.target-delivery-artifact-manifest-oci-entrypoint.sha256.v1\x00"
)
_OCI_CMD_DOMAIN = b"omninode-rsd.target-delivery-artifact-manifest-oci-cmd.sha256.v1\x00"


class TargetDeliveryArtifactManifestError(ValueError):
    """Fixed, value-redacted B2 validation failure."""

    __slots__ = ("phase",)

    def __init__(self, phase: Literal["parse", "anchor", "input", "manifest"]):
        super().__init__("target delivery artifact manifest validation failed")
        self.phase = phase


class _Model(BaseModel):
    model_config = ConfigDict(extra="forbid", frozen=True, strict=True, validate_default=True)


def _fail(phase: Literal["parse", "anchor", "input", "manifest"]) -> NoReturn:
    raise TargetDeliveryArtifactManifestError(phase)


def _b64(value: str) -> bytes:
    if type(value) is not str:
        raise ValueError("base64 is invalid")
    try:
        result = base64.b64decode(value, validate=True)
    except (binascii.Error, ValueError):
        raise ValueError("base64 is invalid") from None
    if base64.b64encode(result).decode("ascii") != value:
        raise ValueError("base64 is invalid")
    return result


def _canonical(model: BaseModel, *, limit: int, exclude: set[str] | None = None) -> bytes:
    try:
        payload = json.dumps(
            model.model_dump(mode="json", exclude=exclude or set(), warnings="error"),
            ensure_ascii=True,
            sort_keys=True,
            separators=(",", ":"),
            allow_nan=False,
        ).encode("ascii")
    except (RecursionError, TypeError, ValueError):
        raise ValueError("model is invalid") from None
    if len(payload) > limit:
        raise ValueError("model is too large")
    return payload


def _no_duplicates(pairs: list[tuple[object, object]]) -> dict[str, object]:
    result: dict[str, object] = {}
    for key, value in pairs:
        if type(key) is not str or key in result:
            raise ValueError("JSON is invalid")
        result[key] = value
    return result


def _arrays_to_tuples(value: object) -> object:
    if type(value) is list:
        return tuple(_arrays_to_tuples(item) for item in value)
    if type(value) is dict:
        return {key: _arrays_to_tuples(item) for key, item in value.items()}
    return value


def _preflight(payload: bytes, *, limit: int) -> None:
    if type(payload) is not bytes or not 1 <= len(payload) <= limit:
        raise ValueError("JSON is invalid")
    depth = nodes = 0
    quoted = escaped = False
    for char in payload:
        if quoted:
            if escaped:
                escaped = False
            elif char == 92:
                escaped = True
            elif char == 34:
                quoted = False
            elif char < 32:
                raise ValueError("JSON is invalid")
            continue
        if char == 34:
            quoted = True
        elif char in (123, 91):
            depth += 1
        elif char in (125, 93):
            depth -= 1
        if char not in b" \t\r\n:,":
            nodes += 1
        if depth < 0 or depth > _MAX_DEPTH or nodes > _MAX_NODES:
            raise ValueError("JSON is invalid")
    if quoted or escaped or depth:
        raise ValueError("JSON is invalid")


def _parse[T: _Model](payload: bytes, expected: type[T], *, limit: int) -> T:
    _preflight(payload, limit=limit)
    try:
        value = json.loads(
            payload.decode("ascii"),
            object_pairs_hook=_no_duplicates,
            parse_float=lambda _value: (_ for _ in ()).throw(ValueError("float")),
        )
    except (UnicodeDecodeError, TypeError, ValueError):
        raise ValueError("JSON is invalid") from None
    if type(value) is not dict:
        raise ValueError("JSON is invalid")
    result = expected.model_validate(_arrays_to_tuples(value), strict=True)
    if _canonical(result, limit=limit) != payload:
        raise ValueError("JSON is invalid")
    return result


def _same_shape(original: object, canonical: object) -> bool:
    if type(original) is not type(canonical):
        return False
    if isinstance(original, BaseModel):
        return all(
            _same_shape(getattr(original, name), getattr(canonical, name))
            for name in original.__class__.model_fields
        )
    if type(original) is tuple:
        canonical_tuple = cast(tuple[object, ...], canonical)
        return len(original) == len(canonical_tuple) and all(
            _same_shape(left, right) for left, right in zip(original, canonical_tuple, strict=True)
        )
    return original == canonical


def _strict[T: _Model](value: object, expected: type[T], *, limit: int) -> T:
    if type(value) is not expected:
        raise ValueError("model type is invalid")
    rendered = _canonical(cast(BaseModel, value), limit=limit)
    canonical = _parse(rendered, expected, limit=limit)
    if not _same_shape(value, canonical):
        raise ValueError("model is not canonical")
    return canonical


def _hash(domain: bytes, value: object) -> str:
    try:
        rendered = json.dumps(
            value, ensure_ascii=True, sort_keys=True, separators=(",", ":"), allow_nan=False
        )
    except (TypeError, ValueError):
        raise ValueError("hash input is invalid") from None
    return hashlib.sha256(domain + rendered.encode("ascii")).hexdigest()


def _sequence(domain: bytes, values: tuple[object, ...]) -> tuple[str, int, int]:
    encoded = json.dumps(
        values, ensure_ascii=True, sort_keys=True, separators=(",", ":"), allow_nan=False
    ).encode("ascii")
    return hashlib.sha256(domain + encoded).hexdigest(), len(values), len(encoded)


class TargetDeliveryArtifactManifestTrustAnchorV1(_Model):
    """Externally pinned public signer root for a B2 manifest."""

    schema_version: Literal["rsd.target-delivery-artifact-manifest-trust-anchor.v1"]
    key_id: str = Field(pattern=_IDENTIFIER)
    public_key_base64: str = Field(min_length=4, max_length=128)
    public_key_fingerprint_sha256: str = Field(pattern=_SHA256)
    authority_identity_sha256: str = Field(pattern=_SHA256)
    independence_domain_identity_sha256: str = Field(pattern=_SHA256)
    algorithm: Literal["ed25519"]

    @model_validator(mode="after")
    def exact_key_and_identities(self) -> Self:
        key = _b64(self.public_key_base64)
        if (
            len(key) != 32
            or hashlib.sha256(key).hexdigest() != self.public_key_fingerprint_sha256
            or len(
                {
                    self.public_key_fingerprint_sha256,
                    self.authority_identity_sha256,
                    self.independence_domain_identity_sha256,
                }
            )
            != 3
        ):
            raise ValueError("manifest anchor is invalid")
        return self


class TargetDeliveryArtifactManifestRoleInputV1(_Model):
    """Original per-role artifacts; acceptances cannot be supplied by callers."""

    schema_version: Literal["rsd.target-delivery-artifact-manifest-role-input.v1"]
    component: Literal["primary_infisical", "primary_valkey", "restore_infisical", "restore_valkey"]
    profile_envelope: ContainerBootstrapStaticRoleProfileEnvelopeV4
    projection_binding: TargetDeliveryMapProjectionBindingV1
    phase_a_closure: ContainerBootstrapArtifactEvidenceClosureV4


class TargetDeliveryArtifactSourceSummaryV1(_Model):
    schema_version: Literal["rsd.target-delivery-artifact-source-summary.v1"]
    repository_identity_sha256: str = Field(pattern=_SHA256)
    git_object_format: Literal["sha1"]
    commit_oid: str = Field(pattern=r"^[0-9a-f]{40}$")
    tree_oid: str = Field(pattern=r"^[0-9a-f]{40}$")
    source_snapshot_sha256: str = Field(pattern=_SHA256)
    wrapper_subtree_path: str = Field(min_length=1, max_length=240)
    wrapper_tree_entries_sha256: str = Field(pattern=_SHA256)
    wrapper_tree_entry_count: int = Field(ge=1, le=32)
    wrapper_tree_entries_byte_count: int = Field(ge=2, le=16_384)
    source_clean: Literal[True]
    untracked_files_absent: Literal[True]
    submodules_absent: Literal[True]
    recipe_sha256: str = Field(pattern=_SHA256)
    toolchain_sha256: str = Field(pattern=_SHA256)
    lock_sha256: str = Field(pattern=_SHA256)
    vendor_sha256: str = Field(pattern=_SHA256)
    builder_recipe_identity_sha256: str = Field(pattern=_SHA256)


class TargetDeliveryArtifactOciSummaryV1(_Model):
    schema_version: Literal["rsd.target-delivery-artifact-oci-summary.v1"]
    derived_repository: str = Field(min_length=1, max_length=240)
    derived_reference: str = Field(min_length=80, max_length=280)
    base_image_policy_sha256: str = Field(pattern=_SHA256)
    base_resolution_attestation_sha256: str = Field(pattern=_SHA256)
    base_registry_index_digest_sha256: str = Field(pattern=_SHA256)
    base_linux_amd64_manifest_digest_sha256: str = Field(pattern=_SHA256)
    base_config_digest_sha256: str = Field(pattern=_SHA256)
    index_digest_sha256: str = Field(pattern=_SHA256)
    linux_amd64_manifest_digest_sha256: str = Field(pattern=_SHA256)
    config_digest_sha256: str = Field(pattern=_SHA256)
    wrapper_layer_digest_sha256: str = Field(pattern=_SHA256)
    wrapper_layer_ordinal: int = Field(ge=0, le=31)
    wrapper_path: str = Field(min_length=1, max_length=240)
    wrapper_sha256: str = Field(pattern=_SHA256)
    wrapper_byte_count: int = Field(ge=1, le=67_108_864)
    layers_sha256: str = Field(pattern=_SHA256)
    layer_count: int = Field(ge=1, le=32)
    layers_byte_count: int = Field(ge=2, le=16_384)
    diff_ids_sha256: str = Field(pattern=_SHA256)
    diff_id_count: int = Field(ge=1, le=32)
    diff_ids_byte_count: int = Field(ge=2, le=4_096)
    entrypoint_sha256: str = Field(pattern=_SHA256)
    entrypoint_count: int = Field(ge=1, le=128)
    # JSON sequence spelling includes quotes and separators beyond the V4
    # 32,768-byte argv payload maximum.
    entrypoint_byte_count: int = Field(ge=1, le=33_280)
    cmd_sha256: str = Field(pattern=_SHA256)
    cmd_count: int = Field(ge=0, le=64)
    cmd_byte_count: int = Field(ge=2, le=16_640)

    @model_validator(mode="after")
    def coherent_local_sequences(self) -> Self:
        if (
            self.diff_id_count != self.layer_count
            or self.wrapper_layer_ordinal != self.layer_count - 1
        ):
            raise ValueError("OCI summary is invalid")
        return self


class TargetDeliveryArtifactManifestRoleEntryV1(_Model):
    schema_version: Literal["rsd.target-delivery-artifact-manifest-role-entry.v1"]
    component: Literal["primary_infisical", "primary_valkey", "restore_infisical", "restore_valkey"]
    component_role: Literal["infisical", "valkey"]
    ordinal: Literal[0, 1, 2, 3]
    profile_sha256: str = Field(pattern=_SHA256)
    profile_envelope_sha256: str = Field(pattern=_SHA256)
    profile_root_key_id: str = Field(pattern=_IDENTIFIER)
    profile_root_fingerprint_sha256: str = Field(pattern=_SHA256)
    selected_delivery_route_sha256: str = Field(pattern=_SHA256)
    phase_a_closure_sha256: str = Field(pattern=_SHA256)
    phase_a_verification_context_sha256: str = Field(pattern=_SHA256)
    worker_attestation_sha256s: tuple[str, str]
    worker_run_ids: tuple[str, str]
    physical_builder_identity_sha256s: tuple[str, str]
    b1_binding_sha256: str = Field(pattern=_SHA256)
    b1_verification_context_sha256: str = Field(pattern=_SHA256)
    wrapper_artifact_sha256: str = Field(pattern=_SHA256)
    wrapper_artifact_byte_count: int = Field(ge=1, le=67_108_864)
    wrapper_executable_path: str = Field(min_length=1, max_length=240)
    source: TargetDeliveryArtifactSourceSummaryV1
    oci: TargetDeliveryArtifactOciSummaryV1

    @model_validator(mode="after")
    def exact_role(self) -> Self:
        if self.component_role != _ROLES[self.component] or self.ordinal != _COMPONENTS.index(
            self.component
        ):
            raise ValueError("manifest role is invalid")
        if len(set(self.worker_run_ids)) != 2 or len(set(self.worker_attestation_sha256s)) != 2:
            raise ValueError("manifest role is invalid")
        return self


class TargetDeliveryArtifactManifestV1(_Model):
    schema_version: Literal["rsd.target-delivery-artifact-manifest.v1"]
    signature_algorithm: Literal["ed25519"]
    component_order: tuple[
        Literal["primary_infisical"],
        Literal["primary_valkey"],
        Literal["restore_infisical"],
        Literal["restore_valkey"],
    ]
    target_delivery_map_sha256: str = Field(pattern=_SHA256)
    static_delivery_projection_sha256: str = Field(pattern=_SHA256)
    map_signer_key_id: str = Field(pattern=_IDENTIFIER)
    map_signer_fingerprint_sha256: str = Field(pattern=_SHA256)
    b1_policy_sha256: str = Field(pattern=_SHA256)
    source: TargetDeliveryArtifactSourceSummaryV1
    roles: tuple[
        TargetDeliveryArtifactManifestRoleEntryV1,
        TargetDeliveryArtifactManifestRoleEntryV1,
        TargetDeliveryArtifactManifestRoleEntryV1,
        TargetDeliveryArtifactManifestRoleEntryV1,
    ]
    signer_key_id: str = Field(pattern=_IDENTIFIER)
    signer_fingerprint_sha256: str = Field(pattern=_SHA256)
    signature_base64: str = Field(min_length=4, max_length=128)
    build_allowed: Literal[False]
    materialization_allowed: Literal[False]
    attach_allowed: Literal[False]
    effect_allowed: Literal[False]

    @field_validator("roles", mode="before")
    @classmethod
    def roles_tuple_only(cls, value: object) -> tuple[object, ...]:
        if type(value) is not tuple or len(value) != 4:
            raise ValueError("manifest roles are invalid")
        return value

    @model_validator(mode="after")
    def exact_shape(self) -> Self:
        if (
            self.component_order != _COMPONENTS
            or tuple(role.component for role in self.roles) != _COMPONENTS
            or len(_b64(self.signature_base64)) != 64
        ):
            raise ValueError("manifest is invalid")
        return self


class TargetDeliveryArtifactManifestRoleAcceptanceSummaryV1(_Model):
    schema_version: Literal["rsd.target-delivery-artifact-manifest-role-acceptance-summary.v1"]
    component: Literal["primary_infisical", "primary_valkey", "restore_infisical", "restore_valkey"]
    profile_sha256: str = Field(pattern=_SHA256)
    phase_a_closure_sha256: str = Field(pattern=_SHA256)
    b1_binding_sha256: str = Field(pattern=_SHA256)


class TargetDeliveryArtifactManifestAcceptanceV1(_Model):
    """Small unsigned B2 diagnostic; it cannot replace original evidence."""

    schema_version: Literal["rsd.target-delivery-artifact-manifest-acceptance.v1"]
    manifest_sha256: str = Field(pattern=_SHA256)
    verification_context_sha256: str = Field(pattern=_SHA256)
    target_delivery_map_sha256: str = Field(pattern=_SHA256)
    static_delivery_projection_sha256: str = Field(pattern=_SHA256)
    b1_policy_sha256: str = Field(pattern=_SHA256)
    roles: tuple[
        TargetDeliveryArtifactManifestRoleAcceptanceSummaryV1,
        TargetDeliveryArtifactManifestRoleAcceptanceSummaryV1,
        TargetDeliveryArtifactManifestRoleAcceptanceSummaryV1,
        TargetDeliveryArtifactManifestRoleAcceptanceSummaryV1,
    ]
    evidence_effect_allowed: Literal[False]
    build_allowed: Literal[False]
    materialization_allowed: Literal[False]
    attach_allowed: Literal[False]
    effect_allowed: Literal[False]

    @field_validator("roles", mode="before")
    @classmethod
    def roles_tuple_only(cls, value: object) -> tuple[object, ...]:
        if type(value) is not tuple or len(value) != 4:
            raise ValueError("manifest acceptance roles are invalid")
        return value

    @model_validator(mode="after")
    def exact_roles(self) -> Self:
        if tuple(role.component for role in self.roles) != _COMPONENTS or any(
            type(role) is not TargetDeliveryArtifactManifestRoleAcceptanceSummaryV1
            for role in self.roles
        ):
            raise ValueError("manifest acceptance is invalid")
        return self


def target_delivery_artifact_manifest_trust_anchor_v1_canonical_json(
    anchor: TargetDeliveryArtifactManifestTrustAnchorV1,
) -> bytes:
    """Serialize the externally pinned B2 public root canonically."""
    try:
        if type(anchor) is not TargetDeliveryArtifactManifestTrustAnchorV1:
            raise ValueError
        return _canonical(anchor, limit=2_048)
    except (TypeError, ValueError):
        _fail("anchor")


def parse_target_delivery_artifact_manifest_trust_anchor_v1_canonical_json(
    payload: bytes,
) -> TargetDeliveryArtifactManifestTrustAnchorV1:
    """Parse only the bounded canonical B2 public root spelling."""
    try:
        return _parse(payload, TargetDeliveryArtifactManifestTrustAnchorV1, limit=2_048)
    except (TypeError, ValidationError, ValueError):
        _fail("parse")


def target_delivery_artifact_manifest_v1_canonical_json(
    manifest: TargetDeliveryArtifactManifestV1,
) -> bytes:
    try:
        if type(manifest) is not TargetDeliveryArtifactManifestV1:
            raise ValueError
        return _canonical(manifest, limit=_MAX_MANIFEST_BYTES)
    except (TypeError, ValueError):
        _fail("manifest")


def parse_target_delivery_artifact_manifest_v1_canonical_json(
    payload: bytes,
) -> TargetDeliveryArtifactManifestV1:
    try:
        return _parse(payload, TargetDeliveryArtifactManifestV1, limit=_MAX_MANIFEST_BYTES)
    except (TypeError, ValidationError, ValueError):
        _fail("parse")


def target_delivery_artifact_manifest_v1_message(
    manifest: TargetDeliveryArtifactManifestV1,
) -> bytes:
    try:
        if type(manifest) is not TargetDeliveryArtifactManifestV1:
            raise ValueError
        return _MANIFEST_DOMAIN + _canonical(
            manifest, limit=_MAX_MANIFEST_BYTES, exclude={"signature_base64"}
        )
    except (TypeError, ValueError):
        _fail("manifest")


def target_delivery_artifact_manifest_v1_sha256(manifest: TargetDeliveryArtifactManifestV1) -> str:
    return hashlib.sha256(
        _MANIFEST_HASH_DOMAIN + target_delivery_artifact_manifest_v1_canonical_json(manifest)
    ).hexdigest()


def target_delivery_artifact_manifest_acceptance_v1_canonical_json(
    acceptance: TargetDeliveryArtifactManifestAcceptanceV1,
) -> bytes:
    try:
        if type(acceptance) is not TargetDeliveryArtifactManifestAcceptanceV1:
            raise ValueError
        return _canonical(acceptance, limit=_MAX_ACCEPTANCE_BYTES)
    except (TypeError, ValueError):
        _fail("manifest")


def parse_target_delivery_artifact_manifest_acceptance_v1_canonical_json(
    payload: bytes,
) -> TargetDeliveryArtifactManifestAcceptanceV1:
    try:
        return _parse(
            payload, TargetDeliveryArtifactManifestAcceptanceV1, limit=_MAX_ACCEPTANCE_BYTES
        )
    except (TypeError, ValidationError, ValueError):
        _fail("parse")


def _source(
    attestation: ContainerBootstrapArtifactWorkerAttestationV4,
) -> TargetDeliveryArtifactSourceSummaryV1:
    entries = attestation.wrapper_tree_entries
    commitment, count, bytes_ = _sequence(
        _SOURCE_TREE_ENTRIES_DOMAIN,
        tuple(entry.model_dump(mode="json") for entry in entries),
    )
    return TargetDeliveryArtifactSourceSummaryV1(
        schema_version="rsd.target-delivery-artifact-source-summary.v1",
        repository_identity_sha256=attestation.canonical_repository_identity_sha256,
        git_object_format=attestation.git_object_format,
        commit_oid=attestation.commit_oid,
        tree_oid=attestation.tree_oid,
        source_snapshot_sha256=attestation.canonical_source_snapshot_sha256,
        wrapper_subtree_path=attestation.wrapper_subtree_path,
        wrapper_tree_entries_sha256=commitment,
        wrapper_tree_entry_count=count,
        wrapper_tree_entries_byte_count=bytes_,
        source_clean=attestation.source_clean,
        untracked_files_absent=attestation.untracked_files_absent,
        submodules_absent=attestation.submodules_absent,
        recipe_sha256=attestation.recipe_sha256,
        toolchain_sha256=attestation.toolchain_sha256,
        lock_sha256=attestation.lock_sha256,
        vendor_sha256=attestation.vendor_sha256,
        builder_recipe_identity_sha256=attestation.builder_recipe_identity_sha256,
    )


def _oci(
    attestation: ContainerBootstrapArtifactWorkerAttestationV4,
) -> TargetDeliveryArtifactOciSummaryV1:
    oci = attestation.oci
    layers, layer_count, layer_bytes = _sequence(
        _OCI_LAYERS_DOMAIN, tuple(item.model_dump(mode="json") for item in oci.ordered_layers)
    )
    diffs, diff_count, diff_bytes = _sequence(
        _OCI_DIFF_IDS_DOMAIN, cast(tuple[object, ...], oci.config_rootfs_diff_ids_sha256)
    )
    entrypoint, entrypoint_count, entrypoint_bytes = _sequence(
        _OCI_ENTRYPOINT_DOMAIN, cast(tuple[object, ...], oci.entrypoint)
    )
    cmd, cmd_count, cmd_bytes = _sequence(_OCI_CMD_DOMAIN, cast(tuple[object, ...], oci.cmd))
    return TargetDeliveryArtifactOciSummaryV1(
        schema_version="rsd.target-delivery-artifact-oci-summary.v1",
        derived_repository=oci.derived_repository,
        derived_reference=oci.derived_reference,
        base_image_policy_sha256=oci.base_image_policy_sha256,
        base_resolution_attestation_sha256=oci.base_resolution_attestation_sha256,
        base_registry_index_digest_sha256=oci.base_registry_index_digest_sha256,
        base_linux_amd64_manifest_digest_sha256=oci.base_linux_amd64_manifest_digest_sha256,
        base_config_digest_sha256=oci.base_config_digest_sha256,
        index_digest_sha256=oci.index_digest_sha256,
        linux_amd64_manifest_digest_sha256=oci.linux_amd64_manifest_digest_sha256,
        config_digest_sha256=oci.config_digest_sha256,
        wrapper_layer_digest_sha256=oci.wrapper_layer_digest_sha256,
        wrapper_layer_ordinal=oci.wrapper_layer_ordinal,
        wrapper_path=oci.wrapper_tar_entry.path,
        wrapper_sha256=oci.wrapper_tar_entry.content_sha256,
        wrapper_byte_count=oci.wrapper_tar_entry.byte_count,
        layers_sha256=layers,
        layer_count=layer_count,
        layers_byte_count=layer_bytes,
        diff_ids_sha256=diffs,
        diff_id_count=diff_count,
        diff_ids_byte_count=diff_bytes,
        entrypoint_sha256=entrypoint,
        entrypoint_count=entrypoint_count,
        entrypoint_byte_count=entrypoint_bytes,
        cmd_sha256=cmd,
        cmd_count=cmd_count,
        cmd_byte_count=cmd_bytes,
    )


def _entry(
    role_input: TargetDeliveryArtifactManifestRoleInputV1,
    closure_sha256: str,
    closure_context: str,
    binding_sha256: str,
    binding_context: str,
    profile_root_key_id: str,
    profile_root_fingerprint: str,
) -> TargetDeliveryArtifactManifestRoleEntryV1:
    profile = role_input.profile_envelope.static_role_profile
    first, second = role_input.phase_a_closure.worker_attestations
    return TargetDeliveryArtifactManifestRoleEntryV1(
        schema_version="rsd.target-delivery-artifact-manifest-role-entry.v1",
        component=profile.component,
        component_role=profile.component_role,
        ordinal=cast(Literal[0, 1, 2, 3], _COMPONENTS.index(profile.component)),
        profile_sha256=profile.profile_sha256,
        profile_envelope_sha256=container_bootstrap_static_role_profile_envelope_v4_sha256(
            role_input.profile_envelope
        ),
        profile_root_key_id=profile_root_key_id,
        profile_root_fingerprint_sha256=profile_root_fingerprint,
        selected_delivery_route_sha256=profile.selected_delivery_route_sha256,
        phase_a_closure_sha256=closure_sha256,
        phase_a_verification_context_sha256=closure_context,
        worker_attestation_sha256s=(
            container_bootstrap_artifact_worker_attestation_v4_sha256(first),
            container_bootstrap_artifact_worker_attestation_v4_sha256(second),
        ),
        worker_run_ids=(first.run_id, second.run_id),
        physical_builder_identity_sha256s=(
            first.physical_builder_identity_sha256,
            second.physical_builder_identity_sha256,
        ),
        b1_binding_sha256=binding_sha256,
        b1_verification_context_sha256=binding_context,
        wrapper_artifact_sha256=first.wrapper_artifact_sha256,
        wrapper_artifact_byte_count=first.wrapper_artifact_byte_count,
        wrapper_executable_path=first.wrapper_executable_path,
        source=_source(first),
        oci=_oci(first),
    )


def _check_anchor(
    anchor: TargetDeliveryArtifactManifestTrustAnchorV1,
    policy: TargetDeliveryMapProjectionBindingTrustPolicyV1,
    inputs: tuple[
        TargetDeliveryArtifactManifestRoleInputV1,
        TargetDeliveryArtifactManifestRoleInputV1,
        TargetDeliveryArtifactManifestRoleInputV1,
        TargetDeliveryArtifactManifestRoleInputV1,
    ],
) -> None:
    roots = (
        policy.map_signer_trust_anchor,
        policy.binding_trust_anchor,
        policy.profile_trust_anchor,
        *policy.phase_a_worker_trust_policy.worker_trust_anchors,
    )
    namespace: list[str] = [
        policy.policy_id,
        policy.phase_a_worker_trust_policy.policy_id,
        policy.map_authority_identity_sha256,
        policy.map_independence_domain_identity_sha256,
        policy.binding_trust_anchor.authority_identity_sha256,
        policy.binding_trust_anchor.independence_domain_identity_sha256,
        policy.phase_a_worker_trust_policy.independence_domain_sha256,
    ]
    for root in roots:
        namespace.extend((root.key_id, root.public_key_base64, root.public_key_fingerprint_sha256))
        for attribute in ("worker_identity_sha256", "authority_identity_sha256"):
            if hasattr(root, attribute):
                namespace.append(cast(str, getattr(root, attribute)))
    for role_input in inputs:
        profile = role_input.profile_envelope.static_role_profile
        for profile_root in (profile.ticket_trust_anchor, profile.replay_receipt_trust_anchor):
            namespace.extend(
                (
                    profile_root.key_id,
                    profile_root.public_key_base64,
                    profile_root.public_key_fingerprint_sha256,
                )
            )
    anchor_namespace = (
        anchor.key_id,
        anchor.public_key_base64,
        anchor.public_key_fingerprint_sha256,
        anchor.authority_identity_sha256,
        anchor.independence_domain_identity_sha256,
    )
    if len(set(anchor_namespace)) != len(anchor_namespace) or any(
        value in namespace for value in anchor_namespace
    ):
        raise ValueError("root namespace collision")


def validate_target_delivery_artifact_manifest_v1(
    *,
    delivery_map: TargetDeliveryMapV1,
    static_delivery_projection: ContainerBootstrapStaticDeliveryProjectionV4,
    b1_trust_policy: TargetDeliveryMapProjectionBindingTrustPolicyV1,
    manifest_trust_anchor: TargetDeliveryArtifactManifestTrustAnchorV1,
    role_inputs: tuple[
        TargetDeliveryArtifactManifestRoleInputV1,
        TargetDeliveryArtifactManifestRoleInputV1,
        TargetDeliveryArtifactManifestRoleInputV1,
        TargetDeliveryArtifactManifestRoleInputV1,
    ],
    manifest: TargetDeliveryArtifactManifestV1,
) -> TargetDeliveryArtifactManifestAcceptanceV1:
    """Revalidate every original role artifact, reconstruct, then verify B2.

    This method deliberately has no acceptance parameter and no callback or
    effect surface.  Calling it again repeats only pure signature checks.
    """
    try:
        if (
            type(delivery_map) is not TargetDeliveryMapV1
            or type(static_delivery_projection) is not ContainerBootstrapStaticDeliveryProjectionV4
            or type(manifest_trust_anchor) is not TargetDeliveryArtifactManifestTrustAnchorV1
            or type(b1_trust_policy) is not TargetDeliveryMapProjectionBindingTrustPolicyV1
            or type(role_inputs) is not tuple
            or len(role_inputs) != 4
            or any(
                type(item) is not TargetDeliveryArtifactManifestRoleInputV1 for item in role_inputs
            )
        ):
            raise ValueError
        # Every top-level model is exact-canonicalized before its attributes
        # participate in a reconstruction or signature check.  Child B1 and
        # Phase-A validators repeat their own strict canonicalization below.
        static_delivery_projection = (
            parse_container_bootstrap_static_delivery_projection_v4_canonical_json(
                container_bootstrap_static_delivery_projection_v4_canonical_json(
                    static_delivery_projection
                )
            )
        )
        b1_trust_policy = (
            parse_target_delivery_map_projection_binding_trust_policy_v1_canonical_json(
                target_delivery_map_projection_binding_trust_policy_v1_canonical_json(
                    b1_trust_policy
                )
            )
        )
        manifest_trust_anchor = _strict(
            manifest_trust_anchor, TargetDeliveryArtifactManifestTrustAnchorV1, limit=2_048
        )
        role_inputs = cast(
            tuple[
                TargetDeliveryArtifactManifestRoleInputV1,
                TargetDeliveryArtifactManifestRoleInputV1,
                TargetDeliveryArtifactManifestRoleInputV1,
                TargetDeliveryArtifactManifestRoleInputV1,
            ],
            tuple(
                _strict(item, TargetDeliveryArtifactManifestRoleInputV1, limit=_MAX_MANIFEST_BYTES)
                for item in role_inputs
            ),
        )
        manifest = _strict(manifest, TargetDeliveryArtifactManifestV1, limit=_MAX_MANIFEST_BYTES)
        if tuple(item.component for item in role_inputs) != _COMPONENTS:
            raise ValueError
        _check_anchor(manifest_trust_anchor, b1_trust_policy, role_inputs)
    except (AttributeError, TypeError, ValueError):
        _fail("anchor")
    entries: list[TargetDeliveryArtifactManifestRoleEntryV1] = []
    source: TargetDeliveryArtifactSourceSummaryV1 | None = None
    try:
        for role_input in role_inputs:
            b1 = validate_target_delivery_map_projection_binding_v1(
                delivery_map=delivery_map,
                static_delivery_projection=static_delivery_projection,
                profile_envelope=role_input.profile_envelope,
                binding=role_input.projection_binding,
                trust_policy=b1_trust_policy,
            )
            phase_a = validate_container_bootstrap_artifact_evidence_closure_v4(
                closure=role_input.phase_a_closure,
                worker_trust_policy=b1_trust_policy.phase_a_worker_trust_policy,
                profile_envelope=role_input.profile_envelope,
                profile_trust_anchor=b1_trust_policy.profile_trust_anchor,
            )
            entry = _entry(
                role_input,
                phase_a.closure_sha256,
                phase_a.verification_context_sha256,
                b1.binding_sha256,
                b1.verification_context_sha256,
                b1_trust_policy.profile_trust_anchor.key_id,
                b1_trust_policy.profile_trust_anchor.public_key_fingerprint_sha256,
            )
            if (
                role_input.component != entry.component
                or entry.component_role != _ROLES[role_input.component]
            ):
                raise ValueError
            if source is None:
                source = entry.source
            elif source != entry.source:
                raise ValueError
            entries.append(entry)
        if len({run for entry in entries for run in entry.worker_run_ids}) != 8 or source is None:
            raise ValueError
        policy_bytes = target_delivery_map_projection_binding_trust_policy_v1_canonical_json(
            b1_trust_policy
        )
        policy_hash = hashlib.sha256(
            b"omninode-rsd.target-delivery-artifact-manifest-b1-policy.sha256.v1\x00" + policy_bytes
        ).hexdigest()
        expected = TargetDeliveryArtifactManifestV1(
            schema_version="rsd.target-delivery-artifact-manifest.v1",
            signature_algorithm="ed25519",
            component_order=cast(
                tuple[
                    Literal["primary_infisical"],
                    Literal["primary_valkey"],
                    Literal["restore_infisical"],
                    Literal["restore_valkey"],
                ],
                _COMPONENTS,
            ),
            target_delivery_map_sha256=b1.target_delivery_map_sha256,
            static_delivery_projection_sha256=b1.static_delivery_projection_sha256,
            map_signer_key_id=b1_trust_policy.map_signer_trust_anchor.key_id,
            map_signer_fingerprint_sha256=b1_trust_policy.map_signer_trust_anchor.public_key_fingerprint_sha256,
            b1_policy_sha256=policy_hash,
            source=source,
            roles=cast(
                tuple[
                    TargetDeliveryArtifactManifestRoleEntryV1,
                    TargetDeliveryArtifactManifestRoleEntryV1,
                    TargetDeliveryArtifactManifestRoleEntryV1,
                    TargetDeliveryArtifactManifestRoleEntryV1,
                ],
                tuple(entries),
            ),
            signer_key_id=manifest_trust_anchor.key_id,
            signer_fingerprint_sha256=manifest_trust_anchor.public_key_fingerprint_sha256,
            signature_base64=manifest.signature_base64,
            build_allowed=False,
            materialization_allowed=False,
            attach_allowed=False,
            effect_allowed=False,
        )
        if type(manifest) is not TargetDeliveryArtifactManifestV1 or manifest != expected:
            raise ValueError
        Ed25519PublicKey.from_public_bytes(_b64(manifest_trust_anchor.public_key_base64)).verify(
            _b64(manifest.signature_base64), target_delivery_artifact_manifest_v1_message(manifest)
        )
    except (InvalidSignature, TargetDeliveryArtifactManifestError, TypeError, ValueError):
        _fail("manifest")
    manifest_hash = target_delivery_artifact_manifest_v1_sha256(manifest)
    context = hashlib.sha256(
        _CONTEXT_DOMAIN
        + manifest_trust_anchor.public_key_fingerprint_sha256.encode("ascii")
        + policy_hash.encode("ascii")
        + b"".join(
            entry.phase_a_verification_context_sha256.encode("ascii")
            + entry.b1_verification_context_sha256.encode("ascii")
            for entry in entries
        )
    ).hexdigest()
    return TargetDeliveryArtifactManifestAcceptanceV1(
        schema_version="rsd.target-delivery-artifact-manifest-acceptance.v1",
        manifest_sha256=manifest_hash,
        verification_context_sha256=context,
        target_delivery_map_sha256=manifest.target_delivery_map_sha256,
        static_delivery_projection_sha256=manifest.static_delivery_projection_sha256,
        b1_policy_sha256=policy_hash,
        roles=cast(
            tuple[
                TargetDeliveryArtifactManifestRoleAcceptanceSummaryV1,
                TargetDeliveryArtifactManifestRoleAcceptanceSummaryV1,
                TargetDeliveryArtifactManifestRoleAcceptanceSummaryV1,
                TargetDeliveryArtifactManifestRoleAcceptanceSummaryV1,
            ],
            tuple(
                TargetDeliveryArtifactManifestRoleAcceptanceSummaryV1(
                    schema_version="rsd.target-delivery-artifact-manifest-role-acceptance-summary.v1",
                    component=entry.component,
                    profile_sha256=entry.profile_sha256,
                    phase_a_closure_sha256=entry.phase_a_closure_sha256,
                    b1_binding_sha256=entry.b1_binding_sha256,
                )
                for entry in entries
            ),
        ),
        evidence_effect_allowed=False,
        build_allowed=False,
        materialization_allowed=False,
        attach_allowed=False,
        effect_allowed=False,
    )
