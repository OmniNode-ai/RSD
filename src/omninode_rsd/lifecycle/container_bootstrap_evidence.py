"""Pure value-free build-evidence binding for Container Bootstrap V2.

This module verifies canonical signed commitments only.  It never builds or
inspects bytes, resolves an OCI registry, opens a socket, reads a provider, or
authorizes a runtime effect.  Its hashes are commitments to supplied evidence
preimages, not proof that a build, SBOM, reproducibility exercise, or runtime
inspection happened.
"""

from __future__ import annotations

import base64
import binascii
import hashlib
import json
import re
from typing import Final, Literal, Self, cast

from cryptography.exceptions import InvalidSignature
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PublicKey
from pydantic import BaseModel, ConfigDict, Field, ValidationError, field_validator, model_validator

from omninode_rsd.lifecycle.infisical_disposable import (
    ContainerBootstrapAttachProtocolV2,
    ContainerBootstrapValkeyLaunchPolicyV2,
    ContainerBootstrapWrapperArtifactV2,
    ContainerBootstrapWrapperManifestV2,
    DockerImagePolicyV1,
    container_bootstrap_attach_v2_protocol_message,
    container_bootstrap_attach_v2_protocol_sha256,
    container_bootstrap_environment_construction_policy_sha256,
    container_bootstrap_wrapper_v2_artifact_sha256,
    container_bootstrap_wrapper_v2_manifest_message,
    container_bootstrap_wrapper_v2_manifest_sha256,
)

_SHA256: Final = r"^[0-9a-f]{64}$"
_COMMIT: Final = r"^[0-9a-f]{40}$"
_IDENTIFIER: Final = r"^[A-Za-z][A-Za-z0-9_.-]{0,127}$"
_ROLE_ORDER: Final = (
    "primary_infisical",
    "primary_valkey",
    "restore_infisical",
    "restore_valkey",
)
_BUILD_RECIPE_DOMAIN: Final = b"omninode-rsd.container-bootstrap-build-recipe.sha256.v1\x00"
_STATIC_PATCH_DOMAIN: Final = b"omninode-rsd.container-bootstrap-static-patch.sha256.v1\x00"
_PROVENANCE_DOMAIN: Final = b"omninode-rsd.container-bootstrap-provenance.sha256.v1\x00"
_SBOM_DOMAIN: Final = b"omninode-rsd.container-bootstrap-sbom.sha256.v1\x00"
_REPRODUCIBILITY_DOMAIN: Final = b"omninode-rsd.container-bootstrap-reproducibility.sha256.v1\x00"
_EVIDENCE_BUNDLE_DOMAIN: Final = b"omninode-rsd.container-bootstrap-evidence.sha256.v1\x00"
_EVIDENCE_SIGNATURE_DOMAIN: Final = b"omninode-rsd.container-bootstrap-evidence.ed25519.v1\x00"

ComponentRoleV1 = Literal[
    "primary_infisical",
    "primary_valkey",
    "restore_infisical",
    "restore_valkey",
]


class ContainerBootstrapEvidenceError(RuntimeError):
    """Value-safe, fail-closed evidence-verifier error."""

    def __init__(self, phase: str) -> None:
        self.phase = phase
        super().__init__(f"container bootstrap evidence verification failed at phase: {phase}")


class _EvidenceModel(BaseModel):
    model_config = ConfigDict(extra="forbid", frozen=True, strict=True, validate_default=True)


def _items(value: object, *, field: str) -> tuple[object, ...]:
    if type(value) is tuple:
        return cast(tuple[object, ...], value)
    if type(value) is list:
        return tuple(value)
    raise ValueError(f"{field} must be a sequence")


def _canonical_bytes(model: BaseModel) -> bytes:
    try:
        return json.dumps(
            model.model_dump(mode="json", warnings="error"),
            sort_keys=True,
            separators=(",", ":"),
        ).encode("utf-8")
    except Exception:
        raise ValueError("evidence model is not canonical") from None


def _same_exact_shape(original: object, canonical: object) -> bool:
    """Reject constructed or copied models whose concrete nested types drifted."""

    if type(original) is not type(canonical):
        return False
    if isinstance(original, BaseModel):
        if not isinstance(canonical, BaseModel) or type(original) is not type(canonical):
            return False
        return all(
            _same_exact_shape(getattr(original, name), getattr(canonical, name))
            for name in original.__class__.model_fields
        )
    if type(original) is tuple:
        checked = cast(tuple[object, ...], canonical)
        return len(original) == len(checked) and all(
            _same_exact_shape(left, right) for left, right in zip(original, checked, strict=True)
        )
    if type(original) is list:
        checked_list = cast(list[object], canonical)
        return len(original) == len(checked_list) and all(
            _same_exact_shape(left, right)
            for left, right in zip(original, checked_list, strict=True)
        )
    if type(original) is dict:
        checked_dict = cast(dict[object, object], canonical)
        return len(original) == len(checked_dict) and all(
            _same_exact_shape(left_key, right_key)
            and _same_exact_shape(original[left_key], checked_dict[right_key])
            for left_key, right_key in zip(original, checked_dict, strict=True)
        )
    return original == canonical


def _strict[StrictModel: BaseModel](
    model: object, model_type: type[StrictModel], *, phase: str
) -> StrictModel:
    """Canonicalize a full nested model tree and reject type drift."""

    failed = False
    canonical: StrictModel | None = None
    original = b""
    rendered = b""
    try:
        if type(model) is not model_type:
            raise ValueError
        original = _canonical_bytes(cast(BaseModel, model))
        canonical = model_type.model_validate_json(original, strict=True)
        rendered = _canonical_bytes(canonical)
        if (
            type(canonical) is not model_type
            or original != rendered
            or not _same_exact_shape(model, canonical)
        ):
            raise ValueError
    except (TypeError, ValueError, ValidationError):
        failed = True
    if failed or canonical is None:
        raise ContainerBootstrapEvidenceError(phase)
    return canonical


def _domain_sha256(domain: bytes, model: BaseModel) -> str:
    if type(domain) is not bytes or not domain.endswith(b"\x00"):
        raise ValueError("evidence digest domain is invalid")
    return hashlib.sha256(domain + _canonical_bytes(model)).hexdigest()


def _canonical_base64_bytes(value: str) -> bytes:
    if type(value) is not str:
        raise ValueError("base64 is invalid")
    try:
        decoded = base64.b64decode(value, validate=True)
    except (binascii.Error, ValueError):
        raise ValueError("base64 is invalid") from None
    if base64.b64encode(decoded).decode("ascii") != value:
        raise ValueError("base64 is not canonical")
    return decoded


def _merged_argv_sha256(
    *,
    wrapper_argv_prefix: tuple[str, ...],
    base_entrypoint: tuple[str, ...],
    base_command: tuple[str, ...],
) -> str:
    return hashlib.sha256(
        json.dumps(
            wrapper_argv_prefix + base_entrypoint + base_command,
            sort_keys=True,
            separators=(",", ":"),
        ).encode("utf-8")
    ).hexdigest()


class ContainerBootstrapBuildRecipePreimageV1(_EvidenceModel):
    """Canonical non-secret recipe preimage for one compile-time wrapper role."""

    schema_version: Literal["rsd.container-bootstrap-build-recipe-preimage.v1"]
    source_commit: str = Field(pattern=_COMMIT)
    component: ComponentRoleV1
    compile_time_role: ComponentRoleV1
    architecture: Literal["x86_64-unknown-linux-musl"]
    artifact_sha256: str = Field(pattern=_SHA256)
    artifact_byte_count: int = Field(ge=1, le=16_777_216)
    executable_mode: Literal["0755"]
    toolchain_sha256: str = Field(pattern=_SHA256)
    cargo_lock_sha256: str = Field(pattern=_SHA256)
    vendored_source_sha256: str = Field(pattern=_SHA256)
    builder_identity_sha256: str = Field(pattern=_SHA256)
    base_image_policy: DockerImagePolicyV1
    derived_image_policy: DockerImagePolicyV1
    wrapper_argv_prefix: tuple[str, ...] = Field(min_length=1, max_length=16)
    base_entrypoint: tuple[str, ...] = Field(default=(), max_length=16)
    base_command: tuple[str, ...] = Field(default=(), max_length=32)
    entrypoint_command_merge: Literal["exec_wrapper_then_base_entrypoint_and_cmd_v2"]
    merged_argv_sha256: str = Field(pattern=_SHA256)
    network_access_allowed: Literal[False]
    cargo_locked_required: Literal[True]
    cargo_offline_required: Literal[True]
    source_date_epoch_required: Literal[True]
    incremental_compilation_allowed: Literal[False]

    @field_validator("wrapper_argv_prefix", "base_entrypoint", "base_command", mode="before")
    @classmethod
    def canonical_argv(cls, value: object) -> tuple[object, ...]:
        return _items(value, field="build recipe argv")

    @model_validator(mode="after")
    def exact_recipe(self) -> Self:
        if (
            self.component != self.compile_time_role
            or self.base_image_policy == self.derived_image_policy
            or self.base_image_policy.image == self.derived_image_policy.image
            or self.merged_argv_sha256
            != _merged_argv_sha256(
                wrapper_argv_prefix=self.wrapper_argv_prefix,
                base_entrypoint=self.base_entrypoint,
                base_command=self.base_command,
            )
            or len(
                {
                    self.toolchain_sha256,
                    self.cargo_lock_sha256,
                    self.vendored_source_sha256,
                    self.builder_identity_sha256,
                }
            )
            != 4
        ):
            raise ValueError("container bootstrap build recipe is invalid")
        return self


class ContainerBootstrapStaticPatchPreimageV1(_EvidenceModel):
    """Canonical static patch preimage without any target value or carrier."""

    schema_version: Literal["rsd.container-bootstrap-static-patch-preimage.v1"]
    source_commit: str = Field(pattern=_COMMIT)
    component: ComponentRoleV1
    compile_time_role: ComponentRoleV1
    patch_kind: Literal[
        "infisical_no_write_launcher_and_envp_v1",
        "valkey_stdin_launcher_and_acl_v1",
    ]
    patch_bytes_sha256: str = Field(pattern=_SHA256)
    artifact_sha256: str = Field(pattern=_SHA256)
    base_image_policy: DockerImagePolicyV1
    derived_image_policy: DockerImagePolicyV1
    child_environment_policy_sha256: str = Field(pattern=_SHA256)
    infisical_ca_updater_allowed: bool
    infisical_explicit_target_envp_required: bool
    wrapper_dynamic_environment_allowed: Literal[False]
    wrapper_dynamic_argv_allowed: Literal[False]
    wrapper_filesystem_write_allowed: Literal[False]
    target_value_carrier_in_patch_allowed: Literal[False]
    valkey_launch_policy: ContainerBootstrapValkeyLaunchPolicyV2 | None = None

    @model_validator(mode="after")
    def exact_role_patch(self) -> Self:
        infisical = self.component.endswith("infisical")
        if (
            self.component != self.compile_time_role
            or self.base_image_policy == self.derived_image_policy
            or self.base_image_policy.image == self.derived_image_policy.image
            or (
                infisical
                and (
                    self.patch_kind != "infisical_no_write_launcher_and_envp_v1"
                    or self.infisical_ca_updater_allowed is not False
                    or self.infisical_explicit_target_envp_required is not True
                    or self.valkey_launch_policy is not None
                )
            )
            or (
                not infisical
                and (
                    self.patch_kind != "valkey_stdin_launcher_and_acl_v1"
                    or self.infisical_ca_updater_allowed is not False
                    or self.infisical_explicit_target_envp_required is not False
                    or self.valkey_launch_policy is None
                    or self.valkey_launch_policy.command != ("valkey-server", "-")
                    or self.valkey_launch_policy.stdin_configuration_required is not True
                    or self.valkey_launch_policy.persistence_disabled is not True
                    or self.valkey_launch_policy.dynamic_environment_allowed is not False
                    or self.valkey_launch_policy.dynamic_argv_allowed is not False
                    or self.valkey_launch_policy.config_file_allowed is not False
                )
            )
        ):
            raise ValueError("container bootstrap static patch is invalid")
        return self


class ContainerBootstrapProvenancePreimageV1(_EvidenceModel):
    """Value-free provenance preimage; it does not assert production occurred."""

    schema_version: Literal["rsd.container-bootstrap-provenance-preimage.v1"]
    source_commit: str = Field(pattern=_COMMIT)
    component: ComponentRoleV1
    architecture: Literal["x86_64-unknown-linux-musl"]
    artifact_sha256: str = Field(pattern=_SHA256)
    artifact_byte_count: int = Field(ge=1, le=16_777_216)
    executable_mode: Literal["0755"]
    build_recipe_sha256: str = Field(pattern=_SHA256)
    static_patch_sha256: str = Field(pattern=_SHA256)
    toolchain_sha256: str = Field(pattern=_SHA256)
    cargo_lock_sha256: str = Field(pattern=_SHA256)
    builder_identity_sha256: str = Field(pattern=_SHA256)
    base_image_policy: DockerImagePolicyV1
    derived_image_policy: DockerImagePolicyV1
    provenance_format: Literal["in_toto_slsa_style_v1"]
    detached_attestation_required: Literal[True]
    signing_key_embedded_in_artifact_allowed: Literal[False]


class ContainerBootstrapSbomPreimageV1(_EvidenceModel):
    """Value-free SBOM preimage; it does not assert an SBOM was generated."""

    schema_version: Literal["rsd.container-bootstrap-sbom-preimage.v1"]
    source_commit: str = Field(pattern=_COMMIT)
    component: ComponentRoleV1
    artifact_sha256: str = Field(pattern=_SHA256)
    build_recipe_sha256: str = Field(pattern=_SHA256)
    static_patch_sha256: str = Field(pattern=_SHA256)
    sbom_document_sha256: str = Field(pattern=_SHA256)
    base_image_policy: DockerImagePolicyV1
    derived_image_policy: DockerImagePolicyV1
    sbom_format: Literal["spdx_json_v2_3"]
    target_value_in_sbom_allowed: Literal[False]


class ContainerBootstrapReproducibilityPreimageV1(_EvidenceModel):
    """Value-free reproducibility preimage; it does not assert two builds ran."""

    schema_version: Literal["rsd.container-bootstrap-reproducibility-preimage.v1"]
    source_commit: str = Field(pattern=_COMMIT)
    component: ComponentRoleV1
    architecture: Literal["x86_64-unknown-linux-musl"]
    artifact_sha256: str = Field(pattern=_SHA256)
    artifact_byte_count: int = Field(ge=1, le=16_777_216)
    executable_mode: Literal["0755"]
    build_recipe_sha256: str = Field(pattern=_SHA256)
    static_patch_sha256: str = Field(pattern=_SHA256)
    provenance_sha256: str = Field(pattern=_SHA256)
    sbom_sha256: str = Field(pattern=_SHA256)
    first_builder_evidence_sha256: str = Field(pattern=_SHA256)
    second_builder_evidence_sha256: str = Field(pattern=_SHA256)
    base_image_policy: DockerImagePolicyV1
    derived_image_policy: DockerImagePolicyV1
    clean_builder_count: Literal[2]
    network_access_allowed: Literal[False]
    exact_wrapper_bytes_required: Literal[True]
    exact_executable_mode_required: Literal[True]
    exact_oci_layer_config_manifest_required: Literal[True]

    @model_validator(mode="after")
    def distinct_builder_evidence(self) -> Self:
        if self.first_builder_evidence_sha256 == self.second_builder_evidence_sha256:
            raise ValueError("container bootstrap reproducibility evidence is invalid")
        return self


def container_bootstrap_build_recipe_sha256(recipe: ContainerBootstrapBuildRecipePreimageV1) -> str:
    """Commit a canonical recipe preimage under a dedicated domain."""

    if type(recipe) is not ContainerBootstrapBuildRecipePreimageV1:
        raise ValueError("container bootstrap build recipe is invalid")
    return _domain_sha256(_BUILD_RECIPE_DOMAIN, recipe)


def container_bootstrap_static_patch_sha256(patch: ContainerBootstrapStaticPatchPreimageV1) -> str:
    """Commit a canonical static-patch preimage under a dedicated domain."""

    if type(patch) is not ContainerBootstrapStaticPatchPreimageV1:
        raise ValueError("container bootstrap static patch is invalid")
    return _domain_sha256(_STATIC_PATCH_DOMAIN, patch)


def container_bootstrap_provenance_sha256(
    provenance: ContainerBootstrapProvenancePreimageV1,
) -> str:
    """Commit a canonical provenance preimage without retaining provenance bytes."""

    if type(provenance) is not ContainerBootstrapProvenancePreimageV1:
        raise ValueError("container bootstrap provenance is invalid")
    return _domain_sha256(_PROVENANCE_DOMAIN, provenance)


def container_bootstrap_sbom_sha256(sbom: ContainerBootstrapSbomPreimageV1) -> str:
    """Commit a canonical SBOM preimage without retaining an SBOM document."""

    if type(sbom) is not ContainerBootstrapSbomPreimageV1:
        raise ValueError("container bootstrap SBOM is invalid")
    return _domain_sha256(_SBOM_DOMAIN, sbom)


def container_bootstrap_reproducibility_sha256(
    reproducibility: ContainerBootstrapReproducibilityPreimageV1,
) -> str:
    """Commit a canonical reproducibility preimage without claiming a result."""

    if type(reproducibility) is not ContainerBootstrapReproducibilityPreimageV1:
        raise ValueError("container bootstrap reproducibility evidence is invalid")
    return _domain_sha256(_REPRODUCIBILITY_DOMAIN, reproducibility)


class ContainerBootstrapEvidenceProfileV1(_EvidenceModel):
    """Evidence preimages plus the complete immutable V2 artifact they bind."""

    schema_version: Literal["rsd.container-bootstrap-evidence-profile.v1"]
    component: ComponentRoleV1
    artifact: ContainerBootstrapWrapperArtifactV2
    recipe: ContainerBootstrapBuildRecipePreimageV1
    recipe_sha256: str = Field(pattern=_SHA256)
    static_patch: ContainerBootstrapStaticPatchPreimageV1
    static_patch_sha256: str = Field(pattern=_SHA256)
    provenance: ContainerBootstrapProvenancePreimageV1
    provenance_sha256: str = Field(pattern=_SHA256)
    sbom: ContainerBootstrapSbomPreimageV1
    sbom_sha256: str = Field(pattern=_SHA256)
    reproducibility: ContainerBootstrapReproducibilityPreimageV1
    reproducibility_sha256: str = Field(pattern=_SHA256)

    @model_validator(mode="after")
    def exact_hash_chain(self) -> Self:
        artifact = self.artifact
        recipe = self.recipe
        patch = self.static_patch
        provenance = self.provenance
        sbom = self.sbom
        reproducibility = self.reproducibility
        source_commits = {
            recipe.source_commit,
            patch.source_commit,
            provenance.source_commit,
            sbom.source_commit,
            reproducibility.source_commit,
        }
        if (
            artifact.component != self.component
            or any(
                item.component != self.component
                for item in (recipe, patch, provenance, sbom, reproducibility)
            )
            or len(source_commits) != 1
            or self.recipe_sha256 != container_bootstrap_build_recipe_sha256(recipe)
            or self.static_patch_sha256 != container_bootstrap_static_patch_sha256(patch)
            or self.provenance_sha256 != container_bootstrap_provenance_sha256(provenance)
            or self.sbom_sha256 != container_bootstrap_sbom_sha256(sbom)
            or self.reproducibility_sha256
            != container_bootstrap_reproducibility_sha256(reproducibility)
            or artifact.build_recipe_sha256 != self.recipe_sha256
            or artifact.static_patch_sha256 != self.static_patch_sha256
            or artifact.build_provenance_sha256 != self.provenance_sha256
            or recipe.artifact_sha256 != artifact.artifact_sha256
            or recipe.artifact_byte_count != artifact.artifact_byte_count
            or recipe.executable_mode != artifact.executable_mode
            or recipe.base_image_policy != artifact.base_image_policy
            or recipe.derived_image_policy != artifact.derived_image_policy
            or recipe.wrapper_argv_prefix != artifact.wrapper_argv_prefix
            or recipe.base_entrypoint != artifact.base_entrypoint
            or recipe.base_command != artifact.base_command
            or recipe.entrypoint_command_merge != artifact.entrypoint_command_merge
            or recipe.merged_argv_sha256 != artifact.merged_argv_sha256
            or patch.artifact_sha256 != artifact.artifact_sha256
            or patch.base_image_policy != artifact.base_image_policy
            or patch.derived_image_policy != artifact.derived_image_policy
            or patch.child_environment_policy_sha256
            != container_bootstrap_environment_construction_policy_sha256(
                artifact.child_environment_policy
            )
            or patch.valkey_launch_policy != artifact.valkey_launch_policy
            or provenance.artifact_sha256 != artifact.artifact_sha256
            or provenance.artifact_byte_count != artifact.artifact_byte_count
            or provenance.executable_mode != artifact.executable_mode
            or provenance.build_recipe_sha256 != self.recipe_sha256
            or provenance.static_patch_sha256 != self.static_patch_sha256
            or provenance.toolchain_sha256 != recipe.toolchain_sha256
            or provenance.cargo_lock_sha256 != recipe.cargo_lock_sha256
            or provenance.builder_identity_sha256 != recipe.builder_identity_sha256
            or provenance.base_image_policy != artifact.base_image_policy
            or provenance.derived_image_policy != artifact.derived_image_policy
            or sbom.artifact_sha256 != artifact.artifact_sha256
            or sbom.build_recipe_sha256 != self.recipe_sha256
            or sbom.static_patch_sha256 != self.static_patch_sha256
            or sbom.base_image_policy != artifact.base_image_policy
            or sbom.derived_image_policy != artifact.derived_image_policy
            or reproducibility.artifact_sha256 != artifact.artifact_sha256
            or reproducibility.artifact_byte_count != artifact.artifact_byte_count
            or reproducibility.executable_mode != artifact.executable_mode
            or reproducibility.build_recipe_sha256 != self.recipe_sha256
            or reproducibility.static_patch_sha256 != self.static_patch_sha256
            or reproducibility.provenance_sha256 != self.provenance_sha256
            or reproducibility.sbom_sha256 != self.sbom_sha256
            or reproducibility.base_image_policy != artifact.base_image_policy
            or reproducibility.derived_image_policy != artifact.derived_image_policy
        ):
            raise ValueError("container bootstrap evidence profile is invalid")
        return self


class ContainerBootstrapEvidenceBundleV1(_EvidenceModel):
    """Signed named evidence for all four fixed wrapper roles."""

    schema_version: Literal["rsd.container-bootstrap-evidence-bundle.v1"]
    wrapper_manifest_v2_sha256: str = Field(pattern=_SHA256)
    attach_protocol_v2_sha256: str = Field(pattern=_SHA256)
    primary_infisical: ContainerBootstrapEvidenceProfileV1
    primary_valkey: ContainerBootstrapEvidenceProfileV1
    restore_infisical: ContainerBootstrapEvidenceProfileV1
    restore_valkey: ContainerBootstrapEvidenceProfileV1
    signer_key_id: str = Field(pattern=_IDENTIFIER)
    signature_base64: str = Field(min_length=4, max_length=256)

    @model_validator(mode="after")
    def complete_roles(self) -> Self:
        profiles = _bundle_profiles(self)
        if (
            tuple(profile.component for profile in profiles) != _ROLE_ORDER
            or any(
                profile.artifact.attach_protocol_v2_sha256 != self.attach_protocol_v2_sha256
                for profile in profiles
            )
            or len({profile.artifact.artifact_binding_sha256 for profile in profiles}) != 4
            or len(_canonical_base64_bytes(self.signature_base64)) != 64
        ):
            raise ValueError("container bootstrap evidence bundle is invalid")
        return self


def _bundle_profiles(
    bundle: ContainerBootstrapEvidenceBundleV1,
) -> tuple[
    ContainerBootstrapEvidenceProfileV1,
    ContainerBootstrapEvidenceProfileV1,
    ContainerBootstrapEvidenceProfileV1,
    ContainerBootstrapEvidenceProfileV1,
]:
    return (
        bundle.primary_infisical,
        bundle.primary_valkey,
        bundle.restore_infisical,
        bundle.restore_valkey,
    )


def container_bootstrap_evidence_bundle_sha256(bundle: ContainerBootstrapEvidenceBundleV1) -> str:
    """Return the canonical value-free commitment for one evidence bundle."""

    if type(bundle) is not ContainerBootstrapEvidenceBundleV1:
        raise ValueError("container bootstrap evidence bundle is invalid")
    return _domain_sha256(_EVIDENCE_BUNDLE_DOMAIN, bundle)


def container_bootstrap_evidence_bundle_message(
    bundle: ContainerBootstrapEvidenceBundleV1,
) -> bytes:
    """Return direct-signature bytes; this module intentionally cannot sign them."""

    bundle = _strict(bundle, ContainerBootstrapEvidenceBundleV1, phase="bundle")
    try:
        material = json.dumps(
            bundle.model_dump(mode="json", exclude={"signature_base64"}, warnings="error"),
            sort_keys=True,
            separators=(",", ":"),
        ).encode("utf-8")
    except Exception:
        raise ValueError("container bootstrap evidence bundle is invalid") from None
    return _EVIDENCE_SIGNATURE_DOMAIN + material


class ContainerBootstrapEvidenceVerificationV1(_EvidenceModel):
    """Value-free verification result; it grants no build or runtime capability."""

    schema_version: Literal["rsd.container-bootstrap-evidence-verification.v1"]
    source_commit: str = Field(pattern=_COMMIT)
    wrapper_manifest_v2_sha256: str = Field(pattern=_SHA256)
    evidence_bundle_sha256: str = Field(pattern=_SHA256)
    attach_protocol_v2_sha256: str = Field(pattern=_SHA256)
    artifact_bindings_sha256: tuple[str, str, str, str]

    @field_validator("artifact_bindings_sha256", mode="before")
    @classmethod
    def canonical_bindings(cls, value: object) -> tuple[object, ...]:
        return _items(value, field="container bootstrap artifact bindings")

    @model_validator(mode="after")
    def exact_bindings(self) -> Self:
        if (
            any(re.fullmatch(_SHA256, value) is None for value in self.artifact_bindings_sha256)
            or len(set(self.artifact_bindings_sha256)) != 4
        ):
            raise ValueError("container bootstrap evidence verification is invalid")
        return self


def _verify_signature(
    *,
    signer_key_id: str,
    signature_base64: str,
    message: bytes,
    expected_signer_key_id: str,
    signer_public_key: bytes,
    phase: str,
) -> None:
    failed = False
    try:
        if (
            type(expected_signer_key_id) is not str
            or re.fullmatch(_IDENTIFIER, expected_signer_key_id) is None
            or type(signer_public_key) is not bytes
            or len(signer_public_key) != 32
            or type(signer_key_id) is not str
            or signer_key_id != expected_signer_key_id
            or type(message) is not bytes
        ):
            raise ValueError
        signature = _canonical_base64_bytes(signature_base64)
        if len(signature) != 64:
            raise ValueError
        Ed25519PublicKey.from_public_bytes(signer_public_key).verify(signature, message)
    except (InvalidSignature, ValueError, TypeError):
        failed = True
    if failed:
        raise ContainerBootstrapEvidenceError(phase)


def _manifest_artifacts(
    manifest: ContainerBootstrapWrapperManifestV2,
) -> tuple[
    ContainerBootstrapWrapperArtifactV2,
    ContainerBootstrapWrapperArtifactV2,
    ContainerBootstrapWrapperArtifactV2,
    ContainerBootstrapWrapperArtifactV2,
]:
    return (
        manifest.primary_infisical,
        manifest.primary_valkey,
        manifest.restore_infisical,
        manifest.restore_valkey,
    )


def _profile_matches_artifact(
    *,
    profile: ContainerBootstrapEvidenceProfileV1,
    artifact: ContainerBootstrapWrapperArtifactV2,
    source_commit: str,
    attach_protocol_v2_sha256: str,
) -> bool:
    return (
        profile.component == artifact.component
        and profile.artifact == artifact
        and profile.recipe.source_commit == source_commit
        and profile.artifact.attach_protocol_v2_sha256 == attach_protocol_v2_sha256
        and container_bootstrap_wrapper_v2_artifact_sha256(profile.artifact)
        == profile.artifact.artifact_binding_sha256
    )


def verify_container_bootstrap_evidence(
    *,
    wrapper_manifest: ContainerBootstrapWrapperManifestV2,
    attach_protocol: ContainerBootstrapAttachProtocolV2,
    evidence_bundle: ContainerBootstrapEvidenceBundleV1,
    signer_key_id: str,
    signer_public_key: bytes,
) -> ContainerBootstrapEvidenceVerificationV1:
    """Fail closed on every incomplete, substituted, or noncanonical commitment.

    ``signer_public_key`` is supplied directly by the caller.  This function
    does not load, retrieve, or create signing material.  It reuses the typed
    OCI-resolution bindings inside ``DockerImagePolicyV1`` but does not claim
    to re-resolve or independently re-attest an OCI chain.
    """

    manifest = _strict(wrapper_manifest, ContainerBootstrapWrapperManifestV2, phase="manifest")
    protocol = _strict(attach_protocol, ContainerBootstrapAttachProtocolV2, phase="protocol")
    bundle = _strict(evidence_bundle, ContainerBootstrapEvidenceBundleV1, phase="bundle")
    _verify_signature(
        signer_key_id=manifest.signer_key_id,
        signature_base64=manifest.signature_base64,
        message=container_bootstrap_wrapper_v2_manifest_message(manifest),
        expected_signer_key_id=signer_key_id,
        signer_public_key=signer_public_key,
        phase="manifest_signature",
    )
    _verify_signature(
        signer_key_id=protocol.signer_key_id,
        signature_base64=protocol.signature_base64,
        message=container_bootstrap_attach_v2_protocol_message(protocol),
        expected_signer_key_id=signer_key_id,
        signer_public_key=signer_public_key,
        phase="protocol_signature",
    )
    _verify_signature(
        signer_key_id=bundle.signer_key_id,
        signature_base64=bundle.signature_base64,
        message=container_bootstrap_evidence_bundle_message(bundle),
        expected_signer_key_id=signer_key_id,
        signer_public_key=signer_public_key,
        phase="bundle_signature",
    )
    manifest_sha256 = container_bootstrap_wrapper_v2_manifest_sha256(manifest)
    protocol_sha256 = container_bootstrap_attach_v2_protocol_sha256(protocol)
    if (
        bundle.wrapper_manifest_v2_sha256 != manifest_sha256
        or bundle.attach_protocol_v2_sha256 != protocol_sha256
        or manifest.attach_protocol_v2_sha256 != protocol_sha256
    ):
        raise ContainerBootstrapEvidenceError("bundle_binding")
    artifacts = _manifest_artifacts(manifest)
    for profile, artifact in zip(_bundle_profiles(bundle), artifacts, strict=True):
        if not _profile_matches_artifact(
            profile=profile,
            artifact=artifact,
            source_commit=manifest.source_commit,
            attach_protocol_v2_sha256=protocol_sha256,
        ):
            raise ContainerBootstrapEvidenceError("profile_binding")
    return ContainerBootstrapEvidenceVerificationV1(
        schema_version="rsd.container-bootstrap-evidence-verification.v1",
        source_commit=manifest.source_commit,
        wrapper_manifest_v2_sha256=manifest_sha256,
        evidence_bundle_sha256=container_bootstrap_evidence_bundle_sha256(bundle),
        attach_protocol_v2_sha256=protocol_sha256,
        artifact_bindings_sha256=cast(
            tuple[str, str, str, str],
            tuple(artifact.artifact_binding_sha256 for artifact in artifacts),
        ),
    )


__all__ = [
    "ContainerBootstrapBuildRecipePreimageV1",
    "ContainerBootstrapEvidenceBundleV1",
    "ContainerBootstrapEvidenceError",
    "ContainerBootstrapEvidenceProfileV1",
    "ContainerBootstrapEvidenceVerificationV1",
    "ContainerBootstrapProvenancePreimageV1",
    "ContainerBootstrapReproducibilityPreimageV1",
    "ContainerBootstrapSbomPreimageV1",
    "ContainerBootstrapStaticPatchPreimageV1",
    "container_bootstrap_build_recipe_sha256",
    "container_bootstrap_evidence_bundle_message",
    "container_bootstrap_evidence_bundle_sha256",
    "container_bootstrap_provenance_sha256",
    "container_bootstrap_reproducibility_sha256",
    "container_bootstrap_sbom_sha256",
    "container_bootstrap_static_patch_sha256",
    "verify_container_bootstrap_evidence",
]
