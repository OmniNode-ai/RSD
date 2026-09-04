"""Offline adversarial tests for the container-bootstrap evidence contract."""

from __future__ import annotations

import base64
import hashlib
import importlib.util
import sys
from pathlib import Path
from typing import Any, cast

import pytest
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey
from pydantic import ValidationError

from omninode_rsd.lifecycle import container_bootstrap_evidence as evidence
from omninode_rsd.lifecycle.infisical_disposable import (
    ContainerBootstrapAttachProtocolV2,
    ContainerBootstrapWrapperArtifactV2,
    ContainerBootstrapWrapperManifestV2,
    container_bootstrap_attach_v2_protocol_sha256,
    container_bootstrap_environment_construction_policy_sha256,
    container_bootstrap_wrapper_v2_artifact_sha256,
    container_bootstrap_wrapper_v2_manifest_sha256,
)


def _load_v2_fixtures() -> Any:
    """Load adjacent V2 fixtures without making the test tree a package."""

    path = Path(__file__).with_name("test_container_attach_v2.py")
    spec = importlib.util.spec_from_file_location("_rsd_v2_evidence_fixtures", path)
    if spec is None or spec.loader is None:
        raise RuntimeError("V2 fixture module is unavailable")
    module = importlib.util.module_from_spec(spec)
    sys.modules[spec.name] = module
    spec.loader.exec_module(module)
    return module


v2_fixtures = _load_v2_fixtures()
_ROLES = (
    "primary_infisical",
    "primary_valkey",
    "restore_infisical",
    "restore_valkey",
)


def _hash(label: str) -> str:
    return hashlib.sha256(label.encode("ascii")).hexdigest()


def _signature(private_key: Ed25519PrivateKey, message: bytes) -> str:
    return base64.b64encode(private_key.sign(message)).decode("ascii")


def _recipe(
    artifact: ContainerBootstrapWrapperArtifactV2,
    source_commit: str,
) -> evidence.ContainerBootstrapBuildRecipePreimageV1:
    component = artifact.component
    return evidence.ContainerBootstrapBuildRecipePreimageV1(
        schema_version="rsd.container-bootstrap-build-recipe-preimage.v1",
        source_commit=source_commit,
        component=component,
        compile_time_role=component,
        architecture="x86_64-unknown-linux-musl",
        artifact_sha256=artifact.artifact_sha256,
        artifact_byte_count=artifact.artifact_byte_count,
        executable_mode=artifact.executable_mode,
        toolchain_sha256=_hash(f"{component}-toolchain"),
        cargo_lock_sha256=_hash(f"{component}-cargo-lock"),
        vendored_source_sha256=_hash(f"{component}-vendored-source"),
        builder_identity_sha256=_hash(f"{component}-builder"),
        base_image_policy=artifact.base_image_policy,
        derived_image_policy=artifact.derived_image_policy,
        wrapper_argv_prefix=artifact.wrapper_argv_prefix,
        base_entrypoint=artifact.base_entrypoint,
        base_command=artifact.base_command,
        entrypoint_command_merge=artifact.entrypoint_command_merge,
        merged_argv_sha256=artifact.merged_argv_sha256,
        network_access_allowed=False,
        cargo_locked_required=True,
        cargo_offline_required=True,
        source_date_epoch_required=True,
        incremental_compilation_allowed=False,
    )


def _static_patch(
    artifact: ContainerBootstrapWrapperArtifactV2,
    source_commit: str,
) -> evidence.ContainerBootstrapStaticPatchPreimageV1:
    component = artifact.component
    is_infisical = component.endswith("infisical")
    return evidence.ContainerBootstrapStaticPatchPreimageV1(
        schema_version="rsd.container-bootstrap-static-patch-preimage.v1",
        source_commit=source_commit,
        component=component,
        compile_time_role=component,
        patch_kind=(
            "infisical_no_write_launcher_and_envp_v1"
            if is_infisical
            else "valkey_stdin_launcher_and_acl_v1"
        ),
        patch_bytes_sha256=_hash(f"{component}-patch-bytes"),
        artifact_sha256=artifact.artifact_sha256,
        base_image_policy=artifact.base_image_policy,
        derived_image_policy=artifact.derived_image_policy,
        child_environment_policy_sha256=container_bootstrap_environment_construction_policy_sha256(
            artifact.child_environment_policy
        ),
        infisical_ca_updater_allowed=False,
        infisical_explicit_target_envp_required=is_infisical,
        wrapper_dynamic_environment_allowed=False,
        wrapper_dynamic_argv_allowed=False,
        wrapper_filesystem_write_allowed=False,
        target_value_carrier_in_patch_allowed=False,
        valkey_launch_policy=artifact.valkey_launch_policy,
    )


def _profile(
    artifact: ContainerBootstrapWrapperArtifactV2,
    source_commit: str,
) -> evidence.ContainerBootstrapEvidenceProfileV1:
    recipe = _recipe(artifact, source_commit)
    recipe_sha256 = evidence.container_bootstrap_build_recipe_sha256(recipe)
    patch = _static_patch(artifact, source_commit)
    patch_sha256 = evidence.container_bootstrap_static_patch_sha256(patch)
    component = artifact.component
    provenance = evidence.ContainerBootstrapProvenancePreimageV1(
        schema_version="rsd.container-bootstrap-provenance-preimage.v1",
        source_commit=source_commit,
        component=component,
        architecture="x86_64-unknown-linux-musl",
        artifact_sha256=artifact.artifact_sha256,
        artifact_byte_count=artifact.artifact_byte_count,
        executable_mode=artifact.executable_mode,
        build_recipe_sha256=recipe_sha256,
        static_patch_sha256=patch_sha256,
        toolchain_sha256=recipe.toolchain_sha256,
        cargo_lock_sha256=recipe.cargo_lock_sha256,
        builder_identity_sha256=recipe.builder_identity_sha256,
        base_image_policy=artifact.base_image_policy,
        derived_image_policy=artifact.derived_image_policy,
        provenance_format="in_toto_slsa_style_v1",
        detached_attestation_required=True,
        signing_key_embedded_in_artifact_allowed=False,
    )
    provenance_sha256 = evidence.container_bootstrap_provenance_sha256(provenance)
    sbom = evidence.ContainerBootstrapSbomPreimageV1(
        schema_version="rsd.container-bootstrap-sbom-preimage.v1",
        source_commit=source_commit,
        component=component,
        artifact_sha256=artifact.artifact_sha256,
        build_recipe_sha256=recipe_sha256,
        static_patch_sha256=patch_sha256,
        sbom_document_sha256=_hash(f"{component}-sbom-document"),
        base_image_policy=artifact.base_image_policy,
        derived_image_policy=artifact.derived_image_policy,
        sbom_format="spdx_json_v2_3",
        target_value_in_sbom_allowed=False,
    )
    sbom_sha256 = evidence.container_bootstrap_sbom_sha256(sbom)
    reproducibility = evidence.ContainerBootstrapReproducibilityPreimageV1(
        schema_version="rsd.container-bootstrap-reproducibility-preimage.v1",
        source_commit=source_commit,
        component=component,
        architecture="x86_64-unknown-linux-musl",
        artifact_sha256=artifact.artifact_sha256,
        artifact_byte_count=artifact.artifact_byte_count,
        executable_mode=artifact.executable_mode,
        build_recipe_sha256=recipe_sha256,
        static_patch_sha256=patch_sha256,
        provenance_sha256=provenance_sha256,
        sbom_sha256=sbom_sha256,
        first_builder_evidence_sha256=_hash(f"{component}-builder-one"),
        second_builder_evidence_sha256=_hash(f"{component}-builder-two"),
        base_image_policy=artifact.base_image_policy,
        derived_image_policy=artifact.derived_image_policy,
        clean_builder_count=2,
        network_access_allowed=False,
        exact_wrapper_bytes_required=True,
        exact_executable_mode_required=True,
        exact_oci_layer_config_manifest_required=True,
    )
    return evidence.ContainerBootstrapEvidenceProfileV1(
        schema_version="rsd.container-bootstrap-evidence-profile.v1",
        component=component,
        artifact=artifact,
        recipe=recipe,
        recipe_sha256=recipe_sha256,
        static_patch=patch,
        static_patch_sha256=patch_sha256,
        provenance=provenance,
        provenance_sha256=provenance_sha256,
        sbom=sbom,
        sbom_sha256=sbom_sha256,
        reproducibility=reproducibility,
        reproducibility_sha256=evidence.container_bootstrap_reproducibility_sha256(reproducibility),
    )


def _artifact_with_evidence_hashes(
    artifact: ContainerBootstrapWrapperArtifactV2,
    source_commit: str,
) -> ContainerBootstrapWrapperArtifactV2:
    """Make an artifact whose existing V2 commitments match this test evidence."""

    provisional = artifact.model_copy(
        update={
            "build_recipe_sha256": _hash(f"{artifact.component}-placeholder-recipe"),
            "static_patch_sha256": _hash(f"{artifact.component}-placeholder-patch"),
            "build_provenance_sha256": _hash(f"{artifact.component}-placeholder-provenance"),
            "artifact_binding_sha256": "0" * 64,
        }
    )
    recipe = _recipe(provisional, source_commit)
    patch = _static_patch(provisional, source_commit)
    recipe_sha256 = evidence.container_bootstrap_build_recipe_sha256(recipe)
    patch_sha256 = evidence.container_bootstrap_static_patch_sha256(patch)
    provenance = evidence.ContainerBootstrapProvenancePreimageV1(
        schema_version="rsd.container-bootstrap-provenance-preimage.v1",
        source_commit=source_commit,
        component=provisional.component,
        architecture="x86_64-unknown-linux-musl",
        artifact_sha256=provisional.artifact_sha256,
        artifact_byte_count=provisional.artifact_byte_count,
        executable_mode=provisional.executable_mode,
        build_recipe_sha256=recipe_sha256,
        static_patch_sha256=patch_sha256,
        toolchain_sha256=recipe.toolchain_sha256,
        cargo_lock_sha256=recipe.cargo_lock_sha256,
        builder_identity_sha256=recipe.builder_identity_sha256,
        base_image_policy=provisional.base_image_policy,
        derived_image_policy=provisional.derived_image_policy,
        provenance_format="in_toto_slsa_style_v1",
        detached_attestation_required=True,
        signing_key_embedded_in_artifact_allowed=False,
    )
    draft = provisional.model_copy(
        update={
            "build_recipe_sha256": recipe_sha256,
            "static_patch_sha256": patch_sha256,
            "build_provenance_sha256": evidence.container_bootstrap_provenance_sha256(provenance),
            "artifact_binding_sha256": "0" * 64,
        }
    )
    return draft.model_copy(
        update={"artifact_binding_sha256": container_bootstrap_wrapper_v2_artifact_sha256(draft)}
    )


def _signed_bundle(
    *,
    manifest: ContainerBootstrapWrapperManifestV2,
    protocol: ContainerBootstrapAttachProtocolV2,
    profiles: dict[str, evidence.ContainerBootstrapEvidenceProfileV1],
    private_key: Ed25519PrivateKey,
) -> evidence.ContainerBootstrapEvidenceBundleV1:
    unsigned = evidence.ContainerBootstrapEvidenceBundleV1(
        schema_version="rsd.container-bootstrap-evidence-bundle.v1",
        wrapper_manifest_v2_sha256=container_bootstrap_wrapper_v2_manifest_sha256(manifest),
        attach_protocol_v2_sha256=container_bootstrap_attach_v2_protocol_sha256(protocol),
        primary_infisical=profiles["primary_infisical"],
        primary_valkey=profiles["primary_valkey"],
        restore_infisical=profiles["restore_infisical"],
        restore_valkey=profiles["restore_valkey"],
        signer_key_id="v2-signer",
        signature_base64=base64.b64encode(b"x" * 64).decode("ascii"),
    )
    return unsigned.model_copy(
        update={
            "signature_base64": _signature(
                private_key, evidence.container_bootstrap_evidence_bundle_message(unsigned)
            )
        }
    )


def _controls(
    tmp_path: Path,
) -> tuple[
    ContainerBootstrapWrapperManifestV2,
    ContainerBootstrapAttachProtocolV2,
    evidence.ContainerBootstrapEvidenceBundleV1,
]:
    fixture_controls = v2_fixtures._controls(tmp_path)
    protocol = cast(ContainerBootstrapAttachProtocolV2, fixture_controls["protocol"])
    original = cast(ContainerBootstrapWrapperManifestV2, fixture_controls["manifest"])
    artifacts = {
        role: _artifact_with_evidence_hashes(getattr(original, role), original.source_commit)
        for role in _ROLES
    }
    manifest = v2_fixtures._resign_v2_manifest(original, **artifacts)
    profiles = {role: _profile(getattr(manifest, role), manifest.source_commit) for role in _ROLES}
    bundle = _signed_bundle(
        manifest=manifest,
        protocol=protocol,
        profiles=profiles,
        private_key=v2_fixtures._PRIVATE,
    )
    return manifest, protocol, bundle


def _verify(
    manifest: ContainerBootstrapWrapperManifestV2,
    protocol: ContainerBootstrapAttachProtocolV2,
    bundle: evidence.ContainerBootstrapEvidenceBundleV1,
    *,
    signer_key_id: str = "v2-signer",
    signer_public_key: bytes | None = None,
) -> evidence.ContainerBootstrapEvidenceVerificationV1:
    return evidence.verify_container_bootstrap_evidence(
        wrapper_manifest=manifest,
        attach_protocol=protocol,
        evidence_bundle=bundle,
        signer_key_id=signer_key_id,
        signer_public_key=v2_fixtures._PUBLIC if signer_public_key is None else signer_public_key,
    )


def test_verifies_complete_signed_four_role_value_free_evidence(tmp_path: Path) -> None:
    manifest, protocol, bundle = _controls(tmp_path)

    verified = _verify(manifest, protocol, bundle)

    assert verified.source_commit == manifest.source_commit
    assert verified.wrapper_manifest_v2_sha256 == container_bootstrap_wrapper_v2_manifest_sha256(
        manifest
    )
    assert verified.attach_protocol_v2_sha256 == container_bootstrap_attach_v2_protocol_sha256(
        protocol
    )
    assert verified.artifact_bindings_sha256 == tuple(
        getattr(manifest, role).artifact_binding_sha256 for role in _ROLES
    )


def test_rejects_resigned_artifact_substitution_even_when_profile_is_self_consistent(
    tmp_path: Path,
) -> None:
    manifest, protocol, bundle = _controls(tmp_path)
    original = manifest.primary_infisical
    provisional = original.model_copy(
        update={
            "artifact_sha256": _hash("substituted-wrapper"),
            "artifact_binding_sha256": "0" * 64,
        }
    )
    substituted = _artifact_with_evidence_hashes(provisional, manifest.source_commit)
    profile = _profile(substituted, manifest.source_commit)
    altered_bundle = _signed_bundle(
        manifest=manifest,
        protocol=protocol,
        profiles={
            **{role: getattr(bundle, role) for role in _ROLES},
            "primary_infisical": profile,
        },
        private_key=v2_fixtures._PRIVATE,
    )

    with pytest.raises(evidence.ContainerBootstrapEvidenceError, match="profile_binding"):
        _verify(manifest, protocol, altered_bundle)


def test_rejects_resigned_manifest_or_protocol_substitution(tmp_path: Path) -> None:
    manifest, protocol, bundle = _controls(tmp_path)
    changed_manifest = v2_fixtures._resign_v2_manifest(manifest, source_commit="b" * 40)
    changed_protocol = v2_fixtures._protocol(max_chunk_bytes=2048)

    with pytest.raises(evidence.ContainerBootstrapEvidenceError, match="bundle_binding"):
        _verify(changed_manifest, protocol, bundle)
    with pytest.raises(evidence.ContainerBootstrapEvidenceError, match="bundle_binding"):
        _verify(manifest, changed_protocol, bundle)


def test_rejects_cross_domain_or_tampered_evidence_signature(tmp_path: Path) -> None:
    manifest, protocol, bundle = _controls(tmp_path)
    cross_domain = bundle.model_copy(update={"signature_base64": manifest.signature_base64})
    malformed = bundle.model_copy(
        update={"signature_base64": base64.b64encode(b"z" * 64).decode("ascii")}
    )

    with pytest.raises(evidence.ContainerBootstrapEvidenceError, match="bundle_signature"):
        _verify(manifest, protocol, cross_domain)
    with pytest.raises(evidence.ContainerBootstrapEvidenceError, match="bundle_signature"):
        _verify(manifest, protocol, malformed)


def test_rejects_self_consistent_wrapper_policy_drift_against_signed_manifest(
    tmp_path: Path,
) -> None:
    manifest, protocol, bundle = _controls(tmp_path)
    original = manifest.primary_infisical
    altered_pid1 = original.pid1_policy.model_copy(update={"shutdown_timeout_seconds": 11})
    altered_artifact = _artifact_with_evidence_hashes(
        original.model_copy(
            update={"pid1_policy": altered_pid1, "artifact_binding_sha256": "0" * 64}
        ),
        manifest.source_commit,
    )
    altered_bundle = _signed_bundle(
        manifest=manifest,
        protocol=protocol,
        profiles={
            **{role: getattr(bundle, role) for role in _ROLES},
            "primary_infisical": _profile(altered_artifact, manifest.source_commit),
        },
        private_key=v2_fixtures._PRIVATE,
    )

    with pytest.raises(evidence.ContainerBootstrapEvidenceError, match="profile_binding"):
        _verify(manifest, protocol, altered_bundle)


def test_rejects_role_swaps_missing_roles_and_duplicate_artifact_bindings(tmp_path: Path) -> None:
    manifest, protocol, bundle = _controls(tmp_path)

    with pytest.raises(ValidationError):
        evidence.ContainerBootstrapEvidenceBundleV1(
            **(bundle.model_dump(mode="python") | {"primary_infisical": bundle.restore_infisical})
        )
    with pytest.raises(ValidationError):
        evidence.ContainerBootstrapEvidenceBundleV1(
            **(
                bundle.model_dump(mode="python")
                | {"primary_valkey": bundle.primary_valkey, "restore_valkey": bundle.primary_valkey}
            )
        )
    fields = bundle.model_dump(mode="python")
    del fields["restore_infisical"]
    with pytest.raises(ValidationError):
        evidence.ContainerBootstrapEvidenceBundleV1(**fields)
    assert _verify(manifest, protocol, bundle).artifact_bindings_sha256


def test_rejects_wrong_trust_anchor_key_noncanonical_signature_and_constructed_type_drift(
    tmp_path: Path,
) -> None:
    manifest, protocol, bundle = _controls(tmp_path)
    wrong_public_key = (
        Ed25519PrivateKey.from_private_bytes(b"w" * 32).public_key().public_bytes_raw()
    )

    with pytest.raises(evidence.ContainerBootstrapEvidenceError, match="manifest_signature"):
        _verify(manifest, protocol, bundle, signer_public_key=wrong_public_key)
    with pytest.raises(evidence.ContainerBootstrapEvidenceError, match="manifest_signature"):
        _verify(manifest, protocol, bundle, signer_key_id="different-signer")
    noncanonical = bundle.model_copy(update={"signature_base64": bundle.signature_base64 + "\n"})
    with pytest.raises(evidence.ContainerBootstrapEvidenceError, match="bundle"):
        _verify(manifest, protocol, noncanonical)
    drifted = evidence.ContainerBootstrapEvidenceBundleV1.model_construct(
        **(bundle.model_dump(mode="python") | {"primary_infisical": {}})
    )
    with pytest.raises(evidence.ContainerBootstrapEvidenceError, match="bundle"):
        _verify(manifest, protocol, drifted)


def test_infisical_and_valkey_static_patch_policy_is_exact_and_has_no_target_carrier(
    tmp_path: Path,
) -> None:
    manifest, _, _ = _controls(tmp_path)
    infisical = manifest.primary_infisical
    valkey = manifest.primary_valkey

    with pytest.raises(ValidationError):
        evidence.ContainerBootstrapStaticPatchPreimageV1(
            **(
                _static_patch(infisical, manifest.source_commit).model_dump(mode="python")
                | {"infisical_ca_updater_allowed": True}
            )
        )
    with pytest.raises(ValidationError):
        evidence.ContainerBootstrapStaticPatchPreimageV1(
            **(
                _static_patch(valkey, manifest.source_commit).model_dump(mode="python")
                | {"target_value_carrier_in_patch_allowed": True}
            )
        )
    malformed_policy = cast(
        Any,
        valkey.valkey_launch_policy,
    ).model_copy(update={"command": ("valkey-server", "--bad")})
    with pytest.raises(ValidationError):
        evidence.ContainerBootstrapStaticPatchPreimageV1(
            **(
                _static_patch(valkey, manifest.source_commit).model_dump(mode="python")
                | {"valkey_launch_policy": malformed_policy}
            )
        )
    fields = set(evidence.ContainerBootstrapStaticPatchPreimageV1.model_fields)
    assert not {"target", "value", "uri", "credential", "provider_reference"} <= fields


def test_errors_are_fixed_value_safe_and_evidence_models_have_no_secret_carriers(
    tmp_path: Path,
) -> None:
    manifest, protocol, bundle = _controls(tmp_path)
    sentinel = "untrusted-sentinel"
    try:
        _verify(manifest, protocol, bundle, signer_key_id=sentinel)
    except evidence.ContainerBootstrapEvidenceError as error:
        assert error.phase == "manifest_signature"
        assert sentinel not in str(error)
        assert sentinel not in repr(error)
        assert sentinel not in repr(error.__dict__)
        assert error.__context__ is None
        assert error.__cause__ is None
        assert getattr(error, "__notes__", None) is None
    else:
        pytest.fail("wrong signer identifier unexpectedly verified")
    rendered = bundle.model_dump_json()
    assert sentinel not in rendered
    for forbidden in (
        '"provider_reference"',
        '"database_connection_uri"',
        '"target_value"',
        '"target_value_bytes"',
    ):
        assert forbidden not in rendered
