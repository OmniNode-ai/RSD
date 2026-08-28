"""Phase-A regression coverage retained while V2 replaces the effect contract.

These checks deliberately exercise the compiler boundary rather than a retired
initial-effect API.  They retain the non-authorizing artifact and topology
guarantees that remain prerequisites for allocation and materialization.
"""

from __future__ import annotations

import hashlib
import json
from datetime import UTC, datetime
from pathlib import Path

import pytest
import yaml

from omninode_rsd.lifecycle.infisical_disposable import (
    AllocationEvidenceBindingsV1,
    ApprovalEvidenceV1,
    CandidateCompositeV1,
    DetachedSignatureV1,
    DisposablePreflightError,
    DisposableTransportProfile,
    DockerEngineFilteredProjectionV1,
    EvidenceBindingsV1,
    GovernedBaselineV1,
    GovernedIdentityV1,
    ImageReferenceV1,
    PostgreSQLAcceptanceOverlayV1,
    PostgreSQLContractV1,
    PreflightPaths,
    ProposalV1,
    ProviderDeclarationV1,
    ProviderReferencesV2,
    ProviderReferenceV1,
    RegistryImageVerificationV1,
    RegistryVerificationV1,
    RuntimeContractV1,
    ServiceIdentityV1,
    StableIdentifierKind,
    StableIdentifierV1,
    TargetAttestationV1,
    TransportContractV1,
    ValkeyIdentityV1,
    canonical_sha256,
    compile_preflight,
    docker_engine_fingerprint_sha256,
    docker_volume_instance_fingerprint_sha256,
    main,
    proposal_sha256,
)

_NOW = datetime(2026, 8, 28, 12, 0, tzinfo=UTC)
_COMMIT = "a" * 40
_HASH = "b" * 64
_IMAGE = ImageReferenceV1(reference=f"registry.example.test/infisical@sha256:{'c' * 64}")
_CACHE_IMAGE = ImageReferenceV1(reference=f"registry.example.test/valkey@sha256:{'d' * 64}")
_VOLUME_ENGINE_FINGERPRINT = docker_engine_fingerprint_sha256(
    DockerEngineFilteredProjectionV1(
        daemon_id="phase-a-fixture-engine",
        api_version="1.47",
        operating_system="linux",
        architecture="amd64",
    )
)
_VOLUME_CREATED_AT = "2026-08-28T12:00:00Z"


def _digest(value: bytes) -> str:
    return hashlib.sha256(value).hexdigest()


def _container_identity(name: str) -> str:
    return _digest(f"container:{name}".encode())


def _volume_instance_fingerprint(volume: str) -> str:
    return docker_volume_instance_fingerprint_sha256(
        name=volume,
        engine_fingerprint_sha256=_VOLUME_ENGINE_FINGERPRINT,
        driver="local",
        scope="local",
        created_at=_VOLUME_CREATED_AT,
        options=(),
    )


def _signature() -> DetachedSignatureV1:
    return DetachedSignatureV1(
        algorithm="ed25519-detached-v1",
        signer_key_id="test-signer",
        signer_public_key_fingerprint_sha256="1" * 64,
        detached_signature_sha256="2" * 64,
    )


def _reference(name: str, version: int = 1) -> ProviderReferenceV1:
    data = {
        "account": f"account-{name}",
        "provider": "metadata-provider",
        "service": f"service-{name}",
        "version": version,
    }
    return ProviderReferenceV1(
        **data,
        reference_sha256=_digest(json.dumps(data, sort_keys=True, separators=(",", ":")).encode()),
    )


def _references(*, tls: bool = False) -> ProviderReferencesV2:
    return ProviderReferencesV2(
        commitment_hmac=_reference("commitment"),
        backup_encryption=_reference("backup"),
        encryption_key=_reference("encryption"),
        auth_secret=_reference("auth"),
        primary_valkey_password=_reference("primary-cache"),
        restore_valkey_password=_reference("restore-cache"),
        postgres_application_password=_reference("postgres-application"),
        tls_trust_anchor=_reference("trust") if tls else None,
    )


def _service(
    *, number: int, project: str, network: str, restore: bool = False, tls: bool = False
) -> ServiceIdentityV1:
    authority = None
    if not restore:
        authority = "https://198.51.100.31:443" if tls else "http://127.0.0.1:8080"
    return ServiceIdentityV1(
        authority=authority,
        authority_sha256=None if authority is None else _digest(authority.encode()),
        machine_id=f"machine-{number}",
        compose_project=project,
        service_name="infisical",
        network_name=network,
        network_id=_digest(f"network:{network}".encode()),
        container_id=_container_identity(f"service:{number}"),
        workload_name=f"workload-{number}",
        image=_IMAGE,
        listener_binding="isolated_network_only"
        if restore
        else ("tls_lan" if tls else "loopback_only"),
        host_listener_port=None if restore else (443 if tls else 8080),
        isolated_network_alias="restore-infisical" if restore else None,
    )


def _cache(
    *, network: str, volume: str, namespace: str, reference: str, marker: str
) -> ValkeyIdentityV1:
    return ValkeyIdentityV1(
        compose_project=f"cache-project-{namespace}",
        service_name="valkey",
        network_name=network,
        network_id=_digest(f"network:{network}".encode()),
        volume_name=volume,
        volume_instance_fingerprint_sha256=_volume_instance_fingerprint(volume),
        container_id=_container_identity(f"valkey:{marker}"),
        workload_name=f"workload-{namespace}",
        logical_namespace=namespace,
        credential_reference_sha256=reference,
        image=_CACHE_IMAGE,
    )


def _proposal(*, tls: bool = False) -> ProposalV1:
    references = _references(tls=tls)
    authority = "https://198.51.100.31:443" if tls else "http://127.0.0.1:8080"
    candidate = CandidateCompositeV1(
        authority=authority,
        authority_sha256=_digest(authority.encode()),
        primary_service=_service(
            number=31, project="primary-project", network="primary-network", tls=tls
        ),
        restore_service=_service(
            number=32, project="restore-project", network="restore-network", restore=True
        ),
        postgres=PostgreSQLContractV1(
            authority="postgresql://192.0.2.40:5432",
            system_identifier="12345678",
            database_name="acceptance-db",
            database_oid=101,
            schema_name="acceptance-schema",
            owner_role="owner-role",
            role_names=("owner-role", "reader-role"),
            schema_fingerprint_sha256=_HASH,
            membership_fingerprint_sha256="c" * 64,
            database_acl_sha256="d" * 64,
            stage_database_prefix="stage-db",
            restore_database_prefix="restore-db",
        ),
        primary_valkey=_cache(
            network="primary-network",
            volume="primary-volume",
            namespace="primary-ns",
            reference=references.primary_valkey_password.reference_sha256,
            marker="3",
        ),
        restore_valkey=_cache(
            network="restore-network",
            volume="restore-volume",
            namespace="restore-ns",
            reference=references.restore_valkey_password.reference_sha256,
            marker="4",
        ),
    )
    return ProposalV1(
        schema_version="rsd.disposable-infisical-proposal.v1",
        operation_id="123e4567-e89b-42d3-a456-426614174000",
        source_commit=_COMMIT,
        transport=TransportContractV1(
            profile=(
                DisposableTransportProfile.TLS_VERIFIED
                if tls
                else DisposableTransportProfile.UNPUBLISHED_LOOPBACK_OR_NETWORK
            ),
            authority=authority,
            authority_sha256=_digest(authority.encode()),
            listener_binding="tls_lan" if tls else "loopback_only",
            host_listener_port=443 if tls else 8080,
            tls_trust_anchor_reference_sha256=(
                references.tls_trust_anchor.reference_sha256 if tls else None
            ),
            minimum_tls_version="TLSv1.3" if tls else None,
        ),
        candidate=candidate,
        primary_image=_IMAGE,
        restore_image=_IMAGE,
        provider_references=references,
        retention_expires_at="2030-01-01T00:00:00Z",
        disposal_owner="acceptance-owner",
        approval_reference_sha256="5" * 64,
        allocation_evidence=AllocationEvidenceBindingsV1(
            approval_sha256="0" * 64,
            governed_deny_sha256="1" * 64,
            governed_baseline_sha256="2" * 64,
            collision_evidence_sha256="3" * 64,
            registry_verification_sha256="4" * 64,
            provider_declaration_sha256="5" * 64,
            executor_control_policy_sha256="6" * 64,
            docker_engine_control_policy_sha256="7" * 64,
            postgres_control_policy_sha256="8" * 64,
            postgres_prepared_control_policy_sha256="9" * 64,
        ),
    )


def _write(root: Path, name: str, model: object) -> str:
    raw = yaml.safe_dump(model.model_dump(mode="json"), sort_keys=True).encode()  # type: ignore[union-attr]
    (root / name).write_bytes(raw)
    (root / name).chmod(0o600)
    return _digest(raw)


def _materials(
    root: Path,
    *,
    governed_collision: bool = False,
    target_database_oid: int | None = None,
    overlay_database_oid: int | None = None,
    provider_epoch: str = "snapshot-1",
) -> None:
    root.mkdir(mode=0o700)
    proposal = _proposal()
    subject = proposal_sha256(proposal)
    _write(root, "proposal.yaml", proposal)
    approval = ApprovalEvidenceV1(
        schema_version="rsd.disposable-approval.v1",
        authorization_subject_sha256=subject,
        approval_reference_sha256=proposal.approval_reference_sha256,
        source_commit=_COMMIT,
        issued_at="2026-08-28T11:50:00Z",
        expires_at="2026-08-28T12:10:00Z",
        approver_identity="approval-owner",
        proposal_authorized=True,
        execution_authorized=False,
        signature=_signature(),
    )
    collision = (
        proposal.candidate.stable()[0]
        if governed_collision
        else StableIdentifierV1(kind=StableIdentifierKind.WORKLOAD, value="unrelated-workload")
    )
    governed = GovernedBaselineV1(
        schema_version="rsd.disposable-governed-baseline.v1",
        authorization_subject_sha256=subject,
        source_commit=_COMMIT,
        signature=_signature(),
        identities=(
            GovernedIdentityV1(surface="governed_surface", stable_identifiers=(collision,)),
        ),
    )
    target = TargetAttestationV1(
        schema_version="rsd.disposable-target-attestation.v1",
        authorization_subject_sha256=subject,
        snapshot_epoch_id="snapshot-1",
        observed_at="2026-08-28T11:59:00Z",
        candidate_composite_sha256=canonical_sha256(proposal.candidate),
        postgres_database_oid=(
            proposal.candidate.postgres.database_oid
            if target_database_oid is None
            else target_database_oid
        ),
        signature=_signature(),
    )
    provider = ProviderDeclarationV1(
        schema_version="rsd.disposable-provider-declaration.v1",
        authorization_subject_sha256=subject,
        snapshot_epoch_id=provider_epoch,
        observed_at="2026-08-28T11:59:00Z",
        proof_source="offline-provider-reference-declaration-v1",
        signature=_signature(),
        references=proposal.provider_references.all(),
    )
    registry = RegistryVerificationV1(
        schema_version="rsd.disposable-registry-verification.v1",
        authorization_subject_sha256=subject,
        snapshot_epoch_id="snapshot-1",
        observed_at="2026-08-28T11:59:00Z",
        signature=_signature(),
        images=(
            RegistryImageVerificationV1(
                role="primary",
                image=_IMAGE,
                platform="linux/amd64",
                platform_digest=f"sha256:{'6' * 64}",
            ),
            RegistryImageVerificationV1(
                role="restore",
                image=_IMAGE,
                platform="linux/amd64",
                platform_digest=f"sha256:{'7' * 64}",
            ),
        ),
    )
    overlay = PostgreSQLAcceptanceOverlayV1(
        schema_version="rsd.postgres-acceptance-overlay.v1",
        database_name="acceptance-db",
        database_oid=101 if overlay_database_oid is None else overlay_database_oid,
        owner_role="owner-role",
        secret_provider_kind="infisical",
        secret_project="acceptance-project",
        secret_environment="test",
        secret_path="/rsd/acceptance",
    )
    hashes = {
        "approval": _write(root, "approval.yaml", approval),
        "governed": _write(root, "governed-baseline.yaml", governed),
        "target": _write(root, "target-attestation.yaml", target),
        "provider": _write(root, "provider-declaration.yaml", provider),
        "registry": _write(root, "registry-verification.yaml", registry),
        "overlay": _write(root, "postgres-overlay.yaml", overlay),
    }
    contract = RuntimeContractV1(
        **proposal.model_dump(mode="python"),
        proposal_sha256=subject,
        evidence=EvidenceBindingsV1(
            approval_sha256=hashes["approval"],
            governed_baseline_sha256=hashes["governed"],
            target_attestation_sha256=hashes["target"],
            provider_declaration_sha256=hashes["provider"],
            registry_verification_sha256=hashes["registry"],
            postgres_overlay_sha256=hashes["overlay"],
        ),
    )
    _write(root, "runtime-contract.yaml", contract)


def test_phase_a_compiles_value_free_non_authorizing_receipt(tmp_path: Path) -> None:
    root = tmp_path / "artifacts"
    _materials(root)
    receipt = compile_preflight(PreflightPaths(root=root), now=_NOW)
    assert receipt.status == "compiled"
    assert receipt.authorization_state == "not_authorized_pending_live_provenance"
    assert len(receipt.evidence_sha256) == 6


def test_phase_a_governed_collision_blocks(tmp_path: Path) -> None:
    root = tmp_path / "artifacts"
    _materials(root, governed_collision=True)
    with pytest.raises(DisposablePreflightError, match="governed_identity"):
        compile_preflight(PreflightPaths(root=root), now=_NOW)


def test_phase_a_reader_rejects_non_owner_only_artifact(tmp_path: Path) -> None:
    root = tmp_path / "artifacts"
    _materials(root)
    (root / "proposal.yaml").chmod(0o644)
    with pytest.raises(DisposablePreflightError, match="owner_only_input"):
        compile_preflight(PreflightPaths(root=root), now=_NOW)


def test_phase_a_content_addressed_overlay_tampering_blocks(tmp_path: Path) -> None:
    root = tmp_path / "artifacts"
    _materials(root)
    overlay = root / "postgres-overlay.yaml"
    overlay.write_text(
        overlay.read_text(encoding="utf-8").replace("acceptance-project", "changed-project"),
        encoding="utf-8",
    )
    overlay.chmod(0o600)
    with pytest.raises(DisposablePreflightError, match="evidence_binding"):
        compile_preflight(PreflightPaths(root=root), now=_NOW)


def test_phase_a_duplicate_yaml_key_blocks_before_model_coercion(tmp_path: Path) -> None:
    root = tmp_path / "artifacts"
    _materials(root)
    proposal = root / "proposal.yaml"
    proposal.write_text(
        "schema_version: rsd.disposable-infisical-proposal.v1\n"
        "schema_version: rsd.disposable-infisical-proposal.v1\n",
        encoding="utf-8",
    )
    proposal.chmod(0o600)
    with pytest.raises(DisposablePreflightError, match="proposal"):
        compile_preflight(PreflightPaths(root=root), now=_NOW)


def test_phase_a_candidate_rejects_shared_restore_cache_volume() -> None:
    candidate = _proposal().candidate
    raw = candidate.model_dump(mode="python")
    raw["restore_valkey"] = {
        **candidate.restore_valkey.model_dump(mode="python"),
        "volume_name": candidate.primary_valkey.volume_name,
        "volume_instance_fingerprint_sha256": (
            candidate.primary_valkey.volume_instance_fingerprint_sha256
        ),
    }
    with pytest.raises(ValueError, match="primary and restore Valkey storage must be distinct"):
        CandidateCompositeV1.model_validate(raw)


def test_phase_a_candidate_rejects_service_cache_identity_collision() -> None:
    candidate = _proposal().candidate
    raw = candidate.model_dump(mode="python")
    cache = candidate.primary_valkey.model_dump(mode="python")
    cache["container_id"] = candidate.primary_service.container_id
    raw["primary_valkey"] = cache
    with pytest.raises(ValueError, match="all component container identities"):
        CandidateCompositeV1.model_validate(raw)


def test_phase_a_candidate_rejects_cross_pair_network_identity_collision() -> None:
    candidate = _proposal().candidate
    raw = candidate.model_dump(mode="python")
    cache = candidate.restore_valkey.model_dump(mode="python")
    cache["network_id"] = candidate.primary_service.network_id
    raw["restore_valkey"] = cache
    with pytest.raises(ValueError, match="distinct shared networks"):
        CandidateCompositeV1.model_validate(raw)


def test_phase_a_candidate_rejects_restore_service_publication() -> None:
    candidate = _proposal(tls=True).candidate
    raw = candidate.model_dump(mode="python")
    raw["restore_service"] = {
        **candidate.restore_service.model_dump(mode="python"),
        "authority": candidate.authority,
        "authority_sha256": candidate.authority_sha256,
        "listener_binding": "tls_lan",
        "host_listener_port": 443,
        "isolated_network_alias": None,
    }
    with pytest.raises(ValueError, match="restore service must be unpublished and isolated"):
        CandidateCompositeV1.model_validate(raw)


def test_phase_a_proposal_rejects_transport_authority_mismatch() -> None:
    proposal = _proposal(tls=True)
    authority = "https://198.51.100.39:443"
    raw = proposal.model_dump(mode="python")
    raw["transport"] = TransportContractV1(
        profile=DisposableTransportProfile.TLS_VERIFIED,
        authority=authority,
        authority_sha256=_digest(authority.encode()),
        listener_binding="tls_lan",
        host_listener_port=443,
        tls_trust_anchor_reference_sha256=proposal.provider_references.tls_trust_anchor.reference_sha256,  # type: ignore[union-attr]
        minimum_tls_version="TLSv1.3",
    )
    with pytest.raises(ValueError, match="transport must bind primary candidate service"):
        ProposalV1.model_validate(raw)


def test_phase_a_proposal_rejects_loopback_claim_over_tls_candidate() -> None:
    proposal = _proposal(tls=True)
    raw = proposal.model_dump(mode="python")
    refs = proposal.provider_references.model_dump(mode="python")
    refs["tls_trust_anchor"] = None
    raw["provider_references"] = ProviderReferencesV2.model_validate(refs)
    raw["transport"] = TransportContractV1(
        profile=DisposableTransportProfile.UNPUBLISHED_LOOPBACK_OR_NETWORK,
        authority="http://127.0.0.1:8080",
        authority_sha256=_digest(b"http://127.0.0.1:8080"),
        listener_binding="loopback_only",
        host_listener_port=8080,
    )
    with pytest.raises(ValueError, match="transport must bind primary candidate service"):
        ProposalV1.model_validate(raw)


@pytest.mark.parametrize("authority", ("http://8.8.8.8:8080", "http://service.example.test:8080"))
def test_phase_a_unpublished_network_transport_rejects_external_or_dns(authority: str) -> None:
    with pytest.raises(ValueError):
        TransportContractV1(
            profile=DisposableTransportProfile.UNPUBLISHED_LOOPBACK_OR_NETWORK,
            authority=authority,
            authority_sha256=_digest(authority.encode()),
            listener_binding="isolated_network_only",
            isolated_network_name="isolated-network",
            isolated_network_alias="internal-service",
        )


def test_phase_a_accepts_candidate_bound_internal_network_transport() -> None:
    proposal = _proposal()
    authority = "http://198.51.100.41:8080"
    candidate = proposal.candidate.model_dump(mode="python")
    candidate["authority"] = authority
    candidate["authority_sha256"] = _digest(authority.encode())
    candidate["primary_service"] = {
        **proposal.candidate.primary_service.model_dump(mode="python"),
        "authority": authority,
        "authority_sha256": _digest(authority.encode()),
        "listener_binding": "isolated_network_only",
        "host_listener_port": None,
        "isolated_network_alias": "primary-internal",
    }
    refs = proposal.provider_references.model_dump(mode="python")
    refs["tls_trust_anchor"] = None
    raw = proposal.model_dump(mode="python")
    raw["candidate"] = CandidateCompositeV1.model_validate(candidate)
    raw["provider_references"] = ProviderReferencesV2.model_validate(refs)
    raw["transport"] = TransportContractV1(
        profile=DisposableTransportProfile.UNPUBLISHED_LOOPBACK_OR_NETWORK,
        authority=authority,
        authority_sha256=_digest(authority.encode()),
        listener_binding="isolated_network_only",
        isolated_network_name="primary-network",
        isolated_network_alias="primary-internal",
    )
    assert ProposalV1.model_validate(raw).transport.isolated_network_alias == "primary-internal"


def test_phase_a_postgres_identity_requires_positive_oid() -> None:
    raw = _proposal().candidate.postgres.model_dump(mode="python")
    raw["database_oid"] = 0
    with pytest.raises(ValueError, match="database_oid"):
        PostgreSQLContractV1.model_validate(raw)


def test_phase_a_final_contract_rejects_oid_replay_tampering() -> None:
    proposal = _proposal()
    candidate = proposal.candidate.model_dump(mode="python")
    candidate["postgres"] = {**candidate["postgres"], "database_oid": 102}
    raw = proposal.model_dump(mode="python")
    raw["candidate"] = CandidateCompositeV1.model_validate(candidate)
    with pytest.raises(ValueError, match="runtime contract does not bind proposal"):
        RuntimeContractV1(
            **raw,
            proposal_sha256=proposal_sha256(proposal),
            evidence=EvidenceBindingsV1(
                approval_sha256="0" * 64,
                governed_baseline_sha256="1" * 64,
                target_attestation_sha256="2" * 64,
                provider_declaration_sha256="3" * 64,
                registry_verification_sha256="4" * 64,
                postgres_overlay_sha256="5" * 64,
            ),
        )


def test_phase_a_target_and_overlay_oid_are_revalidated(tmp_path: Path) -> None:
    target_root = tmp_path / "target-oid"
    _materials(target_root, target_database_oid=102)
    with pytest.raises(DisposablePreflightError, match="target_attestation"):
        compile_preflight(PreflightPaths(root=target_root), now=_NOW)
    overlay_root = tmp_path / "overlay-oid"
    _materials(overlay_root, overlay_database_oid=102)
    with pytest.raises(DisposablePreflightError, match="postgres_overlay"):
        compile_preflight(PreflightPaths(root=overlay_root), now=_NOW)


def test_phase_a_provider_snapshot_epoch_replay_is_rejected(tmp_path: Path) -> None:
    root = tmp_path / "replayed-provider"
    _materials(root, provider_epoch="snapshot-replayed")
    with pytest.raises(DisposablePreflightError, match="provider_declaration"):
        compile_preflight(PreflightPaths(root=root), now=_NOW)


def test_phase_a_transport_rejects_cleartext_published_address() -> None:
    authority = "http://198.51.100.77:8080"
    with pytest.raises(ValueError, match="transport profile is unsafe"):
        TransportContractV1(
            profile=DisposableTransportProfile.UNPUBLISHED_LOOPBACK_OR_NETWORK,
            authority=authority,
            authority_sha256=_digest(authority.encode()),
            listener_binding="isolated_network_only",
            host_listener_port=8080,
            isolated_network_name="isolated-network",
        )


def test_phase_a_cli_blocks_without_creating_artifacts(
    tmp_path: Path, capsys: pytest.CaptureFixture[str]
) -> None:
    root = tmp_path / "missing"
    root.mkdir(mode=0o700)
    assert main(["preflight", "--root", str(root)]) == 2
    assert '"status":"blocked"' in capsys.readouterr().out
    assert list(root.iterdir()) == []
