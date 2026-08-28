"""Adversarial tests for the public, offline disposable acceptance compiler."""

from __future__ import annotations

import hashlib
from datetime import UTC, datetime
from pathlib import Path

import pytest
import yaml

from omninode_rsd.lifecycle.infisical_disposable import (
    ApprovalEvidenceV1,
    CandidateCompositeV1,
    DetachedSignatureV1,
    DisposablePreflightError,
    DisposableTransportProfile,
    EvidenceBindingsV1,
    GovernedBaselineV1,
    GovernedIdentityV1,
    ImageReferenceV1,
    PostgreSQLAcceptanceOverlayV1,
    PostgreSQLContractV1,
    PreflightPaths,
    ProposalV1,
    ProviderDeclarationV1,
    ProviderReferencesV1,
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
    main,
    proposal_sha256,
)

_NOW = datetime(2026, 8, 27, 12, 0, tzinfo=UTC)
_COMMIT = "a" * 40
_HASH = "b" * 64
_IMAGE = ImageReferenceV1(reference=f"registry.example.test/infisical@sha256:{'c' * 64}")
_CACHE_IMAGE = ImageReferenceV1(reference=f"registry.example.test/valkey@sha256:{'d' * 64}")


def _digest(data: bytes) -> str:
    return hashlib.sha256(data).hexdigest()


def _signature() -> DetachedSignatureV1:
    return DetachedSignatureV1(
        algorithm="ed25519-detached-v1",
        signer_key_id="test-signer",
        signer_public_key_fingerprint_sha256="1" * 64,
        detached_signature_sha256="2" * 64,
    )


def _reference(name: str, version: int) -> ProviderReferenceV1:
    data = {
        "account": f"account-{name}",
        "provider": "metadata-provider",
        "service": f"service-{name}",
        "version": version,
    }
    return ProviderReferenceV1(
        **data,
        reference_sha256=_digest(
            __import__("json").dumps(data, sort_keys=True, separators=(",", ":")).encode()
        ),
    )


def _provider_references() -> ProviderReferencesV1:
    return ProviderReferencesV1(
        commitment_hmac=_reference("commitment", 1),
        backup_encryption=_reference("backup", 1),
        encryption_key=_reference("encryption", 1),
        auth_secret=_reference("auth", 1),
        primary_valkey_password=_reference("primary-cache", 1),
        restore_valkey_password=_reference("restore-cache", 1),
        tls_trust_anchor=_reference("trust", 1),
    )


def _service(
    *, number: int, project: str, network: str, restore: bool = False
) -> ServiceIdentityV1:
    authority = None
    if not restore:
        authority = "https://" + ".".join(("198", "51", "100", str(number))) + ":443"
    container_char = "a" if number == 31 else "b"
    return ServiceIdentityV1(
        authority=authority,
        authority_sha256=None if authority is None else _digest(authority.encode()),
        machine_id=f"machine-{number}",
        compose_project=project,
        service_name="infisical",
        network_id=network,
        container_id=container_char * 64,
        workload_id=f"workload-{number}",
        image=_IMAGE,
        listener_binding="isolated_network_only" if restore else "tls_lan",
        host_listener_port=None if restore else 443,
        isolated_network_alias="restore-infisical" if restore else None,
    )


def _cache(
    *, project: str, network: str, volume: str, namespace: str, reference: str, char: str
) -> ValkeyIdentityV1:
    return ValkeyIdentityV1(
        compose_project=project,
        service_name="valkey",
        network_id=network,
        volume_id=volume,
        container_id=char * 64,
        workload_id=f"workload-{namespace}",
        logical_namespace=namespace,
        credential_reference_sha256=reference,
        image=_CACHE_IMAGE,
    )


def _proposal() -> ProposalV1:
    references = _provider_references()
    authority = "https://198.51.100.31:443"
    candidate = CandidateCompositeV1(
        authority=authority,
        authority_sha256=_digest(authority.encode()),
        primary_service=_service(number=31, project="primary-project", network="primary-network"),
        restore_service=_service(
            number=32, project="restore-project", network="restore-network", restore=True
        ),
        postgres=PostgreSQLContractV1(
            authority="postgresql://192.0.2.40:5432",
            system_identifier="12345678",
            database_name="rsdacceptance",
            database_oid=101,
            owner_role="rsdowner",
            schema_fingerprint_sha256=_HASH,
            membership_fingerprint_sha256=_HASH,
            database_acl_sha256=_HASH,
            stage_database_prefix="rsdstage",
            restore_database_prefix="rsdrestore",
        ),
        primary_valkey=_cache(
            project="primary-cache-project",
            network="primary-cache-network",
            volume="primary-volume",
            namespace="primary-ns",
            reference=references.primary_valkey_password.reference_sha256,
            char="3",
        ),
        restore_valkey=_cache(
            project="restore-cache-project",
            network="restore-cache-network",
            volume="restore-volume",
            namespace="restore-ns",
            reference=references.restore_valkey_password.reference_sha256,
            char="4",
        ),
    )
    return ProposalV1(
        schema_version="rsd.disposable-infisical-proposal.v1",
        operation_id="123e4567-e89b-42d3-a456-426614174000",
        source_commit=_COMMIT,
        transport=TransportContractV1(
            profile=DisposableTransportProfile.TLS_VERIFIED,
            authority=authority,
            authority_sha256=_digest(authority.encode()),
            listener_binding="tls_lan",
            host_listener_port=443,
            tls_trust_anchor_reference_sha256=references.tls_trust_anchor.reference_sha256,
            minimum_tls_version="TLSv1.3",
        ),
        candidate=candidate,
        primary_image=_IMAGE,
        restore_image=_IMAGE,
        provider_references=references,
        retention_expires_at="2030-01-01T00:00:00Z",
        disposal_owner="acceptance-owner",
        approval_reference_sha256="5" * 64,
    )


def _write(path: Path, name: str, model: object) -> str:
    raw = yaml.safe_dump(model.model_dump(mode="json"), sort_keys=True).encode()  # type: ignore[union-attr]
    (path / name).write_bytes(raw)
    (path / name).chmod(0o600)
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
        issued_at="2026-08-27T11:50:00Z",
        expires_at="2026-08-27T12:10:00Z",
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
        observed_at="2026-08-27T11:59:00Z",
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
        observed_at="2026-08-27T11:59:00Z",
        proof_source="offline-provider-reference-declaration-v1",
        signature=_signature(),
        references=proposal.provider_references.all(),
    )
    registry = RegistryVerificationV1(
        schema_version="rsd.disposable-registry-verification.v1",
        authorization_subject_sha256=subject,
        snapshot_epoch_id="snapshot-1",
        observed_at="2026-08-27T11:59:00Z",
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
        database_name="rsdacceptance",
        database_oid=101 if overlay_database_oid is None else overlay_database_oid,
        owner_role="rsdowner",
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


def test_compiles_non_authorizing_value_free_receipt(tmp_path: Path) -> None:
    root = tmp_path / "artifacts"
    _materials(root)

    receipt = compile_preflight(PreflightPaths(root=root), now=_NOW)

    assert receipt.status == "compiled"
    assert receipt.authorization_state == "not_authorized_pending_live_provenance"
    assert len(receipt.evidence_sha256) == 6


def test_governed_composite_match_denies_even_on_shared_host(tmp_path: Path) -> None:
    root = tmp_path / "artifacts"
    _materials(root, governed_collision=True)

    with pytest.raises(DisposablePreflightError, match="governed_identity"):
        compile_preflight(PreflightPaths(root=root), now=_NOW)


def test_reader_rejects_non_owner_only_artifact(tmp_path: Path) -> None:
    root = tmp_path / "artifacts"
    _materials(root)
    (root / "proposal.yaml").chmod(0o644)

    with pytest.raises(DisposablePreflightError, match="owner_only_input"):
        compile_preflight(PreflightPaths(root=root), now=_NOW)


def test_content_addressed_overlay_tampering_is_rejected(tmp_path: Path) -> None:
    root = tmp_path / "artifacts"
    _materials(root)
    overlay_path = root / "postgres-overlay.yaml"
    overlay_path.write_text(
        overlay_path.read_text(encoding="utf-8").replace("acceptance-project", "changed-project"),
        encoding="utf-8",
    )
    overlay_path.chmod(0o600)

    with pytest.raises(DisposablePreflightError, match="evidence_binding"):
        compile_preflight(PreflightPaths(root=root), now=_NOW)


def test_duplicate_yaml_key_is_rejected_before_model_coercion(tmp_path: Path) -> None:
    root = tmp_path / "artifacts"
    _materials(root)
    proposal_path = root / "proposal.yaml"
    proposal_path.write_text(
        "schema_version: rsd.disposable-infisical-proposal.v1\n"
        "schema_version: rsd.disposable-infisical-proposal.v1\n",
        encoding="utf-8",
    )
    proposal_path.chmod(0o600)

    with pytest.raises(DisposablePreflightError, match="proposal"):
        compile_preflight(PreflightPaths(root=root), now=_NOW)


def test_candidate_rejects_shared_restore_valkey_volume() -> None:
    candidate = _proposal().candidate
    raw = candidate.model_dump(mode="python")
    raw["restore_valkey"] = candidate.primary_valkey

    with pytest.raises(ValueError, match="all component container identities"):
        CandidateCompositeV1.model_validate(raw)


@pytest.mark.parametrize("field", ("container_id", "network_id", "workload_id"))
def test_candidate_rejects_service_to_valkey_identity_collision(field: str) -> None:
    candidate = _proposal().candidate
    raw = candidate.model_dump(mode="python")
    colliding_valkey = candidate.primary_valkey.model_dump(mode="python")
    colliding_valkey[field] = getattr(candidate.primary_service, field)
    raw["primary_valkey"] = colliding_valkey

    with pytest.raises(ValueError, match=f"all component {field.removesuffix('_id')} identities"):
        CandidateCompositeV1.model_validate(raw)


def test_candidate_rejects_restore_service_published_authority() -> None:
    candidate = _proposal().candidate
    raw = candidate.model_dump(mode="python")
    published_restore = candidate.restore_service.model_dump(mode="python")
    published_restore.update(
        {
            "authority": candidate.authority,
            "authority_sha256": candidate.authority_sha256,
            "listener_binding": "tls_lan",
            "host_listener_port": 443,
            "isolated_network_alias": None,
        }
    )
    raw["restore_service"] = published_restore

    with pytest.raises(ValueError, match="restore service must be unpublished and isolated"):
        CandidateCompositeV1.model_validate(raw)


def test_proposal_rejects_transport_authority_mismatch_with_primary_candidate() -> None:
    proposal = _proposal()
    authority = "https://" + ".".join(("198", "51", "100", "39")) + ":443"
    raw = proposal.model_dump(mode="python")
    raw["transport"] = TransportContractV1(
        profile=DisposableTransportProfile.TLS_VERIFIED,
        authority=authority,
        authority_sha256=_digest(authority.encode()),
        listener_binding="tls_lan",
        host_listener_port=443,
        tls_trust_anchor_reference_sha256=(
            proposal.provider_references.tls_trust_anchor.reference_sha256
        ),
        minimum_tls_version="TLSv1.3",
    )

    with pytest.raises(ValueError, match="transport must bind primary candidate service"):
        ProposalV1.model_validate(raw)


def test_proposal_rejects_claimed_loopback_when_candidate_is_tls_lan() -> None:
    proposal = _proposal()
    references = proposal.provider_references.model_dump(mode="python")
    references["tls_trust_anchor"] = None
    raw = proposal.model_dump(mode="python")
    raw["provider_references"] = ProviderReferencesV1.model_validate(references)
    raw["transport"] = TransportContractV1(
        profile=DisposableTransportProfile.UNPUBLISHED_LOOPBACK_OR_NETWORK,
        authority="http://127.0.0.1:8080",
        authority_sha256=_digest(b"http://127.0.0.1:8080"),
        listener_binding="loopback_only",
        host_listener_port=8080,
    )

    with pytest.raises(ValueError, match="transport must bind primary candidate service"):
        ProposalV1.model_validate(raw)


def test_unpublished_network_transport_rejects_external_address_and_dns() -> None:
    external_authority = "http://" + ".".join(("8", "8", "8", "8")) + ":8080"
    for authority in (external_authority, "http://service.example.test:8080"):
        with pytest.raises(ValueError):
            TransportContractV1(
                profile=DisposableTransportProfile.UNPUBLISHED_LOOPBACK_OR_NETWORK,
                authority=authority,
                authority_sha256=_digest(authority.encode()),
                listener_binding="isolated_network_only",
                isolated_network_id="isolated-network",
                isolated_network_alias="internal-service",
            )


def test_proposal_accepts_candidate_bound_internal_network_transport() -> None:
    proposal = _proposal()
    authority = "http://" + ".".join(("198", "51", "100", "41")) + ":8080"
    candidate_raw = proposal.candidate.model_dump(mode="python")
    primary_raw = proposal.candidate.primary_service.model_dump(mode="python")
    primary_raw.update(
        {
            "authority": authority,
            "authority_sha256": _digest(authority.encode()),
            "listener_binding": "isolated_network_only",
            "host_listener_port": None,
            "isolated_network_alias": "primary-internal",
        }
    )
    candidate_raw["authority"] = authority
    candidate_raw["authority_sha256"] = _digest(authority.encode())
    candidate_raw["primary_service"] = primary_raw
    references_raw = proposal.provider_references.model_dump(mode="python")
    references_raw["tls_trust_anchor"] = None
    raw = proposal.model_dump(mode="python")
    raw["candidate"] = CandidateCompositeV1.model_validate(candidate_raw)
    raw["provider_references"] = ProviderReferencesV1.model_validate(references_raw)
    raw["transport"] = TransportContractV1(
        profile=DisposableTransportProfile.UNPUBLISHED_LOOPBACK_OR_NETWORK,
        authority=authority,
        authority_sha256=_digest(authority.encode()),
        listener_binding="isolated_network_only",
        isolated_network_id="primary-network",
        isolated_network_alias="primary-internal",
    )

    assert ProposalV1.model_validate(raw).transport.isolated_network_alias == "primary-internal"


def test_postgres_identity_requires_positive_oid() -> None:
    raw = _proposal().candidate.postgres.model_dump(mode="python")
    raw["database_oid"] = 0

    with pytest.raises(ValueError, match="database_oid"):
        PostgreSQLContractV1.model_validate(raw)


def test_final_contract_rejects_postgres_oid_replay_tampering() -> None:
    proposal = _proposal()
    candidate_raw = proposal.candidate.model_dump(mode="python")
    postgres_raw = proposal.candidate.postgres.model_dump(mode="python")
    postgres_raw["database_oid"] = 102
    candidate_raw["postgres"] = postgres_raw
    raw = proposal.model_dump(mode="python")
    raw["candidate"] = CandidateCompositeV1.model_validate(candidate_raw)

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


def test_target_database_oid_and_overlay_oid_are_revalidated(tmp_path: Path) -> None:
    target_root = tmp_path / "target-oid"
    _materials(target_root, target_database_oid=102)

    with pytest.raises(DisposablePreflightError, match="target_attestation"):
        compile_preflight(PreflightPaths(root=target_root), now=_NOW)

    overlay_root = tmp_path / "overlay-oid"
    _materials(overlay_root, overlay_database_oid=102)

    with pytest.raises(DisposablePreflightError, match="postgres_overlay"):
        compile_preflight(PreflightPaths(root=overlay_root), now=_NOW)


def test_provider_snapshot_replay_is_rejected(tmp_path: Path) -> None:
    root = tmp_path / "replayed-provider"
    _materials(root, provider_epoch="snapshot-replayed")

    with pytest.raises(DisposablePreflightError, match="provider_declaration"):
        compile_preflight(PreflightPaths(root=root), now=_NOW)


def test_transport_rejects_cleartext_published_lan() -> None:
    authority = "http://198.51.100.77:8080"

    with pytest.raises(ValueError, match="transport profile is unsafe"):
        TransportContractV1(
            profile=DisposableTransportProfile.UNPUBLISHED_LOOPBACK_OR_NETWORK,
            authority=authority,
            authority_sha256=_digest(authority.encode()),
            listener_binding="isolated_network_only",
            host_listener_port=8080,
            isolated_network_id="isolated-network",
        )


def test_cli_blocks_without_creating_artifacts(
    tmp_path: Path, capsys: pytest.CaptureFixture[str]
) -> None:
    root = tmp_path / "missing"
    root.mkdir(mode=0o700)

    assert main(["preflight", "--root", str(root)]) == 2

    output = capsys.readouterr().out
    assert '"status":"blocked"' in output
    assert list(root.iterdir()) == []
