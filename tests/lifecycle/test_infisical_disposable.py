"""Adversarial tests for the public, offline disposable acceptance compiler."""

from __future__ import annotations

import base64
import hashlib
import inspect
import os
import sqlite3
import traceback
from collections.abc import Callable, Mapping
from concurrent.futures import ThreadPoolExecutor
from datetime import UTC, datetime
from pathlib import Path
from threading import Event

import pytest
import yaml
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey

from omninode_rsd.lifecycle.authorization import (
    _TEST_CLOCK_CAPABILITY,
    ArtifactRootLease,
    AuthorizationError,
    AuthorizationPaths,
    EffectReceiptV1,
    ExecutionReceiptV1,
    JournalMigrationStatus,
    ProviderProvenance,
    SQLiteAuthorizationJournal,
    TrustedEd25519SignerV1,
    VerifiedExecutionContext,
    _authorize_and_execute_for_test,
    _canonical_signed_content,
    _signature_message,
    authorize_and_execute,
)
from omninode_rsd.lifecycle.authorization import (
    main as authorization_main,
)
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


class _Provider:
    def __init__(
        self,
        fingerprints: Mapping[str, str],
        *,
        mutate_artifact: Path | None = None,
        mutate_provider: bool = False,
    ) -> None:
        self._fingerprints = fingerprints
        self._mutate_artifact = mutate_artifact
        self._mutate_provider = mutate_provider
        self._mutated = False
        self._references: tuple[ProviderReferenceV1, ...] = ()

    def acquire(self, references: tuple[ProviderReferenceV1, ...]) -> _Provider:
        self._references = references
        return self

    def __enter__(self) -> _Provider:
        return self

    def __exit__(self, exception_type: object, exception: object, traceback: object) -> None:
        del exception_type, exception, traceback

    def inspect(self, reference: ProviderReferenceV1) -> ProviderProvenance | None:
        if self._mutate_artifact is not None and not self._mutated:
            self._mutate_artifact.write_text(
                self._mutate_artifact.read_text(encoding="utf-8") + "\n", encoding="utf-8"
            )
            self._mutate_artifact.chmod(0o600)
            self._mutated = True
        return ProviderProvenance(
            provider=reference.provider,
            service=reference.service,
            account=reference.account,
            version=reference.version,
            reference_sha256=reference.reference_sha256,
            fingerprint_sha256=self._fingerprints[reference.reference_sha256],
        )

    def recheck(self, reference: ProviderReferenceV1) -> ProviderProvenance | None:
        fingerprint = self._fingerprints[reference.reference_sha256]
        if self._mutate_provider and not self._mutated:
            self._mutated = True
            fingerprint = "0" * 64 if fingerprint != "0" * 64 else "1" * 64
        return ProviderProvenance(
            provider=reference.provider,
            service=reference.service,
            account=reference.account,
            version=reference.version,
            reference_sha256=reference.reference_sha256,
            fingerprint_sha256=fingerprint,
        )


def _authorize_materials(
    root: Path,
) -> tuple[TrustedEd25519SignerV1, dict[str, str], Ed25519PrivateKey]:
    """Create value-free sidecars after Phase-A materials have been compiled."""

    _materials(root)
    key = Ed25519PrivateKey.generate()
    public = key.public_key().public_bytes_raw()
    signer = TrustedEd25519SignerV1(
        key_id="test-signer",
        public_key_base64=base64.b64encode(public).decode(),
        public_key_fingerprint_sha256=_digest(public),
    )
    evidence_names = (
        "approval.yaml",
        "governed-baseline.yaml",
        "target-attestation.yaml",
        "provider-declaration.yaml",
        "registry-verification.yaml",
    )
    for name in evidence_names:
        raw = yaml.safe_load((root / name).read_text(encoding="utf-8"))
        assert type(raw) is dict
        signature = raw["signature"]
        assert type(signature) is dict
        signature["signer_key_id"] = signer.key_id
        signature["signer_public_key_fingerprint_sha256"] = signer.public_key_fingerprint_sha256
        (root / name).write_bytes(yaml.safe_dump(raw, sort_keys=True).encode())
        (root / name).chmod(0o600)
    artifact_names = (
        "proposal.yaml",
        "runtime-contract.yaml",
        "approval.yaml",
        "governed-baseline.yaml",
        "target-attestation.yaml",
        "provider-declaration.yaml",
        "registry-verification.yaml",
        "postgres-overlay.yaml",
    )
    signatures: dict[str, bytes] = {}
    for name in evidence_names:
        content = (root / name).read_bytes()
        signed_content_sha256 = _digest(_canonical_signed_content(name, content))
        signature = key.sign(_signature_message(name, signed_content_sha256))
        signatures[name] = signature
        raw = yaml.safe_load(content)
        assert type(raw) is dict
        marker = raw["signature"]
        assert type(marker) is dict
        marker["detached_signature_sha256"] = _digest(signature)
        (root / name).write_bytes(yaml.safe_dump(raw, sort_keys=True).encode())
        (root / name).chmod(0o600)
    contract = yaml.safe_load((root / "runtime-contract.yaml").read_text(encoding="utf-8"))
    assert type(contract) is dict
    evidence = contract["evidence"]
    assert type(evidence) is dict
    for name, field in (
        ("approval.yaml", "approval_sha256"),
        ("governed-baseline.yaml", "governed_baseline_sha256"),
        ("target-attestation.yaml", "target_attestation_sha256"),
        ("provider-declaration.yaml", "provider_declaration_sha256"),
        ("registry-verification.yaml", "registry_verification_sha256"),
        ("postgres-overlay.yaml", "postgres_overlay_sha256"),
    ):
        evidence[field] = _digest((root / name).read_bytes())
    (root / "runtime-contract.yaml").write_bytes(yaml.safe_dump(contract, sort_keys=True).encode())
    (root / "runtime-contract.yaml").chmod(0o600)
    for name in artifact_names:
        content = (root / name).read_bytes()
        artifact_sha256 = _digest((root / name).read_bytes())
        signed_content_sha256 = _digest(_canonical_signed_content(name, content))
        signature = signatures.get(name, key.sign(_signature_message(name, signed_content_sha256)))
        sidecar = {
            "algorithm": "ed25519",
            "artifact_name": name,
            "artifact_sha256": artifact_sha256,
            "schema_version": "rsd.authorization-signature.v3",
            "signature_base64": base64.b64encode(signature).decode(),
            "signer_key_id": signer.key_id,
            "signed_content_sha256": signed_content_sha256,
        }
        target = root / AuthorizationPaths.signature_name(name)
        target.write_bytes(yaml.safe_dump(sidecar, sort_keys=True).encode())
        target.chmod(0o600)
    fingerprints = {
        reference.reference_sha256: _digest(f"fingerprint:{index}".encode())
        for index, reference in enumerate(_proposal().provider_references.all())
    }
    return signer, fingerprints, key


def _refresh_contract_evidence_hashes(root: Path) -> None:
    contract = yaml.safe_load((root / "runtime-contract.yaml").read_text(encoding="utf-8"))
    assert type(contract) is dict
    evidence = contract["evidence"]
    assert type(evidence) is dict
    for name, field in (
        ("approval.yaml", "approval_sha256"),
        ("governed-baseline.yaml", "governed_baseline_sha256"),
        ("target-attestation.yaml", "target_attestation_sha256"),
        ("provider-declaration.yaml", "provider_declaration_sha256"),
        ("registry-verification.yaml", "registry_verification_sha256"),
        ("postgres-overlay.yaml", "postgres_overlay_sha256"),
    ):
        evidence[field] = _digest((root / name).read_bytes())
    (root / "runtime-contract.yaml").write_bytes(yaml.safe_dump(contract, sort_keys=True).encode())
    (root / "runtime-contract.yaml").chmod(0o600)


def _refresh_sidecar(root: Path, name: str, key: Ed25519PrivateKey, *, resign: bool) -> None:
    target = root / AuthorizationPaths.signature_name(name)
    sidecar = yaml.safe_load(target.read_text(encoding="utf-8"))
    assert type(sidecar) is dict
    content = (root / name).read_bytes()
    signed_content_sha256 = _digest(_canonical_signed_content(name, content))
    sidecar["artifact_sha256"] = _digest(content)
    sidecar["signed_content_sha256"] = signed_content_sha256
    if resign:
        sidecar["signature_base64"] = base64.b64encode(
            key.sign(_signature_message(name, signed_content_sha256))
        ).decode()
    target.write_bytes(yaml.safe_dump(sidecar, sort_keys=True).encode())
    target.chmod(0o600)


def _journal(tmp_path: Path) -> SQLiteAuthorizationJournal:
    root = tmp_path / "journal"
    root.mkdir(mode=0o700, exist_ok=True)
    root.chmod(0o700)
    return SQLiteAuthorizationJournal(root / "authorization.sqlite3")


def _root_lock_path(root: Path) -> Path:
    canonical = root.resolve(strict=True)
    return canonical.parent / f".rsd-authorization-root-{_digest(os.fsencode(str(canonical)))}.lock"


def _effect(context: VerifiedExecutionContext) -> EffectReceiptV1:
    assert not hasattr(context, "root")
    return EffectReceiptV1(
        schema_version="rsd.lifecycle-effect-receipt.v1",
        operation_id=context.operation_id,
        idempotency_key=context.idempotency_key,
        effect_receipt_sha256="f" * 64,
    )


def _execute_for_test(
    paths: AuthorizationPaths,
    *,
    signer: TrustedEd25519SignerV1,
    provider: _Provider,
    provider_fingerprints: Mapping[str, str],
    expected_disposal_owner: str,
    expected_approver_identity: str,
    journal: SQLiteAuthorizationJournal,
    effect: Callable[[VerifiedExecutionContext], EffectReceiptV1],
    now: datetime = _NOW,
) -> ExecutionReceiptV1:
    return _authorize_and_execute_for_test(
        paths,
        signer=signer,
        provider=provider,
        provider_fingerprints=provider_fingerprints,
        expected_disposal_owner=expected_disposal_owner,
        expected_approver_identity=expected_approver_identity,
        journal=journal,
        effect=effect,
        _clock=lambda: now,
        _capability=_TEST_CLOCK_CAPABILITY,
    )


def test_phase_b_executes_only_after_durable_claim(tmp_path: Path) -> None:
    root = tmp_path / "artifacts"
    signer, fingerprints, _ = _authorize_materials(root)

    receipt = _execute_for_test(
        AuthorizationPaths(root),
        signer=signer,
        provider=_Provider(fingerprints),
        provider_fingerprints=fingerprints,
        expected_disposal_owner="acceptance-owner",
        expected_approver_identity="approval-owner",
        journal=_journal(tmp_path),
        effect=_effect,
        now=_NOW,
    )

    assert receipt.status == "committed"
    assert "nonce" not in receipt.model_dump()


def test_public_execution_has_no_caller_controlled_clock(tmp_path: Path) -> None:
    root = tmp_path / "artifacts"
    signer, fingerprints, _ = _authorize_materials(root)

    assert "now" not in inspect.signature(authorize_and_execute).parameters
    with pytest.raises(TypeError, match="unexpected keyword argument 'now'"):
        authorize_and_execute(
            AuthorizationPaths(root),
            signer=signer,
            provider=_Provider(fingerprints),
            provider_fingerprints=fingerprints,
            expected_disposal_owner="acceptance-owner",
            expected_approver_identity="approval-owner",
            journal=_journal(tmp_path),
            effect=_effect,
            now=_NOW,  # type: ignore[call-arg]
        )
    with pytest.raises(AuthorizationError, match="test_clock"):
        _authorize_and_execute_for_test(
            AuthorizationPaths(root),
            signer=signer,
            provider=_Provider(fingerprints),
            provider_fingerprints=fingerprints,
            expected_disposal_owner="acceptance-owner",
            expected_approver_identity="approval-owner",
            journal=_journal(tmp_path),
            effect=_effect,
            _clock=lambda: _NOW,
            _capability=object(),
        )


def test_phase_b_detects_legacy_journal_before_effect(tmp_path: Path) -> None:
    root = tmp_path / "artifacts"
    signer, fingerprints, _ = _authorize_materials(root)
    journal = _journal(tmp_path)
    connection = sqlite3.connect(journal._path)
    try:
        connection.execute(
            """
            CREATE TABLE authorization_nonce_journal (
                nonce TEXT PRIMARY KEY NOT NULL,
                operation_id TEXT NOT NULL,
                receipt_sha256 TEXT NOT NULL,
                claimed_at TEXT NOT NULL
            ) WITHOUT ROWID
            """
        )
        connection.execute(
            """
            INSERT INTO authorization_nonce_journal
                (nonce, operation_id, receipt_sha256, claimed_at)
            VALUES (?, ?, ?, ?)
            """,
            ("a" * 32, _proposal().operation_id, "b" * 64, "2026-08-27T12:00:00Z"),
        )
        connection.commit()
    finally:
        connection.close()
    journal._path.chmod(0o600)
    called = False

    def effect(context: VerifiedExecutionContext) -> EffectReceiptV1:
        nonlocal called
        called = True
        return _effect(context)

    assert journal.migration_status() is JournalMigrationStatus.LEGACY_DETECTED
    with pytest.raises(AuthorizationError, match="journal_legacy_detected"):
        _execute_for_test(
            AuthorizationPaths(root),
            signer=signer,
            provider=_Provider(fingerprints),
            provider_fingerprints=fingerprints,
            expected_disposal_owner="acceptance-owner",
            expected_approver_identity="approval-owner",
            journal=journal,
            effect=effect,
            now=_NOW,
        )
    assert not called
    assert journal.migration_status() is JournalMigrationStatus.LEGACY_DETECTED


def test_same_operation_with_fresh_nonce_executes_effect_once(tmp_path: Path) -> None:
    root = tmp_path / "artifacts"
    signer, fingerprints, _ = _authorize_materials(root)
    journal = _journal(tmp_path)
    effects: list[str] = []

    def effect(context: VerifiedExecutionContext) -> EffectReceiptV1:
        effects.append(context.idempotency_key)
        return _effect(context)

    def execute() -> str:
        try:
            _execute_for_test(
                AuthorizationPaths(root),
                signer=signer,
                provider=_Provider(fingerprints),
                provider_fingerprints=fingerprints,
                expected_disposal_owner="acceptance-owner",
                expected_approver_identity="approval-owner",
                journal=journal,
                effect=effect,
                now=_NOW,
            )
        except AuthorizationError as error:
            return error.phase
        return "committed"

    with ThreadPoolExecutor(max_workers=2) as executor:
        outcomes = list(executor.map(lambda _: execute(), range(2)))

    assert sorted(outcomes) == ["committed", "operation_replayed"]
    assert len(effects) == 1


def test_effect_failure_requires_recovery_and_never_replays(tmp_path: Path) -> None:
    root = tmp_path / "artifacts"
    signer, fingerprints, _ = _authorize_materials(root)
    journal = _journal(tmp_path)

    def fail_effect(context: VerifiedExecutionContext) -> EffectReceiptV1:
        del context
        raise RuntimeError("effect failure")

    with pytest.raises(AuthorizationError, match="effect_failed_recovery_required"):
        _execute_for_test(
            AuthorizationPaths(root),
            signer=signer,
            provider=_Provider(fingerprints),
            provider_fingerprints=fingerprints,
            expected_disposal_owner="acceptance-owner",
            expected_approver_identity="approval-owner",
            journal=journal,
            effect=fail_effect,
            now=_NOW,
        )
    assert journal.operation_state(_proposal().operation_id).value == "failed_recovery_required"
    with pytest.raises(AuthorizationError, match="operation_replayed"):
        _execute_for_test(
            AuthorizationPaths(root),
            signer=signer,
            provider=_Provider(fingerprints),
            provider_fingerprints=fingerprints,
            expected_disposal_owner="acceptance-owner",
            expected_approver_identity="approval-owner",
            journal=journal,
            effect=_effect,
            now=_NOW,
        )


def _assert_value_safe_error(error: AuthorizationError, secret: str) -> None:
    assert secret not in str(error)
    assert secret not in repr(error)
    assert all(secret not in str(argument) for argument in error.args)
    assert error.__cause__ is None
    assert error.__context__ is None
    assert secret not in "".join(traceback.format_exception(error))


def test_provider_and_effect_failures_do_not_expose_adapter_values(tmp_path: Path) -> None:
    secret = "provider-effect-value-must-not-escape"
    provider_root = tmp_path / "provider-artifacts"
    signer, fingerprints, _ = _authorize_materials(provider_root)

    class FailingProvider(_Provider):
        def inspect(self, reference: ProviderReferenceV1) -> ProviderProvenance | None:
            raise RuntimeError(secret) from ValueError(secret)

    with pytest.raises(AuthorizationError) as provider_failure:
        _execute_for_test(
            AuthorizationPaths(provider_root),
            signer=signer,
            provider=FailingProvider(fingerprints),
            provider_fingerprints=fingerprints,
            expected_disposal_owner="acceptance-owner",
            expected_approver_identity="approval-owner",
            journal=_journal(tmp_path),
            effect=_effect,
            now=_NOW,
        )
    assert provider_failure.value.phase == "provider_failure"
    _assert_value_safe_error(provider_failure.value, secret)

    release_root = tmp_path / "release-artifacts"
    signer, fingerprints, _ = _authorize_materials(release_root)
    release_journal_parent = tmp_path / "release-journal"
    release_journal_parent.mkdir(mode=0o700)
    release_journal_parent.chmod(0o700)
    release_journal = _journal(release_journal_parent)

    class ExitFailingProvider(_Provider):
        def __exit__(self, exception_type: object, exception: object, traceback: object) -> None:
            del exception_type, exception, traceback
            raise RuntimeError(secret) from ValueError(secret)

    with pytest.raises(AuthorizationError) as release_failure:
        _execute_for_test(
            AuthorizationPaths(release_root),
            signer=signer,
            provider=ExitFailingProvider(fingerprints),
            provider_fingerprints=fingerprints,
            expected_disposal_owner="acceptance-owner",
            expected_approver_identity="approval-owner",
            journal=release_journal,
            effect=_effect,
            now=_NOW,
        )
    assert release_failure.value.phase == "provider_release"
    _assert_value_safe_error(release_failure.value, secret)

    effect_root = tmp_path / "effect-artifacts"
    signer, fingerprints, _ = _authorize_materials(effect_root)
    effect_journal_parent = tmp_path / "effect-journal"
    effect_journal_parent.mkdir(mode=0o700)
    effect_journal_parent.chmod(0o700)
    journal = _journal(effect_journal_parent)

    def failing_effect(context: VerifiedExecutionContext) -> EffectReceiptV1:
        del context
        raise RuntimeError(secret) from ValueError(secret)

    with pytest.raises(AuthorizationError) as effect_failure:
        _execute_for_test(
            AuthorizationPaths(effect_root),
            signer=signer,
            provider=_Provider(fingerprints),
            provider_fingerprints=fingerprints,
            expected_disposal_owner="acceptance-owner",
            expected_approver_identity="approval-owner",
            journal=journal,
            effect=failing_effect,
            now=_NOW,
        )
    assert effect_failure.value.phase == "effect_failed_recovery_required"
    _assert_value_safe_error(effect_failure.value, secret)
    connection = sqlite3.connect(journal._path)
    try:
        row = connection.execute(
            "SELECT failure_phase FROM authorization_operation_journal"
        ).fetchone()
    finally:
        connection.close()
    assert row == ("effect",)


def test_owner_lock_blocks_cooperating_artifact_writer(tmp_path: Path) -> None:
    root = tmp_path / "artifacts"
    signer, fingerprints, _ = _authorize_materials(root)
    entered_provider = Event()
    release_provider = Event()
    writer_acquired = Event()

    class BlockingProvider(_Provider):
        def inspect(self, reference: ProviderReferenceV1) -> ProviderProvenance | None:
            entered_provider.set()
            assert release_provider.wait(timeout=5)
            return super().inspect(reference)

    def execute() -> None:
        _execute_for_test(
            AuthorizationPaths(root),
            signer=signer,
            provider=BlockingProvider(fingerprints),
            provider_fingerprints=fingerprints,
            expected_disposal_owner="acceptance-owner",
            expected_approver_identity="approval-owner",
            journal=_journal(tmp_path),
            effect=_effect,
            now=_NOW,
        )

    def writer() -> None:
        with ArtifactRootLease(root):
            writer_acquired.set()

    with ThreadPoolExecutor(max_workers=2) as executor:
        running = executor.submit(execute)
        assert entered_provider.wait(timeout=5)
        blocked_writer = executor.submit(writer)
        assert not writer_acquired.wait(timeout=0.1)
        release_provider.set()
        running.result(timeout=5)
        blocked_writer.result(timeout=5)
    assert writer_acquired.is_set()


@pytest.mark.parametrize("mutation", ("root_replace", "lock_unlink"))
def test_phase_b_rejects_root_or_lock_replacement_before_effect(
    tmp_path: Path, mutation: str
) -> None:
    root = tmp_path / "artifacts"
    signer, fingerprints, _ = _authorize_materials(root)
    entered_provider = Event()
    release_provider = Event()
    called = False

    class BlockingProvider(_Provider):
        def inspect(self, reference: ProviderReferenceV1) -> ProviderProvenance | None:
            entered_provider.set()
            assert release_provider.wait(timeout=5)
            return super().inspect(reference)

    def effect(context: VerifiedExecutionContext) -> EffectReceiptV1:
        nonlocal called
        called = True
        return _effect(context)

    def execute() -> str:
        try:
            _execute_for_test(
                AuthorizationPaths(root),
                signer=signer,
                provider=BlockingProvider(fingerprints),
                provider_fingerprints=fingerprints,
                expected_disposal_owner="acceptance-owner",
                expected_approver_identity="approval-owner",
                journal=_journal(tmp_path),
                effect=effect,
                now=_NOW,
            )
        except AuthorizationError as error:
            return error.phase
        return "committed"

    with ThreadPoolExecutor(max_workers=1) as executor:
        running = executor.submit(execute)
        assert entered_provider.wait(timeout=5)
        if mutation == "root_replace":
            root.rename(tmp_path / "moved-artifacts")
            root.mkdir(mode=0o700)
            root.chmod(0o700)
        else:
            _root_lock_path(root).unlink()
        release_provider.set()
        outcome = running.result(timeout=5)

    assert outcome in {"artifact_lock_root", "artifact_lock_file", "artifact_lock_state"}
    assert not called


def test_recovery_cannot_race_a_live_effect(tmp_path: Path) -> None:
    root = tmp_path / "artifacts"
    signer, fingerprints, _ = _authorize_materials(root)
    journal = _journal(tmp_path)
    entered_effect = Event()
    release_effect = Event()

    def effect(context: VerifiedExecutionContext) -> EffectReceiptV1:
        entered_effect.set()
        assert release_effect.wait(timeout=5)
        return _effect(context)

    def execute() -> ExecutionReceiptV1:
        return _execute_for_test(
            AuthorizationPaths(root),
            signer=signer,
            provider=_Provider(fingerprints),
            provider_fingerprints=fingerprints,
            expected_disposal_owner="acceptance-owner",
            expected_approver_identity="approval-owner",
            journal=journal,
            effect=effect,
            now=_NOW,
        )

    with ThreadPoolExecutor(max_workers=1) as executor:
        running = executor.submit(execute)
        assert entered_effect.wait(timeout=5)
        with pytest.raises(AuthorizationError, match="operation_live"):
            journal.require_recovery(_proposal().operation_id)
        release_effect.set()
        assert running.result(timeout=5).status == "committed"


def test_phase_b_refuses_terminal_success_after_lock_changes_during_effect(tmp_path: Path) -> None:
    root = tmp_path / "artifacts"
    signer, fingerprints, _ = _authorize_materials(root)
    journal = _journal(tmp_path)
    entered_effect = Event()
    release_effect = Event()

    def effect(context: VerifiedExecutionContext) -> EffectReceiptV1:
        entered_effect.set()
        assert release_effect.wait(timeout=5)
        return _effect(context)

    def execute() -> str:
        try:
            _execute_for_test(
                AuthorizationPaths(root),
                signer=signer,
                provider=_Provider(fingerprints),
                provider_fingerprints=fingerprints,
                expected_disposal_owner="acceptance-owner",
                expected_approver_identity="approval-owner",
                journal=journal,
                effect=effect,
                now=_NOW,
            )
        except AuthorizationError as error:
            return error.phase
        return "committed"

    with ThreadPoolExecutor(max_workers=1) as executor:
        running = executor.submit(execute)
        assert entered_effect.wait(timeout=5)
        _root_lock_path(root).unlink()
        release_effect.set()
        assert running.result(timeout=5) == "effect_failed_recovery_required"
    assert journal.operation_state(_proposal().operation_id).value == "failed_recovery_required"


def test_artifact_lock_rejects_relaxed_mode_and_symlink(tmp_path: Path) -> None:
    root = tmp_path / "artifacts"
    _materials(root)
    with ArtifactRootLease(root):
        pass
    lock_path = _root_lock_path(root)
    lock_path.chmod(0o644)
    with pytest.raises(AuthorizationError, match="artifact_lock_file"), ArtifactRootLease(root):
        pass

    symlink_root = tmp_path / "symlink-artifacts"
    _materials(symlink_root)
    with ArtifactRootLease(symlink_root):
        pass
    target = tmp_path / "lock-target"
    target.write_bytes(b"lock")
    target.chmod(0o600)
    _root_lock_path(symlink_root).unlink()
    _root_lock_path(symlink_root).symlink_to(target)
    with (
        pytest.raises(AuthorizationError, match="artifact_lock_file"),
        ArtifactRootLease(symlink_root),
    ):
        pass

    root_target = tmp_path / "root-target"
    _materials(root_target)
    root_symlink = tmp_path / "root-symlink"
    root_symlink.symlink_to(root_target, target_is_directory=True)
    with (
        pytest.raises(AuthorizationError, match="artifact_lock_root"),
        ArtifactRootLease(root_symlink),
    ):
        pass


def test_phase_b_rejects_artifact_and_provider_mutation_before_effect(tmp_path: Path) -> None:
    root = tmp_path / "artifacts"
    signer, fingerprints, _ = _authorize_materials(root)
    raced_sidecar = root / AuthorizationPaths.signature_name("proposal.yaml")
    called = False

    def effect(context: VerifiedExecutionContext) -> EffectReceiptV1:
        nonlocal called
        called = True
        return _effect(context)

    with pytest.raises(AuthorizationError, match="artifact_race"):
        _execute_for_test(
            AuthorizationPaths(root),
            signer=signer,
            provider=_Provider(fingerprints, mutate_artifact=raced_sidecar),
            provider_fingerprints=fingerprints,
            expected_disposal_owner="acceptance-owner",
            expected_approver_identity="approval-owner",
            journal=_journal(tmp_path),
            effect=effect,
            now=_NOW,
        )
    assert not called

    provider_root = tmp_path / "provider-artifacts"
    signer, fingerprints, _ = _authorize_materials(provider_root)
    with pytest.raises(AuthorizationError, match="provider_provenance"):
        _execute_for_test(
            AuthorizationPaths(provider_root),
            signer=signer,
            provider=_Provider(fingerprints, mutate_provider=True),
            provider_fingerprints=fingerprints,
            expected_disposal_owner="acceptance-owner",
            expected_approver_identity="approval-owner",
            journal=_journal(tmp_path),
            effect=_effect,
            now=_NOW,
        )


def test_phase_b_rejects_marker_only_signature_and_cli_is_read_only(tmp_path: Path) -> None:
    root = tmp_path / "artifacts"
    signer, fingerprints, _ = _authorize_materials(root)
    (root / AuthorizationPaths.signature_name("approval.yaml")).unlink()

    with pytest.raises(AuthorizationError, match="artifact_snapshot"):
        _execute_for_test(
            AuthorizationPaths(root),
            signer=signer,
            provider=_Provider(fingerprints),
            provider_fingerprints=fingerprints,
            expected_disposal_owner="acceptance-owner",
            expected_approver_identity="approval-owner",
            journal=_journal(tmp_path),
            effect=_effect,
            now=_NOW,
        )
    assert authorization_main(["authorize", "--root", str(root)]) == 2
    assert main(["authorize", "--root", str(root)]) == 2


def test_phase_b_rejects_disposal_owner_or_approval_mismatch(tmp_path: Path) -> None:
    root = tmp_path / "artifacts"
    signer, fingerprints, _ = _authorize_materials(root)

    with pytest.raises(AuthorizationError, match="owner_approval"):
        _execute_for_test(
            AuthorizationPaths(root),
            signer=signer,
            provider=_Provider(fingerprints),
            provider_fingerprints=fingerprints,
            expected_disposal_owner="wrong-owner",
            expected_approver_identity="approval-owner",
            journal=_journal(tmp_path),
            effect=_effect,
            now=_NOW,
        )


def test_external_execution_receipt_cannot_reach_internal_claim(tmp_path: Path) -> None:
    receipt = ExecutionReceiptV1(
        schema_version="rsd.lifecycle-execution-receipt.v1",
        status="committed",
        operation_id="forged-operation",
        idempotency_key="a" * 64,
        effect_receipt_sha256="b" * 64,
        proposal_sha256="c" * 64,
        contract_sha256="d" * 64,
        provider_provenance_sha256="e" * 64,
        committed_at="2026-08-27T12:00:00Z",
    )

    with pytest.raises(AuthorizationError, match="journal"):
        _journal(tmp_path)._claim_verified(receipt)  # type: ignore[arg-type]


def test_phase_b_rejects_marker_tampering_even_when_phase_a_hashes_are_refreshed(
    tmp_path: Path,
) -> None:
    root = tmp_path / "artifacts"
    signer, fingerprints, key = _authorize_materials(root)
    approval_path = root / "approval.yaml"
    approval = yaml.safe_load(approval_path.read_text(encoding="utf-8"))
    assert type(approval) is dict
    marker = approval["signature"]
    assert type(marker) is dict
    marker["detached_signature_sha256"] = "0" * 64
    approval_path.write_bytes(yaml.safe_dump(approval, sort_keys=True).encode())
    approval_path.chmod(0o600)
    _refresh_contract_evidence_hashes(root)
    _refresh_sidecar(root, "approval.yaml", key, resign=False)
    _refresh_sidecar(root, "runtime-contract.yaml", key, resign=True)

    with pytest.raises(AuthorizationError, match="signature_marker"):
        _execute_for_test(
            AuthorizationPaths(root),
            signer=signer,
            provider=_Provider(fingerprints),
            provider_fingerprints=fingerprints,
            expected_disposal_owner="acceptance-owner",
            expected_approver_identity="approval-owner",
            journal=_journal(tmp_path),
            effect=_effect,
            now=_NOW,
        )


def test_phase_b_rejects_sidecar_swap_and_noncanonical_base64_alias(tmp_path: Path) -> None:
    root = tmp_path / "artifacts"
    signer, fingerprints, _ = _authorize_materials(root)
    proposal_sidecar = root / AuthorizationPaths.signature_name("proposal.yaml")
    approval_sidecar = root / AuthorizationPaths.signature_name("approval.yaml")
    proposal_sidecar.write_bytes(approval_sidecar.read_bytes())
    proposal_sidecar.chmod(0o600)

    with pytest.raises(AuthorizationError, match="signature_binding"):
        _execute_for_test(
            AuthorizationPaths(root),
            signer=signer,
            provider=_Provider(fingerprints),
            provider_fingerprints=fingerprints,
            expected_disposal_owner="acceptance-owner",
            expected_approver_identity="approval-owner",
            journal=_journal(tmp_path),
            effect=_effect,
            now=_NOW,
        )

    alias_root = tmp_path / "aliased-artifacts"
    signer, fingerprints, _ = _authorize_materials(alias_root)
    proposal_sidecar = alias_root / AuthorizationPaths.signature_name("proposal.yaml")
    sidecar = yaml.safe_load(proposal_sidecar.read_text(encoding="utf-8"))
    assert type(sidecar) is dict
    encoded = sidecar["signature_base64"]
    assert type(encoded) is str and encoded.endswith("==")
    alphabet = "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/"
    final_index = alphabet.index(encoded[-3])
    alias = alphabet[(final_index & 0b110000) | ((final_index + 1) & 0b001111)]
    sidecar["signature_base64"] = f"{encoded[:-3]}{alias}=="
    proposal_sidecar.write_bytes(yaml.safe_dump(sidecar, sort_keys=True).encode())
    proposal_sidecar.chmod(0o600)

    with pytest.raises(AuthorizationError, match="signature_artifact"):
        _execute_for_test(
            AuthorizationPaths(alias_root),
            signer=signer,
            provider=_Provider(fingerprints),
            provider_fingerprints=fingerprints,
            expected_disposal_owner="acceptance-owner",
            expected_approver_identity="approval-owner",
            journal=_journal(tmp_path),
            effect=_effect,
            now=_NOW,
        )
