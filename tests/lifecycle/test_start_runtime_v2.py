"""Adversarial tests for the value-free StartRuntime V2 boundary.

The fixtures are documentation-only values.  They exercise models, durable
SQLite state, and injected protocol shapes only; no Keychain, SSH, Docker,
PostgreSQL, network, process, or provider implementation is contacted.
"""

from __future__ import annotations

import base64
import inspect
from dataclasses import replace
from datetime import UTC, datetime
from pathlib import Path
from typing import Any, cast

import pytest

import omninode_rsd.lifecycle.authorization as authorization
from omninode_rsd.lifecycle.authorization import (
    AuthorizationError,
    AuthorizationPaths,
    ExecutorControlExpectationV1,
    ReplayTombstoneV1,
    SecretMaterialExpectationV1,
    StartRuntimeExecutionContext,
    StartRuntimeOperationState,
    authorize_start_runtime_and_execute,
)
from omninode_rsd.lifecycle.infisical_disposable import (
    ContainerAttachReceiptV1,
    ContainerAttachRequestV1,
    ContainerAttachTerminalAckV1,
    ContainerBootstrapAttachProtocolV1,
    ContainerBootstrapWrapperManifestV1,
    ExecutorContainerInspectionV1,
    MaterializationEffectReceiptV1,
    MaterializationIntentV1,
    ObservedRestoreDatabaseAttestationV1,
    ObservedRuntimeAttestationV1,
    SecretDeliveryReceiptV1,
    SecretDeliveryRequestV1,
    SecretDeliverySlotReceiptV1,
    StartRuntimeEffectReceiptV2,
    StartRuntimeEvidenceBindingsV2,
    StartRuntimeExecutorReceiptV2,
    StartRuntimeIntentV2,
    TargetDeliveryMapV1,
    container_attach_ack_sha256,
    container_attach_chunk_descriptors_sha256,
    container_attach_receipt_sha256,
    container_attach_request_sha256,
    start_runtime_intent_sha256,
)

from .test_infisical_disposable import (
    _APPROVER,
    _EXECUTOR_ATTESTATION_PRIVATE_KEY,
    _EXECUTOR_ATTESTATION_PUBLIC_BYTES,
    _EXECUTOR_ATTESTATION_PUBLIC_KEY,
    _NOW,
    _OWNER,
    _RETAINS,
    _SIGNATURE,
    _allocation_attestation,
    _allocation_bundle,
    _allocation_receipt,
    _hash,
    _materialization_context,
    _materialization_intent,
    _materialization_receipt,
    _provisioned_allocation,
    _signed_allocation_bundle,
    _trusted_signer,
    _verified_allocation,
)

_START_ID = "123e4567-e89b-42d3-a456-426614174005"
_SECOND_START_ID = "123e4567-e89b-42d3-a456-426614174006"


def _start_intent(
    allocation: object,
    materialization: MaterializationIntentV1,
    *,
    signer_private: object,
    start_operation_id: str = _START_ID,
    request_nonce_sha256: str | None = None,
) -> StartRuntimeIntentV2:
    """Build a signed fresh-start contract without any provider value."""

    allocation_intent = cast(Any, allocation)
    provider_material_sha256 = _hash("provider-material-attestation")
    delivery = SecretDeliveryRequestV1(
        schema_version="rsd.secret-delivery-request.v1",
        operation_scope="start_runtime_v2",
        operation_id=start_operation_id,
        journal_uuid=allocation_intent.journal_uuid,
        provider_material_attestation_sha256=provider_material_sha256,
        channel_binding_sha256=_hash("start-channel"),
        session_binding_sha256=_hash("start-session"),
        request_nonce_sha256=request_nonce_sha256 or _hash("start-request-nonce"),
        slots=materialization.secret_delivery_request.slots,
    )
    unsigned = StartRuntimeIntentV2(
        schema_version="rsd.start-runtime-intent.v2",
        operation_kind="start_runtime_v2",
        operation_scope="start_runtime_v2",
        start_operation_id=start_operation_id,
        materialization_operation_id=materialization.materialization_operation_id,
        source_commit=materialization.source_commit,
        materialization_intent_sha256=authorization.materialization_intent_sha256(materialization),
        materialization_effect_receipt_sha256=_hash("materialization-effect"),
        observed_runtime_attestation_sha256=_hash("observed-runtime"),
        observed_restore_database_attestation_sha256=(
            materialization.observed_restore_database_attestation_sha256
        ),
        provider_references=allocation_intent.provider_references,
        evidence=StartRuntimeEvidenceBindingsV2(
            materialization_intent_sha256=authorization.materialization_intent_sha256(
                materialization
            ),
            materialization_effect_receipt_sha256=_hash("materialization-effect"),
            observed_runtime_attestation_sha256=_hash("observed-runtime"),
            observed_restore_database_attestation_sha256=(
                materialization.observed_restore_database_attestation_sha256
            ),
            executor_control_policy_sha256=_hash("executor-control-policy"),
            executor_installation_policy_sha256=_hash("executor-installation-policy"),
            executor_installation_intent_sha256=_hash("executor-installation-intent"),
            executor_installation_receipt_sha256=_hash("executor-installation-receipt"),
            secret_capability_policy_sha256=_hash("secret-capability-policy"),
            secret_handling_policy_sha256=_hash("secret-handling-policy"),
            provider_material_attestation_sha256=provider_material_sha256,
            wrapper_manifest_sha256=materialization.wrapper_manifest_sha256,
            target_delivery_map_sha256=materialization.target_delivery_map_sha256,
            container_attach_protocol_sha256=materialization.container_attach_protocol_sha256,
        ),
        delivery_request=delivery,
        retention_expires_at=_RETAINS,
        disposal_owner=_OWNER,
        approver_identity=_APPROVER,
        approval_reference_sha256=_hash("start-approval"),
        journal_uuid=allocation_intent.journal_uuid,
        replay_policy_sha256=allocation_intent.replay_policy_sha256,
        created_at=_NOW,
        signer_key_id="test-signer",
        signature_base64=_SIGNATURE,
    )
    signing_key = cast(Any, signer_private)
    return unsigned.model_copy(
        update={
            "signature_base64": base64.b64encode(
                signing_key.sign(authorization._start_runtime_intent_message(unsigned))
            ).decode("ascii")
        }
    )


def _start_context(
    start: StartRuntimeIntentV2,
    materialization: MaterializationIntentV1,
    materialization_receipt: MaterializationEffectReceiptV1,
    restore_database_attestation: ObservedRestoreDatabaseAttestationV1,
    wrapper_manifest: ContainerBootstrapWrapperManifestV1,
    target_delivery_map: TargetDeliveryMapV1,
    attach_protocol: ContainerBootstrapAttachProtocolV1,
) -> StartRuntimeExecutionContext:
    """Create the opaque context only for receipt/journal boundary testing."""

    return StartRuntimeExecutionContext(
        operation_kind="start_runtime_v2",
        operation_scope="start_runtime_v2",
        start_operation_id=start.start_operation_id,
        intent=start,
        materialization_intent=materialization,
        materialization_receipt=materialization_receipt,
        restore_database_attestation=restore_database_attestation,
        observed_runtime_attestation=ObservedRuntimeAttestationV1.model_construct(),
        provider_expectations=(),
        executor_expectation=ExecutorControlExpectationV1(
            executor_id="local-executor",
            endpoint_sha256=_hash("executor-endpoint"),
            host_fingerprint_sha256=_hash("executor-host"),
            control_capability_fingerprint_sha256=_hash("executor-control"),
            engine_fingerprint_sha256=_hash("engine"),
        ),
        executor_attestation_key_id="executor-attestation",
        executor_attestation_public_key_base64=_EXECUTOR_ATTESTATION_PUBLIC_KEY,
        executor_attestation_public_key_fingerprint_sha256=authorization._digest(
            _EXECUTOR_ATTESTATION_PUBLIC_BYTES
        ),
        secret_material_expectation=SecretMaterialExpectationV1(
            provider_identity_sha256=_hash("provider-material-attestation"),
            capability_fingerprint_sha256=_hash("secret-capability"),
            secret_handling_policy_sha256=_hash("secret-handling"),
        ),
        secret_handling_policy_sha256=_hash("secret-handling"),
        wrapper_manifest=wrapper_manifest,
        target_delivery_map=target_delivery_map,
        container_attach_protocol=attach_protocol,
        secret_delivery_request=start.delivery_request,
        start_runtime_intent_sha256=start_runtime_intent_sha256(start),
        idempotency_key=_hash("start-idempotency"),
        proposal_sha256=_hash("proposal"),
        contract_sha256=_hash("contract"),
        provider_provenance_sha256=_hash("provider-provenance"),
        executor_provenance_sha256=_hash("executor-provenance"),
        secret_capability_provenance_sha256=_hash("secret-capability-provenance"),
        secret_delivery_provenance_sha256=_hash("secret-delivery-provenance"),
        remote_session_provenance_sha256=_hash("remote-session-provenance"),
    )


def _fresh_start_attach_containers(
    context: StartRuntimeExecutionContext,
) -> tuple[
    ExecutorContainerInspectionV1,
    ExecutorContainerInspectionV1,
    ExecutorContainerInspectionV1,
    ExecutorContainerInspectionV1,
]:
    """Rebuild fresh local-delivery evidence for a restart, never reuse a claim."""

    completed: list[ExecutorContainerInspectionV1] = []
    for prior in context.materialization_receipt.executor_receipt.containers:
        target = getattr(context.target_delivery_map, prior.component)
        request = ContainerAttachRequestV1(
            schema_version="rsd.container-attach-request.v1",
            operation_scope="start_runtime_v2",
            operation_id=context.start_operation_id,
            component=prior.component,
            container_id=prior.container_id,
            derived_image_policy_sha256=target.derived_image_policy_sha256,
            wrapper_manifest_sha256=context.materialization_intent.wrapper_manifest_sha256,
            wrapper_artifact_binding_sha256=target.wrapper_artifact_binding_sha256,
            attach_protocol_sha256=context.materialization_intent.container_attach_protocol_sha256,
            target_delivery_map_sha256=context.materialization_intent.target_delivery_map_sha256,
            request_nonce_sha256=context.secret_delivery_request.request_nonce_sha256,
            channel_binding_sha256=context.secret_delivery_request.channel_binding_sha256,
            session_binding_sha256=context.secret_delivery_request.session_binding_sha256,
            expected_ready_state="ready_v1",
            expected_claim_state="claimed_v1",
            expected_terminal_ack_state="terminal_ack_v1",
            fields=target.fields,
        )
        request_sha256 = container_attach_request_sha256(request)
        descriptor_sha256 = container_attach_chunk_descriptors_sha256(request.fields)
        ack = ContainerAttachTerminalAckV1(
            schema_version="rsd.container-attach-terminal-ack.v1",
            request_sha256=request_sha256,
            state="terminal_ack_v1",
            chunk_count=len(request.fields),
            chunk_descriptors_sha256=descriptor_sha256,
            chunks_zeroized=True,
            persistence_allowed=False,
            logging_allowed=False,
            receipt_contains_secret=False,
            eof_observed=True,
        )
        completed_attach = ContainerAttachReceiptV1(
            schema_version="rsd.container-attach-receipt.v1",
            request_sha256=request_sha256,
            component=prior.component,
            container_id=prior.container_id,
            ready_state="ready_v1",
            claim_state="claimed_v1",
            chunk_count=len(request.fields),
            chunk_descriptors_sha256=descriptor_sha256,
            terminal_ack_state="terminal_ack_v1",
            terminal_ack_sha256=container_attach_ack_sha256(ack),
            chunks_zeroized=True,
            persistence_allowed=False,
            logging_allowed=False,
            receipt_contains_secret=False,
            eof_observed=True,
        )
        completed.append(
            ExecutorContainerInspectionV1(
                component=prior.component,
                container_id=prior.container_id,
                inspection=prior.inspection,
                attach_receipt=completed_attach,
                attach_receipt_sha256=container_attach_receipt_sha256(completed_attach),
            )
        )
    return cast(
        tuple[
            ExecutorContainerInspectionV1,
            ExecutorContainerInspectionV1,
            ExecutorContainerInspectionV1,
            ExecutorContainerInspectionV1,
        ],
        tuple(completed),
    )


def test_start_runtime_requires_refreshed_target_delivery_map_fingerprints(
    tmp_path: Path,
) -> None:
    """A fresh StartV2 snapshot cannot reuse stale target-map fingerprints."""

    allocation, executor, _ = _allocation_bundle(tmp_path)
    allocation_receipt = _allocation_receipt(allocation)
    allocation_observation = _allocation_attestation(allocation, allocation_receipt)
    _, _, _, _, _, target_delivery_map, _ = _materialization_intent(
        allocation, executor, allocation_receipt, allocation_observation
    )
    refreshed = {
        item.reference_sha256: item.fingerprint_sha256
        for item in target_delivery_map.material_fingerprints
    }
    authorization._verify_target_delivery_map_fingerprints(target_delivery_map, refreshed)

    stale = dict(refreshed)
    stale[allocation.provider_references.auth_secret.reference_sha256] = _hash(
        "refreshed-but-different-auth-secret"
    )
    with pytest.raises(AuthorizationError, match="target_delivery_map_provider_binding"):
        authorization._verify_target_delivery_map_fingerprints(target_delivery_map, stale)


def _start_effect_receipt(context: StartRuntimeExecutionContext) -> StartRuntimeEffectReceiptV2:
    """Create a valid redacted, executor-signed receipt for one test context."""

    unsigned_executor = StartRuntimeExecutorReceiptV2(
        schema_version="rsd.start-runtime-executor-receipt.v2",
        operation_kind="start_runtime_v2",
        operation_scope="start_runtime_v2",
        start_operation_id=context.start_operation_id,
        start_runtime_intent_sha256=context.start_runtime_intent_sha256,
        idempotency_key=context.idempotency_key,
        secret_delivery_receipt_sha256=_hash("pending-start-secret-delivery-receipt"),
        request_nonce_sha256=context.secret_delivery_request.request_nonce_sha256,
        channel_binding_sha256=context.secret_delivery_request.channel_binding_sha256,
        session_binding_sha256=context.secret_delivery_request.session_binding_sha256,
        installation_receipt_sha256=(context.intent.evidence.executor_installation_receipt_sha256),
        executor_id=context.executor_expectation.executor_id,
        host_fingerprint_sha256=context.executor_expectation.host_fingerprint_sha256,
        engine_fingerprint_sha256=context.executor_expectation.engine_fingerprint_sha256,
        engine_operation_journal_sha256=_hash("start-engine-operation-journal"),
        wrapper_manifest_sha256=context.materialization_intent.wrapper_manifest_sha256,
        target_delivery_map_sha256=context.materialization_intent.target_delivery_map_sha256,
        container_attach_protocol_sha256=(
            context.materialization_intent.container_attach_protocol_sha256
        ),
        containers=_fresh_start_attach_containers(context),
        completed_at="2026-08-28T12:07:00Z",
        signer_key_id=context.executor_attestation_key_id,
        signature_base64=_SIGNATURE,
    )
    request = context.secret_delivery_request
    delivery = SecretDeliveryReceiptV1(
        schema_version="rsd.secret-delivery-receipt.v1",
        operation_scope="start_runtime_v2",
        operation_id=context.start_operation_id,
        journal_uuid=request.journal_uuid,
        request_nonce_sha256=request.request_nonce_sha256,
        channel_binding_sha256=request.channel_binding_sha256,
        session_binding_sha256=request.session_binding_sha256,
        slots=tuple(
            SecretDeliverySlotReceiptV1(
                purpose=slot.purpose,
                reference_sha256=slot.reference_sha256,
                sink=slot.sink,
                target_identities=slot.target_identities,
                delivered=True,
            )
            for slot in request.slots
        ),
        completed_at="2026-08-28T12:07:00Z",
    )
    unsigned_executor = unsigned_executor.model_copy(
        update={"secret_delivery_receipt_sha256": authorization.canonical_sha256(delivery)}
    )
    executor_receipt = unsigned_executor.model_copy(
        update={
            "signature_base64": base64.b64encode(
                _EXECUTOR_ATTESTATION_PRIVATE_KEY.sign(
                    authorization._start_runtime_executor_receipt_message(unsigned_executor)
                )
            ).decode("ascii")
        }
    )
    return StartRuntimeEffectReceiptV2(
        schema_version="rsd.start-runtime-effect-receipt.v2",
        operation_kind="start_runtime_v2",
        operation_scope="start_runtime_v2",
        status="started_runtime",
        start_operation_id=context.start_operation_id,
        start_runtime_intent_sha256=context.start_runtime_intent_sha256,
        materialization_operation_id=context.materialization_intent.materialization_operation_id,
        materialization_effect_receipt_sha256=authorization.materialization_effect_receipt_sha256(
            context.materialization_receipt
        ),
        journal_uuid=context.intent.journal_uuid,
        idempotency_key=context.idempotency_key,
        wrapper_manifest_sha256=context.materialization_intent.wrapper_manifest_sha256,
        target_delivery_map_sha256=context.materialization_intent.target_delivery_map_sha256,
        container_attach_protocol_sha256=(
            context.materialization_intent.container_attach_protocol_sha256
        ),
        executor_receipt=executor_receipt,
        delivery_receipt=delivery,
        completed_at="2026-08-28T12:07:00Z",
    )


def _materialized_start_context(tmp_path: Path) -> StartRuntimeExecutionContext:
    allocation, executor, _ = _allocation_bundle(tmp_path)
    allocation_receipt = _allocation_receipt(allocation)
    allocation_attestation = _allocation_attestation(allocation, allocation_receipt)
    (
        materialization,
        restore_observation,
        _,
        _,
        wrapper_manifest,
        target_delivery_map,
        attach_protocol,
    ) = _materialization_intent(allocation, executor, allocation_receipt, allocation_attestation)
    _, signing_key = _trusted_signer()
    materialization_context = _materialization_context(
        materialization,
        allocation_attestation,
        restore_observation,
        wrapper_manifest,
        target_delivery_map,
        attach_protocol,
    )
    materialization_receipt = _materialization_receipt(materialization_context)
    start = _start_intent(allocation, materialization, signer_private=signing_key)
    return _start_context(
        start,
        materialization,
        materialization_receipt,
        restore_observation,
        wrapper_manifest,
        target_delivery_map,
        attach_protocol,
    )


def test_start_runtime_receipt_rejects_container_and_secret_slot_substitution(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    monkeypatch.setattr(
        authorization,
        "_system_utc_clock",
        lambda: datetime(2026, 8, 28, 12, 8, tzinfo=UTC),
    )
    context = _materialized_start_context(tmp_path)
    receipt = _start_effect_receipt(context)

    assert authorization._validate_start_runtime_effect_receipt(context, receipt) == receipt

    altered_container = receipt.executor_receipt.containers[0].model_copy(
        update={"container_id": _hash("substituted-container")}
    )
    altered_executor = receipt.executor_receipt.model_copy(
        update={
            "containers": (
                altered_container,
                *receipt.executor_receipt.containers[1:],
            )
        }
    )
    with pytest.raises(AuthorizationError, match="start_runtime_effect_receipt"):
        authorization._validate_start_runtime_effect_receipt(
            context, receipt.model_copy(update={"executor_receipt": altered_executor})
        )

    altered_slot = receipt.delivery_receipt.slots[0].model_copy(
        update={"reference_sha256": _hash("substituted-secret-slot")}
    )
    altered_delivery = receipt.delivery_receipt.model_copy(
        update={"slots": (altered_slot, *receipt.delivery_receipt.slots[1:])}
    )
    with pytest.raises(AuthorizationError, match="start_runtime_effect_receipt"):
        authorization._validate_start_runtime_effect_receipt(
            context, receipt.model_copy(update={"delivery_receipt": altered_delivery})
        )


def test_start_runtime_reconstructs_compact_attach_receipt_before_signature(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    """A valid compact receipt cannot choose its own request or descriptors.

    The executor's outer signature is deliberately left stale in these
    adversarial cases.  The local route verifier must reject the substituted
    completion projection before a signature check could obscure that binding
    failure.
    """

    monkeypatch.setattr(
        authorization,
        "_system_utc_clock",
        lambda: datetime(2026, 8, 28, 12, 8, tzinfo=UTC),
    )
    context = _materialized_start_context(tmp_path)
    receipt = _start_effect_receipt(context)
    original = receipt.executor_receipt.containers[0]
    original_attach = original.attach_receipt

    def rebuilt_effect(
        *, request_sha256: str, descriptors_sha256: str
    ) -> StartRuntimeEffectReceiptV2:
        ack = ContainerAttachTerminalAckV1(
            schema_version="rsd.container-attach-terminal-ack.v1",
            request_sha256=request_sha256,
            state="terminal_ack_v1",
            chunk_count=original_attach.chunk_count,
            chunk_descriptors_sha256=descriptors_sha256,
            chunks_zeroized=True,
            persistence_allowed=False,
            logging_allowed=False,
            receipt_contains_secret=False,
            eof_observed=True,
        )
        altered_attach = ContainerAttachReceiptV1.model_validate(
            {
                **original_attach.model_dump(mode="json"),
                "request_sha256": request_sha256,
                "chunk_descriptors_sha256": descriptors_sha256,
                "terminal_ack_sha256": container_attach_ack_sha256(ack),
            }
        )
        altered_container = ExecutorContainerInspectionV1(
            component=original.component,
            container_id=original.container_id,
            inspection=original.inspection,
            attach_receipt=altered_attach,
            attach_receipt_sha256=container_attach_receipt_sha256(altered_attach),
        )
        altered_executor = receipt.executor_receipt.model_copy(
            update={
                "containers": (
                    altered_container,
                    *receipt.executor_receipt.containers[1:],
                )
            }
        )
        return receipt.model_copy(
            update={
                "executor_receipt": altered_executor,
                "executor_receipt_sha256": authorization.canonical_sha256(altered_executor),
            }
        )

    with pytest.raises(AuthorizationError, match="start_runtime_executor_attach_receipt"):
        authorization._validate_start_runtime_effect_receipt(
            context,
            rebuilt_effect(
                request_sha256=_hash("substituted-attach-request"),
                descriptors_sha256=original_attach.chunk_descriptors_sha256,
            ),
        )

    with pytest.raises(AuthorizationError, match="start_runtime_executor_attach_receipt"):
        authorization._validate_start_runtime_effect_receipt(
            context,
            rebuilt_effect(
                request_sha256=original_attach.request_sha256,
                descriptors_sha256=_hash("substituted-attach-descriptors"),
            ),
        )


def test_start_runtime_journal_requires_materialization_and_blocks_replay(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    _, _, allocation, executor, _, journal, _, _ = _provisioned_allocation(tmp_path, monkeypatch)
    allocation_verified = _verified_allocation(allocation, "start-allocation-nonce")
    allocation_receipt = _allocation_receipt(allocation).model_copy(
        update={"idempotency_key": allocation_verified.context.idempotency_key}
    )
    allocation_attestation = _allocation_attestation(allocation, allocation_receipt)
    journal._claim_verified(allocation_verified)
    journal._begin_effect(allocation_verified)
    journal._commit_effect(allocation_verified, allocation_receipt)

    (
        materialization,
        restore_observation,
        _,
        _,
        wrapper_manifest,
        target_delivery_map,
        attach_protocol,
    ) = _materialization_intent(allocation, executor, allocation_receipt, allocation_attestation)
    materialization_context = _materialization_context(
        materialization,
        allocation_attestation,
        restore_observation,
        wrapper_manifest,
        target_delivery_map,
        attach_protocol,
    )
    materialization_receipt = _materialization_receipt(materialization_context)
    _, signing_key = _trusted_signer()
    start = _start_intent(allocation, materialization, signer_private=signing_key)
    start_context = _start_context(
        start,
        materialization,
        materialization_receipt,
        restore_observation,
        wrapper_manifest,
        target_delivery_map,
        attach_protocol,
    )
    verified_start = authorization._VerifiedStartRuntime(
        context=start_context,
        nonce="start-nonce",
        authorized_at=_NOW,
        capability=authorization._START_RUNTIME_VERIFIED_CAPABILITY,
    )

    with pytest.raises(AuthorizationError, match="start_runtime_materialization_predecessor"):
        journal._claim_start_runtime_verified(verified_start)

    verified_materialization = authorization._VerifiedMaterialization(
        context=materialization_context,
        nonce="materialization-nonce",
        authorized_at=_NOW,
        capability=authorization._MATERIALIZATION_VERIFIED_CAPABILITY,
    )
    journal._claim_materialization_verified(verified_materialization)
    journal._begin_materialization_effect(verified_materialization)
    journal._commit_materialization_effect(verified_materialization, materialization_receipt)
    journal._claim_start_runtime_verified(verified_start)
    journal._begin_start_runtime_effect(verified_start)
    journal._fail_start_runtime_effect(verified_start)

    assert (
        journal.start_runtime_operation_state(start.start_operation_id)
        is StartRuntimeOperationState.FAILED_RECOVERY_REQUIRED
    )
    replayed = replace(verified_start, nonce="fresh-start-nonce")
    with pytest.raises(AuthorizationError, match="start_runtime_operation_replayed"):
        journal._claim_start_runtime_verified(replayed)
    with pytest.raises(AuthorizationError, match="start_runtime_operation_state"):
        journal.require_start_runtime_recovery(start.start_operation_id)


def test_start_tombstone_binds_receipt_and_delivery_nonce(tmp_path: Path) -> None:
    context = _materialized_start_context(tmp_path)
    verified = authorization._VerifiedStartRuntime(
        context=context,
        nonce="start-tombstone-nonce",
        authorized_at=_NOW,
        capability=authorization._START_RUNTIME_VERIFIED_CAPABILITY,
    )
    policy = authorization.ReplayAuthorityPolicyV1(
        schema_version="rsd.replay-authority-policy.v1",
        service="replay-service",
        account_prefix="replay-prefix",
    )
    tombstone = authorization._start_runtime_operation_tombstone(policy, verified)

    assert tombstone.kind == "start_runtime_operation"
    assert (
        tombstone.materialization_effect_receipt_sha256
        == authorization.materialization_effect_receipt_sha256(context.materialization_receipt)
    )
    assert tombstone.request_nonce_sha256 == context.secret_delivery_request.request_nonce_sha256

    raw = tombstone.model_dump(mode="python")
    raw["materialization_effect_receipt_sha256"] = None
    with pytest.raises(ValueError, match="replay tombstone"):
        ReplayTombstoneV1.model_validate(raw)


def test_materialization_tombstone_and_start_journal_globally_bind_delivery_nonce(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    _, _, allocation, executor, _, journal, _, _ = _provisioned_allocation(tmp_path, monkeypatch)
    allocation_verified = _verified_allocation(allocation, "global-nonce-allocation")
    allocation_receipt = _allocation_receipt(allocation).model_copy(
        update={"idempotency_key": allocation_verified.context.idempotency_key}
    )
    allocation_attestation = _allocation_attestation(allocation, allocation_receipt)
    journal._claim_verified(allocation_verified)
    journal._begin_effect(allocation_verified)
    journal._commit_effect(allocation_verified, allocation_receipt)
    (
        materialization,
        restore_observation,
        _,
        _,
        wrapper_manifest,
        target_delivery_map,
        attach_protocol,
    ) = _materialization_intent(
        allocation,
        executor,
        allocation_receipt,
        allocation_attestation,
    )
    materialization_context = _materialization_context(
        materialization,
        allocation_attestation,
        restore_observation,
        wrapper_manifest,
        target_delivery_map,
        attach_protocol,
    )
    materialization_receipt = _materialization_receipt(materialization_context)
    verified_materialization = authorization._VerifiedMaterialization(
        context=materialization_context,
        nonce="global-nonce-materialization",
        authorized_at=_NOW,
        capability=authorization._MATERIALIZATION_VERIFIED_CAPABILITY,
    )
    policy = authorization.ReplayAuthorityPolicyV1(
        schema_version="rsd.replay-authority-policy.v1",
        service="replay-service",
        account_prefix="replay-prefix",
    )
    tombstone = authorization._materialization_operation_tombstone(policy, verified_materialization)
    assert (
        tombstone.request_nonce_sha256
        == materialization.secret_delivery_request.request_nonce_sha256
    )
    journal._claim_materialization_verified(verified_materialization)
    journal._begin_materialization_effect(verified_materialization)
    journal._commit_materialization_effect(verified_materialization, materialization_receipt)

    _, signing_key = _trusted_signer()
    reused = _start_intent(
        allocation,
        materialization,
        signer_private=signing_key,
        request_nonce_sha256=materialization.secret_delivery_request.request_nonce_sha256,
    )
    verified_start = authorization._VerifiedStartRuntime(
        context=_start_context(
            reused,
            materialization,
            materialization_receipt,
            restore_observation,
            wrapper_manifest,
            target_delivery_map,
            attach_protocol,
        ),
        nonce="global-nonce-start",
        authorized_at=_NOW,
        capability=authorization._START_RUNTIME_VERIFIED_CAPABILITY,
    )
    with pytest.raises(AuthorizationError, match="start_runtime_operation_replayed"):
        journal._claim_start_runtime_verified(verified_start)


@pytest.mark.parametrize("completed_at", ("2026-08-28T11:00:00Z", "2026-08-28T12:09:00Z"))
def test_start_runtime_receipt_uses_trusted_clock_for_stale_and_future_evidence(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
    completed_at: str,
) -> None:
    monkeypatch.setattr(
        authorization,
        "_system_utc_clock",
        lambda: datetime(2026, 8, 28, 12, 8, tzinfo=UTC),
    )
    context = _materialized_start_context(tmp_path)
    receipt = _start_effect_receipt(context).model_copy(update={"completed_at": completed_at})
    with pytest.raises(AuthorizationError, match="start_runtime_effect_receipt"):
        authorization._validate_start_runtime_effect_receipt(context, receipt)


def test_start_runtime_boundary_has_no_caller_clock_or_generic_effect() -> None:
    parameters = inspect.signature(authorize_start_runtime_and_execute).parameters

    assert "now" not in parameters
    assert "clock" not in parameters
    assert "effect" not in parameters
    assert "executor" in parameters
    assert "remote_executor_session" in parameters
    assert "secret_material" in parameters


def test_start_runtime_tls_type_drift_creates_no_artifact_root(tmp_path: Path) -> None:
    signer, signing_key, allocation, _, _, _, _, journal, policy, _ = _signed_allocation_bundle(
        tmp_path
    )
    raw = allocation.model_construct(
        **{
            **allocation.model_dump(mode="python"),
            "plan": allocation.plan.model_construct(
                **{
                    **allocation.plan.model_dump(mode="python"),
                    "transport": allocation.plan.transport.model_construct(
                        **{
                            **allocation.plan.transport.model_dump(mode="python"),
                            "profile": "tls_verified_v1",
                        }
                    ),
                }
            ),
            "signature_base64": _SIGNATURE,
        }
    )
    raw = raw.model_construct(
        **{
            **raw.model_dump(mode="python"),
            "signature_base64": base64.b64encode(
                signing_key.sign(authorization._allocation_intent_message(raw))
            ).decode("ascii"),
        }
    )
    materialization, *_ = _materialization_intent(
        allocation,
        _allocation_bundle(tmp_path)[1],
        _allocation_receipt(allocation),
        _allocation_attestation(allocation, _allocation_receipt(allocation)),
    )
    start = _start_intent(allocation, materialization, signer_private=signing_key)
    root = tmp_path / "absent-start-root"

    # A raw-string TLS form is rejected at canonical revalidation, before the
    # later explicit TLS profile stop can open an artifact root or adapter.
    with pytest.raises(AuthorizationError, match="allocation_intent_artifact"):
        authorize_start_runtime_and_execute(
            AuthorizationPaths(root=root),
            signer=signer,
            allocation_intent=raw,
            start_runtime_intent=start,
            provider=cast(Any, object()),
            expected_disposal_owner=_OWNER,
            expected_approver_identity=_APPROVER,
            journal=journal,
            executor=cast(Any, object()),
            executor_control=cast(Any, object()),
            secret_material=cast(Any, object()),
            remote_executor_session=cast(Any, object()),
            replay_authority=cast(Any, object()),
            replay_policy=policy,
        )
    assert not root.exists()


def test_v1_provider_aggregate_and_material_artifacts_are_absent() -> None:
    import omninode_rsd.lifecycle.infisical_disposable as disposable
    import omninode_rsd.lifecycle.provider_crypto as provider_crypto

    assert not hasattr(disposable, "ProviderReferencesV1")
    assert not hasattr(provider_crypto, "ProviderMaterialPolicyV1")
    assert not hasattr(provider_crypto, "ProviderFingerprintAttestationV1")
    assert not hasattr(provider_crypto, "ProviderMaterialGenesisV1")
