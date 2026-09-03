"""Executable integrity checks for the V1-to-V2 coverage manifest."""

from __future__ import annotations

import ast
import hashlib
import json
import re
import runpy
from pathlib import Path
from typing import Any

_MANIFEST_PATH = Path(__file__).with_name("v2_coverage_manifest.py")
_EXPECTED_PARENT_COMMIT = "52abe40d43c8d690c0fb6d5294c81fe47cde4e25"
_EXPECTED_PARENT_MODULE = "tests/lifecycle/test_infisical_disposable.py"
_EXPECTED_PARENT_MODULE_SOURCE_SHA256 = (
    "e22e3beb073a5fb8a25fb22f1bbd5e602185a88466b518a5f499f5c52ceaae05"
)
_EXPECTED_PARENT_INVENTORY_SHA256 = (
    "f9f9f83b6e9973902cab3afecef5d62e603e34ab7e92b594f29e7929b69b481d"
)
_SHA256 = re.compile(r"[0-9a-f]{64}\Z")

_EXPECTED_PARENT_TEST_NAMES = (
    "test_compiles_non_authorizing_value_free_receipt",
    "test_governed_composite_match_denies_even_on_shared_host",
    "test_reader_rejects_non_owner_only_artifact",
    "test_content_addressed_overlay_tampering_is_rejected",
    "test_duplicate_yaml_key_is_rejected_before_model_coercion",
    "test_candidate_rejects_shared_restore_valkey_volume",
    "test_candidate_rejects_service_to_valkey_identity_collision",
    "test_candidate_rejects_restore_service_published_authority",
    "test_proposal_rejects_transport_authority_mismatch_with_primary_candidate",
    "test_proposal_rejects_claimed_loopback_when_candidate_is_tls_lan",
    "test_unpublished_network_transport_rejects_external_address_and_dns",
    "test_proposal_accepts_candidate_bound_internal_network_transport",
    "test_postgres_identity_requires_positive_oid",
    "test_final_contract_rejects_postgres_oid_replay_tampering",
    "test_target_database_oid_and_overlay_oid_are_revalidated",
    "test_provider_snapshot_replay_is_rejected",
    "test_transport_rejects_cleartext_published_lan",
    "test_cli_blocks_without_creating_artifacts",
    "test_phase_b_executes_only_after_durable_claim",
    "test_initial_intent_is_name_only_and_transport_accepts_no_legacy_alias",
    "test_transition_rejects_cross_intent_and_changed_planned_fields",
    "test_initial_scope_cannot_be_used_as_observed_effect_authority",
    "test_initial_genesis_reconciliation_never_retries_creation",
    "test_external_initial_genesis_blocks_same_operation_at_a_new_path",
    "test_public_execution_has_no_caller_controlled_clock",
    "test_public_authorization_cannot_rewind_stale_stage_time",
    "test_phase_b_absent_journal_never_initializes_or_provisions",
    "test_missing_replay_authority_fails_before_journal_provisioning",
    "test_initial_replay_policy_is_durable_before_tombstone_and_allows_exact_recovery",
    "test_initial_replay_policy_substitution_blocks_before_external_claim",
    "test_observed_genesis_requires_completed_initial_stage_and_durable_replay_policy",
    "test_external_tombstone_blocks_local_rollback_and_deleted_operation_row",
    "test_test_replay_authority_claim_is_atomic_across_processes",
    "test_genesis_blocks_pair_removal_replay_and_identity_file_removal",
    "test_genesis_copy_or_removal_blocks_effect_before_claim",
    "test_genesis_rejects_second_provision_and_signed_mismatch",
    "test_genesis_crash_windows_require_signed_reconciliation",
    "test_phase_b_detects_legacy_journal_before_effect",
    "test_phase_b_blocks_replaced_journal_before_effect",
    "test_phase_b_pins_journal_anchor_before_provider_and_effect",
    "test_same_operation_with_fresh_nonce_executes_effect_once",
    "test_effect_failure_requires_recovery_and_never_replays",
    "test_keychain_replay_authority_is_create_only_and_stores_hashes",
    "test_replay_authority_failure_is_value_redacted_and_prevents_effect",
    "test_provider_and_effect_failures_do_not_expose_adapter_values",
    "test_owner_lock_rejects_cooperating_artifact_writer_without_waiting",
    "test_owner_lock_rejects_competing_process_without_waiting",
    "test_owner_lock_rejects_recursive_effect_lease",
    "test_owner_lock_converges_case_variants_on_same_root",
    "test_phase_b_rejects_root_or_lock_replacement_before_effect",
    "test_recovery_cannot_race_a_live_effect",
    "test_phase_b_refuses_terminal_success_after_lock_changes_during_effect",
    "test_artifact_lock_rejects_relaxed_mode_and_symlink",
    "test_phase_b_rejects_artifact_and_provider_mutation_before_effect",
    "test_phase_b_rejects_marker_only_signature_and_cli_is_read_only",
    "test_phase_b_rejects_disposal_owner_or_approval_mismatch",
    "test_external_execution_receipt_cannot_reach_internal_claim",
    "test_phase_b_rejects_marker_tampering_even_when_phase_a_hashes_are_refreshed",
    "test_phase_b_rejects_sidecar_swap_and_noncanonical_base64_alias",
    "test_provider_material_genesis_is_create_only_and_partial_state_blocks_retry",
    "test_keychain_provenance_adapter_rejects_copied_material_policy",
    "test_public_material_persistence_cannot_use_a_historical_clock",
    "test_signer_genesis_binds_keychain_seed_and_refuses_duplicate_creation",
    "test_signer_genesis_is_pinned_before_keychain_writes_and_orphans_block",
    "test_phase_b_rejects_forged_provider_attestation_before_effect",
    "test_phase_b_rejects_manual_provider_without_terminal_material_artifacts",
    "test_tls_initial_intent_never_claims_or_reaches_an_effect",
    "test_tls_rejection_has_zero_journal_or_effect_side_effects",
    "test_tls_cannot_construct_or_load_keychain_signer_or_provider_readiness",
    "test_tls_type_drift_is_blocked_before_replay_or_keychain_creation",
)


def _load_manifest() -> dict[str, Any]:
    return runpy.run_path(str(_MANIFEST_PATH))


def _test_functions(tree: ast.Module) -> dict[str, ast.FunctionDef]:
    return {
        node.name: node
        for node in tree.body
        if isinstance(node, ast.FunctionDef) and node.name.startswith("test_")
    }


def _body_hashes(source: str, node: ast.FunctionDef) -> tuple[str, str]:
    body = ast.Module(body=node.body, type_ignores=[])
    ast_hash = hashlib.sha256(
        ast.dump(body, annotate_fields=True, include_attributes=False).encode("utf-8")
    ).hexdigest()
    end = node.body[-1].end_lineno
    assert end is not None
    body_source = "".join(source.splitlines(keepends=True)[node.body[0].lineno - 1 : end])
    return ast_hash, hashlib.sha256(body_source.encode("utf-8")).hexdigest()


def _is_pytest_skip_decorator(decorator: ast.expr) -> bool:
    target = decorator.func if isinstance(decorator, ast.Call) else decorator
    if isinstance(target, ast.Name):
        return target.id in {"skip", "skipif"}
    if isinstance(target, ast.Attribute):
        return target.attr in {"skip", "skipif"}
    return False


def _has_executable_body(node: ast.FunctionDef) -> bool:
    statements = list(node.body)
    if (
        statements
        and isinstance(statements[0], ast.Expr)
        and isinstance(statements[0].value, ast.Constant)
        and isinstance(statements[0].value.value, str)
    ):
        statements.pop(0)
    return bool(statements) and not all(isinstance(statement, ast.Pass) for statement in statements)


def test_v2_coverage_manifest_is_exact_and_one_to_one() -> None:
    manifest_module = _load_manifest()
    rows = manifest_module["COVERAGE_MANIFEST"]
    assert manifest_module["PARENT_COMMIT"] == _EXPECTED_PARENT_COMMIT
    assert manifest_module["PARENT_MODULE"] == _EXPECTED_PARENT_MODULE
    assert manifest_module["PARENT_MODULE_SOURCE_SHA256"] == _EXPECTED_PARENT_MODULE_SOURCE_SHA256
    assert manifest_module["PARENT_INVENTORY_SHA256"] == _EXPECTED_PARENT_INVENTORY_SHA256
    assert isinstance(rows, tuple)
    assert len(rows) == len(_EXPECTED_PARENT_TEST_NAMES) == 70
    assert tuple(row["parent_name"] for row in rows) == _EXPECTED_PARENT_TEST_NAMES
    assert len({row["parent_name"] for row in rows}) == 70
    assert tuple(manifest_module["PARENT_TEST_NAMES"]) == _EXPECTED_PARENT_TEST_NAMES

    historical_inventory = []
    target_ids: set[tuple[str, str]] = set()
    repository_root = Path(__file__).parents[2]
    for row in rows:
        assert set(row) == {
            "parent_name",
            "parent_ast_sha256",
            "parent_source_sha256",
            "disposition",
            "invariant",
            "target_module",
            "target_function",
            "target_ast_sha256",
            "target_source_sha256",
        }
        assert row["disposition"] in {"migrated", "retired"}
        assert row["invariant"] == row["parent_name"].removeprefix("test_").replace("_", " ")
        assert all(
            _SHA256.fullmatch(row[field])
            for field in (
                "parent_ast_sha256",
                "parent_source_sha256",
                "target_ast_sha256",
                "target_source_sha256",
            )
        )
        historical_inventory.append(
            {
                "name": row["parent_name"],
                "ast": row["parent_ast_sha256"],
                "source": row["parent_source_sha256"],
            }
        )
        module = Path(row["target_module"])
        assert not module.is_absolute() and ".." not in module.parts
        assert module.parts[:2] == ("tests", "lifecycle")
        assert module.name.startswith("test_") and module.suffix == ".py"
        target_path = repository_root / module
        assert target_path.is_file()
        target_source = target_path.read_text(encoding="utf-8")
        target = _test_functions(ast.parse(target_source)).get(row["target_function"])
        assert target is not None
        assert target.name.startswith("test_")
        assert not any(_is_pytest_skip_decorator(item) for item in target.decorator_list)
        assert _has_executable_body(target)
        target_id = (row["target_module"], row["target_function"])
        assert target_id not in target_ids
        target_ids.add(target_id)
        assert _body_hashes(target_source, target) == (
            row["target_ast_sha256"],
            row["target_source_sha256"],
        )

    assert len(target_ids) == 70
    actual_inventory_sha256 = hashlib.sha256(
        json.dumps(historical_inventory, sort_keys=True, separators=(",", ":")).encode("utf-8")
    ).hexdigest()
    assert actual_inventory_sha256 == _EXPECTED_PARENT_INVENTORY_SHA256
