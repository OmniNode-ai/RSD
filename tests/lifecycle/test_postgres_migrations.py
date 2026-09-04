"""Tests for static PostgreSQL lifecycle migration resources."""

from __future__ import annotations

import re
from hashlib import sha256
from importlib import resources

import pytest

from omninode_rsd.lifecycle.postgres.migrations import (
    AppliedLifecycleMigration,
    LifecycleMigration,
    MigrationDiscoveryError,
    MigrationLedgerVerificationError,
    discover_lifecycle_migrations,
    pending_lifecycle_migrations,
)


def test_manifest_is_immutable_deterministic_and_ordered() -> None:
    first = discover_lifecycle_migrations()
    second = discover_lifecycle_migrations()

    assert first == second
    assert isinstance(first, tuple)
    assert [migration.version for migration in first] == sorted(
        migration.version for migration in first
    )
    assert len({migration.version for migration in first}) == len(first)
    assert first[0].name == "create_lifecycle_store"
    resource = resources.files("omninode_rsd.lifecycle.postgres.migrations").joinpath(
        "001_create_lifecycle_store.sql"
    )
    assert first[0].sha256 == sha256(resource.read_bytes()).hexdigest()


def test_migration_resource_is_packaged_and_checksum_changes_when_tampered() -> None:
    migration = discover_lifecycle_migrations()[0]
    resource = resources.files("omninode_rsd.lifecycle.postgres.migrations").joinpath(
        "001_create_lifecycle_store.sql"
    )

    assert resource.read_text(encoding="utf-8") == migration.content
    tampered = LifecycleMigration.from_content(
        version=migration.version,
        name=migration.name,
        content=migration.content + "-- changed\n",
    )
    assert tampered.sha256 != migration.sha256


def test_delegation_claim_migration_is_append_only_and_topology_neutral() -> None:
    migration = discover_lifecycle_migrations()[1]

    assert migration.name == "create_delegation_claims"
    assert "authorization_digest TEXT PRIMARY KEY" in migration.content
    assert "claim_binding_sha256 TEXT NOT NULL" in migration.content
    assert "delegation claims are append-only" in migration.content
    assert "REVOKE ALL ON TABLE rsd_canary.delegation_claims FROM PUBLIC" in migration.content
    assert "IF NOT EXISTS" not in migration.content
    assert "BEGIN;" not in migration.content and "COMMIT;" not in migration.content
    assert "postgresql://" not in migration.content and "os.environ" not in migration.content


def test_migration_metadata_rejects_a_digest_that_does_not_match_its_content() -> None:
    with pytest.raises(ValueError, match="does not match content"):
        LifecycleMigration(
            version=1,
            name="mismatch",
            content="SELECT 1;",
            sha256="0" * 64,
        )


def test_pending_migrations_rejects_ledger_drift_and_returns_only_the_pending_suffix() -> None:
    manifest = discover_lifecycle_migrations()
    applied = tuple(
        AppliedLifecycleMigration(
            version=migration.version,
            name=migration.name,
            checksum=migration.sha256,
        )
        for migration in manifest
    )

    assert pending_lifecycle_migrations(()) == manifest
    assert pending_lifecycle_migrations(applied) == ()
    drifted = AppliedLifecycleMigration(
        version=manifest[0].version,
        name=manifest[0].name,
        checksum="0" * 64,
    )
    with pytest.raises(MigrationLedgerVerificationError, match="checksum drift"):
        pending_lifecycle_migrations((drifted,))


def test_applied_migration_record_accepts_mapping_driver_rows_with_exact_keys() -> None:
    migration = discover_lifecycle_migrations()[0]

    class DriverRow(dict[str, object]):
        """Representative mapping subclass returned by a database driver."""

    row = DriverRow(
        version=migration.version,
        name=migration.name,
        checksum=migration.sha256,
    )

    assert AppliedLifecycleMigration.from_row(row) == AppliedLifecycleMigration(
        version=migration.version,
        name=migration.name,
        checksum=migration.sha256,
    )
    assert (
        AppliedLifecycleMigration.from_row(
            (migration.version, migration.name, migration.sha256)
        ).checksum
        == migration.sha256
    )
    with pytest.raises(MigrationLedgerVerificationError, match="unexpected shape"):
        AppliedLifecycleMigration.from_row({**row, "applied_at": "unexpected"})


def test_pending_migrations_types_each_manifest_drift_category(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    import omninode_rsd.lifecycle.postgres.migrations as migrations

    manifest = (
        LifecycleMigration.from_content(version=1, name="first", content="SELECT 1;\n"),
        LifecycleMigration.from_content(version=3, name="third", content="SELECT 3;\n"),
    )
    monkeypatch.setattr(migrations, "discover_lifecycle_migrations", lambda: manifest)

    first = AppliedLifecycleMigration(version=1, name="first", checksum=manifest[0].sha256)
    third = AppliedLifecycleMigration(version=3, name="third", checksum=manifest[1].sha256)

    with pytest.raises(MigrationLedgerVerificationError, match="duplicate version"):
        pending_lifecycle_migrations((first, first))
    with pytest.raises(MigrationLedgerVerificationError, match="version gap"):
        pending_lifecycle_migrations((third,))
    with pytest.raises(MigrationLedgerVerificationError, match="name drift"):
        pending_lifecycle_migrations(
            (AppliedLifecycleMigration(version=1, name="renamed", checksum=first.checksum),)
        )
    with pytest.raises(MigrationLedgerVerificationError, match="checksum drift"):
        pending_lifecycle_migrations(
            (AppliedLifecycleMigration(version=1, name="first", checksum="0" * 64),)
        )
    with pytest.raises(MigrationLedgerVerificationError, match="unknown version"):
        pending_lifecycle_migrations(
            (AppliedLifecycleMigration(version=2, name="second", checksum="1" * 64),)
        )
    with pytest.raises(MigrationLedgerVerificationError, match="ahead of the manifest"):
        pending_lifecycle_migrations(
            (AppliedLifecycleMigration(version=4, name="fourth", checksum="2" * 64),)
        )


def test_discovery_rejects_duplicate_migration_names(monkeypatch: pytest.MonkeyPatch) -> None:
    from importlib import resources

    import omninode_rsd.lifecycle.postgres.migrations as migrations

    class Resource:
        def __init__(self, name: str) -> None:
            self.name = name

        def read_bytes(self) -> bytes:
            return b"SELECT 1;\n"

    class Root:
        def iterdir(self) -> tuple[Resource, Resource]:
            return (Resource("001_duplicate.sql"), Resource("002_duplicate.sql"))

    monkeypatch.setattr(resources, "files", lambda _: Root())
    with pytest.raises(MigrationDiscoveryError, match="duplicate lifecycle migration name"):
        migrations.discover_lifecycle_migrations()


def test_migration_contains_required_durability_constraints_and_trigger() -> None:
    sql = discover_lifecycle_migrations()[0].content

    for fragment in (
        "CREATE SCHEMA rsd_canary",
        "CREATE TABLE rsd_canary.schema_migrations",
        "checksum TEXT NOT NULL CHECK (checksum ~ '^[0-9a-f]{64}$')",
        "event_id UUID PRIMARY KEY",
        "UNIQUE (run_id, sequence)",
        "occurred_at TIMESTAMPTZ NOT NULL",
        "event_json JSONB NOT NULL CHECK",
        "CREATE TABLE rsd_canary.lifecycle_run_heads",
        "projection_json JSONB NOT NULL CHECK",
        "CREATE INDEX lifecycle_events_run_sequence_order_idx",
        "BEFORE UPDATE OR DELETE ON rsd_canary.lifecycle_events",
        "BEFORE TRUNCATE ON rsd_canary.lifecycle_events",
        "lifecycle events are append-only",
        "FOREIGN KEY (\n        run_id, last_sequence, last_event_hash\n    )",
        "REFERENCES rsd_canary.lifecycle_events (run_id, sequence, event_hash)",
        "REVOKE ALL ON TABLE rsd_canary.lifecycle_events FROM PUBLIC",
    ):
        assert fragment in sql

    assert sql.count("^[0-9a-f]{64}$") >= 6
    assert "event_type IN ('RUN_CREATED', 'WORK_STARTED', 'WORK_COMPLETED', 'WORK_FAILED')" in sql
    assert "state IN ('INITIAL', 'CREATED', 'ACTIVE', 'COMPLETED', 'FAILED')" in sql
    assert "IF NOT EXISTS" not in sql
    assert "SECURITY DEFINER" not in sql
    assert "BEGIN;" not in sql
    assert "COMMIT;" not in sql


def test_migration_json_checks_reject_null_wrong_type_absence_and_scalar_mismatch() -> None:
    sql = discover_lifecycle_migrations()[0].content

    event_fields = {
        "schema_version": "string",
        "event_id": "string",
        "run_id": "string",
        "sequence": "number",
        "occurred_at": "string",
        "event_type": "string",
        "detail": "string",
        "prior_event_hash": "string",
        "event_hash": "string",
    }
    projection_fields = {
        "schema_version": "string",
        "run_id": "string",
        "state": "string",
        "last_sequence": "number",
        "last_event_hash": "string",
        "event_stream_hash": "string",
        "projection_checksum": "string",
    }

    for field, json_type in event_fields.items():
        assert f"(jsonb_typeof(event_json -> '{field}') = '{json_type}') IS TRUE" in sql
        assert f"event_json ->> '{field}'" in sql
    for field, json_type in projection_fields.items():
        assert f"(jsonb_typeof(projection_json -> '{field}') = '{json_type}') IS TRUE" in sql
        assert f"projection_json ->> '{field}'" in sql
    assert "(jsonb_typeof(event_json) = 'object') IS TRUE" in sql
    assert "(jsonb_typeof(projection_json) = 'object') IS TRUE" in sql
    assert "::TIMESTAMPTZ" not in sql


def test_migration_has_no_connection_configuration_or_administrative_sql() -> None:
    sql = discover_lifecycle_migrations()[0].content

    forbidden = re.compile(
        r"\b(?:GRANT|CREATE\s+(?:USER|ROLE)|ALTER\s+(?:USER|ROLE)|"
        r"PASSWORD|CREATE\s+DATABASE|TABLESPACE|OWNER\s+TO)\b",
        re.IGNORECASE,
    )
    assert forbidden.search(sql) is None
    assert (
        re.search(r"(?:os[.]environ|getenv|\$\{|postgres(?:ql)?://|localhost|[.]env)", sql, re.I)
        is None
    )
    assert (
        re.search(
            r"(?:rsd" + r"_new|10[.]|192[.]168[.]|172[.](?:1[6-9]|2[0-9]|3[0-1])[.])",
            sql,
            re.I,
        )
        is None
    )
