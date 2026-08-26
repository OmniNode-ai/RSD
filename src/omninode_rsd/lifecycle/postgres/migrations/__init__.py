"""Versioned lifecycle migrations and fail-closed ledger metadata.

The packaged manifest is pure resource metadata.  A caller-supplied PostgreSQL
adapter owns applying it in a transaction; this module never discovers a
database endpoint or reads runtime configuration.
"""

from __future__ import annotations

import re
from collections.abc import Mapping
from dataclasses import dataclass
from hashlib import sha256
from importlib import resources
from typing import Final

_MIGRATIONS_PACKAGE: Final[str] = "omninode_rsd.lifecycle.postgres.migrations"
_MIGRATION_FILENAME: Final[re.Pattern[str]] = re.compile(
    r"(?P<version>[0-9]{3,})_(?P<name>[a-z][a-z0-9_]*)[.]sql\Z"
)
_SHA256: Final[re.Pattern[str]] = re.compile(r"[0-9a-f]{64}\Z")
_MIGRATION_NAME: Final[re.Pattern[str]] = re.compile(r"[a-z][a-z0-9_]*\Z")
_LEDGER_COLUMNS: Final[tuple[str, str, str]] = ("version", "name", "checksum")


class MigrationDiscoveryError(RuntimeError):
    """Raised when packaged migration resources do not meet the manifest contract."""


class MigrationLedgerVerificationError(RuntimeError):
    """Raised when applied migration records drift from the packaged manifest."""


@dataclass(frozen=True, slots=True)
class LifecycleMigration:
    """One immutable, operator-applied migration resource."""

    version: int
    name: str
    content: str
    sha256: str

    @classmethod
    def from_content(cls, *, version: int, name: str, content: str) -> LifecycleMigration:
        """Create metadata and its digest from a UTF-8 SQL resource."""

        return cls(
            version=version,
            name=name,
            content=content,
            sha256=sha256(content.encode("utf-8")).hexdigest(),
        )

    @classmethod
    def from_bytes(cls, *, version: int, name: str, content: bytes) -> LifecycleMigration:
        """Create metadata from the exact UTF-8 bytes packaged for an operator."""

        try:
            decoded = content.decode("utf-8")
        except UnicodeDecodeError as error:
            raise MigrationDiscoveryError("lifecycle migration is not UTF-8") from error
        return cls(
            version=version,
            name=name,
            content=decoded,
            sha256=sha256(content).hexdigest(),
        )

    def __post_init__(self) -> None:
        if self.version < 1:
            raise ValueError("migration version must be positive")
        if _MIGRATION_NAME.fullmatch(self.name) is None:
            raise ValueError("migration name must be lowercase snake case")
        if not self.content:
            raise ValueError("migration content must not be empty")
        if _SHA256.fullmatch(self.sha256) is None:
            raise ValueError("migration SHA-256 must be a lowercase digest")
        if self.sha256 != sha256(self.content.encode("utf-8")).hexdigest():
            raise ValueError("migration SHA-256 does not match content")


@dataclass(frozen=True, slots=True)
class AppliedLifecycleMigration:
    """One exact row from the durable lifecycle migration ledger.

    Ledger rows deliberately contain only the immutable manifest identity and
    checksum.  They never carry packaged SQL content, so verification compares
    database evidence to the locally packaged manifest without accepting a
    database-supplied replacement resource.
    """

    version: int
    name: str
    checksum: str

    def __post_init__(self) -> None:
        if type(self.version) is not int or self.version < 1:
            raise ValueError("applied migration version must be a positive integer")
        if type(self.name) is not str or _MIGRATION_NAME.fullmatch(self.name) is None:
            raise ValueError("applied migration name must be lowercase snake case")
        if type(self.checksum) is not str or _SHA256.fullmatch(self.checksum) is None:
            raise ValueError("applied migration checksum must be a lowercase digest")

    @classmethod
    def from_row(cls, row: Mapping[str, object] | tuple[object, ...]) -> AppliedLifecycleMigration:
        """Construct one typed record from an exact ledger result row."""

        if type(row) is tuple:
            if len(row) != len(_LEDGER_COLUMNS):
                raise MigrationLedgerVerificationError(
                    "applied migration ledger row has an unexpected shape"
                )
            values = dict(zip(_LEDGER_COLUMNS, row, strict=True))
        elif isinstance(row, Mapping) and set(row) == set(_LEDGER_COLUMNS):
            values = {column: row[column] for column in _LEDGER_COLUMNS}
        else:
            raise MigrationLedgerVerificationError(
                "applied migration ledger row has an unexpected shape"
            )
        version = values["version"]
        name = values["name"]
        checksum = values["checksum"]
        if type(version) is not int or type(name) is not str or type(checksum) is not str:
            raise MigrationLedgerVerificationError("applied migration ledger row is not valid")
        try:
            return cls(version=version, name=name, checksum=checksum)
        except ValueError as error:
            raise MigrationLedgerVerificationError(
                "applied migration ledger row is not valid"
            ) from error


def discover_lifecycle_migrations() -> tuple[LifecycleMigration, ...]:
    """Return packaged lifecycle migrations in deterministic numeric order.

    This function reads package resources only. It does not inspect environment
    variables, construct a connection string, or execute any SQL.
    """

    try:
        resources_root = resources.files(_MIGRATIONS_PACKAGE)
        files = sorted(
            (resource for resource in resources_root.iterdir() if resource.name.endswith(".sql")),
            key=lambda resource: resource.name,
        )
    except (ModuleNotFoundError, OSError) as exc:
        raise MigrationDiscoveryError("packaged lifecycle migrations are unavailable") from exc

    migrations: list[LifecycleMigration] = []
    versions: set[int] = set()
    names: set[str] = set()
    for resource in files:
        match = _MIGRATION_FILENAME.fullmatch(resource.name)
        if match is None:
            raise MigrationDiscoveryError(f"invalid lifecycle migration filename: {resource.name}")
        version = int(match["version"])
        if version < 1:
            raise MigrationDiscoveryError(f"invalid lifecycle migration version: {resource.name}")
        if version in versions:
            raise MigrationDiscoveryError(f"duplicate lifecycle migration version: {version}")
        versions.add(version)
        name = match["name"]
        if name in names:
            raise MigrationDiscoveryError(f"duplicate lifecycle migration name: {name}")
        names.add(name)
        try:
            content = resource.read_bytes()
        except OSError as exc:
            raise MigrationDiscoveryError(
                f"cannot read lifecycle migration resource: {resource.name}"
            ) from exc
        migrations.append(
            LifecycleMigration.from_bytes(version=version, name=name, content=content)
        )

    if not migrations:
        raise MigrationDiscoveryError("no packaged lifecycle migrations found")
    return tuple(sorted(migrations, key=lambda migration: migration.version))


def pending_lifecycle_migrations(
    applied: tuple[AppliedLifecycleMigration, ...],
) -> tuple[LifecycleMigration, ...]:
    """Fail closed on ledger drift and return the exact pending migration suffix.

    The applied rows must be an exact ordered prefix of the packaged manifest.
    Duplicate, gap, unknown, ahead-of-manifest, name, and checksum drift are
    rejected before any packaged SQL can execute.
    """

    if type(applied) is not tuple:
        raise MigrationLedgerVerificationError("applied migration ledger must be a tuple")
    manifest = discover_lifecycle_migrations()
    applied_versions: set[int] = set()
    applied_names: set[str] = set()
    manifest_versions = {migration.version for migration in manifest}
    highest_manifest_version = manifest[-1].version
    for actual in applied:
        if type(actual) is not AppliedLifecycleMigration:
            raise MigrationLedgerVerificationError(
                "applied migration ledger must contain applied migration records"
            )
        if actual.version in applied_versions:
            raise MigrationLedgerVerificationError(
                "applied migration ledger has a duplicate version"
            )
        if actual.name in applied_names:
            raise MigrationLedgerVerificationError("applied migration ledger has a duplicate name")
        applied_versions.add(actual.version)
        applied_names.add(actual.name)
        if actual.version > highest_manifest_version:
            raise MigrationLedgerVerificationError(
                "applied migration ledger is ahead of the manifest"
            )
        if actual.version not in manifest_versions:
            raise MigrationLedgerVerificationError(
                "applied migration ledger has an unknown version"
            )
    if len(applied) > len(manifest):
        raise MigrationLedgerVerificationError("applied migration ledger is ahead of the manifest")
    for expected, actual in zip(manifest[: len(applied)], applied, strict=True):
        if actual.version != expected.version:
            raise MigrationLedgerVerificationError("applied migration ledger has a version gap")
        if actual.name != expected.name:
            raise MigrationLedgerVerificationError("applied migration ledger has name drift")
        if actual.checksum != expected.sha256:
            raise MigrationLedgerVerificationError("applied migration ledger has checksum drift")
    return manifest[len(applied) :]
