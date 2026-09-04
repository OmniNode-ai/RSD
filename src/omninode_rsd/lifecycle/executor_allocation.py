"""Sealed, zero-secret allocation backend for a Linux Docker Engine.

This module is deliberately narrower than a general Docker client.  It is
the only concrete mutation adapter in this repository, and it can allocate
two internal networks, two named local volumes, and the already-authorized
empty PostgreSQL objects.  It has no API for runtime container creation,
secret delivery, cleanup, adoption, restart, or arbitrary Engine/psql calls.

The public factory descriptor-loads signed allocation artifacts before it
constructs an adapter.  Tests use the test-only fake factory; production callers
cannot pass a socket path, HTTP path, SQL command, or execution callback.
"""

from __future__ import annotations

import base64
import binascii
import hashlib
import json
import math
import os
import re
import socket
import stat
import struct
import time
from collections.abc import Callable, Mapping, Sequence
from contextlib import suppress
from dataclasses import dataclass, field
from datetime import UTC, datetime
from enum import StrEnum
from pathlib import Path
from typing import TYPE_CHECKING, Final, Literal, Protocol, cast
from urllib.parse import quote

import yaml
from cryptography.exceptions import InvalidSignature
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PublicKey
from pydantic import BaseModel, ConfigDict, Field, ValidationError, field_validator, model_validator

from omninode_rsd.lifecycle.authorization import (
    AuthorizationPaths,
    TrustedEd25519SignerV1,
    _verify_allocation_control_policy_bindings,
    _verify_allocation_intent_signature,
    _verify_docker_engine_control_policy_signature,
    _verify_executor_control_policy_signature,
    _verify_postgres_control_policy_signature,
    _verify_postgres_prepared_control_policy_signature,
)
from omninode_rsd.lifecycle.executor_transport import (
    ExecutorEngineOperationKindV1,
    ExecutorEngineOperationTargetV1,
    VerifiedExecutorTransportArtifactsV2,
)
from omninode_rsd.lifecycle.infisical_disposable import (
    AllocatedNetworkObservationV1,
    AllocatedPostgreSQLObservationV1,
    AllocatedResourceSetV2,
    AllocatedVolumeObservationV1,
    AllocationIntentV2,
    AllocationVolumePlanV1,
    DockerEngineControlPolicyV1,
    DockerEngineFilteredProjectionV1,
    DockerImageLocalEvidenceV1,
    DockerImagePolicyV1,
    EngineIdentityObservationV1,
    ImageReferenceV1,
    IsolatedNetworkPlanV1,
    NetworkOptionV1,
    NoHostPublicationGroundworkV1,
    PostgreSQLControlPolicyV1,
    PostgreSQLGrantObservationV1,
    PostgreSQLPreparedControlPolicyV2,
    PostgreSQLRoleObservationV1,
    _strict_canonical_model,
    _UniqueLoader,
    canonical_sha256,
    docker_engine_fingerprint_sha256,
    docker_unix_socket_identity_sha256,
    docker_volume_instance_fingerprint_sha256,
    expected_docker_image_local_evidence,
    strict_canonical_allocation_intent,
)

if TYPE_CHECKING:
    from omninode_rsd.lifecycle.executor_daemon import (
        AllocationExecutorBackendContextV1,
        ExecutorAllocationBackendEvidenceV1,
        ExecutorBackendReceiptV2,
        ExecutorEngineOperationClaimV1,
    )


_SHA256: Final = r"^[0-9a-f]{64}$"
_IDENTIFIER: Final = r"^[A-Za-z][A-Za-z0-9_.-]{0,127}$"
_CONTAINER_ID: Final = r"^[0-9a-f]{64}$"
_API_VERSION: Final = r"^[0-9]{1,3}\.[0-9]{1,3}$"
_MAX_HEADERS: Final = 16_384
_ALLOCATION_BACKEND_CAPABILITY: Final = object()
_POSTGRES_RESULT_DOMAIN: Final = b"omninode-rsd.postgresql-allocation-result.v1\x00"
_RECONCILIATION_DOMAIN: Final = b"omninode-rsd.allocation-reconciliation.v1\x00"
_POSTGRES_TEMPLATE_DOMAIN: Final = b"omninode-rsd.postgresql-allocation-template.v1\x00"
_POSTGRES_RESULT_SCHEMA_DOMAIN: Final = b"omninode-rsd.postgresql-allocation-result-schema.v1\x00"
_SHA256SUM_ABSOLUTE_PATH: Final = "/usr/bin/sha256sum"


class AllocationBackendError(RuntimeError):
    """A value-redacted, fail-closed allocation backend error."""

    def __init__(self, phase: str, *, _not_found: bool = False) -> None:
        self.phase = phase
        # This is deliberately only an internal branch signal for the
        # read-only reconciler. It never changes the public error text or
        # exposes an Engine response, path, or status value.
        self._not_found = _not_found
        super().__init__(f"allocation backend failed at phase: {phase}")


def _is_confirmed_not_found(error: AllocationBackendError) -> bool:
    """Accept absence only for a fully parsed canonical Engine 404 response."""

    return (
        type(error) is AllocationBackendError
        and error.phase == "engine_status"
        and error._not_found
    )


class _Model(BaseModel):
    model_config = ConfigDict(extra="forbid", frozen=True, strict=True, validate_default=True)


def _system_utc_clock() -> datetime:
    """The non-injectable production clock; tests patch this module helper."""

    return datetime.now(UTC)


def _digest(value: bytes | bytearray | memoryview) -> str:
    return hashlib.sha256(value).hexdigest()


def _canonical_json(value: object) -> bytes:
    try:
        return json.dumps(
            value,
            allow_nan=False,
            ensure_ascii=True,
            sort_keys=True,
            separators=(",", ":"),
        ).encode("ascii")
    except (TypeError, ValueError):
        raise AllocationBackendError("canonical_encoding") from None


_ALLOCATION_SQL_TEMPLATES: Final[tuple[tuple[str, str], ...]] = (
    (
        "roles",
        "DO $$ BEGIN\n"
        "IF EXISTS (SELECT 1 FROM pg_roles WHERE rolname IN "
        "('{owner_literal}','{application_literal}')) THEN\n"
        "  RAISE EXCEPTION 'allocation role collision';\n"
        "END IF;\n"
        "CREATE ROLE {owner_identifier} NOLOGIN NOSUPERUSER NOCREATEDB "
        "NOCREATEROLE NOINHERIT NOREPLICATION NOBYPASSRLS;\n"
        "CREATE ROLE {application_identifier} NOLOGIN NOSUPERUSER NOCREATEDB "
        "NOCREATEROLE NOINHERIT NOREPLICATION NOBYPASSRLS;\n"
        "END $$;\n",
    ),
    (
        "database",
        "CREATE DATABASE {database_identifier} OWNER {owner_identifier};\n",
    ),
    (
        "schema_prefix",
        "\\connect {database_identifier}\n"
        "CREATE SCHEMA {schema_identifier} AUTHORIZATION {owner_identifier};\n"
        "SET ROLE {owner_identifier};\n",
    ),
    ("schema_grant", "GRANT {privilege} ON SCHEMA {schema_identifier} TO {grantee_identifier};\n"),
    (
        "default_table_grant",
        "ALTER DEFAULT PRIVILEGES FOR ROLE {role_identifier} IN SCHEMA {schema_identifier} "
        "GRANT {privilege} ON TABLES TO {grantee_identifier};\n",
    ),
    ("schema_suffix", "RESET ROLE;\n"),
    (
        "expected_grant_empty",
        "SELECT NULL::text AS role, NULL::text AS grantee, NULL::text AS privilege, "
        "NULL::text AS schema_name WHERE FALSE",
    ),
    (
        "expected_grant_row",
        "SELECT '{role_literal}'::text AS role, '{grantee_literal}'::text AS grantee, "
        "'{privilege}'::text AS privilege, '{schema_literal}'::text AS schema_name",
    ),
    (
        "schema_grant_matches",
        "SELECT expected.role, expected.grantee, expected.privilege, expected.schema_name "
        "FROM expected_grants AS expected "
        "WHERE expected.privilege IN ('USAGE','CREATE') AND EXISTS ("
        "SELECT 1 FROM pg_namespace AS namespace "
        "CROSS JOIN LATERAL aclexplode(namespace.nspacl) AS acl "
        "JOIN pg_roles AS grantor ON grantor.oid = acl.grantor "
        "JOIN pg_roles AS grantee_role ON grantee_role.oid = acl.grantee "
        "WHERE namespace.nspname = expected.schema_name "
        "AND grantor.rolname = expected.role "
        "AND grantee_role.rolname = expected.grantee "
        "AND acl.privilege_type = expected.privilege "
        "AND acl.is_grantable IS FALSE)",
    ),
    (
        "default_table_grant_matches",
        "SELECT expected.role, expected.grantee, expected.privilege, expected.schema_name "
        "FROM expected_grants AS expected "
        "WHERE expected.privilege IN ('SELECT','INSERT','UPDATE','DELETE') AND EXISTS ("
        "SELECT 1 FROM pg_default_acl AS defaults "
        "JOIN pg_namespace AS namespace ON namespace.oid = defaults.defaclnamespace "
        "JOIN pg_roles AS default_owner ON default_owner.oid = defaults.defaclrole "
        "CROSS JOIN LATERAL aclexplode(defaults.defaclacl) AS acl "
        "JOIN pg_roles AS grantor ON grantor.oid = acl.grantor "
        "JOIN pg_roles AS grantee_role ON grantee_role.oid = acl.grantee "
        "WHERE defaults.defaclobjtype = 'r' "
        "AND namespace.nspname = expected.schema_name "
        "AND default_owner.rolname = expected.role "
        "AND grantor.rolname = expected.role "
        "AND grantee_role.rolname = expected.grantee "
        "AND acl.privilege_type = expected.privilege "
        "AND acl.is_grantable IS FALSE)",
    ),
    (
        "role_projection",
        "SELECT json_agg(json_build_object('role', rolname, 'role_oid', oid, "
        "'can_login', rolcanlogin, 'password_absent', rolpassword IS NULL) "
        "ORDER BY CASE rolname WHEN '{owner_literal}' THEN 0 "
        "WHEN '{application_literal}' THEN 1 ELSE 2 END) "
        "FROM pg_roles WHERE rolname IN ('{owner_literal}','{application_literal}')",
    ),
    (
        "grant_projection",
        "SELECT COALESCE(json_agg(json_build_object('role', role, 'grantee', grantee, "
        "'privilege', privilege, 'schema_name', schema_name) "
        "ORDER BY role, grantee, privilege, schema_name), '[]'::json) FROM grants",
    ),
    (
        "observation",
        "\\connect {database_identifier}\nCOPY (\n"
        "WITH expected_grants AS ({expected_grants}),\n"
        "schema_grants AS ({schema_grants}),\n"
        "default_table_grants AS ({default_table_grants}),\n"
        "grants AS ({schema_grants} UNION ALL {default_table_grants})\n"
        "SELECT json_build_object(\n"
        " 'system_identifier', (SELECT system_identifier::text FROM pg_control_system()),\n"
        " 'database_name', current_database(),\n"
        " 'database_oid', (SELECT oid FROM pg_database WHERE datname = current_database()),\n"
        " 'schema_name', '{schema_literal}',\n"
        " 'schema_oid', (SELECT oid FROM pg_namespace WHERE nspname = '{schema_literal}'),\n"
        " 'owner_role', '{owner_literal}',\n"
        " 'owner_role_oid', (SELECT oid FROM pg_roles WHERE rolname = '{owner_literal}'),\n"
        " 'application_role', '{application_literal}',\n"
        " 'application_role_oid', (SELECT oid FROM pg_roles WHERE rolname = "
        "'{application_literal}'),\n"
        " 'password_encryption', current_setting('password_encryption'),\n"
        " 'log_statement', current_setting('log_statement'),\n"
        " 'role_oids', ({role_projection}),\n"
        " 'grants', ({grant_projection})\n"
        ")::text\n) TO STDOUT;\n",
    ),
)

_ALLOCATION_RESULT_FIELDS: Final[tuple[str, ...]] = (
    "system_identifier",
    "database_name",
    "database_oid",
    "schema_name",
    "schema_oid",
    "owner_role",
    "owner_role_oid",
    "application_role",
    "application_role_oid",
    "password_encryption",
    "log_statement",
    "role_oids",
    "grants",
)


def _allocation_sql_template(name: str) -> str:
    for candidate, template in _ALLOCATION_SQL_TEMPLATES:
        if candidate == name:
            return template
    raise AllocationBackendError("postgres_template")


def _render_allocation_sql(name: str, **fields: str) -> str:
    try:
        return _allocation_sql_template(name).format(**fields)
    except (KeyError, ValueError):
        raise AllocationBackendError("postgres_template") from None


def allocation_postgres_template_bundle_sha256() -> str:
    """Return the signed digest of every static allocation SQL template.

    Dynamic values are only canonical identifiers or the signed grant plan.
    All executable static SQL lives in ``_ALLOCATION_SQL_TEMPLATES`` so a
    source change to any template necessarily changes this policy commitment.
    """

    return _digest(
        _POSTGRES_TEMPLATE_DOMAIN
        + _canonical_json(
            {
                "identifier_quoting": "strict_double_quote_v1",
                "psql_stdin_protocol": "postgresql_prepared_psql_stdin_v1",
                "schema_version": "rsd.postgresql-allocation-template-bundle.v1",
                "templates": dict(_ALLOCATION_SQL_TEMPLATES),
            }
        )
    )


def allocation_postgres_result_schema_sha256() -> str:
    """Return the exact value-free PostgreSQL observation schema commitment."""

    return _digest(
        _POSTGRES_RESULT_SCHEMA_DOMAIN
        + _canonical_json(
            {
                "fields": _ALLOCATION_RESULT_FIELDS,
                "roles": (
                    "database_owner_nologin_password_absent,application_nologin_password_absent"
                ),
                "schema_version": "rsd.postgresql-allocation-observation.v1",
            }
        )
    )


def _require_allocation_prepared_binding(policy: PostgreSQLPreparedControlPolicyV2) -> None:
    """Reject a signed policy whose allocation template is not this backend."""

    try:
        operation = policy.operations[0]
        if (
            operation.kind != "allocation_nologin_v1"
            or operation.secret_input is not False
            or operation.stdin_protocol != "postgresql_prepared_psql_stdin_v1"
            or operation.psql_template_sha256 != allocation_postgres_template_bundle_sha256()
            or operation.result_projection_sha256 != allocation_postgres_result_schema_sha256()
        ):
            raise ValueError
    except (AttributeError, IndexError, ValueError):
        raise AllocationBackendError("postgres_template") from None


def _timestamp(value: object) -> str:
    """Normalize a Docker RFC3339 timestamp without passing it outward raw."""

    if type(value) is not str or len(value) > 64:
        raise AllocationBackendError("engine_projection")
    try:
        parsed = datetime.fromisoformat(value.removesuffix("Z") + "+00:00")
    except ValueError:
        raise AllocationBackendError("engine_projection") from None
    if parsed.tzinfo is None or parsed.utcoffset() is None:
        raise AllocationBackendError("engine_projection")
    return parsed.astimezone(UTC).isoformat(timespec="microseconds").replace("+00:00", "Z")


def _require_identifier(value: object, *, phase: str) -> str:
    if type(value) is not str or re.fullmatch(_IDENTIFIER, value) is None:
        raise AllocationBackendError(phase)
    return value


def _require_container_id(value: object, *, phase: str) -> str:
    if type(value) is not str or re.fullmatch(_CONTAINER_ID, value) is None:
        raise AllocationBackendError(phase)
    return value


def _quote_identifier(value: object) -> str:
    """Render only an already strict SQL identifier; never accept SQL text."""

    identifier = _require_identifier(value, phase="postgres_identifier")
    return f'"{identifier}"'


def _options_map(options: Sequence[NetworkOptionV1]) -> dict[str, str]:
    return {item.key: item.value for item in options}


def _projection_sha256(value: BaseModel | Mapping[str, object]) -> str:
    if isinstance(value, BaseModel):
        payload: object = value.model_dump(mode="json")
    else:
        payload = value
    return _digest(_canonical_json(payload))


@dataclass(frozen=True, slots=True)
class AllocationBackendArtifactPathsV1:
    """Fixed owner-only artifact root for the concrete allocation adapter."""

    root: Path

    def __post_init__(self) -> None:
        if not isinstance(self.root, Path) or not self.root.is_absolute():
            raise AllocationBackendError("allocation_artifacts")

    @staticmethod
    def allocation_intent_name() -> str:
        return AuthorizationPaths.allocation_intent_name()

    @staticmethod
    def executor_control_policy_name() -> str:
        return AuthorizationPaths.executor_control_policy_name()

    @staticmethod
    def docker_engine_control_policy_name() -> str:
        return AuthorizationPaths.docker_engine_control_policy_name()

    @staticmethod
    def postgres_control_policy_name() -> str:
        return AuthorizationPaths.postgres_control_policy_name()

    @staticmethod
    def postgres_prepared_control_policy_name() -> str:
        return AuthorizationPaths.postgres_prepared_control_policy_name()


class _OwnerOnlyAllocationArtifacts:
    """Descriptor-relative loader for the backend's fixed non-secret files."""

    def __init__(self, root: Path) -> None:
        self._root = root
        self._root_fd: int | None = None
        self._identity: tuple[int, int] | None = None

    def __enter__(self) -> _OwnerOnlyAllocationArtifacts:
        try:
            before = os.lstat(self._root)
            if (
                not stat.S_ISDIR(before.st_mode)
                or before.st_uid != os.geteuid()
                or stat.S_IMODE(before.st_mode) != 0o700
            ):
                raise ValueError
            fd = os.open(
                self._root,
                os.O_RDONLY | getattr(os, "O_DIRECTORY", 0) | getattr(os, "O_CLOEXEC", 0),
            )
            after = os.fstat(fd)
            if (before.st_dev, before.st_ino) != (after.st_dev, after.st_ino):
                os.close(fd)
                raise ValueError
            self._root_fd = fd
            self._identity = (after.st_dev, after.st_ino)
            return self
        except (OSError, ValueError):
            raise AllocationBackendError("allocation_artifacts") from None

    def __exit__(self, *_: object) -> None:
        if self._root_fd is not None:
            with suppress(OSError):
                os.close(self._root_fd)
        self._root_fd = None
        self._identity = None

    def _require_root(self) -> int:
        if self._root_fd is None or self._identity is None:
            raise AllocationBackendError("allocation_artifacts")
        try:
            current = os.fstat(self._root_fd)
        except OSError:
            raise AllocationBackendError("allocation_artifacts") from None
        if (current.st_dev, current.st_ino) != self._identity:
            raise AllocationBackendError("allocation_artifacts")
        return self._root_fd

    def read(self, name: str) -> bytes:
        if type(name) is not str or "/" in name or name.startswith("."):
            raise AllocationBackendError("allocation_artifacts")
        root_fd = self._require_root()
        file_fd: int | None = None
        try:
            before = os.lstat(name, dir_fd=root_fd)
            if (
                not stat.S_ISREG(before.st_mode)
                or before.st_uid != os.geteuid()
                or stat.S_IMODE(before.st_mode) != 0o600
                or before.st_nlink != 1
                or before.st_size < 1
                or before.st_size > 131_072
            ):
                raise ValueError
            file_fd = os.open(
                name,
                os.O_RDONLY | getattr(os, "O_NOFOLLOW", 0) | getattr(os, "O_CLOEXEC", 0),
                dir_fd=root_fd,
            )
            after = os.fstat(file_fd)
            if (before.st_dev, before.st_ino) != (after.st_dev, after.st_ino):
                raise ValueError
            chunks: list[bytes] = []
            total = 0
            while chunk := os.read(file_fd, 65_536):
                total += len(chunk)
                if total > 131_072:
                    raise ValueError
                chunks.append(chunk)
            return b"".join(chunks)
        except (OSError, ValueError):
            raise AllocationBackendError("allocation_artifacts") from None
        finally:
            if file_fd is not None:
                with suppress(OSError):
                    os.close(file_fd)


def _load_yaml_model(raw: bytes, model_type: type[BaseModel]) -> BaseModel:
    try:
        parsed = yaml.load(raw.decode("utf-8"), Loader=_UniqueLoader)
        if type(parsed) is not dict:
            raise ValueError
        model = model_type.model_validate(parsed)
        return _strict_canonical_model(model, model_type)
    except (UnicodeDecodeError, ValidationError, ValueError, TypeError, yaml.YAMLError):
        raise AllocationBackendError("allocation_artifacts") from None


@dataclass(frozen=True, slots=True)
class VerifiedAllocationBackendArtifactsV1:
    """Opaque allocation policy bundle admitted only by the sealed loader."""

    intent: AllocationIntentV2
    docker: DockerEngineControlPolicyV1
    postgres: PostgreSQLControlPolicyV1
    postgres_prepared: PostgreSQLPreparedControlPolicyV2
    transport: VerifiedExecutorTransportArtifactsV2
    _capability: object = field(repr=False, compare=False)

    def __post_init__(self) -> None:
        if self._capability is not _ALLOCATION_BACKEND_CAPABILITY:
            raise AllocationBackendError("allocation_artifacts")


def load_verified_allocation_backend_artifacts(
    paths: AllocationBackendArtifactPathsV1,
    *,
    signer: TrustedEd25519SignerV1,
    transport: VerifiedExecutorTransportArtifactsV2,
) -> VerifiedAllocationBackendArtifactsV1:
    """Re-open and bind all allocation controls before any Engine connection.

    The transport bundle proves the signed executor installation and signer
    genesis.  This loader independently reopens the allocation intent and
    controls through a no-follow owner-only descriptor, so a daemon cannot be
    pointed at an ambient socket or caller-built policy object.
    """

    from omninode_rsd.lifecycle.infisical_disposable import ExecutorControlPolicyV1

    if (
        type(paths) is not AllocationBackendArtifactPathsV1
        or type(signer) is not TrustedEd25519SignerV1
        or type(transport) is not VerifiedExecutorTransportArtifactsV2
    ):
        raise AllocationBackendError("allocation_artifacts")
    try:
        with _OwnerOnlyAllocationArtifacts(paths.root) as reader:
            intent = cast(
                AllocationIntentV2,
                _load_yaml_model(reader.read(paths.allocation_intent_name()), AllocationIntentV2),
            )
            executor = cast(
                ExecutorControlPolicyV1,
                _load_yaml_model(
                    reader.read(paths.executor_control_policy_name()), ExecutorControlPolicyV1
                ),
            )
            docker = cast(
                DockerEngineControlPolicyV1,
                _load_yaml_model(
                    reader.read(paths.docker_engine_control_policy_name()),
                    DockerEngineControlPolicyV1,
                ),
            )
            postgres = cast(
                PostgreSQLControlPolicyV1,
                _load_yaml_model(
                    reader.read(paths.postgres_control_policy_name()), PostgreSQLControlPolicyV1
                ),
            )
            postgres_prepared = cast(
                PostgreSQLPreparedControlPolicyV2,
                _load_yaml_model(
                    reader.read(paths.postgres_prepared_control_policy_name()),
                    PostgreSQLPreparedControlPolicyV2,
                ),
            )
        intent = strict_canonical_allocation_intent(intent)
        _verify_allocation_intent_signature(intent, signer=signer)
        _verify_executor_control_policy_signature(executor, signer=signer)
        _verify_docker_engine_control_policy_signature(docker, signer=signer)
        _verify_postgres_control_policy_signature(postgres, signer=signer)
        _verify_postgres_prepared_control_policy_signature(postgres_prepared, signer=signer)
        _verify_allocation_control_policy_bindings(
            intent=intent,
            executor=executor,
            docker=docker,
            postgres=postgres,
            postgres_prepared=postgres_prepared,
            signer=signer,
        )
        _require_allocation_prepared_binding(postgres_prepared)
        genesis = transport.signer_genesis
        if (
            intent != strict_canonical_allocation_intent(intent)
            or transport.policy.allocation_intent_sha256 != canonical_sha256(intent)
            or genesis.allocation_intent_sha256 != canonical_sha256(intent)
            or genesis.key_id != signer.key_id
            or genesis.public_key_fingerprint_sha256 != signer.public_key_fingerprint_sha256
            or executor.executor != transport.installation_policy.executor
            or executor.installation_policy_sha256
            != canonical_sha256(transport.installation_policy)
            or docker.executor_identity_sha256 != canonical_sha256(executor.executor)
            or docker.engine_fingerprint_sha256
            != transport.installation_policy.allowed_engine_fingerprint_sha256
            or docker.unix_socket.owner_uid != 0
            or postgres_prepared.control_container_id == ""
        ):
            raise ValueError
        return VerifiedAllocationBackendArtifactsV1(
            intent=intent,
            docker=docker,
            postgres=postgres,
            postgres_prepared=postgres_prepared,
            transport=transport,
            _capability=_ALLOCATION_BACKEND_CAPABILITY,
        )
    except Exception:
        raise AllocationBackendError("allocation_artifacts") from None


@dataclass(frozen=True, slots=True)
class _HttpResponse:
    status: int
    content_type: str
    body: bytearray

    def zeroize(self) -> None:
        self.body[:] = b"\x00" * len(self.body)


@dataclass(slots=True)
class _EngineIoDeadline:
    """One finite, non-regressing absolute deadline for Engine I/O.

    Socket timeouts alone bound an idle peer but permit an attacker to keep a
    stream alive indefinitely with sub-idle drips.  Every Engine read/write
    therefore uses this signed-policy-derived absolute deadline as well as
    the shorter idle socket timeout.  The direct production adapter obtains
    time only from ``time.monotonic``; test code may patch that module-local
    function but cannot inject a clock through the backend API.
    """

    absolute_deadline: float
    idle_timeout: float
    _last_observed: float

    @classmethod
    def begin(cls, *, absolute_timeout: int, idle_timeout: int) -> _EngineIoDeadline:
        if (
            type(absolute_timeout) is not int
            or type(idle_timeout) is not int
            or absolute_timeout < 1
            or idle_timeout < 1
        ):
            raise AllocationBackendError("engine_timeout")
        now = cls._read_monotonic(None)
        deadline = now + float(absolute_timeout)
        if not math.isfinite(deadline) or deadline <= now:
            raise AllocationBackendError("engine_timeout")
        return cls(
            absolute_deadline=deadline,
            idle_timeout=float(idle_timeout),
            _last_observed=now,
        )

    @staticmethod
    def _read_monotonic(previous: float | None) -> float:
        try:
            value = time.monotonic()
        except Exception:
            raise AllocationBackendError("engine_timeout") from None
        if (
            type(value) is not float
            or not math.isfinite(value)
            or value < 0.0
            or (previous is not None and value < previous)
        ):
            raise AllocationBackendError("engine_timeout")
        return value

    def _remaining(self) -> float:
        now = self._read_monotonic(self._last_observed)
        self._last_observed = now
        remaining = self.absolute_deadline - now
        if not math.isfinite(remaining) or remaining <= 0:
            raise AllocationBackendError("engine_timeout")
        return remaining

    def prepare(self, connection: socket.socket) -> None:
        """Apply the lesser absolute/idle limit before one blocking operation."""

        remaining = self._remaining()
        timeout = min(self.idle_timeout, remaining)
        if not math.isfinite(timeout) or timeout <= 0:
            raise AllocationBackendError("engine_timeout")
        try:
            connection.settimeout(timeout)
        except OSError:
            raise AllocationBackendError("engine_timeout") from None

    def progressed(self) -> None:
        """Observe a completed I/O operation and reject backward/expired time."""

        self._remaining()


def _discard_engine_json(value: object | None) -> None:
    """Drop references to every unfiltered decoded Engine value promptly.

    JSON decoding necessarily creates immutable Python scalar values. They are
    never returned or persisted; recursively clearing containers limits their
    lifetime to the endpoint parser's frame and avoids a raw response graph
    surviving beside a typed receipt.
    """

    if type(value) is dict:
        mapping = cast(dict[object, object], value)
        for item in tuple(mapping.values()):
            _discard_engine_json(item)
        mapping.clear()
    elif type(value) is list:
        sequence = cast(list[object], value)
        for item in sequence:
            _discard_engine_json(item)
        sequence.clear()


def _canonical_not_found_body(
    raw: bytearray,
    *,
    expected_name: str,
    resource: Literal["network", "volume"],
) -> bool:
    """Recognize only a bounded Docker-style JSON 404 for its requested name."""

    parsed: object | None = None
    try:
        parsed = json.loads(raw)
        if type(parsed) is not dict or set(parsed) != {"message"}:
            return False
        message = parsed["message"]
        expected_messages = (
            (f"network {expected_name} not found", f"No such network: {expected_name}")
            if resource == "network"
            else (f"get {expected_name}: no such volume", f"No such volume: {expected_name}")
        )
        return type(message) is str and message in expected_messages
    except (UnicodeDecodeError, json.JSONDecodeError, TypeError, ValueError):
        return False
    finally:
        _discard_engine_json(parsed)


class _UnixDockerEngineClient:
    """Internal, exact-subset HTTP-over-AF_UNIX implementation.

    There is intentionally no generic ``request`` public API.  Each method
    below corresponds to one named signed Engine operation.
    """

    def __init__(self, policy: DockerEngineControlPolicyV1) -> None:
        if type(policy) is not DockerEngineControlPolicyV1:
            raise AllocationBackendError("engine_policy")
        self._policy = policy
        self._socket_policy = policy.unix_socket
        self._api_prefix = f"/v{policy.api_version}"

    def _assert_socket_identity(self) -> None:
        policy = self._socket_policy
        try:
            path = Path(policy.socket_path)
            current = os.lstat(path)
            if (
                not stat.S_ISSOCK(current.st_mode)
                or current.st_dev != policy.device
                or current.st_ino != policy.inode
                or current.st_uid != policy.owner_uid
                or current.st_gid != policy.group_gid
                or stat.S_IMODE(current.st_mode) != policy.mode
                or _digest(os.fsencode(policy.socket_path)) != policy.socket_path_sha256
                or docker_unix_socket_identity_sha256(
                    socket_path_sha256=policy.socket_path_sha256,
                    device=current.st_dev,
                    inode=current.st_ino,
                    owner_uid=current.st_uid,
                    group_gid=current.st_gid,
                    mode=stat.S_IMODE(current.st_mode),
                )
                != policy.socket_identity_sha256
            ):
                raise ValueError
            # A Unix-domain connect is path based.  Reject writable/symlinked
            # parents before it so the checked endpoint cannot be redirected
            # through a user-controlled directory between calls.
            cursor = Path("/")
            for part in path.parts[1:-1]:
                cursor /= part
                node = os.lstat(cursor)
                if (
                    stat.S_ISLNK(node.st_mode)
                    or not stat.S_ISDIR(node.st_mode)
                    or node.st_uid != policy.owner_uid
                    or stat.S_IMODE(node.st_mode) & 0o022
                ):
                    raise ValueError
        except (OSError, ValueError):
            raise AllocationBackendError("engine_socket") from None

    def _connect(self, deadline: _EngineIoDeadline) -> socket.socket:
        self._assert_socket_identity()
        connection: socket.socket | None = None
        try:
            connection = socket.socket(socket.AF_UNIX, socket.SOCK_STREAM)
            deadline.prepare(connection)
            connection.connect(self._socket_policy.socket_path)
            deadline.progressed()
            self._assert_socket_identity()
            self._assert_peer_identity(connection)
            return connection
        except AllocationBackendError:
            if connection is not None:
                with suppress(OSError):
                    connection.close()
            raise
        except OSError:
            if connection is not None:
                with suppress(OSError):
                    connection.close()
            raise AllocationBackendError("engine_connect") from None

    def _assert_peer_identity(self, connection: socket.socket) -> None:
        """Bind the connected Linux peer to the root-owned socket policy.

        AF_UNIX has no descriptor-relative connect operation. The allocation
        deployment consequently requires root-owned, non-writable parent
        directories and checks the Linux peer UID after connect. Root is part of
        the explicitly accepted executor/Engine TCB; a non-root pathname
        replacement cannot redirect this connection.
        """

        try:
            if not hasattr(socket, "SO_PEERCRED"):
                raise ValueError
            raw = connection.getsockopt(socket.SOL_SOCKET, socket.SO_PEERCRED, 12)
            if len(raw) != 12:
                raise ValueError
            _pid, uid, _gid = struct.unpack("3i", raw)
            if uid != self._socket_policy.owner_uid:
                raise ValueError
        except (OSError, ValueError, struct.error):
            raise AllocationBackendError("engine_peer") from None

    def _send(
        self,
        connection: socket.socket,
        value: bytes | bytearray,
        *,
        deadline: _EngineIoDeadline,
    ) -> None:
        try:
            deadline.prepare(connection)
            connection.sendall(value)
            deadline.progressed()
        except OSError:
            raise AllocationBackendError("engine_io") from None

    def _recv_until_headers(
        self, connection: socket.socket, *, deadline: _EngineIoDeadline
    ) -> tuple[bytes, bytearray]:
        raw = bytearray()
        try:
            while b"\r\n\r\n" not in raw:
                if len(raw) >= _MAX_HEADERS:
                    raise ValueError
                deadline.prepare(connection)
                piece = connection.recv(min(4096, _MAX_HEADERS - len(raw)))
                if not piece:
                    raise ValueError
                raw.extend(piece)
                deadline.progressed()
            marker = raw.index(b"\r\n\r\n") + 4
            header = bytes(raw[:marker])
            remainder = bytearray(raw[marker:])
            raw[:] = b"\x00" * len(raw)
            return header, remainder
        except (OSError, ValueError):
            raw[:] = b"\x00" * len(raw)
            raise AllocationBackendError("engine_framing") from None

    def _parse_headers(self, raw: bytes) -> tuple[int, str, int]:
        try:
            lines = raw.decode("ascii").split("\r\n")
            if len(lines) < 3 or re.fullmatch(r"HTTP/1[.]1 [0-9]{3} [ -~]{1,64}", lines[0]) is None:
                raise ValueError
            status = int(lines[0][9:12])
            fields: dict[str, str] = {}
            for line in lines[1:-2]:
                key, value = line.split(":", 1)
                lowered = key.lower()
                if lowered in fields or not key or any(ch.isspace() for ch in key):
                    raise ValueError
                fields[lowered] = value.strip()
            if "transfer-encoding" in fields or "content-length" not in fields:
                raise ValueError
            encoded_length = fields["content-length"]
            if re.fullmatch(r"0|[1-9][0-9]{0,8}", encoded_length) is None:
                raise ValueError
            content_length = int(encoded_length)
            if not 0 <= content_length <= self._policy.max_response_bytes:
                raise ValueError
            content_type = fields.get("content-type", "")
            if len(content_type) > 128:
                raise ValueError
            return status, content_type, content_length
        except (UnicodeDecodeError, ValueError):
            raise AllocationBackendError("engine_framing") from None

    def _receive_exact(
        self,
        connection: socket.socket,
        *,
        initial: bytearray,
        length: int,
        deadline: _EngineIoDeadline,
    ) -> bytearray:
        if len(initial) > length:
            initial[:] = b"\x00" * len(initial)
            raise AllocationBackendError("engine_framing")
        try:
            while len(initial) < length:
                deadline.prepare(connection)
                piece = connection.recv(min(65_536, length - len(initial)))
                if not piece:
                    raise ValueError
                initial.extend(piece)
                deadline.progressed()
            # ``Connection: close`` is mandatory in normal Engine requests.
            deadline.prepare(connection)
            tail = connection.recv(1)
            deadline.progressed()
            if tail:
                raise ValueError
            return initial
        except (OSError, ValueError):
            initial[:] = b"\x00" * len(initial)
            raise AllocationBackendError("engine_framing") from None

    def _request(
        self,
        *,
        method: Literal["GET", "POST"],
        path: str,
        body: Mapping[str, object] | None,
        expected_status: int | tuple[int, ...],
        expected_content_type: str,
        not_found_name: str | None = None,
        not_found_resource: Literal["network", "volume"] | None = None,
    ) -> _HttpResponse:
        if (
            type(path) is not str
            or not path.startswith("/")
            or ".." in path
            or "\r" in path
            or "\n" in path
        ):
            raise AllocationBackendError("engine_endpoint")
        request_body = b"" if body is None else _canonical_json(body)
        if len(request_body) > self._policy.max_request_bytes:
            raise AllocationBackendError("engine_request")
        headers = [
            f"{method} {path} HTTP/1.1".encode("ascii"),
            b"Host: docker",
            b"Connection: close",
            f"Content-Length: {len(request_body)}".encode("ascii"),
        ]
        if body is not None:
            headers.append(b"Content-Type: application/json")
        encoded = b"\r\n".join(headers) + b"\r\n\r\n" + request_body
        connection: socket.socket | None = None
        response: _HttpResponse | None = None
        completed = False
        try:
            deadline = _EngineIoDeadline.begin(
                absolute_timeout=self._policy.request_timeout_seconds,
                idle_timeout=self._policy.request_timeout_seconds,
            )
            connection = self._connect(deadline)
            self._send(connection, encoded, deadline=deadline)
            raw_header, initial = self._recv_until_headers(connection, deadline=deadline)
            status, content_type, length = self._parse_headers(raw_header)
            raw_header = b"\x00" * len(raw_header)
            data = self._receive_exact(
                connection, initial=initial, length=length, deadline=deadline
            )
            expected = (expected_status,) if isinstance(expected_status, int) else expected_status
            if status not in expected or content_type != expected_content_type:
                not_found = (
                    status == 404
                    and content_type == expected_content_type
                    and type(not_found_name) is str
                    and not_found_resource in {"network", "volume"}
                    and _canonical_not_found_body(
                        data,
                        expected_name=not_found_name,
                        resource=not_found_resource,
                    )
                )
                data[:] = b"\x00" * len(data)
                raise AllocationBackendError(
                    "engine_status",
                    _not_found=not_found,
                )
            response = _HttpResponse(status=status, content_type=content_type, body=data)
            self._assert_socket_identity()
            completed = True
            return response
        except AllocationBackendError:
            raise
        except Exception:
            raise AllocationBackendError("engine_io") from None
        finally:
            if connection is not None:
                with suppress(OSError):
                    connection.close()
            if not completed:
                if response is not None:
                    response.zeroize()
                # Request bodies contain no secrets in allocation, but this
                # still makes the one generic error path value-free.
                encoded = b"\x00" * len(encoded)

    def _json(
        self,
        *,
        method: Literal["GET", "POST"],
        path: str,
        body: Mapping[str, object] | None,
        parse: Callable[[dict[str, object]], object],
        expected_status: int | tuple[int, ...] = 200,
        not_found_name: str | None = None,
        not_found_resource: Literal["network", "volume"] | None = None,
    ) -> object:
        """Decode into a caller-specified filtered result and discard all raw JSON.

        Engine JSON may include labels, host paths, errors, and arbitrary
        daemon metadata. Nothing decoded here is returned directly: each
        closed endpoint must build a scalar or typed filtered observation while
        this stack frame still owns the untrusted object graph.
        """

        response = self._request(
            method=method,
            path=path,
            body=body,
            expected_status=expected_status,
            expected_content_type="application/json",
            not_found_name=not_found_name,
            not_found_resource=not_found_resource,
        )
        parsed: object | None = None
        try:
            parsed = json.loads(response.body)
            if type(parsed) is not dict:
                raise ValueError
            return parse(cast(dict[str, object], parsed))
        except (UnicodeDecodeError, json.JSONDecodeError, ValueError, TypeError):
            raise AllocationBackendError("engine_json") from None
        finally:
            _discard_engine_json(parsed)
            response.zeroize()

    def _absent(
        self,
        path: str,
        *,
        expected_name: str,
        resource: Literal["network", "volume"],
    ) -> None:
        response = self._request(
            method="GET",
            path=path,
            body=None,
            expected_status=(404,),
            expected_content_type="application/json",
        )
        try:
            if not _canonical_not_found_body(
                response.body,
                expected_name=expected_name,
                resource=resource,
            ):
                raise AllocationBackendError("engine_status")
        finally:
            response.zeroize()

    def ping(self) -> None:
        response = self._request(
            method="GET",
            path="/_ping",
            body=None,
            expected_status=200,
            expected_content_type="text/plain",
        )
        try:
            if bytes(response.body) != b"OK":
                raise AllocationBackendError("engine_ping")
        finally:
            response.zeroize()

    def version(self) -> str:
        def parse(response: dict[str, object]) -> str:
            value = response.get("ApiVersion")
            if type(value) is not str or re.fullmatch(_API_VERSION, value) is None:
                raise AllocationBackendError("engine_projection")
            return value

        result = self._json(
            method="GET", path=f"{self._api_prefix}/version", body=None, parse=parse
        )
        if type(result) is not str:
            raise AllocationBackendError("engine_projection")
        return result

    def info(self, *, api_version: str) -> DockerEngineFilteredProjectionV1:
        def parse(response: dict[str, object]) -> DockerEngineFilteredProjectionV1:
            try:
                daemon_id = response["ID"]
                operating_system = response["OperatingSystem"]
                architecture = response["Architecture"]
                if (
                    type(daemon_id) is not str
                    or operating_system != "linux"
                    or architecture != "amd64"
                ):
                    raise ValueError
                return DockerEngineFilteredProjectionV1(
                    daemon_id=daemon_id,
                    api_version=api_version,
                    operating_system="linux",
                    architecture="amd64",
                )
            except (KeyError, ValidationError, ValueError, TypeError):
                raise AllocationBackendError("engine_projection") from None

        result = self._json(method="GET", path=f"{self._api_prefix}/info", body=None, parse=parse)
        if type(result) is not DockerEngineFilteredProjectionV1:
            raise AllocationBackendError("engine_projection")
        return result

    @staticmethod
    def _manifest_reference(policy: DockerImagePolicyV1) -> ImageReferenceV1:
        """Derive the only accepted local platform-manifest RepoDigest."""

        if type(policy) is not DockerImagePolicyV1:
            raise AllocationBackendError("control_image")
        try:
            repository = policy.image.reference.rsplit("@", 1)[0]
            return ImageReferenceV1(
                reference=(f"{repository}@sha256:{policy.linux_amd64_manifest_digest_sha256}")
            )
        except (TypeError, ValueError):
            raise AllocationBackendError("control_image") from None

    @staticmethod
    def _local_image_evidence(policy: DockerImagePolicyV1) -> DockerImageLocalEvidenceV1:
        """Build the receipt-safe evidence after both local checks succeed."""

        try:
            return expected_docker_image_local_evidence(policy)
        except (TypeError, ValueError):
            raise AllocationBackendError("control_image") from None

    def inspect_image_reference(
        self,
        policy: DockerImagePolicyV1,
        *,
        reference: ImageReferenceV1,
    ) -> str:
        """Prove one exact local RepoDigest resolves to the signed config.

        The index and platform-manifest references are inspected separately.
        Their membership relationship is deliberately *not* inferred from
        Engine metadata; the separately signed OCI resolution attestation in
        ``DockerImagePolicyV1`` carries that trust assertion.
        """

        if type(policy) is not DockerImagePolicyV1:
            raise AllocationBackendError("control_image")
        if type(reference) is not ImageReferenceV1:
            raise AllocationBackendError("control_image")
        expected_manifest_reference = self._manifest_reference(policy)
        if reference not in {policy.image, expected_manifest_reference}:
            raise AllocationBackendError("control_image")
        encoded_reference = quote(reference.reference, safe="@:_-./")

        def parse(response: dict[str, object]) -> str:
            try:
                image_id = response.get("Id")
                digests = response.get("RepoDigests")
                if (
                    image_id != f"sha256:{policy.config_digest_sha256}"
                    or response.get("Os") != "linux"
                    or response.get("Architecture") != "amd64"
                    or type(digests) is not list
                    or any(type(item) is not str for item in digests)
                    or tuple(cast(list[str], digests)) != (reference.reference,)
                ):
                    raise ValueError
                return reference.reference
            except (ValueError, TypeError):
                raise AllocationBackendError("control_image") from None

        result = self._json(
            method="GET",
            path=f"{self._api_prefix}/images/{encoded_reference}/json",
            body=None,
            parse=parse,
        )
        if type(result) is not str or result != reference.reference:
            raise AllocationBackendError("control_image")
        return result

    def assert_control_container(self, policy: PostgreSQLPreparedControlPolicyV2) -> None:
        control_id = _require_container_id(policy.control_container_id, phase="control_container")

        def parse(response: dict[str, object]) -> None:
            try:
                state = response.get("State")
                config = response.get("Config")
                image = response.get("Image")
                if (
                    response.get("Id") != control_id
                    or image != f"sha256:{policy.control_image.config_digest_sha256}"
                    or type(state) is not dict
                    or state.get("Running") is not True
                    or type(config) is not dict
                ):
                    raise ValueError
                # The policy binds a fixed, safe filtered container projection.
                # Never hash Engine Env, Labels, Mountpoint, path, or error fields.
                projection = {
                    "cmd": config.get("Cmd"),
                    "entrypoint": config.get("Entrypoint"),
                    "image": config.get("Image"),
                    "user": config.get("User"),
                    "working_dir": config.get("WorkingDir"),
                }
                if _projection_sha256(projection) != policy.control_config_sha256:
                    raise ValueError
            except (ValueError, TypeError):
                raise AllocationBackendError("control_container") from None

        self._json(
            method="GET",
            path=f"{self._api_prefix}/containers/{control_id}/json",
            body=None,
            parse=parse,
        )

    def _named_path(self, collection: Literal["networks", "volumes"], name: str) -> str:
        identifier = _require_identifier(name, phase=collection[:-1])
        return f"{self._api_prefix}/{collection}/{quote(identifier, safe='')}"

    def assert_network_absent(self, name: str) -> None:
        self._absent(self._named_path("networks", name), expected_name=name, resource="network")

    def create_network(
        self, *, name: str, subnet: str, gateway: str, options: Sequence[NetworkOptionV1]
    ) -> None:
        self._json(
            method="POST",
            path=f"{self._api_prefix}/networks/create",
            body={
                "CheckDuplicate": True,
                "Driver": "bridge",
                "EnableIPv6": False,
                "Internal": True,
                "IPAM": {"Config": [{"Gateway": gateway, "Subnet": subnet}]},
                "Labels": {},
                "Name": _require_identifier(name, phase="network"),
                "Options": _options_map(options),
            },
            parse=lambda _response: None,
            expected_status=201,
        )

    def inspect_network(
        self,
        *,
        name: str,
        subnet: str,
        gateway: str,
        options: Sequence[NetworkOptionV1],
    ) -> AllocatedNetworkObservationV1:
        def parse(response: dict[str, object]) -> AllocatedNetworkObservationV1:
            try:
                ipam = response.get("IPAM")
                config = ipam.get("Config") if type(ipam) is dict else None
                if (
                    response.get("Name") != name
                    or response.get("Driver") != "bridge"
                    or response.get("Internal") is not True
                    or response.get("EnableIPv6") is not False
                    or response.get("Attachable") is not False
                    or response.get("Ingress") is not False
                    or response.get("Containers") not in ({}, None)
                    or response.get("Options") != _options_map(options)
                    or type(config) is not list
                    or len(config) != 1
                    or type(config[0]) is not dict
                    or config[0].get("Subnet") != subnet
                    or config[0].get("Gateway") != gateway
                ):
                    raise ValueError
                return AllocatedNetworkObservationV1(
                    name=name,
                    network_id=_require_container_id(response.get("Id"), phase="network"),
                    driver="bridge",
                    internal=True,
                    subnet=subnet,
                    gateway=gateway,
                    options=tuple(options),
                )
            except (ValidationError, ValueError, TypeError):
                raise AllocationBackendError("network_projection") from None

        result = self._json(
            method="GET",
            path=self._named_path("networks", name),
            body=None,
            parse=parse,
            not_found_name=name,
            not_found_resource="network",
        )
        if type(result) is not AllocatedNetworkObservationV1:
            raise AllocationBackendError("network_projection")
        return result

    def assert_volume_absent(self, name: str) -> None:
        self._absent(self._named_path("volumes", name), expected_name=name, resource="volume")

    def create_volume(self, *, name: str, options: Sequence[NetworkOptionV1]) -> None:
        self._json(
            method="POST",
            path=f"{self._api_prefix}/volumes/create",
            body={
                "Driver": "local",
                "DriverOpts": _options_map(options),
                "Labels": {},
                "Name": _require_identifier(name, phase="volume"),
            },
            parse=lambda _response: None,
            expected_status=201,
        )

    def inspect_volume(
        self,
        *,
        name: str,
        engine_fingerprint_sha256: str,
        options: Sequence[NetworkOptionV1],
    ) -> AllocatedVolumeObservationV1:
        def parse(response: dict[str, object]) -> AllocatedVolumeObservationV1:
            try:
                if (
                    response.get("Name") != name
                    or response.get("Driver") != "local"
                    or response.get("Scope") != "local"
                    or response.get("Options") != _options_map(options)
                    or response.get("Labels") not in ({}, None)
                ):
                    raise ValueError
                created = _timestamp(response.get("CreatedAt"))
                fingerprint = docker_volume_instance_fingerprint_sha256(
                    name=name,
                    engine_fingerprint_sha256=engine_fingerprint_sha256,
                    driver="local",
                    scope="local",
                    created_at=created,
                    options=tuple(options),
                )
                return AllocatedVolumeObservationV1(
                    name=name,
                    engine_fingerprint_sha256=engine_fingerprint_sha256,
                    driver="local",
                    scope="local",
                    created_at=created,
                    options=tuple(options),
                    volume_instance_fingerprint_sha256=fingerprint,
                )
            except (ValidationError, ValueError, TypeError):
                raise AllocationBackendError("volume_projection") from None

        result = self._json(
            method="GET",
            path=self._named_path("volumes", name),
            body=None,
            parse=parse,
            not_found_name=name,
            not_found_resource="volume",
        )
        if type(result) is not AllocatedVolumeObservationV1:
            raise AllocationBackendError("volume_projection")
        return result

    def _create_control_exec(
        self,
        *,
        policy: PostgreSQLPreparedControlPolicyV2,
        command: tuple[str, ...],
    ) -> str:
        container_id = _require_container_id(policy.control_container_id, phase="postgres_exec")

        def parse(response: dict[str, object]) -> str:
            return _require_container_id(response.get("Id"), phase="postgres_exec")

        result = self._json(
            method="POST",
            path=f"{self._api_prefix}/containers/{container_id}/exec",
            body={
                "AttachStderr": True,
                "AttachStdin": True,
                "AttachStdout": True,
                "Cmd": list(command),
                "Env": [],
                "Privileged": False,
                "Tty": False,
                "User": policy.psql_operating_system_user,
                "WorkingDir": "",
            },
            parse=parse,
            expected_status=201,
        )
        if type(result) is not str:
            raise AllocationBackendError("postgres_exec")
        return result

    def create_exec(self, *, policy: PostgreSQLPreparedControlPolicyV2) -> str:
        """Create exactly the signed psql stdin command, never caller argv."""

        return self._create_control_exec(policy=policy, command=policy.fixed_psql_argv)

    def create_psql_hash_exec(self, *, policy: PostgreSQLPreparedControlPolicyV2) -> str:
        """Create the sole fixed hash command before any PostgreSQL template.

        The control-image digest binds the command implementation, while this
        bounded command proves that the exact signed psql path has the policy
        SHA-256. It accepts no values, shell, environment, or arbitrary argv.
        """

        return self._create_control_exec(
            policy=policy,
            command=(_SHA256SUM_ABSOLUTE_PATH, policy.psql_absolute_path),
        )

    def inspect_exec(
        self,
        *,
        exec_id: str,
        policy: PostgreSQLPreparedControlPolicyV2,
        command: tuple[str, ...],
    ) -> None:
        """Verify the Engine retained the exact create-only exec contract."""

        exec_id = _require_container_id(exec_id, phase="postgres_exec")
        control_id = _require_container_id(policy.control_container_id, phase="postgres_exec")
        if (
            type(command) is not tuple
            or not command
            or any(type(value) is not str or not value for value in command)
        ):
            raise AllocationBackendError("postgres_exec")

        def parse(response: dict[str, object]) -> None:
            try:
                process = response.get("ProcessConfig")
                exit_code = response.get("ExitCode")
                if (
                    response.get("ID") != exec_id
                    or response.get("ContainerID") != control_id
                    or response.get("Running") is not False
                    or (exit_code is not None and (type(exit_code) is not int or exit_code != 0))
                    or response.get("OpenStderr") is not True
                    or response.get("OpenStdin") is not True
                    or response.get("OpenStdout") is not True
                    or type(process) is not dict
                    or process.get("privileged") is not False
                    or process.get("tty") is not False
                    or process.get("user") != policy.psql_operating_system_user
                    or process.get("entrypoint") != command[0]
                    or process.get("arguments") != list(command[1:])
                ):
                    raise ValueError
            except (ValueError, TypeError):
                raise AllocationBackendError("postgres_exec") from None

        self._json(
            method="GET",
            path=f"{self._api_prefix}/exec/{exec_id}/json",
            body=None,
            parse=parse,
        )

    def assert_psql_binary_output(
        self, *, policy: PostgreSQLPreparedControlPolicyV2, output: bytearray
    ) -> None:
        """Accept only the fixed value-free checksum output and erase it."""

        try:
            expected = (
                policy.psql_binary_sha256.encode("ascii")
                + b"  "
                + policy.psql_absolute_path.encode("ascii")
                + b"\n"
            )
            if output != expected:
                raise AllocationBackendError("postgres_binary")
        finally:
            output[:] = b"\x00" * len(output)

    def start_exec(self, *, exec_id: str, sql: bytearray) -> bytearray:
        """Start one exact psql exec and parse only Docker multiplex bytes."""

        if len(sql) < 1 or len(sql) > self._policy.max_request_bytes:
            raise AllocationBackendError("postgres_sql")
        exec_id = _require_container_id(exec_id, phase="postgres_exec")
        body = _canonical_json({"Detach": False, "Tty": False})
        request = (
            f"POST {self._api_prefix}/exec/{exec_id}/start HTTP/1.1\r\n".encode("ascii")
            + b"Host: docker\r\nConnection: Upgrade\r\nUpgrade: tcp\r\n"
            + b"Content-Type: application/json\r\n"
            + f"Content-Length: {len(body)}\r\n\r\n".encode("ascii")
            + body
        )
        connection: socket.socket | None = None
        output = bytearray()
        try:
            deadline = _EngineIoDeadline.begin(
                absolute_timeout=self._policy.hijack_absolute_timeout_seconds,
                idle_timeout=self._policy.hijack_timeout_seconds,
            )
            connection = self._connect(deadline)
            self._send(connection, request, deadline=deadline)
            header, initial = self._recv_until_headers(connection, deadline=deadline)
            status, content_type, length = self._parse_hijack_headers(header)
            header = b"\x00" * len(header)
            if status != 101 or content_type != "application/vnd.docker.raw-stream" or length != -1:
                raise AllocationBackendError("postgres_exec")
            self._send(connection, sql, deadline=deadline)
            with suppress(OSError):
                connection.shutdown(socket.SHUT_WR)
            output = self._read_multiplex(connection, initial, deadline=deadline)
            self._assert_socket_identity()
            return output
        except AllocationBackendError:
            output[:] = b"\x00" * len(output)
            raise
        except Exception:
            output[:] = b"\x00" * len(output)
            raise AllocationBackendError("postgres_exec") from None
        finally:
            sql[:] = b"\x00" * len(sql)
            request = b"\x00" * len(request)
            if connection is not None:
                with suppress(OSError):
                    connection.close()

    def _parse_hijack_headers(self, raw: bytes) -> tuple[int, str, int]:
        try:
            lines = raw.decode("ascii").split("\r\n")
            if len(lines) < 3 or lines[0] != "HTTP/1.1 101 UPGRADED":
                raise ValueError
            fields: dict[str, str] = {}
            for line in lines[1:-2]:
                key, value = line.split(":", 1)
                lowered = key.lower()
                if lowered in fields:
                    raise ValueError
                fields[lowered] = value.strip()
            if (
                fields.get("connection") != "Upgrade"
                or fields.get("upgrade") != "tcp"
                or fields.get("content-type") != "application/vnd.docker.raw-stream"
                or "content-length" in fields
                or "transfer-encoding" in fields
            ):
                raise ValueError
            return 101, fields["content-type"], -1
        except (UnicodeDecodeError, ValueError, KeyError):
            raise AllocationBackendError("engine_framing") from None

    def _read_multiplex(
        self,
        connection: socket.socket,
        initial: bytearray,
        *,
        deadline: _EngineIoDeadline,
    ) -> bytearray:
        data = bytearray(initial)
        initial[:] = b"\x00" * len(initial)
        stdout = bytearray()
        stderr_seen = False
        stderr_total = 0
        total_payload_bytes = 0
        frame_count = 0
        max_wire_bytes = self._policy.max_hijack_bytes + (8 * self._policy.max_hijack_frames)
        try:
            if len(data) > max_wire_bytes:
                raise ValueError
            while True:
                while len(data) < 8:
                    deadline.prepare(connection)
                    piece = connection.recv(4096)
                    if not piece:
                        if not data:
                            if stderr_seen:
                                raise ValueError
                            return stdout
                        raise ValueError
                    data.extend(piece)
                    if len(data) > max_wire_bytes:
                        raise ValueError
                    deadline.progressed()
                stream = data[0]
                if data[1:4] != b"\x00\x00\x00":
                    raise ValueError
                length = int.from_bytes(data[4:8], "big")
                frame_count += 1
                if (
                    stream not in (1, 2)
                    or frame_count > self._policy.max_hijack_frames
                    or length > self._policy.max_hijack_bytes
                    or total_payload_bytes + length > self._policy.max_hijack_bytes
                ):
                    raise ValueError
                del data[:8]
                while len(data) < length:
                    deadline.prepare(connection)
                    piece = connection.recv(min(65_536, length - len(data)))
                    if not piece:
                        raise ValueError
                    data.extend(piece)
                    if len(data) > max_wire_bytes:
                        raise ValueError
                    deadline.progressed()
                payload = data[:length]
                del data[:length]
                total_payload_bytes += length
                if stream == 2:
                    stderr_seen = True
                    stderr_total += len(payload)
                    if stderr_total > self._policy.max_hijack_bytes:
                        raise ValueError
                else:
                    if len(stdout) + len(payload) > self._policy.max_hijack_bytes:
                        raise ValueError
                    stdout.extend(payload)
                payload[:] = b"\x00" * len(payload)
        except (OSError, ValueError, AllocationBackendError):
            stdout[:] = b"\x00" * len(stdout)
            raise AllocationBackendError("engine_multiplex") from None
        finally:
            data[:] = b"\x00" * len(data)


class _OperationRecorder(Protocol):
    def remaining_operations(self) -> int: ...

    def claim_next(self) -> ExecutorEngineOperationClaimV1: ...

    def complete(
        self, claim: ExecutorEngineOperationClaimV1, *, filtered_projection_sha256: str
    ) -> None: ...

    def completed_projection_sha256(self) -> str: ...


def _claim_and_complete(
    recorder: _OperationRecorder,
    *,
    kind: ExecutorEngineOperationKindV1,
    target: ExecutorEngineOperationTargetV1,
    action: Callable[[], object],
) -> object:
    """Claim before every Engine call and persist only a filtered commitment."""

    claim = recorder.claim_next()
    if claim.operation_kind is not kind or claim.target is not target:
        raise AllocationBackendError("engine_operation_plan")
    result = action()
    if isinstance(result, BaseModel):
        projection = canonical_sha256(result)
    elif result is None:
        projection = _digest(f"{kind.value}:{target.value}".encode("ascii"))
    elif type(result) is str:
        projection = _digest(_canonical_json({"value": result}))
    elif type(result) is bytearray:
        projection = _digest(result)
    else:
        try:
            projection = _digest(_canonical_json(cast(Mapping[str, object], result)))
        except AllocationBackendError:
            raise AllocationBackendError("engine_projection") from None
    recorder.complete(claim, filtered_projection_sha256=projection)
    return result


def _sql_roles(policy: PostgreSQLControlPolicyV1) -> bytearray:
    return bytearray(
        _render_allocation_sql(
            "roles",
            owner_literal=_require_identifier(policy.owner_role, phase="postgres_identifier"),
            application_literal=_require_identifier(
                policy.application_role, phase="postgres_identifier"
            ),
            owner_identifier=_quote_identifier(policy.owner_role),
            application_identifier=_quote_identifier(policy.application_role),
        ).encode("utf-8")
    )


def _sql_database(policy: PostgreSQLControlPolicyV1) -> bytearray:
    return bytearray(
        _render_allocation_sql(
            "database",
            database_identifier=_quote_identifier(policy.database_name),
            owner_identifier=_quote_identifier(policy.owner_role),
        ).encode("utf-8")
    )


def _sql_schema_acl(policy: PostgreSQLControlPolicyV1) -> bytearray:
    statements = [
        _render_allocation_sql(
            "schema_prefix",
            database_identifier=_quote_identifier(policy.database_name),
            schema_identifier=_quote_identifier(policy.schema_name),
            owner_identifier=_quote_identifier(policy.owner_role),
        )
    ]
    for grant in policy.grants:
        fields = {
            "role_identifier": _quote_identifier(grant.role),
            "grantee_identifier": _quote_identifier(grant.grantee),
            "privilege": grant.privilege,
            "schema_identifier": _quote_identifier(grant.schema_name),
        }
        if grant.privilege in {"USAGE", "CREATE"}:
            statements.append(_render_allocation_sql("schema_grant", **fields))
        else:
            statements.append(_render_allocation_sql("default_table_grant", **fields))
    statements.append(_render_allocation_sql("schema_suffix"))
    return bytearray("".join(statements).encode("utf-8"))


def _sql_observation(policy: PostgreSQLControlPolicyV1) -> bytearray:
    """Return one fixed JSON document containing only receipt-admissible state."""

    database = _quote_identifier(policy.database_name)
    schema = _require_identifier(policy.schema_name, phase="postgres_identifier")
    owner = _require_identifier(policy.owner_role, phase="postgres_identifier")
    app = _require_identifier(policy.application_role, phase="postgres_identifier")
    expected_grants = " UNION ALL ".join(
        _render_allocation_sql(
            "expected_grant_row",
            role_literal=_require_identifier(grant.role, phase="postgres_identifier"),
            grantee_literal=_require_identifier(grant.grantee, phase="postgres_identifier"),
            privilege=grant.privilege,
            schema_literal=_require_identifier(grant.schema_name, phase="postgres_identifier"),
        )
        for grant in policy.grants
    ) or _render_allocation_sql("expected_grant_empty")
    schema_grants = _render_allocation_sql("schema_grant_matches")
    default_table_grants = _render_allocation_sql("default_table_grant_matches")
    role_projection = _render_allocation_sql(
        "role_projection",
        owner_literal=owner,
        application_literal=app,
    )
    text = _render_allocation_sql(
        "observation",
        database_identifier=database,
        schema_literal=schema,
        owner_literal=owner,
        application_literal=app,
        expected_grants=expected_grants,
        schema_grants=schema_grants,
        default_table_grants=default_table_grants,
        role_projection=role_projection,
        grant_projection=_render_allocation_sql("grant_projection"),
    )
    return bytearray(text.encode("utf-8"))


def _sql_postgres_presence(
    policy: PostgreSQLControlPolicyV1,
    *,
    in_target_database: bool,
) -> bytearray:
    """Build the only non-mutating reconciliation query for known names."""

    owner = policy.owner_role.replace("'", "''")
    app = policy.application_role.replace("'", "''")
    schema = policy.schema_name.replace("'", "''")
    database = policy.database_name.replace("'", "''")
    connect = f"\\connect {_quote_identifier(policy.database_name)}\n" if in_target_database else ""
    database_clause = (
        "true"
        if in_target_database
        else (f"EXISTS (SELECT 1 FROM pg_database WHERE datname = '{database}')")
    )
    schema_clause = (
        f"EXISTS (SELECT 1 FROM pg_namespace WHERE nspname = '{schema}')"
        if in_target_database
        else "false"
    )
    return bytearray(
        (
            connect
            + "COPY (SELECT json_build_object("
            + f"'database_exists', {database_clause}, "
            + "'owner_role_exists', EXISTS (SELECT 1 FROM pg_roles "
            + f"WHERE rolname = '{owner}'), "
            + "'application_role_exists', EXISTS (SELECT 1 FROM pg_roles "
            + f"WHERE rolname = '{app}'), "
            + f"'schema_exists', {schema_clause}"
            + ")::text) TO STDOUT;\n"
        ).encode("utf-8")
    )


def _parse_postgres_presence(output: bytearray) -> tuple[bool, bool, bool, bool]:
    """Parse one bounded, value-free presence projection and erase it."""

    try:
        if not output.endswith(b"\n") or output.count(b"\n") != 1:
            raise ValueError
        parsed = json.loads(bytes(output[:-1]))
        if (
            type(parsed) is not dict
            or set(parsed)
            != {
                "database_exists",
                "owner_role_exists",
                "application_role_exists",
                "schema_exists",
            }
            or any(type(value) is not bool for value in parsed.values())
        ):
            raise ValueError
        return (
            cast(bool, parsed["database_exists"]),
            cast(bool, parsed["owner_role_exists"]),
            cast(bool, parsed["application_role_exists"]),
            cast(bool, parsed["schema_exists"]),
        )
    except (ValueError, TypeError, json.JSONDecodeError):
        raise AllocationBackendError("postgres_reconciliation") from None
    finally:
        output[:] = b"\x00" * len(output)


def _parse_postgres_observation(
    output: bytearray,
    *,
    policy: PostgreSQLControlPolicyV1,
    prepared: PostgreSQLPreparedControlPolicyV2,
) -> AllocatedPostgreSQLObservationV1:
    try:
        # psql's unaligned COPY output is exactly one JSON record plus LF.
        if not output.endswith(b"\n") or output.count(b"\n") != 1:
            raise ValueError
        parsed = json.loads(bytes(output[:-1]))
        if type(parsed) is not dict:
            raise ValueError
        role_values = parsed.get("role_oids")
        grants_values = parsed.get("grants")
        if type(role_values) is not list or type(grants_values) is not list:
            raise ValueError
        roles = tuple(PostgreSQLRoleObservationV1.model_validate(item) for item in role_values)
        grants = tuple(PostgreSQLGrantObservationV1.model_validate(item) for item in grants_values)
        if tuple(item.role for item in roles) != policy.role_names:
            raise ValueError
        if tuple((item.can_login, item.password_absent) for item in roles) != (
            (False, True),
            (False, True),
        ):
            raise ValueError
        if tuple(
            (item.role, item.grantee, item.privilege, item.schema_name) for item in grants
        ) != tuple(
            (item.role, item.grantee, item.privilege, item.schema_name) for item in policy.grants
        ):
            raise ValueError
        if (
            parsed.get("database_name") != policy.database_name
            or parsed.get("schema_name") != policy.schema_name
            or parsed.get("owner_role") != policy.owner_role
            or parsed.get("application_role") != policy.application_role
            or parsed.get("password_encryption") != prepared.password_encryption
            or parsed.get("log_statement") != "none"
        ):
            raise ValueError
        acl_sha256 = _digest(
            _POSTGRES_RESULT_DOMAIN
            + _canonical_json([item.model_dump(mode="json") for item in grants])
        )
        allocation_operation = prepared.operations[0]
        return AllocatedPostgreSQLObservationV1(
            system_identifier=parsed["system_identifier"],
            database_name=parsed["database_name"],
            database_oid=parsed["database_oid"],
            schema_name=parsed["schema_name"],
            schema_oid=parsed["schema_oid"],
            prepared_operation_id=allocation_operation.operation_id,
            prepared_operation_result_sha256=allocation_operation.result_projection_sha256,
            owner_role=parsed["owner_role"],
            owner_role_oid=parsed["owner_role_oid"],
            application_role=parsed["application_role"],
            application_role_oid=parsed["application_role_oid"],
            role_oids=cast(tuple[PostgreSQLRoleObservationV1, PostgreSQLRoleObservationV1], roles),
            grants=grants,
            acl_sha256=acl_sha256,
        )
    except (KeyError, ValidationError, ValueError, TypeError, json.JSONDecodeError):
        raise AllocationBackendError("postgres_projection") from None
    finally:
        output[:] = b"\x00" * len(output)


class AllocationReconciliationStateV1(StrEnum):
    """Read-only state classifications; none can authorize a resume."""

    ABSENT = "absent"
    PARTIAL = "partial"
    COMPLETE = "complete"


class AllocationReconciliationPostgreSQLStateV1(StrEnum):
    """Read-only PostgreSQL allocation classifications."""

    ABSENT = "absent"
    PARTIAL = "partial"
    COMPLETE = "complete"


class AllocationReconciliationProjectionV1(_Model):
    """Filtered read-only view of an interrupted allocation."""

    schema_version: Literal["rsd.allocation-reconciliation-projection.v1"]
    allocation_intent_sha256: str = Field(pattern=_SHA256)
    engine: EngineIdentityObservationV1
    control_image_local_evidence: DockerImageLocalEvidenceV1
    state: AllocationReconciliationStateV1
    observed_network_names: tuple[str, ...] = Field(default=(), max_length=2)
    observed_volume_names: tuple[str, ...] = Field(default=(), max_length=2)
    postgres_state: AllocationReconciliationPostgreSQLStateV1
    observed_postgres: AllocatedPostgreSQLObservationV1 | None = None
    observed_at: str

    @field_validator("observed_network_names", "observed_volume_names", mode="before")
    @classmethod
    def canonical_names(cls, value: object) -> tuple[object, ...]:
        if type(value) not in {tuple, list}:
            raise ValueError("reconciliation names are invalid")
        return tuple(cast(tuple[object, ...] | list[object], value))

    @field_validator("observed_at")
    @classmethod
    def canonical_time(cls, value: str) -> str:
        if type(value) is not str:
            raise ValueError("reconciliation time is invalid")
        _timestamp(value)
        return value

    @model_validator(mode="after")
    def exact_state(self) -> AllocationReconciliationProjectionV1:
        names = self.observed_network_names + self.observed_volume_names
        postgres_complete = (
            self.postgres_state is AllocationReconciliationPostgreSQLStateV1.COMPLETE
        )
        if (
            len(set(names)) != len(names)
            or any(re.fullmatch(_IDENTIFIER, item) is None for item in names)
            or (
                self.state is AllocationReconciliationStateV1.ABSENT
                and (
                    names != ()
                    or self.postgres_state is not AllocationReconciliationPostgreSQLStateV1.ABSENT
                )
            )
            or (
                self.state is AllocationReconciliationStateV1.PARTIAL
                and names == ()
                and self.postgres_state is AllocationReconciliationPostgreSQLStateV1.ABSENT
            )
            or (
                self.state is AllocationReconciliationStateV1.COMPLETE
                and (len(names) != 4 or not postgres_complete)
            )
            or (postgres_complete != (self.observed_postgres is not None))
        ):
            raise ValueError("reconciliation projection is invalid")
        return self


class AllocationReconciliationReceiptV1(_Model):
    """A signed operator-facing reconciliation receipt model, never a resume grant."""

    schema_version: Literal["rsd.allocation-reconciliation-receipt.v1"]
    projection: AllocationReconciliationProjectionV1
    projection_sha256: str = Field(pattern=_SHA256)
    signer_key_id: str = Field(pattern=_IDENTIFIER)
    signature_base64: str = Field(min_length=4, max_length=256)

    @model_validator(mode="after")
    def exact_projection_binding(self) -> AllocationReconciliationReceiptV1:
        try:
            signature = base64.b64decode(self.signature_base64, validate=True)
        except (binascii.Error, ValueError):
            raise ValueError("reconciliation receipt is invalid") from None
        if (
            self.projection_sha256 != canonical_sha256(self.projection)
            or base64.b64encode(signature).decode("ascii") != self.signature_base64
            or len(signature) != 64
        ):
            raise ValueError("reconciliation receipt is invalid")
        return self


def allocation_reconciliation_receipt_message(receipt: AllocationReconciliationReceiptV1) -> bytes:
    """Return the domain-separated receipt bytes for the executor signer."""

    canonical = _strict_canonical_model(receipt, AllocationReconciliationReceiptV1)
    return _RECONCILIATION_DOMAIN + _canonical_json(
        canonical.model_dump(mode="json", exclude={"signature_base64"})
    )


def verify_allocation_reconciliation_receipt(
    receipt: AllocationReconciliationReceiptV1,
    *,
    attestation_key_id: str,
    attestation_public_key_base64: str,
) -> AllocationReconciliationReceiptV1:
    """Verify a value-free executor reconciliation receipt without resuming it."""

    if (
        type(receipt) is not AllocationReconciliationReceiptV1
        or type(attestation_key_id) is not str
        or re.fullmatch(_IDENTIFIER, attestation_key_id) is None
        or type(attestation_public_key_base64) is not str
    ):
        raise AllocationBackendError("reconciliation_receipt")
    try:
        canonical = AllocationReconciliationReceiptV1.model_validate_json(
            _canonical_json(receipt.model_dump(mode="json"))
        )
        signature = base64.b64decode(canonical.signature_base64, validate=True)
        public = base64.b64decode(attestation_public_key_base64, validate=True)
        if (
            canonical.signer_key_id != attestation_key_id
            or base64.b64encode(public).decode("ascii") != attestation_public_key_base64
            or len(public) != 32
        ):
            raise ValueError
        Ed25519PublicKey.from_public_bytes(public).verify(
            signature, allocation_reconciliation_receipt_message(canonical)
        )
        return canonical
    except (InvalidSignature, ValueError, binascii.Error, ValidationError):
        raise AllocationBackendError("reconciliation_receipt") from None


class SealedAllocationBackendV1:
    """The only concrete allocation backend; materialization/start stay blocked."""

    def __init__(
        self, artifacts: VerifiedAllocationBackendArtifactsV1, *, _capability: object
    ) -> None:
        if (
            _capability is not _ALLOCATION_BACKEND_CAPABILITY
            or type(artifacts) is not VerifiedAllocationBackendArtifactsV1
        ):
            raise AllocationBackendError("allocation_backend")
        _require_allocation_prepared_binding(artifacts.postgres_prepared)
        self._artifacts = artifacts
        self._engine = _UnixDockerEngineClient(artifacts.docker)

    def _verify_context(self, context: AllocationExecutorBackendContextV1) -> None:
        from omninode_rsd.lifecycle.executor_daemon import AllocationExecutorBackendContextV1

        artifacts = self._artifacts
        intent = artifacts.intent
        transport = artifacts.transport
        if (
            type(context) is not AllocationExecutorBackendContextV1
            or context.allocation_operation_id != intent.allocation_operation_id
            or context.allocation_intent_sha256 != canonical_sha256(intent)
            or context.executor_id != transport.policy.executor_id
            or context.executor_policy_sha256 != transport.policy.policy_sha256()
            or context.docker_engine_control_policy_sha256 != canonical_sha256(artifacts.docker)
            or context.postgres_prepared_control_policy_sha256
            != canonical_sha256(artifacts.postgres_prepared)
            or context.host_fingerprint_sha256 != transport.policy.host_key_fingerprint_sha256
            or context.engine_fingerprint_sha256 != artifacts.docker.engine_fingerprint_sha256
            or context.allocation_plan_sha256 != canonical_sha256(intent.plan)
            or context.engine_operations.remaining_operations() < 1
        ):
            raise AllocationBackendError("allocation_context")

    def allocate_empty_resources(
        self, context: AllocationExecutorBackendContextV1
    ) -> ExecutorAllocationBackendEvidenceV1:
        """Execute one no-adoption allocation plan; any uncertainty stays ambiguous."""

        from omninode_rsd.lifecycle.executor_daemon import ExecutorAllocationBackendEvidenceV1

        self._verify_context(context)
        plan = self._artifacts.intent.plan
        docker = self._artifacts.docker
        postgres = self._artifacts.postgres
        prepared = self._artifacts.postgres_prepared
        recorder = context.engine_operations

        _claim_and_complete(
            recorder,
            kind=ExecutorEngineOperationKindV1.ENGINE_PING,
            target=ExecutorEngineOperationTargetV1.ENGINE,
            action=self._engine.ping,
        )
        api_version = _claim_and_complete(
            recorder,
            kind=ExecutorEngineOperationKindV1.ENGINE_VERSION,
            target=ExecutorEngineOperationTargetV1.ENGINE,
            action=self._engine.version,
        )
        projection = _claim_and_complete(
            recorder,
            kind=ExecutorEngineOperationKindV1.ENGINE_INFO,
            target=ExecutorEngineOperationTargetV1.ENGINE,
            action=lambda: self._engine.info(api_version=cast(str, api_version)),
        )
        if (
            type(projection) is not DockerEngineFilteredProjectionV1
            or projection != docker.engine_projection
            or docker_engine_fingerprint_sha256(projection) != docker.engine_fingerprint_sha256
        ):
            raise AllocationBackendError("engine_projection")
        engine = EngineIdentityObservationV1(
            projection=projection,
            engine_fingerprint_sha256=docker.engine_fingerprint_sha256,
        )
        index_reference = _claim_and_complete(
            recorder,
            kind=ExecutorEngineOperationKindV1.IMAGE_INSPECT,
            target=ExecutorEngineOperationTargetV1.CONTROL_IMAGE,
            action=lambda: self._engine.inspect_image_reference(
                prepared.control_image,
                reference=prepared.control_image.image,
            ),
        )
        manifest_reference = _claim_and_complete(
            recorder,
            kind=ExecutorEngineOperationKindV1.IMAGE_MANIFEST_INSPECT,
            target=ExecutorEngineOperationTargetV1.CONTROL_IMAGE,
            action=lambda: self._engine.inspect_image_reference(
                prepared.control_image,
                reference=self._engine._manifest_reference(prepared.control_image),
            ),
        )
        image_evidence = self._engine._local_image_evidence(prepared.control_image)
        if (
            index_reference != image_evidence.registry_index_reference.reference
            or manifest_reference != image_evidence.linux_amd64_manifest_reference.reference
        ):
            raise AllocationBackendError("control_image")
        _claim_and_complete(
            recorder,
            kind=ExecutorEngineOperationKindV1.CONTAINER_INSPECT,
            target=ExecutorEngineOperationTargetV1.CONTROL_POSTGRES,
            action=lambda: self._engine.assert_control_container(prepared),
        )
        binary_exec_id = _claim_and_complete(
            recorder,
            kind=ExecutorEngineOperationKindV1.POSTGRES_BINARY_EXEC_CREATE,
            target=ExecutorEngineOperationTargetV1.CONTROL_POSTGRES,
            action=lambda: self._engine.create_psql_hash_exec(policy=prepared),
        )
        if type(binary_exec_id) is not str:
            raise AllocationBackendError("postgres_binary")
        _claim_and_complete(
            recorder,
            kind=ExecutorEngineOperationKindV1.POSTGRES_BINARY_EXEC_INSPECT,
            target=ExecutorEngineOperationTargetV1.CONTROL_POSTGRES,
            action=lambda: self._engine.inspect_exec(
                exec_id=binary_exec_id,
                policy=prepared,
                command=(_SHA256SUM_ABSOLUTE_PATH, prepared.psql_absolute_path),
            ),
        )

        def verify_binary() -> None:
            output = self._engine.start_exec(exec_id=binary_exec_id, sql=bytearray(b"\n"))
            if type(output) is not bytearray:
                raise AllocationBackendError("postgres_binary")
            self._engine.assert_psql_binary_output(policy=prepared, output=output)

        _claim_and_complete(
            recorder,
            kind=ExecutorEngineOperationKindV1.POSTGRES_BINARY_EXEC_START,
            target=ExecutorEngineOperationTargetV1.CONTROL_POSTGRES,
            action=verify_binary,
        )

        primary_network = self._allocate_network(
            recorder,
            target=ExecutorEngineOperationTargetV1.PRIMARY_NETWORK,
            name=plan.topology.primary_network.name,
            subnet=plan.topology.primary_network.subnet,
            gateway=plan.topology.primary_network.gateway,
            options=plan.topology.primary_network.options,
        )
        restore_network = self._allocate_network(
            recorder,
            target=ExecutorEngineOperationTargetV1.RESTORE_NETWORK,
            name=plan.topology.restore_network.name,
            subnet=plan.topology.restore_network.subnet,
            gateway=plan.topology.restore_network.gateway,
            options=plan.topology.restore_network.options,
        )
        primary_volume = self._allocate_volume(
            recorder,
            target=ExecutorEngineOperationTargetV1.PRIMARY_CACHE_VOLUME,
            name=plan.primary_valkey_volume.name,
            options=plan.primary_valkey_volume.options,
            engine_fingerprint_sha256=engine.engine_fingerprint_sha256,
        )
        restore_volume = self._allocate_volume(
            recorder,
            target=ExecutorEngineOperationTargetV1.RESTORE_CACHE_VOLUME,
            name=plan.restore_valkey_volume.name,
            options=plan.restore_valkey_volume.options,
            engine_fingerprint_sha256=engine.engine_fingerprint_sha256,
        )
        postgres_observation = self._allocate_postgres(recorder, postgres, prepared)

        # Final inspections make the signed receipt a post-effect snapshot,
        # never a record assembled from stale creation responses.
        self._final_network(recorder, primary_network, plan.topology.primary_network)
        self._final_network(recorder, restore_network, plan.topology.restore_network)
        self._final_volume(recorder, primary_volume, plan.primary_valkey_volume, engine)
        self._final_volume(recorder, restore_volume, plan.restore_valkey_volume, engine)
        if recorder.remaining_operations() != 0:
            raise AllocationBackendError("engine_operation_plan")
        resources = AllocatedResourceSetV2(
            engine=engine,
            primary_network=primary_network,
            restore_network=restore_network,
            primary_cache_volume=primary_volume,
            restore_cache_volume=restore_volume,
            postgres=postgres_observation,
            no_host_publication=NoHostPublicationGroundworkV1(
                container_ids=(),
                host_network=False,
                publish_all_ports=False,
                published_port_bindings=(),
                allowed_attachment_set_sha256=canonical_sha256(plan.topology),
            ),
        )
        now = _system_utc_clock().isoformat(timespec="seconds").replace("+00:00", "Z")
        return ExecutorAllocationBackendEvidenceV1(
            engine=engine,
            control_image_local_evidence=image_evidence,
            allocated_resources=resources,
            engine_operation_journal_sha256=recorder.completed_projection_sha256(),
            completed_at=now,
        )

    def _allocate_network(
        self,
        recorder: _OperationRecorder,
        *,
        target: ExecutorEngineOperationTargetV1,
        name: str,
        subnet: str,
        gateway: str,
        options: Sequence[NetworkOptionV1],
    ) -> AllocatedNetworkObservationV1:
        _claim_and_complete(
            recorder,
            kind=ExecutorEngineOperationKindV1.NETWORK_ABSENCE_CHECK,
            target=target,
            action=lambda: self._engine.assert_network_absent(name),
        )
        _claim_and_complete(
            recorder,
            kind=ExecutorEngineOperationKindV1.NETWORK_CREATE,
            target=target,
            action=lambda: self._engine.create_network(
                name=name, subnet=subnet, gateway=gateway, options=options
            ),
        )
        result = _claim_and_complete(
            recorder,
            kind=ExecutorEngineOperationKindV1.NETWORK_INSPECT,
            target=target,
            action=lambda: self._engine.inspect_network(
                name=name, subnet=subnet, gateway=gateway, options=options
            ),
        )
        if type(result) is not AllocatedNetworkObservationV1:
            raise AllocationBackendError("network_projection")
        return result

    def _allocate_volume(
        self,
        recorder: _OperationRecorder,
        *,
        target: ExecutorEngineOperationTargetV1,
        name: str,
        options: Sequence[NetworkOptionV1],
        engine_fingerprint_sha256: str,
    ) -> AllocatedVolumeObservationV1:
        _claim_and_complete(
            recorder,
            kind=ExecutorEngineOperationKindV1.VOLUME_ABSENCE_CHECK,
            target=target,
            action=lambda: self._engine.assert_volume_absent(name),
        )
        _claim_and_complete(
            recorder,
            kind=ExecutorEngineOperationKindV1.VOLUME_CREATE,
            target=target,
            action=lambda: self._engine.create_volume(name=name, options=options),
        )
        result = _claim_and_complete(
            recorder,
            kind=ExecutorEngineOperationKindV1.VOLUME_INSPECT,
            target=target,
            action=lambda: self._engine.inspect_volume(
                name=name,
                engine_fingerprint_sha256=engine_fingerprint_sha256,
                options=options,
            ),
        )
        if type(result) is not AllocatedVolumeObservationV1:
            raise AllocationBackendError("volume_projection")
        return result

    def _run_postgres_step(
        self,
        recorder: _OperationRecorder,
        *,
        target: ExecutorEngineOperationTargetV1,
        sql: bytearray,
        parse_output: Callable[[bytearray], object] | None = None,
    ) -> object:
        try:
            exec_id = _claim_and_complete(
                recorder,
                kind=ExecutorEngineOperationKindV1.POSTGRES_EXEC_CREATE,
                target=target,
                action=lambda: self._engine.create_exec(policy=self._artifacts.postgres_prepared),
            )
            if type(exec_id) is not str:
                raise AllocationBackendError("postgres_exec")
            _claim_and_complete(
                recorder,
                kind=ExecutorEngineOperationKindV1.POSTGRES_EXEC_INSPECT,
                target=target,
                action=lambda: self._engine.inspect_exec(
                    exec_id=exec_id,
                    policy=self._artifacts.postgres_prepared,
                    command=self._artifacts.postgres_prepared.fixed_psql_argv,
                ),
            )

            def start_and_validate() -> object:
                output = self._engine.start_exec(exec_id=exec_id, sql=sql)
                if type(output) is not bytearray:
                    raise AllocationBackendError("postgres_exec")
                if parse_output is not None:
                    return parse_output(output)
                try:
                    if output:
                        raise AllocationBackendError("postgres_output")
                    return None
                finally:
                    output[:] = b"\x00" * len(output)

            return _claim_and_complete(
                recorder,
                kind=ExecutorEngineOperationKindV1.POSTGRES_EXEC_START,
                target=target,
                action=start_and_validate,
            )
        finally:
            sql[:] = b"\x00" * len(sql)

    def _allocate_postgres(
        self,
        recorder: _OperationRecorder,
        policy: PostgreSQLControlPolicyV1,
        prepared: PostgreSQLPreparedControlPolicyV2,
    ) -> AllocatedPostgreSQLObservationV1:
        for target, sql in (
            (ExecutorEngineOperationTargetV1.ALLOCATION_POSTGRES_ROLES, _sql_roles(policy)),
            (ExecutorEngineOperationTargetV1.ALLOCATION_POSTGRES_DATABASE, _sql_database(policy)),
            (
                ExecutorEngineOperationTargetV1.ALLOCATION_POSTGRES_SCHEMA_ACL,
                _sql_schema_acl(policy),
            ),
        ):
            result = self._run_postgres_step(recorder, target=target, sql=sql)
            if result is not None:
                raise AllocationBackendError("postgres_output")
        result = self._run_postgres_step(
            recorder,
            target=ExecutorEngineOperationTargetV1.ALLOCATION_POSTGRES_OBSERVATION,
            sql=_sql_observation(policy),
            parse_output=lambda output: _parse_postgres_observation(
                output,
                policy=policy,
                prepared=prepared,
            ),
        )
        if (
            type(result) is not AllocatedPostgreSQLObservationV1
            or result.system_identifier != prepared.system_identifier
        ):
            raise AllocationBackendError("postgres_projection")
        return result

    def _final_network(
        self,
        recorder: _OperationRecorder,
        observation: AllocatedNetworkObservationV1,
        plan: IsolatedNetworkPlanV1,
    ) -> None:
        result = _claim_and_complete(
            recorder,
            kind=ExecutorEngineOperationKindV1.NETWORK_FINAL_INSPECT,
            target=(
                ExecutorEngineOperationTargetV1.PRIMARY_NETWORK
                if observation.name == self._artifacts.intent.plan.topology.primary_network.name
                else ExecutorEngineOperationTargetV1.RESTORE_NETWORK
            ),
            action=lambda: self._engine.inspect_network(
                name=observation.name,
                subnet=plan.subnet,
                gateway=plan.gateway,
                options=plan.options,
            ),
        )
        if result != observation:
            raise AllocationBackendError("network_race")

    def _final_volume(
        self,
        recorder: _OperationRecorder,
        observation: AllocatedVolumeObservationV1,
        plan: AllocationVolumePlanV1,
        engine: EngineIdentityObservationV1,
    ) -> None:
        result = _claim_and_complete(
            recorder,
            kind=ExecutorEngineOperationKindV1.VOLUME_FINAL_INSPECT,
            target=(
                ExecutorEngineOperationTargetV1.PRIMARY_CACHE_VOLUME
                if observation.name == self._artifacts.intent.plan.primary_valkey_volume.name
                else ExecutorEngineOperationTargetV1.RESTORE_CACHE_VOLUME
            ),
            action=lambda: self._engine.inspect_volume(
                name=observation.name,
                engine_fingerprint_sha256=engine.engine_fingerprint_sha256,
                options=plan.options,
            ),
        )
        if result != observation:
            raise AllocationBackendError("volume_race")

    def materialize_and_start(
        self,
        context: object,
        delivery: object,
    ) -> ExecutorBackendReceiptV2:
        del context
        zeroize = getattr(delivery, "zeroize", None)
        if callable(zeroize):
            with suppress(Exception):
                zeroize()
        raise AllocationBackendError("backend_unavailable")

    def start(self, context: object, delivery: object) -> ExecutorBackendReceiptV2:
        del context
        zeroize = getattr(delivery, "zeroize", None)
        if callable(zeroize):
            with suppress(Exception):
                zeroize()
        raise AllocationBackendError("backend_unavailable")

    def reconcile_read_only(self) -> AllocationReconciliationProjectionV1:
        """Inspect only known allocation state; never resumes or creates resources.

        PostgreSQL inspection uses the pre-existing pinned control container
        only to run two fixed read-only psql stdin templates. The transient
        Engine exec descriptors carry no values, have no authorization journal
        effect, and are not an allocation/resource mutation capability.
        """

        plan = self._artifacts.intent.plan
        api_version = self._engine.version()
        projection = self._engine.info(api_version=api_version)
        if projection != self._artifacts.docker.engine_projection:
            raise AllocationBackendError("engine_projection")
        engine = EngineIdentityObservationV1(
            projection=projection,
            engine_fingerprint_sha256=self._artifacts.docker.engine_fingerprint_sha256,
        )
        control_image_evidence = self._engine._local_image_evidence(
            self._artifacts.postgres_prepared.control_image
        )
        index_reference = self._engine.inspect_image_reference(
            self._artifacts.postgres_prepared.control_image,
            reference=self._artifacts.postgres_prepared.control_image.image,
        )
        manifest_reference = self._engine.inspect_image_reference(
            self._artifacts.postgres_prepared.control_image,
            reference=self._engine._manifest_reference(
                self._artifacts.postgres_prepared.control_image
            ),
        )
        if (
            index_reference != control_image_evidence.registry_index_reference.reference
            or manifest_reference != control_image_evidence.linux_amd64_manifest_reference.reference
        ):
            raise AllocationBackendError("control_image")
        self._engine.assert_control_container(self._artifacts.postgres_prepared)
        observed_networks: list[str] = []
        observed_volumes: list[str] = []
        for name, subnet, gateway, options in (
            (
                plan.topology.primary_network.name,
                plan.topology.primary_network.subnet,
                plan.topology.primary_network.gateway,
                plan.topology.primary_network.options,
            ),
            (
                plan.topology.restore_network.name,
                plan.topology.restore_network.subnet,
                plan.topology.restore_network.gateway,
                plan.topology.restore_network.options,
            ),
        ):
            try:
                self._engine.inspect_network(
                    name=name, subnet=subnet, gateway=gateway, options=options
                )
                observed_networks.append(name)
            except AllocationBackendError as error:
                if not _is_confirmed_not_found(error):
                    raise
        for name, options in (
            (plan.primary_valkey_volume.name, plan.primary_valkey_volume.options),
            (plan.restore_valkey_volume.name, plan.restore_valkey_volume.options),
        ):
            try:
                self._engine.inspect_volume(
                    name=name,
                    engine_fingerprint_sha256=engine.engine_fingerprint_sha256,
                    options=options,
                )
                observed_volumes.append(name)
            except AllocationBackendError as error:
                if not _is_confirmed_not_found(error):
                    raise
        postgres_state, observed_postgres = self._reconcile_postgres()
        names = observed_networks + observed_volumes
        state = (
            AllocationReconciliationStateV1.ABSENT
            if not names and postgres_state is AllocationReconciliationPostgreSQLStateV1.ABSENT
            else (
                AllocationReconciliationStateV1.COMPLETE
                if len(names) == 4
                and postgres_state is AllocationReconciliationPostgreSQLStateV1.COMPLETE
                else AllocationReconciliationStateV1.PARTIAL
            )
        )
        return AllocationReconciliationProjectionV1(
            schema_version="rsd.allocation-reconciliation-projection.v1",
            allocation_intent_sha256=canonical_sha256(self._artifacts.intent),
            engine=engine,
            control_image_local_evidence=control_image_evidence,
            state=state,
            observed_network_names=tuple(observed_networks),
            observed_volume_names=tuple(observed_volumes),
            postgres_state=postgres_state,
            observed_postgres=observed_postgres,
            observed_at=_system_utc_clock().isoformat(timespec="seconds").replace("+00:00", "Z"),
        )

    def _reconcile_postgres(
        self,
    ) -> tuple[AllocationReconciliationPostgreSQLStateV1, AllocatedPostgreSQLObservationV1 | None]:
        """Classify only the exact signed role/database/schema state."""

        policy = self._artifacts.postgres
        prepared = self._artifacts.postgres_prepared
        first_exec = self._engine.create_exec(policy=prepared)
        first_output = self._engine.start_exec(
            exec_id=first_exec,
            sql=_sql_postgres_presence(policy, in_target_database=False),
        )
        database_exists, owner_exists, application_exists, _schema = _parse_postgres_presence(
            first_output
        )
        if not database_exists:
            state = (
                AllocationReconciliationPostgreSQLStateV1.ABSENT
                if not owner_exists and not application_exists
                else AllocationReconciliationPostgreSQLStateV1.PARTIAL
            )
            return state, None
        if not owner_exists or not application_exists:
            return AllocationReconciliationPostgreSQLStateV1.PARTIAL, None
        second_exec = self._engine.create_exec(policy=prepared)
        second_output = self._engine.start_exec(
            exec_id=second_exec,
            sql=_sql_postgres_presence(policy, in_target_database=True),
        )
        _database, _owner, _application, schema_exists = _parse_postgres_presence(second_output)
        if not schema_exists:
            return AllocationReconciliationPostgreSQLStateV1.PARTIAL, None
        observation_exec = self._engine.create_exec(policy=prepared)
        observation_output = self._engine.start_exec(
            exec_id=observation_exec,
            sql=_sql_observation(policy),
        )
        observation = _parse_postgres_observation(
            observation_output,
            policy=policy,
            prepared=prepared,
        )
        if observation.system_identifier != prepared.system_identifier:
            raise AllocationBackendError("postgres_reconciliation")
        return AllocationReconciliationPostgreSQLStateV1.COMPLETE, observation


def load_sealed_allocation_backend(
    paths: AllocationBackendArtifactPathsV1,
    *,
    signer: TrustedEd25519SignerV1,
    transport: VerifiedExecutorTransportArtifactsV2,
) -> SealedAllocationBackendV1:
    """Build the concrete allocation-only backend from verified files only."""

    artifacts = load_verified_allocation_backend_artifacts(
        paths, signer=signer, transport=transport
    )
    return SealedAllocationBackendV1(artifacts, _capability=_ALLOCATION_BACKEND_CAPABILITY)


__all__ = [
    "AllocationBackendArtifactPathsV1",
    "AllocationBackendError",
    "AllocationReconciliationPostgreSQLStateV1",
    "AllocationReconciliationProjectionV1",
    "AllocationReconciliationReceiptV1",
    "AllocationReconciliationStateV1",
    "SealedAllocationBackendV1",
    "VerifiedAllocationBackendArtifactsV1",
    "allocation_postgres_result_schema_sha256",
    "allocation_postgres_template_bundle_sha256",
    "allocation_reconciliation_receipt_message",
    "load_sealed_allocation_backend",
    "load_verified_allocation_backend_artifacts",
    "verify_allocation_reconciliation_receipt",
]
