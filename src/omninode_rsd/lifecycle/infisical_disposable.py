"""Offline Phase-A evidence compiler for a disposable Infisical acceptance lane.

The module performs no network, container, database, provider, or receipt write
operation.  It compiles value-free, owner-only artifacts into a non-authorizing
receipt; a separately authorized runtime must verify signatures and live
provenance before it can perform any action.
"""

from __future__ import annotations

import argparse
import base64
import binascii
import hashlib
import ipaddress
import json
import os
import re
import stat
from collections.abc import Sequence
from contextlib import suppress
from dataclasses import dataclass
from datetime import UTC, datetime, timedelta
from enum import StrEnum
from pathlib import Path
from typing import Final, Literal, Self, cast
from urllib.parse import urlsplit

import yaml
from pydantic import BaseModel, ConfigDict, Field, ValidationError, field_validator, model_validator

_MAX_INPUT_BYTES: Final = 131_072
_FRESHNESS: Final = timedelta(minutes=15)
_SHA256: Final = r"^[0-9a-f]{64}$"
_COMMIT: Final = r"^[0-9a-f]{40}$"
_UUID: Final = r"^[0-9a-f]{8}-[0-9a-f]{4}-[1-5][0-9a-f]{3}-[89ab][0-9a-f]{3}-[0-9a-f]{12}$"
_IDENTIFIER: Final = r"^[A-Za-z][A-Za-z0-9_.-]{0,127}$"
_OWNER_IDENTITY: Final = r"^[A-Za-z0-9][A-Za-z0-9@._+-]{0,254}$"
_TIMESTAMP: Final = re.compile(
    r"[0-9]{4}-[0-9]{2}-[0-9]{2}T[0-9]{2}:[0-9]{2}:[0-9]{2}(?:[.][0-9]{1,6})?Z\Z"
)


class DisposablePreflightError(RuntimeError):
    """Value-redacted, fail-closed Phase-A error."""

    def __init__(self, phase: str) -> None:
        self.phase = phase
        super().__init__(f"disposable preflight failed at phase: {phase}")


class DisposableTransportProfile(StrEnum):
    TLS_VERIFIED = "tls_verified_v1"
    UNPUBLISHED_LOOPBACK_OR_NETWORK = "unpublished_loopback_or_network_v1"


class StableIdentifierKind(StrEnum):
    AUTHORITY_HASH = "authority_hash"
    MACHINE_PORT = "machine_port"
    COMPOSE_SERVICE = "compose_service"
    IMAGE_REPO_DIGEST = "image_repo_digest"
    NETWORK = "network"
    NETWORK_ALIAS = "network_alias"
    VOLUME = "volume"
    POSTGRES_SYSTEM_DATABASE = "postgres_system_database"
    POSTGRES_SYSTEM_DATABASE_OID = "postgres_system_database_oid"
    POSTGRES_OWNER = "postgres_owner"
    VALKEY_NAMESPACE_WORKLOAD = "valkey_namespace_workload"
    PROVIDER_REFERENCE = "provider_reference"
    WORKLOAD = "workload"


class _Model(BaseModel):
    model_config = ConfigDict(extra="forbid", frozen=True, strict=True, validate_default=True)


def _digest(value: bytes) -> str:
    return hashlib.sha256(value).hexdigest()


def canonical_sha256(model: BaseModel) -> str:
    """Return a content commitment for one typed model."""

    return _digest(
        json.dumps(model.model_dump(mode="json"), sort_keys=True, separators=(",", ":")).encode()
    )


def _canonical_model_bytes(model: BaseModel) -> bytes:
    """Render a typed model as the one JSON spelling used at security boundaries."""

    try:
        return json.dumps(
            model.model_dump(mode="json", warnings="error"),
            sort_keys=True,
            separators=(",", ":"),
        ).encode("utf-8")
    except Exception:
        raise ValueError("model is not canonically serializable") from None


def _same_exact_model_shape(original: object, canonical: object) -> bool:
    """Reject ``model_construct``/``model_copy`` values with typed-field drift.

    Equality is insufficient here because ``StrEnum`` compares equal to its
    string value.  A signed model may be revalidated from canonical JSON, but
    accepting its pre-validation object would still let a raw string or a
    subclass reach an enum-sensitive boundary.
    """

    if type(original) is not type(canonical):
        return False
    if isinstance(original, BaseModel):
        if not isinstance(canonical, BaseModel) or type(original) is not type(canonical):
            return False
        return all(
            _same_exact_model_shape(getattr(original, name), getattr(canonical, name))
            for name in original.__class__.model_fields
        )
    if type(original) is tuple:
        canonical_tuple = cast(tuple[object, ...], canonical)
        return len(original) == len(canonical_tuple) and all(
            _same_exact_model_shape(left, right)
            for left, right in zip(original, canonical_tuple, strict=True)
        )
    if type(original) is list:
        canonical_list = cast(list[object], canonical)
        return len(original) == len(canonical_list) and all(
            _same_exact_model_shape(left, right)
            for left, right in zip(original, canonical_list, strict=True)
        )
    if type(original) is dict:
        canonical_dict = cast(dict[object, object], canonical)
        if len(original) != len(canonical_dict):
            return False
        return all(
            _same_exact_model_shape(left_key, right_key)
            and _same_exact_model_shape(original[left_key], canonical_dict[right_key])
            for left_key, right_key in zip(original, canonical_dict, strict=True)
        )
    return original == canonical


def _strict_canonical_model[StrictModel: BaseModel](
    model: object, model_type: type[StrictModel]
) -> StrictModel:
    """Round-trip a model and reject every noncanonical or type-drifted input."""

    if type(model) is not model_type:
        raise ValueError("model type is invalid")
    try:
        original = _canonical_model_bytes(cast(BaseModel, model))
        canonical = model_type.model_validate_json(original, strict=True)
        rendered = _canonical_model_bytes(canonical)
    except Exception:
        raise ValueError("model is invalid") from None
    if (
        type(canonical) is not model_type
        or original != rendered
        or not _same_exact_model_shape(model, canonical)
    ):
        raise ValueError("model is not canonical")
    return canonical


def _is_tls_verified_profile(profile: object) -> bool:
    """Compare the canonical profile value only after exact enum validation."""

    return (
        type(profile) is DisposableTransportProfile
        and profile.value == DisposableTransportProfile.TLS_VERIFIED.value
    )


def _timestamp(value: str) -> datetime:
    if not _TIMESTAMP.fullmatch(value):
        raise ValueError("timestamp must be canonical UTC")
    try:
        return datetime.fromisoformat(value.removesuffix("Z") + "+00:00")
    except ValueError:
        raise ValueError("timestamp is invalid") from None


def _authority(value: str, *, schemes: frozenset[str]) -> str:
    if type(value) is not str or any(character.isspace() for character in value):
        raise ValueError("authority is not canonical")
    try:
        parsed = urlsplit(value)
        port = parsed.port
    except ValueError:
        raise ValueError("authority is not canonical") from None
    if (
        parsed.scheme not in schemes
        or parsed.hostname is None
        or parsed.username is not None
        or parsed.password is not None
        or parsed.path
        or parsed.query
        or parsed.fragment
        or port is None
    ):
        raise ValueError("authority is not canonical")
    try:
        host = ipaddress.ip_address(parsed.hostname)
    except ValueError:
        raise ValueError("authority host must be an IP literal") from None
    rendered = f"[{host.compressed}]" if host.version == 6 else host.compressed
    if value != f"{parsed.scheme}://{rendered}:{port}":
        raise ValueError("authority is not canonical")
    return value


def _items(value: object, *, field: str) -> tuple[object, ...]:
    if type(value) is tuple:
        return cast(tuple[object, ...], value)
    if type(value) is not list:
        raise ValueError(f"{field} must be a sequence")
    return tuple(value)


class ImageReferenceV1(_Model):
    reference: str = Field(min_length=20, max_length=512)

    @model_validator(mode="after")
    def immutable(self) -> Self:
        if self.reference.count("@") != 1:
            raise ValueError("image reference must contain one digest separator")
        repository, digest = self.reference.split("@", 1)
        registry, separator, image = repository.partition("/")
        if (
            not separator
            or not registry
            or not image
            or ("." not in registry and ":" not in registry)
            or not re.fullmatch(r"sha256:[0-9a-f]{64}", digest)
            or ":" in repository.rsplit("/", 1)[-1]
        ):
            raise ValueError("image reference must be a full registry RepoDigest")
        return self


class ProviderReferenceV1(_Model):
    """Version-pinned metadata only; no provider value is represented."""

    provider: str = Field(pattern=_IDENTIFIER)
    service: str = Field(pattern=_IDENTIFIER)
    account: str = Field(pattern=_IDENTIFIER)
    version: int = Field(ge=1, le=1_000_000)
    reference_sha256: str = Field(pattern=_SHA256)

    @model_validator(mode="after")
    def binds_metadata(self) -> Self:
        expected = _digest(
            json.dumps(
                {
                    "account": self.account,
                    "provider": self.provider,
                    "service": self.service,
                    "version": self.version,
                },
                sort_keys=True,
                separators=(",", ":"),
            ).encode()
        )
        if self.reference_sha256 != expected:
            raise ValueError("provider reference hash does not bind metadata")
        return self

    @property
    def identity(self) -> tuple[str, str, str]:
        return (self.provider, self.service, self.account)


class ProviderReferencesV2(_Model):
    """Version-2 runtime provider references.

    This is the sole public aggregate reference model for the seven required
    provider items. There is deliberately no V1 alias or parser for the former
    six-item material set.
    """

    commitment_hmac: ProviderReferenceV1
    backup_encryption: ProviderReferenceV1
    encryption_key: ProviderReferenceV1
    auth_secret: ProviderReferenceV1
    primary_valkey_password: ProviderReferenceV1
    restore_valkey_password: ProviderReferenceV1
    postgres_application_password: ProviderReferenceV1
    tls_trust_anchor: ProviderReferenceV1 | None = None

    def all(self) -> tuple[ProviderReferenceV1, ...]:
        result = (
            self.commitment_hmac,
            self.backup_encryption,
            self.encryption_key,
            self.auth_secret,
            self.primary_valkey_password,
            self.restore_valkey_password,
            self.postgres_application_password,
        )
        return result if self.tls_trust_anchor is None else (*result, self.tls_trust_anchor)

    @model_validator(mode="after")
    def unique(self) -> Self:
        values = self.all()
        if len({value.identity for value in values}) != len(values):
            raise ValueError("provider items must be distinct")
        if len({value.reference_sha256 for value in values}) != len(values):
            raise ValueError("provider hashes must be distinct")
        return self


class PostgreSQLAcceptanceOverlayV1(_Model):
    """Public acceptance overlay binding. It intentionally has no connection string."""

    schema_version: Literal["rsd.postgres-acceptance-overlay.v1"]
    database_name: str = Field(pattern=_IDENTIFIER)
    database_oid: int = Field(ge=1)
    owner_role: str = Field(pattern=_IDENTIFIER)
    secret_provider_kind: Literal["infisical"]
    secret_project: str = Field(pattern=_IDENTIFIER)
    secret_environment: str = Field(pattern=_IDENTIFIER)
    secret_path: str = Field(pattern=r"^/[A-Za-z0-9_/-]{1,256}$")


class PostgreSQLContractV1(_Model):
    authority: str
    system_identifier: str = Field(pattern=r"^[0-9]{8,32}$")
    database_name: str = Field(pattern=_IDENTIFIER)
    database_oid: int = Field(ge=1)
    schema_name: str = Field(pattern=_IDENTIFIER)
    owner_role: str = Field(pattern=_IDENTIFIER)
    role_names: tuple[str, ...] = Field(min_length=1, max_length=16)
    schema_fingerprint_sha256: str = Field(pattern=_SHA256)
    membership_fingerprint_sha256: str = Field(pattern=_SHA256)
    database_acl_sha256: str = Field(pattern=_SHA256)
    stage_database_prefix: str = Field(pattern=_IDENTIFIER)
    restore_database_prefix: str = Field(pattern=_IDENTIFIER)

    @field_validator("authority")
    @classmethod
    def canonical_postgres(cls, value: str) -> str:
        return _authority(value, schemes=frozenset({"postgresql"}))

    @model_validator(mode="after")
    def names_differ(self) -> Self:
        if len({self.database_name, self.stage_database_prefix, self.restore_database_prefix}) != 3:
            raise ValueError("database name and prefixes must differ")
        if self.owner_role not in self.role_names or len(set(self.role_names)) != len(
            self.role_names
        ):
            raise ValueError("PostgreSQL roles must be distinct and include the owner")
        return self

    @field_validator("role_names", mode="before")
    @classmethod
    def declared_roles(cls, value: object) -> tuple[object, ...]:
        roles = _items(value, field="role_names")
        if not all(
            type(role) is str and re.fullmatch(_IDENTIFIER, role) is not None for role in roles
        ):
            raise ValueError("PostgreSQL roles must be declared identifiers")
        return roles


class TransportContractV1(_Model):
    profile: DisposableTransportProfile
    authority: str
    authority_sha256: str = Field(pattern=_SHA256)
    listener_binding: Literal["tls_lan", "loopback_only", "isolated_network_only"]
    host_listener_port: int | None = Field(default=None, ge=1, le=65535)
    isolated_network_name: str | None = Field(default=None, pattern=_IDENTIFIER)
    isolated_network_alias: str | None = Field(default=None, pattern=_IDENTIFIER)
    tls_trust_anchor_reference_sha256: str | None = Field(default=None, pattern=_SHA256)
    minimum_tls_version: Literal["TLSv1.3"] | None = None

    @field_validator("profile", mode="before")
    @classmethod
    def declared_profile(cls, value: object) -> DisposableTransportProfile:
        if isinstance(value, DisposableTransportProfile):
            return value
        if type(value) is not str:
            raise ValueError("transport profile must be a declared string")
        try:
            return DisposableTransportProfile(value)
        except ValueError:
            raise ValueError("transport profile is unknown") from None

    @field_validator("authority")
    @classmethod
    def canonical_transport(cls, value: str) -> str:
        return _authority(value, schemes=frozenset({"http", "https"}))

    @model_validator(mode="after")
    def no_lan_cleartext(self) -> Self:
        if self.authority_sha256 != _digest(self.authority.encode()):
            raise ValueError("authority hash does not bind authority")
        parsed = urlsplit(self.authority)
        assert parsed.hostname is not None and parsed.port is not None
        address = ipaddress.ip_address(parsed.hostname)
        if type(self.profile) is not DisposableTransportProfile:
            raise ValueError("transport profile must be canonical")
        if _is_tls_verified_profile(self.profile):
            valid = (
                parsed.scheme == "https"
                and self.listener_binding == "tls_lan"
                and self.host_listener_port == parsed.port
                and self.isolated_network_name is None
                and self.isolated_network_alias is None
                and self.tls_trust_anchor_reference_sha256 is not None
                and self.minimum_tls_version == "TLSv1.3"
            )
        else:
            valid = (
                parsed.scheme == "http"
                and self.tls_trust_anchor_reference_sha256 is None
                and self.minimum_tls_version is None
                and (
                    (
                        address.is_loopback
                        and self.listener_binding == "loopback_only"
                        and self.host_listener_port == parsed.port
                        and self.isolated_network_name is None
                        and self.isolated_network_alias is None
                    )
                    or (
                        not address.is_loopback
                        and address.is_private
                        and not address.is_unspecified
                        and not address.is_multicast
                        and not address.is_link_local
                        and self.listener_binding == "isolated_network_only"
                        and self.host_listener_port is None
                        and self.isolated_network_name is not None
                        and self.isolated_network_alias is not None
                    )
                )
            )
        if not valid:
            raise ValueError("transport profile is unsafe")
        return self


class StableIdentifierV1(_Model):
    kind: StableIdentifierKind
    value: str = Field(min_length=1, max_length=512)

    @field_validator("kind", mode="before")
    @classmethod
    def declared_kind(cls, value: object) -> StableIdentifierKind:
        if isinstance(value, StableIdentifierKind):
            return value
        if type(value) is not str:
            raise ValueError("identifier kind must be a declared string")
        try:
            return StableIdentifierKind(value)
        except ValueError:
            raise ValueError("identifier kind is unknown") from None


class ServiceIdentityV1(_Model):
    authority: str | None = None
    authority_sha256: str | None = Field(default=None, pattern=_SHA256)
    machine_id: str = Field(pattern=_IDENTIFIER)
    compose_project: str = Field(pattern=_IDENTIFIER)
    service_name: str = Field(pattern=_IDENTIFIER)
    network_name: str = Field(pattern=_IDENTIFIER)
    network_id: str = Field(pattern=r"^[0-9a-f]{64}$")
    container_id: str = Field(pattern=r"^[0-9a-f]{64}$")
    workload_name: str = Field(pattern=_IDENTIFIER)
    workload_id: str = Field(pattern=r"^[0-9a-f]{64}$")
    image: ImageReferenceV1
    listener_binding: Literal["tls_lan", "loopback_only", "isolated_network_only"]
    host_listener_port: int | None = Field(default=None, ge=1, le=65535)
    isolated_network_alias: str | None = Field(default=None, pattern=_IDENTIFIER)

    @field_validator("authority")
    @classmethod
    def canonical_service(cls, value: str | None) -> str | None:
        if value is None:
            return value
        return _authority(value, schemes=frozenset({"http", "https"}))

    @model_validator(mode="after")
    def binds_listener(self) -> Self:
        if self.authority is None:
            if self.authority_sha256 is not None:
                raise ValueError("missing service authority cannot have a hash")
            parsed = None
        else:
            parsed = urlsplit(self.authority)
            assert parsed.port is not None and parsed.hostname is not None
            if self.authority_sha256 != _digest(self.authority.encode()):
                raise ValueError("service authority hash does not bind authority")
        if self.listener_binding == "isolated_network_only":
            if self.host_listener_port is not None or self.isolated_network_alias is None:
                raise ValueError("isolated service cannot publish a port")
            if self.authority is not None:
                assert parsed is not None and parsed.hostname is not None
                address = ipaddress.ip_address(parsed.hostname)
                if (
                    parsed.scheme != "http"
                    or address.is_loopback
                    or not address.is_private
                    or address.is_unspecified
                    or address.is_multicast
                    or address.is_link_local
                ):
                    raise ValueError("isolated service authority must be internal HTTP")
        elif self.authority is None or self.authority_sha256 is None:
            raise ValueError("listener port must bind authority")
        else:
            assert parsed is not None and parsed.port is not None
            if self.isolated_network_alias is not None or self.host_listener_port != parsed.port:
                raise ValueError("listener port must bind authority")
        return self

    def stable(self) -> tuple[StableIdentifierV1, ...]:
        output = [
            StableIdentifierV1(
                kind=StableIdentifierKind.COMPOSE_SERVICE,
                value=f"{self.compose_project}/{self.service_name}",
            ),
            StableIdentifierV1(kind=StableIdentifierKind.NETWORK, value=self.network_id),
            StableIdentifierV1(
                kind=StableIdentifierKind.IMAGE_REPO_DIGEST, value=self.image.reference
            ),
            StableIdentifierV1(kind=StableIdentifierKind.WORKLOAD, value=self.workload_id),
        ]
        if self.authority_sha256 is not None:
            output.append(
                StableIdentifierV1(
                    kind=StableIdentifierKind.AUTHORITY_HASH, value=self.authority_sha256
                )
            )
        if self.isolated_network_alias is not None:
            output.append(
                StableIdentifierV1(
                    kind=StableIdentifierKind.NETWORK_ALIAS,
                    value=f"{self.network_id}/{self.isolated_network_alias}",
                )
            )
        if self.host_listener_port is not None:
            output.append(
                StableIdentifierV1(
                    kind=StableIdentifierKind.MACHINE_PORT,
                    value=f"{self.machine_id}:{self.host_listener_port}",
                )
            )
        return tuple(output)


class ValkeyIdentityV1(_Model):
    compose_project: str = Field(pattern=_IDENTIFIER)
    service_name: str = Field(pattern=_IDENTIFIER)
    network_name: str = Field(pattern=_IDENTIFIER)
    network_id: str = Field(pattern=r"^[0-9a-f]{64}$")
    volume_name: str = Field(pattern=_IDENTIFIER)
    volume_id: str = Field(pattern=r"^[0-9a-f]{64}$")
    container_id: str = Field(pattern=r"^[0-9a-f]{64}$")
    workload_name: str = Field(pattern=_IDENTIFIER)
    workload_id: str = Field(pattern=r"^[0-9a-f]{64}$")
    logical_namespace: str = Field(pattern=_IDENTIFIER)
    credential_reference_sha256: str = Field(pattern=_SHA256)
    image: ImageReferenceV1

    def stable(self) -> tuple[StableIdentifierV1, ...]:
        return (
            StableIdentifierV1(
                kind=StableIdentifierKind.COMPOSE_SERVICE,
                value=f"{self.compose_project}/{self.service_name}",
            ),
            StableIdentifierV1(kind=StableIdentifierKind.NETWORK, value=self.network_id),
            StableIdentifierV1(kind=StableIdentifierKind.VOLUME, value=self.volume_id),
            StableIdentifierV1(
                kind=StableIdentifierKind.VALKEY_NAMESPACE_WORKLOAD,
                value=f"{self.logical_namespace}/{self.workload_id}",
            ),
            StableIdentifierV1(
                kind=StableIdentifierKind.PROVIDER_REFERENCE, value=self.credential_reference_sha256
            ),
            StableIdentifierV1(
                kind=StableIdentifierKind.IMAGE_REPO_DIGEST, value=self.image.reference
            ),
        )


class CandidateCompositeV1(_Model):
    authority: str
    authority_sha256: str = Field(pattern=_SHA256)
    primary_service: ServiceIdentityV1
    restore_service: ServiceIdentityV1
    postgres: PostgreSQLContractV1
    primary_valkey: ValkeyIdentityV1
    restore_valkey: ValkeyIdentityV1

    @field_validator("authority")
    @classmethod
    def canonical_candidate(cls, value: str) -> str:
        return _authority(value, schemes=frozenset({"http", "https"}))

    @model_validator(mode="after")
    def isolated_pairs(self) -> Self:
        if self.authority_sha256 != _digest(self.authority.encode()):
            raise ValueError("candidate authority hash does not bind authority")
        if (
            self.primary_service.authority != self.authority
            or self.primary_service.authority_sha256 != self.authority_sha256
        ):
            raise ValueError("primary service must bind candidate authority")
        if (
            self.restore_service.listener_binding != "isolated_network_only"
            or self.restore_service.host_listener_port is not None
            or self.restore_service.authority is not None
            or self.restore_service.authority_sha256 is not None
            or self.restore_service.isolated_network_alias is None
        ):
            raise ValueError("restore service must be unpublished and isolated")
        services = (self.primary_service, self.restore_service)
        caches = (self.primary_valkey, self.restore_valkey)
        components = (*services, *caches)
        if len({item.container_id for item in components}) != 4:
            raise ValueError("all component container identities must be distinct")
        if (
            self.primary_service.network_name != self.primary_valkey.network_name
            or self.primary_service.network_id != self.primary_valkey.network_id
            or self.restore_service.network_name != self.restore_valkey.network_name
            or self.restore_service.network_id != self.restore_valkey.network_id
            or self.primary_service.network_name == self.restore_service.network_name
            or self.primary_service.network_id == self.restore_service.network_id
        ):
            raise ValueError(
                "primary and restore component pairs must use distinct shared networks"
            )
        if len({item.workload_id for item in components}) != 4:
            raise ValueError("all component workload identities must be distinct")
        if len({item.workload_name for item in components}) != 4:
            raise ValueError("all component workload names must be distinct")
        if (
            len({item.volume_id for item in caches}) != 2
            or len({item.volume_name for item in caches}) != 2
            or len({item.logical_namespace for item in caches}) != 2
        ):
            raise ValueError("primary and restore Valkey storage must be distinct")
        if len({(item.compose_project, item.service_name) for item in (*services, *caches)}) != 4:
            raise ValueError("all compose identities must be distinct")
        return self

    def stable(self) -> tuple[StableIdentifierV1, ...]:
        return (
            *self.primary_service.stable(),
            *self.restore_service.stable(),
            StableIdentifierV1(
                kind=StableIdentifierKind.POSTGRES_SYSTEM_DATABASE,
                value=f"{self.postgres.system_identifier}/{self.postgres.database_name}",
            ),
            StableIdentifierV1(
                kind=StableIdentifierKind.POSTGRES_SYSTEM_DATABASE_OID,
                value=f"{self.postgres.system_identifier}/{self.postgres.database_oid}",
            ),
            StableIdentifierV1(
                kind=StableIdentifierKind.POSTGRES_OWNER,
                value=f"{self.postgres.system_identifier}/{self.postgres.owner_role}",
            ),
            *self.primary_valkey.stable(),
            *self.restore_valkey.stable(),
        )


class DetachedSignatureV1(_Model):
    algorithm: Literal["ed25519-detached-v1"]
    signer_key_id: str = Field(pattern=_IDENTIFIER)
    signer_public_key_fingerprint_sha256: str = Field(pattern=_SHA256)
    detached_signature_sha256: str = Field(pattern=_SHA256)


class ProposalV1(_Model):
    schema_version: Literal["rsd.disposable-infisical-proposal.v1"]
    operation_id: str = Field(pattern=_UUID)
    source_commit: str = Field(pattern=_COMMIT)
    transport: TransportContractV1
    candidate: CandidateCompositeV1
    primary_image: ImageReferenceV1
    restore_image: ImageReferenceV1
    provider_references: ProviderReferencesV2
    retention_expires_at: str
    disposal_owner: str = Field(pattern=_OWNER_IDENTITY)
    approval_reference_sha256: str = Field(pattern=_SHA256)
    allocation_evidence: AllocationEvidenceBindingsV1

    @field_validator("retention_expires_at")
    @classmethod
    def future_retention(cls, value: str) -> str:
        if _timestamp(value) <= datetime.now(UTC):
            raise ValueError("retention expiry must be future")
        return value

    @model_validator(mode="after")
    def binds_candidate(self) -> Self:
        primary = self.candidate.primary_service
        if (
            self.transport.authority != self.candidate.authority
            or self.transport.authority_sha256 != self.candidate.authority_sha256
            or primary.authority != self.transport.authority
            or primary.authority_sha256 != self.transport.authority_sha256
            or primary.listener_binding != self.transport.listener_binding
            or primary.host_listener_port != self.transport.host_listener_port
        ):
            raise ValueError("transport must bind primary candidate service")
        if self.transport.listener_binding == "isolated_network_only" and (
            primary.network_name != self.transport.isolated_network_name
            or primary.isolated_network_alias != self.transport.isolated_network_alias
        ):
            raise ValueError("isolated transport must bind primary network alias")
        if self.primary_image != self.restore_image:
            raise ValueError("primary and restore images must share one digest")
        if (
            self.candidate.primary_service.image != self.primary_image
            or self.candidate.restore_service.image != self.restore_image
        ):
            raise ValueError("proposal images do not bind candidate")
        if (
            self.candidate.primary_valkey.credential_reference_sha256
            != self.provider_references.primary_valkey_password.reference_sha256
            or self.candidate.restore_valkey.credential_reference_sha256
            != self.provider_references.restore_valkey_password.reference_sha256
        ):
            raise ValueError("proposal provider references do not bind candidate")
        anchor = self.provider_references.tls_trust_anchor
        if type(self.transport.profile) is not DisposableTransportProfile:
            raise ValueError("transport profile must be canonical")
        if _is_tls_verified_profile(self.transport.profile):
            if (
                anchor is None
                or anchor.reference_sha256 != self.transport.tls_trust_anchor_reference_sha256
            ):
                raise ValueError("TLS profile must bind trust reference")
        elif anchor is not None:
            raise ValueError("unpublished profile cannot carry TLS trust reference")
        return self


def proposal_sha256(proposal: ProposalV1) -> str:
    data = proposal.model_dump(mode="json", include=set(ProposalV1.model_fields))
    return _digest(json.dumps(data, sort_keys=True, separators=(",", ":")).encode())


class EvidenceBindingsV1(_Model):
    approval_sha256: str = Field(pattern=_SHA256)
    governed_baseline_sha256: str = Field(pattern=_SHA256)
    target_attestation_sha256: str = Field(pattern=_SHA256)
    provider_declaration_sha256: str = Field(pattern=_SHA256)
    registry_verification_sha256: str = Field(pattern=_SHA256)
    postgres_overlay_sha256: str = Field(pattern=_SHA256)


class RuntimeContractV1(ProposalV1):
    proposal_sha256: str = Field(pattern=_SHA256)
    evidence: EvidenceBindingsV1

    @model_validator(mode="after")
    def final_binds_proposal(self) -> Self:
        if self.proposal_sha256 != proposal_sha256(self):
            raise ValueError("runtime contract does not bind proposal")
        return self


class AllocationOperationKind(StrEnum):
    """The only pre-runtime operation kind."""

    ALLOCATION = "allocation_v2"


class AllocationScope(StrEnum):
    """The sole V2 allocation effect is intentionally resource-only."""

    ALLOCATE_ISOLATED_EMPTY_RESOURCES = "allocate_isolated_empty_resources_v2"


class MaterializationOperationKind(StrEnum):
    """The post-allocation operation that may create and start runtime containers."""

    MATERIALIZATION = "materialization_v1"


class MaterializationScope(StrEnum):
    """Materialization may only create the final isolated runtime."""

    MATERIALIZE_AND_START_RUNTIME = "materialize_and_start_runtime_v1"


class StartRuntimeOperationKind(StrEnum):
    """A fresh, separately authorized start or restart of the final runtime."""

    START_RUNTIME = "start_runtime_v2"


class StartRuntimeScope(StrEnum):
    """Start never creates resources or reuses a previous secret delivery."""

    START_RUNTIME = "start_runtime_v2"


class ObservedLifecycleOperationKind(StrEnum):
    """The post-runtime lifecycle operation kind."""

    OBSERVED_LIFECYCLE = "observed_lifecycle_v1"


def _canonical_base64_bytes(value: str) -> bytes:
    """Accept only uniquely spelled standard base64 signatures."""

    try:
        decoded = base64.b64decode(value, validate=True)
    except (binascii.Error, ValueError):
        raise ValueError("signature base64 is invalid") from None
    if base64.b64encode(decoded).decode("ascii") != value:
        raise ValueError("signature base64 is not canonical")
    return decoded


def _isolated_ipv4(value: str, *, field: str) -> str:
    if type(value) is not str:
        raise ValueError(f"{field} must be a canonical IPv4 literal")
    try:
        address = ipaddress.ip_address(value)
    except ValueError:
        raise ValueError(f"{field} must be a canonical IPv4 literal") from None
    if (
        address.version != 4
        or not address.is_private
        or address.is_loopback
        or address.is_unspecified
        or address.is_multicast
        or address.is_link_local
        or str(address) != value
    ):
        raise ValueError(f"{field} must be a non-public IPv4 literal")
    return value


def _isolated_ipv4_network(value: str) -> str:
    if type(value) is not str:
        raise ValueError("network subnet must be canonical")
    try:
        network = ipaddress.ip_network(value, strict=True)
    except ValueError:
        raise ValueError("network subnet must be canonical") from None
    if network.version != 4 or not network.is_private or network.with_prefixlen != value:
        raise ValueError("network subnet must be a non-public IPv4 CIDR")
    return value


class NetworkOptionV1(_Model):
    """A non-secret, exact Docker-network or volume option binding."""

    key: str = Field(pattern=_IDENTIFIER)
    value: str = Field(pattern=r"^[A-Za-z0-9_.:/=-]{1,256}$")


class IsolatedNetworkPlanV1(_Model):
    """One internal IPAM network allocated before runtime materialization."""

    name: str = Field(pattern=_IDENTIFIER)
    driver: Literal["bridge"]
    internal: Literal[True]
    subnet: str
    gateway: str
    options: tuple[NetworkOptionV1, ...] = Field(default=(), max_length=16)

    @field_validator("subnet")
    @classmethod
    def canonical_subnet(cls, value: str) -> str:
        return _isolated_ipv4_network(value)

    @field_validator("gateway")
    @classmethod
    def canonical_gateway(cls, value: str) -> str:
        return _isolated_ipv4(value, field="network gateway")

    @field_validator("options", mode="before")
    @classmethod
    def declared_options(cls, value: object) -> tuple[object, ...]:
        return _items(value, field="network options")

    @model_validator(mode="after")
    def exact_configuration(self) -> Self:
        network = ipaddress.ip_network(self.subnet)
        if ipaddress.ip_address(self.gateway) not in network:
            raise ValueError("network gateway must belong to subnet")
        pairs = tuple((option.key, option.value) for option in self.options)
        if pairs != tuple(sorted(pairs)) or len(set(pairs)) != len(pairs):
            raise ValueError("network options must be unique and canonical")
        return self


class AllocationVolumePlanV1(_Model):
    """One empty volume allocated before any cache container exists."""

    name: str = Field(pattern=_IDENTIFIER)
    driver: Literal["local"]
    options: tuple[NetworkOptionV1, ...] = Field(default=(), max_length=16)

    @field_validator("options", mode="before")
    @classmethod
    def declared_options(cls, value: object) -> tuple[object, ...]:
        return _items(value, field="volume options")

    @model_validator(mode="after")
    def exact_configuration(self) -> Self:
        pairs = tuple((option.key, option.value) for option in self.options)
        if pairs != tuple(sorted(pairs)) or len(set(pairs)) != len(pairs):
            raise ValueError("volume options must be unique and canonical")
        return self


class ComponentPlacementV1(_Model):
    """The single permitted attachment and static address of a runtime component."""

    component: Literal[
        "primary_infisical",
        "primary_valkey",
        "restore_infisical",
        "restore_valkey",
    ]
    network_name: str = Field(pattern=_IDENTIFIER)
    alias: str = Field(pattern=_IDENTIFIER)
    static_ipv4: str

    @field_validator("static_ipv4")
    @classmethod
    def canonical_address(cls, value: str) -> str:
        return _isolated_ipv4(value, field="component static IPv4")


class ExecutorPlacementV1(_Model):
    """The local executor's explicitly limited disposable-network attachment set."""

    executor_id: str = Field(pattern=_IDENTIFIER)
    placement: Literal["inside_disposable_networks_v1"]
    attached_network_names: tuple[str, str]

    @field_validator("attached_network_names", mode="before")
    @classmethod
    def declared_networks(cls, value: object) -> tuple[object, ...]:
        networks = _items(value, field="executor attached networks")
        if not all(
            type(network) is str and re.fullmatch(_IDENTIFIER, network) is not None
            for network in networks
        ):
            raise ValueError("executor attached networks must be identifiers")
        return networks


class AllocationTopologyV2(_Model):
    """The complete allowed attachment graph; no component may join another network."""

    primary_network: IsolatedNetworkPlanV1
    restore_network: IsolatedNetworkPlanV1
    primary_infisical: ComponentPlacementV1
    primary_valkey: ComponentPlacementV1
    restore_infisical: ComponentPlacementV1
    restore_valkey: ComponentPlacementV1
    executor: ExecutorPlacementV1

    @model_validator(mode="after")
    def exact_pair_isolation(self) -> Self:
        primary = self.primary_network
        restore = self.restore_network
        placements = (
            self.primary_infisical,
            self.primary_valkey,
            self.restore_infisical,
            self.restore_valkey,
        )
        if primary.name == restore.name or ipaddress.ip_network(primary.subnet).overlaps(
            ipaddress.ip_network(restore.subnet)
        ):
            raise ValueError("primary and restore networks must be distinct and non-overlapping")
        if tuple(item.component for item in placements) != (
            "primary_infisical",
            "primary_valkey",
            "restore_infisical",
            "restore_valkey",
        ):
            raise ValueError("topology components are not canonical")
        if (
            self.primary_infisical.network_name != primary.name
            or self.primary_valkey.network_name != primary.name
            or self.restore_infisical.network_name != restore.name
            or self.restore_valkey.network_name != restore.name
        ):
            raise ValueError("component attachment escapes its isolated pair")
        addresses = tuple(item.static_ipv4 for item in placements)
        aliases = tuple(item.alias for item in placements)
        if len(set(addresses)) != len(addresses) or len(set(aliases)) != len(aliases):
            raise ValueError("component aliases and static addresses must be distinct")
        for placement, network in (
            (self.primary_infisical, primary),
            (self.primary_valkey, primary),
            (self.restore_infisical, restore),
            (self.restore_valkey, restore),
        ):
            address = ipaddress.ip_address(placement.static_ipv4)
            if (
                address not in ipaddress.ip_network(network.subnet)
                or placement.static_ipv4 == network.gateway
            ):
                raise ValueError("component static address does not belong to its isolated network")
        if self.executor.attached_network_names != (primary.name, restore.name):
            raise ValueError("executor attachment set must be exactly both isolated networks")
        return self


class ExecutorIdentityV1(_Model):
    """A non-secret remote executor identity and attestation trust anchor.

    This model intentionally contains public keys and immutable fingerprints
    only.  It neither represents a Secure Shell client signing key nor permits a caller to
    select an ambient local Docker socket.
    """

    executor_id: str = Field(pattern=_IDENTIFIER)
    platform: Literal["remote_linux_systemd_v1"]
    authenticated_transport: Literal["ssh_forced_command_v1"]
    endpoint_sha256: str = Field(pattern=_SHA256)
    host_fingerprint_sha256: str = Field(pattern=_SHA256)
    control_capability_fingerprint_sha256: str = Field(pattern=_SHA256)
    attestation_key_id: str = Field(pattern=_IDENTIFIER)
    attestation_public_key_base64: str = Field(min_length=4, max_length=128)
    attestation_public_key_fingerprint_sha256: str = Field(pattern=_SHA256)
    credential_custody: Literal["tpm2_systemd_encrypted_credential_v1"]
    monotonic_revision: int = Field(ge=1)
    expires_at: str

    @field_validator("expires_at")
    @classmethod
    def canonical_expiry(cls, value: str) -> str:
        _timestamp(value)
        return value

    @model_validator(mode="after")
    def distinct_identity_bindings(self) -> Self:
        try:
            public_key = _canonical_base64_bytes(self.attestation_public_key_base64)
        except ValueError:
            raise ValueError("executor identity attestation key is invalid") from None
        values = (
            self.endpoint_sha256,
            self.host_fingerprint_sha256,
            self.control_capability_fingerprint_sha256,
            self.attestation_public_key_fingerprint_sha256,
        )
        if (
            len(public_key) != 32
            or _digest(public_key) != self.attestation_public_key_fingerprint_sha256
            or len(set(values)) != len(values)
        ):
            raise ValueError("executor identity bindings must be distinct")
        return self


class SSHConnectionPolicyV1(_Model):
    """Exact public Secure Shell transport policy for one forced-command executor."""

    host_key_fingerprints_sha256: tuple[str, ...] = Field(min_length=1, max_length=8)
    dedicated_user: str = Field(pattern=_IDENTIFIER)
    client_key_fingerprint_sha256: str = Field(pattern=_SHA256)
    force_command: Literal["omninode_rsd_executor_v1"]
    force_command_sha256: str = Field(pattern=_SHA256)
    batch_mode: Literal[True]
    strict_host_key_checking: Literal[True]
    disable_forwarding: Literal[True]
    permit_tty: Literal[False]
    forward_agent: Literal[False]
    forward_x11: Literal[False]
    permit_port_forwarding: Literal[False]
    permit_streamlocal_forwarding: Literal[False]
    control_master: Literal[False]

    @field_validator("host_key_fingerprints_sha256", mode="before")
    @classmethod
    def declared_host_key_fingerprints(cls, value: object) -> tuple[object, ...]:
        return _items(value, field="host-key fingerprints")

    @field_validator("host_key_fingerprints_sha256")
    @classmethod
    def canonical_host_key_fingerprints(cls, value: tuple[str, ...]) -> tuple[str, ...]:
        if any(type(item) is not str or re.fullmatch(_SHA256, item) is None for item in value):
            raise ValueError("remote executor policy is invalid")
        return value

    @model_validator(mode="after")
    def exact_forced_command_boundary(self) -> Self:
        if (
            tuple(sorted(self.host_key_fingerprints_sha256)) != self.host_key_fingerprints_sha256
            or len(set(self.host_key_fingerprints_sha256)) != len(self.host_key_fingerprints_sha256)
            or self.client_key_fingerprint_sha256 in self.host_key_fingerprints_sha256
            or self.force_command_sha256 != _digest(self.force_command.encode("ascii"))
        ):
            raise ValueError("remote executor policy is invalid")
        return self


class ExecutorInstallationPolicyV1(_Model):
    """Signed installation policy for a future remote executor effect only."""

    schema_version: Literal["rsd.executor-installation-policy.v1"]
    source_commit: str = Field(pattern=_COMMIT)
    allocation_intent_sha256: str = Field(pattern=_SHA256)
    disposal_owner: str = Field(pattern=_OWNER_IDENTITY)
    approver_identity: str = Field(pattern=_OWNER_IDENTITY)
    executor: ExecutorIdentityV1
    ssh: SSHConnectionPolicyV1
    package_sha256: str = Field(pattern=_SHA256)
    executable_sha256: str = Field(pattern=_SHA256)
    template_bundle_sha256: str = Field(pattern=_SHA256)
    systemd_unit_sha256: str = Field(pattern=_SHA256)
    unix_socket_policy_sha256: str = Field(pattern=_SHA256)
    allowed_host_fingerprint_sha256: str = Field(pattern=_SHA256)
    allowed_engine_fingerprint_sha256: str = Field(pattern=_SHA256)
    allowed_postgres_identity_sha256: str = Field(pattern=_SHA256)
    allowed_operation_scopes: tuple[
        Literal[
            "allocate_isolated_empty_resources_v2",
            "materialize_and_start_runtime_v1",
            "start_runtime_v2",
        ],
        Literal[
            "allocate_isolated_empty_resources_v2",
            "materialize_and_start_runtime_v1",
            "start_runtime_v2",
        ],
        Literal[
            "allocate_isolated_empty_resources_v2",
            "materialize_and_start_runtime_v1",
            "start_runtime_v2",
        ],
    ]
    created_at: str
    expires_at: str
    signer_key_id: str = Field(pattern=_IDENTIFIER)
    signature_base64: str = Field(min_length=4, max_length=256)

    @field_validator("created_at", "expires_at")
    @classmethod
    def canonical_time(cls, value: str) -> str:
        _timestamp(value)
        return value

    @field_validator("allowed_operation_scopes", mode="before")
    @classmethod
    def declared_allowed_operations(cls, value: object) -> tuple[object, ...]:
        return _items(value, field="executor installation operation scopes")

    @model_validator(mode="after")
    def bounded_installation(self) -> Self:
        commitments = (
            self.package_sha256,
            self.executable_sha256,
            self.template_bundle_sha256,
            self.systemd_unit_sha256,
            self.unix_socket_policy_sha256,
            self.allowed_host_fingerprint_sha256,
            self.allowed_engine_fingerprint_sha256,
            self.allowed_postgres_identity_sha256,
        )
        if (
            self.allowed_operation_scopes
            != (
                "allocate_isolated_empty_resources_v2",
                "materialize_and_start_runtime_v1",
                "start_runtime_v2",
            )
            or len(set(commitments)) != len(commitments)
            or self.allowed_host_fingerprint_sha256 != self.executor.host_fingerprint_sha256
            or self.executor.host_fingerprint_sha256 not in self.ssh.host_key_fingerprints_sha256
            or _timestamp(self.expires_at) <= _timestamp(self.created_at)
            or len(_canonical_base64_bytes(self.signature_base64)) != 64
        ):
            raise ValueError("executor installation policy is invalid")
        return self


class ImageConfigBindingV1(_Model):
    """A pinned image and non-secret immutable digest for one runtime component."""

    component: Literal[
        "primary_infisical",
        "primary_valkey",
        "restore_infisical",
        "restore_valkey",
    ]
    image: ImageReferenceV1
    config_sha256: str = Field(pattern=_SHA256)


class ExecutorControlPolicyV1(_Model):
    """Signed allowlist for the pinned remote executor installation."""

    schema_version: Literal["rsd.executor-control-policy.v1"]
    source_commit: str = Field(pattern=_COMMIT)
    executor: ExecutorIdentityV1
    installation_policy_sha256: str = Field(pattern=_SHA256)
    engine_fingerprint_sha256: str = Field(pattern=_SHA256)
    allowed_operations: tuple[
        Literal[
            "allocate_isolated_empty_resources_v2",
            "materialize_and_start_runtime_v1",
            "start_runtime_v2",
        ],
        Literal[
            "allocate_isolated_empty_resources_v2",
            "materialize_and_start_runtime_v1",
            "start_runtime_v2",
        ],
        Literal[
            "allocate_isolated_empty_resources_v2",
            "materialize_and_start_runtime_v1",
            "start_runtime_v2",
        ],
    ]
    image_configs: tuple[
        ImageConfigBindingV1,
        ImageConfigBindingV1,
        ImageConfigBindingV1,
        ImageConfigBindingV1,
    ]
    created_at: str
    signer_key_id: str = Field(pattern=_IDENTIFIER)
    signature_base64: str = Field(min_length=4, max_length=256)

    @field_validator("created_at")
    @classmethod
    def canonical_created_at(cls, value: str) -> str:
        _timestamp(value)
        return value

    @field_validator("allowed_operations", "image_configs", mode="before")
    @classmethod
    def declared_sequence(cls, value: object) -> tuple[object, ...]:
        return _items(value, field="executor control policy sequence")

    @model_validator(mode="after")
    def bounded_control(self) -> Self:
        if self.allowed_operations != (
            "allocate_isolated_empty_resources_v2",
            "materialize_and_start_runtime_v1",
            "start_runtime_v2",
        ):
            raise ValueError("executor operation allowlist is not exact")
        if tuple(item.component for item in self.image_configs) != (
            "primary_infisical",
            "primary_valkey",
            "restore_infisical",
            "restore_valkey",
        ):
            raise ValueError("executor image bindings are not canonical")
        if (
            self.installation_policy_sha256 == self.engine_fingerprint_sha256
            or len(_canonical_base64_bytes(self.signature_base64)) != 64
        ):
            raise ValueError("executor control policy signature is invalid")
        return self


class PostgreSQLGrantPlanV1(_Model):
    """One exact non-secret ACL grant that the allocation capability may create."""

    role: str = Field(pattern=_IDENTIFIER)
    grantee: str = Field(pattern=_IDENTIFIER)
    privilege: Literal["USAGE", "CREATE", "SELECT", "INSERT", "UPDATE", "DELETE"]
    schema_name: str = Field(pattern=_IDENTIFIER)


class PostgreSQLAllocationRoleStateV1(_Model):
    """One secret-free PostgreSQL role state admitted during allocation.

    Allocation is deliberately unable to create a login-capable identity or a
    password verifier.  The later, signed materialization transition is the
    only modeled place where the application role can become usable.
    """

    role: str = Field(pattern=_IDENTIFIER)
    role_kind: Literal["database_owner", "application"]
    can_login: Literal[False]
    password_absent: Literal[True]


class PostgreSQLControlPolicyV1(_Model):
    """Signed bounded PostgreSQL control policy; it contains no connection value."""

    schema_version: Literal["rsd.postgresql-control-policy.v1"]
    source_commit: str = Field(pattern=_COMMIT)
    executor_identity_sha256: str = Field(pattern=_SHA256)
    authority: str
    maintenance_reference_sha256: str = Field(pattern=_SHA256)
    database_name: str = Field(pattern=_IDENTIFIER)
    schema_name: str = Field(pattern=_IDENTIFIER)
    owner_role: str = Field(pattern=_IDENTIFIER)
    application_role: str = Field(pattern=_IDENTIFIER)
    role_names: tuple[str, str]
    allocation_role_states: tuple[PostgreSQLAllocationRoleStateV1, PostgreSQLAllocationRoleStateV1]
    grants: tuple[PostgreSQLGrantPlanV1, ...] = Field(default=(), max_length=32)
    created_at: str
    signer_key_id: str = Field(pattern=_IDENTIFIER)
    signature_base64: str = Field(min_length=4, max_length=256)

    @field_validator("authority")
    @classmethod
    def canonical_postgres(cls, value: str) -> str:
        return _authority(value, schemes=frozenset({"postgresql"}))

    @field_validator("role_names", "allocation_role_states", "grants", mode="before")
    @classmethod
    def declared_sequence(cls, value: object) -> tuple[object, ...]:
        return _items(value, field="PostgreSQL control policy sequence")

    @field_validator("created_at")
    @classmethod
    def canonical_created_at(cls, value: str) -> str:
        _timestamp(value)
        return value

    @model_validator(mode="after")
    def bounded_database_control(self) -> Self:
        if (
            self.owner_role == self.application_role
            or self.role_names != (self.owner_role, self.application_role)
            or tuple(state.role for state in self.allocation_role_states) != self.role_names
            or tuple(state.role_kind for state in self.allocation_role_states)
            != ("database_owner", "application")
            or any(
                grant.role not in self.role_names or grant.grantee not in self.role_names
                for grant in self.grants
            )
            or tuple(
                (grant.role, grant.grantee, grant.privilege, grant.schema_name)
                for grant in self.grants
            )
            != tuple(
                sorted(
                    (grant.role, grant.grantee, grant.privilege, grant.schema_name)
                    for grant in self.grants
                )
            )
            or len(_canonical_base64_bytes(self.signature_base64)) != 64
        ):
            raise ValueError("PostgreSQL control policy is invalid")
        return self


class SecretCapabilityPolicyV1(_Model):
    """Signed binding for one remote opaque secret-delivery capability."""

    schema_version: Literal["rsd.secret-capability-policy.v1"]
    source_commit: str = Field(pattern=_COMMIT)
    executor_identity_sha256: str = Field(pattern=_SHA256)
    provider_identity_sha256: str = Field(pattern=_SHA256)
    capability_fingerprint_sha256: str = Field(pattern=_SHA256)
    secret_handling_policy_sha256: str = Field(pattern=_SHA256)
    delivery_mode: Literal["remote_executor_secret_delivery_v2"]
    allowed_purposes: tuple[
        Literal[
            "commitment_hmac",
            "backup_encryption",
            "encryption_key",
            "auth_secret",
            "primary_valkey_password",
            "restore_valkey_password",
            "postgres_application_password",
        ],
        ...,
    ]
    macos_only_purposes: tuple[Literal["commitment_hmac"], Literal["backup_encryption"]]
    created_at: str
    signer_key_id: str = Field(pattern=_IDENTIFIER)
    signature_base64: str = Field(min_length=4, max_length=256)

    @field_validator("allowed_purposes", "macos_only_purposes", mode="before")
    @classmethod
    def declared_purposes(cls, value: object) -> tuple[object, ...]:
        return _items(value, field="secret capability purposes")

    @field_validator("created_at")
    @classmethod
    def canonical_created_at(cls, value: str) -> str:
        _timestamp(value)
        return value

    @model_validator(mode="after")
    def bounded_secret_use(self) -> Self:
        expected = (
            "commitment_hmac",
            "backup_encryption",
            "encryption_key",
            "auth_secret",
            "primary_valkey_password",
            "restore_valkey_password",
            "postgres_application_password",
        )
        macos_only = ("commitment_hmac", "backup_encryption")
        bindings = (
            self.executor_identity_sha256,
            self.provider_identity_sha256,
            self.capability_fingerprint_sha256,
            self.secret_handling_policy_sha256,
        )
        if (
            self.allowed_purposes != expected
            or self.macos_only_purposes != macos_only
            or len(set(bindings)) != len(bindings)
            or len(_canonical_base64_bytes(self.signature_base64)) != 64
        ):
            raise ValueError("secret capability policy is invalid")
        return self


class SecretHandlingPolicyV1(_Model):
    """Signed, deliberately narrow TCB boundary for a future secret lease.

    This policy does not carry a value or grant a general container trust
    relationship.  It describes only the two disposable target-process sinks
    admitted by the accepted local executor boundary.  The executor must
    reject every other sink before it asks a provider for a value.
    """

    schema_version: Literal["rsd.secret-handling-policy.v1"]
    source_commit: str = Field(pattern=_COMMIT)
    allocation_intent_sha256: str = Field(pattern=_SHA256)
    executor_identity_sha256: str = Field(pattern=_SHA256)
    provider_identity_sha256: str = Field(pattern=_SHA256)
    capability_fingerprint_sha256: str = Field(pattern=_SHA256)
    infisical_target_processes: tuple[Literal["primary_infisical"], Literal["restore_infisical"]]
    valkey_stdin_config_processes: tuple[Literal["primary_valkey"], Literal["restore_valkey"]]
    postgres_application_target_processes: tuple[Literal["postgres_application_target"]]
    infisical_target_process_environment_allowed: Literal[True]
    valkey_stdin_config_allowed: Literal[True]
    postgres_application_target_process_environment_allowed: Literal[True]
    postgres_connection_uri_environment_variable: Literal["DB_CONNECTION_URI"]
    environment_file_allowed: Literal[False]
    host_environment_allowed: Literal[False]
    docker_config_environment_allowed: Literal[False]
    argv_allowed: Literal[False]
    labels_allowed: Literal[False]
    logs_allowed: Literal[False]
    receipts_allowed: Literal[False]
    disk_plaintext_allowed: Literal[False]
    public_artifacts_allowed: Literal[False]
    restart_policy: Literal["no"]
    restart_authorization_schema: Literal["rsd.start-runtime-intent.v2"]
    restart_authorization_scope: Literal["start_runtime_v2"]
    fresh_keychain_redelivery_required: Literal[True]
    created_at: str
    signer_key_id: str = Field(pattern=_IDENTIFIER)
    signature_base64: str = Field(min_length=4, max_length=256)

    @field_validator(
        "infisical_target_processes",
        "valkey_stdin_config_processes",
        "postgres_application_target_processes",
        mode="before",
    )
    @classmethod
    def declared_processes(cls, value: object) -> tuple[object, ...]:
        return _items(value, field="secret handling target processes")

    @field_validator("created_at")
    @classmethod
    def canonical_created_at(cls, value: str) -> str:
        _timestamp(value)
        return value

    @model_validator(mode="after")
    def narrow_trusted_boundary(self) -> Self:
        bindings = (
            self.allocation_intent_sha256,
            self.executor_identity_sha256,
            self.provider_identity_sha256,
            self.capability_fingerprint_sha256,
        )
        if (
            self.infisical_target_processes != ("primary_infisical", "restore_infisical")
            or self.valkey_stdin_config_processes != ("primary_valkey", "restore_valkey")
            or self.postgres_application_target_processes != ("postgres_application_target",)
            or self.infisical_target_process_environment_allowed is not True
            or self.valkey_stdin_config_allowed is not True
            or self.postgres_application_target_process_environment_allowed is not True
            or self.environment_file_allowed is not False
            or len(set(bindings)) != len(bindings)
            or len(_canonical_base64_bytes(self.signature_base64)) != 64
        ):
            raise ValueError("secret handling policy is invalid")
        return self


class AllocationEvidenceBindingsV1(_Model):
    """Signed commitments required before the resource-only allocation effect."""

    approval_sha256: str = Field(pattern=_SHA256)
    governed_deny_sha256: str = Field(pattern=_SHA256)
    governed_baseline_sha256: str = Field(pattern=_SHA256)
    collision_evidence_sha256: str = Field(pattern=_SHA256)
    registry_verification_sha256: str = Field(pattern=_SHA256)
    provider_declaration_sha256: str = Field(pattern=_SHA256)
    executor_control_policy_sha256: str = Field(pattern=_SHA256)
    postgres_control_policy_sha256: str = Field(pattern=_SHA256)

    @model_validator(mode="after")
    def distinct_bindings(self) -> Self:
        values = tuple(self.model_dump(mode="python").values())
        if len(set(values)) != len(values):
            raise ValueError("allocation evidence commitments must be distinct")
        return self


class AllocationPostgreSQLPlanV2(_Model):
    """The empty database/schema/role objects allocation may create through a future capability."""

    authority: str
    database_name: str = Field(pattern=_IDENTIFIER)
    schema_name: str = Field(pattern=_IDENTIFIER)
    owner_role: str = Field(pattern=_IDENTIFIER)
    application_role: str = Field(pattern=_IDENTIFIER)
    role_names: tuple[str, str]
    allocation_role_states: tuple[PostgreSQLAllocationRoleStateV1, PostgreSQLAllocationRoleStateV1]
    grants: tuple[PostgreSQLGrantPlanV1, ...] = Field(default=(), max_length=32)
    stage_database_prefix: str = Field(pattern=_IDENTIFIER)
    restore_database_prefix: str = Field(pattern=_IDENTIFIER)
    control_policy_sha256: str = Field(pattern=_SHA256)

    @field_validator("authority")
    @classmethod
    def canonical_postgres(cls, value: str) -> str:
        return _authority(value, schemes=frozenset({"postgresql"}))

    @field_validator("role_names", "allocation_role_states", "grants", mode="before")
    @classmethod
    def declared_sequence(cls, value: object) -> tuple[object, ...]:
        return _items(value, field="allocation PostgreSQL sequence")

    @model_validator(mode="after")
    def names_and_acl_are_bounded(self) -> Self:
        if (
            len({self.database_name, self.stage_database_prefix, self.restore_database_prefix}) != 3
            or self.owner_role == self.application_role
            or self.role_names != (self.owner_role, self.application_role)
            or tuple(state.role for state in self.allocation_role_states) != self.role_names
            or tuple(state.role_kind for state in self.allocation_role_states)
            != ("database_owner", "application")
            or any(
                grant.role not in self.role_names or grant.grantee not in self.role_names
                for grant in self.grants
            )
            or tuple(
                (grant.role, grant.grantee, grant.privilege, grant.schema_name)
                for grant in self.grants
            )
            != tuple(
                sorted(
                    (grant.role, grant.grantee, grant.privilege, grant.schema_name)
                    for grant in self.grants
                )
            )
        ):
            raise ValueError("allocation PostgreSQL plan is invalid")
        return self


class AllocationPlanV2(_Model):
    """V2 resource-only plan with networks, volumes, and empty PostgreSQL objects."""

    transport: TransportContractV1
    topology: AllocationTopologyV2
    primary_valkey_volume: AllocationVolumePlanV1
    restore_valkey_volume: AllocationVolumePlanV1
    postgres: AllocationPostgreSQLPlanV2

    @model_validator(mode="after")
    def resource_only_non_tls_plan(self) -> Self:
        topology = self.topology
        parsed = urlsplit(self.transport.authority)
        if (
            type(self.transport.profile) is not DisposableTransportProfile
            or _is_tls_verified_profile(self.transport.profile)
            or self.transport.listener_binding != "isolated_network_only"
            or self.transport.host_listener_port is not None
            or self.transport.isolated_network_name != topology.primary_network.name
            or self.transport.isolated_network_alias != topology.primary_infisical.alias
            or parsed.scheme != "http"
            or parsed.hostname != topology.primary_infisical.static_ipv4
            or self.primary_valkey_volume.name == self.restore_valkey_volume.name
            or self.primary_valkey_volume == self.restore_valkey_volume
        ):
            raise ValueError("allocation plan is not an unpublished isolated resource plan")
        return self


class AllocationIntentV2(_Model):
    """Signed authority for exactly the V2 allocation scope and nothing data-bearing."""

    schema_version: Literal["rsd.allocation-intent.v2"]
    operation_kind: Literal["allocation_v2"]
    operation_scope: Literal["allocate_isolated_empty_resources_v2"]
    allocation_operation_id: str = Field(pattern=_UUID)
    source_commit: str = Field(pattern=_COMMIT)
    plan: AllocationPlanV2
    provider_references: ProviderReferencesV2
    evidence: AllocationEvidenceBindingsV1
    retention_expires_at: str
    disposal_owner: str = Field(pattern=_OWNER_IDENTITY)
    approver_identity: str = Field(pattern=_OWNER_IDENTITY)
    approval_reference_sha256: str = Field(pattern=_SHA256)
    journal_path: str = Field(min_length=1, max_length=4096)
    journal_path_sha256: str = Field(pattern=_SHA256)
    journal_uuid: str = Field(pattern=_UUID)
    journal_schema_sha256: str = Field(pattern=_SHA256)
    replay_policy_sha256: str = Field(pattern=_SHA256)
    created_at: str
    signer_key_id: str = Field(pattern=_IDENTIFIER)
    signature_base64: str = Field(min_length=4, max_length=256)

    @field_validator("retention_expires_at", "created_at")
    @classmethod
    def canonical_time(cls, value: str) -> str:
        _timestamp(value)
        return value

    @model_validator(mode="after")
    def binds_preallocation_plan(self) -> Self:
        if (
            not Path(self.journal_path).is_absolute()
            or os.path.normpath(self.journal_path) != self.journal_path
            or self.journal_path_sha256 != _digest(os.fsencode(self.journal_path))
            or _timestamp(self.retention_expires_at) <= _timestamp(self.created_at)
            or len(_canonical_base64_bytes(self.signature_base64)) != 64
            or self.plan.postgres.control_policy_sha256
            != self.evidence.postgres_control_policy_sha256
            or self.provider_references.tls_trust_anchor is not None
        ):
            raise ValueError("allocation intent fields are invalid")
        return self


def strict_canonical_allocation_intent(intent: AllocationIntentV2) -> AllocationIntentV2:
    """Return the only allocation form admissible at a V2 mutation boundary."""

    return _strict_canonical_model(intent, AllocationIntentV2)


def allocation_intent_sha256(intent: AllocationIntentV2) -> str:
    if type(intent) is not AllocationIntentV2:
        raise ValueError("allocation intent is invalid")
    return canonical_sha256(intent)


class AllocatedNetworkObservationV1(_Model):
    """Exact engine observation for one allocated internal network."""

    name: str = Field(pattern=_IDENTIFIER)
    network_id: str = Field(pattern=r"^[0-9a-f]{64}$")
    driver: Literal["bridge"]
    internal: Literal[True]
    subnet: str
    gateway: str
    options: tuple[NetworkOptionV1, ...] = Field(default=(), max_length=16)

    @field_validator("subnet")
    @classmethod
    def canonical_subnet(cls, value: str) -> str:
        return _isolated_ipv4_network(value)

    @field_validator("gateway")
    @classmethod
    def canonical_gateway(cls, value: str) -> str:
        return _isolated_ipv4(value, field="observed network gateway")

    @field_validator("options", mode="before")
    @classmethod
    def declared_options(cls, value: object) -> tuple[object, ...]:
        return _items(value, field="observed network options")

    @model_validator(mode="after")
    def exact_configuration(self) -> Self:
        if ipaddress.ip_address(self.gateway) not in ipaddress.ip_network(self.subnet):
            raise ValueError("observed network gateway must belong to subnet")
        pairs = tuple((option.key, option.value) for option in self.options)
        if pairs != tuple(sorted(pairs)) or len(set(pairs)) != len(pairs):
            raise ValueError("observed network options must be canonical")
        return self


class AllocatedVolumeObservationV1(_Model):
    """Exact engine observation for one empty volume."""

    name: str = Field(pattern=_IDENTIFIER)
    volume_id: str = Field(pattern=r"^[0-9a-f]{64}$")
    driver: Literal["local"]
    options: tuple[NetworkOptionV1, ...] = Field(default=(), max_length=16)

    @field_validator("options", mode="before")
    @classmethod
    def declared_options(cls, value: object) -> tuple[object, ...]:
        return _items(value, field="observed volume options")

    @model_validator(mode="after")
    def exact_configuration(self) -> Self:
        pairs = tuple((option.key, option.value) for option in self.options)
        if pairs != tuple(sorted(pairs)) or len(set(pairs)) != len(pairs):
            raise ValueError("observed volume options must be canonical")
        return self


class PostgreSQLRoleObservationV1(_Model):
    role: str = Field(pattern=_IDENTIFIER)
    role_oid: int = Field(ge=1)
    can_login: Literal[False]
    password_absent: Literal[True]


class PostgreSQLGrantObservationV1(_Model):
    role: str = Field(pattern=_IDENTIFIER)
    grantee: str = Field(pattern=_IDENTIFIER)
    privilege: Literal["USAGE", "CREATE", "SELECT", "INSERT", "UPDATE", "DELETE"]
    schema_name: str = Field(pattern=_IDENTIFIER)


class AllocatedPostgreSQLObservationV1(_Model):
    """The empty PostgreSQL stage identity and ACL observation; no row data is admitted."""

    system_identifier: str = Field(pattern=r"^[0-9]{8,32}$")
    database_name: str = Field(pattern=_IDENTIFIER)
    database_oid: int = Field(ge=1)
    schema_name: str = Field(pattern=_IDENTIFIER)
    schema_oid: int = Field(ge=1)
    owner_role: str = Field(pattern=_IDENTIFIER)
    owner_role_oid: int = Field(ge=1)
    application_role: str = Field(pattern=_IDENTIFIER)
    application_role_oid: int = Field(ge=1)
    role_oids: tuple[PostgreSQLRoleObservationV1, PostgreSQLRoleObservationV1]
    grants: tuple[PostgreSQLGrantObservationV1, ...] = Field(default=(), max_length=32)
    acl_sha256: str = Field(pattern=_SHA256)

    @field_validator("role_oids", "grants", mode="before")
    @classmethod
    def declared_sequence(cls, value: object) -> tuple[object, ...]:
        return _items(value, field="observed PostgreSQL sequence")

    @model_validator(mode="after")
    def exact_acl(self) -> Self:
        roles = tuple(item.role for item in self.role_oids)
        if (
            self.owner_role == self.application_role
            or self.owner_role_oid == self.application_role_oid
            or roles != (self.owner_role, self.application_role)
            or self.owner_role_oid != self.role_oids[0].role_oid
            or self.application_role_oid != self.role_oids[1].role_oid
            or tuple(
                (grant.role, grant.grantee, grant.privilege, grant.schema_name)
                for grant in self.grants
            )
            != tuple(
                sorted(
                    (grant.role, grant.grantee, grant.privilege, grant.schema_name)
                    for grant in self.grants
                )
            )
        ):
            raise ValueError("observed PostgreSQL ACL is invalid")
        return self


class EngineIdentityObservationV1(_Model):
    engine_id: str = Field(pattern=r"^[0-9a-f]{64}$")
    engine_fingerprint_sha256: str = Field(pattern=_SHA256)


class NoHostPublicationGroundworkV1(_Model):
    """Allocation proves zero containers and records the exact future attachment graph."""

    container_ids: tuple[str, ...] = Field(default=(), max_length=0)
    host_network: Literal[False]
    publish_all_ports: Literal[False]
    published_port_bindings: tuple[str, ...] = Field(default=(), max_length=0)
    allowed_attachment_set_sha256: str = Field(pattern=_SHA256)


class AllocatedResourceSetV2(_Model):
    """All and only the resources V2 allocation may report."""

    engine: EngineIdentityObservationV1
    primary_network: AllocatedNetworkObservationV1
    restore_network: AllocatedNetworkObservationV1
    primary_cache_volume: AllocatedVolumeObservationV1
    restore_cache_volume: AllocatedVolumeObservationV1
    postgres: AllocatedPostgreSQLObservationV1
    no_host_publication: NoHostPublicationGroundworkV1

    @model_validator(mode="after")
    def distinct_empty_resources(self) -> Self:
        if (
            self.primary_network.name == self.restore_network.name
            or self.primary_network.network_id == self.restore_network.network_id
            or self.primary_cache_volume.name == self.restore_cache_volume.name
            or self.primary_cache_volume.volume_id == self.restore_cache_volume.volume_id
        ):
            raise ValueError("allocated resources must be distinct")
        return self


class AllocationEffectReceiptV2(_Model):
    """Effect output for the only allocation scope; it contains no runtime container identity."""

    schema_version: Literal["rsd.allocation-effect-receipt.v2"]
    operation_kind: Literal["allocation_v2"]
    operation_scope: Literal["allocate_isolated_empty_resources_v2"]
    status: Literal["allocated_isolated_empty_resources"]
    allocation_operation_id: str = Field(pattern=_UUID)
    allocation_intent_sha256: str = Field(pattern=_SHA256)
    journal_uuid: str = Field(pattern=_UUID)
    idempotency_key: str = Field(pattern=_SHA256)
    allocated_resources: AllocatedResourceSetV2
    effect_receipt_sha256: str = Field(pattern=_SHA256)
    completed_at: str

    @field_validator("completed_at")
    @classmethod
    def completed_time(cls, value: str) -> str:
        _timestamp(value)
        return value


def allocation_effect_receipt_sha256(receipt: AllocationEffectReceiptV2) -> str:
    if type(receipt) is not AllocationEffectReceiptV2:
        raise ValueError("allocation effect receipt is invalid")
    return canonical_sha256(receipt)


class ObservedAllocationAttestationV1(_Model):
    """Signed attestation of the resource-only allocation and isolation groundwork."""

    schema_version: Literal["rsd.observed-allocation-attestation.v1"]
    operation_kind: Literal["allocation_v2"]
    allocation_operation_id: str = Field(pattern=_UUID)
    allocation_intent_sha256: str = Field(pattern=_SHA256)
    allocation_effect_receipt_sha256: str = Field(pattern=_SHA256)
    allocation_topology_sha256: str = Field(pattern=_SHA256)
    allocated_resources: AllocatedResourceSetV2
    observed_at: str
    signer_key_id: str = Field(pattern=_IDENTIFIER)
    signature_base64: str = Field(min_length=4, max_length=256)

    @field_validator("observed_at")
    @classmethod
    def observation_time(cls, value: str) -> str:
        _timestamp(value)
        return value

    @model_validator(mode="after")
    def binds_allocation(self) -> Self:
        if len(_canonical_base64_bytes(self.signature_base64)) != 64:
            raise ValueError("observed allocation signature is invalid")
        return self


def observed_allocation_attestation_sha256(attestation: ObservedAllocationAttestationV1) -> str:
    if type(attestation) is not ObservedAllocationAttestationV1:
        raise ValueError("observed allocation attestation is invalid")
    return canonical_sha256(attestation)


class PostgreSQLLoginTransitionIntentV1(_Model):
    """Signed, observed-OID-bound authorization for the one login transition.

    The model intentionally states only role state and verifier presence.  It
    never carries a password, verifier text, SQL fragment, DSN, or URI.
    """

    schema_version: Literal["rsd.postgresql-login-transition-intent.v1"]
    transition_kind: Literal["enable_application_login_with_provider_verifier_v1"]
    prepared_operation_id: str = Field(pattern=_UUID)
    system_identifier: str = Field(pattern=r"^[0-9]{8,32}$")
    database_name: str = Field(pattern=_IDENTIFIER)
    database_oid: int = Field(ge=1)
    owner_role: str = Field(pattern=_IDENTIFIER)
    owner_role_oid: int = Field(ge=1)
    application_role: str = Field(pattern=_IDENTIFIER)
    application_role_oid: int = Field(ge=1)
    application_password_reference_sha256: str = Field(pattern=_SHA256)
    owner_can_login: Literal[False]
    owner_password_absent: Literal[True]
    application_can_login: Literal[True]
    application_password_verifier_installed: Literal[True]

    @model_validator(mode="after")
    def exact_secret_free_transition(self) -> Self:
        if (
            self.owner_role == self.application_role
            or self.owner_role_oid == self.application_role_oid
        ):
            raise ValueError("PostgreSQL login transition is invalid")
        return self


class PostgreSQLLoginTransitionReceiptV1(_Model):
    """Value-free effect evidence for the one prepared login transition."""

    schema_version: Literal["rsd.postgresql-login-transition-receipt.v1"]
    prepared_operation_id: str = Field(pattern=_UUID)
    system_identifier: str = Field(pattern=r"^[0-9]{8,32}$")
    database_name: str = Field(pattern=_IDENTIFIER)
    database_oid: int = Field(ge=1)
    owner_role: str = Field(pattern=_IDENTIFIER)
    owner_role_oid: int = Field(ge=1)
    application_role: str = Field(pattern=_IDENTIFIER)
    application_role_oid: int = Field(ge=1)
    application_password_reference_sha256: str = Field(pattern=_SHA256)
    owner_can_login: Literal[False]
    owner_password_absent: Literal[True]
    application_can_login: Literal[True]
    application_password_verifier_installed: Literal[True]

    @model_validator(mode="after")
    def exact_secret_free_receipt(self) -> Self:
        if (
            self.owner_role == self.application_role
            or self.owner_role_oid == self.application_role_oid
        ):
            raise ValueError("PostgreSQL login transition receipt is invalid")
        return self


class EphemeralPostgreSQLConnectionPolicyV1(_Model):
    """Bounded URI assembly contract; no URI can leave the trusted effect."""

    schema_version: Literal["rsd.postgresql-ephemeral-connection-policy.v1"]
    authority: str
    database_name: str = Field(pattern=_IDENTIFIER)
    application_role: str = Field(pattern=_IDENTIFIER)
    application_password_reference_sha256: str = Field(pattern=_SHA256)
    prepared_operation_id: str = Field(pattern=_UUID)
    target_process: Literal["postgres_application_target"]
    environment_variable: Literal["DB_CONNECTION_URI"]
    return_uri_allowed: Literal[False]
    persistent_storage_allowed: Literal[False]
    logging_allowed: Literal[False]
    public_artifact_allowed: Literal[False]

    @field_validator("authority")
    @classmethod
    def canonical_postgres(cls, value: str) -> str:
        return _authority(value, schemes=frozenset({"postgresql"}))


class MaterializationComponentPlanV1(_Model):
    """One final runtime component plan. It carries no container ID or secret value."""

    component: Literal[
        "primary_infisical",
        "primary_valkey",
        "restore_infisical",
        "restore_valkey",
    ]
    compose_project: str = Field(pattern=_IDENTIFIER)
    service_name: str = Field(pattern=_IDENTIFIER)
    workload_name: str = Field(pattern=_IDENTIFIER)
    image: ImageReferenceV1
    config_sha256: str = Field(pattern=_SHA256)
    network_name: str = Field(pattern=_IDENTIFIER)
    network_alias: str = Field(pattern=_IDENTIFIER)
    static_ipv4: str
    volume_name: str | None = Field(default=None, pattern=_IDENTIFIER)
    logical_namespace: str | None = Field(default=None, pattern=_IDENTIFIER)
    required_purposes: tuple[
        Literal[
            "commitment_hmac",
            "backup_encryption",
            "encryption_key",
            "auth_secret",
            "primary_valkey_password",
            "restore_valkey_password",
            "postgres_application_password",
        ],
        ...,
    ]

    @field_validator("static_ipv4")
    @classmethod
    def canonical_address(cls, value: str) -> str:
        return _isolated_ipv4(value, field="materialization static IPv4")

    @field_validator("required_purposes", mode="before")
    @classmethod
    def declared_purposes(cls, value: object) -> tuple[object, ...]:
        return _items(value, field="materialization purposes")

    @model_validator(mode="after")
    def bounded_component(self) -> Self:
        expected: dict[str, tuple[str, ...]] = {
            "primary_infisical": ("encryption_key", "auth_secret", "primary_valkey_password"),
            "primary_valkey": ("primary_valkey_password",),
            "restore_infisical": ("encryption_key", "auth_secret", "restore_valkey_password"),
            "restore_valkey": ("restore_valkey_password",),
        }
        cache = self.component.endswith("valkey")
        if (
            self.required_purposes != expected[self.component]
            or (cache and (self.volume_name is None or self.logical_namespace is None))
            or (not cache and (self.volume_name is not None or self.logical_namespace is not None))
        ):
            raise ValueError("materialization component is invalid")
        return self


class MaterializationPlanV1(_Model):
    """The final container plan, admitted only after allocation observation."""

    primary_infisical: MaterializationComponentPlanV1
    primary_valkey: MaterializationComponentPlanV1
    restore_infisical: MaterializationComponentPlanV1
    restore_valkey: MaterializationComponentPlanV1

    @model_validator(mode="after")
    def canonical_components(self) -> Self:
        components = (
            self.primary_infisical,
            self.primary_valkey,
            self.restore_infisical,
            self.restore_valkey,
        )
        if tuple(item.component for item in components) != (
            "primary_infisical",
            "primary_valkey",
            "restore_infisical",
            "restore_valkey",
        ):
            raise ValueError("materialization components are not canonical")
        if len({(item.compose_project, item.service_name) for item in components}) != 4:
            raise ValueError("materialization compose identities must be distinct")
        if len({item.workload_name for item in components}) != 4:
            raise ValueError("materialization workload names must be distinct")
        return self


class ContainerSecretSinkV1(StrEnum):
    """The only non-secret value sinks permitted to a container bootstrap."""

    INFISICAL_TARGET_PROCESS_ENVIRONMENT = "infisical_target_process_environment_v1"
    VALKEY_STDIN_CONFIGURATION = "valkey_stdin_configuration_v1"


class ContainerBootstrapTemplateV1(_Model):
    """Canonical non-secret Docker bootstrap contract for one component.

    A future executor must compare every explicit field with an engine
    inspection.  ``config_sha256`` alone is intentionally insufficient proof.
    """

    schema_version: Literal["rsd.container-bootstrap-template.v1"]
    component: Literal[
        "primary_infisical",
        "primary_valkey",
        "restore_infisical",
        "restore_valkey",
    ]
    image: ImageReferenceV1
    entrypoint_sha256: str = Field(pattern=_SHA256)
    template_sha256: str = Field(pattern=_SHA256)
    run_as_non_root: Literal[True]
    read_only_root_filesystem: Literal[True]
    cap_drop_all: Literal[True]
    no_new_privileges: Literal[True]
    private_pid: Literal[True]
    log_driver: Literal["none"]
    restart_policy: Literal["no"]
    mounts: tuple[str, ...] = Field(default=(), max_length=0)
    docker_socket_mounted: Literal[False]
    host_network: Literal[False]
    publish_all_ports: Literal[False]
    port_bindings: tuple[str, ...] = Field(default=(), max_length=0)
    network_name: str = Field(pattern=_IDENTIFIER)
    network_alias: str = Field(pattern=_IDENTIFIER)
    static_ipv4: str
    accepted_secret_sink: ContainerSecretSinkV1

    @field_validator("static_ipv4")
    @classmethod
    def canonical_address(cls, value: str) -> str:
        return _isolated_ipv4(value, field="container bootstrap static IPv4")

    @field_validator("mounts", "port_bindings", mode="before")
    @classmethod
    def declared_empty_sequence(cls, value: object) -> tuple[object, ...]:
        return _items(value, field="container bootstrap sequence")

    @field_validator("accepted_secret_sink", mode="before")
    @classmethod
    def canonical_sink(cls, value: object) -> ContainerSecretSinkV1:
        if type(value) is ContainerSecretSinkV1:
            return value
        if type(value) is str:
            try:
                return ContainerSecretSinkV1(value)
            except ValueError:
                pass
        raise ValueError("container bootstrap secret sink is invalid")

    @model_validator(mode="after")
    def exact_hardened_runtime(self) -> Self:
        expected_sink = (
            ContainerSecretSinkV1.VALKEY_STDIN_CONFIGURATION
            if self.component.endswith("valkey")
            else ContainerSecretSinkV1.INFISICAL_TARGET_PROCESS_ENVIRONMENT
        )
        if (
            type(self.accepted_secret_sink) is not ContainerSecretSinkV1
            or self.accepted_secret_sink is not expected_sink
            or self.entrypoint_sha256 == self.template_sha256
        ):
            raise ValueError("container bootstrap template is invalid")
        return self


class ContainerBootstrapTemplatesV1(_Model):
    """The complete, ordered bootstrap set for one materialization intent."""

    primary_infisical: ContainerBootstrapTemplateV1
    primary_valkey: ContainerBootstrapTemplateV1
    restore_infisical: ContainerBootstrapTemplateV1
    restore_valkey: ContainerBootstrapTemplateV1

    @model_validator(mode="after")
    def exact_components(self) -> Self:
        templates = (
            self.primary_infisical,
            self.primary_valkey,
            self.restore_infisical,
            self.restore_valkey,
        )
        if (
            tuple(template.component for template in templates)
            != ("primary_infisical", "primary_valkey", "restore_infisical", "restore_valkey")
            or len({template.template_sha256 for template in templates}) != 4
            or len({template.entrypoint_sha256 for template in templates}) != 4
        ):
            raise ValueError("container bootstrap templates are invalid")
        return self


class SecretDeliverySinkV1(StrEnum):
    """The exact non-secret destinations admitted for one delivered slot."""

    INFISICAL_TARGET_PROCESS_ENVIRONMENT = "infisical_target_process_environment_v1"
    VALKEY_STDIN_CONFIGURATION = "valkey_stdin_configuration_v1"
    POSTGRES_APPLICATION_TARGET_ENVIRONMENT = "postgres_application_target_environment_v1"


class SecretDeliverySlotV1(_Model):
    """One value-free, purpose-bound secret delivery authorization.

    A lease implementation may consume the corresponding provider value only
    while fulfilling this typed slot.  It must never return that value through
    this public model or an enclosing capability.
    """

    purpose: Literal[
        "encryption_key",
        "auth_secret",
        "primary_valkey_password",
        "restore_valkey_password",
        "postgres_application_password",
    ]
    reference_sha256: str = Field(pattern=_SHA256)
    format: Literal[
        "infisical_hex_16_v1",
        "infisical_auth_secret_base64_32_v1",
        "valkey_password_base64url_32_v1",
        "postgres_application_password_base64url_32_v1",
    ]
    encoded_byte_count: int = Field(ge=1, le=128)
    sink: SecretDeliverySinkV1
    target_processes: tuple[str, ...] = Field(min_length=1, max_length=2)

    @field_validator("target_processes", mode="before")
    @classmethod
    def declared_targets(cls, value: object) -> tuple[object, ...]:
        return _items(value, field="secret delivery targets")

    @field_validator("sink", mode="before")
    @classmethod
    def canonical_sink(cls, value: object) -> SecretDeliverySinkV1:
        if type(value) is SecretDeliverySinkV1:
            return value
        if type(value) is str:
            try:
                return SecretDeliverySinkV1(value)
            except ValueError:
                pass
        raise ValueError("secret delivery sink is invalid")

    @model_validator(mode="after")
    def exact_nonsecret_slot(self) -> Self:
        expected: dict[str, tuple[str, int, SecretDeliverySinkV1, tuple[str, ...]]] = {
            "encryption_key": (
                "infisical_hex_16_v1",
                32,
                SecretDeliverySinkV1.INFISICAL_TARGET_PROCESS_ENVIRONMENT,
                ("primary_infisical", "restore_infisical"),
            ),
            "auth_secret": (
                "infisical_auth_secret_base64_32_v1",
                44,
                SecretDeliverySinkV1.INFISICAL_TARGET_PROCESS_ENVIRONMENT,
                ("primary_infisical", "restore_infisical"),
            ),
            "primary_valkey_password": (
                "valkey_password_base64url_32_v1",
                43,
                SecretDeliverySinkV1.VALKEY_STDIN_CONFIGURATION,
                ("primary_valkey",),
            ),
            "restore_valkey_password": (
                "valkey_password_base64url_32_v1",
                43,
                SecretDeliverySinkV1.VALKEY_STDIN_CONFIGURATION,
                ("restore_valkey",),
            ),
            "postgres_application_password": (
                "postgres_application_password_base64url_32_v1",
                43,
                SecretDeliverySinkV1.POSTGRES_APPLICATION_TARGET_ENVIRONMENT,
                ("postgres_application_target",),
            ),
        }
        if (
            type(self.sink) is not SecretDeliverySinkV1
            or self.target_processes != expected[self.purpose][3]
            or (self.format, self.encoded_byte_count, self.sink) != expected[self.purpose][:3]
        ):
            raise ValueError("secret delivery slot is invalid")
        return self


class SecretDeliveryRequestV1(_Model):
    """Bounded opaque delivery request handed to a trusted material lease."""

    schema_version: Literal["rsd.secret-delivery-request.v1"]
    operation_scope: Literal["materialize_and_start_runtime_v1", "start_runtime_v2"]
    operation_id: str = Field(pattern=_UUID)
    journal_uuid: str = Field(pattern=_UUID)
    provider_material_attestation_sha256: str = Field(pattern=_SHA256)
    channel_binding_sha256: str = Field(pattern=_SHA256)
    session_binding_sha256: str = Field(pattern=_SHA256)
    request_nonce_sha256: str = Field(pattern=_SHA256)
    slots: tuple[
        SecretDeliverySlotV1,
        SecretDeliverySlotV1,
        SecretDeliverySlotV1,
        SecretDeliverySlotV1,
        SecretDeliverySlotV1,
    ]

    @field_validator("slots", mode="before")
    @classmethod
    def declared_slots(cls, value: object) -> tuple[object, ...]:
        return _items(value, field="secret delivery slots")

    @model_validator(mode="after")
    def complete_exact_slot_set(self) -> Self:
        expected = (
            "encryption_key",
            "auth_secret",
            "primary_valkey_password",
            "restore_valkey_password",
            "postgres_application_password",
        )
        values = (
            self.provider_material_attestation_sha256,
            self.channel_binding_sha256,
            self.session_binding_sha256,
        )
        if tuple(slot.purpose for slot in self.slots) != expected or len(set(values)) != len(
            values
        ):
            raise ValueError("secret delivery request is invalid")
        return self


class SecretDeliverySlotReceiptV1(_Model):
    """Value-free evidence that a lease addressed exactly one authorized slot."""

    purpose: Literal[
        "encryption_key",
        "auth_secret",
        "primary_valkey_password",
        "restore_valkey_password",
        "postgres_application_password",
    ]
    reference_sha256: str = Field(pattern=_SHA256)
    sink: SecretDeliverySinkV1
    target_processes: tuple[str, ...] = Field(min_length=1, max_length=2)
    delivered: Literal[True]

    @field_validator("target_processes", mode="before")
    @classmethod
    def declared_targets(cls, value: object) -> tuple[object, ...]:
        return _items(value, field="secret delivery receipt targets")

    @field_validator("sink", mode="before")
    @classmethod
    def canonical_sink(cls, value: object) -> SecretDeliverySinkV1:
        return SecretDeliverySlotV1.canonical_sink(value)

    @model_validator(mode="after")
    def exact_slot_route(self) -> Self:
        expected: dict[str, tuple[SecretDeliverySinkV1, tuple[str, ...]]] = {
            "encryption_key": (
                SecretDeliverySinkV1.INFISICAL_TARGET_PROCESS_ENVIRONMENT,
                ("primary_infisical", "restore_infisical"),
            ),
            "auth_secret": (
                SecretDeliverySinkV1.INFISICAL_TARGET_PROCESS_ENVIRONMENT,
                ("primary_infisical", "restore_infisical"),
            ),
            "primary_valkey_password": (
                SecretDeliverySinkV1.VALKEY_STDIN_CONFIGURATION,
                ("primary_valkey",),
            ),
            "restore_valkey_password": (
                SecretDeliverySinkV1.VALKEY_STDIN_CONFIGURATION,
                ("restore_valkey",),
            ),
            "postgres_application_password": (
                SecretDeliverySinkV1.POSTGRES_APPLICATION_TARGET_ENVIRONMENT,
                ("postgres_application_target",),
            ),
        }
        if (
            type(self.sink) is not SecretDeliverySinkV1
            or (
                self.sink,
                self.target_processes,
            )
            != expected[self.purpose]
        ):
            raise ValueError("secret delivery receipt slot is invalid")
        return self


class SecretDeliveryReceiptV1(_Model):
    """Opaque delivery completion metadata; no secret bytes or URI are admitted."""

    schema_version: Literal["rsd.secret-delivery-receipt.v1"]
    operation_scope: Literal["materialize_and_start_runtime_v1", "start_runtime_v2"]
    operation_id: str = Field(pattern=_UUID)
    journal_uuid: str = Field(pattern=_UUID)
    request_nonce_sha256: str = Field(pattern=_SHA256)
    channel_binding_sha256: str = Field(pattern=_SHA256)
    session_binding_sha256: str = Field(pattern=_SHA256)
    slots: tuple[
        SecretDeliverySlotReceiptV1,
        SecretDeliverySlotReceiptV1,
        SecretDeliverySlotReceiptV1,
        SecretDeliverySlotReceiptV1,
        SecretDeliverySlotReceiptV1,
    ]
    completed_at: str

    @field_validator("slots", mode="before")
    @classmethod
    def declared_slots(cls, value: object) -> tuple[object, ...]:
        return _items(value, field="secret delivery receipt slots")

    @field_validator("completed_at")
    @classmethod
    def canonical_time(cls, value: str) -> str:
        _timestamp(value)
        return value

    @model_validator(mode="after")
    def complete_exact_receipt_set(self) -> Self:
        expected = (
            "encryption_key",
            "auth_secret",
            "primary_valkey_password",
            "restore_valkey_password",
            "postgres_application_password",
        )
        if tuple(slot.purpose for slot in self.slots) != expected:
            raise ValueError("secret delivery receipt is invalid")
        return self


class MaterializationEvidenceBindingsV1(_Model):
    """Signed chain from allocation observation to the one materialization operation."""

    allocation_intent_sha256: str = Field(pattern=_SHA256)
    allocation_effect_receipt_sha256: str = Field(pattern=_SHA256)
    observed_allocation_attestation_sha256: str = Field(pattern=_SHA256)
    executor_control_policy_sha256: str = Field(pattern=_SHA256)
    executor_installation_policy_sha256: str = Field(pattern=_SHA256)
    executor_installation_intent_sha256: str = Field(pattern=_SHA256)
    executor_installation_receipt_sha256: str = Field(pattern=_SHA256)
    secret_capability_policy_sha256: str = Field(pattern=_SHA256)
    secret_handling_policy_sha256: str = Field(pattern=_SHA256)
    provider_material_attestation_sha256: str = Field(pattern=_SHA256)

    @model_validator(mode="after")
    def distinct_bindings(self) -> Self:
        if len(set(self.model_dump(mode="python").values())) != 10:
            raise ValueError("materialization evidence bindings must be distinct")
        return self


class MaterializationIntentV1(_Model):
    """Signed post-allocation authority for creating and starting final containers once."""

    schema_version: Literal["rsd.materialization-intent.v1"]
    operation_kind: Literal["materialization_v1"]
    operation_scope: Literal["materialize_and_start_runtime_v1"]
    materialization_operation_id: str = Field(pattern=_UUID)
    allocation_operation_id: str = Field(pattern=_UUID)
    source_commit: str = Field(pattern=_COMMIT)
    allocation_intent_sha256: str = Field(pattern=_SHA256)
    allocation_effect_receipt_sha256: str = Field(pattern=_SHA256)
    observed_allocation_attestation_sha256: str = Field(pattern=_SHA256)
    executor_installation_intent_sha256: str = Field(pattern=_SHA256)
    executor_installation_receipt_sha256: str = Field(pattern=_SHA256)
    topology: AllocationTopologyV2
    plan: MaterializationPlanV1
    bootstrap_templates: ContainerBootstrapTemplatesV1
    postgres_login_transition: PostgreSQLLoginTransitionIntentV1
    ephemeral_postgres_connection: EphemeralPostgreSQLConnectionPolicyV1
    secret_delivery_request: SecretDeliveryRequestV1
    provider_references: ProviderReferencesV2
    evidence: MaterializationEvidenceBindingsV1
    retention_expires_at: str
    disposal_owner: str = Field(pattern=_OWNER_IDENTITY)
    approver_identity: str = Field(pattern=_OWNER_IDENTITY)
    approval_reference_sha256: str = Field(pattern=_SHA256)
    journal_uuid: str = Field(pattern=_UUID)
    replay_policy_sha256: str = Field(pattern=_SHA256)
    created_at: str
    signer_key_id: str = Field(pattern=_IDENTIFIER)
    signature_base64: str = Field(min_length=4, max_length=256)

    @field_validator("retention_expires_at", "created_at")
    @classmethod
    def canonical_time(cls, value: str) -> str:
        _timestamp(value)
        return value

    @model_validator(mode="after")
    def binds_allocation_and_provider(self) -> Self:
        components = (
            self.plan.primary_infisical,
            self.plan.primary_valkey,
            self.plan.restore_infisical,
            self.plan.restore_valkey,
        )
        topology = self.topology
        expected = (
            (self.plan.primary_infisical, topology.primary_infisical),
            (self.plan.primary_valkey, topology.primary_valkey),
            (self.plan.restore_infisical, topology.restore_infisical),
            (self.plan.restore_valkey, topology.restore_valkey),
        )
        templates = (
            self.bootstrap_templates.primary_infisical,
            self.bootstrap_templates.primary_valkey,
            self.bootstrap_templates.restore_infisical,
            self.bootstrap_templates.restore_valkey,
        )
        if (
            _timestamp(self.retention_expires_at) <= _timestamp(self.created_at)
            or len(_canonical_base64_bytes(self.signature_base64)) != 64
            or self.provider_references.tls_trust_anchor is not None
            or self.evidence.allocation_intent_sha256 != self.allocation_intent_sha256
            or self.evidence.allocation_effect_receipt_sha256
            != self.allocation_effect_receipt_sha256
            or self.evidence.observed_allocation_attestation_sha256
            != self.observed_allocation_attestation_sha256
            or self.evidence.executor_control_policy_sha256
            == self.evidence.secret_capability_policy_sha256
            or self.evidence.executor_installation_policy_sha256
            == self.evidence.executor_control_policy_sha256
            or self.evidence.executor_installation_intent_sha256
            != self.executor_installation_intent_sha256
            or self.evidence.executor_installation_receipt_sha256
            != self.executor_installation_receipt_sha256
            or self.postgres_login_transition.application_password_reference_sha256
            != self.provider_references.postgres_application_password.reference_sha256
            or self.ephemeral_postgres_connection.application_password_reference_sha256
            != self.postgres_login_transition.application_password_reference_sha256
            or self.ephemeral_postgres_connection.prepared_operation_id
            != self.postgres_login_transition.prepared_operation_id
            or self.ephemeral_postgres_connection.application_role
            != self.postgres_login_transition.application_role
            or self.secret_delivery_request.operation_scope != self.operation_scope
            or self.secret_delivery_request.operation_id != self.materialization_operation_id
            or self.secret_delivery_request.journal_uuid != self.journal_uuid
            or self.secret_delivery_request.provider_material_attestation_sha256
            != self.evidence.provider_material_attestation_sha256
            or any(
                component.network_name != placement.network_name
                or component.network_alias != placement.alias
                or component.static_ipv4 != placement.static_ipv4
                for component, placement in expected
            )
            or any(
                template.component != component.component
                or template.image != component.image
                or template.network_name != placement.network_name
                or template.network_alias != placement.alias
                or template.static_ipv4 != placement.static_ipv4
                for component, placement, template in zip(
                    components, (item[1] for item in expected), templates, strict=True
                )
            )
            or len({component.config_sha256 for component in components}) != 4
        ):
            raise ValueError("materialization intent is invalid")
        references = {
            "encryption_key": self.provider_references.encryption_key.reference_sha256,
            "auth_secret": self.provider_references.auth_secret.reference_sha256,
            "primary_valkey_password": (
                self.provider_references.primary_valkey_password.reference_sha256
            ),
            "restore_valkey_password": (
                self.provider_references.restore_valkey_password.reference_sha256
            ),
            "postgres_application_password": (
                self.provider_references.postgres_application_password.reference_sha256
            ),
        }
        if any(
            slot.reference_sha256 != references[slot.purpose]
            for slot in self.secret_delivery_request.slots
        ):
            raise ValueError("materialization intent secret delivery bindings are invalid")
        return self


def strict_canonical_materialization_intent(
    intent: MaterializationIntentV1,
) -> MaterializationIntentV1:
    return _strict_canonical_model(intent, MaterializationIntentV1)


def materialization_intent_sha256(intent: MaterializationIntentV1) -> str:
    if type(intent) is not MaterializationIntentV1:
        raise ValueError("materialization intent is invalid")
    return canonical_sha256(intent)


class RuntimeNetworkAttachmentV1(_Model):
    network_name: str = Field(pattern=_IDENTIFIER)
    network_id: str = Field(pattern=r"^[0-9a-f]{64}$")
    alias: str = Field(pattern=_IDENTIFIER)
    static_ipv4: str

    @field_validator("static_ipv4")
    @classmethod
    def canonical_address(cls, value: str) -> str:
        return _isolated_ipv4(value, field="runtime static IPv4")


class NoHostPublicationEvidenceV1(_Model):
    """Observed container configuration proving that Docker did not publish a host port."""

    network_mode: Literal["isolated_user_network_v1"]
    host_network: Literal[False]
    publish_all_ports: Literal[False]
    port_bindings: tuple[str, ...] = Field(default=(), max_length=0)

    @field_validator("port_bindings", mode="before")
    @classmethod
    def declared_empty_sequence(cls, value: object) -> tuple[object, ...]:
        return _items(value, field="no-host-publication bindings")


class ContainerBootstrapInspectionV1(_Model):
    """Explicit engine inspection fields required after a future container start."""

    entrypoint_sha256: str = Field(pattern=_SHA256)
    template_sha256: str = Field(pattern=_SHA256)
    run_as_non_root: Literal[True]
    read_only_root_filesystem: Literal[True]
    cap_drop_all: Literal[True]
    no_new_privileges: Literal[True]
    private_pid: Literal[True]
    log_driver: Literal["none"]
    restart_policy: Literal["no"]
    mounts: tuple[str, ...] = Field(default=(), max_length=0)
    docker_socket_mounted: Literal[False]
    host_network: Literal[False]
    publish_all_ports: Literal[False]
    port_bindings: tuple[str, ...] = Field(default=(), max_length=0)
    network_name: str = Field(pattern=_IDENTIFIER)
    network_alias: str = Field(pattern=_IDENTIFIER)
    static_ipv4: str
    accepted_secret_sink: ContainerSecretSinkV1
    running: Literal[True]

    @field_validator("static_ipv4")
    @classmethod
    def canonical_address(cls, value: str) -> str:
        return _isolated_ipv4(value, field="container inspection static IPv4")

    @field_validator("mounts", "port_bindings", mode="before")
    @classmethod
    def declared_empty_sequence(cls, value: object) -> tuple[object, ...]:
        return _items(value, field="container inspection sequence")

    @field_validator("accepted_secret_sink", mode="before")
    @classmethod
    def canonical_sink(cls, value: object) -> ContainerSecretSinkV1:
        return ContainerBootstrapTemplateV1.canonical_sink(value)

    @model_validator(mode="after")
    def distinct_template_fields(self) -> Self:
        if self.entrypoint_sha256 == self.template_sha256:
            raise ValueError("container inspection is invalid")
        return self


class RuntimeContainerObservationV1(_Model):
    """Value-free final container evidence emitted by the future executor."""

    component: Literal[
        "primary_infisical",
        "primary_valkey",
        "restore_infisical",
        "restore_valkey",
    ]
    container_id: str = Field(pattern=r"^[0-9a-f]{64}$")
    workload_id: str = Field(pattern=r"^[0-9a-f]{64}$")
    image: ImageReferenceV1
    config_sha256: str = Field(pattern=_SHA256)
    attachments: tuple[RuntimeNetworkAttachmentV1, ...] = Field(min_length=1, max_length=1)
    no_host_publication: NoHostPublicationEvidenceV1
    inspection: ContainerBootstrapInspectionV1

    @field_validator("attachments", mode="before")
    @classmethod
    def declared_attachments(cls, value: object) -> tuple[object, ...]:
        return _items(value, field="runtime attachments")


class ExecutorInstallationIntentV1(_Model):
    """Signed future-only authority to install, never operate, an executor."""

    schema_version: Literal["rsd.executor-installation-intent.v1"]
    operation_kind: Literal["executor_installation_v1"]
    operation_scope: Literal["install_remote_executor_v1"]
    installation_operation_id: str = Field(pattern=_UUID)
    source_commit: str = Field(pattern=_COMMIT)
    allocation_intent_sha256: str = Field(pattern=_SHA256)
    executor_installation_policy_sha256: str = Field(pattern=_SHA256)
    retention_expires_at: str
    disposal_owner: str = Field(pattern=_OWNER_IDENTITY)
    approver_identity: str = Field(pattern=_OWNER_IDENTITY)
    created_at: str
    signer_key_id: str = Field(pattern=_IDENTIFIER)
    signature_base64: str = Field(min_length=4, max_length=256)

    @field_validator("retention_expires_at", "created_at")
    @classmethod
    def canonical_time(cls, value: str) -> str:
        _timestamp(value)
        return value

    @model_validator(mode="after")
    def bounded_future_installation(self) -> Self:
        if (
            _timestamp(self.retention_expires_at) <= _timestamp(self.created_at)
            or len(_canonical_base64_bytes(self.signature_base64)) != 64
        ):
            raise ValueError("executor installation intent is invalid")
        return self


class ExecutorInstallationReceiptV1(_Model):
    """Redacted signed result reserved for the future installation effect."""

    schema_version: Literal["rsd.executor-installation-receipt.v1"]
    installation_operation_id: str = Field(pattern=_UUID)
    allocation_intent_sha256: str = Field(pattern=_SHA256)
    installation_intent_sha256: str = Field(pattern=_SHA256)
    executor_installation_policy_sha256: str = Field(pattern=_SHA256)
    executor_id: str = Field(pattern=_IDENTIFIER)
    host_fingerprint_sha256: str = Field(pattern=_SHA256)
    engine_fingerprint_sha256: str = Field(pattern=_SHA256)
    package_sha256: str = Field(pattern=_SHA256)
    executable_sha256: str = Field(pattern=_SHA256)
    template_bundle_sha256: str = Field(pattern=_SHA256)
    systemd_unit_sha256: str = Field(pattern=_SHA256)
    unix_socket_policy_sha256: str = Field(pattern=_SHA256)
    ssh_policy_sha256: str = Field(pattern=_SHA256)
    attestation_public_key_fingerprint_sha256: str = Field(pattern=_SHA256)
    monotonic_revision: int = Field(ge=1)
    completed_at: str
    signer_key_id: str = Field(pattern=_IDENTIFIER)
    signature_base64: str = Field(min_length=4, max_length=256)

    @field_validator("completed_at")
    @classmethod
    def canonical_time(cls, value: str) -> str:
        _timestamp(value)
        return value

    @model_validator(mode="after")
    def redacted_receipt(self) -> Self:
        if len(_canonical_base64_bytes(self.signature_base64)) != 64:
            raise ValueError("executor installation receipt is invalid")
        return self


class ExecutorContainerInspectionV1(_Model):
    """One explicit value-free engine inspection inside an executor receipt."""

    component: Literal[
        "primary_infisical",
        "primary_valkey",
        "restore_infisical",
        "restore_valkey",
    ]
    container_id: str = Field(pattern=r"^[0-9a-f]{64}$")
    inspection: ContainerBootstrapInspectionV1


class ExecutorOperationReceiptV1(_Model):
    """Executor-attested, redacted result for materialization or a fresh start."""

    schema_version: Literal["rsd.executor-operation-receipt.v1"]
    executor_id: str = Field(pattern=_IDENTIFIER)
    installation_receipt_sha256: str = Field(pattern=_SHA256)
    operation_scope: Literal["materialize_and_start_runtime_v1", "start_runtime_v2"]
    operation_id: str = Field(pattern=_UUID)
    idempotency_key: str = Field(pattern=_SHA256)
    secret_delivery_receipt_sha256: str = Field(pattern=_SHA256)
    channel_binding_sha256: str = Field(pattern=_SHA256)
    session_binding_sha256: str = Field(pattern=_SHA256)
    host_fingerprint_sha256: str = Field(pattern=_SHA256)
    engine_fingerprint_sha256: str = Field(pattern=_SHA256)
    containers: tuple[
        ExecutorContainerInspectionV1,
        ExecutorContainerInspectionV1,
        ExecutorContainerInspectionV1,
        ExecutorContainerInspectionV1,
    ]
    completed_at: str
    signer_key_id: str = Field(pattern=_IDENTIFIER)
    signature_base64: str = Field(min_length=4, max_length=256)

    @field_validator("containers", mode="before")
    @classmethod
    def declared_containers(cls, value: object) -> tuple[object, ...]:
        return _items(value, field="executor inspected containers")

    @field_validator("completed_at")
    @classmethod
    def canonical_time(cls, value: str) -> str:
        _timestamp(value)
        return value

    @model_validator(mode="after")
    def complete_redacted_inspection(self) -> Self:
        if (
            tuple(item.component for item in self.containers)
            != ("primary_infisical", "primary_valkey", "restore_infisical", "restore_valkey")
            or len({item.container_id for item in self.containers}) != 4
            or len(_canonical_base64_bytes(self.signature_base64)) != 64
        ):
            raise ValueError("executor operation receipt is invalid")
        return self


class MaterializationEffectReceiptV1(_Model):
    """The one value-free receipt that can introduce final runtime container IDs."""

    schema_version: Literal["rsd.materialization-effect-receipt.v1"]
    operation_kind: Literal["materialization_v1"]
    operation_scope: Literal["materialize_and_start_runtime_v1"]
    status: Literal["materialized_and_started_runtime"]
    materialization_operation_id: str = Field(pattern=_UUID)
    materialization_intent_sha256: str = Field(pattern=_SHA256)
    allocation_operation_id: str = Field(pattern=_UUID)
    allocation_effect_receipt_sha256: str = Field(pattern=_SHA256)
    observed_allocation_attestation_sha256: str = Field(pattern=_SHA256)
    journal_uuid: str = Field(pattern=_UUID)
    idempotency_key: str = Field(pattern=_SHA256)
    executor_receipt_sha256: str = Field(pattern=_SHA256)
    executor_receipt: ExecutorOperationReceiptV1
    postgres_login_transition: PostgreSQLLoginTransitionReceiptV1
    delivery_receipt: SecretDeliveryReceiptV1
    primary_infisical: RuntimeContainerObservationV1
    primary_valkey: RuntimeContainerObservationV1
    restore_infisical: RuntimeContainerObservationV1
    restore_valkey: RuntimeContainerObservationV1
    effect_receipt_sha256: str = Field(pattern=_SHA256)
    completed_at: str

    @field_validator("completed_at")
    @classmethod
    def completed_time(cls, value: str) -> str:
        _timestamp(value)
        return value

    @model_validator(mode="after")
    def exact_runtime_components(self) -> Self:
        components = (
            self.primary_infisical,
            self.primary_valkey,
            self.restore_infisical,
            self.restore_valkey,
        )
        if (
            tuple(item.component for item in components)
            != ("primary_infisical", "primary_valkey", "restore_infisical", "restore_valkey")
            or len({item.container_id for item in components}) != 4
            or len({item.workload_id for item in components}) != 4
            or self.executor_receipt_sha256 != canonical_sha256(self.executor_receipt)
            or self.executor_receipt.secret_delivery_receipt_sha256
            != canonical_sha256(self.delivery_receipt)
            or self.delivery_receipt.operation_scope != self.operation_scope
            or self.delivery_receipt.operation_id != self.materialization_operation_id
            or self.delivery_receipt.journal_uuid != self.journal_uuid
        ):
            raise ValueError("materialization receipt components are invalid")
        return self


def materialization_effect_receipt_sha256(receipt: MaterializationEffectReceiptV1) -> str:
    if type(receipt) is not MaterializationEffectReceiptV1:
        raise ValueError("materialization effect receipt is invalid")
    return canonical_sha256(receipt)


class StartRuntimeEvidenceBindingsV2(_Model):
    """All signed predecessor and capability commitments for one fresh start."""

    materialization_intent_sha256: str = Field(pattern=_SHA256)
    materialization_effect_receipt_sha256: str = Field(pattern=_SHA256)
    observed_runtime_attestation_sha256: str = Field(pattern=_SHA256)
    executor_control_policy_sha256: str = Field(pattern=_SHA256)
    executor_installation_policy_sha256: str = Field(pattern=_SHA256)
    executor_installation_intent_sha256: str = Field(pattern=_SHA256)
    executor_installation_receipt_sha256: str = Field(pattern=_SHA256)
    secret_capability_policy_sha256: str = Field(pattern=_SHA256)
    secret_handling_policy_sha256: str = Field(pattern=_SHA256)
    provider_material_attestation_sha256: str = Field(pattern=_SHA256)

    @model_validator(mode="after")
    def distinct_bindings(self) -> Self:
        if len(set(self.model_dump(mode="python").values())) != 10:
            raise ValueError("start runtime evidence bindings must be distinct")
        return self


class StartRuntimeIntentV2(_Model):
    """Signed authority for exactly one fresh secret delivery and runtime start.

    It cannot allocate, materialize, seed, restore, swap, or access data.  A
    future restart requires a new instance with a new operation ID and request
    nonce commitment.
    """

    schema_version: Literal["rsd.start-runtime-intent.v2"]
    operation_kind: Literal["start_runtime_v2"]
    operation_scope: Literal["start_runtime_v2"]
    start_operation_id: str = Field(pattern=_UUID)
    materialization_operation_id: str = Field(pattern=_UUID)
    source_commit: str = Field(pattern=_COMMIT)
    materialization_intent_sha256: str = Field(pattern=_SHA256)
    materialization_effect_receipt_sha256: str = Field(pattern=_SHA256)
    observed_runtime_attestation_sha256: str = Field(pattern=_SHA256)
    provider_references: ProviderReferencesV2
    evidence: StartRuntimeEvidenceBindingsV2
    delivery_request: SecretDeliveryRequestV1
    retention_expires_at: str
    disposal_owner: str = Field(pattern=_OWNER_IDENTITY)
    approver_identity: str = Field(pattern=_OWNER_IDENTITY)
    approval_reference_sha256: str = Field(pattern=_SHA256)
    journal_uuid: str = Field(pattern=_UUID)
    replay_policy_sha256: str = Field(pattern=_SHA256)
    created_at: str
    signer_key_id: str = Field(pattern=_IDENTIFIER)
    signature_base64: str = Field(min_length=4, max_length=256)

    @field_validator("retention_expires_at", "created_at")
    @classmethod
    def canonical_time(cls, value: str) -> str:
        _timestamp(value)
        return value

    @model_validator(mode="after")
    def exact_fresh_start(self) -> Self:
        request = self.delivery_request
        if (
            _timestamp(self.retention_expires_at) <= _timestamp(self.created_at)
            or len(_canonical_base64_bytes(self.signature_base64)) != 64
            or self.provider_references.tls_trust_anchor is not None
            or request.operation_scope != self.operation_scope
            or request.operation_id != self.start_operation_id
            or request.journal_uuid != self.journal_uuid
            or request.provider_material_attestation_sha256
            != self.evidence.provider_material_attestation_sha256
            or self.evidence.materialization_intent_sha256 != self.materialization_intent_sha256
            or self.evidence.materialization_effect_receipt_sha256
            != self.materialization_effect_receipt_sha256
            or self.evidence.observed_runtime_attestation_sha256
            != self.observed_runtime_attestation_sha256
        ):
            raise ValueError("start runtime intent is invalid")
        references = {
            "encryption_key": self.provider_references.encryption_key.reference_sha256,
            "auth_secret": self.provider_references.auth_secret.reference_sha256,
            "primary_valkey_password": (
                self.provider_references.primary_valkey_password.reference_sha256
            ),
            "restore_valkey_password": (
                self.provider_references.restore_valkey_password.reference_sha256
            ),
            "postgres_application_password": (
                self.provider_references.postgres_application_password.reference_sha256
            ),
        }
        if any(slot.reference_sha256 != references[slot.purpose] for slot in request.slots):
            raise ValueError("start runtime secret delivery bindings are invalid")
        return self


def strict_canonical_start_runtime_intent(intent: StartRuntimeIntentV2) -> StartRuntimeIntentV2:
    """Return the only start form admissible at a mutation boundary."""

    return _strict_canonical_model(intent, StartRuntimeIntentV2)


def start_runtime_intent_sha256(intent: StartRuntimeIntentV2) -> str:
    if type(intent) is not StartRuntimeIntentV2:
        raise ValueError("start runtime intent is invalid")
    return canonical_sha256(intent)


class StartRuntimeExecutorReceiptV2(_Model):
    """Executor-attested result for one fresh start, without secret values."""

    schema_version: Literal["rsd.start-runtime-executor-receipt.v2"]
    operation_kind: Literal["start_runtime_v2"]
    operation_scope: Literal["start_runtime_v2"]
    start_operation_id: str = Field(pattern=_UUID)
    start_runtime_intent_sha256: str = Field(pattern=_SHA256)
    idempotency_key: str = Field(pattern=_SHA256)
    secret_delivery_receipt_sha256: str = Field(pattern=_SHA256)
    request_nonce_sha256: str = Field(pattern=_SHA256)
    channel_binding_sha256: str = Field(pattern=_SHA256)
    session_binding_sha256: str = Field(pattern=_SHA256)
    installation_receipt_sha256: str = Field(pattern=_SHA256)
    executor_id: str = Field(pattern=_IDENTIFIER)
    host_fingerprint_sha256: str = Field(pattern=_SHA256)
    engine_fingerprint_sha256: str = Field(pattern=_SHA256)
    containers: tuple[
        ExecutorContainerInspectionV1,
        ExecutorContainerInspectionV1,
        ExecutorContainerInspectionV1,
        ExecutorContainerInspectionV1,
    ]
    completed_at: str
    signer_key_id: str = Field(pattern=_IDENTIFIER)
    signature_base64: str = Field(min_length=4, max_length=256)

    @field_validator("containers", mode="before")
    @classmethod
    def declared_containers(cls, value: object) -> tuple[object, ...]:
        return _items(value, field="start executor inspected containers")

    @field_validator("completed_at")
    @classmethod
    def canonical_time(cls, value: str) -> str:
        _timestamp(value)
        return value

    @model_validator(mode="after")
    def exact_start_evidence(self) -> Self:
        if (
            tuple(item.component for item in self.containers)
            != ("primary_infisical", "primary_valkey", "restore_infisical", "restore_valkey")
            or len({item.container_id for item in self.containers}) != 4
            or len(_canonical_base64_bytes(self.signature_base64)) != 64
        ):
            raise ValueError("start executor receipt is invalid")
        return self


class StartRuntimeEffectReceiptV2(_Model):
    """Value-free terminal evidence for one fresh authorized start."""

    schema_version: Literal["rsd.start-runtime-effect-receipt.v2"]
    operation_kind: Literal["start_runtime_v2"]
    operation_scope: Literal["start_runtime_v2"]
    status: Literal["started_runtime"]
    start_operation_id: str = Field(pattern=_UUID)
    start_runtime_intent_sha256: str = Field(pattern=_SHA256)
    materialization_operation_id: str = Field(pattern=_UUID)
    materialization_effect_receipt_sha256: str = Field(pattern=_SHA256)
    journal_uuid: str = Field(pattern=_UUID)
    idempotency_key: str = Field(pattern=_SHA256)
    executor_receipt: StartRuntimeExecutorReceiptV2
    delivery_receipt: SecretDeliveryReceiptV1
    completed_at: str

    @field_validator("completed_at")
    @classmethod
    def canonical_time(cls, value: str) -> str:
        _timestamp(value)
        return value

    @model_validator(mode="after")
    def bound_opaque_effect(self) -> Self:
        executor = self.executor_receipt
        delivery = self.delivery_receipt
        if (
            executor.start_operation_id != self.start_operation_id
            or executor.start_runtime_intent_sha256 != self.start_runtime_intent_sha256
            or executor.idempotency_key != self.idempotency_key
            or executor.secret_delivery_receipt_sha256 != canonical_sha256(delivery)
            or delivery.operation_scope != self.operation_scope
            or delivery.operation_id != self.start_operation_id
            or delivery.journal_uuid != self.journal_uuid
            or delivery.request_nonce_sha256 != executor.request_nonce_sha256
            or delivery.channel_binding_sha256 != executor.channel_binding_sha256
            or delivery.session_binding_sha256 != executor.session_binding_sha256
        ):
            raise ValueError("start runtime effect receipt is invalid")
        return self


def start_runtime_effect_receipt_sha256(receipt: StartRuntimeEffectReceiptV2) -> str:
    if type(receipt) is not StartRuntimeEffectReceiptV2:
        raise ValueError("start runtime effect receipt is invalid")
    return canonical_sha256(receipt)


class ObservedRuntimeAttestationV1(_Model):
    """Signed final observation linking materialization evidence to a post-runtime candidate."""

    schema_version: Literal["rsd.observed-runtime-attestation.v1"]
    operation_kind: Literal["materialization_v1"]
    materialization_operation_id: str = Field(pattern=_UUID)
    materialization_intent_sha256: str = Field(pattern=_SHA256)
    materialization_effect_receipt_sha256: str = Field(pattern=_SHA256)
    observed_allocation_attestation_sha256: str = Field(pattern=_SHA256)
    proposal_sha256: str = Field(pattern=_SHA256)
    candidate: CandidateCompositeV1
    candidate_composite_sha256: str = Field(pattern=_SHA256)
    observed_at: str
    signer_key_id: str = Field(pattern=_IDENTIFIER)
    signature_base64: str = Field(min_length=4, max_length=256)

    @field_validator("observed_at")
    @classmethod
    def observation_time(cls, value: str) -> str:
        _timestamp(value)
        return value

    @model_validator(mode="after")
    def binds_candidate(self) -> Self:
        if (
            self.candidate_composite_sha256 != canonical_sha256(self.candidate)
            or len(_canonical_base64_bytes(self.signature_base64)) != 64
        ):
            raise ValueError("observed runtime attestation is invalid")
        return self


def observed_runtime_attestation_sha256(attestation: ObservedRuntimeAttestationV1) -> str:
    if type(attestation) is not ObservedRuntimeAttestationV1:
        raise ValueError("observed runtime attestation is invalid")
    return canonical_sha256(attestation)


def validate_observed_allocation_transition(
    intent: AllocationIntentV2,
    receipt: AllocationEffectReceiptV2,
    attestation: ObservedAllocationAttestationV1,
) -> None:
    """Require a signed allocation observation before materialization can be considered."""

    if (
        type(intent) is not AllocationIntentV2
        or type(receipt) is not AllocationEffectReceiptV2
        or type(attestation) is not ObservedAllocationAttestationV1
    ):
        raise ValueError("allocation observation transition is invalid")
    if (
        receipt.allocation_operation_id != intent.allocation_operation_id
        or receipt.allocation_intent_sha256 != allocation_intent_sha256(intent)
        or receipt.journal_uuid != intent.journal_uuid
        or attestation.allocation_operation_id != intent.allocation_operation_id
        or attestation.allocation_intent_sha256 != allocation_intent_sha256(intent)
        or attestation.allocation_effect_receipt_sha256 != allocation_effect_receipt_sha256(receipt)
        or attestation.allocation_topology_sha256 != canonical_sha256(intent.plan.topology)
        or attestation.allocated_resources != receipt.allocated_resources
        or attestation.allocated_resources.primary_network.name
        != intent.plan.topology.primary_network.name
        or attestation.allocated_resources.restore_network.name
        != intent.plan.topology.restore_network.name
        or attestation.allocated_resources.primary_cache_volume.name
        != intent.plan.primary_valkey_volume.name
        or attestation.allocated_resources.restore_cache_volume.name
        != intent.plan.restore_valkey_volume.name
        or attestation.allocated_resources.postgres.database_name
        != intent.plan.postgres.database_name
        or attestation.allocated_resources.postgres.schema_name != intent.plan.postgres.schema_name
        or attestation.allocated_resources.postgres.owner_role != intent.plan.postgres.owner_role
        or tuple(item.role for item in attestation.allocated_resources.postgres.role_oids)
        != intent.plan.postgres.role_names
    ):
        raise ValueError("allocation observation transition is invalid")


def _matches_runtime_component(
    observed: RuntimeContainerObservationV1,
    candidate: ServiceIdentityV1 | ValkeyIdentityV1,
) -> bool:
    attachment = observed.attachments[0]
    return (
        observed.container_id == candidate.container_id
        and observed.workload_id == candidate.workload_id
        and observed.image == candidate.image
        and attachment.network_name == candidate.network_name
        and attachment.network_id == candidate.network_id
    )


def validate_observed_runtime_transition(
    allocation: ObservedAllocationAttestationV1,
    intent: MaterializationIntentV1,
    receipt: MaterializationEffectReceiptV1,
    attestation: ObservedRuntimeAttestationV1,
    proposal: ProposalV1,
    contract: RuntimeContractV1,
) -> None:
    """Require the full V2 allocation/materialization chain before observed effects."""

    if (
        type(allocation) is not ObservedAllocationAttestationV1
        or type(intent) is not MaterializationIntentV1
        or type(receipt) is not MaterializationEffectReceiptV1
        or type(attestation) is not ObservedRuntimeAttestationV1
        or type(proposal) is not ProposalV1
        or type(contract) is not RuntimeContractV1
    ):
        raise ValueError("runtime observation transition is invalid")
    if (
        intent.observed_allocation_attestation_sha256
        != observed_allocation_attestation_sha256(allocation)
        or intent.allocation_operation_id != allocation.allocation_operation_id
        or intent.allocation_intent_sha256 != allocation.allocation_intent_sha256
        or intent.allocation_effect_receipt_sha256 != allocation.allocation_effect_receipt_sha256
        or receipt.materialization_operation_id != intent.materialization_operation_id
        or receipt.materialization_intent_sha256 != materialization_intent_sha256(intent)
        or receipt.allocation_operation_id != intent.allocation_operation_id
        or receipt.allocation_effect_receipt_sha256 != intent.allocation_effect_receipt_sha256
        or receipt.observed_allocation_attestation_sha256
        != intent.observed_allocation_attestation_sha256
        or receipt.journal_uuid != intent.journal_uuid
        or attestation.materialization_operation_id != intent.materialization_operation_id
        or attestation.materialization_intent_sha256 != materialization_intent_sha256(intent)
        or attestation.materialization_effect_receipt_sha256
        != materialization_effect_receipt_sha256(receipt)
        or attestation.observed_allocation_attestation_sha256
        != intent.observed_allocation_attestation_sha256
        or attestation.proposal_sha256 != proposal_sha256(proposal)
        or attestation.candidate != proposal.candidate
        or contract.model_dump(mode="json", include=set(ProposalV1.model_fields))
        != proposal.model_dump(mode="json")
        or not _matches_runtime_component(
            receipt.primary_infisical, proposal.candidate.primary_service
        )
        or not _matches_runtime_component(
            receipt.restore_infisical, proposal.candidate.restore_service
        )
        or not _matches_runtime_component(receipt.primary_valkey, proposal.candidate.primary_valkey)
        or not _matches_runtime_component(receipt.restore_valkey, proposal.candidate.restore_valkey)
        or allocation.allocated_resources.postgres.system_identifier
        != proposal.candidate.postgres.system_identifier
        or allocation.allocated_resources.postgres.database_oid
        != proposal.candidate.postgres.database_oid
    ):
        raise ValueError("runtime observation transition is invalid")


# ``ProposalV1`` intentionally refers forward to allocation evidence so Phase-A
# remains a compiler while the V2 stages bind the later runtime candidate.
ProposalV1.model_rebuild()
RuntimeContractV1.model_rebuild()


class GovernedIdentityV1(_Model):
    surface: Literal["governed_surface"]
    stable_identifiers: tuple[StableIdentifierV1, ...] = Field(min_length=1, max_length=64)

    @field_validator("stable_identifiers", mode="before")
    @classmethod
    def sequence_ids(cls, value: object) -> tuple[object, ...]:
        return _items(value, field="stable_identifiers")


class GovernedBaselineV1(_Model):
    schema_version: Literal["rsd.disposable-governed-baseline.v1"]
    authorization_subject_sha256: str = Field(pattern=_SHA256)
    source_commit: str = Field(pattern=_COMMIT)
    signature: DetachedSignatureV1
    identities: tuple[GovernedIdentityV1, ...] = Field(min_length=1, max_length=16)

    @field_validator("identities", mode="before")
    @classmethod
    def sequence_identities(cls, value: object) -> tuple[object, ...]:
        return _items(value, field="identities")


class TargetAttestationV1(_Model):
    schema_version: Literal["rsd.disposable-target-attestation.v1"]
    authorization_subject_sha256: str = Field(pattern=_SHA256)
    snapshot_epoch_id: str = Field(pattern=_IDENTIFIER)
    observed_at: str
    candidate_composite_sha256: str = Field(pattern=_SHA256)
    postgres_database_oid: int = Field(ge=1)
    signature: DetachedSignatureV1

    @field_validator("observed_at")
    @classmethod
    def observed(cls, value: str) -> str:
        _timestamp(value)
        return value


class ProviderDeclarationV1(_Model):
    schema_version: Literal["rsd.disposable-provider-declaration.v1"]
    authorization_subject_sha256: str = Field(pattern=_SHA256)
    snapshot_epoch_id: str = Field(pattern=_IDENTIFIER)
    observed_at: str
    proof_source: Literal["offline-provider-reference-declaration-v1"]
    signature: DetachedSignatureV1
    references: tuple[ProviderReferenceV1, ...] = Field(min_length=7, max_length=8)

    @field_validator("observed_at")
    @classmethod
    def observed(cls, value: str) -> str:
        _timestamp(value)
        return value

    @field_validator("references", mode="before")
    @classmethod
    def sequence_references(cls, value: object) -> tuple[object, ...]:
        return _items(value, field="references")


class RegistryImageVerificationV1(_Model):
    role: Literal["primary", "restore"]
    image: ImageReferenceV1
    platform: Literal["linux/amd64"]
    platform_digest: str = Field(pattern=r"^sha256:[0-9a-f]{64}$")


class RegistryVerificationV1(_Model):
    schema_version: Literal["rsd.disposable-registry-verification.v1"]
    authorization_subject_sha256: str = Field(pattern=_SHA256)
    snapshot_epoch_id: str = Field(pattern=_IDENTIFIER)
    observed_at: str
    signature: DetachedSignatureV1
    images: tuple[RegistryImageVerificationV1, RegistryImageVerificationV1]

    @field_validator("observed_at")
    @classmethod
    def observed(cls, value: str) -> str:
        _timestamp(value)
        return value

    @field_validator("images", mode="before")
    @classmethod
    def sequence_images(cls, value: object) -> tuple[object, ...]:
        return _items(value, field="images")

    @model_validator(mode="after")
    def roles_complete(self) -> Self:
        if {item.role for item in self.images} != {"primary", "restore"}:
            raise ValueError("registry verification must contain both roles")
        return self


class ApprovalEvidenceV1(_Model):
    schema_version: Literal["rsd.disposable-approval.v1"]
    authorization_subject_sha256: str = Field(pattern=_SHA256)
    approval_reference_sha256: str = Field(pattern=_SHA256)
    source_commit: str = Field(pattern=_COMMIT)
    issued_at: str
    expires_at: str
    approver_identity: str = Field(pattern=_OWNER_IDENTITY)
    proposal_authorized: Literal[True]
    execution_authorized: Literal[False]
    signature: DetachedSignatureV1

    @field_validator("issued_at", "expires_at")
    @classmethod
    def observed(cls, value: str) -> str:
        _timestamp(value)
        return value

    @model_validator(mode="after")
    def window(self) -> Self:
        if _timestamp(self.expires_at) <= _timestamp(self.issued_at):
            raise ValueError("approval expiry must follow issuance")
        return self


class PreflightReceiptV1(_Model):
    schema_version: Literal["rsd.disposable-preflight-receipt.v1"]
    status: Literal["compiled"]
    authorization_state: Literal["not_authorized_pending_live_provenance"]
    operation_id: str = Field(pattern=_UUID)
    contract_sha256: str = Field(pattern=_SHA256)
    proposal_sha256: str = Field(pattern=_SHA256)
    candidate_composite_sha256: str = Field(pattern=_SHA256)
    retention_expires_at: str
    disposal_owner: str = Field(pattern=_OWNER_IDENTITY)
    emitted_at: str
    evidence_sha256: tuple[str, str, str, str, str, str]


class _UniqueLoader(yaml.SafeLoader):
    """Safe YAML parser rejecting duplicate mapping keys."""


def _mapping(
    loader: _UniqueLoader, node: yaml.MappingNode, deep: bool = False
) -> dict[object, object]:
    output: dict[object, object] = {}
    for key_node, value_node in node.value:
        key = loader.construct_object(key_node, deep=deep)
        if key in output:
            raise yaml.YAMLError("duplicate mapping key")
        output[key] = loader.construct_object(value_node, deep=deep)
    return output


_UniqueLoader.add_constructor(yaml.resolver.BaseResolver.DEFAULT_MAPPING_TAG, _mapping)


@dataclass(frozen=True, slots=True)
class PreflightPaths:
    """Fixed root-relative artifact names protect against substitution."""

    root: Path
    proposal_name: str = "proposal.yaml"
    contract_name: str = "runtime-contract.yaml"
    approval_name: str = "approval.yaml"
    governed_baseline_name: str = "governed-baseline.yaml"
    target_attestation_name: str = "target-attestation.yaml"
    provider_declaration_name: str = "provider-declaration.yaml"
    registry_verification_name: str = "registry-verification.yaml"
    postgres_overlay_name: str = "postgres-overlay.yaml"


class _OwnerOnlyReader:
    """Descriptor-relative reader for bounded, owner-only regular files.

    A caller that already owns a checked directory descriptor can pass it in.
    This keeps every read attached to that same directory inode instead of
    resolving the root path again between reads.
    """

    def __init__(self, root: Path, *, root_fd: int | None = None) -> None:
        self._root = root
        self._uid = os.getuid()
        self._source_root_fd = root_fd
        self._root_identity: tuple[int, int] | None = None
        if root_fd is not None:
            try:
                details = os.fstat(root_fd)
            except OSError:
                raise DisposablePreflightError("owner_only_root") from None
            if (
                not stat.S_ISDIR(details.st_mode)
                or details.st_uid != self._uid
                or stat.S_IMODE(details.st_mode) != 0o700
            ):
                raise DisposablePreflightError("owner_only_root")
            self._root_identity = (details.st_dev, details.st_ino)

    def _root_fd(self) -> int:
        if self._source_root_fd is not None and self._root_identity is not None:
            try:
                fd = os.dup(self._source_root_fd)
                details = os.fstat(fd)
            except OSError:
                raise DisposablePreflightError("owner_only_root") from None
            if (details.st_dev, details.st_ino) != self._root_identity:
                with suppress(OSError):
                    os.close(fd)
                raise DisposablePreflightError("owner_only_root")
            return fd
        try:
            before = os.lstat(self._root)
            if (
                not stat.S_ISDIR(before.st_mode)
                or before.st_uid != self._uid
                or stat.S_IMODE(before.st_mode) != 0o700
            ):
                raise DisposablePreflightError("owner_only_root")
            fd = os.open(
                self._root,
                os.O_RDONLY | getattr(os, "O_DIRECTORY", 0) | getattr(os, "O_CLOEXEC", 0),
            )
            after = os.fstat(fd)
            if before.st_ino != after.st_ino or before.st_dev != after.st_dev:
                os.close(fd)
                raise DisposablePreflightError("owner_only_root")
            return fd
        except DisposablePreflightError:
            raise
        except OSError:
            raise DisposablePreflightError("owner_only_root") from None

    def read(self, name: str) -> bytes:
        if "/" in name or name.startswith("."):
            raise DisposablePreflightError("owner_only_input")
        root_fd = self._root_fd()
        file_fd: int | None = None
        try:
            before = os.lstat(name, dir_fd=root_fd)
            if (
                not stat.S_ISREG(before.st_mode)
                or before.st_uid != self._uid
                or stat.S_IMODE(before.st_mode) != 0o600
                or before.st_nlink != 1
                or before.st_size > _MAX_INPUT_BYTES
            ):
                raise DisposablePreflightError("owner_only_input")
            file_fd = os.open(
                name,
                os.O_RDONLY | getattr(os, "O_NOFOLLOW", 0) | getattr(os, "O_CLOEXEC", 0),
                dir_fd=root_fd,
            )
            after = os.fstat(file_fd)
            if before.st_ino != after.st_ino or before.st_dev != after.st_dev:
                raise DisposablePreflightError("owner_only_input")
            parts: list[bytes] = []
            total = 0
            while chunk := os.read(file_fd, 65_536):
                total += len(chunk)
                if total > _MAX_INPUT_BYTES:
                    raise DisposablePreflightError("owner_only_input")
                parts.append(chunk)
            return b"".join(parts)
        except DisposablePreflightError:
            raise
        except OSError:
            raise DisposablePreflightError("owner_only_input") from None
        finally:
            if file_fd is not None:
                with suppress(OSError):
                    os.close(file_fd)
            with suppress(OSError):
                os.close(root_fd)


def _yaml(raw: bytes, *, phase: str) -> dict[str, object]:
    try:
        result = yaml.load(raw.decode("utf-8"), Loader=_UniqueLoader)
        if type(result) is not dict or not all(type(key) is str for key in result):
            raise TypeError
        return cast(dict[str, object], result)
    except (UnicodeDecodeError, TypeError, yaml.YAMLError):
        raise DisposablePreflightError(phase) from None


def _read_model(
    reader: _OwnerOnlyReader, name: str, model: type[_Model], *, phase: str
) -> tuple[_Model, str]:
    raw = reader.read(name)
    try:
        return model.model_validate(_yaml(raw, phase=phase)), _digest(raw)
    except ValidationError:
        raise DisposablePreflightError(phase) from None


def _fresh(value: str, *, now: datetime, phase: str) -> None:
    observed = _timestamp(value)
    if observed > now or now - observed > _FRESHNESS:
        raise DisposablePreflightError(phase)


def compile_preflight(
    paths: PreflightPaths,
    *,
    now: datetime | None = None,
    _reader: _OwnerOnlyReader | None = None,
) -> PreflightReceiptV1:
    """Compile Phase-A artifacts and return a non-authorizing receipt in memory."""

    clock = datetime.now(UTC) if now is None else now
    if clock.tzinfo is None or clock.utcoffset() is None:
        raise DisposablePreflightError("clock")
    reader = _OwnerOnlyReader(paths.root) if _reader is None else _reader
    proposal_raw, proposal_file_hash = _read_model(
        reader, paths.proposal_name, ProposalV1, phase="proposal"
    )
    contract_raw, contract_hash = _read_model(
        reader, paths.contract_name, RuntimeContractV1, phase="contract"
    )
    approval_raw, approval_hash = _read_model(
        reader, paths.approval_name, ApprovalEvidenceV1, phase="approval"
    )
    governed_raw, governed_hash = _read_model(
        reader, paths.governed_baseline_name, GovernedBaselineV1, phase="governed_baseline"
    )
    target_raw, target_hash = _read_model(
        reader, paths.target_attestation_name, TargetAttestationV1, phase="target_attestation"
    )
    provider_raw, provider_hash = _read_model(
        reader, paths.provider_declaration_name, ProviderDeclarationV1, phase="provider_declaration"
    )
    registry_raw, registry_hash = _read_model(
        reader,
        paths.registry_verification_name,
        RegistryVerificationV1,
        phase="registry_verification",
    )
    overlay_raw, overlay_hash = _read_model(
        reader, paths.postgres_overlay_name, PostgreSQLAcceptanceOverlayV1, phase="postgres_overlay"
    )
    proposal = cast(ProposalV1, proposal_raw)
    contract = cast(RuntimeContractV1, contract_raw)
    approval = cast(ApprovalEvidenceV1, approval_raw)
    governed = cast(GovernedBaselineV1, governed_raw)
    target = cast(TargetAttestationV1, target_raw)
    provider = cast(ProviderDeclarationV1, provider_raw)
    registry = cast(RegistryVerificationV1, registry_raw)
    overlay = cast(PostgreSQLAcceptanceOverlayV1, overlay_raw)
    subject = proposal_sha256(proposal)
    if contract.proposal_sha256 != subject or proposal.model_dump(
        mode="json"
    ) != contract.model_dump(mode="json", include=set(ProposalV1.model_fields)):
        raise DisposablePreflightError("proposal_binding")
    expected = EvidenceBindingsV1(
        approval_sha256=approval_hash,
        governed_baseline_sha256=governed_hash,
        target_attestation_sha256=target_hash,
        provider_declaration_sha256=provider_hash,
        registry_verification_sha256=registry_hash,
        postgres_overlay_sha256=overlay_hash,
    )
    if contract.evidence != expected:
        raise DisposablePreflightError("evidence_binding")
    if (
        approval.authorization_subject_sha256 != subject
        or approval.approval_reference_sha256 != proposal.approval_reference_sha256
        or approval.source_commit != proposal.source_commit
        or _timestamp(approval.issued_at) > clock
        or _timestamp(approval.expires_at) <= clock
    ):
        raise DisposablePreflightError("approval")
    if (
        governed.authorization_subject_sha256 != subject
        or governed.source_commit != proposal.source_commit
    ):
        raise DisposablePreflightError("governed_baseline")
    if (
        target.authorization_subject_sha256 != subject
        or target.candidate_composite_sha256 != canonical_sha256(proposal.candidate)
        or target.postgres_database_oid != proposal.candidate.postgres.database_oid
    ):
        raise DisposablePreflightError("target_attestation")
    _fresh(target.observed_at, now=clock, phase="target_attestation")
    if (
        provider.authorization_subject_sha256 != subject
        or provider.snapshot_epoch_id != target.snapshot_epoch_id
        or provider.references != proposal.provider_references.all()
    ):
        raise DisposablePreflightError("provider_declaration")
    _fresh(provider.observed_at, now=clock, phase="provider_declaration")
    if (
        registry.authorization_subject_sha256 != subject
        or registry.snapshot_epoch_id != target.snapshot_epoch_id
        or registry.images[0].image != proposal.primary_image
        or registry.images[1].image != proposal.restore_image
    ):
        raise DisposablePreflightError("registry_verification")
    _fresh(registry.observed_at, now=clock, phase="registry_verification")
    if (
        overlay.database_name != proposal.candidate.postgres.database_name
        or overlay.database_oid != proposal.candidate.postgres.database_oid
        or overlay.owner_role != proposal.candidate.postgres.owner_role
    ):
        raise DisposablePreflightError("postgres_overlay")
    candidate_ids = {(item.kind, item.value) for item in proposal.candidate.stable()}
    governed_ids = {
        (item.kind, item.value)
        for identity in governed.identities
        for item in identity.stable_identifiers
    }
    if candidate_ids.intersection(governed_ids):
        raise DisposablePreflightError("governed_identity")
    emitted = clock.astimezone(UTC).isoformat(timespec="seconds").replace("+00:00", "Z")
    return PreflightReceiptV1(
        schema_version="rsd.disposable-preflight-receipt.v1",
        status="compiled",
        authorization_state="not_authorized_pending_live_provenance",
        operation_id=proposal.operation_id,
        contract_sha256=contract_hash,
        proposal_sha256=proposal_file_hash,
        candidate_composite_sha256=canonical_sha256(proposal.candidate),
        retention_expires_at=proposal.retention_expires_at,
        disposal_owner=proposal.disposal_owner,
        emitted_at=emitted,
        evidence_sha256=(
            approval_hash,
            governed_hash,
            target_hash,
            provider_hash,
            registry_hash,
            overlay_hash,
        ),
    )


def main(argv: Sequence[str] | None = None) -> int:
    """Compile only from an explicit owner-only directory."""

    parser = argparse.ArgumentParser(prog="rsd-infisical-disposable-lifecycle")
    commands = parser.add_subparsers(dest="command", required=True)
    preflight = commands.add_parser("preflight", help="compile value-free Phase-A artifacts")
    preflight.add_argument("--root", type=Path, required=True)
    authorize = commands.add_parser("authorize", help="verify Phase-B authorization read-only")
    authorize.add_argument("--root", type=Path, required=True)
    arguments = parser.parse_args(argv)
    if arguments.command == "authorize":
        from omninode_rsd.lifecycle.authorization import main as authorization_main

        return authorization_main(["authorize", "--root", str(arguments.root)])
    try:
        receipt = compile_preflight(PreflightPaths(root=arguments.root))
    except DisposablePreflightError as error:
        print(json.dumps({"status": "blocked", "phase": error.phase}, separators=(",", ":")))
        return 2
    print(json.dumps(receipt.model_dump(mode="json"), sort_keys=True, separators=(",", ":")))
    return 0


if __name__ == "__main__":  # pragma: no cover
    raise SystemExit(main())
