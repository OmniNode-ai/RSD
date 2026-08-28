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


class ProviderReferencesV1(_Model):
    commitment_hmac: ProviderReferenceV1
    backup_encryption: ProviderReferenceV1
    encryption_key: ProviderReferenceV1
    auth_secret: ProviderReferenceV1
    primary_valkey_password: ProviderReferenceV1
    restore_valkey_password: ProviderReferenceV1
    tls_trust_anchor: ProviderReferenceV1 | None = None

    def all(self) -> tuple[ProviderReferenceV1, ...]:
        result = (
            self.commitment_hmac,
            self.backup_encryption,
            self.encryption_key,
            self.auth_secret,
            self.primary_valkey_password,
            self.restore_valkey_password,
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
        if len({item.network_id for item in components}) != 4:
            raise ValueError("all component network identities must be distinct")
        if len({item.workload_id for item in components}) != 4:
            raise ValueError("all component workload identities must be distinct")
        if len({item.network_name for item in components}) != 4:
            raise ValueError("all component network names must be distinct")
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
    provider_references: ProviderReferencesV1
    retention_expires_at: str
    disposal_owner: str = Field(pattern=_OWNER_IDENTITY)
    approval_reference_sha256: str = Field(pattern=_SHA256)
    initial_provisioning_evidence: InitialProvisioningEvidenceBindingsV1

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


class InitialProvisioningOperationKind(StrEnum):
    """The only operation kind admitted before runtime identities exist."""

    INITIAL_PROVISIONING = "initial_provisioning_v1"


class InitialProvisioningScope(StrEnum):
    """The bounded pre-observation effect scope."""

    CREATE_ISOLATED_EMPTY_RESOURCES = "create_isolated_empty_resources_v1"


class ObservedLifecycleOperationKind(StrEnum):
    """The post-observation lifecycle operation kind."""

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


class InitialProvisioningEvidenceBindingsV1(_Model):
    """Signed commitments to the governed evidence required before creation."""

    approval_sha256: str = Field(pattern=_SHA256)
    governed_deny_sha256: str = Field(pattern=_SHA256)
    governed_baseline_sha256: str = Field(pattern=_SHA256)
    collision_evidence_sha256: str = Field(pattern=_SHA256)
    registry_verification_sha256: str = Field(pattern=_SHA256)
    provider_declaration_sha256: str = Field(pattern=_SHA256)

    @model_validator(mode="after")
    def distinct_bindings(self) -> Self:
        values = tuple(self.model_dump(mode="python").values())
        if len(set(values)) != len(values):
            raise ValueError("initial evidence commitments must be distinct")
        return self


class InitialServicePlanV1(_Model):
    """A planned service identity deliberately excluding runtime identifiers."""

    authority: str | None = None
    authority_sha256: str | None = Field(default=None, pattern=_SHA256)
    machine_id: str = Field(pattern=_IDENTIFIER)
    compose_project: str = Field(pattern=_IDENTIFIER)
    service_name: str = Field(pattern=_IDENTIFIER)
    network_name: str = Field(pattern=_IDENTIFIER)
    workload_name: str = Field(pattern=_IDENTIFIER)
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
                raise ValueError("missing planned authority cannot have a hash")
            parsed = None
        else:
            parsed = urlsplit(self.authority)
            assert parsed.port is not None and parsed.hostname is not None
            if self.authority_sha256 != _digest(self.authority.encode()):
                raise ValueError("planned authority hash does not bind authority")
        if self.listener_binding == "isolated_network_only":
            if self.host_listener_port is not None or self.isolated_network_alias is None:
                raise ValueError("isolated planned service cannot publish a port")
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
                    raise ValueError("isolated planned authority must be internal HTTP")
        elif self.authority is None or self.authority_sha256 is None:
            raise ValueError("planned listener port must bind authority")
        else:
            assert parsed is not None and parsed.port is not None
            if self.isolated_network_alias is not None or self.host_listener_port != parsed.port:
                raise ValueError("planned listener port must bind authority")
        return self


class InitialPostgreSQLPlanV1(_Model):
    """Target database names and roles, without an OID or live fingerprints."""

    authority: str
    database_name: str = Field(pattern=_IDENTIFIER)
    schema_name: str = Field(pattern=_IDENTIFIER)
    owner_role: str = Field(pattern=_IDENTIFIER)
    role_names: tuple[str, ...] = Field(min_length=1, max_length=16)
    stage_database_prefix: str = Field(pattern=_IDENTIFIER)
    restore_database_prefix: str = Field(pattern=_IDENTIFIER)

    @field_validator("authority")
    @classmethod
    def canonical_postgres(cls, value: str) -> str:
        return _authority(value, schemes=frozenset({"postgresql"}))

    @field_validator("role_names", mode="before")
    @classmethod
    def declared_roles(cls, value: object) -> tuple[object, ...]:
        roles = _items(value, field="role_names")
        if not all(
            type(role) is str and re.fullmatch(_IDENTIFIER, role) is not None for role in roles
        ):
            raise ValueError("planned PostgreSQL roles must be declared identifiers")
        return roles

    @model_validator(mode="after")
    def names_differ(self) -> Self:
        if len({self.database_name, self.stage_database_prefix, self.restore_database_prefix}) != 3:
            raise ValueError("planned database name and prefixes must differ")
        if self.owner_role not in self.role_names or len(set(self.role_names)) != len(
            self.role_names
        ):
            raise ValueError("planned PostgreSQL roles must be distinct and include the owner")
        return self


class InitialValkeyPlanV1(_Model):
    """Planned cache names, image, and provider reference without object IDs."""

    compose_project: str = Field(pattern=_IDENTIFIER)
    service_name: str = Field(pattern=_IDENTIFIER)
    network_name: str = Field(pattern=_IDENTIFIER)
    volume_name: str = Field(pattern=_IDENTIFIER)
    workload_name: str = Field(pattern=_IDENTIFIER)
    logical_namespace: str = Field(pattern=_IDENTIFIER)
    credential_reference_sha256: str = Field(pattern=_SHA256)
    image: ImageReferenceV1


class InitialProvisioningPlanV1(_Model):
    """Complete, name-only pre-creation plan for an isolated empty candidate."""

    transport: TransportContractV1
    primary_service: InitialServicePlanV1
    restore_service: InitialServicePlanV1
    postgres: InitialPostgreSQLPlanV1
    primary_valkey: InitialValkeyPlanV1
    restore_valkey: InitialValkeyPlanV1

    @model_validator(mode="after")
    def isolated_pairs(self) -> Self:
        primary = self.primary_service
        restore = self.restore_service
        if (
            primary.authority != self.transport.authority
            or primary.authority_sha256 != self.transport.authority_sha256
            or primary.listener_binding != self.transport.listener_binding
            or primary.host_listener_port != self.transport.host_listener_port
        ):
            raise ValueError("planned transport must bind primary service")
        if self.transport.listener_binding == "isolated_network_only" and (
            primary.network_name != self.transport.isolated_network_name
            or primary.isolated_network_alias != self.transport.isolated_network_alias
        ):
            raise ValueError("planned isolated transport must bind primary network alias")
        if (
            restore.listener_binding != "isolated_network_only"
            or restore.host_listener_port is not None
            or restore.authority is not None
            or restore.authority_sha256 is not None
            or restore.isolated_network_alias is None
        ):
            raise ValueError("planned restore service must be unpublished and isolated")
        services = (primary, restore)
        caches = (self.primary_valkey, self.restore_valkey)
        components = (*services, *caches)
        if len({item.network_name for item in components}) != 4:
            raise ValueError("planned component networks must be distinct")
        if len({item.workload_name for item in components}) != 4:
            raise ValueError("planned component workloads must be distinct")
        if len({(item.compose_project, item.service_name) for item in components}) != 4:
            raise ValueError("planned compose identities must be distinct")
        if (
            len({item.volume_name for item in caches}) != 2
            or len({item.logical_namespace for item in caches}) != 2
        ):
            raise ValueError("planned Valkey storage must be distinct")
        if primary.image != restore.image:
            raise ValueError("planned primary and restore images must share one digest")
        return self


class InitialProvisioningIntentV1(_Model):
    """Signed pre-creation authority limited to isolated empty resource creation."""

    schema_version: Literal["rsd.initial-provisioning-intent.v1"]
    operation_kind: Literal["initial_provisioning_v1"]
    operation_scope: Literal["create_isolated_empty_resources_v1"]
    provisioning_operation_id: str = Field(pattern=_UUID)
    source_commit: str = Field(pattern=_COMMIT)
    plan: InitialProvisioningPlanV1
    provider_references: ProviderReferencesV1
    evidence: InitialProvisioningEvidenceBindingsV1
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
    def binds_precreation_plan(self) -> Self:
        if (
            not Path(self.journal_path).is_absolute()
            or os.path.normpath(self.journal_path) != self.journal_path
            or self.journal_path_sha256 != _digest(os.fsencode(self.journal_path))
            or _timestamp(self.retention_expires_at) <= _timestamp(self.created_at)
            or len(_canonical_base64_bytes(self.signature_base64)) != 64
        ):
            raise ValueError("initial provisioning intent fields are invalid")
        if (
            self.plan.primary_valkey.credential_reference_sha256
            != self.provider_references.primary_valkey_password.reference_sha256
            or self.plan.restore_valkey.credential_reference_sha256
            != self.provider_references.restore_valkey_password.reference_sha256
        ):
            raise ValueError("initial plan provider references do not bind caches")
        anchor = self.provider_references.tls_trust_anchor
        if type(self.plan.transport.profile) is not DisposableTransportProfile:
            raise ValueError("transport profile must be canonical")
        if _is_tls_verified_profile(self.plan.transport.profile):
            if (
                anchor is None
                or anchor.reference_sha256 != self.plan.transport.tls_trust_anchor_reference_sha256
            ):
                raise ValueError("initial TLS plan must bind trust reference")
        elif anchor is not None:
            raise ValueError("initial unpublished plan cannot carry TLS trust reference")
        return self


def strict_canonical_initial_provisioning_intent(
    intent: InitialProvisioningIntentV1,
) -> InitialProvisioningIntentV1:
    """Return the only typed form admissible at a Phase-B mutation boundary.

    This is deliberately separate from signature verification: the caller must
    verify the returned canonical model under its domain-specific trust anchor
    before performing any effect.  The round-trip prevents a caller from using
    Pydantic's construction/copy escape hatches to smuggle raw strings or
    subclasses into enum- or type-sensitive code.
    """

    return _strict_canonical_model(intent, InitialProvisioningIntentV1)


class ObservedServiceResourcesV1(_Model):
    """Runtime identifiers observed only after the bounded creation effect."""

    network_name: str = Field(pattern=_IDENTIFIER)
    network_id: str = Field(pattern=r"^[0-9a-f]{64}$")
    container_id: str = Field(pattern=r"^[0-9a-f]{64}$")
    workload_name: str = Field(pattern=_IDENTIFIER)
    workload_id: str = Field(pattern=r"^[0-9a-f]{64}$")


class ObservedValkeyResourcesV1(ObservedServiceResourcesV1):
    """Observed cache identity including its concrete volume ID."""

    volume_name: str = Field(pattern=_IDENTIFIER)
    volume_id: str = Field(pattern=r"^[0-9a-f]{64}$")


class ObservedResourceSetV1(_Model):
    """The IDs emitted by initial creation, before any data-bearing action."""

    postgres_system_identifier: str = Field(pattern=r"^[0-9]{8,32}$")
    postgres_database_oid: int = Field(ge=1)
    primary_service: ObservedServiceResourcesV1
    restore_service: ObservedServiceResourcesV1
    primary_valkey: ObservedValkeyResourcesV1
    restore_valkey: ObservedValkeyResourcesV1

    @model_validator(mode="after")
    def distinct_resources(self) -> Self:
        services = (self.primary_service, self.restore_service)
        caches = (self.primary_valkey, self.restore_valkey)
        components = (*services, *caches)
        if (
            len({item.network_name for item in components}) != 4
            or len({item.network_id for item in components}) != 4
            or len({item.container_id for item in components}) != 4
            or len({item.workload_name for item in components}) != 4
            or len({item.workload_id for item in components}) != 4
            or len({item.volume_name for item in caches}) != 2
            or len({item.volume_id for item in caches}) != 2
        ):
            raise ValueError("observed resources must be distinct")
        return self


class InitialProvisioningEffectReceiptV1(_Model):
    """Effect output for the sole pre-observation creation scope."""

    schema_version: Literal["rsd.initial-provisioning-effect-receipt.v1"]
    operation_kind: Literal["initial_provisioning_v1"]
    operation_scope: Literal["create_isolated_empty_resources_v1"]
    status: Literal["created_isolated_empty_resources"]
    provisioning_operation_id: str = Field(pattern=_UUID)
    intent_sha256: str = Field(pattern=_SHA256)
    journal_uuid: str = Field(pattern=_UUID)
    idempotency_key: str = Field(pattern=_SHA256)
    observed_resources: ObservedResourceSetV1
    effect_receipt_sha256: str = Field(pattern=_SHA256)
    completed_at: str

    @field_validator("completed_at")
    @classmethod
    def completed_time(cls, value: str) -> str:
        _timestamp(value)
        return value


def initial_provisioning_intent_sha256(intent: InitialProvisioningIntentV1) -> str:
    """Commit the complete signed pre-creation intent for stage hand-off."""

    if type(intent) is not InitialProvisioningIntentV1:
        raise ValueError("initial provisioning intent is invalid")
    return canonical_sha256(intent)


def initial_provisioning_effect_receipt_sha256(
    receipt: InitialProvisioningEffectReceiptV1,
) -> str:
    """Commit the bounded-effect receipt later signed by the observer."""

    if type(receipt) is not InitialProvisioningEffectReceiptV1:
        raise ValueError("initial provisioning effect receipt is invalid")
    return canonical_sha256(receipt)


class ObservedCandidateAttestationV1(_Model):
    """Signed post-creation attestation adding real IDs to the planned intent."""

    schema_version: Literal["rsd.observed-candidate-attestation.v1"]
    operation_kind: Literal["observed_lifecycle_v1"]
    provisioning_operation_id: str = Field(pattern=_UUID)
    observed_operation_id: str = Field(pattern=_UUID)
    initial_provisioning_intent_sha256: str = Field(pattern=_SHA256)
    provisioning_effect_receipt_sha256: str = Field(pattern=_SHA256)
    proposal_sha256: str = Field(pattern=_SHA256)
    candidate: CandidateCompositeV1
    candidate_composite_sha256: str = Field(pattern=_SHA256)
    observed_resources: ObservedResourceSetV1
    observed_at: str
    signer_key_id: str = Field(pattern=_IDENTIFIER)
    signature_base64: str = Field(min_length=4, max_length=256)

    @field_validator("observed_at")
    @classmethod
    def observation_time(cls, value: str) -> str:
        _timestamp(value)
        return value

    @model_validator(mode="after")
    def binds_observed_candidate(self) -> Self:
        if (
            self.candidate_composite_sha256 != canonical_sha256(self.candidate)
            or len(_canonical_base64_bytes(self.signature_base64)) != 64
        ):
            raise ValueError("observed candidate attestation is invalid")
        resources = self.observed_resources
        candidate = self.candidate
        if (
            resources.postgres_system_identifier != candidate.postgres.system_identifier
            or resources.postgres_database_oid != candidate.postgres.database_oid
            or not _matches_observed_service(resources.primary_service, candidate.primary_service)
            or not _matches_observed_service(resources.restore_service, candidate.restore_service)
            or not _matches_observed_valkey(resources.primary_valkey, candidate.primary_valkey)
            or not _matches_observed_valkey(resources.restore_valkey, candidate.restore_valkey)
        ):
            raise ValueError("observed resources do not bind candidate")
        return self


def _matches_observed_service(
    observed: ObservedServiceResourcesV1, candidate: ServiceIdentityV1 | ValkeyIdentityV1
) -> bool:
    return (
        observed.network_name == candidate.network_name
        and observed.network_id == candidate.network_id
        and observed.container_id == candidate.container_id
        and observed.workload_name == candidate.workload_name
        and observed.workload_id == candidate.workload_id
    )


def _matches_observed_valkey(
    observed: ObservedValkeyResourcesV1, candidate: ValkeyIdentityV1
) -> bool:
    return (
        _matches_observed_service(observed, candidate)
        and observed.volume_name == candidate.volume_name
        and observed.volume_id == candidate.volume_id
    )


def observed_candidate_attestation_sha256(attestation: ObservedCandidateAttestationV1) -> str:
    """Return the full signed observation commitment."""

    if type(attestation) is not ObservedCandidateAttestationV1:
        raise ValueError("observed candidate attestation is invalid")
    return canonical_sha256(attestation)


def validate_observed_candidate_transition(
    intent: InitialProvisioningIntentV1,
    receipt: InitialProvisioningEffectReceiptV1,
    attestation: ObservedCandidateAttestationV1,
    proposal: ProposalV1,
    contract: RuntimeContractV1,
) -> None:
    """Require a signed planned-to-observed transition before lifecycle effects.

    The intent contains names and policies only.  The effect receipt introduces
    IDs, and the signed attestation must bind those IDs to the exact final
    candidate/proposal before the observed lifecycle boundary can proceed.
    """

    if (
        type(intent) is not InitialProvisioningIntentV1
        or type(receipt) is not InitialProvisioningEffectReceiptV1
        or type(attestation) is not ObservedCandidateAttestationV1
        or type(proposal) is not ProposalV1
        or type(contract) is not RuntimeContractV1
    ):
        raise ValueError("initial stage transition is invalid")
    intent_hash = initial_provisioning_intent_sha256(intent)
    receipt_hash = initial_provisioning_effect_receipt_sha256(receipt)
    if (
        receipt.provisioning_operation_id != intent.provisioning_operation_id
        or receipt.intent_sha256 != intent_hash
        or receipt.journal_uuid != intent.journal_uuid
        or attestation.provisioning_operation_id != intent.provisioning_operation_id
        or attestation.observed_operation_id != proposal.operation_id
        or attestation.initial_provisioning_intent_sha256 != intent_hash
        or attestation.provisioning_effect_receipt_sha256 != receipt_hash
        or attestation.observed_resources != receipt.observed_resources
        or attestation.proposal_sha256 != proposal_sha256(proposal)
        or attestation.candidate != proposal.candidate
        or contract.model_dump(mode="json", include=set(ProposalV1.model_fields))
        != proposal.model_dump(mode="json")
    ):
        raise ValueError("initial stage transition is invalid")
    if (
        intent.source_commit != proposal.source_commit
        or intent.retention_expires_at != proposal.retention_expires_at
        or intent.disposal_owner != proposal.disposal_owner
        or intent.approval_reference_sha256 != proposal.approval_reference_sha256
        or intent.provider_references != proposal.provider_references
        or intent.plan.transport != proposal.transport
    ):
        raise ValueError("initial plan does not match observed proposal")
    plan = intent.plan
    candidate = proposal.candidate
    if (
        not _planned_service_matches(plan.primary_service, candidate.primary_service)
        or not _planned_service_matches(plan.restore_service, candidate.restore_service)
        or not _planned_postgres_matches(plan.postgres, candidate.postgres)
        or not _planned_valkey_matches(plan.primary_valkey, candidate.primary_valkey)
        or not _planned_valkey_matches(plan.restore_valkey, candidate.restore_valkey)
        or intent.evidence != proposal.initial_provisioning_evidence
    ):
        raise ValueError("initial plan does not match observed proposal")


def _planned_service_matches(plan: InitialServicePlanV1, observed: ServiceIdentityV1) -> bool:
    return (
        plan.authority == observed.authority
        and plan.authority_sha256 == observed.authority_sha256
        and plan.machine_id == observed.machine_id
        and plan.compose_project == observed.compose_project
        and plan.service_name == observed.service_name
        and plan.network_name == observed.network_name
        and plan.workload_name == observed.workload_name
        and plan.image == observed.image
        and plan.listener_binding == observed.listener_binding
        and plan.host_listener_port == observed.host_listener_port
        and plan.isolated_network_alias == observed.isolated_network_alias
    )


def _planned_postgres_matches(
    plan: InitialPostgreSQLPlanV1, observed: PostgreSQLContractV1
) -> bool:
    return (
        plan.authority == observed.authority
        and plan.database_name == observed.database_name
        and plan.schema_name == observed.schema_name
        and plan.owner_role == observed.owner_role
        and plan.role_names == observed.role_names
        and plan.stage_database_prefix == observed.stage_database_prefix
        and plan.restore_database_prefix == observed.restore_database_prefix
    )


def _planned_valkey_matches(plan: InitialValkeyPlanV1, observed: ValkeyIdentityV1) -> bool:
    return (
        plan.compose_project == observed.compose_project
        and plan.service_name == observed.service_name
        and plan.network_name == observed.network_name
        and plan.volume_name == observed.volume_name
        and plan.workload_name == observed.workload_name
        and plan.logical_namespace == observed.logical_namespace
        and plan.credential_reference_sha256 == observed.credential_reference_sha256
        and plan.image == observed.image
    )


# ``ProposalV1`` intentionally refers forward to the pre-creation evidence
# model so its observed artifact commits the original governed plan too.
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
    references: tuple[ProviderReferenceV1, ...] = Field(min_length=6, max_length=7)

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
